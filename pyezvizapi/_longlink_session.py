"""One channel-99 connection, renewed from LBS on every worker attempt."""

from __future__ import annotations

from collections.abc import Callable
import json
import socket
from threading import Event, Lock
from time import monotonic
from typing import Any

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

from . import _longlink as wire
from ._longlink_auth import PushCredentials, authenticate
from ._longlink_transport import LbsConnection
from ._paho import set_keepalive
from .exceptions import EzvizPushFatalError

# Paho VERSION2 maps MQTT 3.1.1 CONNACK 1/2/4/5 to MQTT 5 reason values.
# Server unavailable (3 -> 0x88) remains retryable with fresh LBS credentials.
_PERMANENT_CONNACK_REASONS = frozenset({0x84, 0x85, 0x86, 0x87})
_MQTT_SETUP_TIMEOUT = 30


class Channel99Session:
    """Interruptible MQTT loop. HTTP registration is performed by the owner.

    credentials_input is evaluated on each attempt so HTTPS session rotation is
    visible to reconnects. Socket connection attempts have a ten-second timeout;
    platform DNS resolution is subject to the operating system's resolver.
    """

    def __init__(
        self,
        endpoint: tuple[str, int],
        serial: bytes,
        credentials_input: Callable[[], str],
        state: dict[str, Any],
        save: Callable[[dict[str, Any]], None],
        on_message: Callable[[bytes], None],
        *,
        prepare: Callable[[], None] | None = None,
        is_current: Callable[[], bool] | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.serial = serial
        self.credentials_input = credentials_input
        self.state = state
        self.save = save
        self.on_message = on_message
        self.prepare = prepare
        self.is_current = is_current or (lambda: True)
        self._lock = Lock()
        self._closed = Event()
        self.ready = Event()
        self.last_connect_reason: int | None = None
        self.last_subscribe_reasons: list[int] | None = None
        self._failure: EzvizPushFatalError | None = None
        self.last_disconnect_reason: int | None = None
        self.last_loop_result: int | None = None
        self._lbs: LbsConnection | None = None
        self._mqtt: mqtt.Client | None = None

    def close(self) -> None:
        self._closed.set()
        self.ready.clear()
        with self._lock:
            lbs, client = self._lbs, self._mqtt
        if lbs is not None:
            lbs.close()
        if client is not None:
            client.disconnect()

    def run(self, stopped: Event) -> None:
        if stopped.is_set() or self._closed.is_set() or not self.is_current():
            return
        if self.prepare is not None:
            self.prepare()
        if stopped.is_set() or self._closed.is_set() or not self.is_current():
            return
        with LbsConnection(socket.create_connection(self.endpoint, timeout=10)) as lbs:
            with self._lock:
                self._lbs = lbs
            try:
                if stopped.is_set() or self._closed.is_set() or not self.is_current():
                    return
                credentials = authenticate(
                    lbs, self.serial, self.credentials_input(), self.state, self.save
                )
            finally:
                with self._lock:
                    self._lbs = None
        self._run_mqtt(credentials, stopped)

    def _run_mqtt(self, credentials: PushCredentials, stopped: Event) -> None:
        """Run one broker attempt, surfacing permanent refusals to the worker."""
        client = self._client(credentials)
        with self._lock:
            self._mqtt = client
        try:
            if stopped.is_set() or self._closed.is_set() or not self.is_current():
                return
            client.connect(credentials.broker["Address"], credentials.broker["Port"], keepalive=30)
            deadline = monotonic() + _MQTT_SETUP_TIMEOUT
            while not stopped.is_set() and not self._closed.is_set() and self.is_current():
                result = client.loop(timeout=1)
                self.last_loop_result = int(result)
                if self._failure is not None:
                    raise self._failure
                if result == mqtt.MQTT_ERR_PROTOCOL and self.last_connect_reason is None:
                    # Paho skips on_connect for MQTT 3.1.1 protocol-version refusal.
                    self._failure = EzvizPushFatalError(
                        "MQTT setup protocol rejected; caller intervention required"
                    )
                    raise self._failure
                if result != mqtt.MQTT_ERR_SUCCESS:
                    return
                if not self.ready.is_set() and monotonic() >= deadline:
                    raise TimeoutError("MQTT connection/subscription acknowledgement timed out")
        except Exception as error:
            if self._failure is not None and error is not self._failure:
                raise self._failure from error
            raise
        finally:
            self._finish_mqtt(client)

    def _finish_mqtt(self, client: mqtt.Client) -> None:
        """Close even a rejected/broken transport without masking its refusal."""
        self._closed.set()
        self.ready.clear()
        try:
            try:
                client.disconnect()
                client.loop(timeout=0.1)
            finally:
                # disconnect() queues a packet; a broken cleanup loop may never
                # close the transport. Use Paho's public socket accessor as well.
                sock = client.socket()
                if sock is not None:
                    sock.close()
        except Exception:
            if self._failure is None:
                raise
        finally:
            with self._lock:
                self._mqtt = None

    def _client(self, credentials: PushCredentials) -> mqtt.Client:
        client = mqtt.Client(
            CallbackAPIVersion.VERSION2,
            # Paho accepts bytes at runtime; native device IDs are binary.
            client_id=credentials.device_id,  # type: ignore[arg-type]
            clean_session=True,
            protocol=mqtt.MQTTv311,
            reconnect_on_failure=False,
        )
        client.connect_timeout = 10
        client.username_pw_set(self.serial.decode(), None)
        serial = self.serial.decode()
        will = {
            "DevSerial": "",
            "SubSerial": serial,
            "FirmwareVersion": "",
            "DevType": "",
            "DevTypeDisplay": "",
            "MAC": "",
            "Status": 0,
            "NickName": "",
            "FirmwareIdentificationCode": "",
            "dev_oeminfo": 0,
            "LbsDomain": "",
            "RegMode": 0,
            "SDKMainVersion": "V2.4.0",
            "SDKVersion": {"1000": "V2.4.0", "0": ""},
        }
        topic = ("/Basic/pu2cenplt/" + serial + "/firstconnect").ljust(128, "\0")
        client.will_set(
            topic,
            wire.encrypt(credentials.session_key, json.dumps(will, separators=(",", ":")).encode()),
            qos=1,
            retain=True,
        )

        subscription_mid: int | None = None

        def connected(
            c: mqtt.Client, userdata: Any, flags: Any, reason: Any, properties: Any
        ) -> None:
            nonlocal subscription_mid
            if self._closed.is_set() or not self.is_current():
                return
            self.last_connect_reason = reason.value
            if reason.is_failure:
                self.ready.clear()
                if reason.value in _PERMANENT_CONNACK_REASONS:
                    self._failure = EzvizPushFatalError(
                        f"MQTT connection rejected (reason {reason.value}); caller intervention required"
                    )
                c.disconnect()
                return
            result, subscription_mid = c.subscribe("/" + serial + "/#", qos=1)
            if result != mqtt.MQTT_ERR_SUCCESS:
                subscription_mid = None
                if result == mqtt.MQTT_ERR_INVAL:
                    self._failure = EzvizPushFatalError("Invalid MQTT subscription request")
                c.disconnect()

        def subscribed(
            c: mqtt.Client, userdata: Any, mid: int, reasons: Any, properties: Any
        ) -> None:
            if self._closed.is_set() or not self.is_current() or mid != subscription_mid:
                return
            self.last_subscribe_reasons = [reason.value for reason in reasons]
            if any(reason.is_failure for reason in reasons):
                self.ready.clear()
                # MQTT 3.1.1 SUBACK 0x80 is an explicit refusal of our only topic.
                # Retrying unchanged forever would conceal the unusable feed.
                self._failure = EzvizPushFatalError(
                    f"MQTT subscription rejected (reasons {self.last_subscribe_reasons}); "
                    "caller intervention required"
                )
                c.disconnect()
            elif len(reasons) != 1 or reasons[0].value not in (0, 1):
                c.disconnect()  # Malformed acknowledgement, not proof of authorization failure.
            else:
                self.ready.set()

        def received(c: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
            if not self._closed.is_set() and self.is_current():
                self._receive(c, msg, credentials.session_key)

        def disconnected(
            c: mqtt.Client, userdata: Any, flags: Any, reason: Any, properties: Any
        ) -> None:
            self.ready.clear()
            self.last_disconnect_reason = reason.value

        client.on_disconnect = disconnected
        client.on_connect = connected
        client.on_subscribe = subscribed
        client.on_message = received
        return client

    def _receive(self, client: mqtt.Client, message: mqtt.MQTTMessage, key: bytes) -> None:
        if len(message.payload) > 65536:
            return
        event = wire.decode_event_envelope(message.topic, message.payload, key, self.serial)
        domain, command = event["domain"], event["command"]
        if domain == 1000 and command == 1:
            interval = wire.control_keepalive(event["body"])
            if interval is not None:
                # Paho has no public API for a server-negotiated keepalive.
                set_keepalive(client, interval)
        elif domain == 9000 and command == 1:
            body = event["body"].rstrip(b"\0")
            if not isinstance(json.loads(body), dict):
                raise ValueError("Push event must be a JSON object")
            # The channel-99 broker closes the connection when a direct JSON
            # notification is answered on /9000/2. The native mobile handler's
            # queued XML response is not evidence that this login may publish it.
            # Leave MQTT-level acknowledgements to Paho; deliver without a reply.
            self.on_message(body)
        elif domain == 9000 and 0x6000 <= command <= 0x6FFF:
            # These native mobile messages have not yet been observed live.
            wire.decode_mobile_body(event["body"])
            topic, payload = wire.encode_application_ack(
                key, domain, command + 1, event["sequence"]
            )
            client.publish(topic, payload, qos=0)
