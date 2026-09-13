"""One channel-99 connection, renewed from LBS on every worker attempt."""

from __future__ import annotations

from collections.abc import Callable
import json
import socket
from threading import Event, Lock
from typing import Any

import paho.mqtt.client as mqtt

from . import _longlink as wire
from ._longlink_auth import PushCredentials, authenticate
from ._longlink_transport import LbsConnection


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
    ) -> None:
        self.endpoint = endpoint
        self.serial = serial
        self.credentials_input = credentials_input
        self.state = state
        self.save = save
        self.on_message = on_message
        self.prepare = prepare
        self._lock = Lock()
        self._closed = Event()
        self.ready = Event()
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
        if stopped.is_set() or self._closed.is_set():
            return
        if self.prepare is not None:
            self.prepare()
        if stopped.is_set() or self._closed.is_set():
            return
        with LbsConnection(socket.create_connection(self.endpoint, timeout=10)) as lbs:
            with self._lock:
                self._lbs = lbs
            try:
                if stopped.is_set() or self._closed.is_set():
                    return
                credentials = authenticate(
                    lbs, self.serial, self.credentials_input(), self.state, self.save
                )
            finally:
                with self._lock:
                    self._lbs = None
        client = self._client(credentials)
        with self._lock:
            self._mqtt = client
        try:
            if stopped.is_set() or self._closed.is_set():
                return
            client.connect(credentials.broker["Address"], credentials.broker["Port"], keepalive=30)
            while not stopped.is_set() and not self._closed.is_set():
                result = client.loop(timeout=1)
                self.last_loop_result = int(result)
                if result != mqtt.MQTT_ERR_SUCCESS:
                    return
        finally:
            self.ready.clear()
            client.disconnect()
            client.loop(timeout=0.1)
            with self._lock:
                self._mqtt = None

    def _client(self, credentials: PushCredentials) -> mqtt.Client:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
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

        def connected(
            c: mqtt.Client, userdata: Any, flags: Any, reason: Any, properties: Any
        ) -> None:
            if reason.is_failure:
                c.disconnect()
                return
            result, _ = c.subscribe("/" + serial + "/#", qos=1)
            if result != mqtt.MQTT_ERR_SUCCESS:
                c.disconnect()

        def subscribed(
            c: mqtt.Client, userdata: Any, mid: int, reasons: Any, properties: Any
        ) -> None:
            if not reasons or any(reason.is_failure for reason in reasons):
                c.disconnect()
            else:
                self.ready.set()

        def received(c: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
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
                client._keepalive = interval  # noqa: SLF001
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
