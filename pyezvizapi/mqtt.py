"""Ezviz cloud MQTT client for push messages.

Synchronous MQTT client tailored for EZVIZ push notifications as used by
`pyezvizapi` and Home Assistant integrations. Handles the EZVIZ registration
flow, starts/stops push, maintains a long-lived MQTT connection, and decodes
incoming payloads into a structured form.

This module is intentionally synchronous (uses `requests` and
`paho-mqtt`'s background network thread via `loop_start()`), which keeps
integration code simple. If you later migrate to an async HA integration,
wrap the blocking calls with `hass.async_add_executor_job`.

Example:
    >>> client = MQTTClient(token)
    >>> client.connect()
    >>> # ... handle callbacks or read client.messages_by_device ...
    >>> client.stop()

"""

from __future__ import annotations

import base64
from collections import OrderedDict
from collections.abc import Callable
from contextlib import suppress
import json
import logging
from typing import Any, Final, TypedDict

import paho.mqtt.client as mqtt
import requests

from .api_endpoints import (
    API_ENDPOINT_REGISTER_MQTT,
    API_ENDPOINT_START_MQTT,
    API_ENDPOINT_STOP_MQTT,
)
from .constants import APP_SECRET, DEFAULT_TIMEOUT, FEATURE_CODE, MQTT_APP_KEY
from .exceptions import HTTPError, InvalidURL, PyEzvizError

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed structures
# ---------------------------------------------------------------------------


class ServiceUrls(TypedDict):
    """Service URLs present in the EZVIZ auth token.

    Attributes:
        pushAddr: Hostname of the EZVIZ push/MQTT entry point.
    """

    pushAddr: str


class EzvizToken(TypedDict):
    """Minimal shape of the EZVIZ token required for MQTT.

    Attributes:
        username: Internal EZVIZ username.
        session_id: Current session id.
        service_urls: Nested object containing at least ``pushAddr``.
    """

    username: str
    session_id: str
    service_urls: ServiceUrls


class MqttData(TypedDict):
    """Typed dictionary for EZVIZ MQTT connection data."""

    mqtt_clientid: str | None
    ticket: str | None
    push_url: str


# ---------------------------------------------------------------------------
# Payload decoding helpers
# ---------------------------------------------------------------------------

# Field names in the comma‑separated ``ext`` payload from EZVIZ.
EXT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "channel_type",
    "time",
    "device_serial",
    "channel_no",
    "alert_type_code",
    "unused1",
    "unused2",
    "unused3",
    "unused4",
    "status_flag",
    "file_id",
    "is_encrypted",
    "picChecksum",
    "unknown_flag",
    "unused5",
    "msgId",
    "image",
    "device_name",
    "unused6",
    "sequence_number",
)

# Fields that should be converted to ``int`` if present.
EXT_INT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "channel_type",
        "channel_no",
        "alert_type_code",
        "status_flag",
        "is_encrypted",
        "sequence_number",
    }
)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class MQTTClient:
    """MQTT client for Ezviz push notifications.

    Handles the Ezviz-specific registration and connection process,
    maintains a persistent MQTT connection, and processes incoming messages.

    Messages are stored per device_serial in `messages_by_device`, and an optional
    callback can be provided to handle messages as they arrive.

    Typical usage::

        client = MQTTClient(token=auth_token)
        client.connect(clean_session=True)

        # Access last message for a device
        last_msg = client.messages_by_device.get(device_serial)

        # Stop the client when done
        client.stop()
    """

    def __init__(
        self,
        token: EzvizToken | dict,
        session: requests.Session,
        timeout: int = DEFAULT_TIMEOUT,
        on_message_callback: Callable[[dict[str, Any]], None] | None = None,
        *,
        max_messages: int = 1000,
    ) -> None:
        """Initialize the Ezviz MQTT client.

        This client handles registration with the Ezviz push service, maintains
        a persistent MQTT connection, and decodes incoming push messages.

        Args:
            token (dict): Authentication token dictionary returned by EzvizClient.login().
                Must include:
                    - 'username': Ezviz account username (The account aliase or generated one.)
                    - 'session_id': session token for API access
                    - 'service_urls': dictionary containing at least 'pushAddr'
            timeout (int, optional): HTTP request timeout in seconds. Defaults to DEFAULT_TIMEOUT.
            session (requests.Session): Pre-configured requests session for HTTP calls.
            on_message_callback (Callable[[dict[str, Any]], None], optional): Optional callback function
                that will be called for each decoded MQTT message. The callback receives
                a dictionary with the message data. Defaults to None.
            max_messages:
                Maximum number of device entries kept in :attr:`messages_by_device`.
                Oldest entries are evicted when the limit is exceeded. Defaults to ``1000``.

        Raises:
            PyEzvizError: If the provided token is missing required fields.
        """
        if not token or not token.get("username"):
            raise PyEzvizError(
                "Ezviz internal username is required. Ensure EzvizClient.login() was called first."
            )

        # Requests session (synchronous)
        self._session = session

        self._token: EzvizToken | dict = token
        self._timeout: int = timeout
        self._topic: str = f"{MQTT_APP_KEY}/#"
        self._on_message_callback = on_message_callback
        self._max_messages: int = max_messages

        self._mqtt_data: MqttData = {
            "mqtt_clientid": None,
            "ticket": None,
            "push_url": token["service_urls"]["pushAddr"],
        }

        self.mqtt_client: mqtt.Client | None = None
        # Keep last payload per device, bounded by ``max_messages``
        self.messages_by_device: OrderedDict[str, dict[str, Any]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, *, clean_session: bool = False, keepalive: int = 60) -> None:
        """Connect to the Ezviz MQTT broker and start receiving push messages.

        This method performs the following steps:
            1. Registers the client with Ezviz push service.
            2. Starts push notifications for this client.
            3. Configures and connects the underlying MQTT client.
            4. Starts the MQTT network loop in a background thread.

        Keyword Args:
          clean_session (bool, optional): Whether to start a clean MQTT session. Defaults to False.
          keepalive (int, optional): Keep-alive interval in seconds for the MQTT connection. Defaults to 60.

        Raises:
          PyEzvizError: If required Ezviz credentials are missing or registration/start fails.
          InvalidURL: If a push API endpoint is invalid or unreachable.
          HTTPError: If a push API request returns a non-success status.
        """
        self._register_ezviz_push()
        self._start_ezviz_push()
        self._configure_mqtt(clean_session=clean_session)
        assert self.mqtt_client is not None
        self.mqtt_client.connect(self._mqtt_data["push_url"], 1882, keepalive)
        self.mqtt_client.loop_start()

    def stop(self) -> None:
        """Stop the MQTT client and push notifications.

        This method stops the MQTT network loop, disconnects from the broker,
        and signals the Ezviz API to stop push notifications.

        This method is idempotent and can be called multiple times safely.

        Raises:
          PyEzvizError: If stopping the push service fails.
        """
        if self.mqtt_client:
            try:
                # Stop background thread and disconnect
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("MQTT disconnect failed: %s", err)
        # Always attempt to stop push on server side
        self._stop_ezviz_push()

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _on_subscribe(
        self, client: mqtt.Client, userdata: Any, mid: int, granted_qos: tuple[int, ...]
    ) -> None:
        """Handle subscription acknowledgement from the broker."""
        _LOGGER.debug(
            "MQTT subscribed: topic=%s mid=%s qos=%s", self._topic, mid, granted_qos
        )

    def _on_connect(
        self, client: mqtt.Client, userdata: Any, flags: dict, rc: int
    ) -> None:
        """Handle successful or failed MQTT connection attempts.

        Subscribes to the topic if this is a new session and logs connection status.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            flags (dict): MQTT flags dictionary, includes 'session present'.
            rc (int): MQTT connection result code. 0 indicates success.
        """
        session_present = (
            flags.get("session present") if isinstance(flags, dict) else None
        )
        _LOGGER.debug("MQTT connected: rc=%s session_present=%s", rc, session_present)
        if rc == 0 and not session_present:
            client.subscribe(self._topic, qos=2)
        if rc != 0:
            # Let paho handle reconnects (reconnect_delay_set configured)
            _LOGGER.error(
                "MQTT connect failed: serial=%s code=%s msg=%s",
                "unknown",
                rc,
                "connect_failed",
            )

    def _on_disconnect(self, client: mqtt.Client, userdata: Any, rc: int) -> None:
        """Called when the MQTT client disconnects from the broker.

        Logs the disconnection. Automatic reconnects are handled by paho-mqtt.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            rc (int): Disconnect result code. 0 indicates a clean disconnect.
        """
        _LOGGER.debug(
            "MQTT disconnected: serial=%s code=%s msg=%s",
            "unknown",
            rc,
            "disconnected",
        )

    def _on_message(
        self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage
    ) -> None:
        """Handle incoming MQTT messages.

        Decodes the payload, updates `messages_by_device` with the latest message,
        and calls the optional user callback.

        Args:
            client (mqtt.Client): The MQTT client instance.
            userdata (Any): The user data passed to the client (not used).
            msg (mqtt.MQTTMessage): The MQTT message object containing payload and topic.
        """
        try:
            decoded = self.decode_mqtt_message(msg.payload)
        except PyEzvizError as err:
            _LOGGER.warning("MQTT decode error: msg=%s", str(err))
            return

        ext: dict[str, Any] = (
            decoded.get("ext", {}) if isinstance(decoded.get("ext"), dict) else {}
        )
        device_serial = ext.get("device_serial")
        alert_code = ext.get("alert_type_code")
        msg_id = ext.get("msgId")

        if device_serial:
            self._cache_message(device_serial, decoded)
            _LOGGER.debug(
                "MQTT msg: serial=%s alert_code=%s msg_id=%s",
                device_serial,
                alert_code,
                msg_id,
            )
        else:
            _LOGGER.debug(
                "MQTT message missing serial: alert_code=%s msg_id=%s",
                alert_code,
                msg_id,
            )

        if self._on_message_callback:
            try:
                self._on_message_callback(decoded)
            except Exception:
                _LOGGER.exception("The on_message_callback raised")

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _register_ezviz_push(self) -> None:
        """Register the client with the Ezviz push service.

        Sends the necessary information to Ezviz to obtain a unique MQTT client ID.

        Raises:
            PyEzvizError: If the registration fails or the API returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        auth_seq = (
            "Basic "
            + base64.b64encode(f"{MQTT_APP_KEY}:{APP_SECRET}".encode("ascii")).decode()
        )

        payload = {
            "appKey": MQTT_APP_KEY,
            "clientType": "5",
            "mac": FEATURE_CODE,
            "token": "123456",
            "version": "v1.3.0",
        }

        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_REGISTER_MQTT}",
                allow_redirects=False,
                headers={"Authorization": auth_seq},
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.HTTPError as err:  # network OK, HTTP error status
            raise HTTPError from err

        try:
            json_output = req.json()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not register to EZVIZ mqtt server: Got {json_output})"
            )

        # Persist client id from payload
        self._mqtt_data["mqtt_clientid"] = json_output["data"]["clientId"]

    def _start_ezviz_push(self) -> None:
        """Start push notifications for this client with the Ezviz API.

        Sends the client ID, session ID, and username to Ezviz so that the server
        will start pushing messages to this client.

        Raises:
            PyEzvizError: If the API fails to start push notifications or returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        payload = {
            "appKey": MQTT_APP_KEY,
            "clientId": self._mqtt_data["mqtt_clientid"],
            "clientType": 5,
            "sessionId": self._token["session_id"],
            "username": self._token["username"],
            "token": "123456",
        }

        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_START_MQTT}",
                allow_redirects=False,
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_output = req.json()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to start pushing messages: Got {json_output})"
            )

        self._mqtt_data["ticket"] = json_output["ticket"]
        _LOGGER.debug(
            "MQTT ticket acquired: client_id=%s", self._mqtt_data["mqtt_clientid"]
        )

    def _stop_ezviz_push(self) -> None:
        """Stop push notifications for this client via the Ezviz API.

        Sends the client ID and session information to stop further messages.

        Raises:
            PyEzvizError: If the API fails to stop push notifications or returns a non-200 status.
            InvalidURL: If the push service URL is invalid or unreachable.
            HTTPError: If the HTTP request fails for other reasons.
        """
        payload = {
            "appKey": MQTT_APP_KEY,
            "clientId": self._mqtt_data["mqtt_clientid"],
            "clientType": 5,
            "sessionId": self._token["session_id"],
            "username": self._token["username"],
        }

        try:
            req = self._session.post(
                f"https://{self._mqtt_data['push_url']}{API_ENDPOINT_STOP_MQTT}",
                data=payload,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_output = req.json()
        except requests.ConnectionError as err:
            raise InvalidURL("Invalid URL or proxy error") from err
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "Response was: "
                + str(req.text)
            ) from err

        if json_output.get("status") != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to stop pushing messages: Got {json_output})"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _configure_mqtt(self, *, clean_session: bool) -> None:
        """Internal helper to configure and connect the paho-mqtt client.

        This method sets up the MQTT client with:
            - Callbacks for connect, disconnect, subscribe, and message
            - Username and password authentication
            - Reconnect delay settings
            - Broker connection on the configured topic

        Args:
            clean_session (bool): Whether to start a clean MQTT session.

        Notes:
            This method is called automatically by `connect()`.

        """
        broker = self._mqtt_data["push_url"]

        self.mqtt_client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=self._mqtt_data["mqtt_clientid"],
            clean_session=clean_session,
            protocol=mqtt.MQTTv311,
            transport="tcp",
        )

        # Bind callbacks
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_disconnect = self._on_disconnect
        self.mqtt_client.on_subscribe = self._on_subscribe
        self.mqtt_client.on_message = self._on_message

        # Auth (do not log these!)
        self.mqtt_client.username_pw_set(MQTT_APP_KEY, APP_SECRET)

        # Backoff for reconnects handled by paho
        self.mqtt_client.reconnect_delay_set(min_delay=5, max_delay=10)

        _LOGGER.debug("Configured MQTT client for broker %s", broker)

    def _cache_message(self, device_serial: str, payload: dict[str, Any]) -> None:
        """Cache latest message per device with an LRU-like policy.

        Parameters:
            device_serial (str): Device serial extracted from the message ``ext``.
            payload (dict[str, Any]): Decoded message dictionary to store.
        """
        # Move existing to the end or insert new
        if device_serial in self.messages_by_device:
            del self.messages_by_device[device_serial]
        self.messages_by_device[device_serial] = payload
        # Evict oldest if above limit
        while len(self.messages_by_device) > self._max_messages:
            self.messages_by_device.popitem(last=False)

    # ------------------------------------------------------------------
    # Public decoding API
    # ------------------------------------------------------------------

    def decode_mqtt_message(self, payload_bytes: bytes) -> dict[str, Any]:
        """Decode raw MQTT message payload into a structured dictionary.

        The returned dictionary will contain all top-level fields from the message,
        and the 'ext' field is parsed into named subfields with numeric fields converted to int.

        Parameters:
            payload_bytes (bytes): Raw payload received from MQTT broker.

        Returns:
            dict: Decoded message with ``ext`` mapped to named fields; numeric fields
            converted to ``int`` where appropriate.

        Raises:
            PyEzvizError: If the payload is not valid JSON.
        """
        try:
            payload_str = payload_bytes.decode("utf-8")
            data: dict[str, Any] = json.loads(payload_str)

            if "ext" in data and isinstance(data["ext"], str):
                ext_parts = data["ext"].split(",")
                ext_dict: dict[str, Any] = {}
                for i, name in enumerate(EXT_FIELD_NAMES):
                    value: Any = ext_parts[i] if i < len(ext_parts) else None
                    if value is not None and name in EXT_INT_FIELDS:
                        with suppress(ValueError):
                            value = int(value)
                    ext_dict[name] = value
                data["ext"] = ext_dict

        except json.JSONDecodeError as err:
            # Stop the client on malformed payloads as a defensive measure,
            # mirroring previous behaviour.
            self.stop()
            raise PyEzvizError(f"Unable to decode MQTT message: {err}") from err

        return data
