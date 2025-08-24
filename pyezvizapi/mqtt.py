"""Ezviz cloud MQTT client for push messages."""

from __future__ import annotations

import base64
from collections.abc import Callable
from contextlib import suppress
import json
import logging
from typing import Any

import paho.mqtt.client as mqtt
import requests

from .api_endpoints import (
    API_ENDPOINT_REGISTER_MQTT,
    API_ENDPOINT_START_MQTT,
    API_ENDPOINT_STOP_MQTT,
)
from .constants import (
    APP_SECRET,
    DEFAULT_TIMEOUT,
    FEATURE_CODE,
    MQTT_APP_KEY,
    REQUEST_HEADER,
)
from .exceptions import HTTPError, InvalidURL, PyEzvizError

_LOGGER = logging.getLogger(__name__)

# Field names in ext
EXT_FIELD_NAMES = [
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
    "encrypted_pwd_hash",
    "unknown_flag",
    "unused5",
    "alarm_log_id",
    "image",
    "device_name",
    "unused6",
    "sequence_number",
]

# Fields that should be converted to int
EXT_INT_FIELDS = {
    "channel_type",
    "channel_no",
    "alert_type_code",
    "status_flag",
    "is_encrypted",
    "sequence_number",
}


class MQTTClient:
    """MQTT client for Ezviz push notifications.

    Handles the Ezviz-specific registration and connection process,
    opens a persistent MQTT connection, and processes incoming messages.

    Typical usage::

        client = MQTTClient(token=auth_token)
        client.connect()

        # Messages can be retrieved from client.rcv_message
        # or handled via a callback passed into __init__.

        client.stop()
    """

    def __init__(
        self,
        token: dict,
        timeout: int = DEFAULT_TIMEOUT,
        on_message_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Initialize the Ezviz MQTT client.

        Args:
            token (dict): Authentication token including service URLs and session_id.
            timeout (int): HTTP request timeout in seconds.
            on_message_callback (Callable, optional): Callback function called with each
                decoded message dictionary. Defaults to None.

        Raises:
            PyEzvizError: If no valid token is provided.
        """
        if not token or not token.get("username"):
            raise PyEzvizError(
                "Ezviz internal username is required. "
                "Ensure EzvizClient.login() was called first."
            )

        self._session = requests.session()
        self._session.headers.update(REQUEST_HEADER)
        self._token = token
        self._timeout = timeout
        self._topic = f"{MQTT_APP_KEY}/#"
        self._on_message_callback = on_message_callback

        self._mqtt_data = {
            "mqtt_clientid": None,
            "ticket": None,
            "push_url": token["service_urls"]["pushAddr"],
        }

        self.mqtt_client: mqtt.Client | None = None
        self.messages_by_device: dict[Any, Any] = {}

    def decode_mqtt_message(self, payload_bytes: bytes) -> dict:
        """Decode MQTT payload bytes to a structured dict with typed ext fields.

        Returns:
            dict: Decoded message with `ext` mapped to named fields,
                numeric fields converted to int where appropriate.
        """
        try:
            # Decode bytes to string and parse JSON
            payload_str = payload_bytes.decode("utf-8")
            data = json.loads(payload_str)

            # Map ext fields
            if "ext" in data:
                ext_parts = data["ext"].split(",")

                ext_dict = {}
                for i, name in enumerate(EXT_FIELD_NAMES):
                    value = ext_parts[i] if i < len(ext_parts) else None

                    # Convert int fields
                    if value is not None and name in EXT_INT_FIELDS:
                        with suppress(ValueError):
                            value = int(value)

                    ext_dict[name] = value

                data["ext"] = ext_dict

        except json.JSONDecodeError as err:
            self.stop()
            raise PyEzvizError(f"Unable to decode MQTT message: {err}") from err

        return data

    # ----------------------------------------------------------------------
    # Ezviz API helpers
    # ----------------------------------------------------------------------

    def _register_ezviz_push(self) -> None:
        """Register client with Ezviz push service.

        Raises:
            PyEzvizError: If the registration fails.
            InvalidURL: If the push service URL is invalid.
            HTTPError: If the push service returns an error response.

        Returns:
            None: API JSON response:
                {
                    "status": int,         # Status code (200 if successful)
                    "message": str,        # Success message in Chinese
                    "data": {
                        "clientId": str,  # Unique client ID for MQTT
                        "mqtts": str      # MQTT server URL:port
                    }
                }
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
                + "\nResponse was: "
                + str(req.text)
            ) from err

        if json_output["status"] != 200:
            raise PyEzvizError(
                f"Could not register to EZVIZ mqtt server: Got {json_output})"
            )

        self._mqtt_data["mqtt_clientid"] = json_output["data"]["clientId"]

    def _start_ezviz_push(self) -> None:
        """Tell Ezviz API to start push notifications for this client.

        Raises:
            PyEzvizError: If the push service registration fails.
            InvalidURL: If the push service URL is invalid.
            HTTPError: If the push service returns an error response.

        Returns:
            None: API JSON response:
                {
                    "ticket": str,          # EZVIZ mqtt ticket number
                    "message": str,         # Status message in Chinese
                    "status": int           # Status code (200 if successful)
                }
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
                + "\nResponse was: "
                + str(req.text)
            ) from err

        if json_output["status"] != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to start pushing messages: Got {json_output})"
            )

        self._mqtt_data["ticket"] = json_output["ticket"]
        _LOGGER.info("EZVIZ MQTT ticket: : %s", self._mqtt_data["ticket"])

    def _stop_ezviz_push(self) -> None:
        """Tell Ezviz API to stop push notifications for this client.

        Raises:
            PyEzvizError: If the push service registration fails.
            InvalidURL: If the push service URL is invalid.
            HTTPError: If the push service returns an error response.

        Returns:
            None: API JSON response:
                {
                    "message": str,         # Status message in Chinese
                    "status": int           # Status code (200 if successful)
                }
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
                + "\nResponse was: "
                + str(req.text)
            ) from err

        if json_output["status"] != 200:
            raise PyEzvizError(
                f"Could not signal EZVIZ mqtt server to stop pushing messages: Got {json_output})"
            )

    # ----------------------------------------------------------------------
    # MQTT callbacks
    # ----------------------------------------------------------------------

    def _on_subscribe(
        self, client: Any, userdata: Any, mid: Any, granted_qos: Any
    ) -> None:
        """Handle subscription acknowledgement."""
        _LOGGER.info("Subscribed: %s %s", mid, granted_qos)
        _LOGGER.info("Subscribed to EZVIZ MQTT topic: %s", self._topic)

    def _on_connect(self, client: Any, userdata: Any, flags: dict, rc: int) -> None:
        """Handle successful or failed connection attempts."""
        session_present = (
            flags.get("session present") if isinstance(flags, dict) else flags
        )
        _LOGGER.info(
            "Connected to EZVIZ broker, session_present=%s, rc=%s", session_present, rc
        )
        if not flags.get("session present"):  # v1
            client.subscribe(self._topic, qos=2)
        if rc == 0:
            _LOGGER.info("Connected to EZVIZ MQTT broker (rc=%s)", rc)
        else:
            _LOGGER.error("MQTT connection failed, return code: %s", rc)
            client.reconnect()

    def _on_disconnect(self, client: Any, userdata: Any, rc: int) -> None:
        """Called when the client disconnects from the broker."""
        _LOGGER.warning("Disconnected from EZVIZ MQTT broker (rc=%s)", rc)

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        """Handle incoming MQTT messages."""
        _LOGGER.info("MQTT message received")

        # Decode the payload
        decoded = self.decode_mqtt_message(msg.payload)

        # Extract device_serial from decoded message
        device_serial = decoded.get("ext", {}).get("device_serial")
        if device_serial:
            # Store/update the message indexed by device_serial
            self.messages_by_device[device_serial] = decoded
            _LOGGER.debug("Stored message for device_serial %s", device_serial)
        else:
            _LOGGER.warning("Received message with no device_serial: %s", decoded)

        # Call user callback if defined
        if self._on_message_callback:
            self._on_message_callback(decoded)

    def set_mqtt(self, clean_session: bool = False) -> None:
        """Sets MQTT configuration."""
        broker = self._mqtt_data["push_url"]
        # self._topic = f"{MQTT_APP_KEY}/ticket/{self._mqtt_data['ticket']}"

        self.mqtt_client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=self._mqtt_data["mqtt_clientid"],
            clean_session=clean_session,
            protocol=mqtt.MQTTv311,
            transport="tcp",
        )
        # Set paho-mqtt callbacks
        self.mqtt_client.on_connect = self._on_connect
        self.mqtt_client.on_disconnect = self._on_disconnect
        self.mqtt_client.on_subscribe = self._on_subscribe
        self.mqtt_client.on_message = self._on_message
        self.mqtt_client.username_pw_set(MQTT_APP_KEY, APP_SECRET)
        self.mqtt_client.reconnect_delay_set(min_delay=5, max_delay=10)

        self.mqtt_client.connect(broker, 1882, 60)

    def connect(self) -> None:
        """Connect to Ezviz MQTT broker and start receiving push messages.

        Raises:
            PyEzvizError: If required Ezviz credentials are missing.
        """
        self._register_ezviz_push()
        self._start_ezviz_push()

        self.set_mqtt()

        self.mqtt_client.loop_start()

    def stop(self) -> None:
        """Stop MQTT client and push notifications."""
        if self.mqtt_client:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
            except Exception as err:
                _LOGGER.debug("MQTT disconnect failed: %s", err)

        self._stop_ezviz_push()
