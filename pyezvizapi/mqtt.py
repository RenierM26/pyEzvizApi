"""EZVIZ channel-99 push client with the historical MQTTClient API name.

Login registration uses the Android profile; LBS negotiates the device/session
keys before a background MQTT connection delivers decoded notifications.
Call EzvizClient.enable_channel99() to migrate an old web-profile login and
provide a synchronous token persistence callback before connecting.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from contextlib import suppress
from copy import deepcopy
import json
import logging
from typing import Any, Final, NotRequired, TypedDict, cast

import requests

from ._longlink_profile import PROFILE as PUSH_PROFILE, REGISTER as PUSH_REGISTER
from ._longlink_session import Channel99Session
from ._longlink_worker import PushWorker
from .constants import DEFAULT_TIMEOUT
from .exceptions import EzvizAuthTokenExpired, PyEzvizError

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typed structures
# ---------------------------------------------------------------------------


class ServiceUrls(TypedDict):
    """Service URLs present in the EZVIZ auth token.

    Attributes:
        pushAddr: Hostname of the EZVIZ push/MQTT entry point.
    """

    pushAddr: NotRequired[str]
    pushDasDomain: NotRequired[str]
    pushDasPort: NotRequired[int | str]


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
    user_id: NotRequired[str]
    feature_code: NotRequired[str]
    api_url: NotRequired[str]
    push_profile: NotRequired[str]
    push_state: NotRequired[dict[str, Any]]


class MqttData(TypedDict):
    """Typed dictionary for EZVIZ MQTT connection data."""

    mqtt_clientid: str | None
    ticket: str | None
    push_url: str


# ---------------------------------------------------------------------------
# Payload decoding helpers
# ---------------------------------------------------------------------------

# Field names in the comma-separated ``ext`` payload from EZVIZ.
EXT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "channel_type",
    "time",
    "device_serial",
    "channel_no",
    "alert_type_code",
    "default_pic_url",
    "media_url_alt1",
    "media_url_alt2",
    "resource_type",
    "status_flag",
    "file_id",
    "is_encrypted",
    "picChecksum",
    "is_dev_video",
    "metadata",
    "msgId",
    "image",
    "device_name",
    "reserved",
    "sequence_number",
)

# Fields that should be converted to ``int`` if present.
EXT_INT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "channel_type",
        "channel_no",
        "alert_type_code",
        "resource_type",
        "status_flag",
        "is_encrypted",
        "is_dev_video",
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
        on_token_updated: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialize the Ezviz MQTT client.

        This client handles registration with the Ezviz push service, maintains
        a persistent MQTT connection, and decodes incoming push messages.

        Args:
            token (dict): Authentication token dictionary returned by EzvizClient.login().
                Must include:
                    - 'username': Ezviz account username (The account aliase or generated one.)
                    - 'session_id': session token for API access
                    - 'service_urls': channel-99 pushDasDomain/pushDasPort discovery
            timeout (int, optional): HTTP request timeout in seconds. Defaults to DEFAULT_TIMEOUT.
            session (requests.Session): Pre-configured requests session for HTTP calls.
            on_message_callback (Callable[[dict[str, Any]], None], optional): Optional callback function
                that will be called for each decoded MQTT message. The callback receives
                a dictionary with the message data. Defaults to None.
            on_token_updated:
                Synchronous callback receiving the complete token snapshot. Must
                durably save it before returning; required for push reception.
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
        self._on_message_callback = on_message_callback
        self._on_token_updated = on_token_updated
        self._push_worker: PushWorker | None = None
        self._max_messages: int = max_messages

        # Keep last payload per device, bounded by ``max_messages``
        self.messages_by_device: OrderedDict[str, dict[str, Any]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, *, clean_session: bool = False, keepalive: int = 60) -> None:
        """Start background channel-99 registration, negotiation and reception.

        Returns before broker acceptance. Keep polling independent of push.
        clean_session and keepalive remain accepted for source compatibility;
        channel-99 uses its native clean-session profile and server keepalive.
        """
        if self._token.get("push_profile") != PUSH_PROFILE:
            raise EzvizAuthTokenExpired(
                "Legacy push registration is no longer supported; migrate with "
                "EzvizClient.enable_channel99() and persist the returned token"
            )
        self._connect_channel99()

    def stop(self) -> None:
        """Cancel push without calling the obsolete HTTP stop endpoint.

        Raises TimeoutError if in-flight setup exceeds the worker join deadline.
        Cancellation remains signalled; do not start another worker until it exits.
        """
        if self._push_worker is not None:
            self._push_worker.stop()

    def _connect_channel99(self) -> None:
        """Start push in the background; persistence runs on the worker thread."""
        if self._on_token_updated is None:
            raise PyEzvizError("Channel-99 requires on_token_updated to durably save the token")
        token = cast(dict[str, Any], self._token)
        if not all(token.get(key) for key in ("user_id", "feature_code", "session_id", "api_url")):
            raise PyEzvizError("Channel-99 login metadata is incomplete; migrate the login first")
        urls = token.get("service_urls", {})
        host = urls.get("pushDasDomain")
        port = int(urls.get("pushDasPort") or 8666)
        if not isinstance(host, str) or not host or not 1 <= port <= 65535:
            raise PyEzvizError("Channel-99 service discovery is missing")
        serial = f"MOBILE:ys7:{token['user_id']}:{token['feature_code']}".encode("ascii")
        state = token.setdefault("push_state", {})
        if not isinstance(state, dict):
            raise PyEzvizError("Invalid saved push state")

        def save(snapshot: dict[str, Any]) -> None:
            token["push_state"] = snapshot
            assert self._on_token_updated is not None
            self._on_token_updated(deepcopy(dict(token)))

        def prepare() -> None:
            # Isolate requests state from the owner's concurrent polling requests.
            with requests.Session() as session:
                session.headers.update(self._session.headers)
                session.headers["sessionId"] = token["session_id"]
                response = session.put(
                    f"https://{token['api_url']}/v3/push/token",
                    params=PUSH_REGISTER,
                    timeout=self._timeout,
                    allow_redirects=False,
                )
                response.raise_for_status()
                if response.json().get("meta", {}).get("code") != 200:
                    raise PyEzvizError("Channel-99 registration rejected")

        if self._push_worker is None:
            self._push_worker = PushWorker(
                lambda: Channel99Session(
                    (host, port),
                    serial,
                    lambda: token["session_id"],
                    state,
                    save,
                    self._handle_payload,
                    prepare=prepare,
                )
            )
        self._push_worker.start()

    # ------------------------------------------------------------------
    # MQTT callbacks
    # ------------------------------------------------------------------

    def _handle_payload(self, payload: bytes) -> None:
        """Preserve the public decoded-message/cache contract across transports."""
        try:
            decoded = self.decode_mqtt_message(payload)
        except PyEzvizError as err:
            _LOGGER.warning("MQTT decode error: msg=%s", str(err))
            return

        ext: dict[str, Any] = decoded.get("ext", {}) if isinstance(decoded.get("ext"), dict) else {}
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
