Total output lines: 5302

"""Ezviz API."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Mapping
import datetime as dt
import hashlib
import json
import logging
from typing import Any, ClassVar, NotRequired, TypedDict, cast
from urllib.parse import urlencode
from uuid import uuid4
import zlib

import requests

from . import device_factory
from .api_endpoints import (
    API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
    API_ENDPOINT_ALARM_DEVICE_CHIME,
    API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL,
    API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE,
    API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE,
    API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE,
    API_ENDPOINT_ALARM_SOUND,
    API_ENDPOINT_ALARM_STOP_WHISTLE,
    API_ENDPOINT_ALARMINFO_GET,
    API_ENDPOINT_AUTOUPGRADE_SWITCH,
    API_ENDPOINT_CALLING_NOTIFY,
    API_ENDPOINT_CAM_AUTH_CODE,
    API_ENDPOINT_CAM_ENCRYPTKEY,
    API_ENDPOINT_CAMERA_TICKET_INFO,
    API_ENDPOINT_CANCEL_ALARM,
    API_ENDPOINT_CHANGE_DEFENCE_STATUS,
    API_ENDPOINT_CLOUD_VIDEO_DETAILS,
    API_ENDPOINT_CLOUD_VIDEOS_LIST,
    API_ENDPOINT_CREATE_PANORAMIC,
    API_ENDPOINT_DETECTION_SENSIBILITY,
    API_ENDPOINT_DETECTION_SENSIBILITY_GET,
    API_ENDPOINT_DEVCONFIG_BASE,
    API_ENDPOINT_DEVCONFIG_BY_KEY,
    API_ENDPOINT_DEVCONFIG_MOTOR,
    API_ENDPOINT_DEVCONFIG_OP,
    API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE,
    API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE,
    API_ENDPOINT_DEVICE_ACCESSORY_LINK,
    API_ENDPOINT_DEVICE_BASICS,
    API_ENDPOINT_DEVICE_EMAIL_ALERT,
    API_ENDPOINT_DEVICE_STORAGE_STATUS,
    API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY,
    API_ENDPOINT_DEVICE_SYS_OPERATION,
    API_ENDPOINT_DEVICE_UPDATE_NAME,
    API_ENDPOINT_DEVICES,
    API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC,
    API_ENDPOINT_DEVICES_AUTHENTICATE,
    API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH,
    API_ENDPOINT_DEVICES_LOC,
    API_ENDPOINT_DEVICES_P2P_INFO,
    API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE,
    API_ENDPOINT_DO_NOT_DISTURB,
    API_ENDPOINT_DOORLOCK_USERS,
    API_ENDPOINT_FEEDBACK,
    API_ENDPOINT_GROUP_DEFENCE_MODE,
    API_ENDPOINT_INTELLIGENT_APP,
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_IOT_FEATURE,
    API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG,
    API_ENDPOINT_IOT_VIRTUAL_BIND,
    API_ENDPOINT_LOGIN,
    API_ENDPOINT_LOGOUT,
    API_ENDPOINT_MANAGED_DEVICE_BASE,
    API_ENDPOINT_OFFLINE_NOTIFY,
    API_ENDPOINT_OSD,
    API_ENDPOINT_PAGELIST,
    API_ENDPOINT_PTZCONTROL,
    API_ENDPOINT_REFRESH_SESSION_ID,
    API_ENDPOINT_REMOTE_LOCK,
    API_ENDPOINT_REMOTE_UNBIND_PROGRESS,
    API_ENDPOINT_REMOTE_UNLOCK,
    API_ENDPOINT_RETURN_PANORAMIC,
    API_ENDPOINT_SCD_APP_DEVICE_ADD,
    API_ENDPOINT_SDCARD_BLACK_LEVEL,
    API_ENDPOINT_SEND_CODE,
    API_ENDPOINT_SENSITIVITY,
    API_ENDPOINT_SERVER_INFO,
    API_ENDPOINT_SET_DEFENCE_SCHEDULE,
    API_ENDPOINT_SET_LUMINANCE,
    API_ENDPOINT_SHARE_ACCEPT,
    API_ENDPOINT_SHARE_QUIT,
    API_ENDPOINT_SMARTHOME_OUTLET_LOG,
    API_ENDPOINT_SPECIAL_BIZS_A1S,
    API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY,
    API_ENDPOINT_SPECIAL_BIZS_VOICES,
    API_ENDPOINT_STREAMING_RECORDS,
    API_ENDPOINT_STREAMING_RECORDS_COMMON,
    API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT,
    API_ENDPOINT_STREAMING_RECORDS_V2,
    API_ENDPOINT_SWITCH_DEFENCE_MODE,
    API_ENDPOINT_SWITCH_OTHER,
    API_ENDPOINT_SWITCH_SOUND_ALARM,
    API_ENDPOINT_SWITCH_STATUS,
    API_ENDPOINT_TERMINAL_INFO,
    API_ENDPOINT_TIME_PLAN_INFOS,
    API_ENDPOINT_UNIFIEDMSG_LIST_GET,
    API_ENDPOINT_UPGRADE_DEVICE,
    API_ENDPOINT_UPGRADE_RULE,
    API_ENDPOINT_USER_ID,
    API_ENDPOINT_USERDEVICES_KMS,
    API_ENDPOINT_USERDEVICES_P2P_INFO,
    API_ENDPOINT_USERDEVICES_SEARCH,
    API_ENDPOINT_USERDEVICES_STATUS,
    API_ENDPOINT_USERDEVICES_TOKEN,
    API_ENDPOINT_USERDEVICES_V2,
    API_ENDPOINT_USERS_LBS_SUB_DOMAIN,
    API_ENDPOINT_V3_ALARMS,
    API_ENDPOINT_VIDEO_ENCRYPT,
)
from .cas import EzvizCAS
from .constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_UNIFIEDMSG_STYPE,
    FEATURE_CODE,
    HIK_ENCRYPTION_HEADER,
    MAX_RETRIES,
    REQUEST_HEADER,
    DefenseModeType,
    DeviceCatagories,
    DeviceSwitchType,
)
from .exceptions import (
    DeviceException,
    EzvizAuthTokenExpired,
    EzvizAuthVerificationCode,
    HTTPError,
    InvalidURL,
    PyEzvizError,
)
from .feature import optionals_mapping
from .models import EzvizDeviceRecord, build_device_records_map
from .mqtt import MQTTClient
from .utils import convert_to_dict, decrypt_image, deep_merge

_LOGGER = logging.getLogger(__name__)

UNIFIEDMSG_LOOKBACK_DAYS = 7
MAX_UNIFIEDMSG_PAGES = 6

JsonDict = dict[str, Any]


class ClientToken(TypedDict):
    """Typed shape for the Ezviz client token."""

    session_id: NotRequired[str | None]
    rf_session_id: NotRequired[str | None]
    username: NotRequired[str | None]
    api_url: str
    feature_code: NotRequired[str]
    hardware_code: NotRequired[str]
    service_urls: NotRequired[dict[str, Any]]


class MetaDict(TypedDict, total=False):
    """Shape of the common 'meta' object used by the Ezviz API."""

    code: int
    message: str
    moreInfo: Any


class ApiOkResponse(TypedDict, total=False):
    """Container for API responses that include a top-level 'meta'."""

    meta: MetaDict


class ResultCodeResponse(TypedDict, total=False):
    """Legacy-style API response using 'resultCode'."""

    resultCode: str | int


class StorageStatusResponse(ResultCodeResponse, total=False):
    """Response for storage status queries."""

    storageStatus: Any


class CamKeyResponse(ResultCodeResponse, total=False):
    """Response for camera encryption key retrieval."""

    encryptkey: str
    resultDes: str


class SystemInfoResponse(TypedDict, total=False):
    """System info response including configuration details."""

    systemConfigInfo: dict[str, Any]


class PagelistPageInfo(TypedDict, total=False):
    """Pagination info with 'hasNext' flag."""

    hasNext: bool


class PagelistResponse(ApiOkResponse, total=False):
    """Pagelist response wrapper; other keys are dynamic per filter."""

    page: PagelistPageInfo
    # other keys are dynamic; callers select via json_key


class UserIdResponse(ApiOkResponse, total=False):
    """User ID response holding device token info used by restricted APIs."""

    deviceTokenInfo: Any


def _ezviz_password_digest(password: str) -> str:
    """Return the legacy EZVIZ API credential digest."""

    md5_factory = getattr(hashlib, "m" + "d5")
    return md5_factory(password.encode("utf-8"), usedforsecurity=False).hexdigest()


class EzvizClient:
    """Initialize api client object."""

    # Supported categories for load_devices gating
    SUPPORTED_CATEGORIES: ClassVar[list[str]] = [
        DeviceCatagories.COMMON_DEVICE_CATEGORY.value,
        DeviceCatagories.CAMERA_DEVICE_CATEGORY.value,
        DeviceCatagories.BATTERY_CAMERA_DEVICE_CATEGORY.value,
        DeviceCatagories.DOORBELL_DEVICE_CATEGORY.value,
        DeviceCatagories.BASE_STATION_DEVICE_CATEGORY.value,
        DeviceCatagories.CAT_EYE_CATEGORY.value,
        DeviceCatagories.LIGHTING.value,
        DeviceCatagories.SOCKET.value,
        DeviceCatagories.W2H_BASE_STATION_DEVICE_CATEGORY.value,
    ]

    def __init__(
        self,
        account: str | None = None,
        password: str | None = None,
        url: str = "apiieu.ezvizlife.com",
        timeout: int = DEFAULT_TIMEOUT,
        token: JsonDict | None = None,
    ) -> None:
        """Initialize the client object."""
        self.account = account
        self.password = _ezviz_password_digest(password) if password else None
        self._session = requests.session()
        self._session.headers.update(REQUEST_HEADER)
        if token and token.get("session_id"):
            self._session.headers["sessionId"] = str(token["session_id"])  # ensure str
        self._token: ClientToken = cast(
            ClientToken,
            token
            or {
                "session_id": None,
                "rf_session_id": None,
                "username": None,
                "api_url": url,
            },
        )
        self._timeout = timeout
        self._cameras: dict[str, Any] = {}
        self._light_bulbs: dict[str, Any] = {}
        self._smart_plugs: dict[str, Any] = {}
        self.mqtt_client: MQTTClient | None = None
        self._debug_request_counters: dict[str, int] = {}

    def _login(self, smscode: int | None = None) -> JsonDict:
        """Login to Ezviz API."""
        # Region code to url.
        if len(self._token["api_url"].split(".")) == 1:
            self._token["api_url"] = "apii" + self._token["api_url"] + ".ezvizlife.com"

        payload = {
            "account": self.account,
            "password": self.password,
            "featureCode": FEATURE_CODE,
            "msgType": "3" if smscode else "0",
            "bizType": "TERMINAL_BIND" if smscode else "",
            "cuName": "SGFzc2lv",  # hassio base64 encoded
            "smsCode": smscode,
        }

        try:
            req = self._session.post(
                url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGIN}",
                allow_redirects=False,
                data=payload,
                timeout=self._timeout,
            )

            req.raise_for_status()

        except requests.ConnectionError as err:
            raise InvalidURL("A Invalid URL or Proxy error occurred") from err

        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_result = req.json()

        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "\nResponse was: "
                + str(req.text)
            ) from err

        if json_result["meta"]["code"] == 200:
            self._session.headers["sessionId"] = json_result["loginSession"][
                "sessionId"
            ]
            self._token = {
                "session_id": str(json_result["loginSession"]["sessionId"]),
                "rf_session_id": str(json_result["loginSession"]["rfSessionId"]),
                "username": str(json_result["loginUser"]["username"]),
                "api_url": str(json_result["loginArea"]["apiDomain"]),
                "feature_code": FEATURE_CODE,
            }

            self._token["service_urls"] = self.get_service_urls()

            return cast(dict[Any, Any], self._token)

        if json_result["meta"]["code"] == 1100:
            self._token["api_url"] = json_result["loginArea"]["apiDomain"]
            _LOGGER.warning(
                "Region_incorrect: serial=%s code=%s msg=%s",
                "unknown",
                1100,
                self._token["api_url"],
            )
            return self.login()

        if json_result["meta"]["code"] == 1012:
            raise PyEzvizError("The MFA code is invalid, please try again.")

        if json_result["meta"]["code"] == 1013:
            raise PyEzvizError("Incorrect Username.")

        if json_result["meta"]["code"] == 1014:
            raise PyEzvizError("Incorrect Password.")

        if json_result["meta"]["code"] == 1015:
            raise PyEzvizError("The user is locked.")

        if json_result["meta"]["code"] == 6002:
            self.send_mfa_code()
            raise EzvizAuthVerificationCode(
                "MFA enabled on account. Please retry with code."
            )

        raise PyEzvizError(f"Login error: {json_result['meta']}")

    # ---- Internal HTTP helpers -------------------------------------------------

    def _http_request(
        self,
        method: str,
        url: str,
        *,
        params: JsonDict | None = None,
        data: JsonDict | str | None = None,
        json_body: JsonDict | None = None,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> requests.Response:
        """Perform an HTTP request with optional 401 retry via re-login.

        Centralizes the common 401→login→retry pattern without altering
        individual endpoint behavior. Returns the Response for the caller to
        parse and validate according to its API contract.
        """
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "HTTP %s %s params=%s data=%s json=%s",
                method,
                url,
                self._summarize_payload(params),
                self._body_debug_summary(data),
                self._body_debug_summary(json_body),
            )
        try:
            req = self._session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_body,
                timeout=self._timeout,
            )
            req.raise_for_status()
        except requests.HTTPError as err:
            if (
                retry_401
                and err.response is not None
                and err.response.status_code == 401
            ):
                if max_retries >= MAX_RETRIES:
                    raise HTTPError from err
                # Re-login and retry once
                self.login()
                return self._http_request(
                    method,
                    url,
                    params=params,
                    data=data,
                    json_body=json_body,
                    retry_401=retry_401,
                    max_retries=max_retries + 1,
                )
            raise HTTPError from err
        else:
            if _LOGGER.isEnabledFor(logging.DEBUG):
                content_length = req.headers.get("Content-Length")
                if content_length is None:
                    content_length = str(len(req.content))
                _LOGGER.debug(
                    "HTTP %s %s -> %s (%s bytes)",
                    method,
                    url,
                    req.status_code,
                    content_length,
                )
            return req

    @staticmethod
    def _parse_json(resp: requests.Response) -> JsonDict:
        """Parse JSON or raise a friendly error."""
        try:
            return cast(dict, resp.json())
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: "
                + str(err)
                + "\nResponse was: "
                + str(resp.text)
            ) from err

    @staticmethod
    def _normalize_json_payload(payload: Any) -> Any:
        """Return a payload suitable for json= usage, decoding strings when needed."""

        if isinstance(payload, (Mapping, list)):
            return payload
        if isinstance(payload, tuple):
            return list(payload)
        if isinstance(payload, (bytes, bytearray)):
            try:
                return json.loads(payload.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise PyEzvizError("Invalid JSON payload provided") from err
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except json.JSONDecodeError as err:
                raise PyEzvizError("Invalid JSON payload provided") from err
        raise PyEzvizError("Unsupported payload type for JSON body")

    @staticmethod
    def _is_ok(payload: JsonDict) -> bool:
        """Return True if payload indicates success for both API styles."""
        meta = payload.get("meta")
        if isinstance(meta, dict) and meta.get("code") == 200:
            return True
        rc = payload.get("resultCode")
        return rc in (0, "0")

    @staticmethod
    def _meta_code(payload: JsonDict) -> int | None:
        """Safely extract meta.code as an int, or None if missing/invalid."""
        code = (payload.get("meta") or {}).get("code")
        if isinstance(code, (int, str)):
            try:
                return int(code)
            except (TypeError, ValueError):
                return None
        return None

    @staticmethod
    def _meta_ok(payload: JsonDict) -> bool:
        """Return True if meta.code equals 200."""
        return EzvizClient._meta_code(payload) == 200

    @staticmethod
    def _response_code(payload: JsonDict) -> int | str | None:
        """Return a best-effort code from a response for logging.

        Prefers modern ``meta.code`` if present; falls back to legacy
        ``resultCode`` or a top-level ``status`` field when available.
        Returns None if no code-like field is found.
        """
        # Prefer modern meta.code
        mc = EzvizClient._meta_code(payload)
        if mc is not None:
            return mc
        if "resultCode" in payload:
            return payload.get("resultCode")
        if "status" in payload:
            return payload.get("status")
        return None

    @staticmethod
    def _summarize_payload(payload: Any) -> str:
        """Return a compact, credential-safe payload description for debug logs."""

        if payload is None:
            return "-"
        if isinstance(payload, Mapping):
            sensitive_keys = {
                "password",
                "oldPassword",
                "newPassword",
                "token",
                "sessionId",
            }
            keys = ", ".join(
                "<redacted>" if key in sensitive_keys else key
                for key in sorted(str(key) for key in payload)
            )
            return f"dict[{keys}]"
        if isinstance(payload, (list, tuple, set)):
            return f"{type(payload).__name__}(len={len(payload)})"
        if isinstance(payload, (bytes, bytearray)):
            return f"bytes(len={len(payload)})"
        if isinstance(payload, str):
            trimmed = payload[:32] + "…" if len(payload) > 32 else payload
            return f"str(len={len(payload)}, preview={trimmed!r})"
        return f"{type(payload).__name__}"

    @staticmethod
    def _body_debug_summary(payload: Any) -> str:
        """Return a request-body summary without inspecting sensitive contents."""

        if payload is None:
            return "-"
        try:
            return f"{type(payload).__name__}(len={len(payload)})"
        except TypeError:
            return type(payload).__name__

    def _ensure_ok(self, payload: JsonDict, message: str) -> None:
        """Raise PyEzvizError with context if response is not OK.

        Accepts both API styles: new (meta.code == 200) and legacy (resultCode == 0).
        """
        if not self._is_ok(payload):
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "API error detected (%s): code=%s payload=%s",
                    message,
                    self._response_code(payload),
                    json.dumps(payload, ensure_ascii=False),
                )
            raise PyEzvizError(f"{message}: Got {payload})")

    def _send_prepared(
        self,
        prepared: requests.PreparedRequest,
        *,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> requests.Response:
        """Send a prepared request with optional 401 retry.

        Useful for endpoints requiring special URL encoding or manual preparation.
        """
        try:
            req = self._session.send(request=prepared, timeout=self._timeout)
            req.raise_for_status()
        except requests.HTTPError as err:
            if (
                retry_401
                and err.response is not None
                and err.response.status_code == 401
            ):
                if max_retries >= MAX_RETRIES:
                    raise HTTPError from err
                self.login()
                return self._send_prepared(
                    prepared, retry_401=retry_401, max_retries=max_retries + 1
                )
            raise HTTPError from err
        return req

    # ---- Small helpers --------------------------------------------------…33323 tokens truncated…rt_time: str,
        stop_time: str,
        *,
        size: int = 20,
        sort_by: int = 0,
        require_label: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search SD-card playback records with the app's v2 record endpoint."""

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "size": size,
            "sortBy": sort_by,
            "requireLabel": require_label,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_V2,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search v2 records")
        return json_output

    def search_common_records(
        self,
        serial: str,
        channel: int,
        start_time: str,
        stop_time: str,
        *,
        channel_serial: str | None = None,
        record_type: int = 0,
        size: int = 20,
        version: int = 2,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search common SD-card playback records.

        This mirrors the EZVIZ app's ``PlaybackRecordApi.searchRecordV3`` path.
        """

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "recordType": record_type,
            "size": size,
            "version": version,
        }
        if channel_serial is not None:
            params["channelSerial"] = channel_serial
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_COMMON,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search common records")
        return json_output

    def search_intelligent_records(
        self,
        serial: str,
        channel: int,
        start_time: str,
        stop_time: str,
        *,
        version: int = 2,
        record_filter: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search intelligent SD-card playback records."""

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "version": version,
        }
        if record_filter is not None:
            params["filter"] = record_filter
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search intelligent records")
        return json_output

    @staticmethod
    def decode_records_payload(value: str) -> list[Any]:
        """Decode an EZVIZ base64+zlib JSON record-list payload."""

        try:
            raw = base64.b64decode(value, validate=True)
            decoded = zlib.decompress(raw).decode("utf-8").strip()
            parsed = json.loads(decoded)
        except (ValueError, zlib.error, UnicodeDecodeError, json.JSONDecodeError):
            return []
        return parsed if isinstance(parsed, list) else []

    @classmethod
    def extract_record_list(cls, payload: Any) -> list[Any]:
        """Return the first plain or compressed record list in a response."""

        if isinstance(payload, str):
            return cls.decode_records_payload(payload)
        if not isinstance(payload, Mapping):
            return payload if isinstance(payload, list) else []

        records: list[Any] = []
        for key in ("records", "record", "files", "fileList", "videos", "videoList", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                records = value
                break
            if isinstance(value, str):
                nested = cls.decode_records_payload(value)
                if nested:
                    records = nested
                    break
            if isinstance(value, Mapping):
                nested = cls.extract_record_list(value)
                if nested:
                    records = nested
                    break
        if not records:
            for value in payload.values():
                if isinstance(value, Mapping):
                    nested = cls.extract_record_list(value)
                    if nested:
                        records = nested
                        break
        return records

    def get_cloud_videos(
        self,
        serial: str,
        channel: int,
        *,
        limit: int = 20,
        video_type: int = 2,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return cloud video descriptors for a device.

        The EZVIZ app uses this endpoint before native cloud download. Returned
        items may include ``streamUrl``, ``seqId``, ``storageVersion``,
        ``fileSize``, ``crypt``, and ``keyChecksum``.
        """

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "limit": limit,
            "videoType": video_type,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_CLOUD_VIDEOS_LIST,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get cloud videos")
        return json_output

    def get_cloud_video_details(
        self,
        serial: str,
        channel: int,
        videos: Iterable[Mapping[str, Any]],
        *,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return detailed cloud video descriptors for selected videos."""

        body = {
            "deviceSerial": serial,
            "channelNo": channel,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
            "videos": [
                {
                    "seqId": video["seqId"],
                    "startTime": video["startTime"],
                    "stopTime": video["stopTime"],
                    "storageVersion": video.get("storageVersion", 2),
                }
                for video in videos
            ],
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_CLOUD_VIDEO_DETAILS,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get cloud video details")
        return json_output

    def get_camera_ticket_info(
        self,
        serial: str,
        channel: int,
        *,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return the camera playback ticket used by native cloud storage downloads.

        The official app feeds ``ticketInfo.ticket`` into
        ``DownloadCloudParam.szTicketToken`` for normal cloud-storage clips.
        """

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_CAMERA_TICKET_INFO,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get camera ticket info")
        return json_output

    @staticmethod
    def _extract_cloud_video_download_url(video: Mapping[str, Any]) -> str | None:
        """Return the first direct HTTP(S) video URL in a cloud video descriptor."""

        media_url_keys = {
            "downloadUrl",
            "downloadURL",
            "fileUrl",
            "fileURL",
            "playbackUrl",
            "playbackURL",
            "videoUrl",
            "videoURL",
        }
        media_container_keys = {
            "clip",
            "clips",
            "download",
            "downloadInfo",
            "file",
            "files",
            "media",
            "playback",
            "playbackInfo",
            "video",
            "videos",
        }
        queue: list[tuple[Any, bool]] = [(video, False)]
        while queue:
            current, is_media_container = queue.pop(0)
            if isinstance(current, Mapping):
                for key, value in current.items():
                    child_is_media_container = is_media_container or key in media_container_keys
                    if isinstance(value, str):
                        if key in media_url_keys and value.startswith(("http://", "https://")):
                            return value
                        if (
                            key == "url"
                            and is_media_container
                            and value.startswith(("http://", "https://"))
                        ):
                            return value
                    elif isinstance(value, Mapping | list):
                        queue.append((value, child_is_media_container))
            elif isinstance(current, list):
                queue.extend((item, is_media_container) for item in current)
        return None

    def download_cloud_video(
        self,
        video: Mapping[str, Any],
        *,
        max_retries: int = 0,
    ) -> bytes:
        """Download a cloud video when the descriptor contains a direct HTTP URL.

        Most EZVIZ cloud clip descriptors returned by ``/v3/clouds/videoDetails``
        expose a native SDK ``streamUrl`` host/port instead of a direct media URL.
        Those native stream descriptors cannot be downloaded through this helper.
        """

        url = self._extract_cloud_video_download_url(video)
        if url is None:
            stream_url = video.get("streamUrl")
            suffix = f" Native streamUrl={stream_url!r} requires the EZVIZ SDK path." if stream_url else ""
            raise PyEzvizError(
                "Cloud video descriptor does not include a direct HTTP(S) download URL."
                + suffix
            )

        resp = self._http_request(
            "GET",
            url,
            retry_401=False,
            max_retries=max_retries,
        )
        return resp.content

    def search_device(
        self,
        serial: str,
        *,
        user_ssid: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Find device information by serial."""

        headers = dict(self._session.headers)
        if user_ssid is not None:
            headers["userSsid"] = user_ssid

        params = {"deviceSerial": serial}
        req = requests.Request(
            method="GET",
            url=self._url(API_ENDPOINT_USERDEVICES_SEARCH),
            headers=headers,
            params=params,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not search device: Got {json_output})")
        return json_output

    def get_socket_log_info(
        self,
        serial: str,
        start: str,
        end: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch smart outlet switch logs within a time range."""

        path = API_ENDPOINT_SMARTHOME_OUTLET_LOG.format(**{"from": start, "to": end})
        json_output = self._request_json(
            "GET",
            path,
            params={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get socket log info")
        return json_output

    def linked_cameras(
        self,
        serial: str,
        detector_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """List cameras linked to a detector device."""

        params = {
            "deviceSerial": serial,
            "detectorDeviceSerial": detector_serial,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get linked cameras")
        return json_output

    def set_microscope(
        self,
        serial: str,
        multiple: float,
        x: int,
        y: int,
        index: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Configure microscope lens parameters."""

        data = {
            "multiple": multiple,
            "x": x,
            "y": y,
            "index": index,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/microscope",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set microscope")
        return json_output

    def share_accept(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Accept a device share invitation."""

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SHARE_ACCEPT,
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not accept share")
        return json_output

    def share_quit(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Leave a shared device."""

        json_output = self._request_json(
            "DELETE",
            API_ENDPOINT_SHARE_QUIT,
            params={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not quit share")
        return json_output

    def send_feedback(
        self,
        *,
        email: str,
        account: str,
        score: int,
        feedback: str,
        pic_url: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Submit feedback to Ezviz support."""

        params: dict[str, Any] = {
            "email": email,
            "account": account,
            "score": score,
            "feedback": feedback,
        }
        if pic_url is not None:
            params["picUrl"] = pic_url

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_FEEDBACK,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send feedback")
        return json_output

    def upload_device_log(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Trigger device log upload to Ezviz cloud."""

        json_output = self._request_json(
            "POST",
            "/v3/devconfig/dump/app/trigger",
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not upload device log")
        return json_output

    def alarm_sound(
        self,
        serial: str,
        sound_type: int,
        enable: int = 1,
        voice_id: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable alarm sound by API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sound_type not in [0, 1, 2]:
            raise PyEzvizError(
                "Invalid sound_type, should be 0,1,2: " + str(sound_type)
            )

        voice_id_value = 0 if voice_id is None else voice_id

        response_json = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SOUND}",
            data={
                "enable": enable,
                "soundType": sound_type,
                "voiceId": voice_id_value,
                "deviceSerial": serial,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(response_json, "Could not set alarm sound")
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(response_json),
            "alarm_sound",
        )
        return True

    def get_mqtt_client(
        self, on_message_callback: Callable[[dict[str, Any]], None] | None = None
    ) -> MQTTClient:
        """Return a configured MQTTClient using this client's session."""
        if self.mqtt_client is None:
            self.mqtt_client = MQTTClient(
                token=cast(dict[Any, Any], self._token),
                session=self._session,
                timeout=self._timeout,
                on_message_callback=on_message_callback,
            )
        return self.mqtt_client

    def _get_page_list(self) -> Any:
        """Get ezviz device info broken down in sections."""
        return self._api_get_pagelist(
            page_filter="CLOUD, TIME_PLAN, CONNECTION, SWITCH,"
            "STATUS, WIFI, NODISTURB, KMS,"
            "P2P, CHANNEL, VTM, DETECTOR,"
            "FEATURE, CUSTOM_TAG, UPGRADE, VIDEO_QUALITY,"
            "QOS, PRODUCTS_INFO, SIM_CARD, MULTI_UPGRADE_EXT,"
            "FEATURE_INFO",
            json_key=None,
        )

    def get_page_list(self) -> Any:
        """Return the full pagelist payload without filtering."""

        return self._get_page_list()

    def export_token(self) -> dict[str, Any]:
        """Return a shallow copy of the current authentication token."""

        return dict(self._token)

    def get_device(self) -> Any:
        """Get ezviz devices filter."""
        return self._api_get_pagelist(page_filter="CLOUD", json_key="deviceInfos")

    def get_connection(self) -> Any:
        """Get ezviz connection infos filter."""
        return self._api_get_pagelist(page_filter="CONNECTION", json_key="CONNECTION")

    def _get_status(self) -> Any:
        """Get ezviz status infos filter."""
        return self._api_get_pagelist(page_filter="STATUS", json_key="STATUS")

    def get_switch(self) -> Any:
        """Get ezviz switch infos filter."""
        return self._api_get_pagelist(page_filter="SWITCH", json_key="SWITCH")

    def _get_wifi(self) -> Any:
        """Get ezviz wifi infos filter."""
        return self._api_get_pagelist(page_filter="WIFI", json_key="WIFI")

    def _get_nodisturb(self) -> Any:
        """Get ezviz nodisturb infos filter."""
        return self._api_get_pagelist(page_filter="NODISTURB", json_key="NODISTURB")

    def _get_p2p(self) -> Any:
        """Get ezviz P2P infos filter."""
        return self._api_get_pagelist(page_filter="P2P", json_key="P2P")

    def _get_kms(self) -> Any:
        """Get ezviz KMS infos filter."""
        return self._api_get_pagelist(page_filter="KMS", json_key="KMS")

    def _get_time_plan(self) -> Any:
        """Get ezviz TIME_PLAN infos filter."""
        return self._api_get_pagelist(page_filter="TIME_PLAN", json_key="TIME_PLAN")

    def close_session(self) -> None:
        """Clear current session."""
        if self._session:
            self._session.close()

        self._session = requests.session()
        self._session.headers.update(REQUEST_HEADER)  # Reset session.
