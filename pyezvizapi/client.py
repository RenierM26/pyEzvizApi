"""Ezviz API."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import datetime as dt
import hashlib
import json
import logging
from typing import Any, ClassVar, NotRequired, TypedDict, cast
from urllib.parse import urlencode
from uuid import uuid4

import requests

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
    API_ENDPOINT_CANCEL_ALARM,
    API_ENDPOINT_CHANGE_DEFENCE_STATUS,
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
    API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
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
    API_ENDPOINT_SWITCH_DEFENCE_MODE,
    API_ENDPOINT_SWITCH_OTHER,
    API_ENDPOINT_SWITCH_SOUND_ALARM,
    API_ENDPOINT_SWITCH_STATUS,
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
from .camera import EzvizCamera
from .cas import EzvizCAS
from .constants import (
    DEFAULT_TIMEOUT,
    DEFAULT_UNIFIEDMSG_STYPE,
    FEATURE_CODE,
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
from .light_bulb import EzvizLightBulb
from .models import EzvizDeviceRecord, build_device_records_map
from .mqtt import MQTTClient
from .smart_plug import EzvizSmartPlug
from .utils import convert_to_dict, deep_merge

_LOGGER = logging.getLogger(__name__)

UNIFIEDMSG_LOOKBACK_DAYS = 7
MAX_UNIFIEDMSG_PAGES = 6


class ClientToken(TypedDict):
    """Typed shape for the Ezviz client token."""

    session_id: NotRequired[str | None]
    rf_session_id: NotRequired[str | None]
    username: NotRequired[str | None]
    api_url: str
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
        token: dict | None = None,
    ) -> None:
        """Initialize the client object."""
        self.account = account
        self.password = (
            hashlib.md5(password.encode("utf-8")).hexdigest() if password else None
        )  # Ezviz API sends md5 of password
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

    def _login(self, smscode: int | None = None) -> dict[Any, Any]:
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
        params: dict | None = None,
        data: dict | str | None = None,
        json_body: dict | None = None,
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
                self._summarize_payload(data),
                self._summarize_payload(json_body),
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
    def _parse_json(resp: requests.Response) -> dict:
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
    def _is_ok(payload: dict) -> bool:
        """Return True if payload indicates success for both API styles."""
        meta = payload.get("meta")
        if isinstance(meta, dict) and meta.get("code") == 200:
            return True
        rc = payload.get("resultCode")
        return rc in (0, "0")

    @staticmethod
    def _meta_code(payload: dict) -> int | None:
        """Safely extract meta.code as an int, or None if missing/invalid."""
        code = (payload.get("meta") or {}).get("code")
        if isinstance(code, (int, str)):
            try:
                return int(code)
            except (TypeError, ValueError):
                return None
        return None

    @staticmethod
    def _meta_ok(payload: dict) -> bool:
        """Return True if meta.code equals 200."""
        return EzvizClient._meta_code(payload) == 200

    @staticmethod
    def _response_code(payload: dict) -> int | str | None:
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
        """Return a compact description of payload content for debug logs."""

        if payload is None:
            return "-"
        if isinstance(payload, Mapping):
            keys = ", ".join(sorted(str(key) for key in payload))
            return f"dict[{keys}]"
        if isinstance(payload, (list, tuple, set)):
            return f"{type(payload).__name__}(len={len(payload)})"
        if isinstance(payload, (bytes, bytearray)):
            return f"bytes(len={len(payload)})"
        if isinstance(payload, str):
            trimmed = payload[:32] + "…" if len(payload) > 32 else payload
            return f"str(len={len(payload)}, preview={trimmed!r})"
        return f"{type(payload).__name__}"

    def _ensure_ok(self, payload: dict, message: str) -> None:
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

    # ---- Small helpers --------------------------------------------------------------

    def _url(self, path: str) -> str:
        """Build a full API URL for the given path."""
        return f"https://{self._token['api_url']}{path}"

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        data: dict | str | None = None,
        json_body: dict | None = None,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> dict:
        """Perform request and parse JSON in one step."""
        resp = self._http_request(
            method,
            self._url(path),
            params=params,
            data=data,
            json_body=json_body,
            retry_401=retry_401,
            max_retries=max_retries,
        )
        payload = self._parse_json(resp)
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "JSON %s %s -> status=%s meta=%s keys=%s",
                method,
                path,
                resp.status_code,
                self._response_code(payload),
                ", ".join(sorted(payload.keys())),
            )
        return payload

    def _retry_json(
        self,
        producer: Callable[[], dict],
        *,
        attempts: int,
        should_retry: Callable[[dict], bool],
        log: str,
        serial: str | None = None,
    ) -> dict:
        """Run a JSON-producing callable with retry policy.

        Calls ``producer`` up to ``attempts + 1`` times. After each call, the
        result is passed to ``should_retry``; if it returns True and attempts
        remain, a retry is performed and a concise warning is logged. If it
        returns False, the payload is returned to the caller.

        Raises:
            PyEzvizError: If retries are exhausted without a successful payload.
        """
        total = max(0, attempts)
        for attempt in range(total + 1):
            payload = producer()
            if not should_retry(payload):
                return payload
            if attempt < total:
                # Prefer modern meta.code; fall back to legacy resultCode
                code = self._response_code(payload)
                _LOGGER.warning(
                    "Http_retry: serial=%s code=%s msg=%s",
                    serial or "unknown",
                    code,
                    log,
                )
        raise PyEzvizError(f"{log}: exceeded retries")

    def send_mfa_code(self) -> bool:
        """Send verification code."""
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SEND_CODE,
            data={"from": self.account, "bizType": "TERMINAL_BIND"},
            retry_401=False,
        )

        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not request MFA code: Got {json_output})")

        return True

    def get_service_urls(self) -> Any:
        """Get Ezviz service urls."""
        if not self._token["session_id"]:
            raise PyEzvizError("No Login token present!")

        try:
            json_output = self._request_json("GET", API_ENDPOINT_SERVER_INFO)
        except requests.ConnectionError as err:  # pragma: no cover - keep behavior
            raise InvalidURL("A Invalid URL or Proxy error occurred") from err
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Error getting Service URLs: {json_output}")

        service_urls = json_output.get("systemConfigInfo", {})
        service_urls["sysConf"] = str(service_urls.get("sysConf", "")).split("|")
        return service_urls

    def lbs_domain(self, max_retries: int = 0) -> dict:
        """Retrieve the LBS sub-domain information."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERS_LBS_SUB_DOMAIN,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get LBS domain")
        return json_output

    def _api_get_pagelist(
        self,
        page_filter: str,
        json_key: str | None = None,
        group_id: int = -1,
        limit: int = 30,
        offset: int = 0,
        max_retries: int = 0,
    ) -> Any:
        """Get data from pagelist API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if page_filter is None:
            raise PyEzvizError("Trying to call get_pagelist without filter")

        params: dict[str, int | str] = {
            "groupId": group_id,
            "limit": limit,
            "offset": offset,
            "filter": page_filter,
        }

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_PAGELIST,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        if self._meta_code(json_output) != 200:
            # session is wrong, need to relogin and retry
            self.login()
            _LOGGER.warning(
                "Http_retry: serial=%s code=%s msg=%s",
                "unknown",
                self._meta_code(json_output),
                "pagelist_relogin",
            )
            return self._api_get_pagelist(
                page_filter, json_key, group_id, limit, offset, max_retries + 1
            )

        page_info = json_output.get("page") or {}
        next_page = bool(page_info.get("hasNext", False))

        data = json_output[json_key] if json_key else json_output

        if next_page:
            next_offset = offset + limit
            # Recursive call to fetch next page
            next_data = self._api_get_pagelist(
                page_filter, json_key, group_id, limit, next_offset, max_retries
            )
            # Merge data from next page into current data
            data = deep_merge(data, next_data)

        return data

    def get_alarminfo(self, serial: str, limit: int = 1, max_retries: int = 0) -> dict:
        """Get data from alarm info API for camera serial."""
        params: dict[str, int | str] = {
            "deviceSerials": serial,
            "queryType": -1,
            "limit": limit,
            "stype": -1,
        }

        json_output = self._retry_json(
            lambda: self._request_json(
                "GET",
                API_ENDPOINT_ALARMINFO_GET,
                params=params,
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: self._meta_code(p) == 500,
            log="alarm_info_server_busy",
            serial=serial,
        )
        if self._meta_code(json_output) != 200:
            raise PyEzvizError(f"Could not get data from alarm api: Got {json_output})")
        return json_output

    def get_device_messages_list(
        self,
        serials: str | None = None,
        s_type: str | int | Iterable[str | int] | None = DEFAULT_UNIFIEDMSG_STYPE,
        *,
        limit: int = 20,
        date: str | dt.date | dt.datetime | None = None,
        end_time: str | int | None = "",
        max_retries: int = 0,
    ) -> dict:
        r"""Return unified alarm/message list for the requested devices.

        Args:
            serials: Optional CSV string of serial numbers. ``None`` returns all.
            s_type: Can be a string, int, iterable of either, or
                :class:`~pyezvizapi.constants.UnifiedMessageSubtype`.
            limit: Clamp between 1 and 50 as enforced by the public API.
            date: Accepts ``YYYYMMDD`` string, :class:`datetime.date`, or
                :class:`datetime.datetime`. Defaults to "today" in API format.
            end_time: Pass the ``msgId`` (string) returned by the previous call
                for pagination. The mobile app sends an empty string to fetch the
                most recent message, so ``""`` is preserved on purpose here.
            max_retries: Number of additional attempts when the backend reports
                temporary failures. Capped by :data:`MAX_RETRIES`.
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        def _stringify(value: Any) -> str:
            raw = getattr(value, "value", value)
            return str(raw)

        stype_param: str | None
        if s_type is None:
            stype_param = DEFAULT_UNIFIEDMSG_STYPE
        elif isinstance(s_type, str):
            stype_param = s_type
        elif isinstance(s_type, Iterable) and not isinstance(
            s_type, (bytes, bytearray)
        ):
            parts = [_stringify(item) for item in s_type if item not in (None, "")]
            stype_param = ",".join(parts) if parts else DEFAULT_UNIFIEDMSG_STYPE
        else:
            stype_param = _stringify(s_type)

        if date is None:
            date_value = dt.datetime.now().strftime("%Y%m%d")
        elif isinstance(date, (dt.date, dt.datetime)):
            date_value = date.strftime("%Y%m%d")
        else:
            date_value = str(date)

        try:
            limit_value = max(1, min(int(limit), 50))
        except (TypeError, ValueError):
            limit_value = 20

        end_time_value: str = "" if end_time is None else str(end_time)

        params: dict[str, Any] = {
            "serials": serials,
            "stype": stype_param,
            "limit": limit_value,
            "date": date_value,
            "endTime": end_time_value,
        }
        filtered_params = {k: v for k, v in params.items() if v not in (None, "")}
        # keep empty string endTime to mimic app behavior
        if end_time_value == "":
            filtered_params["endTime"] = ""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_UNIFIEDMSG_LIST_GET,
            params=filtered_params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get unified message list")
        if _LOGGER.isEnabledFor(logging.DEBUG):
            counter_key = "unifiedmsg"
            self._debug_request_counters[counter_key] = (
                self._debug_request_counters.get(counter_key, 0) + 1
            )
            _LOGGER.debug(
                "req_counter[%s]=%s params=%s",
                counter_key,
                self._debug_request_counters[counter_key],
                filtered_params,
            )
        return json_output

    def add_device(
        self,
        serial: str,
        validate_code: str,
        *,
        add_type: str | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Add a new device to the current account."""

        data = {
            "deviceSerial": serial,
            "validateCode": validate_code,
        }
        if add_type is not None:
            data["addType"] = add_type
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_USERDEVICES_V2,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add device")
        return json_output

    def add_hik_activate(
        self,
        serial: str,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Activate a Hikvision device using the security endpoint."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE}{serial}",
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not activate Hik device")
        return json_output

    def add_hik_challenge(
        self,
        serial: str,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Request a Hikvision security challenge."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE}{serial}",
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not request Hik challenge")
        return json_output

    def add_local_device(
        self,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Add a device discovered on the local network."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICES_LOC,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add local device")
        return json_output

    def save_hik_dev_code(
        self,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Submit a Hikvision device code via the SCD endpoint."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SCD_APP_DEVICE_ADD,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not save Hik device code")
        return json_output

    def bind_virtual_device(
        self,
        product_id: str,
        version: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Bind a virtual IoT device using product identifier and version."""

        params = {"productId": product_id, "version": version}
        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_IOT_VIRTUAL_BIND,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not bind virtual device")
        return json_output

    def dev_config_search(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Trigger a network search on the device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork"
        json_output = self._request_json(
            "POST",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not start network search")
        return json_output

    def dev_config_send_config_command(
        self,
        serial: str,
        channel: int,
        target_serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Send a network configuration command to a target device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/command"
        json_output = self._request_json(
            "POST",
            path,
            params={"targetDeviceSerial": target_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send network command")
        return json_output

    def dev_config_wifi_list(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve Wi-Fi network list detected by the device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get Wi-Fi list")
        return json_output

    def device_between_error(
        self,
        serial: str,
        channel: int,
        target_serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve error details for a network configuration attempt."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/result"
        json_output = self._request_json(
            "GET",
            path,
            params={"targetDeviceSerial": target_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get network error info")
        return json_output

    def dev_token(self, max_retries: int = 0) -> dict:
        """Request a device token for provisioning flows."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_TOKEN,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device token")
        return json_output

    def set_switch_v3(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> dict:
        """Update a device switch via the v3 endpoint."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        enable_flag = 1 if bool(enable) else 0
        path = (
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}/{enable_flag}/"
            f"{switch_type}{API_ENDPOINT_SWITCH_STATUS}"
        )
        payload = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set the switch")
        return payload

    def set_switch_legacy(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> dict:
        """Fallback legacy switch endpoint used by older firmware."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        payload = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY,
            data={
                "serial": serial,
                "enable": "1" if bool(enable) else "0",
                "type": str(switch_type),
                "channel": str(channel),
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set the switch (legacy)")
        return payload

    def set_switch(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> dict:
        """Try the v3 switch endpoint, falling back to the legacy API if needed."""

        try:
            return self.set_switch_v3(
                serial, switch_type, enable, channel, max_retries=max_retries
            )
        except PyEzvizError as first_error:
            try:
                return self.set_switch_legacy(
                    serial, switch_type, enable, channel, max_retries=max_retries
                )
            except PyEzvizError:
                raise first_error from None

    def switch_status(
        self,
        serial: str,
        status_type: int,
        enable: bool | int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Camera features are represented as switches. Switch them on or off."""

        target_state = bool(enable)
        self.set_switch(
            serial,
            status_type,
            target_state,
            channel=channel_no,
            max_retries=max_retries,
        )
        if self._cameras.get(serial):
            self._cameras[serial]["switches"][status_type] = target_state
        return True

    def device_switch(
        self,
        serial: str,
        channel: int,
        enable: int,
        switch_type: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Direct wrapper for /v3/devices/{serial}/switch endpoint."""

        params = {
            "channelNo": channel,
            "enable": enable,
            "switchType": switch_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_SWITCH_OTHER}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not toggle device switch")
        return json_output

    def switch_status_other(
        self,
        serial: str,
        status_type: int,
        enable: int,
        channel_number: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Features are represented as switches. This api is for alternative switch types to turn them on or off.

        All day recording is a good example.
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_SWITCH_OTHER}",
            params={
                "channelNo": channel_number,
                "enable": enable,
                "switchType": status_type,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set the switch")
        return True

    def set_camera_defence(
        self,
        serial: str,
        enable: int,
        channel_no: int = 1,
        arm_type: str = "Global",
        actor: str = "V",
        max_retries: int = 0,
    ) -> bool:
        """Enable/Disable motion detection on camera."""
        json_output = self._retry_json(
            lambda: self._request_json(
                "PUT",
                f"{API_ENDPOINT_DEVICES}{serial}/{channel_no}{API_ENDPOINT_CHANGE_DEFENCE_STATUS}",
                data={"type": arm_type, "status": enable, "actor": actor},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: self._meta_code(p) == 504,
            log="arm_disarm_timeout",
            serial=serial,
        )
        if self._meta_code(json_output) != 200:
            raise PyEzvizError(
                f"Could not arm or disarm Camera {serial}: Got {json_output})"
            )
        return True

    def set_battery_camera_work_mode(self, serial: str, value: int) -> bool:
        """Set battery camera work mode."""
        return self.set_device_config_by_key(serial, value, key="batteryCameraWorkMode")

    def set_detection_mode(self, serial: str, value: int) -> bool:
        """Set detection mode.

        Deprecated in favour of set_alarm_detect_human_car() but kept for
        backwards compatibility with older callers inside the integration.
        """
        return self.set_alarm_detect_human_car(serial, value)

    def set_alarm_detect_human_car(self, serial: str, value: int) -> bool:
        """Update Alarm_DetectHumanCar type on the device."""
        return self.set_device_config_by_key(
            serial, value=f'{{"type":{value}}}', key="Alarm_DetectHumanCar"
        )

    def set_alarm_advanced_detect(self, serial: str, value: int) -> bool:
        """Update Alarm_AdvancedDetect type on the device."""
        return self.set_device_config_by_key(
            serial, value=f'{{"type":{value}}}', key="Alarm_AdvancedDetect"
        )

    def set_algorithm_param(
        self,
        serial: str,
        subtype: str | int,
        value: int,
        channel: int = 1,
    ) -> bool:
        """Update a single AlgorithmInfo subtype value via devconfig."""

        payload = {
            "AlgorithmInfo": [
                {
                    "SubType": str(subtype),
                    "Value": str(value),
                    "channel": channel,
                }
            ]
        }

        return self.set_device_config_by_key(
            serial,
            value=json.dumps(payload, separators=(",", ":")),
            key="AlgorithmInfo",
        )

    def set_night_vision_mode(
        self, serial: str, mode: int, luminance: int = 100
    ) -> bool:
        """Set night vision mode."""
        return self.set_device_config_by_key(
            serial,
            value=f'{{"graphicType":{mode},"luminance":{luminance}}}',
            key="NightVision_Model",
        )

    def set_display_mode(self, serial: str, mode: int) -> bool:
        """Change video color and saturation mode."""
        return self.set_device_config_by_key(
            serial, value=f'{{"mode":{mode}}}', key="display_mode"
        )

    def set_dev_config_kv(
        self,
        serial: str,
        channel: int,
        key: str,
        value: Mapping[str, Any] | str | bytes | float | bool,
        max_retries: int = 0,
    ) -> dict:
        """Update a device configuration key/value pair via devconfig."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if isinstance(value, Mapping):
            value_payload = json.dumps(value, separators=(",", ":"))
        elif isinstance(value, bytes):
            value_payload = value.decode()
        elif isinstance(value, bool):
            value_payload = "1" if value else "0"
        elif isinstance(value, (int, float)):
            value_payload = str(value)
        else:
            value_payload = str(value)

        data = {
            "key": key,
            "value": value_payload,
        }

        payload = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set devconfig key")
        return payload

    def set_common_key_value(
        self,
        serial: str,
        channel: int,
        key: str,
        value: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update a devconfig key/value pair using query parameters."""

        params = {
            "key": key,
            "value": value if isinstance(value, str) else str(value),
        }
        payload = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set common key value")
        return payload

    def set_device_config_by_key(
        self,
        serial: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        """Change value on device by setting key."""

        self.set_dev_config_kv(
            serial,
            1,
            key,
            value,
            max_retries=max_retries,
        )
        return True

    def set_device_key_value(
        self,
        serial: str,
        channel: int,
        key: str,
        value: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Alias for the query-based key/value setter."""

        return self.set_common_key_value(
            serial,
            channel,
            key,
            value,
            max_retries=max_retries,
        )

    def audition_request(
        self,
        serial: str,
        channel: int,
        request: str,
        payload: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Send an audition request via /v3/devconfig/op."""

        data = {
            "deviceSerial": serial,
            "channelNo": channel,
            "request": request,
            "data": payload,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVCONFIG_OP,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send audition request")
        return json_output

    def baby_control(
        self,
        serial: str,
        channel: int,
        local_index: int,
        command: str,
        action: str,
        speed: int,
        uuid: str,
        control: str,
        hardware_code: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Send the baby monitor motor control request."""

        data = {
            "deviceSerial": serial,
            "channelNo": channel,
            "localIndex": local_index,
            "command": command,
            "action": action,
            "speed": speed,
            "uuid": uuid,
            "control": control,
            "hardwareCode": hardware_code,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVCONFIG_MOTOR,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not control baby motor")
        return json_output

    def set_device_feature_by_key(
        self,
        serial: str,
        product_id: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        """Change value on device by setting the iot-feature's key.

        The FEATURE key that is part of 'device info' holds
        information about the device's functions (for example light_switch, brightness etc.).
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        payload = json.dumps({"itemKey": key, "productId": product_id, "value": value})

        full_url = f"https://{self._token['api_url']}{API_ENDPOINT_IOT_FEATURE}{serial.upper()}/0"

        headers = {
            **self._session.headers,
            "Content-Type": "application/json",
        }

        req_prep = requests.Request(
            method="PUT", url=full_url, headers=headers, data=payload
        ).prepare()

        req = self._send_prepared(req_prep, retry_401=True, max_retries=max_retries)
        json_output = self._parse_json(req)
        if not self._meta_ok(json_output):
            raise PyEzvizError(
                f"Could not set iot-feature key '{key}': Got {json_output})"
            )

        return True

    def _iot_request(
        self,
        method: str,
        endpoint: str,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        payload: Any = None,
        max_retries: int = 0,
        error_message: str,
    ) -> dict:
        """Helper to perform IoT feature/action requests with JSON payload support."""

        path = (
            f"{endpoint}{serial.upper()}/{resource_identifier}/"
            f"{local_index}/{domain_id}/{action_id}"
        )

        headers = dict(self._session.headers)
        data: str | bytes | bytearray | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            if isinstance(payload, (bytes, bytearray, str)):
                data = payload
            else:
                data = json.dumps(payload, separators=(",", ":"))

        req = requests.Request(
            method=method,
            url=self._url(path),
            headers=headers,
            data=data,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"{error_message}: Got {json_output})")
        return json_output

    def get_low_battery_keep_alive(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch low-battery keep-alive status exposed under the IoT feature API."""

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch low battery keep-alive status",
        )

    def get_object_removal_status(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        payload: Any | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Fetch object-removal (left-behind) status for supported devices."""

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            error_message="Could not fetch object removal status",
        )

    def get_remote_control_path_list(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return the remote control patrol path list for auto-tracking models."""

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch remote control path list",
        )

    def get_tracking_status(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Obtain the current subject-tracking status from the IoT feature API."""

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch tracking status",
        )

    def get_port_security(
        self,
        serial: str,
        *,
        resource_identifier: str = "Video",
        local_index: str = "1",
        domain_id: str = "NetworkSecurityProtection",
        action_id: str = "PortSecurity",
        max_retries: int = 0,
    ) -> dict:
        """Fetch port security configuration via the IoT feature API."""

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch port security status",
        )

    def set_port_security(
        self,
        serial: str,
        value: Mapping[str, Any] | dict[str, Any],
        *,
        resource_identifier: str = "Video",
        local_index: str = "1",
        domain_id: str = "NetworkSecurityProtection",
        action_id: str = "PortSecurity",
        max_retries: int = 0,
    ) -> dict:
        """Update port security configuration via the IoT feature API."""

        payload = {"value": value}
        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            error_message="Could not set port security status",
        )

    def get_device_feature_value(
        self,
        serial: str,
        resource_identifier: str,
        domain_identifier: str,
        prop_identifier: str,
        *,
        local_index: str | int = "1",
        max_retries: int = 0,
    ) -> dict:
        """Retrieve a device feature value via the IoT feature API."""

        local_idx = str(local_index)
        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_idx,
            domain_identifier,
            prop_identifier,
            max_retries=max_retries,
            error_message="Could not fetch device feature value",
        )

    def set_intelligent_fill_light(
        self,
        serial: str,
        *,
        enabled: bool,
        local_index: str = "1",
        max_retries: int = 0,
    ) -> dict:
        """Toggle the intelligent fill light mode via the IoT feature API."""

        payload = {
            "value": {
                "enabled": bool(enabled),
                "supplementLightSwitchMode": "eventIntelligence"
                if enabled
                else "irLight",
            }
        }
        body = self._normalize_json_payload(payload)
        return self.set_iot_feature(
            serial,
            resource_identifier="Video",
            local_index=local_index,
            domain_id="SupplementLightMgr",
            action_id="ImageSupplementLightModeSwitchParams",
            value=body,
            max_retries=max_retries,
        )

    def set_image_flip_iot(
        self,
        serial: str,
        *,
        enabled: bool | None = None,
        payload: Any | None = None,
        local_index: str = "1",
        max_retries: int = 0,
    ) -> dict:
        """Set image flip configuration using the IoT feature endpoint."""

        if payload is None:
            if enabled is None:
                raise PyEzvizError("Either 'enabled' or 'payload' must be provided")
            payload = {"value": {"enabled": bool(enabled)}}
        body = self._normalize_json_payload(payload)
        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            "Video",
            local_index,
            "VideoAdjustment",
            "ImageFlip",
            payload=body,
            max_retries=max_retries,
            error_message="Could not set image flip",
        )

    def set_iot_action(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        value: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Trigger an IoT action (setAction/putAction in the mobile API)."""

        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_ACTION,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=value,
            max_retries=max_retries,
            error_message="Could not execute IoT action",
        )

    def set_iot_feature(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        value: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update an IoT feature value via the feature endpoint."""

        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=value,
            max_retries=max_retries,
            error_message="Could not set IoT feature value",
        )

    def set_lens_defog_mode(
        self,
        serial: str,
        value: int,
        *,
        local_index: str = "1",
        max_retries: int = 0,
    ) -> tuple[bool, str]:
        """Update the lens defog configuration using canonical option index.

        Args:
            serial: Device serial number.
            value: Select option index (0=auto, 1=on, 2=off).
            local_index: Channel index for multi-channel devices.
            max_retries: Number of retries for transient failures.

        Returns:
            A tuple of (enabled flag, defog mode string) reflecting the
            configuration that was sent to the device.
        """

        if value == 1:
            enabled, mode = True, "open"
        elif value == 2:
            enabled, mode = False, "auto"
        else:
            enabled, mode = True, "auto"

        payload = {"value": {"enabled": enabled, "defogMode": mode}}
        self.set_iot_feature(
            serial,
            resource_identifier="Video",
            local_index=local_index,
            domain_id="LensCleaning",
            action_id="DefogCfg",
            value=payload,
            max_retries=max_retries,
        )

        return enabled, mode

    def update_device_name(
        self,
        serial: str,
        name: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Rename a device via the legacy updateName endpoint."""

        if not name:
            raise PyEzvizError("Device name must not be empty")

        data = {
            "deviceSerialNo": serial,
            "deviceName": name,
        }

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_UPDATE_NAME,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not update device name")
        return json_output

    def upgrade_device(self, serial: str, max_retries: int = 0) -> bool:
        """Upgrade device firmware."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_UPGRADE_DEVICE}{serial}/0/upgrade",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not initiate firmware upgrade")
        return True

    def get_storage_status(self, serial: str, max_retries: int = 0) -> Any:
        """Get device storage status."""
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_DEVICE_STORAGE_STATUS,
                data={"subSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="storage_status_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) != "0":
            raise PyEzvizError(
                f"Could not get device storage status: Got {json_output})"
            )
        return json_output.get("storageStatus")

    def sound_alarm(self, serial: str, enable: int = 1, max_retries: int = 0) -> bool:
        """Sound alarm on a device."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/0{API_ENDPOINT_SWITCH_SOUND_ALARM}",
            data={"enable": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set the alarm sound")
        return True

    def get_user_id(self, max_retries: int = 0) -> Any:
        """Get Ezviz userid, used by restricted api endpoints."""
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USER_ID,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get user id")
        return json_output.get("deviceTokenInfo")

    def set_video_enc(
        self,
        serial: str,
        enable: int = 1,
        camera_verification_code: str | None = None,
        new_password: str | None = None,
        old_password: str | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable or Disable video encryption."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if enable == 2 and not old_password:
            raise PyEzvizError("Old password is required when changing password.")

        if new_password and not enable == 2:
            raise PyEzvizError("New password is only required when changing password.")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{API_ENDPOINT_VIDEO_ENCRYPT}",
            data={
                "deviceSerial": serial,
                "isEncrypt": enable,
                "oldPassword": old_password,
                "password": new_password,
                "featureCode": FEATURE_CODE,
                "validateCode": camera_verification_code,
                "msgType": -1,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set video encryption")

        return True

    def device_authenticate(
        self,
        serial: str,
        *,
        need_check_code: bool,
        check_code: str | None,
        sender_type: int,
        max_retries: int = 0,
    ) -> dict:
        """Authenticate a device, optionally requiring check code."""

        data = {
            "needCheckCode": str(bool(need_check_code)).lower(),
            "checkCode": check_code or "",
            "senderType": sender_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES_AUTHENTICATE}{serial}",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not authenticate device")
        return json_output

    def reboot_camera(
        self,
        serial: str,
        delay: int = 1,
        operation: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Reboot camera."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                f"{API_ENDPOINT_DEVICE_SYS_OPERATION}{serial}",
                data={"oper": operation, "deviceSerial": serial, "delay": delay},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="reboot_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) not in ("0", 0):
            raise PyEzvizError(f"Could not reboot device {json_output})")
        return True

    def set_offline_notification(
        self,
        serial: str,
        enable: int = 1,
        req_type: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set offline notification."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_OFFLINE_NOTIFY,
                data={"reqType": req_type, "serial": serial, "status": enable},
                retry_401=True,
                max_retries=0,
            )
            result = str(json_output.get("resultCode"))
            if result == "0":
                return True
            if result == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Unable to set offline notification, camera %s is unreachable, retrying %s/%s",
                    serial,
                    attempt + 1,
                    attempts,
                )
                continue
            raise PyEzvizError(f"Could not set offline notification {json_output})")
        raise PyEzvizError("Could not set offline notification: exceeded retries")

    def device_email_alert_state(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Get email alert state for one or more devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICE_EMAIL_ALERT,
            params={"devices": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device email alert state")
        return json_output

    def save_device_email_alert_state(
        self,
        enable: bool,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update email alert state for the provided devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        data = {
            "enable": str(bool(enable)).lower(),
            "devices": serial_param,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_EMAIL_ALERT,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not save device email alert state")
        return json_output

    def get_group_defence_mode(self, max_retries: int = 0) -> Any:
        """Get group arm status. The alarm arm/disarm concept on 1st page of app."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_GROUP_DEFENCE_MODE,
            params={"groupId": -1},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get group defence status")
        return json_output.get("mode")

    # Not tested
    def cancel_alarm_device(self, serial: str, max_retries: int = 0) -> bool:
        """Cacnel alarm on an Alarm device."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_CANCEL_ALARM,
            data={"subSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not cancel alarm siren")
        return True

    def load_devices(self, refresh: bool = True) -> dict[Any, Any]:
        """Build status maps for cameras and light bulbs.

        refresh: if True, camera.status() may perform network fetches (e.g. alarms).
        Returns a combined mapping of serial -> status dict for both cameras and bulbs.

        Note: We update in place and do not remove keys for devices that may
        have disappeared. Users who intentionally remove a device can restart
        the integration to flush stale entries.
        """

        # Build lightweight records for clean gating/selection
        records = cast(dict[str, EzvizDeviceRecord], self.get_device_records(None))
        supported_categories = self.SUPPORTED_CATEGORIES

        def _is_supported_camera(rec: EzvizDeviceRecord) -> bool:
            """Return True if record should be treated as a camera."""
            if rec.device_category not in supported_categories:
                return False
            if rec.device_category == DeviceCatagories.LIGHTING.value:
                return False
            return not (
                rec.device_category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value
                and not ((rec.raw.get("deviceInfos") or {}).get("hik"))
            )

        latest_alarms: dict[str, dict[str, Any]] = {}
        if refresh:
            camera_serials = [
                serial
                for serial, record in records.items()
                if _is_supported_camera(record)
            ]
            latest_alarms = self._prefetch_latest_camera_alarms(camera_serials)

        for device, rec in records.items():
            if rec.device_category in supported_categories:
                # Add support for connected HikVision cameras
                if (
                    rec.device_category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value
                    and not (rec.raw.get("deviceInfos") or {}).get("hik")
                ):
                    continue

                if rec.device_category == DeviceCatagories.LIGHTING.value:
                    try:
                        # Create a light bulb object
                        self._light_bulbs[device] = EzvizLightBulb(
                            self, device, dict(rec.raw)
                        ).status()
                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
                elif rec.device_category == DeviceCatagories.SOCKET.value:
                    try:
                        # Create a smart plug object
                        self._smart_plugs[device] = EzvizSmartPlug(
                            self, device, dict(rec.raw)
                        ).status()
                    except (
                            PyEzvizError,
                            KeyError,
                            TypeError,
                            ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
                else:
                    try:
                        # Create camera object
                        cam = EzvizCamera(self, device, dict(rec.raw))
                        self._cameras[device] = cam.status(
                            refresh=refresh,
                            latest_alarm=latest_alarms.get(device),
                        )

                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
        return {**self._cameras, **self._light_bulbs, **self._smart_plugs}

    def _prefetch_latest_camera_alarms(
        self, serials: Iterable[str], *, chunk_size: int = 20
    ) -> dict[str, dict[str, Any]]:
        """Attempt to fetch the most recent unified message per camera serial."""
        serial_list = [serial for serial in serials if serial]
        if not serial_list:
            return {}

        latest: dict[str, dict[str, Any]] = {}

        def _query_chunk(
            missing: set[str], limit: int, *, filtered: bool
        ) -> None:
            """Populate latest alarms for a given chunk, retrying a few times."""
            attempts = 0
            while missing and attempts < MAX_UNIFIEDMSG_PAGES:
                attempts += 1
                serial_param = None if not filtered else ",".join(sorted(missing))
                try:
                    response = self.get_device_messages_list(
                        serials=serial_param,
                        limit=limit,
                        date="",
                        end_time="",
                        max_retries=1,
                    )
                except PyEzvizError as err:
                    _LOGGER.debug(
                        "alarm_prefetch_failed: serials=%s error=%r",
                        serial_param or "",
                        err,
                    )
                    return

                items = response.get("message") or response.get("messages") or []
                if not isinstance(items, list) or not items:
                    return

                matched = 0
                for item in items:
                    serial = item.get("deviceSerial")
                    if (
                        isinstance(serial, str)
                        and serial in missing
                        and serial not in latest
                    ):
                        latest[serial] = item
                        missing.discard(serial)
                        matched += 1

                # If this filtered call returned fewer entries than we still need,
                # assume remaining serials truly have no data and stop retrying.
                if filtered and matched < len(missing):
                    return

                if not response.get("hasNext"):
                    return

        remaining_serials = set(serial_list)

        # First, try a global fetch without serial filtering to capture the freshest alarms
        before = set(remaining_serials)
        _query_chunk(remaining_serials, limit=50, filtered=False)
        satisfied = before - remaining_serials
        if satisfied:
            remaining_serials.difference_update(satisfied)

        for start_idx in range(0, len(serial_list), chunk_size):
            chunk = [
                serial
                for serial in serial_list[start_idx : start_idx + chunk_size]
                if serial
            ]
            if not chunk:
                continue
            remaining = {serial for serial in chunk if serial in remaining_serials}
            if not remaining:
                continue
            chunk_key = ",".join(chunk)
            limit = min(50, max(len(chunk), 20))
            before_chunk = set(remaining)
            _query_chunk(remaining, limit, filtered=True)
            satisfied_chunk = before_chunk - remaining
            if satisfied_chunk:
                remaining_serials.difference_update(satisfied_chunk)
            if remaining:
                _LOGGER.debug(
                    "alarm_prefetch_incomplete: serials=%s missing=%s",
                    chunk_key,
                    ",".join(sorted(remaining)),
                )
        return latest

    def load_cameras(self, refresh: bool = True) -> dict[Any, Any]:
        """Load and return all camera status mappings.

        refresh: pass-through to load_devices() to control network fetches.
        """
        self.load_devices(refresh=refresh)
        return self._cameras

    def load_light_bulbs(self, refresh: bool = True) -> dict[Any, Any]:
        """Load and return all light bulb status mappings.

        refresh: pass-through to load_devices().
        """
        self.load_devices(refresh=refresh)
        return self._light_bulbs

    def load_smart_plugs(self, refresh: bool = True) -> dict[Any, Any]:
        """Load and return all smart plugs status mappings.

        refresh: pass-through to load_devices().
        """
        self.load_devices(refresh=refresh)
        return self._smart_plugs

    def get_device_infos(self, serial: str | None = None) -> dict[Any, Any]:
        """Load all devices and build dict per device serial."""
        devices = self._get_page_list()
        result: dict[str, Any] = {}
        _res_id = "NONE"

        for device in devices.get("deviceInfos", []) or []:
            _serial = device["deviceSerial"]
            _res_id_list = {
                item
                for item in devices.get("CLOUD", {})
                if devices["CLOUD"][item].get("deviceSerial") == _serial
            }
            _res_id = _res_id_list.pop() if _res_id_list else "NONE"

            result[_serial] = {
                "CLOUD": {_res_id: devices.get("CLOUD", {}).get(_res_id, {})},
                "VTM": {_res_id: devices.get("VTM", {}).get(_res_id, {})},
                "P2P": devices.get("P2P", {}).get(_serial, {}),
                "CONNECTION": devices.get("CONNECTION", {}).get(_serial, {}),
                "KMS": devices.get("KMS", {}).get(_serial, {}),
                "STATUS": devices.get("STATUS", {}).get(_serial, {}),
                "TIME_PLAN": devices.get("TIME_PLAN", {}).get(_serial, {}),
                "CHANNEL": {_res_id: devices.get("CHANNEL", {}).get(_res_id, {})},
                "QOS": devices.get("QOS", {}).get(_serial, {}),
                "NODISTURB": devices.get("NODISTURB", {}).get(_serial, {}),
                "FEATURE": devices.get("FEATURE", {}).get(_serial, {}),
                "UPGRADE": devices.get("UPGRADE", {}).get(_serial, {}),
                "FEATURE_INFO": devices.get("FEATURE_INFO", {}).get(_serial, {}),
                "SWITCH": devices.get("SWITCH", {}).get(_serial, {}),
                "CUSTOM_TAG": devices.get("CUSTOM_TAG", {}).get(_serial, {}),
                "VIDEO_QUALITY": {
                    _res_id: devices.get("VIDEO_QUALITY", {}).get(_res_id, {})
                },
                "resourceInfos": [
                    item
                    for item in (devices.get("resourceInfos") or [])
                    if isinstance(item, dict) and item.get("deviceSerial") == _serial
                ],  # Could be more than one
                "WIFI": devices.get("WIFI", {}).get(_serial, {}),
                "deviceInfos": device,
            }
            # Nested keys are still encoded as JSON strings
            try:
                support_ext = result[_serial].get("deviceInfos", {}).get("supportExt")
                if isinstance(support_ext, str) and support_ext:
                    result[_serial]["deviceInfos"]["supportExt"] = json.loads(
                        support_ext
                    )
            except (TypeError, ValueError):
                # Leave as-is if not valid JSON
                pass
            convert_to_dict(result[_serial]["STATUS"].get("optionals"))

        if not serial:
            return result

        return cast(dict[Any, Any], result.get(serial, {}))

    def get_device_records(
        self, serial: str | None = None
    ) -> dict[str, EzvizDeviceRecord] | EzvizDeviceRecord | dict[Any, Any]:
        """Return devices as EzvizDeviceRecord mapping (or single record).

        Falls back to raw when a specific serial is requested but not found.
        """
        devices = self.get_device_infos()
        records = build_device_records_map(devices)
        if serial is None:
            return records
        return records.get(serial) or devices.get(serial, {})

    def get_accessory(
        self,
        serial: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve accessory information linked to a device."""

        path = (
            f"{API_ENDPOINT_DEVICE_ACCESSORY_LINK}{serial}/{local_index}/1/linked/info"
        )
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get accessory info")
        return json_output

    def get_dev_config(
        self,
        serial: str,
        channel: int,
        key: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve a devconfig value by key."""

        params = {"key": key}
        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get devconfig value")
        return json_output

    def ptz_control(
        self, command: str, serial: str, action: str, speed: int = 5
    ) -> Any:
        """PTZ Control by API."""
        if command is None:
            raise PyEzvizError("Trying to call ptzControl without command")
        if action is None:
            raise PyEzvizError("Trying to call ptzControl without action")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_PTZCONTROL}",
            data={
                "command": command,
                "action": action,
                "channelNo": 1,
                "speed": speed,
                "uuid": str(uuid4()),
                "serial": serial,
            },
            retry_401=False,
        )

        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(json_output),
            "ptz_control",
        )

        return True

    def capture_picture(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Trigger a snapshot capture on the device."""

        path = f"/v3/devconfig/v1/{serial}/{channel}/capture"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not capture picture")
        return json_output

    def get_cam_key(
        self, serial: str, smscode: int | None = None, max_retries: int = 0
    ) -> Any:
        """Get Camera encryption key. The key that is set after the camera is added to the account.

        Args:
            serial (str): The camera serial number.
            smscode (int | None): The 2FA code account when rights elevation is required.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the camera encryption key can't be retrieved.
            EzvizAuthVerificationCode: If the account requires elevation with 2FA code.
            DeviceException: If the physical device is not reachable.

        Returns:
            Any: JSON response, filtered to return encryptkey:
                {
                    "resultCode": int,     # Result code (0 if successful)
                    "encryptkey": str,     # Camera encryption key
                    "resultDes": str       # Status message in chinese
                }
        """
        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_CAM_ENCRYPTKEY,
                data={
                    "checkcode": smscode,
                    "serial": serial,
                    "clientNo": "web_site",
                    "clientType": 3,
                    "netType": "WIFI",
                    "featureCode": FEATURE_CODE,
                    "sessionId": self._token["session_id"],
                },
                retry_401=True,
                max_retries=0,
            )

            code = str(json_output.get("resultCode"))
            if code == "20002":
                raise EzvizAuthVerificationCode(
                    f"MFA code required: Got {json_output})"
                )
            if code == "2009":
                raise DeviceException(f"Device not reachable: Got {json_output})")
            if code == "0":
                return json_output.get("encryptkey")
            if code == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Http_retry: serial=%s code=%s msg=%s",
                    serial,
                    code,
                    "cam_key_not_found",
                )
                continue
            raise PyEzvizError(
                f"Could not get camera encryption key: Got {json_output})"
            )

        raise PyEzvizError("Could not get camera encryption key: exceeded retries")

    def get_cam_auth_code(
        self,
        serial: str,
        encrypt_pwd: str | None = None,
        msg_auth_code: int | None = None,
        sender_type: int = 0,
        max_retries: int = 0,
    ) -> Any:
        """Get Camera auth code. This is the verification code on the camera sticker.

        Args:
            serial (str): The camera serial number.
            encrypt_pwd (str | None): This is always none.
            msg_auth_code (int | None): The 2FA code.
            sender_type (int): The sender type. Defaults to 0. Needs to be 3 when returning 2FA code.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the camera auth code cannot be retrieved.
            EzvizAuthVerificationCode: If the operation requires elevation with 2FA.
            DeviceException: If the physical device is not reachable.

        Returns:
            Any: JSON response, filtered to return devAuthCode:
                {
                    "devAuthCode": str,     # Device authorization code
                    "meta": {
                        "code": int,       # Status code (200 if successful)
                        "message": str,         # Status message in chinese
                        "moreInfo": null or {"INVALID_PARAMETER": str}
                    }
                }
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        params: dict[str, int | str | None] = {
            "encrptPwd": encrypt_pwd,
            "msgAuthCode": msg_auth_code,
            "senderType": sender_type,
        }

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_CAM_AUTH_CODE}{serial}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )

        if self._meta_code(json_output) == 80000:
            raise EzvizAuthVerificationCode("Operation requires 2FA check")

        if self._meta_code(json_output) == 2009:
            raise DeviceException(f"Device not reachable: Got {json_output}")

        if not self._meta_ok(json_output):
            raise PyEzvizError(
                f"Could not get camera verification key: Got {json_output}"
            )

        return json_output["devAuthCode"]

    def get_2fa_check_code(
        self,
        biz_type: str = "DEVICE_AUTH_CODE",
        username: str | None = None,
        max_retries: int = 0,
    ) -> Any:
        """Initiate 2FA check for sensitive operations. Elevates your session token permission.

        Args:
            biz_type (str): The operation type. (DEVICE_ENCRYPTION | DEVICE_AUTH_CODE)
            username (str): The account username.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the operation fails.

        Returns:
            Any: JSON response with the following structure:
                {
                    "meta": {
                        "code": int,       # Status code (200 if successful)
                        "message": str         # Status message in chinese
                        "moreInfo": null
                    },
                    "contact": {
                        "type": str,   # 2FA code will be sent to this (EMAIL)
                        "fuzzyContact": str     # Destination value (e.g., someone@email.local)
                    }
                }
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
            data={"bizType": biz_type, "from": username},
            retry_401=True,
            max_retries=max_retries,
        )

        if not self._meta_ok(json_output):
            raise PyEzvizError(
                f"Could not request elevated permission: Got {json_output})"
            )

        return json_output

    def create_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Create panoramic image."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_CREATE_PANORAMIC,
                data={"deviceSerial": serial},
                retry_401=True,
                max_retries=0,
            )
            result = str(json_output.get("resultCode"))
            if result == "0":
                return json_output
            if result == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Create panoramic failed on device %s retrying %s/%s",
                    serial,
                    attempt + 1,
                    attempts,
                )
                continue
            raise PyEzvizError(
                f"Could not send command to create panoramic photo: Got {json_output})"
            )
        raise PyEzvizError(
            "Could not send command to create panoramic photo: exceeded retries"
        )

    def return_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Return panoramic image url list."""
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_RETURN_PANORAMIC,
                data={"deviceSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="panoramic_busy_or_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) != "0":
            raise PyEzvizError(f"Could retrieve panoramic photo: Got {json_output})")
        return json_output

    def ptz_control_coordinates(
        self, serial: str, x_axis: float, y_axis: float
    ) -> bool:
        """PTZ Coordinate Move."""
        if 0 < x_axis > 1:
            raise PyEzvizError(
                f"Invalid X coordinate: {x_axis}: Should be between 0 and 1 inclusive"
            )

        if 0 < y_axis > 1:
            raise PyEzvizError(
                f"Invalid Y coordinate: {y_axis}: Should be between 0 and 1 inclusive"
            )

        json_result = self._request_json(
            "POST",
            API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
            data={
                "x": f"{x_axis:.6f}",
                "y": f"{y_axis:.6f}",
                "deviceSerial": serial,
            },
            retry_401=False,
        )

        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(json_result),
            "ptz_control_coordinates",
        )

        return True

    def get_door_lock_users(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve users associated with a door lock device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DOORLOCK_USERS}{serial}/users",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get door lock users")
        return json_output

    def remote_unlock(
        self,
        serial: str,
        user_id: str,
        lock_no: int,
        *,
        resource_id: str | None = None,
        local_index: str | int | None = None,
        stream_token: str | None = None,
        lock_type: str | None = None,
    ) -> bool:
        """Sends a remote command to unlock a specific lock.

        Args:
            serial (str): The camera serial.
            user_id (str): The user id.
            lock_no (int): The lock number.
            resource_id (str, optional): Resource identifier reported by the device
                (for example ``Video`` or ``DoorLock``). Defaults to ``"Video"``.
            local_index (str | int, optional): Local channel index for the lock.
                Defaults to ``"1"``.
            stream_token (str, optional): Stream token associated with the lock if
                provided by the API. Defaults to empty string when omitted.
            lock_type (str, optional): Optional lock type hint used by some devices.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        route_resource = resource_id or "Video"
        route_index = str(local_index if local_index is not None else 1)
        un_lock_info: dict[str, Any] = {
            "bindCode": f"{FEATURE_CODE}{user_id}",
            "lockNo": lock_no,
            "streamToken": stream_token or "",
            "userName": user_id,
        }
        if lock_type:
            un_lock_info["type"] = lock_type
        payload = {"unLockInfo": un_lock_info}
        json_result = self._request_json(
            "PUT",
            f"{API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{API_ENDPOINT_REMOTE_UNLOCK}",
            json_body=payload,
            retry_401=True,
            max_retries=0,
        )
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._response_code(json_result),
            "remote_unlock",
        )
        return True

    def remote_lock(
        self,
        serial: str,
        user_id: str,
        lock_no: int,
        *,
        resource_id: str | None = None,
        local_index: str | int | None = None,
        stream_token: str | None = None,
        lock_type: str | None = None,
    ) -> bool:
        """Send a remote lock command to a specific lock."""

        route_resource = resource_id or "Video"
        route_index = str(local_index if local_index is not None else 1)
        un_lock_info: dict[str, Any] = {
            "bindCode": f"{FEATURE_CODE}{user_id}",
            "lockNo": lock_no,
            "streamToken": stream_token or "",
            "userName": user_id,
        }
        if lock_type:
            un_lock_info["type"] = lock_type
        payload = {"unLockInfo": un_lock_info}
        json_result = self._request_json(
            "PUT",
            f"{API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{API_ENDPOINT_REMOTE_LOCK}",
            json_body=payload,
            retry_401=True,
            max_retries=0,
        )
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._response_code(json_result),
            "remote_lock",
        )
        return True

    def get_remote_unbind_progress(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Check progress of a remote unbind request."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_REMOTE_UNBIND_PROGRESS}{serial}/progress",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get unbind progress")
        return json_output

    def login(self, sms_code: int | None = None) -> dict[Any, Any]:
        """Get or refresh ezviz login token."""
        if self._token["session_id"] and self._token["rf_session_id"]:
            try:
                req = self._session.put(
                    url=f"https://{self._token['api_url']}{API_ENDPOINT_REFRESH_SESSION_ID}",
                    data={
                        "refreshSessionId": self._token["rf_session_id"],
                        "featureCode": FEATURE_CODE,
                    },
                    timeout=self._timeout,
                )
                req.raise_for_status()

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
                self._session.headers["sessionId"] = json_result["sessionInfo"][
                    "sessionId"
                ]
                self._token["session_id"] = str(json_result["sessionInfo"]["sessionId"])
                self._token["rf_session_id"] = str(
                    json_result["sessionInfo"]["refreshSessionId"]
                )

                if not self._token.get("service_urls"):
                    self._token["service_urls"] = self.get_service_urls()

                return cast(dict[Any, Any], self._token)

            if json_result["meta"]["code"] == 403:
                if self.account and self.password:
                    self._token = {
                        "session_id": None,
                        "rf_session_id": None,
                        "username": None,
                        "api_url": self._token["api_url"],
                    }
                    return self.login()

                raise EzvizAuthTokenExpired(
                    f"Token expired, Login with username and password required: {req.text}"
                )

            raise PyEzvizError(f"Error renewing login token: {json_result['meta']}")

        if self.account and self.password:
            return self._login(sms_code)

        raise PyEzvizError("Login with account and password required")

    def logout(self) -> bool:
        """Close Ezviz session and remove login session from ezviz servers."""
        try:
            req = self._session.delete(
                url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGOUT}",
                timeout=self._timeout,
            )
            req.raise_for_status()

        except requests.HTTPError as err:
            if err.response.status_code == 401:
                _LOGGER.warning(
                    "Http_warning: serial=%s code=%s msg=%s",
                    "unknown",
                    401,
                    "logout_already_invalid",
                )
                return True
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

        self.close_session()

        return bool(json_result["meta"]["code"] == 200)

    def set_camera_defence_old(self, serial: str, enable: int) -> bool:
        """Enable/Disable motion detection on camera."""
        cas_client = EzvizCAS(cast(dict[str, Any], self._token))
        cas_client.set_camera_defence_state(serial, enable)

        return True

    def api_set_defence_schedule(
        self, serial: str, schedule: str, enable: int, max_retries: int = 0
    ) -> bool:
        """Set defence schedules."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        schedulestring = (
            '{"CN":0,"EL":'
            + str(enable)
            + ',"SS":"'
            + serial
            + '","WP":['
            + schedule
            + "]}]}"
        )
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_SET_DEFENCE_SCHEDULE,
                data={"devTimingPlan": schedulestring},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="defence_schedule_offline_or_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) not in ("0", 0):
            raise PyEzvizError(f"Could not set the schedule: Got {json_output})")
        return True

    def api_set_defence_mode(
        self,
        mode: DefenseModeType | int,
        *,
        visual_alarm: int | None = None,
        sound_mode: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Set defence mode for all devices. The alarm panel from main page is used."""
        data: dict[str, Any] = {
            "groupId": -1,
            "mode": int(mode.value if isinstance(mode, DefenseModeType) else mode),
        }
        if visual_alarm is not None:
            data["visualAlarm"] = visual_alarm
        if sound_mode is not None:
            data["soundMode"] = sound_mode

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SWITCH_DEFENCE_MODE,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set defence mode")
        return True

    def switch_defence_mode(
        self,
        group_id: int,
        mode: int,
        *,
        visual_alarm: int | None = None,
        sound_mode: int | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Set defence mode for a specific group with optional sound/visual flags."""

        data: dict[str, Any] = {
            "groupId": group_id,
            "mode": mode,
        }
        if visual_alarm is not None:
            data["visualAlarm"] = visual_alarm
        if sound_mode is not None:
            data["soundMode"] = sound_mode

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SWITCH_DEFENCE_MODE,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not switch defence mode")
        return json_output

    def do_not_disturb(
        self,
        serial: str,
        enable: int = 1,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set do not disturb on camera with specified serial."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_V3_ALARMS}{serial}/{channelno}{API_ENDPOINT_DO_NOT_DISTURB}",
            data={"enable": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set do not disturb")
        return True

    def set_answer_call(
        self,
        serial: str,
        enable: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set answer call on camera with specified serial."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_CALLING_NOTIFY}{serial}{API_ENDPOINT_DO_NOT_DISTURB}",
            data={"deviceSerial": serial, "switchStatus": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set answer call")

        return True

    def manage_intelligent_app(
        self,
        serial: str,
        resource_id: str,
        app_name: str,
        action: str = "add",
        max_retries: int = 0,
    ) -> bool:
        """Manage the intelligent app on the camera by adding (add) or removing (remove) it.

        Args:
            serial (str): The camera serial.
            resource_id (str): The resource identifier of the camera.
            app_name (str): The intelligent app name.
                "app_video_change" = Image change detection,
                "app_human_detect" = Human shape detection,
                "app_car_detect" = Vehicle detection,
                "app_wave_recognize" = Gesture recognition
            action (str, optional): Add or remove app ("add" or "remove"). Defaults to "add".
            max_retries (int, optional): Number of retries attempted. Defaults to 0.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")
        url_path = f"{API_ENDPOINT_INTELLIGENT_APP}{serial}/{resource_id}/{app_name}"
        # Determine which method to call based on the parameter.
        action = action.lower()
        if action == "add":
            method = "PUT"
        elif action == "remove":
            method = "DELETE"
        else:
            raise PyEzvizError(f"Invalid action '{action}'. Use 'add' or 'remove'.")

        json_output = self._request_json(
            method, url_path, retry_401=True, max_retries=max_retries
        )
        self._ensure_ok(json_output, f"Could not {action} intelligent app")

        return True

    def _resolve_resource_id(self, serial: str, resource_id: str | None) -> str:
        """Resolve the intelligent app resource id for a given camera."""

        if resource_id:
            return resource_id

        camera = self._cameras.get(serial)
        if not camera:
            raise PyEzvizError(
                f"Unknown camera serial {serial}. Call load_devices/load_cameras first"
            )

        resource_infos = camera.get("resourceInfos") or []
        for item in resource_infos:
            if isinstance(item, dict) and item.get("resourceId"):
                return cast(str, item["resourceId"])

        legacy = camera.get("resouceid") or camera.get("resource_id")
        if isinstance(legacy, str) and legacy:
            return legacy

        raise PyEzvizError(
            "Unable to determine resourceId for intelligent app operation"
        )

    def set_intelligent_app_state(
        self,
        serial: str,
        app_name: str,
        enabled: bool,
        resource_id: str | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable or disable an intelligent detection app on a camera."""

        resolved_id = self._resolve_resource_id(serial, resource_id)
        action = "add" if enabled else "remove"
        return self.manage_intelligent_app(
            serial,
            resolved_id,
            app_name,
            action=action,
            max_retries=max_retries,
        )

    def device_mirror(
        self,
        serial: str,
        channel: int,
        command: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Send a mirror command using the basics API."""

        path = f"{API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/{command}/mirror"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set mirror state")
        return json_output

    def flip_image(
        self,
        serial: str,
        channel: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Flips the camera image when called.

        Args:
            serial (str): The camera serial.
            channel (int, optional): The camera channel number to flip. Defaults to 1.
            max_retries (int, optional): Number of retries attempted. Defaults to 0.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/CENTER/mirror",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not flip image on camera")

        return True

    def _resolve_osd_text(
        self,
        serial: str,
        *,
        name: str | None = None,
        camera_data: Mapping[str, Any] | None = None,
    ) -> str:
        """Return the preferred OSD label for a camera."""

        if isinstance(name, str) and name.strip():
            return name.strip()

        candidates: list[Mapping[str, Any]] = []

        if isinstance(camera_data, Mapping):
            candidates.append(camera_data)

        cached = self._cameras.get(serial)
        if isinstance(cached, Mapping):
            candidates.append(cached)

        for data in candidates:
            direct = data.get("name")
            if isinstance(direct, str) and direct.strip():
                return direct.strip()

            device_info = data.get("deviceInfos")
            if isinstance(device_info, Mapping):
                alt = device_info.get("name")
                if isinstance(alt, str) and alt.strip():
                    return alt.strip()

            optionals = optionals_mapping(data)
            osd_entries = optionals.get("OSD")
            if isinstance(osd_entries, Mapping):
                osd_entries = [osd_entries]
            if isinstance(osd_entries, list):
                for entry in osd_entries:
                    if not isinstance(entry, Mapping):
                        continue
                    text = entry.get("name")
                    if isinstance(text, str) and text.strip():
                        return text.strip()

        return serial

    def set_camera_osd(
        self,
        serial: str,
        text: str | None = None,
        *,
        enabled: bool | None = None,
        name: str | None = None,
        camera_data: Mapping[str, Any] | None = None,
        channel: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set or clear the on-screen display text for a camera.

        Args:
            serial: Camera serial number that should receive the update.
            text: Explicit OSD label to apply. If provided it takes precedence over
                all other inputs and `enabled` is ignored.
            enabled: Convenience flag used when `text` is omitted. When set to
                `True`, the client derives a label automatically (optionally using
                `name`/`camera_data`). When `False`, the overlay is cleared.
            name: Optional friendly name to favour when building the automatic
                overlay text.
            camera_data: Optional camera payload (matching coordinator data) that
                can be inspected for existing OSD labels and names.
            channel: Camera channel identifier (defaults to the primary channel).
            max_retries: Number of retry attempts for transient API failures.

        Returns:
            bool: ``True`` when the request is accepted by the Ezviz backend.
        """

        if text is not None:
            resolved = text
        elif enabled is False:
            resolved = ""
        else:
            if camera_data is None:
                camera_data = self._cameras.get(serial)
            if camera_data is None:
                raise PyEzvizError(
                    "Camera data unavailable; call load_devices() before setting the OSD"
                )

            resolved = (
                self._resolve_osd_text(
                    serial,
                    name=name,
                    camera_data=camera_data,
                )
                if enabled
                else ""
            )

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_OSD}{serial}/{channel}/osd",
            data={"osd": resolved},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could set osd message on camera")

        return True

    def set_floodlight_brightness(
        self,
        serial: str,
        luminance: int = 50,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool | str:
        """Set brightness on camera with adjustable light."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if luminance not in range(1, 100):
            raise PyEzvizError(
                "Range of luminance is 1-100, got " + str(luminance) + "."
            )

        response_json = self._request_json(
            "POST",
            f"{API_ENDPOINT_SET_LUMINANCE}{serial}/{channelno}",
            data={"luminance": luminance},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(response_json, "Unable to set brightness")

        return True

    def set_brightness(
        self,
        serial: str,
        luminance: int = 50,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool | str:
        """Facade that changes the brightness to light bulbs or cameras' light."""
        device = self._light_bulbs.get(serial)
        if device:
            # the device is a light bulb
            return self.set_device_feature_by_key(
                serial, device["productId"], luminance, "brightness", max_retries
            )

        # assume the device is a camera
        return self.set_floodlight_brightness(serial, luminance, channelno, max_retries)

    def switch_light_status(
        self,
        serial: str,
        enable: int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Facade that turns on/off light bulbs or cameras' light."""
        device = self._light_bulbs.get(serial)
        if device:
            # the device is a light bulb
            return self.set_device_feature_by_key(
                serial, device["productId"], bool(enable), "light_switch", max_retries
            )

        # assume the device is a camera
        return self.switch_status(
            serial, DeviceSwitchType.ALARM_LIGHT.value, enable, channel_no, max_retries
        )

    def detection_sensibility(
        self,
        serial: str,
        sensibility: int = 3,
        type_value: int = 3,
        max_retries: int = 0,
    ) -> bool | str:
        """Set detection sensibility."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sensibility not in [0, 1, 2, 3, 4, 5, 6] and type_value == 0:
            raise PyEzvizError(
                "Unproper sensibility for type 0 (should be within 1 to 6)."
            )
        try:
            req = self._session.post(
                url=f"https://{self._token['api_url']}{API_ENDPOINT_DETECTION_SENSIBILITY}",
                data={
                    "subSerial": serial,
                    "type": type_value,
                    "channelNo": 1,
                    "value": sensibility,
                },
                timeout=self._timeout,
            )

            req.raise_for_status()

        except requests.HTTPError as err:
            if err.response.status_code == 401:
                # session is wrong, need to re-log-in
                self.login()
                return self.detection_sensibility(
                    serial, sensibility, type_value, max_retries + 1
                )

            raise HTTPError from err

        try:
            response_json = req.json()

        except ValueError as err:
            raise PyEzvizError("Could not decode response:" + str(err)) from err

        if response_json["resultCode"] != "0":
            if response_json["resultCode"] == "-1":
                _LOGGER.warning(
                    "Camera %s is offline or unreachable, can't set sensitivity, retrying %s of %s",
                    serial,
                    max_retries,
                    MAX_RETRIES,
                )
                return self.detection_sensibility(
                    serial, sensibility, type_value, max_retries + 1
                )
            raise PyEzvizError(
                f"Unable to set detection sensibility. Got: {response_json}"
            )

        return True

    def get_motion_detect_sensitivity(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Get motion detection sensitivity via v1 devconfig endpoint."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_SENSITIVITY}{serial}/{channel}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get motion detect sensitivity")
        return json_output

    def get_motion_detect_sensitivity_dp1s(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Get motion detection sensitivity for DP1S devices."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}/sensitivity",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get DP1S motion sensitivity")
        return json_output

    def set_detection_sensitivity(
        self,
        serial: str,
        channel: int,
        sensitivity_type: int,
        value: int,
        max_retries: int = 0,
    ) -> bool:
        """Set detection sensitivity via v3 devconfig endpoint."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sensitivity_type == 0 and not 1 <= value <= 6:
            raise PyEzvizError("Detection sensitivity must be within 1..6")
        if sensitivity_type != 0 and not 1 <= value <= 100:
            raise PyEzvizError("Detection sensitivity must be within 1..100")

        url_path = (
            f"{API_ENDPOINT_SENSITIVITY}{serial}/{channel}/{sensitivity_type}/{value}"
        )
        json_output = self._request_json(
            "PUT",
            url_path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set detection sensitivity")

        return True

    def get_detection_sensibility(
        self, serial: str, type_value: str = "0", max_retries: int = 0
    ) -> Any:
        """Get detection sensibility notifications."""
        response_json = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_DETECTION_SENSIBILITY_GET,
                data={"subSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log=f"Camera {serial} is offline or unreachable",
        )
        if str(response_json.get("resultCode")) != "0":
            raise PyEzvizError(
                f"Unable to get detection sensibility. Got: {response_json}"
            )

        if response_json.get("algorithmConfig", {}).get("algorithmList"):
            for idx in response_json["algorithmConfig"]["algorithmList"]:
                if idx.get("type") == type_value:
                    return idx.get("value")

        return None

    def get_detector_setting_info(
        self,
        device_serial: str,
        detector_serial: str,
        key: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch a specific configuration key for an A1S detector."""

        path = (
            f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/"
            f"{detector_serial}/{key}"
        )
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get detector setting info")
        return json_output

    def set_detector_setting_info(
        self,
        device_serial: str,
        detector_serial: str,
        key: str,
        value: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update a configuration key for an A1S detector."""

        path = (
            f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/{detector_serial}"
        )
        json_output = self._request_json(
            "POST",
            path,
            params={"key": key},
            data={"value": value},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set detector setting info")
        return json_output

    def get_detector_info(
        self,
        detector_serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve status/details for an A1S detector."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}detector/{detector_serial}"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get detector info")
        return json_output

    def get_radio_signals(
        self,
        device_serial: str,
        child_device_serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return radio signal metrics for a detector connected to a device."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/radioSignal"
        json_output = self._request_json(
            "GET",
            path,
            params={"childDevSerial": child_device_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get radio signals")
        return json_output

    def get_voice_config(
        self,
        product_id: str,
        version: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch voice configuration metadata for a product."""

        params = {"productId": product_id, "version": version}
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get voice config")
        return json_output

    # soundtype: 0 = normal, 1 = intensive, 2 = disabled ... don't ask me why...
    def get_voice_info(
        self,
        serial: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve uploaded custom voice prompts for a device."""

        params: dict[str, Any] = {"deviceSerial": serial}
        if local_index is not None:
            params["localIndex"] = local_index

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get voice list")
        return json_output

    def add_voice_info(
        self,
        serial: str,
        voice_name: str,
        voice_url: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Upload metadata for a new custom voice prompt."""

        data: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceName": voice_name,
            "voiceUrl": voice_url,
        }
        if local_index is not None:
            data["localIndex"] = local_index

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add voice info")
        return json_output

    def add_shared_voice_info(
        self,
        serial: str,
        voice_name: str,
        voice_url: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Upload a shared voice with explicit local index, mirroring the mobile API."""

        return self.add_voice_info(
            serial,
            voice_name,
            voice_url,
            local_index=local_index,
            max_retries=max_retries,
        )

    def set_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_name: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Update metadata for an existing voice prompt."""

        data: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceId": voice_id,
            "voiceName": voice_name,
        }
        if local_index is not None:
            data["localIndex"] = local_index

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not update voice info")
        return json_output

    def set_shared_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_name: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Alias for updating shared voices that ensures local index is supplied."""

        return self.set_voice_info(
            serial,
            voice_id,
            voice_name,
            local_index=local_index,
            max_retries=max_retries,
        )

    def delete_voice_info(
        self,
        serial: str,
        voice_id: int,
        *,
        voice_url: str | None = None,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict:
        """Remove a voice prompt from a device."""

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceId": voice_id,
        }
        if voice_url is not None:
            params["voiceUrl"] = voice_url
        if local_index is not None:
            params["localIndex"] = local_index

        json_output = self._request_json(
            "DELETE",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not delete voice info")
        return json_output

    def delete_shared_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_url: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Alias for deleting shared voices with required parameters."""

        return self.delete_voice_info(
            serial,
            voice_id,
            voice_url=voice_url,
            local_index=local_index,
            max_retries=max_retries,
        )

    def get_whistle_status_by_channel(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return whistle configuration per channel for a device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get whistle status by channel")
        return json_output

    def get_whistle_status_by_device(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return whistle configuration at the device level."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get whistle status by device")
        return json_output

    def set_channel_whistle(
        self,
        serial: str,
        channel_whistles: list[Mapping[str, Any]] | list[dict[str, Any]],
        *,
        max_retries: int = 0,
    ) -> dict:
        """Configure whistle behaviour for individual channels."""

        if not channel_whistles:
            raise PyEzvizError("channel_whistles must contain at least one entry")

        entries: list[dict[str, Any]] = []
        required_fields = {"channel", "status", "duration", "volume"}
        for item in channel_whistles:
            entry = dict(item)
            entry.setdefault("deviceSerial", serial)
            missing = [field for field in required_fields if field not in entry]
            if missing:
                raise PyEzvizError(
                    "channel_whistles entries must include " + ", ".join(missing)
                )
            entries.append(entry)

        payload = {"channelWhistleList": entries}

        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE}",
            json_body=payload,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set channel whistle")
        return json_output

    def set_device_whistle(
        self,
        serial: str,
        *,
        status: int,
        duration: int,
        volume: int,
        max_retries: int = 0,
    ) -> dict:
        """Configure whistle behaviour at the device level."""

        params = {
            "status": status,
            "duration": duration,
            "volume": volume,
        }

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set device whistle")
        return json_output

    def stop_whistle(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Stop any ongoing whistle sound."""

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_STOP_WHISTLE}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not stop whistle")
        return json_output

    def delay_battery_device_sleep(
        self,
        serial: str,
        channel: int,
        sleep_type: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Request additional awake time for a battery-powered device."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY}{serial}/{channel}/{sleep_type}/sleep"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not delay battery device sleep")
        return json_output

    def get_device_chime_info(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch chime configuration for a specific channel."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get chime info")
        return json_output

    def set_device_chime_info(
        self,
        serial: str,
        channel: int,
        *,
        sound_type: int,
        duration: int,
        max_retries: int = 0,
    ) -> dict:
        """Update chime type and duration for a channel."""

        data = {
            "type": sound_type,
            "duration": duration,
        }

        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set chime info")
        return json_output

    def set_switch_enable_req(
        self,
        serial: str,
        channel: int,
        enable: int,
        switch_type: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Call the legacy setSwitchEnableReq endpoint."""

        params = {
            "enable": enable,
            "type": switch_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}{API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set switch enable request")
        return json_output

    def get_managed_device_info(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return metadata for a managed device (e.g. base station)."""

        path = f"{API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/base"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get managed device info")
        return json_output

    def get_managed_device_ipcs(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """List IPC sub-devices that belong to a managed device."""

        path = f"{API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/ipcs"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get managed IPC list")
        return json_output

    def get_devices_status(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch online/offline status for one or more devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_STATUS,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device status")
        return json_output

    def get_device_secret_key_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve KMS secret key metadata for devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_KMS,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device secret key info")
        return json_output

    def get_device_list_encrypt_key(
        self,
        area_id: int,
        form_data: Mapping[str, Any] | bytes | bytearray | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Batch query encrypt keys for devices, matching the mobile client's risk API."""

        headers = {
            **self._session.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "areaId": str(area_id),
        }
        if isinstance(form_data, (bytes, bytearray, str)):
            body = form_data
        else:
            body = urlencode(form_data, doseq=True)
        req = requests.Request(
            method="POST",
            url=self._url(API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH),
            headers=headers,
            data=body,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(
                f"Could not get device encrypt key list: Got {json_output})"
            )
        return json_output

    def get_p2p_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve P2P info via the device-scoped endpoint."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICES_P2P_INFO,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get P2P info")
        return json_output

    def get_p2p_server_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve P2P server info via the userdevices endpoint."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_P2P_INFO,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get P2P server info")
        return json_output

    def check_device_upgrade_rule(
        self,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Check firmware upgrade eligibility rules."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_UPGRADE_RULE,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get upgrade rules")
        return json_output

    def get_autoupgrade_switch(
        self,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Return the current auto-upgrade switch settings."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_AUTOUPGRADE_SWITCH,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get auto-upgrade switch")
        return json_output

    def set_autoupgrade_switch(
        self,
        auto_upgrade: int,
        time_type: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update the auto-upgrade switch configuration."""

        data = {
            "autoUpgrade": auto_upgrade,
            "timeType": time_type,
        }

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_AUTOUPGRADE_SWITCH,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set auto-upgrade switch")
        return json_output

    def get_black_level_list(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Retrieve SD-card black level data for a device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_SDCARD_BLACK_LEVEL}{serial}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get black level list")
        return json_output

    def get_time_plan_infos(
        self,
        serial: str,
        channel: int,
        timing_plan_type: int,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Fetch timing plan information for a device/channel."""

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "timingPlanType": timing_plan_type,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_TIME_PLAN_INFOS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get time plan infos")
        return json_output

    def set_time_plan_infos(
        self,
        serial: str,
        channel: int,
        timing_plan_type: int,
        enable: int,
        timer_defence_qos: Any,
        *,
        max_retries: int = 0,
    ) -> dict:
        """Update timing plan configuration."""

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "timingPlanType": timing_plan_type,
            "enable": enable,
        }
        if not isinstance(timer_defence_qos, str):
            params["timerDefenceQos"] = json.dumps(timer_defence_qos)
        else:
            params["timerDefenceQos"] = timer_defence_qos

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_TIME_PLAN_INFOS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set time plan infos")
        return json_output

    def search_records(
        self,
        serial: str,
        channel: int,
        channel_serial: str,
        start_time: str,
        stop_time: str,
        *,
        size: int = 20,
        max_retries: int = 0,
    ) -> dict:
        """Search recorded video clips for a device."""

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "channelSerial": channel_serial,
            "startTime": start_time,
            "stopTime": stop_time,
            "size": size,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search records")
        return json_output

    def search_device(
        self,
        serial: str,
        *,
        user_ssid: str | None = None,
        max_retries: int = 0,
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
    ) -> dict:
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
            "P2P, TIME_PLAN, CHANNEL, VTM, DETECTOR,"
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
