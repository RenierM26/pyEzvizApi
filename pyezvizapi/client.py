"""Ezviz API."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import hashlib
import json
import logging
from typing import Any, ClassVar, TypedDict, cast
import urllib.parse
from uuid import uuid4

import requests

from .api_endpoints import (
    API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
    API_ENDPOINT_ALARM_SOUND,
    API_ENDPOINT_ALARMINFO_GET,
    API_ENDPOINT_CALLING_NOTIFY,
    API_ENDPOINT_CAM_AUTH_CODE,
    API_ENDPOINT_CAM_ENCRYPTKEY,
    API_ENDPOINT_CANCEL_ALARM,
    API_ENDPOINT_CHANGE_DEFENCE_STATUS,
    API_ENDPOINT_CREATE_PANORAMIC,
    API_ENDPOINT_DETECTION_SENSIBILITY,
    API_ENDPOINT_DETECTION_SENSIBILITY_GET,
    API_ENDPOINT_DEVCONFIG_BY_KEY,
    API_ENDPOINT_DEVICE_BASICS,
    API_ENDPOINT_DEVICE_STORAGE_STATUS,
    API_ENDPOINT_DEVICE_SYS_OPERATION,
    API_ENDPOINT_DEVICES,
    API_ENDPOINT_DO_NOT_DISTURB,
    API_ENDPOINT_GROUP_DEFENCE_MODE,
    API_ENDPOINT_INTELLIGENT_APP,
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_IOT_FEATURE,
    API_ENDPOINT_LOGIN,
    API_ENDPOINT_LOGOUT,
    API_ENDPOINT_OFFLINE_NOTIFY,
    API_ENDPOINT_OSD,
    API_ENDPOINT_PAGELIST,
    API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
    API_ENDPOINT_PTZCONTROL,
    API_ENDPOINT_REFRESH_SESSION_ID,
    API_ENDPOINT_REMOTE_UNLOCK,
    API_ENDPOINT_RETURN_PANORAMIC,
    API_ENDPOINT_SEND_CODE,
    API_ENDPOINT_SERVER_INFO,
    API_ENDPOINT_SET_DEFENCE_SCHEDULE,
    API_ENDPOINT_SET_LUMINANCE,
    API_ENDPOINT_SWITCH_DEFENCE_MODE,
    API_ENDPOINT_SWITCH_OTHER,
    API_ENDPOINT_SWITCH_SOUND_ALARM,
    API_ENDPOINT_SWITCH_STATUS,
    API_ENDPOINT_UNIFIEDMSG_LIST_GET,
    API_ENDPOINT_UPGRADE_DEVICE,
    API_ENDPOINT_USER_ID,
    API_ENDPOINT_V3_ALARMS,
    API_ENDPOINT_VIDEO_ENCRYPT,
)
from .camera import EzvizCamera
from .cas import EzvizCAS
from .constants import (
    DEFAULT_TIMEOUT,
    FEATURE_CODE,
    MAX_RETRIES,
    REQUEST_HEADER,
    DefenseModeType,
    DeviceCatagories,
    DeviceSwitchType,
    MessageFilterType,
)
from .exceptions import (
    DeviceException,
    EzvizAuthTokenExpired,
    EzvizAuthVerificationCode,
    HTTPError,
    InvalidURL,
    PyEzvizError,
)
from .light_bulb import EzvizLightBulb
from .models import EzvizDeviceRecord, build_device_records_map
from .mqtt import MQTTClient
from .utils import convert_to_dict, deep_merge

_LOGGER = logging.getLogger(__name__)


class ClientToken(TypedDict, total=False):
    """Typed shape for the Ezviz client token."""

    session_id: str | None
    rf_session_id: str | None
    username: str | None
    api_url: str
    service_urls: dict[str, Any]


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
        self.mqtt_client: MQTTClient | None = None

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

    def _ensure_ok(self, payload: dict, message: str) -> None:
        """Raise PyEzvizError with context if response is not OK.

        Accepts both API styles: new (meta.code == 200) and legacy (resultCode == 0).
        """
        if not self._is_ok(payload):
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
        return self._parse_json(resp)

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
        s_type: int = MessageFilterType.FILTER_TYPE_ALL_ALARM.value,
        limit: int | None = 20,  # 50 is the max even if you set it higher
        date: str = datetime.today().strftime("%Y%m%d"),
        end_time: str | None = None,
        tags: str = "ALL",
        max_retries: int = 0,
    ) -> dict:
        """Get data from Unified message list API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        params: dict[str, int | str | None] = {
            "serials": serials,
            "stype": s_type,
            "limit": limit,
            "date": date,
            "endTime": end_time,
            "tags": tags,
        }

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_UNIFIEDMSG_LIST_GET,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get unified message list")
        return json_output

    def switch_status(
        self,
        serial: str,
        status_type: int,
        enable: int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Camera features are represented as switches. Switch them on or off."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/{channel_no}/{enable}/{status_type}{API_ENDPOINT_SWITCH_STATUS}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set the switch")
        if self._cameras.get(serial):
            self._cameras[serial]["switches"][status_type] = bool(enable)
        return True

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

    def set_device_config_by_key(
        self,
        serial: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        """Change value on device by setting key."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        params = {"key": key, "value": value}
        params_str = urllib.parse.urlencode(
            params, safe="}{:"
        )  # not encode curly braces and colon

        full_url = f"https://{self._token['api_url']}{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/1/op"

        # EZVIZ api request needs {}: in the url, but requests lib doesn't allow it
        # so we need to manually prepare it
        req_prep = requests.Request(
            method="PUT", url=full_url, headers=self._session.headers
        ).prepare()
        req_prep.url = full_url + "?" + params_str

        req = self._send_prepared(req_prep, retry_401=True, max_retries=max_retries)
        json_output = self._parse_json(req)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not set config key '${key}': Got {json_output})")

        return True

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

        headers = self._session.headers
        headers.update({"Content-Type": "application/json"})

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
                    ) as err:  # pragma: no cover - defensive
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
                        self._cameras[device] = cam.status(refresh=refresh)
                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:  # pragma: no cover - defensive
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
        return {**self._cameras, **self._light_bulbs}

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

    def remote_unlock(self, serial: str, user_id: str, lock_no: int) -> bool:
        """Sends a remote command to unlock a specific lock.

        Args:
            serial (str): The camera serial.
            user_id (str): The user id.
            lock_no (int): The lock number.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        payload = {
            "unLockInfo": {
                "bindCode": f"{FEATURE_CODE}{user_id}",
                "lockNo": lock_no,
                "streamToken": "",
                "userName": user_id,
            }
        }
        json_result = self._request_json(
            "PUT",
            f"{API_ENDPOINT_IOT_ACTION}{serial}{API_ENDPOINT_REMOTE_UNLOCK}",
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

    def api_set_defence_mode(self, mode: DefenseModeType, max_retries: int = 0) -> bool:
        """Set defence mode for all devices. The alarm panel from main page is used."""
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SWITCH_DEFENCE_MODE,
            data={"groupId": -1, "mode": mode},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set defence mode")
        return True

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

    def set_camera_osd(
        self,
        serial: str,
        text: str = "",
        channel: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set OSD (on screen display) text.

        Args:
            serial (str): The camera serial.
            text (str, optional): The osd text to set. The default of "" will clear.
            channel (int, optional): The cammera channel to set this on. Defaults to 1.
            max_retries (int, optional): Number of retries attempted. Defaults to 0.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_OSD}{serial}/{channel}/osd",
            data={"osd": text},
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

    # soundtype: 0 = normal, 1 = intensive, 2 = disabled ... don't ask me why...
    def alarm_sound(
        self, serial: str, sound_type: int, enable: int = 1, max_retries: int = 0
    ) -> bool:
        """Enable alarm sound by API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sound_type not in [0, 1, 2]:
            raise PyEzvizError(
                "Invalid sound_type, should be 0,1,2: " + str(sound_type)
            )

        response_json = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SOUND}",
            data={
                "enable": enable,
                "soundType": sound_type,
                "voiceId": "0",
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
