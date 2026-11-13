# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""settings implementation; runtime hooks arrive through an explicit owner context.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.constants import DefenseModeType as _StaticDefenseModeType

if TYPE_CHECKING:
    import pyezvizapi._typing.client as _owner_types


def set_camera_defence_old(
    self: _owner_types.EzvizClient, serial: str, enable: int, *, _owner: _ModuleType
) -> bool:
    """Enable/Disable motion detection on camera."""
    cas_client = _owner.EzvizCAS(
        _owner.cast("dict[str, _owner_types.Any]", self._token),
        **_owner._feature_code_options(self.feature_code),
    )
    cas_client.set_camera_defence_state(serial, enable)
    return True


def api_set_defence_schedule(
    self: _owner_types.EzvizClient,
    serial: str,
    schedule: str,
    enable: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Set defence schedules."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    schedulestring = (
        '{"CN":0,"EL":' + str(enable) + ',"SS":"' + serial + '","WP":[' + schedule + "]}]}"
    )
    json_output = self._retry_json(
        lambda: self._request_json(
            "POST",
            _owner.API_ENDPOINT_SET_DEFENCE_SCHEDULE,
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
        raise _owner.PyEzvizError(
            f"Could not set the schedule: Got {self._response_summary(json_output)})"
        )
    return True


def api_set_defence_mode(
    self: _owner_types.EzvizClient,
    mode: _owner_types.DefenseModeType | int,
    *,
    visual_alarm: int | None,
    sound_mode: int | None,
    max_retries: int,
    _owner: _ModuleType,
) -> bool:
    """Set defence mode for all devices. The alarm panel from main page is used."""
    data: dict[str, _owner_types.Any] = {
        "groupId": -1,
        "mode": int(mode.value if isinstance(mode, _StaticDefenseModeType) else mode),
    }
    if visual_alarm is not None:
        data["visualAlarm"] = visual_alarm
    if sound_mode is not None:
        data["soundMode"] = sound_mode
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_SWITCH_DEFENCE_MODE,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set defence mode")
    return True


def switch_defence_mode(
    self: _owner_types.EzvizClient,
    group_id: int,
    mode: int,
    *,
    visual_alarm: int | None,
    sound_mode: int | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Set defence mode for a specific group with optional sound/visual flags."""
    data: dict[str, _owner_types.Any] = {"groupId": group_id, "mode": mode}
    if visual_alarm is not None:
        data["visualAlarm"] = visual_alarm
    if sound_mode is not None:
        data["soundMode"] = sound_mode
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_SWITCH_DEFENCE_MODE,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not switch defence mode")
    return json_output


def do_not_disturb(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    channelno: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Set do not disturb on camera with specified serial."""
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_V3_ALARMS}{serial}/{channelno}{_owner.API_ENDPOINT_DO_NOT_DISTURB}",
        data={"enable": enable},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set do not disturb")
    return True


def set_answer_call(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Set answer call on camera with specified serial."""
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_CALLING_NOTIFY}{serial}{_owner.API_ENDPOINT_DO_NOT_DISTURB}",
        data={"deviceSerial": serial, "switchStatus": enable},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set answer call")
    return True


def manage_intelligent_app(
    self: _owner_types.EzvizClient,
    serial: str,
    resource_id: str,
    app_name: str,
    action: str,
    max_retries: int,
    *,
    _owner: _ModuleType,
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
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    url_path = f"{_owner.API_ENDPOINT_INTELLIGENT_APP}{serial}/{resource_id}/{app_name}"
    action = action.lower()
    if action == "add":
        method = "PUT"
    elif action == "remove":
        method = "DELETE"
    else:
        raise _owner.PyEzvizError(f"Invalid action '{action}'. Use 'add' or 'remove'.")
    json_output = self._request_json(method, url_path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, f"Could not {action} intelligent app")
    return True


def _resolve_resource_id(
    self: _owner_types.EzvizClient, serial: str, resource_id: str | None, *, _owner: _ModuleType
) -> str:
    """Resolve the intelligent app resource id for a given camera."""
    if resource_id:
        return resource_id
    camera = self._cameras.get(serial)
    if not camera:
        raise _owner.PyEzvizError(
            f"Unknown camera serial {serial}. Call load_devices/load_cameras first"
        )
    resource_infos = camera.get("resourceInfos") or []
    for item in resource_infos:
        if isinstance(item, dict) and item.get("resourceId"):
            return _owner.cast("str", item["resourceId"])
    legacy = camera.get("resouceid") or camera.get("resource_id")
    if isinstance(legacy, str) and legacy:
        return legacy
    raise _owner.PyEzvizError("Unable to determine resourceId for intelligent app operation")


def set_intelligent_app_state(
    self: _owner_types.EzvizClient,
    serial: str,
    app_name: str,
    enabled: bool,
    resource_id: str | None,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Enable or disable an intelligent detection app on a camera."""
    resolved_id = self._resolve_resource_id(serial, resource_id)
    action = "add" if enabled else "remove"
    return self.manage_intelligent_app(
        serial, resolved_id, app_name, action=action, max_retries=max_retries
    )


def device_mirror(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    command: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Send a mirror command using the basics API."""
    path = f"{_owner.API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/{command}/mirror"
    json_output = self._request_json("PUT", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not set mirror state")
    return json_output


def flip_image(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
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
        f"{_owner.API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/CENTER/mirror",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not flip image on camera")
    return True


def _resolve_osd_text(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    name: str | None,
    camera_data: _owner_types.Mapping[str, _owner_types.Any] | None,
    _owner: _ModuleType,
) -> str:
    """Return the preferred OSD label for a camera."""
    if isinstance(name, str) and name.strip():
        return name.strip()
    candidates: list[_owner_types.Mapping[str, _owner_types.Any]] = []
    if isinstance(camera_data, _StaticMapping):
        candidates.append(camera_data)
    cached = self._cameras.get(serial)
    if isinstance(cached, _StaticMapping):
        candidates.append(cached)
    for data in candidates:
        direct = data.get("name")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        device_info = data.get("deviceInfos")
        if isinstance(device_info, _StaticMapping):
            alt = device_info.get("name")
            if isinstance(alt, str) and alt.strip():
                return alt.strip()
        optionals = _owner.optionals_mapping(data)
        osd_entries = optionals.get("OSD")
        if isinstance(osd_entries, _StaticMapping):
            osd_entries = [osd_entries]
        if isinstance(osd_entries, list):
            for entry in osd_entries:
                if not isinstance(entry, _StaticMapping):
                    continue
                text = entry.get("name")
                if isinstance(text, str) and text.strip():
                    return text.strip()
    return serial


def set_camera_osd(
    self: _owner_types.EzvizClient,
    serial: str,
    text: str | None,
    *,
    enabled: bool | None,
    name: str | None,
    camera_data: _owner_types.Mapping[str, _owner_types.Any] | None,
    channel: int,
    max_retries: int,
    _owner: _ModuleType,
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
            raise _owner.PyEzvizError(
                "Camera data unavailable; call load_devices() before setting the OSD"
            )
        resolved = (
            self._resolve_osd_text(serial, name=name, camera_data=camera_data) if enabled else ""
        )
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_OSD}{serial}/{channel}/osd",
        data={"osd": resolved},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could set osd message on camera")
    return True


def set_floodlight_brightness(
    self: _owner_types.EzvizClient,
    serial: str,
    luminance: int,
    channelno: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool | str:
    """Set brightness on camera with adjustable light."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if luminance not in range(1, 101):
        raise _owner.PyEzvizError("Range of luminance is 1-100, got " + str(luminance) + ".")
    response_json = self._request_json(
        "POST",
        f"{_owner.API_ENDPOINT_SET_LUMINANCE}{serial}/{channelno}",
        data={"luminance": luminance},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(response_json, "Unable to set brightness")
    return True


def set_brightness(
    self: _owner_types.EzvizClient,
    serial: str,
    luminance: int,
    channelno: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool | str:
    """Facade that changes the brightness to light bulbs or cameras' light."""
    device = self._light_bulbs.get(serial)
    if device:
        return self.set_device_feature_by_key(
            serial, device["productId"], luminance, "brightness", max_retries
        )
    return self.set_floodlight_brightness(serial, luminance, channelno, max_retries)


def switch_light_status(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    channel_no: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Facade that turns on/off light bulbs or cameras' light."""
    device = self._light_bulbs.get(serial)
    if device:
        return self.set_device_feature_by_key(
            serial, device["productId"], bool(enable), "light_switch", max_retries
        )
    return self.switch_status(
        serial, _owner.DeviceSwitchType.ALARM_LIGHT.value, enable, channel_no, max_retries
    )


def detection_sensibility(
    self: _owner_types.EzvizClient,
    serial: str,
    sensibility: int,
    type_value: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool | str:
    """Set detection sensibility."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if sensibility not in [0, 1, 2, 3, 4, 5, 6] and type_value == 0:
        raise _owner.PyEzvizError("Unproper sensibility for type 0 (should be within 1 to 6).")
    try:
        with _owner.request_budget_lock(self._token_lock):
            req = _owner.budgeted_http_call(
                self._session,
                "post",
                url=f"https://{self._token['api_url']}{_owner.API_ENDPOINT_DETECTION_SENSIBILITY}",
                data={
                    "subSerial": serial,
                    "type": type_value,
                    "channelNo": 1,
                    "value": sensibility,
                },
                timeout=_owner.bounded_request_timeout(self._timeout),
            )
        req.raise_for_status()
    except _owner.requests.HTTPError as err:
        if err.response.status_code == 401:
            self.login()
            return self.detection_sensibility(serial, sensibility, type_value, max_retries + 1)
        raise _owner.HTTPError from err
    try:
        response_json = req.json()
    except ValueError as err:
        raise _owner.PyEzvizError("Could not decode response:" + str(err)) from err
    if response_json["resultCode"] != "0":
        if response_json["resultCode"] == "-1":
            _owner._LOGGER.warning(
                "Camera %s is offline or unreachable, can't set sensitivity, retrying %s of %s",
                serial,
                max_retries,
                _owner.MAX_RETRIES,
            )
            return self.detection_sensibility(serial, sensibility, type_value, max_retries + 1)
        raise _owner.PyEzvizError(
            f"Unable to set detection sensibility. Got: {self._response_summary(response_json)}"
        )
    return True


def get_motion_detect_sensitivity(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Get motion detection sensitivity via v1 devconfig endpoint."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_SENSITIVITY}{serial}/{channel}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get motion detect sensitivity")
    return json_output


def get_motion_detect_sensitivity_dp1s(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Get motion detection sensitivity for DP1S devices."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}/{channel}/sensitivity",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get DP1S motion sensitivity")
    return json_output


def set_detection_sensitivity(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    sensitivity_type: int,
    value: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Set detection sensitivity via v3 devconfig endpoint."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if sensitivity_type == 0 and (not 1 <= value <= 6):
        raise _owner.PyEzvizError("Detection sensitivity must be within 1..6")
    if sensitivity_type != 0 and (not 1 <= value <= 100):
        raise _owner.PyEzvizError("Detection sensitivity must be within 1..100")
    url_path = f"{_owner.API_ENDPOINT_SENSITIVITY}{serial}/{channel}/{sensitivity_type}/{value}"
    json_output = self._request_json("PUT", url_path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not set detection sensitivity")
    return True


def get_detection_sensibility(
    self: _owner_types.EzvizClient,
    serial: str,
    type_value: str,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.Any:
    """Get detection sensibility notifications."""
    response_json = self._retry_json(
        lambda: self._request_json(
            "POST",
            _owner.API_ENDPOINT_DETECTION_SENSIBILITY_GET,
            data={"subSerial": serial},
            retry_401=True,
            max_retries=0,
        ),
        attempts=max_retries,
        should_retry=lambda p: str(p.get("resultCode")) == "-1",
        log=f"Camera {serial} is offline or unreachable",
    )
    if str(response_json.get("resultCode")) != "0":
        raise _owner.PyEzvizError(
            f"Unable to get detection sensibility. Got: {self._response_summary(response_json)}"
        )
    if response_json.get("algorithmConfig", {}).get("algorithmList"):
        for idx in response_json["algorithmConfig"]["algorithmList"]:
            if idx.get("type") == type_value:
                return idx.get("value")
    return None


def get_detector_setting_info(
    self: _owner_types.EzvizClient,
    device_serial: str,
    detector_serial: str,
    key: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch a specific configuration key for an A1S detector."""
    path = f"{_owner.API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/{detector_serial}/{key}"
    json_output = self._request_json("GET", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not get detector setting info")
    return json_output


def set_detector_setting_info(
    self: _owner_types.EzvizClient,
    device_serial: str,
    detector_serial: str,
    key: str,
    value: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update a configuration key for an A1S detector."""
    path = f"{_owner.API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/{detector_serial}"
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
    self: _owner_types.EzvizClient, detector_serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Retrieve status/details for an A1S detector."""
    path = f"{_owner.API_ENDPOINT_SPECIAL_BIZS_A1S}detector/{detector_serial}"
    json_output = self._request_json("GET", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not get detector info")
    return json_output


def get_radio_signals(
    self: _owner_types.EzvizClient,
    device_serial: str,
    child_device_serial: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Return radio signal metrics for a detector connected to a device."""
    path = f"{_owner.API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/radioSignal"
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
    self: _owner_types.EzvizClient,
    product_id: str,
    version: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch voice configuration metadata for a product."""
    params = {"productId": product_id, "version": version}
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG,
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get voice config")
    return json_output


def get_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    local_index: str | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve uploaded custom voice prompts for a device."""
    params: dict[str, _owner_types.Any] = {"deviceSerial": serial}
    if local_index is not None:
        params["localIndex"] = local_index
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_SPECIAL_BIZS_VOICES,
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get voice list")
    return json_output


def add_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_name: str,
    voice_url: str,
    *,
    local_index: str | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Upload metadata for a new custom voice prompt."""
    data: dict[str, _owner_types.Any] = {
        "deviceSerial": serial,
        "voiceName": voice_name,
        "voiceUrl": voice_url,
    }
    if local_index is not None:
        data["localIndex"] = local_index
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_SPECIAL_BIZS_VOICES,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not add voice info")
    return json_output


def add_shared_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_name: str,
    voice_url: str,
    local_index: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Upload a shared voice with explicit local index, mirroring the mobile API."""
    return self.add_voice_info(
        serial, voice_name, voice_url, local_index=local_index, max_retries=max_retries
    )


def set_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_id: int,
    voice_name: str,
    *,
    local_index: str | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update metadata for an existing voice prompt."""
    data: dict[str, _owner_types.Any] = {
        "deviceSerial": serial,
        "voiceId": voice_id,
        "voiceName": voice_name,
    }
    if local_index is not None:
        data["localIndex"] = local_index
    json_output = self._request_json(
        "PUT",
        _owner.API_ENDPOINT_SPECIAL_BIZS_VOICES,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not update voice info")
    return json_output


def set_shared_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_id: int,
    voice_name: str,
    local_index: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Alias for updating shared voices that ensures local index is supplied."""
    return self.set_voice_info(
        serial, voice_id, voice_name, local_index=local_index, max_retries=max_retries
    )


def delete_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_id: int,
    *,
    voice_url: str | None,
    local_index: str | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Remove a voice prompt from a device."""
    params: dict[str, _owner_types.Any] = {"deviceSerial": serial, "voiceId": voice_id}
    if voice_url is not None:
        params["voiceUrl"] = voice_url
    if local_index is not None:
        params["localIndex"] = local_index
    json_output = self._request_json(
        "DELETE",
        _owner.API_ENDPOINT_SPECIAL_BIZS_VOICES,
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not delete voice info")
    return json_output


def delete_shared_voice_info(
    self: _owner_types.EzvizClient,
    serial: str,
    voice_id: int,
    voice_url: str,
    local_index: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Alias for deleting shared voices with required parameters."""
    return self.delete_voice_info(
        serial, voice_id, voice_url=voice_url, local_index=local_index, max_retries=max_retries
    )


def get_whistle_status_by_channel(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Return whistle configuration per channel for a device."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get whistle status by channel")
    return json_output


def get_whistle_status_by_device(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Return whistle configuration at the device level."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get whistle status by device")
    return json_output


def set_channel_whistle(
    self: _owner_types.EzvizClient,
    serial: str,
    channel_whistles: list[_owner_types.Mapping[str, _owner_types.Any]]
    | list[dict[str, _owner_types.Any]],
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Configure whistle behaviour for individual channels."""
    if not channel_whistles:
        raise _owner.PyEzvizError("channel_whistles must contain at least one entry")
    entries: list[dict[str, _owner_types.Any]] = []
    required_fields = {"channel", "status", "duration", "volume"}
    for item in channel_whistles:
        entry = dict(item)
        entry.setdefault("deviceSerial", serial)
        missing = [field for field in required_fields if field not in entry]
        if missing:
            raise _owner.PyEzvizError("channel_whistles entries must include " + ", ".join(missing))
        entries.append(entry)
    payload = {"channelWhistleList": entries}
    json_output = self._request_json(
        "POST",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE}",
        json_body=payload,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set channel whistle")
    return json_output


def set_device_whistle(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    status: int,
    duration: int,
    volume: int,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Configure whistle behaviour at the device level."""
    params = {"status": status, "duration": duration, "volume": volume}
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE}",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set device whistle")
    return json_output


def stop_whistle(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Stop any ongoing whistle sound."""
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_STOP_WHISTLE}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not stop whistle")
    return json_output


def delay_battery_device_sleep(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    sleep_type: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Request additional awake time for a battery-powered device."""
    path = f"{_owner.API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY}{serial}/{channel}/{sleep_type}/sleep"
    json_output = self._request_json("PUT", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not delay battery device sleep")
    return json_output


def get_device_chime_info(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch chime configuration for a specific channel."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get chime info")
    return json_output


def set_device_chime_info(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    *,
    sound_type: int,
    duration: int,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update chime type and duration for a channel."""
    data = {"type": sound_type, "duration": duration}
    json_output = self._request_json(
        "POST",
        f"{_owner.API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set chime info")
    return json_output


def set_switch_enable_req(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    enable: int,
    switch_type: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Call the legacy setSwitchEnableReq endpoint."""
    params = {"enable": enable, "type": switch_type}
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}/{channel}{_owner.API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE}",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set switch enable request")
    return json_output


def get_managed_device_info(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Return metadata for a managed device (e.g. base station)."""
    path = f"{_owner.API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/base"
    json_output = self._request_json("GET", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not get managed device info")
    return json_output


def get_managed_device_ipcs(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """List IPC sub-devices that belong to a managed device."""
    path = f"{_owner.API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/ipcs"
    json_output = self._request_json("GET", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not get managed IPC list")
    return json_output


def get_devices_status(
    self: _owner_types.EzvizClient,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch online/offline status for one or more devices."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_USERDEVICES_STATUS,
        params={"deviceSerials": serial_param},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get device status")
    return json_output


def get_device_secret_key_info(
    self: _owner_types.EzvizClient,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve KMS secret key metadata for devices."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_USERDEVICES_KMS,
        params={"deviceSerials": serial_param},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get device secret key info")
    return json_output


def get_device_list_encrypt_key(
    self: _owner_types.EzvizClient,
    area_id: int,
    form_data: _owner_types.Mapping[str, _owner_types.Any] | bytes | bytearray | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Batch query encrypt keys for devices, matching the mobile client's risk API."""
    headers = {
        **self._session.headers,
        "Content-Type": "application/x-www-form-urlencoded",
        "areaId": str(area_id),
    }
    if isinstance(form_data, (bytes, bytearray, str)):
        body = form_data
    else:
        body = _owner.urlencode(form_data, doseq=True)
    req = _owner.requests.Request(
        method="POST",
        url=self._url(_owner.API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH),
        headers=headers,
        data=body,
    ).prepare()
    resp = self._send_prepared(req, retry_401=True, max_retries=max_retries)
    json_output = self._parse_json(resp)
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(
            f"Could not get device encrypt key list: Got {self._response_summary(json_output)})"
        )
    return json_output


def get_p2p_info(
    self: _owner_types.EzvizClient,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve P2P info via the device-scoped endpoint."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_DEVICES_P2P_INFO,
        params={"deviceSerials": serial_param},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get P2P info")
    return json_output


def get_p2p_server_info(
    self: _owner_types.EzvizClient,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve P2P server info via the userdevices endpoint."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_USERDEVICES_P2P_INFO,
        params={"deviceSerials": serial_param},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get P2P server info")
    return json_output


def register_p2p_session(
    self: _owner_types.EzvizClient, *, session_id: str | None, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Authorize the current cloud session for EZVIZ LAN/P2P operations.

    Some devices reject CAS ``getDevOperationCode`` lookups until the app-style
    P2P registration endpoint has seen the current user ``sessionId``.
    """
    selected_session_id = session_id
    attempts = 0
    while True:
        current_session_id = selected_session_id or self._token.get("session_id")
        if not current_session_id:
            raise _owner.PyEzvizError("P2P session registration requires a session_id")
        try:
            json_output = self._request_json(
                "POST",
                _owner.API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P,
                data={"sessionId": str(current_session_id)},
                retry_401=False,
            )
        except _owner.HTTPError as err:
            if self._http_error_status(err) != 401 or attempts >= max_retries:
                raise
            attempts += 1
            selected_session_id = None
            self.login()
            continue
        self._ensure_ok(json_output, "Could not register P2P session")
        return json_output


def check_device_upgrade_rule(
    self: _owner_types.EzvizClient, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Check firmware upgrade eligibility rules."""
    json_output = self._request_json(
        "GET", _owner.API_ENDPOINT_UPGRADE_RULE, retry_401=True, max_retries=max_retries
    )
    self._ensure_ok(json_output, "Could not get upgrade rules")
    return json_output


def get_autoupgrade_switch(
    self: _owner_types.EzvizClient, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Return the current auto-upgrade switch settings."""
    json_output = self._request_json(
        "GET", _owner.API_ENDPOINT_AUTOUPGRADE_SWITCH, retry_401=True, max_retries=max_retries
    )
    self._ensure_ok(json_output, "Could not get auto-upgrade switch")
    return json_output


def set_autoupgrade_switch(
    self: _owner_types.EzvizClient,
    auto_upgrade: int,
    time_type: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update the auto-upgrade switch configuration."""
    data = {"autoUpgrade": auto_upgrade, "timeType": time_type}
    json_output = self._request_json(
        "PUT",
        _owner.API_ENDPOINT_AUTOUPGRADE_SWITCH,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set auto-upgrade switch")
    return json_output


def get_black_level_list(
    self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Retrieve SD-card black level data for a device."""
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_SDCARD_BLACK_LEVEL}{serial}",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get black level list")
    return json_output


def get_time_plan_infos(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    timing_plan_type: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch timing plan information for a device/channel."""
    params = {"deviceSerial": serial, "channelNo": channel, "timingPlanType": timing_plan_type}
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_TIME_PLAN_INFOS,
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get time plan infos")
    return json_output


def set_time_plan_infos(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    timing_plan_type: int,
    enable: int,
    timer_defence_qos: _owner_types.Any,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update timing plan configuration."""
    params: dict[str, _owner_types.Any] = {
        "deviceSerial": serial,
        "channelNo": channel,
        "timingPlanType": timing_plan_type,
        "enable": enable,
    }
    if not isinstance(timer_defence_qos, str):
        params["timerDefenceQos"] = _owner.json.dumps(timer_defence_qos)
    else:
        params["timerDefenceQos"] = timer_defence_qos
    json_output = self._request_json(
        "PUT",
        _owner.API_ENDPOINT_TIME_PLAN_INFOS,
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set time plan infos")
    return json_output
