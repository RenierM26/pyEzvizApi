# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""controls implementation; runtime hooks arrive through an explicit owner context.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi._typing.client as _owner_types


def set_switch_v3(
    self: _owner_types.EzvizClient,
    serial: str,
    switch_type: int,
    enable: bool | int,
    channel: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update a device switch via the v3 endpoint."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    enable_flag = 1 if bool(enable) else 0
    path = f"{_owner.API_ENDPOINT_DEVICES}{serial}/{channel}/{enable_flag}/{switch_type}{_owner.API_ENDPOINT_SWITCH_STATUS}"
    payload = self._request_json("PUT", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(payload, "Could not set the switch")
    return payload


def set_switch_legacy(
    self: _owner_types.EzvizClient,
    serial: str,
    switch_type: int,
    enable: bool | int,
    channel: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fallback legacy switch endpoint used by older firmware."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    payload = self._request_json(
        "POST",
        _owner.API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY,
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
    self: _owner_types.EzvizClient,
    serial: str,
    switch_type: int,
    enable: bool | int,
    channel: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Try the v3 switch endpoint, falling back to the legacy API if needed."""
    try:
        return self.set_switch_v3(serial, switch_type, enable, channel, max_retries=max_retries)
    except _owner.PyEzvizError as first_error:
        try:
            return self.set_switch_legacy(
                serial, switch_type, enable, channel, max_retries=max_retries
            )
        except _owner.PyEzvizError:
            # Keep the primary transport cause, not the legacy failure context.
            # Consumers need its HTTP status even when the fallback also fails.
            raise first_error from first_error.__cause__


def switch_status(
    self: _owner_types.EzvizClient,
    serial: str,
    status_type: int,
    enable: bool | int,
    channel_no: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Camera features are represented as switches. Switch them on or off."""
    target_state = bool(enable)
    self.set_switch(serial, status_type, target_state, channel=channel_no, max_retries=max_retries)
    if self._cameras.get(serial):
        self._cameras[serial]["switches"][status_type] = target_state
    return True


def device_switch(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    enable: int,
    switch_type: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Direct wrapper for /v3/devices/{serial}/switch endpoint."""
    params = {"channelNo": channel, "enable": enable, "switchType": switch_type}
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_SWITCH_OTHER}",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not toggle device switch")
    return json_output


def switch_status_other(
    self: _owner_types.EzvizClient,
    serial: str,
    status_type: int,
    enable: int,
    channel_number: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Features are represented as switches. This api is for alternative switch types to turn them on or off.

    All day recording is a good example.
    """
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_SWITCH_OTHER}",
        params={"channelNo": channel_number, "enable": enable, "switchType": status_type},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set the switch")
    return True


def set_camera_defence(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    channel_no: int,
    arm_type: str,
    actor: str,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Enable/Disable motion detection on camera."""
    json_output = self._retry_json(
        lambda: self._request_json(
            "PUT",
            f"{_owner.API_ENDPOINT_DEVICES}{serial}/{channel_no}{_owner.API_ENDPOINT_CHANGE_DEFENCE_STATUS}",
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
        raise _owner.PyEzvizError(
            f"Could not arm or disarm Camera {serial}: Got {self._response_summary(json_output)})"
        )
    return True


def set_battery_camera_work_mode(
    self: _owner_types.EzvizClient, serial: str, value: int, *, _owner: _ModuleType
) -> bool:
    """Set battery camera work mode."""
    return self.set_device_config_by_key(serial, value, key="batteryCameraWorkMode")


def set_detection_mode(
    self: _owner_types.EzvizClient, serial: str, value: int, *, _owner: _ModuleType
) -> bool:
    """Set detection mode.

    Deprecated in favour of set_alarm_detect_human_car() but kept for
    backwards compatibility with older callers inside the integration.
    """
    return self.set_alarm_detect_human_car(serial, value)


def set_alarm_detect_human_car(
    self: _owner_types.EzvizClient, serial: str, value: int, *, _owner: _ModuleType
) -> bool:
    """Update Alarm_DetectHumanCar type on the device."""
    return self.set_device_config_by_key(
        serial, value=f'{{"type":{value}}}', key="Alarm_DetectHumanCar"
    )


def set_alarm_advanced_detect(
    self: _owner_types.EzvizClient, serial: str, value: int, *, _owner: _ModuleType
) -> bool:
    """Update Alarm_AdvancedDetect type on the device."""
    return self.set_device_config_by_key(
        serial, value=f'{{"type":{value}}}', key="Alarm_AdvancedDetect"
    )


def set_algorithm_param(
    self: _owner_types.EzvizClient,
    serial: str,
    subtype: str | int,
    value: int,
    channel: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Update a single AlgorithmInfo subtype value via devconfig."""
    payload = {
        "AlgorithmInfo": [{"SubType": str(subtype), "Value": str(value), "channel": channel}]
    }
    return self.set_device_config_by_key(
        serial, value=_owner.json.dumps(payload, separators=(",", ":")), key="AlgorithmInfo"
    )


def set_night_vision_mode(
    self: _owner_types.EzvizClient, serial: str, mode: int, luminance: int, *, _owner: _ModuleType
) -> bool:
    """Set night vision mode."""
    return self.set_device_config_by_key(
        serial, value=f'{{"graphicType":{mode},"luminance":{luminance}}}', key="NightVision_Model"
    )


def set_display_mode(
    self: _owner_types.EzvizClient, serial: str, mode: int, *, _owner: _ModuleType
) -> bool:
    """Change video color and saturation mode."""
    return self.set_device_config_by_key(serial, value=f'{{"mode":{mode}}}', key="display_mode")


def set_dev_config_kv(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    key: str,
    value: _owner_types.Mapping[str, _owner_types.Any] | str | bytes | float | bool,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update a device configuration key/value pair via devconfig."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if isinstance(value, _StaticMapping):
        value_payload = _owner.json.dumps(value, separators=(",", ":"))
    elif isinstance(value, bytes):
        value_payload = value.decode()
    elif isinstance(value, bool):
        value_payload = "1" if value else "0"
    elif isinstance(value, (int, float)):
        value_payload = str(value)
    else:
        value_payload = str(value)
    data = {"key": key, "value": value_payload}
    payload = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(payload, "Could not set devconfig key")
    return payload


def set_common_key_value(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    key: str,
    value: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update a devconfig key/value pair using query parameters."""
    params = {"key": key, "value": value if isinstance(value, str) else str(value)}
    payload = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(payload, "Could not set common key value")
    return payload


def set_device_config_by_key(
    self: _owner_types.EzvizClient,
    serial: str,
    value: _owner_types.Any,
    key: str,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Change value on device by setting key."""
    self.set_dev_config_kv(serial, 1, key, value, max_retries=max_retries)
    return True


def set_device_key_value(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    key: str,
    value: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Alias for the query-based key/value setter."""
    return self.set_common_key_value(serial, channel, key, value, max_retries=max_retries)


def audition_request(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    request: str,
    payload: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Send an audition request via /v3/devconfig/op."""
    data = {"deviceSerial": serial, "channelNo": channel, "request": request, "data": payload}
    json_output = self._request_json(
        "POST", _owner.API_ENDPOINT_DEVCONFIG_OP, data=data, retry_401=True, max_retries=max_retries
    )
    self._ensure_ok(json_output, "Could not send audition request")
    return json_output


def baby_control(  # noqa: PLR0913 -- explicit runtime context plus retained signature
    self: _owner_types.EzvizClient,
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
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
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
        _owner.API_ENDPOINT_DEVCONFIG_MOTOR,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not control baby motor")
    return json_output


def set_device_feature_by_key(
    self: _owner_types.EzvizClient,
    serial: str,
    product_id: str,
    value: _owner_types.Any,
    key: str,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Change value on device by setting the iot-feature's key.

    The FEATURE key that is part of 'device info' holds
    information about the device's functions (for example light_switch, brightness etc.).
    """
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    payload = _owner.json.dumps({"itemKey": key, "productId": product_id, "value": value})
    full_url = (
        f"https://{self._token['api_url']}{_owner.API_ENDPOINT_IOT_FEATURE}{serial.upper()}/0"
    )
    headers = {**self._session.headers, "Content-Type": "application/json"}
    req_prep = _owner.requests.Request(
        method="PUT", url=full_url, headers=headers, data=payload
    ).prepare()
    req = self._send_prepared(req_prep, retry_401=True, max_retries=max_retries)
    json_output = self._parse_json(req)
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(
            f"Could not set iot-feature key '{key}': Got {self._response_summary(json_output)})"
        )
    return True


def _iot_request(  # noqa: PLR0913 -- explicit runtime context plus retained signature
    self: _owner_types.EzvizClient,
    method: str,
    endpoint: str,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    *,
    payload: _owner_types.Any,
    max_retries: int,
    error_message: str,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Helper to perform IoT feature/action requests with JSON payload support."""
    path = f"{endpoint}{serial.upper()}/{resource_identifier}/{local_index}/{domain_id}/{action_id}"
    headers = dict(self._session.headers)
    data: str | bytes | bytearray | None = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        if isinstance(payload, (bytes, bytearray, str)):
            data = payload
        else:
            data = _owner.json.dumps(payload, separators=(",", ":"))
    req = _owner.requests.Request(
        method=method, url=self._url(path), headers=headers, data=data
    ).prepare()
    resp = self._send_prepared(req, retry_401=True, max_retries=max_retries)
    json_output = self._parse_json(resp)
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(f"{error_message}: Got {self._response_summary(json_output)})")
    return json_output


def get_low_battery_keep_alive(
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch low-battery keep-alive status exposed under the IoT feature API."""
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
        serial,
        resource_identifier,
        local_index,
        domain_id,
        action_id,
        max_retries=max_retries,
        error_message="Could not fetch low battery keep-alive status",
    )


def get_object_removal_status(
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    *,
    payload: _owner_types.Any | None,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch object-removal (left-behind) status for supported devices."""
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
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
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Return the remote control patrol path list for auto-tracking models."""
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
        serial,
        resource_identifier,
        local_index,
        domain_id,
        action_id,
        max_retries=max_retries,
        error_message="Could not fetch remote control path list",
    )


def get_tracking_status(
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Obtain the current subject-tracking status from the IoT feature API."""
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
        serial,
        resource_identifier,
        local_index,
        domain_id,
        action_id,
        max_retries=max_retries,
        error_message="Could not fetch tracking status",
    )


def get_port_security(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Fetch port security configuration via the IoT feature API."""
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
        serial,
        resource_identifier,
        local_index,
        domain_id,
        action_id,
        max_retries=max_retries,
        error_message="Could not fetch port security status",
    )


def set_port_security(
    self: _owner_types.EzvizClient,
    serial: str,
    value: _owner_types.Mapping[str, _owner_types.Any] | dict[str, _owner_types.Any],
    *,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update port security configuration via the IoT feature API."""
    payload = {"value": value}
    return self._iot_request(
        "PUT",
        _owner.API_ENDPOINT_IOT_FEATURE,
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
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    domain_identifier: str,
    prop_identifier: str,
    *,
    local_index: str | int,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve a device feature value via the IoT feature API."""
    local_idx = str(local_index)
    return self._iot_request(
        "GET",
        _owner.API_ENDPOINT_IOT_FEATURE,
        serial,
        resource_identifier,
        local_idx,
        domain_identifier,
        prop_identifier,
        max_retries=max_retries,
        error_message="Could not fetch device feature value",
    )


def set_intelligent_fill_light(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    enabled: bool,
    local_index: str,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Toggle the intelligent fill light mode via the IoT feature API."""
    payload = {
        "value": {
            "enabled": bool(enabled),
            "supplementLightSwitchMode": "eventIntelligence" if enabled else "irLight",
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
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    enabled: bool | None,
    payload: _owner_types.Any | None,
    local_index: str,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Set image flip configuration using the IoT feature endpoint."""
    if payload is None:
        if enabled is None:
            raise _owner.PyEzvizError("Either 'enabled' or 'payload' must be provided")
        payload = {"value": {"enabled": bool(enabled)}}
    body = self._normalize_json_payload(payload)
    return self._iot_request(
        "PUT",
        _owner.API_ENDPOINT_IOT_FEATURE,
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
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    value: _owner_types.Any,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Trigger an IoT action (setAction/putAction in the mobile API)."""
    return self._iot_request(
        "PUT",
        _owner.API_ENDPOINT_IOT_ACTION,
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
    self: _owner_types.EzvizClient,
    serial: str,
    resource_identifier: str,
    local_index: str,
    domain_id: str,
    action_id: str,
    value: _owner_types.Any,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update an IoT feature value via the feature endpoint."""
    return self._iot_request(
        "PUT",
        _owner.API_ENDPOINT_IOT_FEATURE,
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
    self: _owner_types.EzvizClient,
    serial: str,
    value: int,
    *,
    local_index: str,
    max_retries: int,
    _owner: _ModuleType,
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
        enabled, mode = (True, "open")
    elif value == 2:
        enabled, mode = (False, "auto")
    else:
        enabled, mode = (True, "auto")
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
    return (enabled, mode)


def update_device_name(
    self: _owner_types.EzvizClient, serial: str, name: str, *, max_retries: int, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Rename a device via the legacy updateName endpoint."""
    if not name:
        raise _owner.PyEzvizError("Device name must not be empty")
    data = {"deviceSerialNo": serial, "deviceName": name}
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_DEVICE_UPDATE_NAME,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not update device name")
    return json_output


def upgrade_device(
    self: _owner_types.EzvizClient, serial: str, max_retries: int, *, _owner: _ModuleType
) -> bool:
    """Upgrade device firmware."""
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_UPGRADE_DEVICE}{serial}/0/upgrade",
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not initiate firmware upgrade")
    return True


def get_storage_status(
    self: _owner_types.EzvizClient, serial: str, max_retries: int, *, _owner: _ModuleType
) -> _owner_types.Any:
    """Get device storage status."""
    json_output = self._retry_json(
        lambda: self._request_json(
            "POST",
            _owner.API_ENDPOINT_DEVICE_STORAGE_STATUS,
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
        raise _owner.PyEzvizError(
            f"Could not get device storage status: Got {self._response_summary(json_output)})"
        )
    return json_output.get("storageStatus")


def sound_alarm(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Sound alarm on a device."""
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}/0{_owner.API_ENDPOINT_SWITCH_SOUND_ALARM}",
        data={"enable": enable},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set the alarm sound")
    return True


def get_user_id(
    self: _owner_types.EzvizClient, max_retries: int, *, _owner: _ModuleType
) -> _owner_types.Any:
    """Get Ezviz userid, used by restricted api endpoints."""
    json_output = self._request_json(
        "GET", _owner.API_ENDPOINT_USER_ID, retry_401=True, max_retries=max_retries
    )
    self._ensure_ok(json_output, "Could not get user id")
    return json_output.get("deviceTokenInfo")


def set_video_enc(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    camera_verification_code: str | None,
    new_password: str | None,
    old_password: str | None,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Enable or Disable video encryption."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if enable == 2 and (not old_password):
        raise _owner.PyEzvizError("Old password is required when changing password.")
    if new_password and (not enable == 2):
        raise _owner.PyEzvizError("New password is only required when changing password.")
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{_owner.API_ENDPOINT_VIDEO_ENCRYPT}",
        data={
            "deviceSerial": serial,
            "isEncrypt": enable,
            "oldPassword": old_password,
            "password": new_password,
            "featureCode": self.feature_code,
            "validateCode": camera_verification_code,
            "msgType": -1,
        },
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not set video encryption")
    return True


def device_authenticate(
    self: _owner_types.EzvizClient,
    serial: str,
    *,
    need_check_code: bool,
    check_code: str | None,
    sender_type: int,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Authenticate a device, optionally requiring check code."""
    data = {
        "needCheckCode": str(bool(need_check_code)).lower(),
        "checkCode": check_code or "",
        "senderType": sender_type,
    }
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES_AUTHENTICATE}{serial}",
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not authenticate device")
    return json_output


def reboot_camera(
    self: _owner_types.EzvizClient,
    serial: str,
    delay: int,
    operation: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Reboot camera."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    json_output = self._retry_json(
        lambda: self._request_json(
            "POST",
            f"{_owner.API_ENDPOINT_DEVICE_SYS_OPERATION}{serial}",
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
        raise _owner.PyEzvizError(f"Could not reboot device {self._response_summary(json_output)})")
    return True


def set_offline_notification(
    self: _owner_types.EzvizClient,
    serial: str,
    enable: int,
    req_type: int,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> bool:
    """Set offline notification."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    attempts = max(0, max_retries)
    for attempt in range(attempts + 1):
        json_output = self._request_json(
            "POST",
            _owner.API_ENDPOINT_OFFLINE_NOTIFY,
            data={"reqType": req_type, "serial": serial, "status": enable},
            retry_401=True,
            max_retries=0,
        )
        result = str(json_output.get("resultCode"))
        if result == "0":
            return True
        if result == "-1" and attempt < attempts:
            _owner._LOGGER.warning(
                "Unable to set offline notification, camera %s is unreachable, retrying %s/%s",
                serial,
                attempt + 1,
                attempts,
            )
            continue
        raise _owner.PyEzvizError(
            f"Could not set offline notification {self._response_summary(json_output)})"
        )
    raise _owner.PyEzvizError("Could not set offline notification: exceeded retries")


def device_email_alert_state(
    self: _owner_types.EzvizClient,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Get email alert state for one or more devices."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_DEVICE_EMAIL_ALERT,
        params={"devices": serial_param},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get device email alert state")
    return json_output


def save_device_email_alert_state(
    self: _owner_types.EzvizClient,
    enable: bool,
    serials: list[str] | str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Update email alert state for the provided devices."""
    if isinstance(serials, (list, tuple, set)):
        serial_param = ",".join(sorted({str(s) for s in serials}))
    else:
        serial_param = str(serials)
    data = {"enable": str(bool(enable)).lower(), "devices": serial_param}
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_DEVICE_EMAIL_ALERT,
        data=data,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not save device email alert state")
    return json_output


def get_group_defence_mode(
    self: _owner_types.EzvizClient, max_retries: int, *, _owner: _ModuleType
) -> _owner_types.Any:
    """Get group arm status. The alarm arm/disarm concept on 1st page of app."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    json_output = self._request_json(
        "GET",
        _owner.API_ENDPOINT_GROUP_DEFENCE_MODE,
        params={"groupId": -1},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get group defence status")
    return json_output.get("mode")


def cancel_alarm_device(
    self: _owner_types.EzvizClient, serial: str, max_retries: int, *, _owner: _ModuleType
) -> bool:
    """Cacnel alarm on an Alarm device."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    json_output = self._request_json(
        "POST",
        _owner.API_ENDPOINT_CANCEL_ALARM,
        data={"subSerial": serial},
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not cancel alarm siren")
    return True
