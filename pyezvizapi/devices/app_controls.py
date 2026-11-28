"""Cloud camera controls traced from the Android settings app."""

# ruff: noqa: SLF001
# This SDK facade shares the authenticated client transport and result validation.

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum, IntEnum
import json
from typing import TYPE_CHECKING, Any

from pyezvizapi._shared.coercion import decode_json
from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


class CameraAppProperty(Enum):
    """Known Android settings with property-specific JSON objects."""

    HOMING_PRESET = ("Video", "1", "PTZMaintenance", "HomingPresetCfg")
    PLATE_REGION = ("Video", "1", "MotorVehiclesAnalysis", "PlateRecognitionCfg")
    MICROPHONE_AUTO_GAIN = ("Video", "1", "AudioMgr", "MicAdaptive")
    PROMPT_TONE_VOLUME = ("global", "0", "SoundSetting", "PromptToneVolume")
    VOICE_STYLE = ("Video", "1", "SoundSetting", "VoiceStyle")
    VEHICLE_TRACKING = ("Video", "1", "VehicleDetections", "VehicleTraceSwitch")
    WAKEUP_STRATEGY = ("Video", "1", "EnergySaving", "WakeupStrategyCfg")
    ENERGY_MODE = ("Video", "1", "EnergySaving", "EnergyModeCfg")
    TIME_LAPSE = ("Video", "1", "BatCustomSpecial", "TimeLapseMode")
    ELECTRONIC_STABILIZATION = ("Video", "1", "ImageEnhance", "EIS")
    HORIZON_ENHANCEMENT = ("Video", "1", "ImageEnhance", "HorizonEnhancement")
    RADAR_INTERFERENCE_SUPPRESSION = ("Video", "1", "SensorLight", "RadarFMCfg")
    NIGHTTIME_PROMPT = ("global", "0", "SoundSetting", "PromptParam")
    SMART_COMPRESSION = ("Video", "1", "RecordStorage", "RecordCompressionParams")


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PyEzvizError(f"Missing or invalid {label}")
    return dict(value)


def get_app_property(client: EzvizClient, serial: str, prop: CameraAppProperty) -> dict[str, Any]:
    """Read the app's exact resource; callers should first check product support."""
    resource, index, domain, key = prop.value
    return _object(
        client.get_device_feature_value(serial, resource, domain, key, local_index=index).get(
            "data"
        ),
        key,
    )


def set_app_property(
    client: EzvizClient, serial: str, prop: CameraAppProperty, config: Mapping[str, Any]
) -> None:
    """Write a model-supported configuration object using the app's envelope."""
    resource, index, domain, key = prop.value
    client.set_iot_feature(serial, resource, index, domain, key, {"value": dict(config)})


def get_smart_recording_compression(client: EzvizClient, serial: str) -> bool | None:
    """Return the reported Smart Compression flag, or None for an unknown flag."""
    enabled = get_app_property(client, serial, CameraAppProperty.SMART_COMPRESSION).get("enabled")
    return enabled if isinstance(enabled, bool) else None


def set_smart_recording_compression(client: EzvizClient, serial: str, *, enabled: bool) -> None:
    """Set Smart Compression on models exposing the app's Video/1 property."""
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    set_app_property(client, serial, CameraAppProperty.SMART_COMPRESSION, {"enabled": enabled})


_APP_SWITCH_WRITES = {
    CameraAppProperty.ELECTRONIC_STABILIZATION: None,
    CameraAppProperty.HORIZON_ENHANCEMENT: None,
    CameraAppProperty.RADAR_INTERFERENCE_SUPPRESSION: {},
    CameraAppProperty.NIGHTTIME_PROMPT: {"mode": "nighttime"},
}


def get_camera_app_switch(client: EzvizClient, serial: str, prop: CameraAppProperty) -> bool | None:
    """Read a traced switch, keeping an unknown flag distinct from off."""
    if prop not in _APP_SWITCH_WRITES:
        raise ValueError("Not a supported camera app switch")
    enabled = get_app_property(client, serial, prop).get("enabled")
    return enabled if isinstance(enabled, bool) else None


def set_camera_app_switch(
    client: EzvizClient, serial: str, prop: CameraAppProperty, *, enabled: bool
) -> None:
    """Set a traced switch using its app-specific payload."""
    if prop not in _APP_SWITCH_WRITES or not isinstance(enabled, bool):
        raise ValueError("Expected a supported camera app switch and a boolean")
    template = _APP_SWITCH_WRITES[prop]
    if template is None:
        config = get_app_property(client, serial, prop)
        if not isinstance(config.get("enabled"), bool):
            raise PyEzvizError("Cannot update an image switch with unknown current state")
    else:
        config = dict(template)
    config["enabled"] = enabled
    set_app_property(client, serial, prop, config)


class CameraPlan(IntEnum):
    """The Android base timer editor's camera plan types."""

    SLEEP = 4
    PATROL = 14


def _plan_params(serial: str, plan: CameraPlan) -> dict[str, Any]:
    if not isinstance(plan, CameraPlan):
        raise ValueError("plan must be a CameraPlan")
    return {
        "deviceSerial": serial,
        "channelNo": 0,
        "timingPlanType": int(plan),
        "secondDayEnable": "true",
    }


def get_camera_plan(client: EzvizClient, serial: str, plan: CameraPlan) -> dict[str, Any]:
    """Read the Android sleep/patrol schedule and its raw timingPlanVos."""
    response = client._request_json(
        "GET", "/v3/devconfig/v2/base/plan", params=_plan_params(serial, plan)
    )
    client._ensure_ok(response, "Could not read camera plan")
    return response


def set_camera_plan(
    client: EzvizClient,
    serial: str,
    plan: CameraPlan,
    slots: Sequence[Mapping[str, Any]],
    *,
    enabled: bool,
) -> None:
    """Replace the schedule using device-format timing slots, not app UI input."""
    if not isinstance(enabled, bool) or len(slots) > 4:
        raise ValueError("Expected a boolean and at most four timing slots")
    data = _plan_params(serial, plan)
    data.update(enable=int(enabled), timingPlanQos=json.dumps([dict(slot) for slot in slots]))
    response = client._request_json("PUT", "/v3/devconfig/v2/base/plan", data=data)
    client._ensure_ok(response, "Could not write camera plan")


def get_patrol_path(client: EzvizClient, serial: str, *, channel: CameraChannel) -> dict[str, Any]:
    """Read patrol path 1 through the action on the explicitly selected PTZ resource."""
    response = client.set_iot_action(
        serial,
        channel.resource_identifier,
        channel.local_index,
        "PTZPreset",
        "GetPTZPatrolPath",
        {"value": {"patrolID": 1}},
    )
    return _object(response.get("data"), "patrol path")


def set_patrol_path(
    client: EzvizClient,
    serial: str,
    sequence: Sequence[Mapping[str, Any]],
    *,
    channel: CameraChannel,
    enabled: bool,
) -> None:
    """Modify existing patrol path 1; do not create/delete or move the camera directly."""
    if not isinstance(enabled, bool) or not sequence:
        raise ValueError("Expected a boolean and at least one existing patrol point")
    client.set_iot_action(
        serial,
        channel.resource_identifier,
        channel.local_index,
        "PTZPreset",
        "ModifyPTZPatrolPath",
        {
            "value": {
                "patrolID": 1,
                "patrolName": "1",
                "enabled": enabled,
                "PatrolSequenceList": [dict(point) for point in sequence],
            }
        },
    )


def calibrate_ptz(client: EzvizClient, serial: str) -> None:
    """Start app-style PTZ calibration; the camera can physically move."""
    response = client._request_json(
        "POST",
        f"/api/device/v2/sysOper/{serial}",
        params={"oper": 4, "delay": 0},
        data={"sessionId": client._token.get("session_id")},
        retry_401=False,
    )
    if str(response.get("resultCode")) != "0":
        raise PyEzvizError("Could not calibrate PTZ")


def get_privacy_mask(client: EzvizClient, serial: str, *, channel: int) -> dict[str, Any]:
    """Read the legacy rectangular privacy cover, not camera sleep or an AI fence."""
    response = client._request_json(
        "GET", f"/v3/devconfig/v1/keyValue/{serial}/{channel}/op", params={"key": "pri_cover_area"}
    )
    client._ensure_ok(response, "Could not read privacy mask")
    return _object(decode_json(response.get("valueInfo")), "privacy mask")


def set_privacy_mask(
    client: EzvizClient,
    serial: str,
    rectangles: Sequence[tuple[int, int, int, int]],
    *,
    channel: int,
) -> None:
    """Replace up to four masks using integer coordinates normalized to 0-1000."""
    if len(rectangles) > 4:
        raise ValueError("At most four privacy rectangles are supported")
    for left, top, right, bottom in rectangles:
        if any(type(x) is not int for x in (left, top, right, bottom)) or not (
            0 <= left < right <= 1000 and 0 <= top < bottom <= 1000
        ):
            raise ValueError("Invalid privacy rectangle")
    keys = ("ltop_x", "ltop_y", "rlow_x", "rlow_y")
    padded = [*rectangles, *([(0, 0, 0, 0)] * (4 - len(rectangles)))]
    value = {
        "cover_num": len(rectangles),
        "cover_data": [dict(zip(keys, box, strict=True)) for box in padded],
    }
    client.set_device_key_value(serial, channel, "pri_cover_area", json.dumps(value))


def _pir_grid(grid: object) -> bool:
    return (
        isinstance(grid, list)
        and bool(grid)
        and isinstance(grid[0], list)
        and bool(grid[0])
        and all(
            isinstance(row, list)
            and len(row) == len(grid[0])
            and all(type(cell) is int and cell in (0, 1) for cell in row)
            for row in grid
        )
    )


def get_pir_detection_grid(
    client: EzvizClient, sub_serial: str, *, channel: int
) -> list[list[int]]:
    """Read the PIR grid on the app's sub-device serial and explicit channel."""
    response = client._request_json("GET", f"/v3/alarms/device/pir/area/{sub_serial}/{channel}")
    client._ensure_ok(response, "Could not read PIR grid")
    area = _object(response.get("area"), "PIR area")
    grid = decode_json(area.get("area"))
    if (
        not isinstance(grid, list)
        or not _pir_grid(grid)
        or (area.get("rows"), area.get("cols")) != (len(grid), len(grid[0]))
    ):
        raise PyEzvizError("Invalid PIR grid")
    return grid


def set_pir_detection_grid(
    client: EzvizClient, sub_serial: str, grid: list[list[int]], *, channel: int
) -> None:
    """Replace the PIR grid; require dimensions matching the current device grid."""
    if not _pir_grid(grid):
        raise ValueError("Expected a rectangular grid of 0/1 integers")
    current = get_pir_detection_grid(client, sub_serial, channel=channel)
    if (len(grid), len(grid[0])) != (len(current), len(current[0])):
        raise ValueError("PIR grid dimensions do not match the current device grid")
    response = client._request_json(
        "POST",
        f"/v3/alarms/device/pir/area/{sub_serial}/{channel}",
        data={"rows": len(grid), "cols": len(grid[0]), "area": json.dumps(grid)},
    )
    client._ensure_ok(response, "Could not write PIR grid")


def get_legacy_motion_area(client: EzvizClient, serial: str, *, channel: int) -> dict[str, Any]:
    """Read legacy motion regions; this is not a general region encoder."""
    response = client._request_json(
        "GET",
        f"/v3/devices/{serial}/{channel}/motionDetectAreaInfo",
        params={"category": "TEL"},
    )
    client._ensure_ok(response, "Could not read legacy motion area")
    return _object(response.get("motionDetectAreaInfo"), "legacy motion area")


def reported_custom_alarm_sound(camera_data: Mapping[str, Any]) -> int | None:
    """Read the selected custom voice from STATUS; other modes have no custom selection."""
    status = decode_json(camera_data.get("STATUS"))
    if not isinstance(status, Mapping) or status.get("alarmSoundMode") not in (3, "3"):
        return None
    optionals = decode_json(status.get("optionals"))
    voice = optionals.get("voiceIndex") if isinstance(optionals, Mapping) else None
    if isinstance(voice, str) and voice.isascii() and voice.isdecimal() and len(voice) <= 10:
        voice = int(voice)
    return voice if type(voice) is int and voice > 0 else None


def set_custom_alarm_sound(client: EzvizClient, serial: str, *, voice_id: int) -> None:
    """Select an already-uploaded custom voice without changing the legacy setter."""
    if type(voice_id) is not int or voice_id <= 0:
        raise ValueError("voice_id must be a positive integer")
    response = client._request_json(
        "PUT",
        f"/v3/devices/{serial}/alarm/sound",
        params={"enable": 1, "soundType": 3, "voiceId": voice_id},
    )
    client._ensure_ok(response, "Could not select custom alarm sound")


def format_cloud_sd_card(client: EzvizClient, serial: str, *, disk: int, confirm: bool) -> None:
    """Erase the selected cloud-managed SD disk. Recheck progress separately."""
    if confirm is not True or type(disk) is not int or disk < 1:
        raise ValueError("Formatting requires confirm=True and a positive disk index")
    response = client._request_json(
        "PUT",
        f"/v3/basics/v1/storages/{serial}/{disk}/format",
        params={"type": 0},
        retry_401=False,
    )
    client._ensure_ok(response, "Could not start SD formatting")


def get_cloud_sd_format_progress(client: EzvizClient, serial: str) -> Any:
    """Return the reported per-device cloud formatting progress."""
    response = client._request_json(
        "GET", f"/v3/basics/v1/storages/{serial}/formattingRate", params={"type": 0}
    )
    client._ensure_ok(response, "Could not read SD formatting progress")
    if response.get("formattingRateInfo") is None:
        raise PyEzvizError("Missing SD formatting progress")
    return response["formattingRateInfo"]
