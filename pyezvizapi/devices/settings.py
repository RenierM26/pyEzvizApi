"""Typed helpers for the app's cloud recording, indicator, and WDR routes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import time
from enum import IntEnum
import json
from typing import TYPE_CHECKING, Any

from pyezvizapi._shared.coercion import decode_json
from pyezvizapi.devices.capabilities import SupportExtView
from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.devices.features import optionals_mapping
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient

_RECORD_STORAGE = "RecordStorage"
_RECORD_MODE = "RecordMode"
_WDR_LEVEL_MAX = 100


class RecordingMode(IntEnum):
    """Numeric cloud recording modes; availability varies by device."""

    EVENT = 0
    ALL_DAY = 1
    STOP = 2
    AOV = 4


class IndicatorDaylightMode(IntEnum):
    """Daylight behavior when the status light is enabled."""

    DAYTIME_ONLY = 0
    ALWAYS_ON = 1


def recording_mode_options(camera_data: Mapping[str, Any]) -> tuple[RecordingMode, ...]:
    """Return advertised numeric choices, without checking disk or work-mode gates."""
    support = SupportExtView.from_camera_data(camera_data)
    mask = support.get("793")
    if type(mask) in (int, str) and str(mask).strip() not in ("", "0"):
        return tuple(
            mode
            for token, mode in (
                ("1", RecordingMode.EVENT),
                ("2", RecordingMode.ALL_DAY),
                ("4", RecordingMode.AOV),
            )
            if support.has("793", (token,))
        )
    if str(support.get("219")).strip() == "1":
        return (RecordingMode.EVENT, RecordingMode.ALL_DAY, RecordingMode.STOP)
    return ()


def reported_indicator_daylight_mode(
    camera_data: Mapping[str, Any],
) -> IndicatorDaylightMode | None:
    """Return a recognized daylight mode with flag 331; switch 3 is a separate gate."""
    support = SupportExtView.from_camera_data(camera_data)
    if str(support.get("331")).strip() != "1":
        return None
    config = decode_json(optionals_mapping(camera_data).get("IndicatorLight"))
    if not isinstance(config, Mapping):
        return None
    mode = config.get("mode")
    return next(
        (choice for choice in IndicatorDaylightMode if str(mode).strip() == str(choice.value)),
        None,
    )


def set_recording_mode(
    client: EzvizClient,
    serial: str,
    mode: RecordingMode,
    *,
    channel: int = 1,
) -> None:
    """Write the numeric mode on the app's key/value route, not switch 29."""

    if not isinstance(mode, RecordingMode):
        raise PyEzvizError("Expected a RecordingMode")
    if type(channel) is not int or channel < 0:
        raise PyEzvizError("Recording channel must be a nonnegative integer")
    client.set_device_key_value(serial, channel, "Record_Mode", json.dumps({"mode": int(mode)}))


def _read_video_setting(
    client: EzvizClient, serial: str, domain: str, prop: str, local_index: str
) -> dict[str, Any]:
    # Validate the Video route's syntax only; it does not prove profile support.
    route = CameraChannel("Video", local_index)
    response = client.get_device_feature_value(
        serial, route.resource_identifier, domain, prop, local_index=route.local_index
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise PyEzvizError(f"Missing or invalid {domain}.{prop} configuration")
    return dict(data)


def _require_bool(enabled: bool) -> None:
    if not isinstance(enabled, bool):
        raise PyEzvizError("Expected a boolean setting value")


def set_recording_pre_roll(
    client: EzvizClient, serial: str, enabled: bool, *, local_index: str = "1"
) -> None:
    """Toggle pre-roll on a supported resource, preserving the fetched settings."""

    _require_bool(enabled)
    data = _read_video_setting(client, serial, _RECORD_STORAGE, _RECORD_MODE, local_index)
    if data.get("recordMode") not in ("event", "preRolling"):
        raise PyEzvizError("Pre-roll requires event or pre-roll recording mode")
    data["recordMode"] = "preRolling" if enabled else "event"
    client.set_iot_feature(
        serial, "Video", local_index, _RECORD_STORAGE, _RECORD_MODE, {"value": data}
    )


def set_recording_pre_roll_fps(
    client: EzvizClient, serial: str, fps: int, *, local_index: str = "1"
) -> None:
    """Set the app's 2/4 fps pre-roll option when pre-roll is active."""

    if type(fps) is not int or fps not in (2, 4):
        raise PyEzvizError("Pre-roll frame rate must be 2 or 4")
    data = _read_video_setting(client, serial, _RECORD_STORAGE, _RECORD_MODE, local_index)
    if data.get("recordMode") != "preRolling":
        raise PyEzvizError("Pre-roll must be enabled before setting its frame rate")
    data["preRecordParams"] = {"fps": fps}
    client.set_iot_feature(
        serial, "Video", local_index, _RECORD_STORAGE, _RECORD_MODE, {"value": data}
    )


def set_supplemental_event_recording(
    client: EzvizClient, serial: str, enabled: bool, *, local_index: str = "1"
) -> None:
    """Set recording enhancement on a resource already in event mode."""

    _require_bool(enabled)
    data = _read_video_setting(client, serial, _RECORD_STORAGE, _RECORD_MODE, local_index)
    if data.get("recordMode") != "event":
        raise PyEzvizError("Recording enhancement requires event recording mode")
    payload = {"recordMode": "event", "eventRecordParams": {"suppleRecordEnabled": enabled}}
    client.set_iot_feature(
        serial, "Video", local_index, _RECORD_STORAGE, _RECORD_MODE, {"value": payload}
    )


def set_indicator_daylight_mode(
    client: EzvizClient, serial: str, mode: IndicatorDaylightMode
) -> None:
    """Set the channel-1 daylight behavior of an enabled status light."""

    if not isinstance(mode, IndicatorDaylightMode):
        raise PyEzvizError("Expected an IndicatorDaylightMode")
    client.set_device_key_value(
        serial, 1, "IndicatorLight", json.dumps({"enable": 1, "mode": int(mode)})
    )


def set_indicator_night_mode(client: EzvizClient, serial: str, enabled: bool) -> None:
    """Set the separate device-global indicator night-mode option."""

    _require_bool(enabled)
    client.set_iot_feature(
        serial,
        "global",
        "0",
        "IndicatorLight",
        "IndicatorLightCfg",
        {"value": {"enabled": enabled, "mode": "nightMode"}},
    )


def _require_wdr_level(level: object) -> None:
    if type(level) is not int or not 0 <= level <= _WDR_LEVEL_MAX:
        raise PyEzvizError("WDR level must be an integer from 0 to 100")


def set_iot_wdr_enabled(
    client: EzvizClient, serial: str, enabled: bool, *, local_index: str = "1"
) -> None:
    """Toggle cloud IoT WDR without changing the reported level."""

    _require_bool(enabled)
    data = _read_video_setting(client, serial, "ImageBacklight", "WDR", local_index)
    level = data.get("WDRLevel1")
    _require_wdr_level(level)
    payload = {"hdrSwitchEnabled": "open" if enabled else "close", "WDRLevel1": level}
    client.set_iot_feature(
        serial, "Video", local_index, "ImageBacklight", "WDR", {"value": payload}
    )


def set_iot_wdr_level(
    client: EzvizClient, serial: str, level: int, *, local_index: str = "1"
) -> None:
    """Set cloud IoT WDR strength; do not implicitly enable WDR."""

    _require_wdr_level(level)
    data = _read_video_setting(client, serial, "ImageBacklight", "WDR", local_index)
    if data.get("hdrSwitchEnabled") != "open":
        raise PyEzvizError("WDR must be enabled before setting its level")
    payload = {"hdrSwitchEnabled": "open", "WDRLevel1": level}
    client.set_iot_feature(
        serial, "Video", local_index, "ImageBacklight", "WDR", {"value": payload}
    )


def set_mute_plan_enabled(
    client: EzvizClient, serial: str, enabled: bool, *, channel: CameraChannel
) -> None:
    """Toggle a supported mute plan without replacing its schedule.

    Callers must verify that the product profile advertises this property
    on the selected channel.
    """
    _require_bool(enabled)
    resource, index = channel.resource_identifier, channel.local_index
    response = client.get_device_feature_value(
        serial, resource, "SoundSetting", "MutePlan", local_index=index
    )
    config = response.get("data")
    if not isinstance(config, dict) or not isinstance(config.get("plan"), list):
        raise PyEzvizError("Missing or invalid mute plan schedule")
    client.set_iot_feature(
        serial,
        resource,
        index,
        "SoundSetting",
        "MutePlan",
        {"value": {**config, "enabled": enabled}},
    )


def set_tracking_zoom_enabled(client: EzvizClient, serial: str, enabled: bool) -> None:
    """Toggle zoom during tracking on the app's Video/1 route.

    Callers must verify the product profile and that tracking is active.
    This does not enable tracking itself.
    """
    _require_bool(enabled)
    client.set_iot_feature(
        serial,
        "Video",
        "1",
        "PTZTrace",
        "AutoTraceParams",
        {"value": {"trackZoomEnabled": enabled}},
    )


def set_mute_plan_schedule(
    client: EzvizClient,
    serial: str,
    slots: tuple[tuple[time, time, tuple[int, ...]], ...],
    *,
    channel: CameraChannel,
) -> None:
    """Replace and enable a supported mute plan, using ISO weekdays (1-7)."""
    if len(slots) > 4:
        raise PyEzvizError("A mute plan supports at most four slots")
    plan = []
    for start, end, days in slots:
        if not days or any(type(day) is not int or not 1 <= day <= 7 for day in days):
            raise PyEzvizError("Mute plan requires ISO weekdays from 1 to 7")
        if any(t.second or t.microsecond or t.tzinfo is not None for t in (start, end)):
            raise PyEzvizError("Mute plan requires local times at minute precision")
        duration = ((end.hour - start.hour) * 60 + end.minute - start.minute) % 1440
        plan.append(
            {
                "repeatPeriod": list(days),
                "startTime": start.isoformat(),
                "sustain": max(1, duration),
                "enabled": True,
                "action": [{"actionType": "MutePlan", "startValue": True}],
            }
        )
    client.set_iot_feature(
        serial,
        channel.resource_identifier,
        channel.local_index,
        "SoundSetting",
        "MutePlan",
        {"value": {"plan": plan, "enabled": True}},
    )


def set_doorlock_night_light_enabled(client: EzvizClient, serial: str, enabled: bool) -> None:
    """Toggle the indoor night light on a lock advertising DoorLock/0 NightLightCfg.

    Use this for the app's binary branch. Mode-capable locks may require a
    mode selection in addition to the enabled state.
    """
    _require_bool(enabled)
    client.set_iot_feature(
        serial, "DoorLock", "0", "LightCtrl", "NightLightCfg", {"value": {"enabled": enabled}}
    )


class DoorLockLightMode(IntEnum):
    """App picker options; off is sent without a mode field."""

    DIM_LIGHT = 0
    ALL_DAY = 1
    SENSING = 2
    OFF = 99


def _doorlock_light_payload(mode: DoorLockLightMode) -> dict[str, bool | int]:
    if not isinstance(mode, DoorLockLightMode):
        raise PyEzvizError("Expected a DoorLockLightMode")
    if mode is DoorLockLightMode.OFF:
        return {"enabled": False}
    return {"enabled": True, "mode": int(mode)}


def set_doorlock_night_light_mode(
    client: EzvizClient, serial: str, mode: DoorLockLightMode
) -> None:
    """Set the indoor night-light mode on a lock advertising that mode picker."""
    if mode is DoorLockLightMode.SENSING:
        raise PyEzvizError("Sensing mode is only available for the welcome light")
    client.set_iot_feature(
        serial,
        "DoorLock",
        "0",
        "LightCtrl",
        "NightLightCfg",
        {"value": _doorlock_light_payload(mode)},
    )


def set_doorlock_welcome_light_mode(
    client: EzvizClient, serial: str, mode: DoorLockLightMode
) -> None:
    """Set the welcome-light mode on a lock advertising the projection lamp picker."""
    client.set_iot_feature(
        serial,
        "DoorLock",
        "0",
        "RGBLightCtrl",
        "ProjectionLampCfg",
        {"value": _doorlock_light_payload(mode)},
    )


def get_recording_schedule(
    client: EzvizClient, serial: str, *, channel: CameraChannel
) -> dict[str, Any]:
    """Read the schedule from a video resource advertising TimingRecord.RecordSchedule."""
    return _read_timing_record(client, serial, channel, "RecordSchedule")


def get_recording_storage_params(
    client: EzvizClient, serial: str, *, channel: CameraChannel
) -> dict[str, Any]:
    """Read storage allocation and overwrite settings, not schedule slots."""
    return _read_timing_record(client, serial, channel, "ScheduleRecordParams")


def _read_timing_record(
    client: EzvizClient, serial: str, channel: CameraChannel, property_name: str
) -> dict[str, Any]:
    response = client.get_device_feature_value(
        serial,
        channel.resource_identifier,
        "TimingRecord",
        property_name,
        local_index=channel.local_index,
    )
    data = response.get("data")
    if not isinstance(data, dict):
        raise PyEzvizError(f"Missing or invalid TimingRecord.{property_name} configuration")
    return dict(data)
