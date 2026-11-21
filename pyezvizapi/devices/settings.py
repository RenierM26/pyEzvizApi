"""Typed helpers for the app's cloud recording, indicator, and WDR routes."""

from __future__ import annotations

from collections.abc import Mapping
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
