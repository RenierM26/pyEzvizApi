"""Offline checks for the app-traced cloud settings."""

from collections.abc import Callable
import json
from typing import Any
from unittest.mock import Mock

import pytest

from pyezvizapi.devices import settings
from pyezvizapi.exceptions import PyEzvizError


@pytest.mark.parametrize("mode", list(settings.RecordingMode))
def test_numeric_recording_mode(mode: settings.RecordingMode) -> None:
    client = Mock()
    settings.set_recording_mode(client, "serial", mode, channel=2)
    serial, channel, key, value = client.set_device_key_value.call_args.args
    assert (serial, channel, key, json.loads(value)) == (
        "serial",
        2,
        "Record_Mode",
        {"mode": int(mode)},
    )
    client.switch_status.assert_not_called()


@pytest.mark.parametrize(("enabled", "expected"), [(True, "preRolling"), (False, "event")])
def test_preroll_preserves_outer_config(enabled: bool, expected: str) -> None:
    client = Mock()
    original = {"recordMode": "event" if enabled else "preRolling", "preRecordParams": {"fps": 2}}
    client.get_device_feature_value.return_value = {"data": original}
    settings.set_recording_pre_roll(client, "serial", enabled, local_index="2")
    client.get_device_feature_value.assert_called_once_with(
        "serial", "Video", "RecordStorage", "RecordMode", local_index="2"
    )
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "Video",
        "2",
        "RecordStorage",
        "RecordMode",
        {"value": {"recordMode": expected, "preRecordParams": {"fps": 2}}},
    )
    assert original["recordMode"] != expected


def test_preroll_frame_rate_and_enhancement_use_distinct_payloads() -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {
        "data": {"recordMode": "preRolling", "extra": True}
    }
    settings.set_recording_pre_roll_fps(client, "serial", 4)
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "Video",
        "1",
        "RecordStorage",
        "RecordMode",
        {"value": {"recordMode": "preRolling", "preRecordParams": {"fps": 4}, "extra": True}},
    )
    client.reset_mock()
    client.get_device_feature_value.return_value = {
        "data": {"recordMode": "event", "eventRecordParams": {"suppleRecordStorage": 10}}
    }
    settings.set_supplemental_event_recording(client, "serial", False)
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "Video",
        "1",
        "RecordStorage",
        "RecordMode",
        {"value": {"recordMode": "event", "eventRecordParams": {"suppleRecordEnabled": False}}},
    )


def test_indicator_modes_use_channel_and_global_routes() -> None:
    client = Mock()
    settings.set_indicator_daylight_mode(
        client, "serial", settings.IndicatorDaylightMode.DAYTIME_ONLY
    )
    serial, channel, key, value = client.set_device_key_value.call_args.args
    assert (serial, channel, key, json.loads(value)) == (
        "serial",
        1,
        "IndicatorLight",
        {"enable": 1, "mode": 0},
    )
    settings.set_indicator_night_mode(client, "serial", False)
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "global",
        "0",
        "IndicatorLight",
        "IndicatorLightCfg",
        {"value": {"enabled": False, "mode": "nightMode"}},
    )


def test_iot_wdr_toggle_preserves_level_and_slider_uses_same_route() -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {
        "data": {"hdrSwitchEnabled": "open", "WDRLevel1": 30}
    }
    settings.set_iot_wdr_level(client, "serial", 70, local_index="2")
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "Video",
        "2",
        "ImageBacklight",
        "WDR",
        {"value": {"hdrSwitchEnabled": "open", "WDRLevel1": 70}},
    )
    client.reset_mock()
    settings.set_iot_wdr_enabled(client, "serial", False, local_index="2")
    client.set_iot_feature.assert_called_once_with(
        "serial",
        "Video",
        "2",
        "ImageBacklight",
        "WDR",
        {"value": {"hdrSwitchEnabled": "close", "WDRLevel1": 30}},
    )


@pytest.mark.parametrize(
    ("setter", "value", "data"),
    [
        (settings.set_recording_pre_roll, True, None),
        (settings.set_recording_pre_roll, True, {"recordMode": "allDay"}),
        (settings.set_recording_pre_roll_fps, 4, {"recordMode": "event"}),
        (settings.set_recording_pre_roll_fps, 3, {"recordMode": "preRolling"}),
        (settings.set_supplemental_event_recording, True, {"recordMode": "preRolling"}),
        (settings.set_iot_wdr_level, 30, {"hdrSwitchEnabled": "close"}),
        (settings.set_iot_wdr_level, True, {"hdrSwitchEnabled": "open"}),
        (settings.set_iot_wdr_enabled, True, {"WDRLevel1": "bad"}),
    ],
)
def test_invalid_or_unavailable_setting_never_writes(
    setter: Callable[..., None], value: Any, data: dict[str, Any] | None
) -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {"data": data}
    with pytest.raises(PyEzvizError):
        setter(client, "serial", value)
    client.set_iot_feature.assert_not_called()
    client.switch_status.assert_not_called()


def test_rejected_iot_write_does_not_fall_back_to_switch() -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {"data": {"WDRLevel1": 30}}
    client.set_iot_feature.side_effect = PyEzvizError("server rejected write")
    with pytest.raises(PyEzvizError, match="server rejected"):
        settings.set_iot_wdr_enabled(client, "serial", True)
    client.set_iot_feature.assert_called_once()
    client.switch_status.assert_not_called()
