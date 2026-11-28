"""Offline checks for the app-traced cloud settings."""

from collections.abc import Callable, Iterator
from datetime import time
import json
from typing import Any
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from pyezvizapi import EzvizClient
from pyezvizapi.devices import settings
from pyezvizapi.devices.channels import CameraChannel, CameraChannelError
from pyezvizapi.devices.tracking import (
    intelligent_app_enabled,
    iter_resource_intelligent_apps,
    set_app_auto_tracking,
    set_intelligent_app_config,
)
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


@pytest.mark.parametrize(
    ("support", "expected"),
    [
        ({"219": 1}, ("EVENT", "ALL_DAY", "STOP")),
        ({"219": "1", "793": " 2, 4 "}, ("ALL_DAY", "AOV")),
        ({"219": 1, "793": "0"}, ("EVENT", "ALL_DAY", "STOP")),
        ({"219": 1, "793": "14"}, ()),
        ({"219": 0, "88": 1}, ()),
        ({"219": True}, ()),
    ],
)
def test_recording_options_use_advertised_numeric_modes(
    support: dict[str, Any], expected: tuple[str, ...]
) -> None:
    data = {"deviceInfos": {"supportExt": support}}
    assert tuple(mode.name for mode in settings.recording_mode_options(data)) == expected


@pytest.mark.parametrize(
    ("support", "optionals", "expected"),
    [
        (1, {"IndicatorLight": {"mode": 0}}, settings.IndicatorDaylightMode.DAYTIME_ONLY),
        (
            "1",
            '{"IndicatorLight":"{\\"mode\\":\\"1\\"}"}',
            settings.IndicatorDaylightMode.ALWAYS_ON,
        ),
        (1, {"IndicatorLight": {"mode": -1}}, None),
        (1, {"IndicatorLight": {"mode": True}}, None),
        (1, {"IndicatorLight": "not JSON"}, None),
        (0, {"IndicatorLight": {"mode": 1}}, None),
        (True, {"IndicatorLight": {"mode": 1}}, None),
    ],
)
def test_reported_indicator_daylight_mode(
    support: Any, optionals: Any, expected: settings.IndicatorDaylightMode | None
) -> None:
    data = {"supportExt": {"331": support}, "STATUS": {"optionals": optionals}}
    assert settings.reported_indicator_daylight_mode(data) is expected


@pytest.fixture
def device_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[EzvizClient, list[requests.PreparedRequest], list[dict[str, Any]]]]:
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.invalid"})
    sent: list[requests.PreparedRequest] = []
    replies: list[dict[str, Any]] = []

    def send(
        _session: requests.Session, request: requests.PreparedRequest, **_kwargs: Any
    ) -> requests.Response:
        sent.append(request)
        assert replies, f"Unexpected request: {request.method} {request.url}"
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(replies.pop(0)).encode()  # noqa: SLF001 - offline response.
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    try:
        yield client, sent, replies
    finally:
        client.close_session()


def test_query_and_form_key_value_puts_keep_distinct_wire_contracts(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}}] * 3)
    settings.set_recording_mode(client, "CAM001", settings.RecordingMode.AOV, channel=7)
    settings.set_indicator_daylight_mode(client, "CAM001", settings.IndicatorDaylightMode.ALWAYS_ON)
    client.set_dev_config_kv("CAM001", 7, "Record_Mode", {"mode": 4})

    assert len(sent) == 3
    for request, channel, key, value in (
        (sent[0], 7, "Record_Mode", {"mode": 4}),
        (sent[1], 1, "IndicatorLight", {"enable": 1, "mode": 1}),
    ):
        url = urlsplit(request.url)
        assert request.method == "PUT"
        assert url.path == f"/v3/devconfig/v1/keyValue/CAM001/{channel}/op"
        query = parse_qs(url.query, strict_parsing=True)
        assert query.keys() == {"key", "value"}
        assert query["key"] == [key]
        (encoded_value,) = query["value"]
        assert json.loads(encoded_value) == value
        assert request.body is None

    form = sent[2]
    assert form.method == "PUT"
    assert form.url == "https://api.example.invalid/v3/devconfig/v1/keyValue/CAM001/7/op"
    assert form.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(form.body, strict_parsing=True) == {
        "key": ["Record_Mode"],
        "value": ['{"mode":4}'],
    }


def test_rejected_query_put_does_not_fall_back_to_form_or_switch(device_requests) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 403}})
    with pytest.raises(PyEzvizError, match="Could not set common key value"):
        settings.set_recording_mode(client, "CAM001", settings.RecordingMode.EVENT)

    (request,) = sent
    assert request.method == "PUT"
    assert urlsplit(request.url).path == "/v3/devconfig/v1/keyValue/CAM001/1/op"
    assert parse_qs(urlsplit(request.url).query)["key"] == ["Record_Mode"]
    assert request.body is None


@pytest.mark.parametrize(
    ("setter", "value", "domain", "prop", "state", "payload"),
    [
        (
            settings.set_recording_pre_roll,
            True,
            "RecordStorage",
            "RecordMode",
            {"recordMode": "event", "preRecordParams": {"fps": 2}},
            {"recordMode": "preRolling", "preRecordParams": {"fps": 2}},
        ),
        (
            settings.set_recording_pre_roll_fps,
            4,
            "RecordStorage",
            "RecordMode",
            {"recordMode": "preRolling"},
            {"recordMode": "preRolling", "preRecordParams": {"fps": 4}},
        ),
        (
            settings.set_supplemental_event_recording,
            False,
            "RecordStorage",
            "RecordMode",
            {"recordMode": "event", "eventRecordParams": {"suppleRecordStorage": 10}},
            {"recordMode": "event", "eventRecordParams": {"suppleRecordEnabled": False}},
        ),
        (
            settings.set_iot_wdr_enabled,
            False,
            "ImageBacklight",
            "WDR",
            {"hdrSwitchEnabled": "open", "WDRLevel1": 30},
            {"hdrSwitchEnabled": "close", "WDRLevel1": 30},
        ),
        (
            settings.set_iot_wdr_level,
            70,
            "ImageBacklight",
            "WDR",
            {"hdrSwitchEnabled": "open", "WDRLevel1": 30},
            {"hdrSwitchEnabled": "open", "WDRLevel1": 70},
        ),
    ],
)
def test_video_iot_stays_on_the_explicit_local_index(
    device_requests, setter, value, domain, prop, state, payload
) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "data": state}, {"meta": {"code": 200}}])
    setter(client, "cam001", value, local_index="2")

    url = f"https://api.example.invalid/v3/iot-feature/feature/CAM001/Video/2/{domain}/{prop}"
    assert [(request.method, request.url) for request in sent] == [("GET", url), ("PUT", url)]
    assert sent[0].body is None
    assert sent[1].headers["Content-Type"] == "application/json"
    assert json.loads(sent[1].body) == {"value": payload}


def test_night_mode_is_device_global_and_does_not_read_video(device_requests) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 200}})
    settings.set_indicator_night_mode(client, "cam001", False)

    (request,) = sent
    assert request.method == "PUT"
    assert request.url == (
        "https://api.example.invalid/v3/iot-feature/feature/CAM001/global/0/IndicatorLight/IndicatorLightCfg"
    )
    assert request.headers["Content-Type"] == "application/json"
    assert json.loads(request.body) == {"value": {"enabled": False, "mode": "nightMode"}}


@pytest.mark.parametrize("channel", [True, -1, "1"])
def test_invalid_legacy_channel_never_reaches_transport(device_requests, channel) -> None:
    client, sent, _ = device_requests
    with pytest.raises(PyEzvizError, match="Recording channel"):
        settings.set_recording_mode(client, "CAM001", settings.RecordingMode.EVENT, channel=channel)
    assert sent == []


@pytest.mark.parametrize("local_index", [1, True, "01", "-1", "1/global"])
def test_invalid_video_index_never_reaches_transport(device_requests, local_index) -> None:
    client, sent, _ = device_requests
    with pytest.raises(CameraChannelError, match="invalid"):
        settings.set_iot_wdr_enabled(client, "CAM001", True, local_index=local_index)
    assert sent == []


@pytest.mark.parametrize("rejected_method", ["GET", "PUT"])
def test_rejected_video_iot_request_never_changes_scope_or_route(
    device_requests, rejected_method: str
) -> None:
    client, sent, replies = device_requests
    if rejected_method == "PUT":
        replies.append({"meta": {"code": 200}, "data": {"WDRLevel1": 30}})
    replies.append({"meta": {"code": 403}})
    with pytest.raises(PyEzvizError, match="Could not"):
        settings.set_iot_wdr_enabled(client, "CAM001", True, local_index="2")

    url = "https://api.example.invalid/v3/iot-feature/feature/CAM001/Video/2/ImageBacklight/WDR"
    expected = [("GET", url)]
    if rejected_method == "PUT":
        expected.append(("PUT", url))
    assert [(request.method, request.url) for request in sent] == expected


def test_mute_plan_preserves_schedule_on_selected_resource() -> None:
    client = Mock()
    channel = CameraChannel("Video_1", "2")
    config = {"enabled": False, "plan": [{"day": 1}], "extra": 2}
    client.get_device_feature_value.return_value = {"data": config}
    settings.set_mute_plan_enabled(client, "SERIAL", True, channel=channel)
    client.get_device_feature_value.assert_called_once_with(
        "SERIAL", "Video_1", "SoundSetting", "MutePlan", local_index="2"
    )
    client.set_iot_feature.assert_called_once_with(
        "SERIAL",
        "Video_1",
        "2",
        "SoundSetting",
        "MutePlan",
        {"value": {**config, "enabled": True}},
    )
    assert config["enabled"] is False


def test_missing_mute_schedule_does_not_write() -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {"data": {"enabled": False}}
    with pytest.raises(PyEzvizError, match="mute plan schedule"):
        settings.set_mute_plan_enabled(client, "SERIAL", True, channel=CameraChannel("Video", "1"))
    client.set_iot_feature.assert_not_called()


def test_tracking_zoom_only_writes_zoom_field() -> None:
    client = Mock()
    settings.set_tracking_zoom_enabled(client, "SERIAL", False)
    client.set_iot_feature.assert_called_once_with(
        "SERIAL",
        "Video",
        "1",
        "PTZTrace",
        "AutoTraceParams",
        {"value": {"trackZoomEnabled": False}},
    )


def test_replace_mute_schedule() -> None:
    client = Mock()
    settings.set_mute_plan_schedule(
        client, "TEST", ((time(23), time(23, 45), (7,)),), channel=CameraChannel("Video_1", "2")
    )
    client.set_iot_feature.assert_called_once_with(
        "TEST",
        "Video_1",
        "2",
        "SoundSetting",
        "MutePlan",
        {
            "value": {
                "enabled": True,
                "plan": [
                    {
                        "repeatPeriod": [7],
                        "startTime": "23:00:00",
                        "sustain": 45,
                        "enabled": True,
                        "action": [{"actionType": "MutePlan", "startValue": True}],
                    }
                ],
            }
        },
    )


def test_app_tracking_action() -> None:
    client = Mock()
    set_app_auto_tracking(client, "TEST", "app_human_detect", False)
    client.set_iot_action.assert_called_once_with(
        "TEST",
        "Video",
        "1",
        "IntelligentAPP",
        "ModifyAppFunctionCfgs",
        {
            "value": {
                "configLists": [
                    {
                        "appId": "app_human_detect",
                        "path": "/PTZTrace/AutoTraceSwitch/prop",
                        "payload": "false",
                    }
                ]
            }
        },
    )


def test_app_tracking_preserves_explicit_route_and_full_app_id() -> None:
    client = Mock()
    set_app_auto_tracking(
        client,
        "TEST",
        "app_human_detect$:$v3",
        True,
        resource_identifier="Video_1",
        local_index="2",
    )
    client.set_iot_action.assert_called_once_with(
        "TEST",
        "Video_1",
        "2",
        "IntelligentAPP",
        "ModifyAppFunctionCfgs",
        {
            "value": {
                "configLists": [
                    {
                        "appId": "app_human_detect$:$v3",
                        "path": "/PTZTrace/AutoTraceSwitch/prop",
                        "payload": "true",
                    }
                ]
            }
        },
    )


@pytest.mark.parametrize(
    "invalid",
    [
        {"app_id": ""},
        {"resource_identifier": ""},
        {"local_index": ""},
        {"path": "relative"},
        {"path": "/"},
        {"payload": {"enabled": True}},
    ],
)
def test_app_config_rejects_unknown_route_or_unencoded_values(invalid) -> None:
    client = Mock()
    args = {
        "app_id": "app_human_detect$:$v3",
        "resource_identifier": "Video",
        "local_index": "1",
        "path": "/Example/prop",
        "payload": "true",
        **invalid,
    }
    with pytest.raises(PyEzvizError):
        set_intelligent_app_config(client, "TEST", **args)
    client.set_iot_action.assert_not_called()


@pytest.mark.parametrize("enabled", [True, False])
def test_doorlock_night_light_uses_lock_resource(enabled: bool) -> None:
    client = Mock()
    settings.set_doorlock_night_light_enabled(client, "TEST", enabled)
    client.set_iot_feature.assert_called_once_with(
        "TEST", "DoorLock", "0", "LightCtrl", "NightLightCfg", {"value": {"enabled": enabled}}
    )


@pytest.mark.parametrize(
    ("mode", "value"),
    [
        (settings.DoorLockLightMode.DIM_LIGHT, {"enabled": True, "mode": 0}),
        (settings.DoorLockLightMode.ALL_DAY, {"enabled": True, "mode": 1}),
        (settings.DoorLockLightMode.OFF, {"enabled": False}),
    ],
)
def test_doorlock_light_picker_payloads(
    mode: settings.DoorLockLightMode, value: dict[str, bool | int]
) -> None:
    client = Mock()
    settings.set_doorlock_night_light_mode(client, "TEST", mode)
    client.set_iot_feature.assert_called_once_with(
        "TEST", "DoorLock", "0", "LightCtrl", "NightLightCfg", {"value": value}
    )
    client.reset_mock()
    settings.set_doorlock_welcome_light_mode(client, "TEST", mode)
    client.set_iot_feature.assert_called_once_with(
        "TEST", "DoorLock", "0", "RGBLightCtrl", "ProjectionLampCfg", {"value": value}
    )


def test_sensing_mode_is_only_for_welcome_light() -> None:
    client = Mock()
    with pytest.raises(PyEzvizError, match="only available"):
        settings.set_doorlock_night_light_mode(client, "TEST", settings.DoorLockLightMode.SENSING)
    client.set_iot_feature.assert_not_called()
    settings.set_doorlock_welcome_light_mode(client, "TEST", settings.DoorLockLightMode.SENSING)
    client.set_iot_feature.assert_called_once_with(
        "TEST",
        "DoorLock",
        "0",
        "RGBLightCtrl",
        "ProjectionLampCfg",
        {"value": {"enabled": True, "mode": 2}},
    )


@pytest.mark.parametrize(
    ("reader", "property_name"),
    [
        (settings.get_recording_schedule, "RecordSchedule"),
        (settings.get_recording_storage_params, "ScheduleRecordParams"),
    ],
)
def test_recording_reads_use_distinct_scoped_properties(
    reader: Callable[..., dict[str, Any]], property_name: str
) -> None:
    client = Mock()
    client.get_device_feature_value.return_value = {"data": {"reported": True}}
    channel = CameraChannel("Video_1", "2")
    assert reader(client, "TEST", channel=channel) == {"reported": True}
    client.get_device_feature_value.assert_called_once_with(
        "TEST", "Video_1", "TimingRecord", property_name, local_index="2"
    )
    client.get_device_feature_value.return_value = {"data": None}
    with pytest.raises(PyEzvizError, match=property_name):
        reader(client, "TEST", channel=channel)


def test_resource_app_discovery_preserves_identity_and_state():
    data = {
        "FEATURE_INFO": {
            "9": {
                "Video": {
                    "IntelligentAPP": {
                        "DownloadedAPP": {
                            "APP": [
                                {"APPID": "human$:$v1", "enabled": "false"},
                            ]
                        }
                    }
                },
                "Video_1": {
                    "IntelligentAPP": {
                        "DownloadedAPP": {
                            "APP": [
                                {"APPID": "human$:$v2", "enabled": 1},
                                {"APPID": "car$:$v3", "enabled": "unexpected"},
                                {"APPID": " "},
                            ]
                        }
                    }
                },
            }
        }
    }
    assert not intelligent_app_enabled(data, "human")
    assert list(
        iter_resource_intelligent_apps(data, feature_group="9", resource_identifier="Video")
    ) == [("human$:$v1", False)]
    assert list(
        iter_resource_intelligent_apps(data, feature_group="9", resource_identifier="Video_1")
    ) == [("human$:$v2", True), ("car$:$v3", None)]
    assert not list(
        iter_resource_intelligent_apps(data, feature_group="10", resource_identifier="Video_1")
    )


@pytest.mark.parametrize(
    ("setting", "path"),
    [
        (settings.ImageSwitch.ANTI_BANDING, "ImageExposure/AntiBandingParams"),
        (settings.ImageSwitch.LOW_LIGHT_ENHANCEMENT, "ImageEnhance/LowLightImageEnhanceCfg"),
        (settings.ImageSwitch.ADAPTIVE_NIGHT_VISION, "FillLight/NightVisionAdaptMode"),
    ],
)
def test_graphics_switch_uses_app_wire_contract(device_requests, setting, path) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "data": {"enabled": False}}, {"meta": {"code": 200}}])
    assert settings.get_image_switch(client, "CAM001", setting) is False
    settings.set_image_switch(client, "CAM001", setting, True)

    url = f"https://api.example.invalid/v3/iot-feature/feature/CAM001/Video/1/{path}"
    assert [(request.method, request.url) for request in sent] == [("GET", url), ("PUT", url)]
    assert sent[0].body is None
    assert json.loads(sent[1].body) == {"value": {"enabled": True}}


@pytest.mark.parametrize("data", [None, {}, {"enabled": "false"}, {"enabled": 0}])
def test_graphics_switch_keeps_unknown_distinct_from_disabled(device_requests, data) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 200}, "data": data})
    assert settings.get_image_switch(client, "CAM001", settings.ImageSwitch.ANTI_BANDING) is None
    assert len(sent) == 1


@pytest.mark.parametrize("method", ["GET", "PUT"])
def test_graphics_switch_api_rejection_does_not_fall_back(device_requests, method) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 403}})
    with pytest.raises(PyEzvizError, match="Could not"):
        if method == "GET":
            settings.get_image_switch(client, "CAM001", settings.ImageSwitch.ANTI_BANDING)
        else:
            settings.set_image_switch(client, "CAM001", settings.ImageSwitch.ANTI_BANDING, False)
    assert [request.method for request in sent] == [method]


def test_legacy_icr_and_iot_black_and_white_use_distinct_routes(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [
            {"meta": {"code": 200}},
            {"meta": {"code": 200}, "data": {"mode": 0}},
            {"meta": {"code": 200}},
        ]
    )
    settings.set_cloud_day_night_settings(client, "CAM001", 0, 2, channel=2)
    assert (
        settings.get_black_and_white_mode(client, "CAM001") is settings.BlackAndWhiteMode.INFRARED
    )
    settings.set_black_and_white_mode(
        client, "CAM001", settings.BlackAndWhiteMode.ENHANCED_INFRARED
    )

    legacy, read, write = sent
    url = urlsplit(legacy.url)
    query = parse_qs(url.query)
    assert legacy.method == "PUT" and not legacy.body
    assert url.path == "/v3/devconfig/v1/keyValue/CAM001/2/op"
    assert query["key"] == ["device_ICR_DSS"]
    assert json.loads(query["value"][0]) == {"mode": 0, "sensitivity": 2}
    iot = "https://api.example.invalid/v3/iot-feature/feature/CAM001/Video/1/FillLight/BlackAndWhiteCfg"
    assert [(r.method, r.url) for r in (read, write)] == [("GET", iot), ("PUT", iot)]
    assert json.loads(write.body) == {"value": {"mode": 3}}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('{"mode":0,"sensitivity":3}', {"mode": 0, "sensitivity": 3}),
        ({"mode": False, "sensitivity": 2}, {"mode": None, "sensitivity": 2}),
        ({"mode": 3, "sensitivity": 0}, {"mode": None, "sensitivity": None}),
    ],
)
def test_legacy_icr_snapshot_reports_no_fallback_defaults(raw, expected) -> None:
    assert (
        settings.reported_cloud_day_night_settings({"optionals": {"device_ICR_DSS": raw}})
        == expected
    )


@pytest.mark.parametrize(
    ("setter", "args"),
    [
        (settings.set_image_switch, (settings.ImageSwitch.ANTI_BANDING, 0)),
        (settings.set_image_switch, ("AntiBandingParams", False)),
        (settings.set_cloud_day_night_settings, (3, 1)),
        (settings.set_cloud_day_night_settings, (0, True)),
        (settings.set_black_and_white_mode, (3,)),
    ],
)
def test_invalid_image_setting_never_reaches_transport(device_requests, setter, args) -> None:
    client, sent, _ = device_requests
    with pytest.raises(PyEzvizError):
        setter(client, "CAM001", *args)
    assert sent == []


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"hdrSwitchEnabled": "close", "WDRLevel1": 0}, {"enabled": False, "level": 0}),
        ({"hdrSwitchEnabled": "open", "WDRLevel1": 50}, {"enabled": True, "level": 50}),
        ({"hdrSwitchEnabled": True, "WDRLevel1": True}, {"enabled": None, "level": None}),
    ],
)
def test_wdr_getter_does_not_substitute_another_route(device_requests, data, expected) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 200}, "data": data})
    assert settings.get_iot_wdr_settings(client, "CAM001", local_index="2") == expected
    (request,) = sent
    assert request.method == "GET"
    assert request.url.endswith("/CAM001/Video/2/ImageBacklight/WDR")


@pytest.mark.parametrize("mode", [False, "3", 255])
def test_black_and_white_getter_does_not_default_to_infrared(device_requests, mode) -> None:
    client, _, replies = device_requests
    replies.append({"meta": {"code": 200}, "data": {"mode": mode}})
    assert settings.get_black_and_white_mode(client, "CAM001") is None


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        (
            settings.NightFillLightMode.OFF,
            {"enabled": False, "supplementLightSwitchMode": "irLight"},
        ),
        (
            settings.NightFillLightMode.INFRARED,
            {"enabled": True, "supplementLightSwitchMode": "irLight"},
        ),
        (
            settings.NightFillLightMode.SMART,
            {"enabled": True, "supplementLightSwitchMode": "eventIntelligence"},
        ),
    ],
)
def test_night_fill_light_distinguishes_off_infrared_and_smart(
    device_requests, mode, state
) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "data": state}, {"meta": {"code": 200}}])
    assert settings.get_night_fill_light_mode(client, "CAM001") is mode
    settings.set_night_fill_light_mode(client, "CAM001", mode)

    url = (
        "https://api.example.invalid/v3/iot-feature/feature/CAM001/Video/1/"
        "SupplementLightMgr/ImageSupplementLightModeSwitchParams"
    )
    assert [(r.method, r.url) for r in sent] == [("GET", url), ("PUT", url)]
    assert json.loads(sent[1].body) == {"value": state}


@pytest.mark.parametrize(
    "data",
    [
        {"enabled": True},
        {"enabled": 0, "supplementLightSwitchMode": "irLight"},
        {"enabled": False, "supplementLightSwitchMode": "eventIntelligence"},
    ],
)
def test_night_fill_light_does_not_guess_a_picker_mode(device_requests, data) -> None:
    client, _, replies = device_requests
    replies.append({"meta": {"code": 200}, "data": data})
    assert settings.get_night_fill_light_mode(client, "CAM001") is None
