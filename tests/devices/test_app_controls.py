"""Offline wire tests for camera controls traced from the Android app."""

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from pyezvizapi.devices import app_controls
from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.exceptions import PyEzvizError


@pytest.mark.parametrize(
    ("prop", "route"),
    [
        (app_controls.CameraAppProperty.HOMING_PRESET, "Video/1/PTZMaintenance/HomingPresetCfg"),
        (
            app_controls.CameraAppProperty.PLATE_REGION,
            "Video/1/MotorVehiclesAnalysis/PlateRecognitionCfg",
        ),
        (app_controls.CameraAppProperty.MICROPHONE_AUTO_GAIN, "Video/1/AudioMgr/MicAdaptive"),
        (
            app_controls.CameraAppProperty.PROMPT_TONE_VOLUME,
            "global/0/SoundSetting/PromptToneVolume",
        ),
        (app_controls.CameraAppProperty.VOICE_STYLE, "Video/1/SoundSetting/VoiceStyle"),
        (
            app_controls.CameraAppProperty.VEHICLE_TRACKING,
            "Video/1/VehicleDetections/VehicleTraceSwitch",
        ),
        (app_controls.CameraAppProperty.WAKEUP_STRATEGY, "Video/1/EnergySaving/WakeupStrategyCfg"),
        (app_controls.CameraAppProperty.ENERGY_MODE, "Video/1/EnergySaving/EnergyModeCfg"),
        (app_controls.CameraAppProperty.TIME_LAPSE, "Video/1/BatCustomSpecial/TimeLapseMode"),
        (
            app_controls.CameraAppProperty.SMART_COMPRESSION,
            "Video/1/RecordStorage/RecordCompressionParams",
        ),
    ],
)
def test_app_property_wire(device_requests, prop, route) -> None:
    client, sent, replies = device_requests
    config = {"example": 2}
    replies.extend([{"meta": {"code": 200}, "data": config}, {"meta": {"code": 200}}])
    assert app_controls.get_app_property(client, "CAM001", prop) == config
    app_controls.set_app_property(client, "CAM001", prop, config)
    assert [r.method for r in sent] == ["GET", "PUT"]
    assert all(urlsplit(r.url).path == f"/v3/iot-feature/feature/CAM001/{route}" for r in sent)
    assert json.loads(sent[1].body) == {"value": config}


@pytest.mark.parametrize("plan", list(app_controls.CameraPlan))
def test_app_base_plan_wire(device_requests, plan) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "timingPlanVos": []}, {"meta": {"code": 200}}])
    assert app_controls.get_camera_plan(client, "CAM001", plan)["timingPlanVos"] == []
    slot = {"week": ["1"], "startTime": "22:00", "endTime": "n06:00"}
    app_controls.set_camera_plan(client, "CAM001", plan, [slot], enabled=True)
    common = dict(
        deviceSerial=["CAM001"],
        channelNo=["0"],
        timingPlanType=[str(int(plan))],
        secondDayEnable=["true"],
    )
    assert [r.method for r in sent] == ["GET", "PUT"]
    assert all(urlsplit(r.url).path == "/v3/devconfig/v2/base/plan" for r in sent)
    assert parse_qs(urlsplit(sent[0].url).query) == common
    form = parse_qs(sent[1].body)
    slots = form.pop("timingPlanQos")
    assert json.loads(slots[0]) == [slot]
    assert form == {**common, "enable": ["1"]}


def test_app_patrol_action_uses_explicit_route(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "data": {"patrolID": 1}}, {"meta": {"code": 200}}])
    channel = CameraChannel("Video_1", "2")
    assert app_controls.get_patrol_path(client, "CAM001", channel=channel) == {"patrolID": 1}
    sequence = [{"presetIndex": 2}]
    app_controls.set_patrol_path(client, "CAM001", sequence, channel=channel, enabled=False)
    for req, action in zip(sent, ["GetPTZPatrolPath", "ModifyPTZPatrolPath"], strict=True):
        assert req.method == "PUT"
        assert (
            urlsplit(req.url).path == f"/v3/iot-feature/action/CAM001/Video_1/2/PTZPreset/{action}"
        )
    assert json.loads(sent[0].body) == {"value": {"patrolID": 1}}
    assert json.loads(sent[1].body) == {
        "value": {
            "patrolID": 1,
            "patrolName": "1",
            "enabled": False,
            "PatrolSequenceList": sequence,
        }
    }


def test_app_privacy_mask_wire(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [{"meta": {"code": 200}, "valueInfo": '{"cover_num": 0}'}, {"meta": {"code": 200}}]
    )
    assert app_controls.get_privacy_mask(client, "CAM001", channel=2) == {"cover_num": 0}
    app_controls.set_privacy_mask(client, "CAM001", [(100, 200, 300, 400)], channel=2)
    assert [r.method for r in sent] == ["GET", "PUT"]
    assert all(urlsplit(r.url).path == "/v3/devconfig/v1/keyValue/CAM001/2/op" for r in sent)
    query = parse_qs(urlsplit(sent[1].url).query)
    assert query["key"] == ["pri_cover_area"]
    data = json.loads(query["value"][0])
    assert data["cover_num"] == 1
    assert data["cover_data"][0] == {"ltop_x": 100, "ltop_y": 200, "rlow_x": 300, "rlow_y": 400}
    assert len(data["cover_data"]) == 4


def test_app_pir_grid_wire_and_dimension_guard(device_requests) -> None:
    client, sent, replies = device_requests
    state = {"meta": {"code": 200}, "area": {"rows": 1, "cols": 2, "area": "[[0,1]]"}}
    replies.extend([state, {"meta": {"code": 200}}, state])
    app_controls.set_pir_detection_grid(client, "PIR001", [[1, 0]], channel=2)
    with pytest.raises(ValueError, match="dimensions"):
        app_controls.set_pir_detection_grid(client, "PIR001", [[1]], channel=2)
    assert [r.method for r in sent] == ["GET", "POST", "GET"]
    assert all(urlsplit(r.url).path == "/v3/alarms/device/pir/area/PIR001/2" for r in sent)
    form = parse_qs(sent[1].body)
    assert form["rows"] == ["1"] and form["cols"] == ["2"]
    assert json.loads(form["area"][0]) == [[1, 0]]


def test_camera_maintenance_and_alarm_wire(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [
            {"resultCode": "0"},
            {"meta": {"code": 200}},
            {"meta": {"code": 200}, "formattingRateInfo": {"rate": 42}},
            {"meta": {"code": 200}},
            {"meta": {"code": 200}, "motionDetectAreaInfo": {}},
        ]
    )
    app_controls.calibrate_ptz(client, "CAM001")
    with pytest.raises(ValueError, match="confirm"):
        app_controls.format_cloud_sd_card(client, "CAM001", disk=1, confirm=False)
    app_controls.format_cloud_sd_card(client, "CAM001", disk=1, confirm=True)
    assert app_controls.get_cloud_sd_format_progress(client, "CAM001") == {"rate": 42}
    app_controls.set_custom_alarm_sound(client, "CAM001", voice_id=5)
    assert app_controls.get_legacy_motion_area(client, "CAM001", channel=2) == {}
    expected = [
        ("POST", "/api/device/v2/sysOper/CAM001", {"oper": ["4"], "delay": ["0"]}),
        ("PUT", "/v3/basics/v1/storages/CAM001/1/format", {"type": ["0"]}),
        ("GET", "/v3/basics/v1/storages/CAM001/formattingRate", {"type": ["0"]}),
        (
            "PUT",
            "/v3/devices/CAM001/alarm/sound",
            {"enable": ["1"], "soundType": ["3"], "voiceId": ["5"]},
        ),
        ("GET", "/v3/devices/CAM001/2/motionDetectAreaInfo", {"category": ["TEL"]}),
    ]
    assert [
        (r.method, urlsplit(r.url).path, parse_qs(urlsplit(r.url).query)) for r in sent
    ] == expected
    assert parse_qs(sent[0].body) == {"sessionId": ["synthetic"]}


def test_app_compression_unknown_and_api_rejection(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [
            {"meta": {"code": 200}, "data": {"enabled": "false"}},
            {"meta": {"code": 200}, "data": {"enabled": False}},
            {"meta": {"code": 400}},
        ]
    )
    assert app_controls.get_smart_recording_compression(client, "CAM001") is None
    assert app_controls.get_smart_recording_compression(client, "CAM001") is False
    with pytest.raises(PyEzvizError):
        app_controls.set_smart_recording_compression(client, "CAM001", enabled=True)
    assert json.loads(sent[-1].body) == {"value": {"enabled": True}}
    assert len(sent) == 3


def test_custom_voice_selection_comes_from_status_only() -> None:
    assert (
        app_controls.reported_custom_alarm_sound(
            {"STATUS": {"alarmSoundMode": 3, "optionals": '{"voiceIndex": "7"}'}}
        )
        == 7
    )
    assert (
        app_controls.reported_custom_alarm_sound(
            {"STATUS": {"alarmSoundMode": 1, "optionals": {"voiceIndex": 7}}}
        )
        is None
    )


@pytest.mark.parametrize(
    ("prop", "route", "current", "expected", "methods"),
    [
        (
            app_controls.CameraAppProperty.ELECTRONIC_STABILIZATION,
            "Video/1/ImageEnhance/EIS",
            {"enabled": False, "EISMode": "auto", "EISLevel": 2},
            {"enabled": True, "EISMode": "auto", "EISLevel": 2},
            ["GET", "GET", "PUT"],
        ),
        (
            app_controls.CameraAppProperty.HORIZON_ENHANCEMENT,
            "Video/1/ImageEnhance/HorizonEnhancement",
            {"enabled": False, "level": 2},
            {"enabled": True, "level": 2},
            ["GET", "GET", "PUT"],
        ),
        (
            app_controls.CameraAppProperty.RADAR_INTERFERENCE_SUPPRESSION,
            "Video/1/SensorLight/RadarFMCfg",
            {"enabled": False},
            {"enabled": True},
            ["GET", "PUT"],
        ),
        (
            app_controls.CameraAppProperty.NIGHTTIME_PROMPT,
            "global/0/SoundSetting/PromptParam",
            {"enabled": False, "mode": "nighttime"},
            {"enabled": True, "mode": "nighttime"},
            ["GET", "PUT"],
        ),
    ],
)
def test_additional_camera_app_switches(
    device_requests, prop, route, current, expected, methods
) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}, "data": current}] * methods.count("GET"))
    replies.append({"meta": {"code": 200}})
    assert app_controls.get_camera_app_switch(client, "CAM001", prop) is False
    app_controls.set_camera_app_switch(client, "CAM001", prop, enabled=True)
    assert [request.method for request in sent] == methods
    assert all(
        urlsplit(request.url).path == f"/v3/iot-feature/feature/CAM001/{route}" for request in sent
    )
    assert json.loads(sent[-1].body) == {"value": expected}


def test_stabilization_does_not_overwrite_unknown_state(device_requests) -> None:
    client, sent, replies = device_requests
    prop = app_controls.CameraAppProperty.ELECTRONIC_STABILIZATION
    replies.extend([{"meta": {"code": 200}, "data": {"enabled": "false"}}] * 2)
    assert app_controls.get_camera_app_switch(client, "CAM001", prop) is None
    with pytest.raises(PyEzvizError, match="unknown"):
        app_controls.set_camera_app_switch(client, "CAM001", prop, enabled=True)
    assert [request.method for request in sent] == ["GET", "GET"]


@pytest.mark.parametrize(
    ("encoding", "grid", "encoded"),
    [
        (app_controls.MotionAreaEncoding.ROW_BITMAP, [[1, 0, 1], [0, 1, 0]], "AAAABQAAAAI="),
        (app_controls.MotionAreaEncoding.ROW_BITMAP, [[0] * 31 + [1]], "gAAAAA=="),
        (app_controls.MotionAreaEncoding.DOORBELL_HIK, [[1, 0, 1], [0, 1, 0]], "AQABAAEA"),
        (
            app_controls.MotionAreaEncoding.ROW_BITMAP,
            [[1]] * 12,
            "AAAAAQAAAAEAAAAB" * 3 + "AAAAAQAAAAEA AAAB",
        ),
    ],
)
def test_motion_detection_area_wire(
    device_requests, encoding: app_controls.MotionAreaEncoding, grid: list[list[int]], encoded: str
) -> None:
    client, sent, replies = device_requests
    area = {"width": len(grid[0]), "height": len(grid), "area": encoded, "type": "Humanoid"}
    state = {"meta": {"code": 200}, "detectAreaInfo": area}
    replies.extend([state, state, {"meta": {"code": 200}}])
    assert (
        app_controls.get_motion_detection_area(
            client, "CAM001", channel=2, detection_type="Humanoid"
        )
        == area
    )
    app_controls.set_motion_detection_area(
        client, "CAM001", grid, channel=2, detection_type="Humanoid", encoding=encoding
    )
    assert [r.method for r in sent] == ["GET", "GET", "PUT"]
    assert [urlsplit(r.url).path for r in sent] == [
        "/v3/devices/CAM001/2/detectAreaInfo/Humanoid",
        "/v3/devices/CAM001/2/detectAreaInfo/Humanoid",
        "/v3/devices/CAM001/2/detectAreaInfo",
    ]
    assert all(not urlsplit(r.url).query for r in sent)
    assert sent[2].headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert parse_qs(sent[2].body) == {
        "width": [str(len(grid[0]))],
        "height": [str(len(grid))],
        "data": [encoded],
        "type": ["Humanoid"],
    }


@pytest.mark.parametrize(
    ("grid", "detection_type", "error"),
    [
        ([[1], [1, 0]], "Humanoid", "rectangular"),
        ([[True]], "Humanoid", "rectangular"),
        ([[0]], "Humanoid", "selected cell"),
        ([[1] * 33], "Humanoid", "32 columns"),
        ([[1]], "", "detection_type"),
        ([[1]], "../human", "detection_type"),
    ],
)
def test_motion_detection_area_invalid_input(
    device_requests, grid: list[list[int]], detection_type: str, error: str
) -> None:
    client, sent, _ = device_requests
    with pytest.raises(ValueError, match=error):
        app_controls.set_motion_detection_area(
            client,
            "CAM001",
            grid,
            channel=2,
            detection_type=detection_type,
            encoding=app_controls.MotionAreaEncoding.ROW_BITMAP,
        )
    assert not sent


@pytest.mark.parametrize(
    ("reply", "error", "message"),
    [
        ({"meta": {"code": 403}}, PyEzvizError, "Could not read"),
        ({"meta": {"code": 200}}, PyEzvizError, "Missing API object section"),
        (
            {"meta": {"code": 200}, "detectAreaInfo": {"width": True, "height": 1}},
            PyEzvizError,
            "Invalid motion detection area dimensions",
        ),
        (
            {"meta": {"code": 200}, "detectAreaInfo": {"width": 3, "height": 1}},
            ValueError,
            "dimensions do not match",
        ),
    ],
)
def test_motion_detection_area_failed_read_does_not_write(
    device_requests, reply: dict[str, Any], error: type[Exception], message: str
) -> None:
    client, sent, replies = device_requests
    replies.append(reply)
    with pytest.raises(error, match=message):
        app_controls.set_motion_detection_area(
            client,
            "CAM001",
            [[1, 0]],
            channel=2,
            detection_type="Humanoid",
            encoding=app_controls.MotionAreaEncoding.ROW_BITMAP,
        )
    assert [r.method for r in sent] == ["GET"]


def test_motion_detection_area_write_error_propagates(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [
            {"meta": {"code": 200}, "detectAreaInfo": {"width": 2, "height": 1}},
            {"meta": {"code": 403}},
        ]
    )
    with pytest.raises(PyEzvizError, match="Could not write motion detection area"):
        app_controls.set_motion_detection_area(
            client,
            "CAM001",
            [[1, 0]],
            channel=2,
            detection_type="Humanoid",
            encoding=app_controls.MotionAreaEncoding.ROW_BITMAP,
        )
    assert [r.method for r in sent] == ["GET", "PUT"]
