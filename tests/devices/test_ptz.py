"""Offline request parity for the app's cloud PTZ controls."""

from email import policy
from email.parser import BytesParser
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
import requests

from pyezvizapi.devices import app_controls, ptz
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.devices.channels import CameraChannel
from pyezvizapi.exceptions import PyEzvizError


def _multipart(request: requests.PreparedRequest) -> dict[str, Any]:
    assert isinstance(request.body, bytes)
    header = f"Content-Type: {request.headers['Content-Type']}\r\n\r\n".encode()
    parts = BytesParser(policy=policy.default).parsebytes(header + request.body)
    parsed = {}
    for part in parts.iter_parts():
        name = part.get_param("name", header="Content-Disposition")
        assert isinstance(name, str)
        parsed[name] = part.get_payload(decode=True)
    return parsed


def test_directional_ptz_wire(device_requests, monkeypatch) -> None:
    client, sent, replies = device_requests
    monkeypatch.setattr("pyezvizapi.client.time.time", lambda: 1_700_000_000.125)
    monkeypatch.setattr("pyezvizapi.client.uuid4", lambda: UUID("a1234567-89ab-4def-8123-456789abcdef"))
    replies.extend([{"meta": {"code": 200}}] * 2)
    for action in ("START", "STOP"):
        success = client.ptz_control("UPLEFT", "CAM001", action, 4, channel=2)
        assert success
    for request, action in zip(sent, ("START", "STOP"), strict=True):
        assert request.method == "PUT"
        assert urlsplit(request.url).path == "/v3/devices/CAM001/ptzControl"
        form = parse_qs(request.body)
        uuid = form.pop("uuid")
        assert uuid == ["a123456789ab4def8123456789abcdef"]
        assert form == {
            "command": ["UPLEFT"],
            "action": [action],
            "channelNo": ["2"],
            "speed": ["4"],
            "time": ["1700000000125"],
        }


@pytest.mark.parametrize("channel", [True, -1, 1.5, "2"])
def test_invalid_channel_stays_offline(device_requests, channel) -> None:
    client, sent, _ = device_requests
    with pytest.raises(PyEzvizError, match="channel"):
        client.ptz_control("LEFT", "CAM001", "START", channel=channel)
    with pytest.raises(ValueError, match="channel"):
        ptz.list_ptz_presets(client, "CAM001", channel=channel)
    assert not sent


def test_preset_list_recall_and_delete_wire(device_requests) -> None:
    client, sent, replies = device_requests
    row = {"subSerial": "CAM001", "channelNo": 2, "index": 7, "name": "Gate"}
    replies.extend([{"resultCode": "0", "data": [row]}, {"resultCode": 0}, {"resultCode": "0"}])
    presets = ptz.list_ptz_presets(client, "CAM001", channel=2)
    assert presets == [row]
    ptz.goto_ptz_preset(client, "CAM001", 7, channel=2)
    ptz.delete_ptz_preset(client, "CAM001", 7, channel=2)
    for request, path in zip(sent, ("list", "config", "config"), strict=True):
        assert request.method == "POST"
        assert urlsplit(request.url).path == f"/api/device/preset/{path}"
        fields = parse_qs(request.body)
        assert fields["sessionId"] == ["synthetic"]
        assert fields["subSerial"] == ["CAM001"]
        assert fields["channelNo"] == ["2"]
    assert parse_qs(sent[1].body)["configPreset"] == ["GOTO_PRESET"]
    assert parse_qs(sent[2].body)["configPreset"] == ["CLE_PRESET"]
    assert parse_qs(sent[2].body)["index"] == ["7"]


def test_preset_create_and_rename_multipart(device_requests) -> None:
    client, sent, replies = device_requests
    row = {"subSerial": "CAM001", "channelNo": 2, "index": 7}
    replies.extend([{"resultCode": 0, "Preset": row}] * 2)
    created_preset = ptz.create_ptz_preset(client, "CAM001", "Gate", channel=2, thumbnail=b"image")
    assert created_preset == row
    renamed_preset = ptz.rename_ptz_preset(client, "CAM001", 7, "Drive", channel=2, pic_url="/p.jpg")
    assert renamed_preset == row
    for request, path in zip(sent, ("set", "update"), strict=True):
        assert request.method == "POST"
        assert urlsplit(request.url).path == f"/api/device/preset/{path}"
        assert request.headers["Content-Type"].startswith("multipart/form-data; boundary=")
        fields = _multipart(request)
        assert {key: fields[key] for key in ("sessionId", "subSerial", "channelNo")} == {
            "sessionId": b"synthetic",
            "subSerial": b"CAM001",
            "channelNo": b"2",
        }
    created = _multipart(sent[0])
    assert (created["Filedata"], created["index"], created["name"]) == (b"image", b"0", b"Gate")
    updated = _multipart(sent[1])
    assert "Filedata" not in updated
    assert (updated["index"], updated["name"], updated["picUrl"]) == (b"7", b"Drive", b"/p.jpg")


def test_preset_errors_are_not_success_or_empty_list(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend(
        [
            {"resultCode": 4},
            {"resultCode": 0, "data": {}},
            {"resultCode": 0, "data": []},
            {"resultCode": 0},
        ]
    )
    with pytest.raises(PyEzvizError, match="config PTZ preset"):
        ptz.goto_ptz_preset(client, "CAM001", 1, channel=1)
    with pytest.raises(PyEzvizError, match="invalid PTZ preset list"):
        ptz.list_ptz_presets(client, "CAM001", channel=1)
    presets = ptz.list_ptz_presets(client, "CAM001", channel=1)
    assert presets == []
    with pytest.raises(PyEzvizError, match="invalid PTZ preset"):
        ptz.rename_ptz_preset(client, "CAM001", 1, "Gate", channel=1, pic_url="")
    with pytest.raises(ValueError, match="index"):
        ptz.delete_ptz_preset(client, "CAM001", True, channel=1)
    with pytest.raises(ValueError, match="thumbnail"):
        ptz.create_ptz_preset(client, "CAM001", "Gate", channel=1, thumbnail=b"")
    assert len(sent) == 4


def test_resource_patrol_lifecycle_wire(device_requests) -> None:
    client, sent, replies = device_requests
    channel = CameraChannel("Video_2", "2")
    points = [{"type": 1, "presetID": 7}]
    replies.extend([{"meta": {"code": 200}}] * 2)
    app_controls.create_patrol_path(client, "CAM001", points, channel=channel)
    app_controls.delete_patrol_path(client, "CAM001", channel=channel)
    root = "/v3/iot-feature/action/CAM001/Video_2/2/PTZPreset/"
    assert [(r.method, urlsplit(r.url).path) for r in sent] == [
        ("PUT", root + "AddPTZPatrolPath"),
        ("PUT", root + "DeletePTZPatrolPath"),
    ]
    assert json.loads(sent[0].body) == {
        "value": {"patrolID": 1, "patrolName": "1", "enabled": True, "PatrolSequenceList": points}
    }
    assert json.loads(sent[1].body) == {
        "value": {"deleteMode": "preset", "PTZPatrolList": [{"patrolID": 1}]}
    }


def test_resource_panorama_wire(device_requests) -> None:
    client, sent, replies = device_requests
    channel = CameraChannel("Video_2", "2")
    info = {"percent": 50, "picInfoList": []}
    replies.extend(
        [{"meta": {"code": 200}}, {"meta": {"code": 200}, "data": info}, {"meta": {"code": 403}}]
    )
    ptz.start_panorama_capture(client, "cam001", channel=channel)
    progress = ptz.get_panorama_info(client, "cam001", channel=channel)
    assert progress == info
    assert sent[0].method == "POST"
    assert urlsplit(sent[0].url).path == "/v3/panoramicDevices/action/pics/collect/CAM001/2"
    assert json.loads(sent[0].body) == {
        "resourceId": "Video_2",
        "domainId": "Panorama",
        "propId": "PanoramicCompPictureInfo",
        "actionId": "TriggerPanoramicCapture",
    }
    assert sent[1].method == "PUT"
    assert urlsplit(sent[1].url).path == (
        "/v3/iot-feature/action/CAM001/Video_2/2/Panorama/QueryPanoramicPicInfo"
    )
    assert json.loads(sent[1].body) == {}
    with pytest.raises(PyEzvizError, match="Could not start panorama"):
        ptz.start_panorama_capture(client, "CAM001", channel=channel)
    assert len(sent) == 3


def test_save_patrol_point_uses_distinct_multipart_contract(device_requests) -> None:
    client, sent, replies = device_requests
    replies_index = 12
    replies.extend([{"meta": {"code": 200}, "index": replies_index}, {"meta": {"code": 200}}])
    index = ptz.save_patrol_point(client, "CAM001", 2, thumbnail=b"image")
    assert index == replies_index
    assert sent[0].method == "POST"
    assert urlsplit(sent[0].url).path == "/v3/devconfig/CAM001/0/preset/set"
    assert _multipart(sent[0]) == {
        "configPreset": b"SET_CRUISE_POINT",
        "name": b"2",
        "filedata": b"image",
    }
    with pytest.raises(PyEzvizError, match="invalid patrol point index"):
        ptz.save_patrol_point(client, "CAM001", 2, thumbnail=b"image")
    with pytest.raises(ValueError, match="point name"):
        ptz.save_patrol_point(client, "CAM001", 0, thumbnail=b"image")
    assert len(sent) == 2



@pytest.mark.parametrize("payload", [{"resultCode": 0}, {"resultCode": "0", "data": None}])
def test_empty_preset_list_matches_app(device_requests, payload) -> None:
    client, _, replies = device_requests
    replies.append(payload)
    rows = ptz.list_ptz_presets(client, "CAM001", channel=2)
    assert rows == []


@pytest.mark.parametrize("operation", [ptz.goto_ptz_preset, ptz.delete_ptz_preset])
@pytest.mark.parametrize("response", [
    {"meta": {"code": 200}, "resultCode": 4},
    {"meta": {"code": 200}},
    {"resultCode": False},
    {"resultCode": 0.0},
])
def test_legacy_preset_requires_legacy_success(device_requests, operation, response) -> None:
    client, sent, replies = device_requests
    replies.append(response)
    with pytest.raises(PyEzvizError, match="config PTZ preset"):
        operation(client, "CAM001", 1, channel=2)
    assert len(sent) == 1


def test_panorama_interaction_uses_explicit_routes(device_requests) -> None:
    client, sent, replies = device_requests
    replies.extend([{"meta": {"code": 200}}] * 3)
    ptz.move_to_panorama_point(client, "cam001", 0.12556789, 1.0)
    ptz.move_to_panorama_point(
        client, "cam001", 0.12556789, 1.0, channel=CameraChannel("Video_2", "2")
    )
    ptz.reset_panorama_mark(client, "cam001")
    assert [(r.method, urlsplit(r.url).path) for r in sent] == [
        ("POST", "/v3/panoramicDevices/operation"),
        ("PUT", "/v3/iot-feature/action/CAM001/Video_2/2/Panorama/RotateFixpoint"),
        ("PUT", "/v3/panoramicDevices/ptz/coordinate/mark"),
    ]
    assert parse_qs(sent[0].body) == {
        "deviceSerial": ["CAM001"], "x": ["0.125568"], "y": ["1"],
    }
    assert json.loads(sent[1].body) == {"x": 0.126, "y": 1.0}
    assert parse_qs(sent[2].body, keep_blank_values=True) == {
        "deviceSerial": ["CAM001"], "detectorSubSerial": [""], "x": [""], "y": [""],
        "markType": ["3"],
    }


@pytest.mark.parametrize("axis", [True, -0.1, 1.1, float("nan"), float("inf"), "0.5"])
def test_invalid_panorama_points_stay_offline(device_requests, axis) -> None:
    client, sent, _ = device_requests
    with pytest.raises(ValueError, match="coordinates"):
        ptz.move_to_panorama_point(client, "CAM001", axis, 0.5)
    assert not sent


@pytest.mark.parametrize("channel", [None, CameraChannel("Video_2", "2")])
def test_panorama_move_failure_does_not_try_another_route(device_requests, channel) -> None:
    client, sent, replies = device_requests
    replies.append({"meta": {"code": 403}})
    with pytest.raises(PyEzvizError):
        ptz.move_to_panorama_point(client, "CAM001", 0.25, 0.5, channel=channel)
    assert len(sent) == 1


def test_camera_move_targets_both_legs_and_rejects_invalid_channel(device_requests) -> None:

    client, sent, replies = device_requests
    camera = EzvizCamera(client, "CAM001", device_obj={"resourceInfos": []})
    replies.extend([{"meta": {"code": 200}}] * 2)
    camera.move("left", channel=2)
    assert [(f["channelNo"], f["action"]) for f in (parse_qs(r.body) for r in sent)] == [
        (["2"], ["START"]),
        (["2"], ["STOP"]),
    ]
    with pytest.raises(PyEzvizError, match="channel"):
        camera.move("left", channel=-1)
    assert len(sent) == 2
