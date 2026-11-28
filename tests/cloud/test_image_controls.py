"""Offline tests for the Android image-control routes."""

import json

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.devices.features import reported_night_vision_settings
from pyezvizapi.exceptions import PyEzvizError


@pytest.fixture
def image_client(monkeypatch):
    client = EzvizClient(token={"session_id": "test", "api_url": "https://example.invalid"})
    calls = []
    payload = {"meta": {"code": 200}}

    def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return payload if method == "GET" else {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", request)
    return client, calls, payload


@pytest.mark.parametrize(
    ("mode", "previous", "enabled", "position", "expected"),
    [(1, 4, False, None, 4), (1, 0, True, 3, 3), (1, 2, True, None, 2), (0, 0, True, None, 0)],
)
def test_backlight_writes_preserve_reported_settings(
    image_client, mode, previous, enabled, position, expected
):
    client, calls, payload = image_client
    payload["valueInfo"] = json.dumps({"mode": mode, "enable": 0, "position": previous})
    assert client.get_backlight_compensation("CAM123") == {
        "mode": mode,
        "enabled": False,
        "position": previous,
    }
    calls.clear()

    assert client.set_backlight_compensation("CAM123", enabled, position=position)
    assert [request[0] for request in calls] == ["GET", "PUT"]
    for _, path, _ in calls:
        assert path == "/v3/devconfig/v1/keyValue/CAM123/1/op"
    assert calls[0][2]["params"] == {"key": "inverse_mode"}
    data = calls[1][2]["data"]
    assert data["key"] == "inverse_mode"
    assert json.loads(data["value"]) == {"mode": mode, "enable": int(enabled), "position": expected}


@pytest.mark.parametrize(
    ("value", "position"),
    [
        (None, None),
        ("bad JSON", None),
        ({"mode": 3, "enable": 1, "position": 0}, None),
        ({"mode": 0, "enable": 1, "position": 0}, 2),
        ({"mode": 1, "enable": 0, "position": 0}, None),
    ],
)
def test_backlight_rejects_unknown_state_or_region_without_writing(image_client, value, position):
    client, calls, payload = image_client
    payload["valueInfo"] = value
    with pytest.raises(PyEzvizError):
        client.set_backlight_compensation("CAM123", True, position=position)
    assert [request[0] for request in calls] == ["GET"]


@pytest.mark.parametrize(
    ("value", "expected"), [('{"mode":2}', 2), ({"mode": True}, None), ({}, None)]
)
def test_display_read_does_not_substitute_preset(image_client, value, expected):
    client, calls, payload = image_client
    payload["valueInfo"] = value
    assert client.get_display_mode("CAM123") == expected
    assert calls[0][0] == "GET"
    assert calls[0][2]["params"] == {"key": "display_mode"}


def test_night_vision_query_includes_duration_but_legacy_form_is_unchanged(image_client):
    client, calls, _ = image_client
    assert client.set_night_vision_settings("CAM123", 2, 40, 60)
    assert client.set_night_vision_mode("CAM123", 1)
    query, legacy = calls
    assert query[0:2] == legacy[0:2] == ("PUT", "/v3/devconfig/v1/keyValue/CAM123/1/op")
    assert query[2]["params"]["key"] == "NightVision_Model"
    assert json.loads(query[2]["params"]["value"]) == {
        "graphicType": 2,
        "luminance": 40,
        "duration": 60,
    }
    assert json.loads(legacy[2]["data"]["value"]) == {"graphicType": 1, "luminance": 100}
    with pytest.raises(PyEzvizError):
        client.set_night_vision_settings("CAM123", 2, 40, -1)
    assert len(calls) == 2


def test_night_vision_snapshot_preserves_zero_and_missing_fields():
    assert reported_night_vision_settings(
        {"STATUS": {"optionals": {"NightVision_Model": '{"graphicType":0,"luminance":"0"}'}}}
    ) == {"mode": 0, "luminance": 0, "duration": None}
    assert reported_night_vision_settings({"NightVision_Model": {"duration": True}}) == {
        "mode": None,
        "luminance": None,
        "duration": None,
    }
