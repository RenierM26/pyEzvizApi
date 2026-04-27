from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import UnifiedMessageSubtype
from pyezvizapi.exceptions import HTTPError, PyEzvizError


def _client() -> EzvizClient:
    return EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"},
        timeout=1,
    )


def _response(*, status_code: int = 200, text: str = '{"meta": {"code": 200}}') -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = text.encode()
    resp.url = "https://api.example.test/path"
    return resp


def test_parse_json_returns_decoded_payload() -> None:
    assert EzvizClient._parse_json(_response(text='{"resultCode": "0", "value": 1}')) == {
        "resultCode": "0",
        "value": 1,
    }


def test_parse_json_raises_contextual_error_for_invalid_json() -> None:
    with pytest.raises(PyEzvizError, match="Impossible to decode response"):
        EzvizClient._parse_json(_response(text="not-json"))


def test_normalize_json_payload_accepts_common_shapes() -> None:
    assert EzvizClient._normalize_json_payload({"a": 1}) == {"a": 1}
    assert EzvizClient._normalize_json_payload(("a", "b")) == ["a", "b"]
    assert EzvizClient._normalize_json_payload(b'{"a": 1}') == {"a": 1}
    assert EzvizClient._normalize_json_payload('["a"]') == ["a"]


def test_normalize_json_payload_rejects_invalid_shapes() -> None:
    with pytest.raises(PyEzvizError, match="Invalid JSON payload"):
        EzvizClient._normalize_json_payload("not-json")

    with pytest.raises(PyEzvizError, match="Unsupported payload type"):
        EzvizClient._normalize_json_payload(123)


def test_meta_and_ok_helpers_support_modern_and_legacy_responses() -> None:
    assert EzvizClient._meta_code({"meta": {"code": "200"}}) == 200
    assert EzvizClient._meta_ok({"meta": {"code": 200}}) is True
    assert EzvizClient._is_ok({"meta": {"code": 200}}) is True
    assert EzvizClient._is_ok({"resultCode": "0"}) is True
    assert EzvizClient._is_ok({"resultCode": 0}) is True
    assert EzvizClient._is_ok({"meta": {"code": 500}}) is False
    assert EzvizClient._response_code({"status": 200}) == 200


def test_ensure_ok_raises_contextual_error() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Could not test"):
        client._ensure_ok({"meta": {"code": 500}}, "Could not test")


def test_http_request_relogs_and_retries_on_401(monkeypatch) -> None:
    client = _client()
    responses = [_response(status_code=401, text="{}"), _response(text='{"ok": true}')]
    calls: list[dict[str, Any]] = []
    login_calls = 0

    def fake_request(**kwargs: Any) -> requests.Response:
        calls.append(kwargs)
        return responses.pop(0)

    def fake_login(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal login_calls
        login_calls += 1
        return {"session_id": "new-session", "api_url": "apiieu.ezvizlife.com"}

    monkeypatch.setattr(client._session, "request", fake_request)
    monkeypatch.setattr(client, "login", fake_login)

    resp = client._http_request("GET", "https://api.example.test/path")

    assert resp.status_code == 200
    assert login_calls == 1
    assert len(calls) == 2


def test_http_request_wraps_non_401_errors(monkeypatch) -> None:
    client = _client()

    def fake_request(**kwargs: Any) -> requests.Response:
        return _response(status_code=500, text="server error")

    monkeypatch.setattr(client._session, "request", fake_request)

    with pytest.raises(HTTPError):
        client._http_request("GET", "https://api.example.test/path")


def test_request_json_uses_url_and_parses_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        captured.update({"method": method, "url": url, **kwargs})
        return _response(text='{"meta": {"code": 200}, "value": 1}')

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    payload = client._request_json("POST", "/api/path", json_body={"x": 1})

    assert payload == {"meta": {"code": 200}, "value": 1}
    assert captured["method"] == "POST"
    assert captured["url"] == "https://apiieu.ezvizlife.com/api/path"
    assert captured["json_body"] == {"x": 1}


def test_get_device_messages_list_builds_normalized_request_params(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "messages": []}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    payload = client.get_device_messages_list(
        serials="CAM123,CAM456",
        s_type=[UnifiedMessageSubtype.ALL_ALARMS, 2701, ""],
        limit=99,
        date=dt.date(2026, 4, 27),
        end_time=12345,
        max_retries=2,
    )

    assert payload == {"meta": {"code": 200}, "messages": []}
    assert captured["method"] == "GET"
    assert captured["params"] == {
        "serials": "CAM123,CAM456",
        "stype": "92,2701",
        "limit": 50,
        "date": "20260427",
        "endTime": "12345",
    }
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_get_device_messages_list_keeps_empty_end_time_and_defaults(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "messages": []}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    client.get_device_messages_list(
        serials=None,
        s_type=[],
        limit="not-an-int",  # type: ignore[arg-type]
        date="20260427",
        end_time=None,
    )

    assert captured["params"] == {
        "stype": "92",
        "limit": 20,
        "date": "20260427",
        "endTime": "",
    }


def test_get_device_messages_list_rejects_too_many_retries() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.get_device_messages_list(max_retries=99)


def test_get_device_messages_list_raises_contextual_api_error(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "backend unhappy"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get unified message list"):
        client.get_device_messages_list(date="20260427")


def test_add_device_builds_request_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "result": "ok"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.add_device("CAM123", "ABCDEF", add_type="qr", max_retries=2) == {
        "meta": {"code": 200},
        "result": "ok",
    }
    assert captured["method"] == "POST"
    assert captured["data"] == {
        "deviceSerial": "CAM123",
        "validateCode": "ABCDEF",
        "addType": "qr",
    }
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_hik_and_local_add_helpers_normalize_json_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.add_hik_activate("CAM123", '{"key": "value"}') == {
        "meta": {"code": 200},
        "path": calls[0]["path"],
    }
    assert client.add_hik_challenge("CAM123", {"challenge": True}, max_retries=1) == {
        "meta": {"code": 200},
        "path": calls[1]["path"],
    }
    assert client.add_local_device(("a", "b")) == {
        "meta": {"code": 200},
        "path": calls[2]["path"],
    }
    assert client.save_hik_dev_code(b'{"code": "123456"}') == {
        "meta": {"code": 200},
        "path": calls[3]["path"],
    }

    assert calls[0]["method"] == "POST"
    assert calls[0]["path"].endswith("CAM123")
    assert calls[0]["json_body"] == {"key": "value"}
    assert calls[1]["path"].endswith("CAM123")
    assert calls[1]["json_body"] == {"challenge": True}
    assert calls[1]["max_retries"] == 1
    assert calls[2]["json_body"] == ["a", "b"]
    assert calls[3]["json_body"] == {"code": "123456"}
    assert all(call["retry_401"] is True for call in calls)


def test_bind_virtual_device_builds_put_params(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "bound": True}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.bind_virtual_device("product-1", "v2") == {
        "meta": {"code": 200},
        "bound": True,
    }
    assert captured["method"] == "PUT"
    assert captured["params"] == {"productId": "product-1", "version": "v2"}
    assert captured["retry_401"] is True


def test_add_helpers_raise_contextual_api_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "nope"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not add device"):
        client.add_device("CAM123", "ABCDEF")

    with pytest.raises(PyEzvizError, match="Could not activate Hik device"):
        client.add_hik_activate("CAM123", {"key": "value"})

    with pytest.raises(PyEzvizError, match="Could not add local device"):
        client.add_local_device({"local": True})


def test_dev_config_network_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.dev_config_search("CAM123", 1, max_retries=1)["meta"]["code"] == 200
    assert client.dev_config_send_config_command("CAM123", 1, "TARGET456")["meta"]["code"] == 200
    assert client.dev_config_wifi_list("CAM123", 1)["meta"]["code"] == 200
    assert client.device_between_error("CAM123", 1, "TARGET456")["meta"]["code"] == 200
    assert client.dev_token()["meta"]["code"] == 200

    assert calls[0]["method"] == "POST"
    assert calls[0]["path"].endswith("/CAM123/1/netWork")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "POST"
    assert calls[1]["path"].endswith("/CAM123/1/netWork/command")
    assert calls[1]["params"] == {"targetDeviceSerial": "TARGET456"}
    assert calls[2]["method"] == "GET"
    assert calls[2]["path"].endswith("/CAM123/1/netWork")
    assert calls[3]["method"] == "GET"
    assert calls[3]["path"].endswith("/CAM123/1/netWork/result")
    assert calls[3]["params"] == {"targetDeviceSerial": "TARGET456"}
    assert calls[4]["method"] == "GET"
    assert all(call["retry_401"] is True for call in calls)


def test_switch_request_helpers_build_modern_and_legacy_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_switch_v3("CAM123", 7, True, channel=2, max_retries=1)["meta"]["code"] == 200
    assert client.set_switch_legacy("CAM123", 7, False, channel=2)["meta"]["code"] == 200
    assert client.device_switch("CAM123", 3, 1, 29)["meta"]["code"] == 200
    assert client.switch_status_other("CAM123", 29, 1, channel_number=3) is True

    assert calls[0]["method"] == "PUT"
    assert "/CAM123/2/1/7" in calls[0]["path"]
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "POST"
    assert calls[1]["data"] == {
        "serial": "CAM123",
        "enable": "0",
        "type": "7",
        "channel": "2",
    }
    assert calls[2]["method"] == "PUT"
    assert calls[2]["params"] == {"channelNo": 3, "enable": 1, "switchType": 29}
    assert calls[3]["method"] == "PUT"
    assert calls[3]["params"] == {"channelNo": 3, "enable": 1, "switchType": 29}


def test_set_switch_falls_back_to_legacy_and_preserves_first_error(monkeypatch) -> None:
    client = _client()
    calls: list[tuple[str, int]] = []

    def fake_v3(serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0) -> dict[str, Any]:
        calls.append(("v3", channel))
        raise PyEzvizError("modern failed")

    def fake_legacy(serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0) -> dict[str, Any]:
        calls.append(("legacy", channel))
        return {"meta": {"code": 200}, "legacy": True}

    monkeypatch.setattr(client, "set_switch_v3", fake_v3)
    monkeypatch.setattr(client, "set_switch_legacy", fake_legacy)

    assert client.set_switch("CAM123", 7, True, channel=4) == {
        "meta": {"code": 200},
        "legacy": True,
    }
    assert calls == [("v3", 4), ("legacy", 4)]

    def failing_legacy(serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0) -> dict[str, Any]:
        raise PyEzvizError("legacy failed")

    monkeypatch.setattr(client, "set_switch_legacy", failing_legacy)

    with pytest.raises(PyEzvizError, match="modern failed"):
        client.set_switch("CAM123", 7, True)


def test_switch_status_updates_cached_camera_switch_state(monkeypatch) -> None:
    client = _client()
    client._cameras["CAM123"] = {"switches": {7: False}}

    def fake_set_switch(serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0) -> dict[str, Any]:
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "set_switch", fake_set_switch)

    assert client.switch_status("CAM123", 7, True, channel_no=2) is True
    assert client._cameras["CAM123"]["switches"][7] is True


def test_set_camera_defence_retries_transient_timeout(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses = [
        {"meta": {"code": 504}},
        {"meta": {"code": 200}},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_camera_defence(
        "CAM123",
        1,
        channel_no=2,
        arm_type="Local",
        actor="A",
        max_retries=1,
    ) is True

    assert len(calls) == 2
    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/2/changeDefenceStatusReq")
    assert calls[0]["data"] == {"type": "Local", "status": 1, "actor": "A"}
    assert calls[0]["max_retries"] == 0
    assert calls[1]["data"] == {"type": "Local", "status": 1, "actor": "A"}


def test_set_camera_defence_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not arm or disarm Camera CAM123"):
        client.set_camera_defence("CAM123", 0)


def test_devconfig_key_helpers_normalize_values_and_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_dev_config_kv("CAM123", 1, "Mapping", {"b": 2})["meta"]["code"] == 200
    assert client.set_dev_config_kv("CAM123", 1, "Bytes", b"raw")["meta"]["code"] == 200
    assert client.set_dev_config_kv("CAM123", 1, "Bool", True)["meta"]["code"] == 200
    assert client.set_dev_config_kv("CAM123", 1, "Float", 1.5)["meta"]["code"] == 200
    assert client.set_common_key_value("CAM123", 2, "Common", "value")["meta"]["code"] == 200
    assert client.set_device_key_value("CAM123", 3, "Alias", "value2")["meta"]["code"] == 200

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/1/op")
    assert calls[0]["data"] == {"key": "Mapping", "value": '{"b":2}'}
    assert calls[1]["data"] == {"key": "Bytes", "value": "raw"}
    assert calls[2]["data"] == {"key": "Bool", "value": "1"}
    assert calls[3]["data"] == {"key": "Float", "value": "1.5"}
    assert calls[4]["params"] == {"key": "Common", "value": "value"}
    assert calls[5]["params"] == {"key": "Alias", "value": "value2"}


def test_high_level_device_config_wrappers_forward_expected_values(monkeypatch) -> None:
    client = _client()
    calls: list[tuple[str, object, str]] = []

    def fake_set_device_config_by_key(
        serial: str,
        value: object,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        calls.append((serial, value, key))
        return True

    monkeypatch.setattr(client, "set_device_config_by_key", fake_set_device_config_by_key)

    assert client.set_battery_camera_work_mode("CAM123", 1) is True
    assert client.set_detection_mode("CAM123", 2) is True
    assert client.set_alarm_detect_human_car("CAM123", 3) is True
    assert client.set_alarm_advanced_detect("CAM123", 4) is True
    assert client.set_algorithm_param("CAM123", 99, 7, channel=2) is True
    assert client.set_night_vision_mode("CAM123", 1, luminance=55) is True
    assert client.set_display_mode("CAM123", 8) is True

    assert calls == [
        ("CAM123", 1, "batteryCameraWorkMode"),
        ("CAM123", '{"type":2}', "Alarm_DetectHumanCar"),
        ("CAM123", '{"type":3}', "Alarm_DetectHumanCar"),
        ("CAM123", '{"type":4}', "Alarm_AdvancedDetect"),
        (
            "CAM123",
            '{"AlgorithmInfo":[{"SubType":"99","Value":"7","channel":2}]}',
            "AlgorithmInfo",
        ),
        ("CAM123", '{"graphicType":1,"luminance":55}', "NightVision_Model"),
        ("CAM123", '{"mode":8}', "display_mode"),
    ]


def test_audition_and_baby_control_build_request_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.audition_request("CAM123", 1, "play", "payload", max_retries=1)["meta"]["code"] == 200
    assert client.baby_control(
        "CAM123",
        1,
        2,
        "move",
        "START",
        5,
        "uuid-1",
        "pan",
        "HW1",
    )["meta"]["code"] == 200

    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {
        "deviceSerial": "CAM123",
        "channelNo": 1,
        "request": "play",
        "data": "payload",
    }
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "POST"
    assert calls[1]["data"] == {
        "deviceSerial": "CAM123",
        "channelNo": 1,
        "localIndex": 2,
        "command": "move",
        "action": "START",
        "speed": 5,
        "uuid": "uuid-1",
        "control": "pan",
        "hardwareCode": "HW1",
    }
