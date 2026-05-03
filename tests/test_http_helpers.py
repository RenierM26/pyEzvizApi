from __future__ import annotations

import datetime as dt
from typing import Any, cast

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import (
    FEATURE_CODE,
    DefenseModeType,
    DeviceSwitchType,
    UnifiedMessageSubtype,
)
from pyezvizapi.exceptions import (
    DeviceException,
    EzvizAuthVerificationCode,
    HTTPError,
    PyEzvizError,
)


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


def test_iot_request_builds_prepared_request_with_json_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        captured.update({"req": req, **kwargs})
        return _response(text='{"meta": {"code": 200}, "ok": true}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    payload = client.set_iot_feature(
        "cam123",
        "Video",
        "1",
        "Domain",
        "Action",
        {"value": {"enabled": True}},
        max_retries=2,
    )

    req = captured["req"]
    assert payload == {"meta": {"code": 200}, "ok": True}
    assert req.method == "PUT"
    assert req.url == "https://apiieu.ezvizlife.com/v3/iot-feature/feature/CAM123/Video/1/Domain/Action"
    assert req.headers["Content-Type"] == "application/json"
    assert req.body == '{"value":{"enabled":true}}'
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_iot_get_helpers_build_expected_feature_paths(monkeypatch) -> None:
    client = _client()
    urls: list[str] = []
    bodies: list[str | bytes | None] = []

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        urls.append(req.url or "")
        bodies.append(req.body)
        return _response(text='{"meta": {"code": 200}}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    assert client.get_low_battery_keep_alive("cam123", "Battery", "0", "Power", "KeepAlive")["meta"]["code"] == 200
    assert client.get_object_removal_status("cam123", "Video", "1", "Object", "Removal", payload={"q": 1})["meta"]["code"] == 200
    assert client.get_remote_control_path_list("cam123", "PTZ", "1", "Cruise", "PathList")["meta"]["code"] == 200
    assert client.get_tracking_status("cam123", "Video", "1", "Track", "Status")["meta"]["code"] == 200
    assert client.get_port_security("cam123")["meta"]["code"] == 200
    assert client.get_device_feature_value("cam123", "Video", "Domain", "Prop", local_index=3)["meta"]["code"] == 200

    assert urls[0].endswith("/v3/iot-feature/feature/CAM123/Battery/0/Power/KeepAlive")
    assert urls[1].endswith("/v3/iot-feature/feature/CAM123/Video/1/Object/Removal")
    assert bodies[1] == '{"q":1}'
    assert urls[2].endswith("/v3/iot-feature/feature/CAM123/PTZ/1/Cruise/PathList")
    assert urls[3].endswith("/v3/iot-feature/feature/CAM123/Video/1/Track/Status")
    assert urls[4].endswith("/v3/iot-feature/feature/CAM123/Video/1/NetworkSecurityProtection/PortSecurity")
    assert urls[5].endswith("/v3/iot-feature/feature/CAM123/Video/3/Domain/Prop")
    assert bodies[0] is None


def test_iot_action_and_port_security_wrappers_build_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_iot_request(
        method: str,
        endpoint: str,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        calls.append(
            {
                "method": method,
                "endpoint": endpoint,
                "serial": serial,
                "resource_identifier": resource_identifier,
                "local_index": local_index,
                "domain_id": domain_id,
                "action_id": action_id,
                **kwargs,
            }
        )
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_iot_request", fake_iot_request)

    assert client.set_port_security("CAM123", {"https": True}, max_retries=1)["meta"]["code"] == 200
    assert client.set_iot_action("CAM123", "PTZ", "1", "Move", "Start", {"speed": 3})["meta"]["code"] == 200

    assert calls[0]["method"] == "PUT"
    assert calls[0]["resource_identifier"] == "Video"
    assert calls[0]["domain_id"] == "NetworkSecurityProtection"
    assert calls[0]["action_id"] == "PortSecurity"
    assert calls[0]["payload"] == {"value": {"https": True}}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["resource_identifier"] == "PTZ"
    assert calls[1]["payload"] == {"speed": 3}


def test_iot_feature_user_helpers_normalize_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_iot_request(
        method: str,
        endpoint: str,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        calls.append(
            {
                "method": method,
                "resource_identifier": resource_identifier,
                "local_index": local_index,
                "domain_id": domain_id,
                "action_id": action_id,
                **kwargs,
            }
        )
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_iot_request", fake_iot_request)

    assert client.set_intelligent_fill_light("CAM123", enabled=True, local_index="2")["meta"]["code"] == 200
    assert client.set_intelligent_fill_light("CAM123", enabled=False)["meta"]["code"] == 200
    assert client.set_image_flip_iot("CAM123", enabled=True)["meta"]["code"] == 200
    assert client.set_image_flip_iot("CAM123", payload='{"value":{"enabled":false}}')["meta"]["code"] == 200

    assert calls[0]["domain_id"] == "SupplementLightMgr"
    assert calls[0]["action_id"] == "ImageSupplementLightModeSwitchParams"
    assert calls[0]["payload"] == {
        "value": {"enabled": True, "supplementLightSwitchMode": "eventIntelligence"}
    }
    assert calls[0]["local_index"] == "2"
    assert calls[1]["payload"] == {
        "value": {"enabled": False, "supplementLightSwitchMode": "irLight"}
    }
    assert calls[2]["domain_id"] == "VideoAdjustment"
    assert calls[2]["action_id"] == "ImageFlip"
    assert calls[2]["payload"] == {"value": {"enabled": True}}
    assert calls[3]["payload"] == {"value": {"enabled": False}}


def test_set_image_flip_iot_requires_enabled_or_payload() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Either 'enabled' or 'payload' must be provided"):
        client.set_image_flip_iot("CAM123")


def test_set_lens_defog_mode_maps_options(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_set_iot_feature(
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        value: Any,
        *,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "serial": serial,
                "resource_identifier": resource_identifier,
                "local_index": local_index,
                "domain_id": domain_id,
                "action_id": action_id,
                "value": value,
                "max_retries": max_retries,
            }
        )
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "set_iot_feature", fake_set_iot_feature)

    assert client.set_lens_defog_mode("CAM123", 1, local_index="2", max_retries=1) == (True, "open")
    assert client.set_lens_defog_mode("CAM123", 2) == (False, "auto")
    assert client.set_lens_defog_mode("CAM123", 0) == (True, "auto")

    assert calls[0] == {
        "serial": "CAM123",
        "resource_identifier": "Video",
        "local_index": "2",
        "domain_id": "LensCleaning",
        "action_id": "DefogCfg",
        "value": {"value": {"enabled": True, "defogMode": "open"}},
        "max_retries": 1,
    }
    assert calls[1]["value"] == {"value": {"enabled": False, "defogMode": "auto"}}
    assert calls[2]["value"] == {"value": {"enabled": True, "defogMode": "auto"}}


def test_iot_request_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        return _response(text='{"meta": {"code": 500}, "message": "bad"}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    with pytest.raises(PyEzvizError, match="Could not set IoT feature value"):
        client.set_iot_feature("CAM123", "Video", "1", "Domain", "Action", {"value": 1})


def test_update_device_name_and_upgrade_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.update_device_name("CAM123", "Front Door", max_retries=1)["meta"]["code"] == 200
    assert client.upgrade_device("CAM123", max_retries=2) is True

    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {"deviceSerialNo": "CAM123", "deviceName": "Front Door"}
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("CAM123/0/upgrade")
    assert calls[1]["max_retries"] == 2


def test_update_device_name_rejects_empty_name() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Device name must not be empty"):
        client.update_device_name("CAM123", "")


def test_get_storage_status_retries_unreachable_response(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [
        {"resultCode": "-1"},
        {"resultCode": "0", "storageStatus": {"hdd": "ok"}},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_storage_status("CAM123", max_retries=1) == {"hdd": "ok"}
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {"subSerial": "CAM123"}
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0


def test_get_storage_status_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "500", "message": "bad disk"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get device storage status"):
        client.get_storage_status("CAM123")


def test_sound_alarm_and_device_authenticate_build_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.sound_alarm("CAM123", enable=0, max_retries=1) is True
    assert client.device_authenticate(
        "CAM123",
        need_check_code=True,
        check_code="ABCDEF",
        sender_type=2,
    )["meta"]["code"] == 200
    assert client.device_authenticate(
        "CAM456",
        need_check_code=False,
        check_code=None,
        sender_type=1,
    )["meta"]["code"] == 200

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/0/sendAlarm")
    assert calls[0]["data"] == {"enable": 0}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("CAM123")
    assert calls[1]["data"] == {
        "needCheckCode": "true",
        "checkCode": "ABCDEF",
        "senderType": 2,
    }
    assert calls[2]["data"] == {
        "needCheckCode": "false",
        "checkCode": "",
        "senderType": 1,
    }


def test_reboot_camera_retries_unreachable_response(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [
        {"resultCode": "-1"},
        {"resultCode": "0"},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.reboot_camera("CAM123", delay=5, operation=2, max_retries=1) is True
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"].endswith("CAM123")
    assert calls[0]["data"] == {"oper": 2, "deviceSerial": "CAM123", "delay": 5}
    assert calls[0]["max_retries"] == 0


def test_offline_notification_retries_and_raises_contextual_error(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [{"resultCode": "-1"}, {"resultCode": "0"}]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_offline_notification("CAM123", enable=0, req_type=2, max_retries=1) is True
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {"reqType": 2, "serial": "CAM123", "status": 0}
    assert calls[0]["max_retries"] == 0

    def fake_failure(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "500"}

    monkeypatch.setattr(client, "_request_json", fake_failure)

    with pytest.raises(PyEzvizError, match="Could not set offline notification"):
        client.set_offline_notification("CAM123")


def test_email_alert_helpers_normalize_serials(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.device_email_alert_state(["CAM2", "CAM1", "CAM1"])["meta"]["code"] == 200
    assert client.save_device_email_alert_state(False, ["CAM2", "CAM1"])["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["params"] == {"devices": "CAM1,CAM2"}
    assert calls[1]["method"] == "POST"
    assert calls[1]["data"] == {"enable": "false", "devices": "CAM1,CAM2"}


def test_group_defence_and_cancel_alarm_helpers(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if method == "GET":
            return {"meta": {"code": 200}, "mode": "home"}
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_group_defence_mode(max_retries=1) == "home"
    assert client.cancel_alarm_device("ALARM123", max_retries=2) is True

    assert calls[0]["method"] == "GET"
    assert calls[0]["params"] == {"groupId": -1}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "POST"
    assert calls[1]["data"] == {"subSerial": "ALARM123"}
    assert calls[1]["max_retries"] == 2


def test_get_user_id_returns_device_token_info(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "deviceTokenInfo": {"userId": "user-1"}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_user_id(max_retries=2) == {"userId": "user-1"}
    assert captured["method"] == "GET"
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_set_video_enc_builds_default_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_video_enc(
        "CAM123",
        enable=1,
        camera_verification_code="ABCDEF",
        max_retries=1,
    ) is True
    assert captured["method"] == "PUT"
    assert captured["data"] == {
        "deviceSerial": "CAM123",
        "isEncrypt": 1,
        "oldPassword": None,
        "password": None,
        "featureCode": FEATURE_CODE,
        "validateCode": "ABCDEF",
        "msgType": -1,
    }
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 1


def test_set_video_enc_builds_password_change_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_video_enc(
        "CAM123",
        enable=2,
        old_password="old-pass",
        new_password="new-pass",
    ) is True
    assert captured["data"] == {
        "deviceSerial": "CAM123",
        "isEncrypt": 2,
        "oldPassword": "old-pass",
        "password": "new-pass",
        "featureCode": FEATURE_CODE,
        "validateCode": None,
        "msgType": -1,
    }


def test_set_video_enc_validates_password_arguments() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Old password is required"):
        client.set_video_enc("CAM123", enable=2, new_password="new-pass")

    with pytest.raises(PyEzvizError, match="New password is only required"):
        client.set_video_enc("CAM123", enable=1, new_password="new-pass")

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.set_video_enc("CAM123", max_retries=99)


def test_set_video_enc_raises_contextual_api_error(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not set video encryption"):
        client.set_video_enc("CAM123")


def test_voice_info_helpers_build_request_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_voice_config("prod-1", "v1", max_retries=1)["meta"]["code"] == 200
    assert client.get_voice_info("CAM123", local_index="2")["meta"]["code"] == 200
    assert client.add_voice_info("CAM123", "hello", "https://voice.example/1", local_index="2")["meta"]["code"] == 200
    assert client.set_voice_info("CAM123", 5, "hello2", local_index="2")["meta"]["code"] == 200
    assert client.delete_voice_info(
        "CAM123",
        5,
        voice_url="https://voice.example/1",
        local_index="2",
    )["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["params"] == {"productId": "prod-1", "version": "v1"}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["params"] == {"deviceSerial": "CAM123", "localIndex": "2"}
    assert calls[2]["method"] == "POST"
    assert calls[2]["data"] == {
        "deviceSerial": "CAM123",
        "voiceName": "hello",
        "voiceUrl": "https://voice.example/1",
        "localIndex": "2",
    }
    assert calls[3]["method"] == "PUT"
    assert calls[3]["data"] == {
        "deviceSerial": "CAM123",
        "voiceId": 5,
        "voiceName": "hello2",
        "localIndex": "2",
    }
    assert calls[4]["method"] == "DELETE"
    assert calls[4]["params"] == {
        "deviceSerial": "CAM123",
        "voiceId": 5,
        "voiceUrl": "https://voice.example/1",
        "localIndex": "2",
    }


def test_shared_voice_aliases_forward_local_index(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_add_voice_info(
        serial: str,
        voice_name: str,
        voice_url: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "op": "add",
                "serial": serial,
                "voice_name": voice_name,
                "voice_url": voice_url,
                "local_index": local_index,
                "max_retries": max_retries,
            }
        )
        return {"meta": {"code": 200}}

    def fake_set_voice_info(
        serial: str,
        voice_id: int,
        voice_name: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "op": "set",
                "serial": serial,
                "voice_id": voice_id,
                "voice_name": voice_name,
                "local_index": local_index,
                "max_retries": max_retries,
            }
        )
        return {"meta": {"code": 200}}

    def fake_delete_voice_info(
        serial: str,
        voice_id: int,
        *,
        voice_url: str | None = None,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "op": "delete",
                "serial": serial,
                "voice_id": voice_id,
                "voice_url": voice_url,
                "local_index": local_index,
                "max_retries": max_retries,
            }
        )
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "add_voice_info", fake_add_voice_info)
    monkeypatch.setattr(client, "set_voice_info", fake_set_voice_info)
    monkeypatch.setattr(client, "delete_voice_info", fake_delete_voice_info)

    assert client.add_shared_voice_info("CAM123", "hello", "url", "3", max_retries=1)["meta"]["code"] == 200
    assert client.set_shared_voice_info("CAM123", 7, "hello2", "3", max_retries=2)["meta"]["code"] == 200
    assert client.delete_shared_voice_info("CAM123", 7, "url", "3", max_retries=3)["meta"]["code"] == 200

    assert calls == [
        {
            "op": "add",
            "serial": "CAM123",
            "voice_name": "hello",
            "voice_url": "url",
            "local_index": "3",
            "max_retries": 1,
        },
        {
            "op": "set",
            "serial": "CAM123",
            "voice_id": 7,
            "voice_name": "hello2",
            "local_index": "3",
            "max_retries": 2,
        },
        {
            "op": "delete",
            "serial": "CAM123",
            "voice_id": 7,
            "voice_url": "url",
            "local_index": "3",
            "max_retries": 3,
        },
    ]


def test_whistle_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_whistle_status_by_channel("CAM123")["meta"]["code"] == 200
    assert client.get_whistle_status_by_device("CAM123")["meta"]["code"] == 200
    assert client.set_channel_whistle(
        "CAM123",
        [{"channel": 1, "status": 1, "duration": 10, "volume": 50}],
        max_retries=1,
    )["meta"]["code"] == 200
    assert client.set_device_whistle("CAM123", status=1, duration=10, volume=50)["meta"]["code"] == 200
    assert client.stop_whistle("CAM123")["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[1]["method"] == "GET"
    assert calls[2]["method"] == "POST"
    assert calls[2]["json_body"] == {
        "channelWhistleList": [
            {
                "channel": 1,
                "status": 1,
                "duration": 10,
                "volume": 50,
                "deviceSerial": "CAM123",
            }
        ]
    }
    assert calls[2]["max_retries"] == 1
    assert calls[3]["method"] == "PUT"
    assert calls[3]["params"] == {"status": 1, "duration": 10, "volume": 50}
    assert calls[4]["method"] == "PUT"


def test_channel_whistle_validates_entries() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="must contain at least one"):
        client.set_channel_whistle("CAM123", [])

    with pytest.raises(PyEzvizError, match="entries must include"):
        client.set_channel_whistle("CAM123", [{"channel": 1, "status": 1}])


def test_chime_sleep_and_switch_enable_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.delay_battery_device_sleep("CAM123", 1, 2, max_retries=1)["meta"]["code"] == 200
    assert client.get_device_chime_info("CAM123", 1)["meta"]["code"] == 200
    assert client.set_device_chime_info("CAM123", 1, sound_type=2, duration=30)["meta"]["code"] == 200
    assert client.set_switch_enable_req("CAM123", 1, 0, 7)["meta"]["code"] == 200

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/1/2/sleep")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["path"].endswith("CAM123/1")
    assert calls[2]["method"] == "POST"
    assert calls[2]["data"] == {"type": 2, "duration": 30}
    assert calls[3]["method"] == "PUT"
    assert calls[3]["params"] == {"enable": 0, "type": 7}


def test_detector_helpers_build_request_paths(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_detector_setting_info(
        "A1S123",
        "DET456",
        "sensitivity",
        max_retries=1,
    )["meta"]["code"] == 200
    assert client.set_detector_setting_info(
        "A1S123",
        "DET456",
        "sensitivity",
        3,
        max_retries=2,
    )["meta"]["code"] == 200
    assert client.get_detector_info("DET456", max_retries=3)["meta"]["code"] == 200
    assert client.get_radio_signals("A1S123", "DET456", max_retries=4)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("A1S123/detector/DET456/sensitivity")
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "POST"
    assert calls[1]["path"].endswith("A1S123/detector/DET456")
    assert calls[1]["params"] == {"key": "sensitivity"}
    assert calls[1]["data"] == {"value": 3}
    assert calls[1]["max_retries"] == 2
    assert calls[2]["method"] == "GET"
    assert calls[2]["path"].endswith("detector/DET456")
    assert calls[2]["max_retries"] == 3
    assert calls[3]["method"] == "GET"
    assert calls[3]["path"].endswith("A1S123/radioSignal")
    assert calls[3]["params"] == {"childDevSerial": "DET456"}
    assert calls[3]["max_retries"] == 4


def test_detector_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get detector setting info"):
        client.get_detector_setting_info("A1S123", "DET456", "sensitivity")

    with pytest.raises(PyEzvizError, match="Could not set detector setting info"):
        client.set_detector_setting_info("A1S123", "DET456", "sensitivity", 3)

    with pytest.raises(PyEzvizError, match="Could not get detector info"):
        client.get_detector_info("DET456")

    with pytest.raises(PyEzvizError, match="Could not get radio signals"):
        client.get_radio_signals("A1S123", "DET456")


class _JsonResponse:
    def __init__(self, payload: dict[str, Any] | None = None, *, json_error: Exception | None = None) -> None:
        self._payload = payload or {}
        self._json_error = json_error

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        if self._json_error is not None:
            raise self._json_error
        return self._payload


def test_motion_detection_sensitivity_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_motion_detect_sensitivity("CAM123", 1, max_retries=1)["meta"]["code"] == 200
    assert client.get_motion_detect_sensitivity_dp1s("CAM123", 2, max_retries=2)["meta"]["code"] == 200
    assert client.set_detection_sensitivity("CAM123", 3, 0, 6, max_retries=3) is True
    assert client.set_detection_sensitivity("CAM123", 3, 4, 80) is True

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("CAM123/1")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["path"].endswith("CAM123/2/sensitivity")
    assert calls[1]["max_retries"] == 2
    assert calls[2]["method"] == "PUT"
    assert calls[2]["path"].endswith("CAM123/3/0/6")
    assert calls[2]["max_retries"] == 3
    assert calls[3]["method"] == "PUT"
    assert calls[3]["path"].endswith("CAM123/3/4/80")
    assert all(call["retry_401"] is True for call in calls)


def test_set_detection_sensitivity_validates_ranges() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match=r"within 1\.\.6"):
        client.set_detection_sensitivity("CAM123", 1, 0, 7)

    with pytest.raises(PyEzvizError, match=r"within 1\.\.100"):
        client.set_detection_sensitivity("CAM123", 1, 3, 101)

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.set_detection_sensitivity("CAM123", 1, 0, 3, max_retries=99)


def test_get_detection_sensibility_retries_and_selects_algorithm(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [
        {"resultCode": "-1"},
        {
            "resultCode": "0",
            "algorithmConfig": {
                "algorithmList": [
                    {"type": "1", "value": 22},
                    {"type": "3", "value": 44},
                ]
            },
        },
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_detection_sensibility("CAM123", type_value="3", max_retries=1) == 44
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {"subSerial": "CAM123"}
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0


def test_get_detection_sensibility_returns_none_for_missing_type(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "0", "algorithmConfig": {"algorithmList": []}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_detection_sensibility("CAM123", type_value="7") is None


def test_detection_sensibility_legacy_posts_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_post(**kwargs: Any) -> _JsonResponse:
        captured.update(kwargs)
        return _JsonResponse({"resultCode": "0"})

    monkeypatch.setattr(client._session, "post", fake_post)

    assert client.detection_sensibility("CAM123", sensibility=5, type_value=0) is True
    assert captured["data"] == {
        "subSerial": "CAM123",
        "type": 0,
        "channelNo": 1,
        "value": 5,
    }
    assert captured["timeout"] == 1


def test_detection_sensibility_legacy_validates_and_wraps_errors(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Unproper sensibility"):
        client.detection_sensibility("CAM123", sensibility=8, type_value=0)

    def fake_post(**kwargs: Any) -> _JsonResponse:
        return _JsonResponse(json_error=ValueError("not json"))

    monkeypatch.setattr(client._session, "post", fake_post)

    with pytest.raises(PyEzvizError, match="Could not decode response"):
        client.detection_sensibility("CAM123", sensibility=3, type_value=0)


def test_manage_intelligent_app_builds_add_and_remove_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.manage_intelligent_app(
        "CAM123",
        "res-1",
        "app_human_detect",
        action="add",
        max_retries=1,
    ) is True
    assert client.manage_intelligent_app(
        "CAM123",
        "res-1",
        "app_human_detect",
        action="REMOVE",
        max_retries=2,
    ) is True

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/res-1/app_human_detect")
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "DELETE"
    assert calls[1]["path"].endswith("CAM123/res-1/app_human_detect")
    assert calls[1]["max_retries"] == 2


def test_manage_intelligent_app_validates_action_and_retries() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Invalid action"):
        client.manage_intelligent_app("CAM123", "res-1", "app_human_detect", action="toggle")

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.manage_intelligent_app("CAM123", "res-1", "app_human_detect", max_retries=99)


def test_set_intelligent_app_state_resolves_resource_ids(monkeypatch) -> None:
    client = _client()
    client._cameras["CAM123"] = {"resourceInfos": [{"resourceId": "res-auto"}]}
    calls: list[dict[str, Any]] = []

    def fake_manage_intelligent_app(
        serial: str,
        resource_id: str,
        app_name: str,
        action: str = "add",
        max_retries: int = 0,
    ) -> bool:
        calls.append(
            {
                "serial": serial,
                "resource_id": resource_id,
                "app_name": app_name,
                "action": action,
                "max_retries": max_retries,
            }
        )
        return True

    monkeypatch.setattr(client, "manage_intelligent_app", fake_manage_intelligent_app)

    assert client.set_intelligent_app_state("CAM123", "app_car_detect", True, max_retries=1) is True
    assert client.set_intelligent_app_state(
        "CAM123",
        "app_car_detect",
        False,
        resource_id="res-explicit",
        max_retries=2,
    ) is True

    assert calls == [
        {
            "serial": "CAM123",
            "resource_id": "res-auto",
            "app_name": "app_car_detect",
            "action": "add",
            "max_retries": 1,
        },
        {
            "serial": "CAM123",
            "resource_id": "res-explicit",
            "app_name": "app_car_detect",
            "action": "remove",
            "max_retries": 2,
        },
    ]


def test_resolve_resource_id_uses_legacy_fields_and_errors() -> None:
    client = _client()

    assert client._resolve_resource_id("CAM123", "given") == "given"

    client._cameras["CAM123"] = {"resouceid": "legacy-typo"}
    assert client._resolve_resource_id("CAM123", None) == "legacy-typo"

    client._cameras["CAM123"] = {"resource_id": "legacy-resource"}
    assert client._resolve_resource_id("CAM123", None) == "legacy-resource"

    with pytest.raises(PyEzvizError, match="Unknown camera serial"):
        client._resolve_resource_id("UNKNOWN", None)

    client._cameras["EMPTY"] = {"name": "No Resource"}
    with pytest.raises(PyEzvizError, match="Unable to determine resourceId"):
        client._resolve_resource_id("EMPTY", None)


def test_mirror_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.device_mirror("CAM123", 2, "LEFT", max_retries=1)["meta"]["code"] == 200
    assert client.flip_image("CAM123", channel=3, max_retries=2) is True

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/2/LEFT/mirror")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("CAM123/3/CENTER/mirror")
    assert calls[1]["max_retries"] == 2


def test_resolve_osd_text_prefers_name_then_payload_sources() -> None:
    client = _client()

    assert client._resolve_osd_text("CAM123", name="  Friendly  ") == "Friendly"
    assert client._resolve_osd_text("CAM123", camera_data={"name": "Direct"}) == "Direct"
    assert client._resolve_osd_text(
        "CAM123",
        camera_data={"deviceInfos": {"name": "Device Info"}},
    ) == "Device Info"
    assert client._resolve_osd_text(
        "CAM123",
        camera_data={"optionals": {"OSD": [{"name": "OSD Name"}]}},
    ) == "OSD Name"
    assert client._resolve_osd_text("CAM123", camera_data={}) == "CAM123"


def test_set_camera_osd_builds_request_from_text_and_enabled(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_camera_osd("CAM123", text="Explicit", channel=2, max_retries=1) is True
    assert client.set_camera_osd("CAM123", enabled=False) is True
    assert client.set_camera_osd(
        "CAM123",
        enabled=True,
        camera_data={"deviceInfos": {"name": "Front Door"}},
    ) is True

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/2/osd")
    assert calls[0]["data"] == {"osd": "Explicit"}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["data"] == {"osd": ""}
    assert calls[2]["data"] == {"osd": "Front Door"}


def test_set_camera_osd_requires_camera_data_when_deriving() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Camera data unavailable"):
        client.set_camera_osd("CAM123", enabled=True)


def test_set_floodlight_brightness_builds_request(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.set_floodlight_brightness("CAM123", luminance=75, channelno=2, max_retries=1) is True
    assert captured["method"] == "POST"
    assert captured["path"].endswith("CAM123/2")
    assert captured["data"] == {"luminance": 75}
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 1


def test_set_floodlight_brightness_validates_range_and_retries() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Range of luminance"):
        client.set_floodlight_brightness("CAM123", luminance=0)

    with pytest.raises(PyEzvizError, match="Range of luminance"):
        client.set_floodlight_brightness("CAM123", luminance=100)

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.set_floodlight_brightness("CAM123", max_retries=99)


def test_set_brightness_routes_light_bulbs_to_iot_feature(monkeypatch) -> None:
    client = _client()
    client._light_bulbs["LIGHT123"] = {"productId": "prod-light"}
    calls: list[dict[str, Any]] = []

    def fake_set_device_feature_by_key(
        serial: str,
        product_id: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        calls.append(
            {
                "serial": serial,
                "product_id": product_id,
                "value": value,
                "key": key,
                "max_retries": max_retries,
            }
        )
        return True

    monkeypatch.setattr(client, "set_device_feature_by_key", fake_set_device_feature_by_key)

    assert client.set_brightness("LIGHT123", luminance=42, max_retries=2) is True
    assert calls == [
        {
            "serial": "LIGHT123",
            "product_id": "prod-light",
            "value": 42,
            "key": "brightness",
            "max_retries": 2,
        }
    ]


def test_set_brightness_routes_unknown_serial_to_floodlight(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_set_floodlight_brightness(
        serial: str,
        luminance: int = 50,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool:
        calls.append(
            {
                "serial": serial,
                "luminance": luminance,
                "channelno": channelno,
                "max_retries": max_retries,
            }
        )
        return True

    monkeypatch.setattr(client, "set_floodlight_brightness", fake_set_floodlight_brightness)

    assert client.set_brightness("CAM123", luminance=55, channelno=3, max_retries=1) is True
    assert calls == [
        {
            "serial": "CAM123",
            "luminance": 55,
            "channelno": 3,
            "max_retries": 1,
        }
    ]


def test_switch_light_status_routes_light_bulbs_to_iot_feature(monkeypatch) -> None:
    client = _client()
    client._light_bulbs["LIGHT123"] = {"productId": "prod-light"}
    calls: list[dict[str, Any]] = []

    def fake_set_device_feature_by_key(
        serial: str,
        product_id: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        calls.append(
            {
                "serial": serial,
                "product_id": product_id,
                "value": value,
                "key": key,
                "max_retries": max_retries,
            }
        )
        return True

    monkeypatch.setattr(client, "set_device_feature_by_key", fake_set_device_feature_by_key)

    assert client.switch_light_status("LIGHT123", enable=1, max_retries=2) is True
    assert calls == [
        {
            "serial": "LIGHT123",
            "product_id": "prod-light",
            "value": True,
            "key": "light_switch",
            "max_retries": 2,
        }
    ]


def test_switch_light_status_routes_cameras_to_alarm_light_switch(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_switch_status(
        serial: str,
        status_type: int,
        enable: bool | int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        calls.append(
            {
                "serial": serial,
                "status_type": status_type,
                "enable": enable,
                "channel_no": channel_no,
                "max_retries": max_retries,
            }
        )
        return True

    monkeypatch.setattr(client, "switch_status", fake_switch_status)

    assert client.switch_light_status("CAM123", enable=0, channel_no=2, max_retries=1) is True
    assert calls == [
        {
            "serial": "CAM123",
            "status_type": DeviceSwitchType.ALARM_LIGHT.value,
            "enable": 0,
            "channel_no": 2,
            "max_retries": 1,
        }
    ]


def test_do_not_disturb_and_answer_call_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.do_not_disturb("CAM123", enable=0, channelno=2, max_retries=1) is True
    assert client.set_answer_call("CAM123", enable=1, max_retries=2) is True

    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"].endswith("CAM123/2/nodisturb")
    assert calls[0]["data"] == {"enable": 0}
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("CAM123/nodisturb")
    assert calls[1]["data"] == {"deviceSerial": "CAM123", "switchStatus": 1}
    assert calls[1]["retry_401"] is True
    assert calls[1]["max_retries"] == 2


def test_do_not_disturb_and_answer_call_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not set do not disturb"):
        client.do_not_disturb("CAM123")

    with pytest.raises(PyEzvizError, match="Could not set answer call"):
        client.set_answer_call("CAM123")


def test_api_set_defence_schedule_retries_and_builds_payload(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [{"resultCode": "-1"}, {"resultCode": "0"}]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.api_set_defence_schedule(
        "CAM123",
        '{"start":"08:00","stop":"17:00"}',
        enable=1,
        max_retries=1,
    ) is True
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {
        "devTimingPlan": '{"CN":0,"EL":1,"SS":"CAM123","WP":[{"start":"08:00","stop":"17:00"}]}]}'
    }
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0


def test_api_set_defence_schedule_validates_and_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.api_set_defence_schedule("CAM123", "{}", 1, max_retries=99)

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "500", "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not set the schedule"):
        client.api_set_defence_schedule("CAM123", "{}", 1)


def test_defence_mode_helpers_build_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "ok": True}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.api_set_defence_mode(DefenseModeType.HOME_MODE, visual_alarm=1, sound_mode=2, max_retries=1) is True
    assert client.api_set_defence_mode(3) is True
    assert client.switch_defence_mode(5, 2, visual_alarm=0, sound_mode=1, max_retries=2) == {
        "meta": {"code": 200},
        "ok": True,
    }

    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {
        "groupId": -1,
        "mode": int(DefenseModeType.HOME_MODE.value),
        "visualAlarm": 1,
        "soundMode": 2,
    }
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["data"] == {"groupId": -1, "mode": 3}
    assert calls[2]["method"] == "POST"
    assert calls[2]["data"] == {
        "groupId": 5,
        "mode": 2,
        "visualAlarm": 0,
        "soundMode": 1,
    }
    assert calls[2]["max_retries"] == 2


def test_defence_mode_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not set defence mode"):
        client.api_set_defence_mode(1)

    with pytest.raises(PyEzvizError, match="Could not switch defence mode"):
        client.switch_defence_mode(5, 1)


def test_door_lock_and_remote_lock_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_door_lock_users("LOCK123", max_retries=1)["meta"]["code"] == 200
    assert client.remote_unlock(
        "LOCK123",
        "user-1",
        7,
        resource_id="DoorLock",
        local_index=2,
        stream_token="stream-1",
        lock_type="fingerprint",
        use_terminal_bind=False,
    ) is True
    assert client.remote_lock("LOCK123", "user-1", 7) is True
    assert client.get_remote_unbind_progress("LOCK123", max_retries=2)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("LOCK123/users")
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("LOCK123/DoorLock/2/DoorLockMgr/RemoteUnlockReq")
    assert calls[1]["json_body"] == {
        "unLockInfo": {
            "bindCode": f"{FEATURE_CODE}user-1",
            "lockNo": 7,
            "streamToken": "stream-1",
            "userName": "user-1",
            "type": "fingerprint",
        }
    }
    assert calls[1]["retry_401"] is True
    assert calls[1]["max_retries"] == 0
    assert calls[2]["method"] == "PUT"
    assert calls[2]["path"].endswith("LOCK123/Video/1/DoorLockMgr/RemoteLockReq")
    assert calls[2]["json_body"] == {
        "unLockInfo": {
            "bindCode": f"{FEATURE_CODE}user-1",
            "lockNo": 7,
            "streamToken": "",
            "userName": "user-1",
        }
    }
    assert calls[3]["method"] == "GET"
    assert calls[3]["path"].endswith("LOCK123/progress")
    assert calls[3]["max_retries"] == 2


def test_terminal_helpers_parse_latest_bind(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {
            "meta": {"code": 200},
            "terminals": [
                {
                    "name": "older phone",
                    "sign": "old-sign-",
                    "userId": "old-user",
                    "lastModifytime": "2025-01-01T00:00:00Z",
                },
                {
                    "name": "latest phone",
                    "sign": "new-sign-",
                    "userId": "new-user",
                    "lastModifytime": "2025-01-02T00:00:00Z",
                },
            ],
        }

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == ("new-sign-new-user", "latest phone")
    assert captured["method"] == "GET"
    assert captured["path"].endswith("/v3/terminals")
    assert captured["params"] == {"limit": 20, "offset": 0}
    assert captured["retry_401"] is True


def test_terminal_helpers_ignore_latest_terminal_without_bind_fields(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "meta": {"code": 200},
            "terminals": [
                {
                    "name": "valid older phone",
                    "sign": "valid-sign-",
                    "userId": "valid-user",
                    "lastModifytime": "2025-01-01T00:00:00Z",
                },
                {
                    "name": "invalid latest phone",
                    "lastModifytime": "2025-01-02T00:00:00Z",
                },
            ],
        }

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == ("valid-sign-valid-user", "valid older phone")


def test_terminal_helpers_ignore_empty_bind_fields(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "meta": {"code": 200},
            "terminals": [
                {
                    "name": "valid phone",
                    "sign": " valid-sign- ",
                    "userId": " valid-user ",
                    "lastModifytime": "2025-01-01T00:00:00Z",
                },
                {
                    "name": "empty latest phone",
                    "sign": "",
                    "userId": " ",
                    "lastModifytime": "2025-01-02T00:00:00Z",
                },
            ],
        }

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == ("valid-sign-valid-user", "valid phone")


def test_remote_unlock_uses_terminal_bind_when_available(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if path.endswith("/v3/terminals"):
            return {
                "meta": {"code": 200},
                "terminals": [
                    {
                        "name": "phone",
                        "sign": "terminal-sign-",
                        "userId": "terminal-user",
                        "lastModifytime": "2025-01-02T00:00:00Z",
                    }
                ],
            }
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.remote_unlock("LOCK123", "legacy-user", 2) is True
    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("/v3/terminals")
    assert calls[1]["method"] == "PUT"
    assert calls[1]["json_body"] == {
        "unLockInfo": {
            "bindCode": "terminal-sign-terminal-user",
            "lockNo": 2,
            "streamToken": "",
            "userName": "phone",
        }
    }


def test_remote_unlock_falls_back_when_terminal_lookup_request_fails(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if path.endswith("/v3/terminals"):
            raise requests.Timeout("timed out")
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.remote_unlock("LOCK123", "legacy-user", 2) is True
    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("/v3/terminals")
    assert calls[1]["method"] == "PUT"
    assert calls[1]["json_body"] == {
        "unLockInfo": {
            "bindCode": f"{FEATURE_CODE}legacy-user",
            "lockNo": 2,
            "streamToken": "",
            "userName": "legacy-user",
        }
    }


def test_door_lock_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get door lock users"):
        client.get_door_lock_users("LOCK123")

    with pytest.raises(PyEzvizError, match="Could not get unbind progress"):
        client.get_remote_unbind_progress("LOCK123")


def test_ptz_control_builds_request_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.ptz_control("LEFT", "CAM123", "START", speed=4) is True
    assert captured["method"] == "PUT"
    assert captured["path"].endswith("CAM123/ptzControl")
    assert captured["data"]["command"] == "LEFT"
    assert captured["data"]["action"] == "START"
    assert captured["data"]["channelNo"] == 1
    assert captured["data"]["speed"] == 4
    assert captured["data"]["serial"] == "CAM123"
    assert isinstance(captured["data"]["uuid"], str)
    assert captured["retry_401"] is False


def test_ptz_control_requires_command_and_action() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="without command"):
        client.ptz_control(None, "CAM123", "START")  # type: ignore[arg-type]

    with pytest.raises(PyEzvizError, match="without action"):
        client.ptz_control("LEFT", "CAM123", None)  # type: ignore[arg-type]


def test_panoramic_helpers_retry_and_build_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [
        {"resultCode": "-1"},
        {"resultCode": "0", "panoramic": "created"},
        {"resultCode": "-1"},
        {"resultCode": "0", "urls": ["https://image.example/pano.jpg"]},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.create_panoramic("CAM123", max_retries=1) == {
        "resultCode": "0",
        "panoramic": "created",
    }
    assert client.return_panoramic("CAM123", max_retries=1) == {
        "resultCode": "0",
        "urls": ["https://image.example/pano.jpg"],
    }

    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {"deviceSerial": "CAM123"}
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0
    assert calls[2]["method"] == "POST"
    assert calls[2]["data"] == {"deviceSerial": "CAM123"}
    assert calls[2]["max_retries"] == 0


def test_panoramic_helpers_validate_and_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.create_panoramic("CAM123", max_retries=99)

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "500"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="create panoramic photo"):
        client.create_panoramic("CAM123")

    with pytest.raises(PyEzvizError, match="retrieve panoramic photo"):
        client.return_panoramic("CAM123")


def test_ptz_control_coordinates_formats_payload_and_validates(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.ptz_control_coordinates("CAM123", 0.25, 0.75) is True
    assert captured["method"] == "POST"
    assert captured["data"] == {
        "x": "0.250000",
        "y": "0.750000",
        "deviceSerial": "CAM123",
    }
    assert captured["retry_401"] is False

    with pytest.raises(PyEzvizError, match="Invalid X coordinate"):
        client.ptz_control_coordinates("CAM123", 1.1, 0.5)

    with pytest.raises(PyEzvizError, match="Invalid Y coordinate"):
        client.ptz_control_coordinates("CAM123", 0.5, 1.1)


def test_capture_picture_builds_request(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.capture_picture("CAM123", 2, max_retries=1)["meta"]["code"] == 200
    assert captured["method"] == "PUT"
    assert captured["path"].endswith("CAM123/2/capture")
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 1


def test_get_cam_key_retries_and_returns_encrypt_key(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = [
        {"resultCode": "-1"},
        {"resultCode": "0", "encryptkey": "ENC123"},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_cam_key("CAM123", smscode=123456, max_retries=1) == "ENC123"
    assert len(calls) == 2
    assert calls[0]["method"] == "POST"
    assert calls[0]["data"] == {
        "checkcode": 123456,
        "serial": "CAM123",
        "clientNo": "web_site",
        "clientType": 3,
        "netType": "WIFI",
        "featureCode": FEATURE_CODE,
        "sessionId": "session",
    }
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0


def test_get_cam_key_maps_special_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"resultCode": "20002"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(EzvizAuthVerificationCode, match="MFA code required"):
        client.get_cam_key("CAM123")

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"resultCode": "2009"})

    with pytest.raises(DeviceException, match="Device not reachable"):
        client.get_cam_key("CAM123")

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"resultCode": "500"})

    with pytest.raises(PyEzvizError, match="Could not get camera encryption key"):
        client.get_cam_key("CAM123")


def test_get_cam_auth_code_builds_request_and_returns_code(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "devAuthCode": "AUTH123"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_cam_auth_code(
        "CAM123",
        encrypt_pwd="enc",
        msg_auth_code=123456,
        sender_type=3,
        max_retries=1,
    ) == "AUTH123"
    assert captured["method"] == "GET"
    assert captured["path"].endswith("CAM123")
    assert captured["params"] == {
        "encrptPwd": "enc",
        "msgAuthCode": 123456,
        "senderType": 3,
    }
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 1


def test_get_cam_auth_code_maps_special_errors(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.get_cam_auth_code("CAM123", max_retries=99)

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"meta": {"code": 80000}})
    with pytest.raises(EzvizAuthVerificationCode, match="Operation requires 2FA"):
        client.get_cam_auth_code("CAM123")

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"meta": {"code": 2009}})
    with pytest.raises(DeviceException, match="Device not reachable"):
        client.get_cam_auth_code("CAM123")

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"meta": {"code": 500}})
    with pytest.raises(PyEzvizError, match="Could not get camera verification key"):
        client.get_cam_auth_code("CAM123")


def test_get_2fa_check_code_builds_request(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "contact": {"type": "EMAIL"}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_2fa_check_code(
        biz_type="DEVICE_ENCRYPTION",
        username="user@example.test",
        max_retries=2,
    ) == {"meta": {"code": 200}, "contact": {"type": "EMAIL"}}
    assert captured["method"] == "POST"
    assert captured["data"] == {
        "bizType": "DEVICE_ENCRYPTION",
        "from": "user@example.test",
    }
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_get_2fa_check_code_validates_and_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.get_2fa_check_code(max_retries=99)

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not request elevated permission"):
        client.get_2fa_check_code()


def test_accessory_and_dev_config_read_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}, "path": path}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_accessory("CAM123", "2", max_retries=1)["meta"]["code"] == 200
    assert client.get_dev_config("CAM123", 3, "NightVision_Model", max_retries=2)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("CAM123/2/1/linked/info")
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["path"].endswith("CAM123/3/op")
    assert calls[1]["params"] == {"key": "NightVision_Model"}
    assert calls[1]["retry_401"] is True
    assert calls[1]["max_retries"] == 2


def test_accessory_and_dev_config_read_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get accessory info"):
        client.get_accessory("CAM123", "2")

    with pytest.raises(PyEzvizError, match="Could not get devconfig value"):
        client.get_dev_config("CAM123", 3, "NightVision_Model")


def test_managed_device_and_status_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_managed_device_info("BASE123", max_retries=1)["meta"]["code"] == 200
    assert client.get_managed_device_ipcs("BASE123", max_retries=2)["meta"]["code"] == 200
    assert client.get_devices_status(["CAM2", "CAM1", "CAM1"], max_retries=3)["meta"]["code"] == 200
    assert client.get_device_secret_key_info("CAM1", max_retries=4)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("BASE123/base")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["path"].endswith("BASE123/ipcs")
    assert calls[1]["max_retries"] == 2
    assert calls[2]["method"] == "GET"
    assert calls[2]["params"] == {"deviceSerials": "CAM1,CAM2"}
    assert calls[2]["max_retries"] == 3
    assert calls[3]["method"] == "GET"
    assert calls[3]["params"] == {"deviceSerials": "CAM1"}
    assert calls[3]["max_retries"] == 4
    assert all(call["retry_401"] is True for call in calls)


def test_p2p_and_upgrade_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_p2p_info(["CAM2", "CAM1"])["meta"]["code"] == 200
    assert client.get_p2p_server_info(["CAM2", "CAM1"])["meta"]["code"] == 200
    assert client.check_device_upgrade_rule(max_retries=1)["meta"]["code"] == 200
    assert client.get_autoupgrade_switch(max_retries=2)["meta"]["code"] == 200
    assert client.set_autoupgrade_switch(1, 2, max_retries=3)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["params"] == {"deviceSerials": "CAM1,CAM2"}
    assert calls[1]["method"] == "GET"
    assert calls[1]["params"] == {"deviceSerials": "CAM1,CAM2"}
    assert calls[2]["method"] == "GET"
    assert calls[2]["max_retries"] == 1
    assert calls[3]["method"] == "GET"
    assert calls[3]["max_retries"] == 2
    assert calls[4]["method"] == "PUT"
    assert calls[4]["data"] == {"autoUpgrade": 1, "timeType": 2}
    assert calls[4]["max_retries"] == 3


def test_device_encrypt_key_list_builds_prepared_form_request(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        captured.update({"req": req, **kwargs})
        return _response(text='{"meta": {"code": 200}, "keys": []}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    assert client.get_device_list_encrypt_key(7, {"serial": ["CAM1", "CAM2"]}, max_retries=1) == {
        "meta": {"code": 200},
        "keys": [],
    }
    req = captured["req"]
    assert req.method == "POST"
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert req.headers["areaId"] == "7"
    assert req.body == "serial=CAM1&serial=CAM2"
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 1


def test_device_encrypt_key_list_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        return _response(text='{"meta": {"code": 500}, "message": "failed"}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    with pytest.raises(PyEzvizError, match="Could not get device encrypt key list"):
        client.get_device_list_encrypt_key(7, "serial=CAM1")


def test_black_level_time_plan_and_record_helpers_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_black_level_list("CAM123", max_retries=1)["meta"]["code"] == 200
    assert client.get_time_plan_infos("CAM123", 2, 3, max_retries=2)["meta"]["code"] == 200
    assert client.set_time_plan_infos(
        "CAM123",
        2,
        3,
        1,
        [{"start": "08:00", "stop": "17:00"}],
        max_retries=3,
    )["meta"]["code"] == 200
    assert client.set_time_plan_infos("CAM123", 2, 3, 0, "[]")["meta"]["code"] == 200
    assert client.search_records(
        "CAM123",
        2,
        "CHAN123",
        "2026-04-27T08:00:00Z",
        "2026-04-27T09:00:00Z",
        size=50,
        max_retries=4,
    )["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert calls[0]["path"].endswith("CAM123")
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "timingPlanType": 3,
    }
    assert calls[1]["max_retries"] == 2
    assert calls[2]["method"] == "PUT"
    assert calls[2]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "timingPlanType": 3,
        "enable": 1,
        "timerDefenceQos": '[{"start": "08:00", "stop": "17:00"}]',
    }
    assert calls[2]["max_retries"] == 3
    assert calls[3]["params"]["timerDefenceQos"] == "[]"
    assert calls[4]["method"] == "GET"
    assert calls[4]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "channelSerial": "CHAN123",
        "startTime": "2026-04-27T08:00:00Z",
        "stopTime": "2026-04-27T09:00:00Z",
        "size": 50,
    }
    assert calls[4]["max_retries"] == 4
    assert all(call["retry_401"] is True for call in calls)


def test_time_plan_and_record_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get black level list"):
        client.get_black_level_list("CAM123")

    with pytest.raises(PyEzvizError, match="Could not get time plan infos"):
        client.get_time_plan_infos("CAM123", 2, 3)

    with pytest.raises(PyEzvizError, match="Could not set time plan infos"):
        client.set_time_plan_infos("CAM123", 2, 3, 1, [])

    with pytest.raises(PyEzvizError, match="Could not search records"):
        client.search_records("CAM123", 2, "CHAN123", "start", "stop")


def test_search_device_builds_prepared_request(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        captured.update({"req": req, **kwargs})
        return _response(text='{"meta": {"code": 200}, "device": {"serial": "CAM123"}}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    assert client.search_device("CAM123", user_ssid="ssid-1", max_retries=2) == {
        "meta": {"code": 200},
        "device": {"serial": "CAM123"},
    }
    req = captured["req"]
    assert req.method == "GET"
    assert "deviceSerial=CAM123" in (req.url or "")
    assert req.headers["userSsid"] == "ssid-1"
    assert captured["retry_401"] is True
    assert captured["max_retries"] == 2


def test_search_device_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_send_prepared(req: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        return _response(text='{"meta": {"code": 500}, "message": "failed"}')

    monkeypatch.setattr(client, "_send_prepared", fake_send_prepared)

    with pytest.raises(PyEzvizError, match="Could not search device"):
        client.search_device("CAM123")


def test_lower_tail_helpers_build_request_payloads(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_socket_log_info("PLUG123", "2026-04-27", "2026-04-28", max_retries=1)["meta"]["code"] == 200
    assert client.linked_cameras("A1S123", "DET456", max_retries=2)["meta"]["code"] == 200
    assert client.set_microscope("CAM123", 2.5, 10, 20, 1, max_retries=3)["meta"]["code"] == 200
    assert client.share_accept("CAM123", max_retries=4)["meta"]["code"] == 200
    assert client.share_quit("CAM123", max_retries=5)["meta"]["code"] == 200
    assert client.send_feedback(
        email="user@example.test",
        account="account-1",
        score=5,
        feedback="works",
        pic_url="https://image.example/pic.jpg",
        max_retries=6,
    )["meta"]["code"] == 200
    assert client.upload_device_log("CAM123", max_retries=7)["meta"]["code"] == 200

    assert calls[0]["method"] == "GET"
    assert "2026-04-27" in calls[0]["path"]
    assert "2026-04-28" in calls[0]["path"]
    assert calls[0]["params"] == {"deviceSerial": "PLUG123"}
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "GET"
    assert calls[1]["params"] == {
        "deviceSerial": "A1S123",
        "detectorDeviceSerial": "DET456",
    }
    assert calls[1]["max_retries"] == 2
    assert calls[2]["method"] == "PUT"
    assert calls[2]["path"].endswith("CAM123/microscope")
    assert calls[2]["data"] == {"multiple": 2.5, "x": 10, "y": 20, "index": 1}
    assert calls[2]["max_retries"] == 3
    assert calls[3]["method"] == "POST"
    assert calls[3]["data"] == {"deviceSerial": "CAM123"}
    assert calls[3]["max_retries"] == 4
    assert calls[4]["method"] == "DELETE"
    assert calls[4]["params"] == {"deviceSerial": "CAM123"}
    assert calls[4]["max_retries"] == 5
    assert calls[5]["method"] == "POST"
    assert calls[5]["params"] == {
        "email": "user@example.test",
        "account": "account-1",
        "score": 5,
        "feedback": "works",
        "picUrl": "https://image.example/pic.jpg",
    }
    assert calls[5]["max_retries"] == 6
    assert calls[6]["method"] == "POST"
    assert calls[6]["path"] == "/v3/devconfig/dump/app/trigger"
    assert calls[6]["data"] == {"deviceSerial": "CAM123"}
    assert calls[6]["max_retries"] == 7
    assert all(call["retry_401"] is True for call in calls)


def test_lower_tail_helpers_raise_contextual_errors(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get socket log info"):
        client.get_socket_log_info("PLUG123", "start", "end")

    with pytest.raises(PyEzvizError, match="Could not get linked cameras"):
        client.linked_cameras("A1S123", "DET456")

    with pytest.raises(PyEzvizError, match="Could not set microscope"):
        client.set_microscope("CAM123", 2.5, 10, 20, 1)

    with pytest.raises(PyEzvizError, match="Could not accept share"):
        client.share_accept("CAM123")

    with pytest.raises(PyEzvizError, match="Could not quit share"):
        client.share_quit("CAM123")

    with pytest.raises(PyEzvizError, match="Could not send feedback"):
        client.send_feedback(email="user@example.test", account="account", score=1, feedback="nope")

    with pytest.raises(PyEzvizError, match="Could not upload device log"):
        client.upload_device_log("CAM123")


def test_lbs_domain_and_alarm_sound_build_requests(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.lbs_domain(max_retries=1)["meta"]["code"] == 200
    assert client.alarm_sound("CAM123", sound_type=2, enable=0, voice_id=9, max_retries=2) is True
    assert client.alarm_sound("CAM456", sound_type=1) is True

    assert calls[0]["method"] == "GET"
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 1
    assert calls[1]["method"] == "PUT"
    assert calls[1]["path"].endswith("CAM123/alarm/sound")
    assert calls[1]["data"] == {
        "enable": 0,
        "soundType": 2,
        "voiceId": 9,
        "deviceSerial": "CAM123",
    }
    assert calls[1]["retry_401"] is True
    assert calls[1]["max_retries"] == 2
    assert calls[2]["data"] == {
        "enable": 1,
        "soundType": 1,
        "voiceId": 0,
        "deviceSerial": "CAM456",
    }


def test_alarm_sound_validates_and_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Invalid sound_type"):
        client.alarm_sound("CAM123", sound_type=9)

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client.alarm_sound("CAM123", sound_type=1, max_retries=99)

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 500}, "message": "failed"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not set alarm sound"):
        client.alarm_sound("CAM123", sound_type=1)

    with pytest.raises(PyEzvizError, match="Could not get LBS domain"):
        client.lbs_domain()


def test_page_list_facades_use_expected_filters(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_api_get_pagelist(
        page_filter: str,
        json_key: str | None = None,
        group_id: int = -1,
        limit: int = 30,
        offset: int = 0,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "page_filter": page_filter,
                "json_key": json_key,
                "group_id": group_id,
                "limit": limit,
                "offset": offset,
                "max_retries": max_retries,
            }
        )
        return {"filter": page_filter, "json_key": json_key}

    monkeypatch.setattr(client, "_api_get_pagelist", fake_api_get_pagelist)

    assert client.get_device() == {"filter": "CLOUD", "json_key": "deviceInfos"}
    assert client.get_connection() == {"filter": "CONNECTION", "json_key": "CONNECTION"}
    assert client.get_switch() == {"filter": "SWITCH", "json_key": "SWITCH"}
    assert client.get_page_list()["json_key"] is None

    assert calls[0]["page_filter"] == "CLOUD"
    assert calls[0]["json_key"] == "deviceInfos"
    assert calls[1]["page_filter"] == "CONNECTION"
    assert calls[1]["json_key"] == "CONNECTION"
    assert calls[2]["page_filter"] == "SWITCH"
    assert calls[2]["json_key"] == "SWITCH"
    assert "CLOUD" in calls[3]["page_filter"]
    assert "SWITCH" in calls[3]["page_filter"]
    assert calls[3]["json_key"] is None


def test_get_mqtt_client_reuses_cached_instance(monkeypatch) -> None:
    client = _client()
    created: list[dict[str, Any]] = []

    class FakeMQTTClient:
        def __init__(self, **kwargs: Any) -> None:
            created.append(kwargs)

    monkeypatch.setattr("pyezvizapi.client.MQTTClient", FakeMQTTClient)

    def callback(payload: dict[str, Any]) -> None:
        return None

    first = client.get_mqtt_client(callback)
    second = client.get_mqtt_client()

    assert first is second
    assert len(created) == 1
    assert created[0]["token"] == client._token
    assert created[0]["session"] is client._session
    assert created[0]["timeout"] == 1
    assert created[0]["on_message_callback"] is callback


def test_get_alarminfo_builds_request_and_retries_server_busy(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    responses = [
        {"meta": {"code": 500}, "message": "busy"},
        {"meta": {"code": 200}, "alarms": []},
    ]

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_alarminfo("CAM123", limit=5, max_retries=1) == {
        "meta": {"code": 200},
        "alarms": [],
    }
    assert len(calls) == 2
    assert calls[0]["method"] == "GET"
    assert calls[0]["params"] == {
        "deviceSerials": "CAM123",
        "queryType": -1,
        "limit": 5,
        "stype": -1,
    }
    assert calls[0]["retry_401"] is True
    assert calls[0]["max_retries"] == 0


def test_get_alarminfo_raises_contextual_error(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 401}, "message": "denied"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    with pytest.raises(PyEzvizError, match="Could not get data from alarm api"):
        client.get_alarminfo("CAM123")


def test_get_device_records_returns_map_single_record_and_raw_fallback(monkeypatch) -> None:
    client = _client()
    device_infos = {
        "CAM123": {
            "deviceInfos": {
                "deviceSerial": "CAM123",
                "name": "Front door",
                "deviceCategory": "camera",
                "version": "1.0",
                "status": 1,
            },
            "STATUS": {"globalStatus": 1, "optionals": {}},
            "SWITCH": [{"type": 1, "enable": 1}],
        },
        "ODD123": {"unexpected": "shape"},
    }

    monkeypatch.setattr(client, "get_device_infos", lambda: device_infos)

    records = cast(dict[str, Any], client.get_device_records())
    assert records["CAM123"].serial == "CAM123"
    assert records["CAM123"].name == "Front door"
    assert records["CAM123"].switches == {1: True}

    cam_record = cast(Any, client.get_device_records("CAM123"))
    assert cam_record.serial == "CAM123"
    assert cam_record.name == "Front door"
    assert client.get_device_records("MISSING") == {}


def test_set_camera_defence_old_delegates_to_cas(monkeypatch) -> None:
    client = _client()
    created: list[dict[str, Any]] = []
    calls: list[tuple[str, int]] = []

    class FakeCAS:
        def __init__(self, token: dict[str, Any]) -> None:
            created.append(token)

        def set_camera_defence_state(self, serial: str, enable: int) -> None:
            calls.append((serial, enable))

    monkeypatch.setattr("pyezvizapi.client.EzvizCAS", FakeCAS)

    assert client.set_camera_defence_old("CAM123", 1) is True
    assert created == [client._token]
    assert calls == [("CAM123", 1)]
