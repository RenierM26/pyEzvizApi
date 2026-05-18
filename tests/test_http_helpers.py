Total output lines: 3472

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, cast

import pytest
import requests

from pyezvizapi.api_endpoints import API_ENDPOINT_IOT_ACTION
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import (
    FEATURE_CODE,
    HIK_ENCRYPTION_HEADER,
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


def _fixture(name: str) -> dict[str, Any]:
    path = Path(__file__).with_name("fixtures") / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _response(*, status_code: int = 200, text: str = '{"meta": {"code": 200}}') -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = text.encode()
    resp.url = "https://api.example.test/path"
    return resp


def _binary_response(content: bytes) -> requests.Response:
    resp = requests.Response()
    resp.status_code = 200
    resp._content = content
    resp.url = "https://image.example.test/alarm.jpg"
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
        ("CAM123", '{"graphicType":1,"luminance":55}', "Nigh…20958 tokens truncated…08:00:00Z",
        "2026-04-27T09:00:00Z",
        size=50,
        max_retries=4,
    )["meta"]["code"] == 200
    assert client.search_records_v2(
        "CAM123",
        2,
        "2026-04-27T08:00:00Z",
        "2026-04-27T09:00:00Z",
        size=10,
        sort_by=1,
        require_label=1,
        max_retries=5,
    )["meta"]["code"] == 200
    assert client.search_common_records(
        "CAM123",
        2,
        "2026-04-27T08:00:00Z",
        "2026-04-27T09:00:00Z",
        channel_serial="CHAN123",
        record_type=2,
        size=11,
        version=3,
        max_retries=6,
    )["meta"]["code"] == 200
    assert client.search_intelligent_records(
        "CAM123",
        2,
        "2026-04-27T08:00:00Z",
        "2026-04-27T09:00:00Z",
        version=4,
        record_filter='{"person":true}',
        max_retries=7,
    )["meta"]["code"] == 200
    assert client.get_cloud_videos(
        "CAM123",
        2,
        limit=5,
        video_type=-1,
        support_multi_channel_shared_service=1,
        max_retries=8,
    )["meta"]["code"] == 200
    assert client.get_cloud_video_details(
        "CAM123",
        2,
        [
            {
                "seqId": 12345,
                "startTime": "2026-04-27 08:00:00",
                "stopTime": "2026-04-27 08:01:00",
                "storageVersion": 2,
            }
        ],
        support_multi_channel_shared_service=1,
        max_retries=9,
    )["meta"]["code"] == 200
    assert client.get_camera_ticket_info(
        "CAM123",
        2,
        support_multi_channel_shared_service=1,
        max_retries=10,
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
    assert calls[5]["method"] == "GET"
    assert calls[5]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "startTime": "2026-04-27T08:00:00Z",
        "stopTime": "2026-04-27T09:00:00Z",
        "size": 10,
        "sortBy": 1,
        "requireLabel": 1,
    }
    assert calls[5]["max_retries"] == 5
    assert calls[6]["method"] == "GET"
    assert calls[6]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "startTime": "2026-04-27T08:00:00Z",
        "stopTime": "2026-04-27T09:00:00Z",
        "recordType": 2,
        "size": 11,
        "version": 3,
        "channelSerial": "CHAN123",
    }
    assert calls[6]["max_retries"] == 6
    assert calls[7]["method"] == "GET"
    assert calls[7]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "startTime": "2026-04-27T08:00:00Z",
        "stopTime": "2026-04-27T09:00:00Z",
        "version": 4,
        "filter": '{"person":true}',
    }
    assert calls[7]["max_retries"] == 7
    assert calls[8]["method"] == "GET"
    assert calls[8]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "limit": 5,
        "videoType": -1,
        "supportMultiChannelSharedService": 1,
    }
    assert calls[8]["max_retries"] == 8
    assert calls[9]["method"] == "POST"
    assert calls[9]["json_body"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "supportMultiChannelSharedService": 1,
        "videos": [
            {
                "seqId": 12345,
                "startTime": "2026-04-27 08:00:00",
                "stopTime": "2026-04-27 08:01:00",
                "storageVersion": 2,
            }
        ],
    }
    assert calls[9]["max_retries"] == 9
    assert calls[10]["method"] == "GET"
    assert calls[10]["params"] == {
        "deviceSerial": "CAM123",
        "channelNo": 2,
        "supportMultiChannelSharedService": 1,
    }
    assert calls[10]["max_retries"] == 10
    assert all(call["retry_401"] is True for call in calls)


def test_get_cloud_video_details_defaults_missing_storage_version(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_cloud_video_details(
        "CAM123",
        2,
        [
            {
                "seqId": 12345,
                "startTime": "2026-04-27 08:00:00",
                "stopTime": "2026-04-27 08:01:00",
            }
        ],
    )["meta"]["code"] == 200
    assert calls[0]["json_body"]["videos"] == [
        {
            "seqId": 12345,
            "startTime": "2026-04-27 08:00:00",
            "stopTime": "2026-04-27 08:01:00",
            "storageVersion": 2,
        }
    ]


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

    with pytest.raises(PyEzvizError, match="Could not search v2 records"):
        client.search_records_v2("CAM123", 2, "start", "stop")

    with pytest.raises(PyEzvizError, match="Could not search common records"):
        client.search_common_records("CAM123", 2, "start", "stop")

    with pytest.raises(PyEzvizError, match="Could not search intelligent records"):
        client.search_intelligent_records("CAM123", 2, "start", "stop")

    with pytest.raises(PyEzvizError, match="Could not get cloud videos"):
        client.get_cloud_videos("CAM123", 2)

    with pytest.raises(PyEzvizError, match="Could not get cloud video details"):
        client.get_cloud_video_details(
            "CAM123",
            2,
            [
                {
                    "seqId": 12345,
                    "startTime": "start",
                    "stopTime": "stop",
                    "storageVersion": 2,
                }
            ],
        )

    with pytest.raises(PyEzvizError, match="Could not get camera ticket info"):
        client.get_camera_ticket_info("CAM123", 2)


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
