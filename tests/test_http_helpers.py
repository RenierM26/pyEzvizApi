from __future__ import annotations

from collections.abc import Iterator
import datetime as dt
import errno
import io
import json
import math
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, BinaryIO, cast

import pytest
import requests

from pyezvizapi._local_stream import (
    HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep,
    _iter_local_stream_payloads,
    local_media_packet_source,
)
from pyezvizapi.api_endpoints import (
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P,
)
from pyezvizapi.client import (
    CLOUD_CLIP_VALIDATION_TIMEOUT_SECONDS,
    EzvizClient,
    _has_linked_h264_video,
    _has_linked_hevc_video,
    _LocalStreamPacketMetadataRecorder,
    _reserve_existing_clip_space,
)
from pyezvizapi.clip import ClipOptions, CloudClipSource, LocalSdkEcdhClipSource
from pyezvizapi.constants import (
    FEATURE_CODE,
    HIK_ENCRYPTION_HEADER,
    MAX_RETRIES,
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
from pyezvizapi.media import (
    CaptureLimits,
    MediaDecodeOptions,
    MediaMuxOptions,
)

DEFAULT_SAVE_TIMEOUT = 10.0
HCNETSDK_SAVE_DURATION = 3.0
HCNETSDK_CLEAN_IDR_PREROLL_SECONDS = 12.5
HCNETSDK_CLEAN_IDR_MAX_WINDOWS = 64
SAVE_CLIP_PAYLOAD = b"mpegts"
SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD = b"mpegps"
SAVE_IMAGE_PAYLOAD = b"jpeg-bytes"


def _client() -> EzvizClient:
    return EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"},
        timeout=1,
    )


def _fixture(name: str) -> dict[str, Any]:
    path = Path(__file__).with_name("fixtures") / name
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _response(
    *, status_code: int = 200, text: str = '{"meta": {"code": 200}}'
) -> requests.Response:
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


class _PacketStream:
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies

    def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
        for index, body in enumerate(self.bodies):
            if max_packets is not None and index >= max_packets:
                return
            yield SimpleNamespace(
                body=body,
                prefix=b"",
                channel=0,
                length=len(body),
                encrypted=False,
            )


class _DeadlinePacketStream(_PacketStream):
    supports_deadline_iter_packets = True

    def __init__(self, bodies: list[bytes]) -> None:
        super().__init__(bodies)
        self.iter_calls: list[dict[str, Any]] = []

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        monotonic: Any = None,
    ) -> Iterator[Any]:
        self.iter_calls.append(
            {
                "max_packets": max_packets,
                "duration_seconds": duration_seconds,
                "monotonic": monotonic,
            }
        )
        yield from super().iter_packets(max_packets=max_packets)


def test_parse_json_returns_decoded_payload() -> None:
    assert EzvizClient._parse_json(_response(text='{"resultCode": "0", "value": 1}')) == {
        "resultCode": "0",
        "value": 1,
    }


def test_local_stream_metadata_recorder_honors_env_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_PACKETS", "2")
    monkeypatch.setenv("PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_BYTES", "64")
    monkeypatch.setenv("PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_FRAMES", "3")
    stream = _PacketStream([b"packet-1", b"packet-2", b"packet-3"])
    recorder = _LocalStreamPacketMetadataRecorder(stream)

    assert len(list(recorder.iter_packets())) == 3
    recorder.finalize_packet_summary()

    summary = recorder.packet_summary["idmx_h264"]
    assert summary["capture_packet_limit"] == 2
    assert summary["capture_byte_limit"] == 64
    assert summary["capture_truncated"] is True
    assert summary["sample_limit"] == 3


def test_local_stream_metadata_recorder_forwards_deadline_capability() -> None:
    stream = _DeadlinePacketStream([b"packet"])
    recorder = _LocalStreamPacketMetadataRecorder(stream)
    monotonic = lambda: 1.0  # noqa: E731

    assert list(
        _iter_local_stream_payloads(
            recorder,
            max_packets=2,
            duration_seconds=3.0,
            monotonic=monotonic,
        )
    ) == [b"packet"]
    assert stream.iter_calls == [
        {
            "max_packets": 2,
            "duration_seconds": 3.0,
            "monotonic": monotonic,
        }
    ]


def test_local_stream_metadata_recorder_does_not_claim_startup_deadline() -> None:
    """Deadline forwarding alone does not imply a duration_from_start keyword."""
    recorder = _LocalStreamPacketMetadataRecorder(_DeadlinePacketStream([b"packet"]))
    source = local_media_packet_source(recorder)

    assert source.duration_from_start is False
    assert [
        packet.body for packet in source.iter_media_packets(limits=CaptureLimits(max_packets=1))
    ] == [b"packet"]


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

    def fake_v3(
        serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0
    ) -> dict[str, Any]:
        calls.append(("v3", channel))
        raise PyEzvizError("modern failed")

    def fake_legacy(
        serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0
    ) -> dict[str, Any]:
        calls.append(("legacy", channel))
        return {"meta": {"code": 200}, "legacy": True}

    monkeypatch.setattr(client, "set_switch_v3", fake_v3)
    monkeypatch.setattr(client, "set_switch_legacy", fake_legacy)

    assert client.set_switch("CAM123", 7, True, channel=4) == {
        "meta": {"code": 200},
        "legacy": True,
    }
    assert calls == [("v3", 4), ("legacy", 4)]

    def failing_legacy(
        serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0
    ) -> dict[str, Any]:
        raise PyEzvizError("legacy failed")

    monkeypatch.setattr(client, "set_switch_legacy", failing_legacy)

    with pytest.raises(PyEzvizError, match="modern failed"):
        client.set_switch("CAM123", 7, True)


def test_switch_status_updates_cached_camera_switch_state(monkeypatch) -> None:
    client = _client()
    client._cameras["CAM123"] = {"switches": {7: False}}

    def fake_set_switch(
        serial: str, switch_type: int, enable: bool | int, channel: int = 0, max_retries: int = 0
    ) -> dict[str, Any]:
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

    assert (
        client.set_camera_defence(
            "CAM123",
            1,
            channel_no=2,
            arm_type="Local",
            actor="A",
            max_retries=1,
        )
        is True
    )

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

    assert (
        client.audition_request("CAM123", 1, "play", "payload", max_retries=1)["meta"]["code"]
        == 200
    )
    assert (
        client.baby_control(
            "CAM123",
            1,
            2,
            "move",
            "START",
            5,
            "uuid-1",
            "pan",
            "HW1",
        )["meta"]["code"]
        == 200
    )

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
    assert (
        req.url
        == "https://apiieu.ezvizlife.com/v3/iot-feature/feature/CAM123/Video/1/Domain/Action"
    )
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

    assert (
        client.get_low_battery_keep_alive("cam123", "Battery", "0", "Power", "KeepAlive")["meta"][
            "code"
        ]
        == 200
    )
    assert (
        client.get_object_removal_status(
            "cam123", "Video", "1", "Object", "Removal", payload={"q": 1}
        )["meta"]["code"]
        == 200
    )
    assert (
        client.get_remote_control_path_list("cam123", "PTZ", "1", "Cruise", "PathList")["meta"][
            "code"
        ]
        == 200
    )
    assert (
        client.get_tracking_status("cam123", "Video", "1", "Track", "Status")["meta"]["code"] == 200
    )
    assert client.get_port_security("cam123")["meta"]["code"] == 200
    assert (
        client.get_device_feature_value("cam123", "Video", "Domain", "Prop", local_index=3)["meta"][
            "code"
        ]
        == 200
    )

    assert urls[0].endswith("/v3/iot-feature/feature/CAM123/Battery/0/Power/KeepAlive")
    assert urls[1].endswith("/v3/iot-feature/feature/CAM123/Video/1/Object/Removal")
    assert bodies[1] == '{"q":1}'
    assert urls[2].endswith("/v3/iot-feature/feature/CAM123/PTZ/1/Cruise/PathList")
    assert urls[3].endswith("/v3/iot-feature/feature/CAM123/Video/1/Track/Status")
    assert urls[4].endswith(
        "/v3/iot-feature/feature/CAM123/Video/1/NetworkSecurityProtection/PortSecurity"
    )
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
    assert (
        client.set_iot_action("CAM123", "PTZ", "1", "Move", "Start", {"speed": 3})["meta"]["code"]
        == 200
    )

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

    assert (
        client.set_intelligent_fill_light("CAM123", enabled=True, local_index="2")["meta"]["code"]
        == 200
    )
    assert client.set_intelligent_fill_light("CAM123", enabled=False)["meta"]["code"] == 200
    assert client.set_image_flip_iot("CAM123", enabled=True)["meta"]["code"] == 200
    assert (
        client.set_image_flip_iot("CAM123", payload='{"value":{"enabled":false}}')["meta"]["code"]
        == 200
    )

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
    assert (
        client.device_authenticate(
            "CAM123",
            need_check_code=True,
            check_code="ABCDEF",
            sender_type=2,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.device_authenticate(
            "CAM456",
            need_check_code=False,
            check_code=None,
            sender_type=1,
        )["meta"]["code"]
        == 200
    )

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

    assert (
        client.set_video_enc(
            "CAM123",
            enable=1,
            camera_verification_code="ABCDEF",
            max_retries=1,
        )
        is True
    )
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

    assert (
        client.set_video_enc(
            "CAM123",
            enable=2,
            old_password="old-pass",
            new_password="new-pass",
        )
        is True
    )
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
    assert (
        client.add_voice_info("CAM123", "hello", "https://voice.example/1", local_index="2")[
            "meta"
        ]["code"]
        == 200
    )
    assert client.set_voice_info("CAM123", 5, "hello2", local_index="2")["meta"]["code"] == 200
    assert (
        client.delete_voice_info(
            "CAM123",
            5,
            voice_url="https://voice.example/1",
            local_index="2",
        )["meta"]["code"]
        == 200
    )

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

    assert (
        client.add_shared_voice_info("CAM123", "hello", "url", "3", max_retries=1)["meta"]["code"]
        == 200
    )
    assert (
        client.set_shared_voice_info("CAM123", 7, "hello2", "3", max_retries=2)["meta"]["code"]
        == 200
    )
    assert (
        client.delete_shared_voice_info("CAM123", 7, "url", "3", max_retries=3)["meta"]["code"]
        == 200
    )

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
    assert (
        client.set_channel_whistle(
            "CAM123",
            [{"channel": 1, "status": 1, "duration": 10, "volume": 50}],
            max_retries=1,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.set_device_whistle("CAM123", status=1, duration=10, volume=50)["meta"]["code"] == 200
    )
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
    assert (
        client.set_device_chime_info("CAM123", 1, sound_type=2, duration=30)["meta"]["code"] == 200
    )
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

    assert (
        client.get_detector_setting_info(
            "A1S123",
            "DET456",
            "sensitivity",
            max_retries=1,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.set_detector_setting_info(
            "A1S123",
            "DET456",
            "sensitivity",
            3,
            max_retries=2,
        )["meta"]["code"]
        == 200
    )
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
    def __init__(
        self, payload: dict[str, Any] | None = None, *, json_error: Exception | None = None
    ) -> None:
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
    assert (
        client.get_motion_detect_sensitivity_dp1s("CAM123", 2, max_retries=2)["meta"]["code"] == 200
    )
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

    assert (
        client.manage_intelligent_app(
            "CAM123",
            "res-1",
            "app_human_detect",
            action="add",
            max_retries=1,
        )
        is True
    )
    assert (
        client.manage_intelligent_app(
            "CAM123",
            "res-1",
            "app_human_detect",
            action="REMOVE",
            max_retries=2,
        )
        is True
    )

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
    assert (
        client.set_intelligent_app_state(
            "CAM123",
            "app_car_detect",
            False,
            resource_id="res-explicit",
            max_retries=2,
        )
        is True
    )

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
    assert (
        client._resolve_osd_text(
            "CAM123",
            camera_data={"deviceInfos": {"name": "Device Info"}},
        )
        == "Device Info"
    )
    assert (
        client._resolve_osd_text(
            "CAM123",
            camera_data={"optionals": {"OSD": [{"name": "OSD Name"}]}},
        )
        == "OSD Name"
    )
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
    assert (
        client.set_camera_osd(
            "CAM123",
            enabled=True,
            camera_data={"deviceInfos": {"name": "Front Door"}},
        )
        is True
    )

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

    assert (
        client.set_floodlight_brightness("CAM123", luminance=75, channelno=2, max_retries=1) is True
    )
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
        client.set_floodlight_brightness("CAM123", luminance=101)

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

    assert (
        client.api_set_defence_schedule(
            "CAM123",
            '{"start":"08:00","stop":"17:00"}',
            enable=1,
            max_retries=1,
        )
        is True
    )
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

    assert (
        client.api_set_defence_mode(
            DefenseModeType.HOME_MODE, visual_alarm=1, sound_mode=2, max_retries=1
        )
        is True
    )
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
    assert (
        client.remote_unlock(
            "LOCK123",
            "user-1",
            7,
            resource_id="DoorLock",
            local_index=2,
            stream_token="stream-1",
            lock_type="fingerprint",
            use_terminal_bind=False,
        )
        is True
    )
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
        return _fixture("terminal_info_response.json")

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == (
        "aaaabbbbccccddddeeeeffff00001111fake-user-id-002",
        "Hassio",
    )
    assert captured["method"] == "GET"
    assert captured["path"].endswith("/v3/terminals")
    assert captured["params"] == {"limit": 20, "offset": 0}
    assert captured["retry_401"] is True


def test_terminal_helpers_prefer_hassio_terminal(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return _fixture("terminal_info_response.json")

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == (
        "aaaabbbbccccddddeeeeffff00001111fake-user-id-002",
        "Hassio",
    )
    assert client.get_latest_terminal_bind(terminal_name=None) == (
        "99998888777766665555444433332222fake-user-id-003",
        "newer phone",
    )


def test_terminal_helpers_ignore_latest_terminal_without_bind_fields(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        payload = _fixture("terminal_info_response.json")
        payload["terminals"] = [
            {
                "name": "Hassio",
                "sign": "valid-sign-",
                "userId": "valid-user",
                "lastModifytime": "2025-01-01T00:00:00Z",
            },
            {
                "name": "Hassio",
                "lastModifytime": "2025-01-02T00:00:00Z",
            },
        ]
        return payload

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == ("valid-sign-valid-user", "Hassio")


def test_terminal_helpers_ignore_empty_bind_fields(monkeypatch) -> None:
    client = _client()

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        payload = _fixture("terminal_info_response.json")
        payload["terminals"] = [
            {
                "name": "Hassio",
                "sign": " valid-sign- ",
                "userId": " valid-user ",
                "lastModifytime": "2025-01-01T00:00:00Z",
            },
            {
                "name": "Hassio",
                "sign": "",
                "userId": " ",
                "lastModifytime": "2025-01-02T00:00:00Z",
            },
        ]
        return payload

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.get_latest_terminal_bind() == ("valid-sign-valid-user", "Hassio")


def test_remote_unlock_uses_terminal_bind_when_available(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if path.endswith("/v3/terminals"):
            payload = _fixture("terminal_info_response.json")
            payload["terminals"] = [
                {
                    "name": "Hassio",
                    "sign": "terminal-sign-",
                    "userId": "terminal-user",
                    "lastModifytime": "2025-01-02T00:00:00Z",
                }
            ]
            return payload
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
            "userName": "Hassio",
        }
    }


def test_remote_unlock_can_use_latest_terminal_without_name_filter(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if path.endswith("/v3/terminals"):
            return _fixture("terminal_info_response.json")
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert (
        client.remote_unlock(
            "LOCK123",
            "legacy-user",
            2,
            terminal_filter_name=None,
        )
        is True
    )
    assert calls[1]["method"] == "PUT"
    assert calls[1]["json_body"] == {
        "unLockInfo": {
            "bindCode": "99998888777766665555444433332222fake-user-id-003",
            "lockNo": 2,
            "streamToken": "",
            "userName": "newer phone",
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
        captured.update(
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

    assert client.ptz_control_coordinates("CAM123", 0.25, 0.75) is True
    assert captured["method"] == "PUT"
    assert captured["endpoint"] == API_ENDPOINT_IOT_ACTION
    assert captured["serial"] == "CAM123"
    assert captured["resource_identifier"] == "Video_1"
    assert captured["local_index"] == "1"
    assert captured["domain_id"] == "PTZManualCtrl"
    assert captured["action_id"] == "CtrlPTZ3DPosition"
    assert captured["payload"] == {
        "positionCtrlType": "point",
        "positionPoint": {
            "x": 0.25,
            "y": 0.75,
        },
        "positionRect": {
            "height": 1.0,
            "width": 1.0,
            "x": 0.0,
            "y": 0.0,
        },
    }
    assert captured["max_retries"] == 0

    with pytest.raises(PyEzvizError, match="Invalid X coordinate"):
        client.ptz_control_coordinates("CAM123", 1.1, 0.5)

    with pytest.raises(PyEzvizError, match="Invalid X coordinate"):
        client.ptz_control_coordinates("CAM123", -0.1, 0.5)

    with pytest.raises(PyEzvizError, match="Invalid Y coordinate"):
        client.ptz_control_coordinates("CAM123", 0.5, 1.1)

    with pytest.raises(PyEzvizError, match="Invalid Y coordinate"):
        client.ptz_control_coordinates("CAM123", 0.5, -0.1)


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


def test_download_alarm_image_returns_plain_image_without_key_lookup(monkeypatch) -> None:
    client = _client()
    plain_payload = b"plain-jpeg-bytes"

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert method == "GET"
        assert url == "https://image.example.test/plain.jpg"
        assert kwargs["retry_401"] is False
        return _binary_response(plain_payload)

    def fail_get_cam_key(*args: Any, **kwargs: Any) -> str:
        raise AssertionError("plain images should not fetch the camera key")

    monkeypatch.setattr(client, "_http_request", fake_http_request)
    monkeypatch.setattr(client, "get_cam_key", fail_get_cam_key)

    assert client.download_alarm_image("https://image.example.test/plain.jpg") == plain_payload


def test_download_alarm_image_fetches_key_and_decrypts_encrypted_payload(monkeypatch) -> None:
    client = _client()
    encrypted_payload = b"x" * 300 + HIK_ENCRYPTION_HEADER + b"x" * 64
    decrypted_payload = b"decrypted-jpeg"
    calls: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        calls["http"] = {"method": method, "url": url, **kwargs}
        return _binary_response(encrypted_payload)

    def fake_get_cam_key(serial: str, **kwargs: Any) -> str:
        calls["key"] = {"serial": serial, **kwargs}
        return "ENC123"

    def fake_decrypt_image(image_data: bytes, password: str) -> bytes:
        calls["decrypt"] = {"image_data": image_data, "password": password}
        return decrypted_payload

    monkeypatch.setattr(client, "_http_request", fake_http_request)
    monkeypatch.setattr(client, "get_cam_key", fake_get_cam_key)
    monkeypatch.setattr("pyezvizapi.client.decrypt_image", fake_decrypt_image)

    assert (
        client.download_alarm_image(
            "https://image.example.test/encrypted.jpg",
            "CAM123",
            smscode=123456,
            max_retries=2,
        )
        == decrypted_payload
    )
    assert calls["http"]["retry_401"] is False
    assert calls["key"] == {
        "serial": "CAM123",
        "smscode": 123456,
        "max_retries": 2,
    }
    assert calls["decrypt"] == {
        "image_data": encrypted_payload,
        "password": "ENC123",
    }


def test_download_alarm_image_requires_serial_or_key_for_encrypted_payload(
    monkeypatch,
) -> None:
    client = _client()

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        return _binary_response(HIK_ENCRYPTION_HEADER + b"x" * 64)

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    with pytest.raises(PyEzvizError, match="Camera serial or encryption key"):
        client.download_alarm_image("https://image.example.test/encrypted.jpg")


def test_save_clip_uses_local_sdk_convenience(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ts"
    calls: list[dict[str, Any]] = []

    def fake_copy_local_sdk_stream_from_client(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> object:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        output.write(SAVE_CLIP_PAYLOAD)
        return object()

    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_sdk_stream_from_client",
        fake_copy_local_sdk_stream_from_client,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        duration_seconds=5.0,
        channel=2,
        decrypt_video=True,
        nalu_header_size=0,
        ffmpeg_path="/usr/bin/ffmpeg",
        smscode="123456",
    )

    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "output_format": "mpegts",
            "decrypt_video": True,
            "media_key": None,
            "nalu_header_size": 0,
            "channel": 2,
            "cas_serial": None,
            "register_p2p_session": True,
            "p2p_register_max_retries": MAX_RETRIES,
            "timeout": DEFAULT_SAVE_TIMEOUT,
            "max_packets": None,
            "duration_seconds": 5.0,
            "ffmpeg_path": "/usr/bin/ffmpeg",
            "smscode": "123456",
        }
    ]
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert result == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(SAVE_CLIP_PAYLOAD),
        "source": "local-sdk",
        "format": "mpegts",
        "duration_seconds": 5.0,
        "content_type": "video/mp2t",
    }


def test_save_clip_delegates_legacy_arguments_to_typed_options(monkeypatch) -> None:
    client = _client()
    captured: list[ClipOptions] = []

    def fake_save_clip_with_options(
        serial: str,
        output: str | Path | BinaryIO,
        options: ClipOptions,
    ) -> dict[str, Any]:
        assert serial == "CAM123"
        assert output == "front.ts"
        captured.append(options)
        return {"ok": True}

    monkeypatch.setattr(client, "save_clip_with_options", fake_save_clip_with_options)

    result = client.save_clip(
        "CAM123",
        "front.ts",
        source="cloud",
        duration_seconds=4.0,
        max_packets=8,
        channel=2,
        decrypt_video=True,
        media_key="MEDIAKEY",
        nalu_header_size=1,
        ffmpeg_path="/usr/bin/ffmpeg",
        timeout=5.0,
        smscode="654321",
        cloud_client_type=7,
        cloud_token_index=1,
        cloud_refresh_vtm=False,
    )

    assert result == {"ok": True}
    assert captured == [
        ClipOptions(
            source=CloudClipSource(
                client_type=7,
                token_index=1,
                refresh_vtm=False,
                timeout=5.0,
                smscode="654321",
            ),
            capture=CaptureLimits(max_packets=8, duration_seconds=4.0),
            decode=MediaDecodeOptions(
                decrypt_video=True,
                media_key="MEDIAKEY",
                nalu_header_size=1,
            ),
            mux=MediaMuxOptions(
                output_format="mpegts",
                ffmpeg_path="/usr/bin/ffmpeg",
            ),
            channel=2,
        )
    ]


def test_clip_options_use_ecdh_compatible_default_mux() -> None:
    options = ClipOptions(source=LocalSdkEcdhClipSource())

    assert options.resolved_mux().output_format == "mpegps"


def test_save_clip_with_options_rejects_unsupported_byte_limit() -> None:
    client = _client()
    options = ClipOptions(capture=CaptureLimits(max_bytes=1024))

    with pytest.raises(PyEzvizError, match=r"does not support CaptureLimits\.max_bytes"):
        client.save_clip_with_options("CAM123", io.BytesIO(), options)


def test_save_clip_with_options_rejects_source_incompatible_mux_options() -> None:
    client = _client()
    options = ClipOptions(
        source=CloudClipSource(),
        mux=MediaMuxOptions(h264_trim_to_clean_idr_window=True),
    )

    with pytest.raises(PyEzvizError, match="require HcNetSdkCommandPortClipSource"):
        client.save_clip_with_options("CAM123", io.BytesIO(), options)


@pytest.mark.parametrize(
    ("max_packets", "duration_seconds"),
    [(0, 10.0), (None, 0.0), (1, float("inf")), (cast(Any, float("nan")), None)],
)
def test_save_clip_preserves_legacy_nonpositive_capture_limits(
    monkeypatch,
    max_packets: int | None,
    duration_seconds: float | None,
) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_save_local_sdk_clip(
        serial: str,
        output: str | Path | BinaryIO,
        **kwargs: Any,
    ) -> dict[str, Any]:
        calls.append({"serial": serial, "output": output, **kwargs})
        return {"ok": True}

    monkeypatch.setattr(client, "_save_local_sdk_clip", fake_save_local_sdk_clip)

    result = client.save_clip(
        "CAM123",
        io.BytesIO(),
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    )

    assert result == {"ok": True}
    if max_packets is not None and math.isnan(max_packets):
        assert math.isnan(calls[0]["max_packets"])
    else:
        assert calls[0]["max_packets"] == max_packets
    assert calls[0]["duration_seconds"] == duration_seconds


def test_save_clip_accepts_arbitrary_size_integer_packet_limit(monkeypatch) -> None:
    """Legacy save_clip must not coerce integer bounds through float."""

    client = _client()
    huge_limit = 10**309
    calls: list[dict[str, Any]] = []

    def fake_save_local_sdk_clip(
        serial: str,
        output: str | Path | BinaryIO,
        **kwargs: Any,
    ) -> dict[str, Any]:
        calls.append({"serial": serial, "output": output, **kwargs})
        return {"ok": True}

    monkeypatch.setattr(client, "_save_local_sdk_clip", fake_save_local_sdk_clip)

    result = client.save_clip("CAM123", io.BytesIO(), max_packets=huge_limit)

    assert result == {"ok": True}
    assert calls[0]["max_packets"] == huge_limit


def test_save_clip_uses_local_sdk_ecdh_source(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ps"
    calls: list[dict[str, Any]] = []

    def fake_copy_local_sdk_ecdh_stream_from_client(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        output.write(SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_sdk_ecdh_stream_from_client",
        fake_copy_local_sdk_ecdh_stream_from_client,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="local-sdk-ecdh",
        output_format="mpegps",
        duration_seconds=5.0,
        max_packets=2,
        channel=2,
        cas_serial="CAMALT",
        register_p2p_session=False,
        p2p_register_max_retries=1,
        timeout=3.0,
        local_sdk_ecdh_receiver_port=10105,
        local_sdk_ecdh_send_init=True,
        local_sdk_ecdh_max_prefix_bytes=8192,
        local_sdk_ecdh_max_frames=8,
    )

    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "cas_serial": "CAMALT",
            "channel": 2,
            "receiver_port": 10105,
            "send_init": True,
            "register_p2p_session": False,
            "p2p_register_max_retries": 1,
            "timeout": 3.0,
            "max_prefix_bytes": 8192,
            "max_packets": 2,
            "max_frames": 8,
            "duration_seconds": 5.0,
            "output_format": "mpegps",
            "decrypt_video": False,
            "media_key": None,
            "ffmpeg_path": "ffmpeg",
            "nalu_header_size": 0,
            "smscode": None,
        }
    ]
    assert output_path.read_bytes() == SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD
    assert result == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD),
        "source": "local-sdk-ecdh",
        "format": "mpegps",
        "duration_seconds": 5.0,
        "content_type": "video/mpeg",
    }


def test_save_clip_local_sdk_ecdh_defaults_to_mpegps(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ps"
    calls: list[dict[str, Any]] = []

    def fake_copy_local_sdk_ecdh_stream_from_client(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        output.write(SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_sdk_ecdh_stream_from_client",
        fake_copy_local_sdk_ecdh_stream_from_client,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="local-sdk-ecdh",
    )

    assert calls[0]["client"] is client
    assert calls[0]["serial"] == "CAM123"
    assert output_path.read_bytes() == SAVE_LOCAL_SDK_ECDH_CLIP_PAYLOAD
    assert result["source"] == "local-sdk-ecdh"
    assert result["format"] == "mpegps"
    assert result["content_type"] == "video/mpeg"


def test_save_clip_local_sdk_ecdh_bounds_input_frames_by_max_packets(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_copy_local_sdk_ecdh_stream_from_client(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})

    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_sdk_ecdh_stream_from_client",
        fake_copy_local_sdk_ecdh_stream_from_client,
    )

    client.save_clip(
        "CAM123",
        tmp_path / "front.ps",
        source="local-sdk-ecdh",
        duration_seconds=None,
        max_packets=2,
    )

    assert calls[0]["max_packets"] == 2
    assert calls[0]["max_frames"] == 2


def test_save_clip_local_sdk_ecdh_supports_decrypted_mpegts(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "front.ts"
    calls: list[dict[str, Any]] = []

    def fake_copy(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_sdk_ecdh_stream_from_client",
        fake_copy,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="local-sdk-ecdh",
        output_format="mpegts",
        decrypt_video=True,
        media_key="media-secret",
        duration_seconds=5.0,
    )

    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert calls[0]["output_format"] == "mpegts"
    assert calls[0]["decrypt_video"] is True
    assert calls[0]["media_key"] == "media-secret"
    assert result["format"] == "mpegts"
    assert result["content_type"] == "video/mp2t"


def test_save_clip_uses_hcnetsdk_command_port_source(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ts"
    calls: list[dict[str, Any]] = []
    metadata_calls: list[Any] = []

    class FakeCommandPortStream:
        def __enter__(self) -> FakeCommandPortStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets == 1
            yield SimpleNamespace(
                channel=0,
                length=4,
                body=b"pkt1",
                prefix=b"pre",
            )

    def fake_open_hcnetsdk_command_port_stream(
        endpoint: Any,
        command_frames: tuple[bytes, ...],
        **kwargs: Any,
    ) -> FakeCommandPortStream:
        calls.append(
            {
                "endpoint": endpoint,
                "command_frames": command_frames,
                **kwargs,
            }
        )
        return FakeCommandPortStream()

    def fake_copy_local_stream_to_mpegts(
        stream: Any,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"stream": stream, **kwargs})
        list(stream.iter_packets(max_packets=1))
        output.write(b"mpegts")

    monkeypatch.setattr(
        "pyezvizapi.client.open_hcnetsdk_command_port_stream",
        fake_open_hcnetsdk_command_port_stream,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_stream_to_mpegts",
        fake_copy_local_stream_to_mpegts,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="hcnetsdk-command-port",
        host="192.0.2.10",
        command_port=8000,
        hcnetsdk_command_frames=(bytes.fromhex("00000010"),),
        hcnetsdk_read_response_after_each=(False,),
        hcnetsdk_command_metadata_callback=metadata_calls.append,
        hcnetsdk_h264_skip_initial_idr_windows=2,
        hcnetsdk_video_trim_to_clean_window=True,
        hcnetsdk_video_clean_window_preroll_seconds=(HCNETSDK_CLEAN_IDR_PREROLL_SECONDS),
        hcnetsdk_video_clean_window_max_windows=HCNETSDK_CLEAN_IDR_MAX_WINDOWS,
        duration_seconds=HCNETSDK_SAVE_DURATION,
        max_packets=4,
    )

    endpoint = calls[0]["endpoint"]
    assert endpoint.host == "192.0.2.10"
    assert endpoint.command_port == 8000
    assert calls[0]["command_frames"] == (bytes.fromhex("00000010"),)
    assert calls[0]["timeout"] == DEFAULT_SAVE_TIMEOUT
    assert calls[0]["read_response_after_each"] == (False,)
    assert calls[1]["ffmpeg_path"] == "ffmpeg"
    assert calls[1]["max_packets"] == 4
    assert calls[1]["duration_seconds"] == HCNETSDK_SAVE_DURATION
    assert calls[1]["h264_skip_initial_idr_windows"] == 2
    assert calls[1]["h264_trim_to_clean_idr_window"] is True
    assert calls[1]["h264_clean_idr_preroll_seconds"] == HCNETSDK_CLEAN_IDR_PREROLL_SECONDS
    assert calls[1]["h264_clean_idr_max_windows"] == HCNETSDK_CLEAN_IDR_MAX_WINDOWS
    assert metadata_calls == [calls[1]["stream"]]
    assert metadata_calls[0].packet_summary["packet_count"] == 1
    assert metadata_calls[0].packet_summary["first_packet_elapsed_seconds"] == 0.0
    assert metadata_calls[0].packet_summary["last_packet_elapsed_seconds"] >= 0.0
    assert metadata_calls[0].packet_summary["samples"][0]["length"] == 4
    assert metadata_calls[0].packet_summary["samples"][0]["elapsed_seconds"] >= 0.0
    assert metadata_calls[0].packet_summary["idmx_h264"]["looks_like_idmx"] is False
    assert metadata_calls[0].packet_summary["idmx_h264"]["frame_count"] == 0
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert result == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 1,
        "output": str(output_path),
        "bytes": len(SAVE_CLIP_PAYLOAD),
        "source": "hcnetsdk-command-port",
        "format": "mpegts",
        "duration_seconds": HCNETSDK_SAVE_DURATION,
        "content_type": "video/mp2t",
        "command_port": 8000,
    }


def test_save_clip_forwards_h264_options_to_decrypted_hcnetsdk_command_port(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "front-decrypted.ts"
    calls: list[dict[str, Any]] = []

    class FakeCommandPortStream:
        def __enter__(self) -> FakeCommandPortStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_hcnetsdk_command_port_stream(
        endpoint: Any,
        command_frames: tuple[bytes, ...],
        **kwargs: Any,
    ) -> FakeCommandPortStream:
        calls.append(
            {
                "endpoint": endpoint,
                "command_frames": command_frames,
                **kwargs,
            }
        )
        return FakeCommandPortStream()

    def fake_copy_local_stream_to_decrypted_mpegts(
        stream: Any,
        output: BinaryIO,
        media_key: str | bytes,
        **kwargs: Any,
    ) -> None:
        calls.append({"stream": stream, "media_key": media_key, **kwargs})
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.client.open_hcnetsdk_command_port_stream",
        fake_open_hcnetsdk_command_port_stream,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_stream_to_decrypted_mpegts",
        fake_copy_local_stream_to_decrypted_mpegts,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="hcnetsdk-command-port",
        host="192.0.2.10",
        command_port=8000,
        hcnetsdk_command_frames=(bytes.fromhex("00000010"),),
        decrypt_video=True,
        media_key="MEDIAKEY",
        hcnetsdk_h264_skip_initial_idr_windows=1,
        hcnetsdk_h264_trim_to_clean_idr_window=True,
        hcnetsdk_h264_clean_idr_max_windows=HCNETSDK_CLEAN_IDR_MAX_WINDOWS,
        nalu_header_size=0,
        duration_seconds=HCNETSDK_SAVE_DURATION,
        max_packets=4,
    )

    assert calls[1]["media_key"] == "MEDIAKEY"
    assert calls[1]["ffmpeg_path"] == "ffmpeg"
    assert calls[1]["nalu_header_size"] == 0
    assert calls[1]["max_packets"] == 4
    assert calls[1]["duration_seconds"] == HCNETSDK_SAVE_DURATION
    assert calls[1]["h264_skip_initial_idr_windows"] == 1
    assert calls[1]["h264_trim_to_clean_idr_window"] is True
    assert calls[1]["h264_clean_idr_max_windows"] == HCNETSDK_CLEAN_IDR_MAX_WINDOWS
    assert result.get("source") == "hcnetsdk-command-port"
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


@pytest.mark.parametrize(
    "unsafe_bounds",
    [
        {"duration_seconds": None, "max_packets": None},
        {"duration_seconds": 0.0, "max_packets": None},
        {"duration_seconds": -1.0, "max_packets": None},
        {"duration_seconds": float("nan"), "max_packets": None},
        {"duration_seconds": float("inf"), "max_packets": None},
        {"duration_seconds": 10**309, "max_packets": None},
        {"duration_seconds": None, "max_packets": 0},
        {"duration_seconds": None, "max_packets": -1},
        {"duration_seconds": None, "max_packets": float("nan")},
        {"duration_seconds": None, "max_packets": float("inf")},
        {"duration_seconds": float("nan"), "max_packets": 1},
        {"duration_seconds": 10**309, "max_packets": 1},
    ],
)
def test_save_clip_rejects_unsafe_hcnetsdk_decrypt_bound_before_endpoint_lookup(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_bounds: dict[str, Any],
) -> None:
    client = _client()

    def fail_endpoint_lookup(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid decrypt bounds must fail before endpoint lookup")

    monkeypatch.setattr(client, "_hcnetsdk_command_port_endpoint", fail_endpoint_lookup)

    with pytest.raises(
        PyEzvizError,
        match="encrypted capture requires a positive finite",
    ):
        client.save_clip(
            "CAM123",
            io.BytesIO(),
            source="hcnetsdk-command-port",
            host="192.0.2.10",
            hcnetsdk_command_frames=(bytes.fromhex("00000010"),),
            decrypt_video=True,
            media_key="MEDIAKEY",
            **unsafe_bounds,
        )


@pytest.mark.parametrize(
    ("duration_seconds", "startup_options"),
    [
        (
            sys.float_info.max,
            {
                "hcnetsdk_h264_trim_to_clean_idr_window": True,
                "hcnetsdk_h264_clean_idr_preroll_seconds": sys.float_info.max,
            },
        ),
        (
            sys.float_info.max,
            {
                "hcnetsdk_h264_wait_for_clean_idr_window": True,
                "hcnetsdk_h264_clean_idr_wait_seconds": sys.float_info.max,
            },
        ),
        (
            10**309,
            {
                "hcnetsdk_h264_trim_to_clean_idr_window": True,
                "hcnetsdk_h264_clean_idr_preroll_seconds": 1.0,
            },
        ),
    ],
)
def test_save_clip_rejects_overflowing_hcnetsdk_duration_before_endpoint_lookup(
    monkeypatch: pytest.MonkeyPatch,
    duration_seconds: float,
    startup_options: dict[str, Any],
) -> None:
    """Derived startup budgets must be finite before command-port I/O begins."""

    client = _client()

    def fail_endpoint_lookup(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("overflowing duration must fail before endpoint lookup")

    monkeypatch.setattr(client, "_hcnetsdk_command_port_endpoint", fail_endpoint_lookup)

    with pytest.raises(PyEzvizError, match="duration must be finite"):
        client.save_clip(
            "CAM123",
            io.BytesIO(),
            source="hcnetsdk-command-port",
            host="192.0.2.10",
            hcnetsdk_command_frames=(bytes.fromhex("00000010"),),
            decrypt_video=True,
            media_key="MEDIAKEY",
            duration_seconds=duration_seconds,
            **startup_options,
        )


def test_save_clip_uses_hcnetsdk_multi_socket_command_plan(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ts"
    calls: list[dict[str, Any]] = []
    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep((bytes.fromhex("00000010"),)),
            HcNetSdkCommandPortSocketStep(
                (bytes.fromhex("00000011"),),
                media_socket=True,
                read_response_after_each=False,
            ),
        )
    )

    class FakeCommandPortStream:
        def __enter__(self) -> FakeCommandPortStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_open_hcnetsdk_command_port_multi_socket_stream(
        endpoint: Any,
        command_plan: HcNetSdkCommandPortMultiSocketPlan,
        **kwargs: Any,
    ) -> FakeCommandPortStream:
        calls.append(
            {
                "endpoint": endpoint,
                "command_plan": command_plan,
                **kwargs,
            }
        )
        return FakeCommandPortStream()

    def fake_copy_local_stream_to_mpegts(
        stream: FakeCommandPortStream,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"stream": stream, **kwargs})
        output.write(b"mpegts")

    monkeypatch.setattr(
        "pyezvizapi.client.open_hcnetsdk_command_port_multi_socket_stream",
        fake_open_hcnetsdk_command_port_multi_socket_stream,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.copy_local_stream_to_mpegts",
        fake_copy_local_stream_to_mpegts,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="hcnetsdk-command-port",
        host="192.0.2.10",
        hcnetsdk_command_plan=plan,
        duration_seconds=HCNETSDK_SAVE_DURATION,
    )

    assert calls[0]["endpoint"].host == "192.0.2.10"
    assert calls[0]["command_plan"] is plan
    assert calls[0]["timeout"] == DEFAULT_SAVE_TIMEOUT
    assert calls[1]["duration_seconds"] == HCNETSDK_SAVE_DURATION
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert result.get("source") == "hcnetsdk-command-port"
    assert result.get("command_port") == 8000


def test_save_clip_uses_cloud_source(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "www" / "front.ts"
    existing_clip = b"existing-clip"
    existing_mode = 0o640
    output_path.parent.mkdir(parents=True)
    output_path.write_bytes(existing_clip)
    output_path.chmod(existing_mode)
    linked_path = tmp_path / "front-linked.ts"
    linked_path.hardlink_to(output_path)
    existing_inode = output_path.stat().st_ino
    calls: list[dict[str, Any]] = []

    def fake_copy_cloud_stream_to_mpegts(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        fake_copy_cloud_stream_to_mpegts,
    )
    validation_calls: list[tuple[Path, str]] = []

    def validate(path: Path, *, ffmpeg_path: str) -> None:
        assert path != output_path
        assert path.parent.parent == output_path.parent
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert path.read_bytes() == SAVE_CLIP_PAYLOAD
        assert output_path.read_bytes() == existing_clip
        validation_calls.append((path, ffmpeg_path))

    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        validate,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        duration_seconds=HCNETSDK_SAVE_DURATION,
        max_packets=4,
        channel=2,
        ffmpeg_path="/usr/bin/ffmpeg",
        decrypt_video=True,
        media_key="MEDIAKEY",
        nalu_header_size=1,
        timeout=5.0,
        smscode="654321",
        cloud_client_type=7,
        cloud_token_index=1,
        cloud_refresh_vtm=False,
    )

    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "channel": 2,
            "client_type": 7,
            "token_index": 1,
            "refresh_vtm": False,
            "timeout": 5.0,
            "max_packets": 4,
            "duration_seconds": HCNETSDK_SAVE_DURATION,
            "decrypt_video": True,
            "media_key": "MEDIAKEY",
            "nalu_header_size": 1,
            "smscode": "654321",
            "ffmpeg_path": "/usr/bin/ffmpeg",
        }
    ]
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert linked_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert output_path.stat().st_ino == existing_inode
    assert linked_path.stat().st_ino == existing_inode
    assert stat.S_IMODE(output_path.stat().st_mode) == existing_mode
    assert len(validation_calls) == 1
    assert validation_calls[0][1] == "/usr/bin/ffmpeg"
    assert not validation_calls[0][0].exists()
    assert result == {
        "ok": True,
        "kind": "clip",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(SAVE_CLIP_PAYLOAD),
        "source": "cloud",
        "format": "mpegts",
        "duration_seconds": HCNETSDK_SAVE_DURATION,
        "content_type": "video/mp2t",
        "cloud_client_type": 7,
        "cloud_token_index": 1,
        "cloud_refresh_vtm": False,
    }


@pytest.mark.parametrize("target_exists", [True, False])
def test_save_cloud_clip_preserves_relative_symlink_destination(
    monkeypatch,
    tmp_path,
    *,
    target_exists: bool,
) -> None:
    client = _client()
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    target_path = target_dir / "front.ts"
    if target_exists:
        target_path.write_bytes(b"existing-clip")
        expected_mode = 0o640
        target_path.chmod(expected_mode)
    else:
        reference_path = target_dir / "normal-create"
        reference_path.write_bytes(b"")
        expected_mode = stat.S_IMODE(reference_path.stat().st_mode)

    link_dir = tmp_path / "links"
    link_dir.mkdir()
    relative_target = Path("../target/front.ts")
    output_path = link_dir / "front.ts"
    output_path.symlink_to(relative_target)
    validation_paths: list[Path] = []

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(SAVE_CLIP_PAYLOAD)

    def validate(path: Path, *, ffmpeg_path: str) -> None:
        assert ffmpeg_path == "ffmpeg"
        if target_exists:
            assert path.parent.parent == target_dir
        else:
            assert path.parent.parent == target_dir
        assert output_path.is_symlink()
        assert output_path.readlink() == relative_target
        validation_paths.append(path)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        validate,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert output_path.is_symlink()
    assert output_path.readlink() == relative_target
    assert target_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert stat.S_IMODE(target_path.stat().st_mode) == expected_mode
    assert result["output"] == str(output_path)
    assert result["bytes"] == len(SAVE_CLIP_PAYLOAD)
    assert len(validation_paths) == 1
    assert not validation_paths[0].exists()


@pytest.mark.parametrize("binary_output", [False, True])
def test_save_decrypted_cloud_mpegps_without_ffmpeg(
    monkeypatch,
    tmp_path,
    *,
    binary_output: bool,
) -> None:
    client = _client()
    video_payload = (
        b"\x00\x00\x01\x67\x42\xc0\x0a\xda\x7b\x01\x10"
        b"\x00\x00\x03\x00\x10\x00\x00\x03\x00\x28\xf1\x22\x6a"
        b"\x00\x00\x01\x68\xce\x0f\xc8"
        b"\x00\x00\x01\x65\x88\x84\x3a\x26\x28\x00\x09\x02\xe0"
    )
    pes_payload = b"\x80\x00\x00" + video_payload
    capture = (
        b"\x00\x00\x01\xe0"
        + len(pes_payload).to_bytes(2, "big")
        + pes_payload
    )

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(capture)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegps", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("MPEG-PS validation must not invoke FFmpeg"),
    )
    output: Path | io.BytesIO = io.BytesIO() if binary_output else tmp_path / "clip.ps"

    result = client.save_clip(
        "CAM123",
        output,
        source="cloud",
        output_format="mpegps",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    saved = output.getvalue() if isinstance(output, io.BytesIO) else output.read_bytes()
    assert saved == capture
    assert result["bytes"] == len(capture)


def test_save_decrypted_cloud_mpegps_rejects_missing_video(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "clip.ps"
    existing_clip = b"existing"
    output_path.write_bytes(existing_clip)

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(b"\x00\x00\x01\xba-no-video")

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegps", fake_copy)

    with pytest.raises(PyEzvizError, match="did not include clear video payload"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            output_format="mpegps",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == existing_clip


def test_save_decrypted_cloud_mpegps_rejects_invalid_slice_body(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ps"
    video_payload = b"\x00\x00\x01\x65\xff"
    pes_payload = b"\x80\x00\x00" + video_payload
    capture = (
        b"\x00\x00\x01\xe0"
        + len(pes_payload).to_bytes(2, "big")
        + pes_payload
    )

    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegps",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            capture
        ),
    )

    with pytest.raises(PyEzvizError, match="did not include clear video payload"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            output_format="mpegps",
            decrypt_video=True,
            media_key="wrong-key",
        )

    assert not output_path.exists()


def test_h264_validation_rejects_truncated_linked_structures() -> None:
    truncated = [
        (b"\x67\x64", b"\x64\x00\x01\x80"),
        (b"\x68\xc0", b"\xc0"),
        (b"\x65\xe0", b"\xe0\x00"),
    ]

    assert not _has_linked_h264_video(truncated)


def test_h264_validation_rejects_slice_before_mandatory_header_is_complete() -> None:
    nals = [
        (
            b"\x67\x42",
            b"\x42\xc0\x0a\xda\x7b\x01\x10\x00\x00\x03\x00\x10"
            b"\x00\x00\x03\x00\x28\xf1\x22\x6a",
        ),
        (b"\x68\xce", b"\xce\x0f\xc8"),
        (b"\x65\x11", b"\x11\x81"),
    ]

    assert not _has_linked_h264_video(nals)


def test_h264_validation_rejects_truncated_vui() -> None:
    sps_bits = (
        _unsigned_exp_golomb_bits(0) * 5
        + "0"
        + _unsigned_exp_golomb_bits(0) * 2
        + "1101"
    )
    nals = [
        (b"\x67\x42", b"\x42\x00\x0a" + _rbsp_bytes(sps_bits)),
        (b"\x68\xce", b"\xce\x0f\xc8"),
        (
            b"\x65\x88",
            b"\x88\x84\x3a\x26\x28\x00\x09\x02\xe0",
        ),
    ]

    assert not _has_linked_h264_video(nals)


def _unsigned_exp_golomb_bits(value: int) -> str:
    encoded = f"{value + 1:b}"
    return "0" * (len(encoded) - 1) + encoded


def _signed_exp_golomb_bits(value: int) -> str:
    code_num = -2 * value if value <= 0 else 2 * value - 1
    return _unsigned_exp_golomb_bits(code_num)


def _rbsp_bytes(bits: str) -> bytes:
    padded = (bits + "1").ljust((len(bits) + 8) // 8 * 8, "0")
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def _hevc_profile_tier_level_bits(
    sub_layer_flags: tuple[tuple[bool, bool], ...],
) -> str:
    bits = "0" * 96
    bits += "".join(
        ("1" if profile else "0") + ("1" if level else "0")
        for profile, level in sub_layer_flags
    )
    if sub_layer_flags:
        bits += "00" * (8 - len(sub_layer_flags))
    for profile, level in sub_layer_flags:
        if profile:
            bits += "0" * 88
        if level:
            bits += "0" * 8
    return bits


def _valid_hevc_validation_nals(  # noqa: PLR0913
    *,
    sps_vps_id: int = 0,
    pps_sps_id: int = 0,
    slice_pps_id: int = 0,
    slice_type: int = 2,
    output_flag_present: bool = False,
    complete_vps: bool = True,
    complete_sps: bool = True,
    complete_pps: bool = True,
    sps_extension_bits: str | None = None,
    pps_extension_bits: str | None = None,
    valid_inline_slice_rps: bool = True,
    slice_chroma_qp_offsets_present: bool = False,
    include_slice_chroma_qp_offsets: bool = True,
    sub_layer_flags: tuple[tuple[bool, bool], ...] = (),
) -> list[tuple[bytes, bytes]]:
    max_sub_layers_minus1 = len(sub_layer_flags)
    vps_bits = (
        "0000"  # vps_video_parameter_set_id
        "11"  # base-layer flags
        "000000"  # vps_max_layers_minus1
        "000"  # vps_max_sub_layers_minus1
        "1"
        + "1" * 16
        + _hevc_profile_tier_level_bits(())
        + "0"  # vps_sub_layer_ordering_info_present_flag
        + _unsigned_exp_golomb_bits(0) * 3
        + "000000"
        + _unsigned_exp_golomb_bits(0)
        + ("00" if complete_vps else "")
    )
    sps_bits = (
        f"{sps_vps_id:04b}"
        f"{max_sub_layers_minus1:03b}"
        "1"
        + _hevc_profile_tier_level_bits(sub_layer_flags)
        + _unsigned_exp_golomb_bits(0)
        + _unsigned_exp_golomb_bits(1)
        + _unsigned_exp_golomb_bits(64)
        + _unsigned_exp_golomb_bits(36)
        + "0"
        + _unsigned_exp_golomb_bits(0) * 2
        + _unsigned_exp_golomb_bits(4)
        + (
            "0"  # sps_sub_layer_ordering_info_present_flag
            + _unsigned_exp_golomb_bits(0) * 3
            + _unsigned_exp_golomb_bits(0) * 6
            + "0000"  # scaling-list, AMP, SAO, and PCM flags
            + _unsigned_exp_golomb_bits(0)  # num_short_term_ref_pic_sets
            + "0000"  # long-term, temporal-MVP, smoothing, and VUI
            + (
                "0"
                if sps_extension_bits is None
                else "1" + sps_extension_bits
            )
            if complete_sps
            else ""
        )
    )
    pps_bits = (
        _unsigned_exp_golomb_bits(0)
        + _unsigned_exp_golomb_bits(pps_sps_id)
        + "0"
        + ("1" if output_flag_present else "0")
        + "00000"
        + _unsigned_exp_golomb_bits(0) * 2
        + _signed_exp_golomb_bits(0)
        + "000"
        + _signed_exp_golomb_bits(0) * 2
        + ("1" if slice_chroma_qp_offsets_present else "0")
        + "00000"
        + (
            "0000"  # loop filter, deblocking, scaling-list, list-modification
            + _unsigned_exp_golomb_bits(0)  # log2_parallel_merge_level_minus2
            + "0"  # slice-header extension flag
            + (
                "0"
                if pps_extension_bits is None
                else "1" + pps_extension_bits
            )
            if complete_pps
            else ""
        )
    )
    slice_bits = (
        "1"
        + _unsigned_exp_golomb_bits(slice_pps_id)
        + _unsigned_exp_golomb_bits(slice_type)
        + ("0" if output_flag_present else "")
        + "0" * 8  # slice_pic_order_cnt_lsb
        + (
            "0" + _unsigned_exp_golomb_bits(0) * 2
            if valid_inline_slice_rps
            else "1"
        )
        + _signed_exp_golomb_bits(0)  # slice_qp_delta
        + (
            _signed_exp_golomb_bits(0) * 2
            if slice_chroma_qp_offsets_present and include_slice_chroma_qp_offsets
            else ""
        )
        + "0"  # at least one slice-data bit before rbsp_stop_one_bit
    )
    return [
        (b"\x40\x01", b"\x01" + _rbsp_bytes(vps_bits)),
        (b"\x42\x01", b"\x01" + _rbsp_bytes(sps_bits)),
        (b"\x44\x01", b"\x01" + _rbsp_bytes(pps_bits)),
        (b"\x02\x01", b"\x01" + _rbsp_bytes(slice_bits)),
    ]


def test_hevc_validation_links_parameter_sets_to_slice() -> None:
    nals = _valid_hevc_validation_nals()

    assert _has_linked_hevc_video(nals)
    assert not _has_linked_hevc_video(_valid_hevc_validation_nals(sps_vps_id=1))
    assert not _has_linked_hevc_video(_valid_hevc_validation_nals(pps_sps_id=1))
    assert not _has_linked_hevc_video(_valid_hevc_validation_nals(slice_pps_id=1))


def test_hevc_validation_rejects_truncated_linked_structures() -> None:
    truncated = [
        (b"\x40\x01", b"\x01\x00\x00\xff\xff"),
        (b"\x42\x01", b"\x01" + b"\x00" * 13),
        (b"\x44\x01", b"\x01\xc0"),
        (b"\x02\x01", b"\x01\xc0"),
    ]

    assert not _has_linked_hevc_video(truncated)
    assert not _has_linked_hevc_video(_valid_hevc_validation_nals(complete_sps=False))
    assert not _has_linked_hevc_video(_valid_hevc_validation_nals(complete_pps=False))
    assert not _has_linked_hevc_video([(b"\x02\x01", b"\x01\x80")])
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(complete_vps=False)
    )


def test_hevc_validation_parses_slice_type_before_output_flag() -> None:
    assert _has_linked_hevc_video(
        _valid_hevc_validation_nals(output_flag_present=True)
    )
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(
            output_flag_present=True,
            slice_type=3,
        )
    )


def test_hevc_validation_parses_interleaved_sub_layer_flags() -> None:
    nals = _valid_hevc_validation_nals(
        sub_layer_flags=((False, True), (True, False))
    )

    assert _has_linked_hevc_video(nals)


def test_hevc_validation_rejects_truncated_sps_range_extension() -> None:
    assert _has_linked_hevc_video(
        _valid_hevc_validation_nals(sps_extension_bits="10000000" + "0" * 9)
    )
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(sps_extension_bits="10000000")
    )


def test_hevc_validation_rejects_truncated_pps_range_extension() -> None:
    assert _has_linked_hevc_video(
        _valid_hevc_validation_nals(pps_extension_bits="10000000" + "0011")
    )
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(pps_extension_bits="10000000")
    )


def test_hevc_validation_rejects_invalid_slice_reference_picture_flag() -> None:
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(valid_inline_slice_rps=False)
    )


def test_hevc_validation_requires_declared_slice_chroma_qp_offsets() -> None:
    assert _has_linked_hevc_video(
        _valid_hevc_validation_nals(slice_chroma_qp_offsets_present=True)
    )
    assert not _has_linked_hevc_video(
        _valid_hevc_validation_nals(
            slice_chroma_qp_offsets_present=True,
            include_slice_chroma_qp_offsets=False,
        )
    )


def test_h264_validation_rejects_partition_b_and_c_without_partition_a() -> None:
    nals = [
        (
            b"\x67\x42",
            b"\x42\xc0\x0a\xda\x7b\x01\x10\x00\x00\x03\x00\x10"
            b"\x00\x00\x03\x00\x28\xf1\x22\x6a",
        ),
        (b"\x68\xce", b"\xce\x0f\xc8"),
        (b"\x63\x88", b"\x88\x84\x3a\x26\x28\x00\x09\x02\xe0"),
        (b"\x64\x88", b"\x88\x84\x3a\x26\x28\x00\x09\x02\xe0"),
    ]

    assert not _has_linked_h264_video(nals)


def test_h264_validation_rejects_truncated_pps_extension() -> None:
    sps = (
        b"\x67\x42",
        b"\x42\xc0\x0a\xda\x7b\x01\x10\x00\x00\x03\x00\x10"
        b"\x00\x00\x03\x00\x28\xf1\x22\x6a",
    )
    slice_nal = (b"\x65\x88", b"\x88\x84\x3a\x26\x28\x00\x09\x02\xe0")
    base_pps_bits = (
        _unsigned_exp_golomb_bits(0) * 2
        + "00"
        + _unsigned_exp_golomb_bits(0) * 3
        + "000"
        + _signed_exp_golomb_bits(0) * 3
        + "000"
    )

    assert _has_linked_h264_video(
        [sps, (b"\x68\x00", _rbsp_bytes(base_pps_bits)), slice_nal]
    )
    assert not _has_linked_h264_video(
        [sps, (b"\x68\x00", _rbsp_bytes(base_pps_bits + "1")), slice_nal]
    )


def test_save_decrypted_cloud_clip_rejects_fifo_target(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    os.mkfifo(output_path)
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda *_args, **_kwargs: pytest.fail("non-regular target must fail first"),
    )

    with pytest.raises(PyEzvizError, match="target must be a regular file"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert stat.S_ISFIFO(output_path.stat().st_mode)


def test_save_decrypted_cloud_clip_supports_write_only_existing_target(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"existing")
    output_path.chmod(0o200)
    original_inode = output_path.stat().st_ino
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    output_path.chmod(0o600)
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert output_path.stat().st_ino == original_inode


def test_save_decrypted_cloud_clip_atomically_replaces_unreadable_acl_target(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"existing")
    output_path.chmod(0o220)
    original_inode = output_path.stat().st_ino
    original_open = os.open
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    def deny_target_read(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path) == output_path and flags & os.O_ACCMODE == os.O_RDONLY:
            raise PermissionError(errno.EACCES, "ACL denies content reads")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("pyezvizapi.client.os.open", deny_target_read)
    monkeypatch.setattr(
        "pyezvizapi.client.os.fchmod",
        lambda *_args: (_ for _ in ()).throw(
            PermissionError(errno.EPERM, "writer does not own target")
        ),
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    output_path.chmod(0o600)
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD
    assert output_path.stat().st_ino != original_inode


def test_save_cloud_clip_preserves_existing_target_when_reservation_fails(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    existing_clip = b"existing-clip"
    output_path.write_bytes(existing_clip)
    original_inode = output_path.stat().st_ino
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.client._reserve_existing_clip_space",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.ENOSPC, "filesystem full")
        ),
    )

    with pytest.raises(OSError, match="filesystem full"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == existing_clip
    assert output_path.stat().st_ino == original_inode


def test_save_cloud_clip_restores_existing_target_when_publication_fails(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    existing_clip = b"existing-clip"
    output_path.write_bytes(existing_clip)
    original_inode = output_path.stat().st_ino
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    real_fsync = os.fsync
    fsync_calls = 0

    def fail_first_fsync(file_descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError(errno.EIO, "simulated publication failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr("pyezvizapi.client.os.fsync", fail_first_fsync)

    with pytest.raises(OSError, match="simulated publication failure"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert fsync_calls == 2
    assert output_path.read_bytes() == existing_clip
    assert output_path.stat().st_ino == original_inode


def test_existing_clip_reservation_has_portable_filesystem_fallback(
    monkeypatch,
    tmp_path,
) -> None:
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"existing")
    descriptor = os.open(output_path, os.O_WRONLY)
    monkeypatch.delattr("pyezvizapi.client.os.fstatvfs")
    monkeypatch.setattr(
        "pyezvizapi.client.shutil.disk_usage",
        lambda _path: SimpleNamespace(free=1024),
    )
    try:
        _reserve_existing_clip_space(
            descriptor,
            required_size=16,
            original_size=8,
            original_allocated_blocks=None,
            filesystem_path=tmp_path,
        )
    finally:
        os.close(descriptor)


def test_save_cloud_clip_falls_back_when_parent_cannot_stage(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"existing")
    staging_parents: list[Path | None] = []
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )

    def temporary_directory(*_args: Any, **kwargs: Any) -> TemporaryDirectory[str]:
        selected_parent = kwargs.get("dir")
        staging_parents.append(selected_parent)
        if selected_parent == tmp_path:
            raise PermissionError(errno.EACCES, "parent is not writable")
        return TemporaryDirectory(*_args, **kwargs)

    def validate(path: Path, *, ffmpeg_path: str) -> None:
        assert ffmpeg_path == "ffmpeg"
        assert path.parent.parent != tmp_path

    monkeypatch.setattr(
        "pyezvizapi.client.tempfile.TemporaryDirectory",
        temporary_directory,
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        validate,
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert staging_parents == [tmp_path, None]
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


def test_save_cloud_clip_supports_long_destination_name(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / ("x" * 240 + ".ts")
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


def test_save_cloud_clip_rejects_concurrent_target_replacement(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"original")
    replacement = tmp_path / "replacement.ts"
    replacement_payload = b"rotated-by-another-process"

    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )

    def rotate_target(*_args: Any, **_kwargs: Any) -> None:
        replacement.write_bytes(replacement_payload)
        os.replace(replacement, output_path)

    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        rotate_target,
    )

    with pytest.raises(PyEzvizError, match="target changed during capture"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == replacement_payload


def test_save_cloud_clip_rejects_fifo_replacement_without_blocking(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    output_path.write_bytes(b"original")
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )

    def replace_target_with_fifo(*_args: Any, **_kwargs: Any) -> None:
        output_path.unlink()
        os.mkfifo(output_path)

    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        replace_target_with_fifo,
    )

    with pytest.raises(PyEzvizError, match="target changed during capture"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert stat.S_ISFIFO(output_path.stat().st_mode)


def test_save_cloud_clip_verifies_new_target_after_hard_link(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    replacement_payload = b"concurrent replacement"
    real_link = os.link
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    def replace_after_link(source: Path, target: Path) -> None:
        real_link(source, target)
        target.unlink()
        target.write_bytes(replacement_payload)

    monkeypatch.setattr("pyezvizapi.client.os.link", replace_after_link)

    with pytest.raises(PyEzvizError, match="changed during capture"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == replacement_payload


def test_save_cloud_clip_falls_back_when_hard_links_are_unsupported(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.os.link",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.EOPNOTSUPP, "hard links unsupported")
        ),
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


def test_save_cloud_clip_falls_back_for_windows_invalid_function(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    hard_link_error = OSError(errno.EINVAL, "invalid function")
    hard_link_error.winerror = 1  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "pyezvizapi.client.os.link",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(hard_link_error),
    )

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


def test_save_cloud_clip_fallback_removes_partial_copy_after_failure(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.os.link",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.EOPNOTSUPP, "hard links unsupported")
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client.os.fsync",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.ENOSPC, "filesystem full")
        ),
    )

    with pytest.raises(OSError, match="filesystem full"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert not output_path.exists()


def test_save_cloud_clip_fallback_does_not_overwrite_concurrent_target(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    replacement_payload = b"concurrent writer"
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    def unsupported_link(_source: Path, target: Path) -> None:
        target.write_bytes(replacement_payload)
        raise OSError(errno.EOPNOTSUPP, "hard links unsupported")

    monkeypatch.setattr("pyezvizapi.client.os.link", unsupported_link)

    with pytest.raises(PyEzvizError, match="changed during capture"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == replacement_payload


def test_save_cloud_clip_fallback_detects_replacement_during_copy(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clip.ts"
    replacement = tmp_path / "replacement.ts"
    replacement_payload = b"concurrent writer"
    real_fsync = os.fsync
    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        lambda _client, _serial, selected_output, **_kwargs: selected_output.write(
            SAVE_CLIP_PAYLOAD
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.client.os.link",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.EOPNOTSUPP, "hard links unsupported")
        ),
    )

    def replace_target_after_copy(file_descriptor: int) -> None:
        real_fsync(file_descriptor)
        replacement.write_bytes(replacement_payload)
        os.replace(replacement, output_path)

    monkeypatch.setattr("pyezvizapi.client.os.fsync", replace_target_after_copy)

    with pytest.raises(PyEzvizError, match="changed during capture"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == replacement_payload


@pytest.mark.parametrize(
    "duration_seconds",
    [None, float("inf"), float("nan"), 10**309, 1e12, sys.float_info.max],
)
def test_save_unbounded_clear_cloud_clip_writes_directly(
    monkeypatch,
    tmp_path,
    duration_seconds: float | None,
) -> None:
    client = _client()
    output_path = tmp_path / "stream.ps"
    observed_names: list[str] = []
    observed_durations: list[float | None] = []

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        observed_names.append(str(selected_output.name))
        observed_durations.append(kwargs["duration_seconds"])
        selected_output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegps", fake_copy)

    client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        output_format="mpegps",
        duration_seconds=duration_seconds,
    )

    assert observed_names == [str(output_path)]
    assert observed_durations == [None]
    assert output_path.read_bytes() == SAVE_CLIP_PAYLOAD


def test_save_clip_cloud_decrypt_uses_automatic_nalu_header_default(
    monkeypatch,
) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_copy_cloud_stream_to_mpegts(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})

    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        fake_copy_cloud_stream_to_mpegts,
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    client.save_clip(
        "CAM123",
        io.BytesIO(),
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert calls[0]["nalu_header_size"] is None


def test_save_cloud_clip_rejects_path_without_decodable_video(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "front.ts"
    existing_clip = b"existing-clip"
    output_path.write_bytes(existing_clip)
    capture_paths: list[Path] = []

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        capture_paths.append(Path(str(output.name)))
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"",
            stderr=b"decoder warning",
        ),
    )

    with pytest.raises(PyEzvizError, match="did not include a decodable video frame"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output_path.read_bytes() == existing_clip
    assert len(capture_paths) == 1
    assert capture_paths[0] != output_path
    assert not capture_paths[0].exists()
    assert list(tmp_path.iterdir()) == [output_path]


def test_save_cloud_clip_accepts_decoded_frame_despite_warnings(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "front.ts"
    reference_path = tmp_path / "normal-create"
    reference_path.write_bytes(b"")
    expected_mode = stat.S_IMODE(reference_path.stat().st_mode)

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    run_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_run(*args: Any, **kwargs: Any) -> SimpleNamespace:
        run_calls.append((args, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=b"\x00",
            stderr=b"decoder warning",
        )

    monkeypatch.setattr(
        "pyezvizapi.client.subprocess.run",
        fake_run,
    )

    result = client.save_clip(
        "CAM123",
        output_path,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
        timeout=0.01,
    )

    assert result["ok"] is True
    assert stat.S_IMODE(output_path.stat().st_mode) == expected_mode
    assert "-nostdin" in run_calls[0][0][0]
    assert run_calls[0][1]["timeout"] == CLOUD_CLIP_VALIDATION_TIMEOUT_SECONDS


def test_save_cloud_clip_does_not_decode_validate_encrypted_path(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "encrypted.ts"

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: pytest.fail("encrypted output must not be decode-validated"),
    )

    result = client.save_clip("CAM123", output_path, source="cloud")

    assert result["ok"] is True


def test_save_clear_cloud_clip_failure_preserves_existing_path(
    monkeypatch,
    tmp_path,
) -> None:
    client = _client()
    output_path = tmp_path / "clear.ps"
    existing_clip = b"existing-clear-clip"
    output_path.write_bytes(existing_clip)

    def fail_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(b"partial")
        raise PyEzvizError("Cloud stream did not provide media before startup expired")

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegps", fail_copy)

    with pytest.raises(PyEzvizError, match="did not provide media"):
        client.save_clip(
            "CAM123",
            output_path,
            source="cloud",
            output_format="mpegps",
        )

    assert output_path.read_bytes() == existing_clip


def test_save_cloud_clip_validates_binary_output_before_copying(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO(b"prefix-")
    output.seek(0, io.SEEK_END)
    validation_paths: list[Path] = []

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(SAVE_CLIP_PAYLOAD)

    def fake_validate(path: Path, *, ffmpeg_path: str) -> None:
        assert ffmpeg_path == "ffmpeg"
        assert path.read_bytes() == SAVE_CLIP_PAYLOAD
        validation_paths.append(path)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        fake_validate,
    )

    result = client.save_clip(
        "CAM123",
        output,
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    assert output.getvalue() == b"prefix-" + SAVE_CLIP_PAYLOAD
    assert result["bytes"] == len(SAVE_CLIP_PAYLOAD)
    assert len(validation_paths) == 1
    assert not validation_paths[0].exists()


def test_save_cloud_clip_invalid_binary_output_is_untouched_and_temp_is_cleaned(
    monkeypatch,
) -> None:
    client = _client()
    existing_output = b"existing"
    output = io.BytesIO(existing_output)
    output.seek(0, io.SEEK_END)
    validation_paths: list[Path] = []

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(SAVE_CLIP_PAYLOAD)

    def reject(path: Path, *, ffmpeg_path: str) -> None:
        assert ffmpeg_path == "ffmpeg"
        validation_paths.append(path)
        raise PyEzvizError("invalid decoded video")

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        reject,
    )

    with pytest.raises(PyEzvizError, match="invalid decoded video"):
        client.save_clip(
            "CAM123",
            output,
            source="cloud",
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output.getvalue() == existing_output
    assert len(validation_paths) == 1
    assert not validation_paths[0].exists()


def test_save_cloud_clip_encrypted_binary_output_still_writes_directly(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()

    def fake_copy(
        _client: EzvizClient,
        _serial: str,
        selected_output: BinaryIO,
        **_kwargs: Any,
    ) -> None:
        selected_output.write(SAVE_CLIP_PAYLOAD)

    monkeypatch.setattr("pyezvizapi.client.copy_cloud_stream_to_mpegts", fake_copy)
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: pytest.fail("encrypted output must not be decode-validated"),
    )

    result = client.save_clip("CAM123", output, source="cloud")

    assert output.getvalue() == SAVE_CLIP_PAYLOAD
    assert result["bytes"] == len(SAVE_CLIP_PAYLOAD)


def test_save_clip_cloud_decrypt_preserves_explicit_zero_nalu_header(
    monkeypatch,
) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_copy_cloud_stream_to_mpegts(
        source_client: EzvizClient,
        serial: str,
        output: BinaryIO,
        **kwargs: Any,
    ) -> None:
        calls.append({"client": source_client, "serial": serial, **kwargs})

    monkeypatch.setattr(
        "pyezvizapi.client.copy_cloud_stream_to_mpegts",
        fake_copy_cloud_stream_to_mpegts,
    )
    monkeypatch.setattr(
        "pyezvizapi.client._require_decodable_saved_video_frame",
        lambda *_args, **_kwargs: None,
    )

    client.save_clip(
        "CAM123",
        io.BytesIO(),
        source="cloud",
        decrypt_video=True,
        media_key="MEDIAKEY",
        nalu_header_size=0,
    )

    assert calls[0]["nalu_header_size"] == 0


def test_save_image_triggers_capture_and_downloads(monkeypatch, tmp_path) -> None:
    client = _client()
    output_path = tmp_path / "snapshots" / "front.jpg"
    calls: dict[str, Any] = {}

    def fake_capture_picture(
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls["capture"] = {
            "serial": serial,
            "channel": channel,
            "max_retries": max_retries,
        }
        return {
            "data": {
                "picUrl": "https://image.example.test/capture.jpg",
            },
            "meta": {"code": 200},
        }

    def fake_download_alarm_image(
        image_url: str,
        serial: str | None = None,
        **kwargs: Any,
    ) -> bytes:
        calls["download"] = {"image_url": image_url, "serial": serial, **kwargs}
        return SAVE_IMAGE_PAYLOAD

    monkeypatch.setattr(client, "capture_picture", fake_capture_picture)
    monkeypatch.setattr(client, "download_alarm_image", fake_download_alarm_image)

    result = client.save_image(
        "CAM123",
        output_path,
        channel=2,
        smscode="654321",
    )

    assert calls["capture"] == {
        "serial": "CAM123",
        "channel": 2,
        "max_retries": 1,
    }
    assert calls["download"] == {
        "image_url": "https://image.example.test/capture.jpg",
        "serial": "CAM123",
        "decrypt": True,
        "smscode": "654321",
        "max_retries": 1,
    }
    assert output_path.read_bytes() == SAVE_IMAGE_PAYLOAD
    assert result == {
        "ok": True,
        "kind": "image",
        "serial": "CAM123",
        "channel": 2,
        "output": str(output_path),
        "bytes": len(SAVE_IMAGE_PAYLOAD),
        "content_type": "image/jpeg",
        "image_url": "https://image.example.test/capture.jpg",
        "triggered_capture": True,
    }


def test_save_image_can_write_to_binary_file(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()

    def fake_download_alarm_image(*_args: Any, **_kwargs: Any) -> bytes:
        return SAVE_IMAGE_PAYLOAD

    monkeypatch.setattr(client, "download_alarm_image", fake_download_alarm_image)

    result = client.save_image(
        "CAM123",
        output,
        image_url="https://image.example.test/alarm.jpg",
        decrypt=False,
    )

    assert output.getvalue() == SAVE_IMAGE_PAYLOAD
    assert result == {
        "ok": True,
        "kind": "image",
        "serial": "CAM123",
        "channel": 1,
        "output": None,
        "bytes": len(SAVE_IMAGE_PAYLOAD),
        "content_type": "image/jpeg",
        "image_url": "https://image.example.test/alarm.jpg",
        "triggered_capture": False,
    }


def test_download_cloud_video_fetches_direct_http_url(monkeypatch) -> None:
    client = _client()
    payload = b"video-bytes"
    calls: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        calls.update({"method": method, "url": url, **kwargs})
        return _binary_response(payload)

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    assert (
        client.download_cloud_video(
            {
                "seqId": 12345,
                "downloadInfo": {"fileUrl": "https://video.example.test/clip.ps"},
            },
            max_retries=2,
        )
        == payload
    )
    assert calls == {
        "method": "GET",
        "url": "https://video.example.test/clip.ps",
        "retry_401": False,
        "max_retries": 2,
    }


def test_download_cloud_video_ignores_nested_thumbnail_url(monkeypatch) -> None:
    client = _client()
    payload = b"video-bytes"
    calls: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        calls.update({"method": method, "url": url, **kwargs})
        return _binary_response(payload)

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    assert (
        client.download_cloud_video(
            {
                "seqId": 12345,
                "cover": {"url": "https://image.example.test/cover.jpg"},
                "downloadInfo": {"fileUrl": "https://video.example.test/clip.ps"},
            }
        )
        == payload
    )
    assert calls["url"] == "https://video.example.test/clip.ps"


def test_download_cloud_video_accepts_generic_url_in_media_container(
    monkeypatch,
) -> None:
    client = _client()
    payload = b"video-bytes"
    calls: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        calls.update({"method": method, "url": url, **kwargs})
        return _binary_response(payload)

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    assert (
        client.download_cloud_video(
            {
                "seqId": 12345,
                "cover": {"url": "https://image.example.test/cover.jpg"},
                "video": {"url": "https://video.example.test/clip.ps"},
            }
        )
        == payload
    )
    assert calls["url"] == "https://video.example.test/clip.ps"


def test_download_cloud_video_rejects_native_stream_descriptor() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="direct HTTP\\(S\\) download URL"):
        client.download_cloud_video(
            {
                "seqId": 12345,
                "streamUrl": "hweustreamer.ezvizlife.com:32723",
            }
        )


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

    assert (
        client.get_cam_auth_code(
            "CAM123",
            encrypt_pwd="enc",
            msg_auth_code=123456,
            sender_type=3,
            max_retries=1,
        )
        == "AUTH123"
    )
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
    assert (
        client.get_dev_config("CAM123", 3, "NightVision_Model", max_retries=2)["meta"]["code"]
        == 200
    )

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


def test_register_p2p_session_builds_app_style_request(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.register_p2p_session()["meta"]["code"] == 200

    assert calls == [
        {
            "method": "POST",
            "path": API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P,
            "data": {"sessionId": "session"},
            "retry_401": False,
        }
    ]


def test_register_p2p_session_refreshes_session_id_on_401(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    login_calls: list[None] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if len(calls) == 1:
            response = requests.Response()
            response.status_code = 401
            requests_error = requests.HTTPError(response=response)
            raise HTTPError from requests_error
        return {"meta": {"code": 200}}

    def fake_login() -> dict[str, Any]:
        login_calls.append(None)
        client._token["session_id"] = "fresh-session"
        return client.export_token()

    monkeypatch.setattr(client, "_request_json", fake_request_json)
    monkeypatch.setattr(client, "login", fake_login)

    assert client.register_p2p_session(session_id="stale-session")["meta"]["code"] == 200

    assert login_calls == [None]
    assert [call["data"] for call in calls] == [
        {"sessionId": "stale-session"},
        {"sessionId": "fresh-session"},
    ]


def test_register_p2p_session_treats_max_retries_as_retry_limit(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []
    login_calls: list[None] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        if len(calls) <= 2:
            response = requests.Response()
            response.status_code = 401
            requests_error = requests.HTTPError(response=response)
            raise HTTPError from requests_error
        return {"meta": {"code": 200}}

    def fake_login() -> dict[str, Any]:
        login_calls.append(None)
        client._token["session_id"] = f"fresh-session-{len(login_calls)}"
        return client.export_token()

    monkeypatch.setattr(client, "_request_json", fake_request_json)
    monkeypatch.setattr(client, "login", fake_login)

    assert (
        client.register_p2p_session(session_id="stale-session", max_retries=2)["meta"]["code"]
        == 200
    )

    assert login_calls == [None, None]
    assert [call["data"] for call in calls] == [
        {"sessionId": "stale-session"},
        {"sessionId": "fresh-session-1"},
        {"sessionId": "fresh-session-2"},
    ]


def test_register_p2p_session_respects_zero_retry_limit(monkeypatch) -> None:
    client = _client()
    login_calls: list[None] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = requests.Response()
        response.status_code = 401
        requests_error = requests.HTTPError(response=response)
        raise HTTPError from requests_error

    def fake_login() -> dict[str, Any]:
        login_calls.append(None)
        return client.export_token()

    monkeypatch.setattr(client, "_request_json", fake_request_json)
    monkeypatch.setattr(client, "login", fake_login)

    with pytest.raises(HTTPError):
        client.register_p2p_session(max_retries=0)

    assert login_calls == []


def test_register_p2p_session_requires_session_id() -> None:
    client = EzvizClient(token={"api_url": "apiieu.ezvizlife.com"}, timeout=1)

    with pytest.raises(PyEzvizError, match="requires a session_id"):
        client.register_p2p_session()


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
    assert (
        client.set_time_plan_infos(
            "CAM123",
            2,
            3,
            1,
            [{"start": "08:00", "stop": "17:00"}],
            max_retries=3,
        )["meta"]["code"]
        == 200
    )
    assert client.set_time_plan_infos("CAM123", 2, 3, 0, "[]")["meta"]["code"] == 200
    assert (
        client.search_records(
            "CAM123",
            2,
            "CHAN123",
            "2026-04-27T08:00:00Z",
            "2026-04-27T09:00:00Z",
            size=50,
            max_retries=4,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.search_records_v2(
            "CAM123",
            2,
            "2026-04-27T08:00:00Z",
            "2026-04-27T09:00:00Z",
            size=10,
            sort_by=1,
            require_label=1,
            max_retries=5,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.search_common_records(
            "CAM123",
            2,
            "2026-04-27T08:00:00Z",
            "2026-04-27T09:00:00Z",
            channel_serial="CHAN123",
            record_type=2,
            size=11,
            version=3,
            max_retries=6,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.search_intelligent_records(
            "CAM123",
            2,
            "2026-04-27T08:00:00Z",
            "2026-04-27T09:00:00Z",
            version=4,
            record_filter='{"person":true}',
            max_retries=7,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.get_cloud_videos(
            "CAM123",
            2,
            limit=5,
            video_type=-1,
            support_multi_channel_shared_service=1,
            max_retries=8,
        )["meta"]["code"]
        == 200
    )
    assert (
        client.get_cloud_video_details(
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
        )["meta"]["code"]
        == 200
    )
    assert (
        client.get_camera_ticket_info(
            "CAM123",
            2,
            support_multi_channel_shared_service=1,
            max_retries=10,
        )["meta"]["code"]
        == 200
    )

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

    assert (
        client.get_cloud_video_details(
            "CAM123",
            2,
            [
                {
                    "seqId": 12345,
                    "startTime": "2026-04-27 08:00:00",
                    "stopTime": "2026-04-27 08:01:00",
                }
            ],
        )["meta"]["code"]
        == 200
    )
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

    assert (
        client.get_socket_log_info("PLUG123", "2026-04-27", "2026-04-28", max_retries=1)["meta"][
            "code"
        ]
        == 200
    )
    assert client.linked_cameras("A1S123", "DET456", max_retries=2)["meta"]["code"] == 200
    assert client.set_microscope("CAM123", 2.5, 10, 20, 1, max_retries=3)["meta"]["code"] == 200
    assert client.share_accept("CAM123", max_retries=4)["meta"]["code"] == 200
    assert client.share_quit("CAM123", max_retries=5)["meta"]["code"] == 200
    assert (
        client.send_feedback(
            email="user@example.test",
            account="account-1",
            score=5,
            feedback="works",
            pic_url="https://image.example/pic.jpg",
            max_retries=6,
        )["meta"]["code"]
        == 200
    )
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
