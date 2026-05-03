from __future__ import annotations

import base64
import json
from typing import Any

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud_stream import get_cloud_stream_info, get_vtdu_token_v2
from pyezvizapi.exceptions import HTTPError, PyEzvizError
from pyezvizapi.stream import (
    StreamTransport,
    VtmChannel,
    VtmMessageCode,
    build_stream_info_request,
    build_stream_keepalive_request,
    build_vtm_url,
    decode_vtm_packet,
    detect_transport,
    encode_vtm_packet,
    parse_stream_info_response,
    parse_vtm_url,
    rtp_payload,
)

BODY = b"abc"
KEEPALIVE_REQ = b"\x0a\x07ssn-123"
STREAM_URL = b"ysproto://vtm:8554/live"
STREAM_KEY = b"key-1"


def _jwt(payload: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def _client() -> EzvizClient:
    return EzvizClient(
        token={
            "session_id": _jwt({"s": "sign-value"}),
            "api_url": "apiieu.ezvizlife.com",
            "service_urls": {"authAddr": "auth.example.test"},
        },
        timeout=1,
    )


def _http_error(status_code: int) -> HTTPError:
    response = requests.Response()
    response.status_code = status_code
    err = requests.HTTPError(response=response)
    wrapped = HTTPError()
    wrapped.__cause__ = err
    return wrapped


def test_vtm_packet_roundtrip() -> None:
    packet = encode_vtm_packet(
        BODY,
        channel=VtmChannel.MESSAGE,
        message_code=VtmMessageCode.STREAMINFO_REQ,
        sequence=7,
    )

    decoded = decode_vtm_packet(packet)

    assert decoded.channel == VtmChannel.MESSAGE
    assert decoded.length == 3
    assert decoded.sequence == 7
    assert decoded.message_code == VtmMessageCode.STREAMINFO_REQ
    assert decoded.body == BODY
    assert not decoded.encrypted


def test_vtm_packet_sequence_wraps_to_16_bits() -> None:
    assert decode_vtm_packet(encode_vtm_packet(BODY, sequence=65536)).sequence == 0
    assert decode_vtm_packet(encode_vtm_packet(BODY, sequence=-1)).sequence == 65535


def test_decode_vtm_packet_rejects_envelope_mismatch() -> None:
    with pytest.raises(PyEzvizError, match="length mismatch"):
        decode_vtm_packet(b"\x24\x00\x00\x02\x00\x00\x01\x3bA")


def test_build_and_parse_vtm_url_preserves_required_params() -> None:
    url = build_vtm_url(
        "1.2.3.4",
        8554,
        "CAM123",
        "serial=CAM123&streamtag=abc",
        "token-1",
        timestamp_ms=123456,
    )

    host, port, path, params = parse_vtm_url(url)

    assert host == "1.2.3.4"
    assert port == 8554
    assert path == "/live"
    assert params["dev"] == "CAM123"
    assert params["ssn"] == "token-1"
    assert params["serial"] == "CAM123"
    assert params["streamtag"] == "abc"
    assert params["timestamp"] == "123456"


def test_build_vtm_url_keeps_required_params_authoritative() -> None:
    url = build_vtm_url(
        "1.2.3.4",
        8554,
        "CAM123",
        "dev=OLD&chn=9&stream=9&cln=7&isp=1&auth=0&ssn=stale&vip=1&timestamp=1",
        "token-1",
        channel=2,
        client_type=9,
        timestamp_ms=123456,
    )

    _host, _port, _path, params = parse_vtm_url(url)

    assert params["dev"] == "CAM123"
    assert params["chn"] == "2"
    assert params["stream"] == "1"
    assert params["cln"] == "9"
    assert params["isp"] == "0"
    assert params["auth"] == "1"
    assert params["ssn"] == "token-1"
    assert params["vip"] == "0"
    assert params["timestamp"] == "123456"


def test_build_vtm_url_brackets_ipv6_hosts() -> None:
    url = build_vtm_url(
        "2001:db8::1",
        8554,
        "CAM123",
        "",
        "token-1",
        timestamp_ms=123456,
    )

    host, port, _path, params = parse_vtm_url(url)

    assert url.startswith("ysproto://[2001:db8::1]:8554/")
    assert host == "2001:db8::1"
    assert port == 8554
    assert params["dev"] == "CAM123"


@pytest.mark.parametrize(
    "stream_biz_url",
    [
        "?serial=CAM123&streamtag=abc",
        "/live?serial=CAM123&streamtag=abc",
        "https://vtm.example.test/live?serial=CAM123&streamtag=abc",
    ],
)
def test_build_vtm_url_parses_stream_biz_query_component(stream_biz_url: str) -> None:
    url = build_vtm_url(
        "1.2.3.4",
        8554,
        "CAM123",
        stream_biz_url,
        "token-1",
        timestamp_ms=123456,
    )

    _host, _port, _path, params = parse_vtm_url(url)

    assert "?serial" not in params
    assert "/live?serial" not in params
    assert params["serial"] == "CAM123"
    assert params["streamtag"] == "abc"


@pytest.mark.parametrize(
    "url",
    [
        "ysproto://host:70000/live",
        "ysproto://host:abc/live",
        "ysproto://[::1/live",
        "ysproto://[v6]/live",
    ],
)
def test_parse_vtm_url_normalizes_invalid_ports(url: str) -> None:
    with pytest.raises(PyEzvizError, match="host or port"):
        parse_vtm_url(url)


def test_stream_info_protobuf_helpers_decode_known_fields() -> None:
    rsp = b"\x08\x00\x22\x07ssn-123\x2a\x05key-1\x3a\x18ysproto://vtdu:8554/live"

    decoded = parse_stream_info_response(rsp)

    assert decoded.result == 0
    assert decoded.streamssn == "ssn-123"
    assert decoded.vtmstreamkey == "key-1"
    assert decoded.streamurl == "ysproto://vtdu:8554/live"

    req = build_stream_info_request(STREAM_URL.decode(), vtm_stream_key=STREAM_KEY.decode())
    keepalive = build_stream_keepalive_request("ssn-123")

    assert STREAM_URL in req
    assert STREAM_KEY in req
    assert keepalive == KEEPALIVE_REQ


def test_stream_info_response_rejects_truncated_length_delimited_field() -> None:
    with pytest.raises(PyEzvizError, match="exceeds payload"):
        parse_stream_info_response(b"\x22\x07ssn")


def test_detect_transport_and_rtp_payload() -> None:
    rtp = b"\x80\x60\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02abc"

    assert detect_transport(b"\x00\x00\x01\xba...") == StreamTransport.MPEG_PS
    assert detect_transport(b"\x47...") == StreamTransport.MPEG_TS
    assert detect_transport(rtp) == StreamTransport.RTP
    assert rtp_payload(rtp) == BODY


def test_get_vtdu_token_v2_uses_auth_addr_and_session_sign(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.headers: dict[str, str] = {}
            self.content = b"{}"
            self.text = "{}"

        def json(self) -> dict[str, Any]:
            return {"retcode": 0, "tokens": ["token-1"], "msg": "ok"}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"method": method, "url": url, **kwargs})
        return FakeResponse()

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    assert get_vtdu_token_v2(client)["tokens"] == ["token-1"]
    assert calls[0]["url"] == "https://auth.example.test/vtdutoken2"
    assert calls[0]["params"]["ssid"] == client.export_token()["session_id"]
    assert calls[0]["params"]["sign"] == "sign-value"


def test_get_vtdu_token_v2_recomputes_auth_after_login(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.headers: dict[str, str] = {}
            self.content = b"{}"
            self.text = "{}"

        def json(self) -> dict[str, Any]:
            return {"retcode": 0, "tokens": ["token-2"], "msg": "ok"}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"method": method, "url": url, **kwargs})
        if len(calls) == 1:
            raise _http_error(401)
        return FakeResponse()

    def fake_login() -> dict[str, Any]:
        object.__getattribute__(client, "_token")["session_id"] = _jwt(
            {"s": "fresh-sign"}
        )
        return client.export_token()

    monkeypatch.setattr(client, "_http_request", fake_http_request)
    monkeypatch.setattr(client, "login", fake_login)

    assert get_vtdu_token_v2(client)["tokens"] == ["token-2"]
    assert len(calls) == 2
    assert calls[0]["params"]["sign"] == "sign-value"
    assert calls[1]["params"]["ssid"] == client.export_token()["session_id"]
    assert calls[1]["params"]["sign"] == "fresh-sign"
    assert calls[0]["retry_401"] is False
    assert calls[1]["retry_401"] is False


def test_get_vtdu_token_v2_does_not_relogin_after_non_auth_error(monkeypatch) -> None:
    client = _client()
    login_calls = 0

    def fake_http_request(_method: str, _url: str, **_kwargs: Any) -> None:
        raise _http_error(500)

    def fake_login() -> dict[str, Any]:
        nonlocal login_calls
        login_calls += 1
        return client.export_token()

    monkeypatch.setattr(client, "_http_request", fake_http_request)
    monkeypatch.setattr(client, "login", fake_login)

    with pytest.raises(HTTPError):
        get_vtdu_token_v2(client)
    assert login_calls == 0


def test_get_cloud_stream_info_builds_bootstrap(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [
                {
                    "deviceSerial": "CAM123",
                    "resourceId": "Video",
                    "localIndex": "2",
                    "streamBizUrl": "serial=CAM123&streamtag=abc",
                }
            ],
            "VTM": {
                "Video": {
                    "externalIp": "1.2.3.4",
                    "port": 8554,
                    "publicKey": {"key": "pub"},
                }
            },
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    info = get_cloud_stream_info(client, "CAM123")

    assert info["vtdu_token"] == "token-1"
    assert info["resource"]["resourceId"] == "Video"
    assert info["vtm"]["externalIp"] == "1.2.3.4"
    assert parse_vtm_url(info["stream_url"])[3]["chn"] == "2"


def test_get_cloud_stream_info_uses_requested_channel_resource(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [
                {
                    "deviceSerial": "CAM123",
                    "resourceId": "Video-1",
                    "localIndex": "1",
                    "streamBizUrl": "serial=CAM123&streamtag=first",
                },
                {
                    "deviceSerial": "CAM123",
                    "resourceId": "Video-2",
                    "localIndex": "2",
                    "streamBizUrl": "serial=CAM123&streamtag=second",
                },
            ],
            "VTM": {
                "Video-1": {"externalIp": "1.2.3.4", "port": 8554},
                "Video-2": {"externalIp": "5.6.7.8", "port": 9554},
            },
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    info = get_cloud_stream_info(client, "CAM123", channel=2)
    host, port, _path, params = parse_vtm_url(info["stream_url"])

    assert info["resource"]["resourceId"] == "Video-2"
    assert host == "5.6.7.8"
    assert port == 9554
    assert params["chn"] == "2"
    assert params["streamtag"] == "second"


def test_get_cloud_stream_info_rejects_missing_vtm_endpoint(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [{"deviceSerial": "CAM123", "resourceId": "Video"}],
            "VTM": {"Video": {"port": 8554}},
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    with pytest.raises(PyEzvizError, match="VTM endpoint"):
        get_cloud_stream_info(client, "CAM123")


def test_get_cloud_stream_info_rejects_missing_vtm_port(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [{"deviceSerial": "CAM123", "resourceId": "Video"}],
            "VTM": {"Video": {"externalIp": "1.2.3.4"}},
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    with pytest.raises(PyEzvizError, match="VTM port"):
        get_cloud_stream_info(client, "CAM123")


def test_get_cloud_stream_info_rejects_out_of_range_vtm_port(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [{"deviceSerial": "CAM123", "resourceId": "Video"}],
            "VTM": {"Video": {"externalIp": "1.2.3.4", "port": 70000}},
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    with pytest.raises(PyEzvizError, match="VTM port"):
        get_cloud_stream_info(client, "CAM123")
