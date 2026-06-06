from __future__ import annotations

import base64
import importlib
import io
import json
import subprocess
from typing import Any

from Crypto.Cipher import AES
import pytest
import requests

import pyezvizapi
from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud_stream import (
    copy_cloud_stream_to_mpegps,
    copy_cloud_stream_to_mpegts,
    get_cloud_stream_info,
    get_vtdu_token_v2,
    get_vtm_info,
    open_cloud_stream,
)
from pyezvizapi.exceptions import DeviceException, HTTPError, PyEzvizError
from pyezvizapi.stream import (
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    StreamTransport,
    VtmChannel,
    VtmMessageCode,
    VtmPacket,
    VtmStreamClient,
    VtmTraceEvent,
    _find_hevc_nal_start_codes,
    build_get_vtdu_info_request,
    build_peer_stream_request,
    build_start_stream_request,
    build_stop_stream_request,
    build_stream_info_request,
    build_stream_keepalive_request,
    build_vtm_url,
    decode_vtm_packet,
    decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size,
    detect_transport,
    download_ezviz_cloud_replay,
    encode_vtm_packet,
    mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length,
    parse_get_vtdu_info_response,
    parse_peer_stream_response,
    parse_start_stream_response,
    parse_stop_stream_response,
    parse_stream_info_response,
    parse_vtm_url,
    rtp_payload,
    summarize_vtm_packet,
)

BODY = b"abc"
cloud_stream_module = importlib.import_module("pyezvizapi.cloud_stream")
stream_module = importlib.import_module("pyezvizapi.stream")
CAMERA_SERIAL_BYTES = b"CAM123"
KEEPALIVE_REQ = b"\x0a\x07ssn-123"
PEER_HOST_BYTES = b"peerhost"
PUBLIC_KEY_BYTES = b"pub"
STOP_STREAM_REQ = b"\x0a\x07ssn-123\x12\x04info"
STREAM_URL = b"ysproto://vtm:8554/live"
STREAM_KEY = b"key-1"
STREAM_KEY_BYTES = b"stream-key"
VTM_STREAM_URL = b"ysproto://vtm.example.test:8554/live"
VTDU_TOKEN_BYTES = b"token-1"


def _encrypt_hikvision_fixture_blocks(key: bytes, payload: bytes) -> bytes:
    """Encrypt independent fixture blocks like the legacy media prefix transform."""

    encrypted = bytearray()
    for pos in range(0, len(payload), AES.block_size):
        block = payload[pos : pos + AES.block_size]
        if len(block) != AES.block_size:
            raise ValueError("fixture payload must contain complete AES blocks")
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes(AES.block_size))
        encrypted.extend(cipher.encrypt(block))
    return bytes(encrypted)


class FakeVtmSocket:
    def __init__(self, responses: list[bytes]) -> None:
        self._buffer = b"".join(responses)
        self.sent = b""
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        chunk = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


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


def _decode_sent_packets(data: bytes) -> list[Any]:
    packets: list[Any] = []
    offset = 0
    while offset < len(data):
        packet_length = int.from_bytes(data[offset + 2 : offset + 4], "big") + 8
        packets.append(decode_vtm_packet(data[offset : offset + packet_length]))
        offset += packet_length
    return packets


def test_package_exports_vtdu_stream_helpers() -> None:
    assert pyezvizapi.VtduInfoResponse is not None
    assert pyezvizapi.VtduStreamResponse is not None
    assert pyezvizapi.StopStreamResponse is not None
    assert pyezvizapi.VtmTraceEvent is VtmTraceEvent
    assert pyezvizapi.build_get_vtdu_info_request is build_get_vtdu_info_request
    assert pyezvizapi.build_start_stream_request is build_start_stream_request
    assert pyezvizapi.build_peer_stream_request is build_peer_stream_request
    assert pyezvizapi.build_stop_stream_request is build_stop_stream_request
    assert pyezvizapi.parse_get_vtdu_info_response is parse_get_vtdu_info_response
    assert pyezvizapi.parse_start_stream_response is parse_start_stream_response
    assert pyezvizapi.parse_peer_stream_response is parse_peer_stream_response
    assert pyezvizapi.parse_stop_stream_response is parse_stop_stream_response
    assert pyezvizapi.summarize_vtm_packet is summarize_vtm_packet


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
    rsp = (
        b"\x08\x00"
        b"\x22\x07ssn-123"
        b"\x2a\x05key-1"
        b"\x3a\x18ysproto://vtdu:8554/live"
        b"\x62\x04pds1"
        b"\x6a\x03::1"
    )

    decoded = parse_stream_info_response(rsp)

    assert decoded.result == 0
    assert decoded.streamssn == "ssn-123"
    assert decoded.vtmstreamkey == "key-1"
    assert decoded.streamurl == "ysproto://vtdu:8554/live"
    assert decoded.pdslist == (b"pds1",)
    assert decoded.srvipv6_addr == "::1"

    req = build_stream_info_request(STREAM_URL.decode(), vtm_stream_key=STREAM_KEY.decode())
    keepalive = build_stream_keepalive_request("ssn-123")

    assert STREAM_URL in req
    assert STREAM_KEY in req
    assert keepalive == KEEPALIVE_REQ


def test_vtdu_info_protobuf_helpers_decode_known_fields() -> None:
    req = build_get_vtdu_info_request(
        "CAM123",
        "token-1",
        channel=2,
        stream_type=1,
        business_type=4,
        client_isp_type=3,
        is_proxy=True,
    )
    rsp = (
        b"\x08\x00"
        b"\x12\x031.2"
        b"\x18\xea\x42"
        b"\x22\x0astream-key"
        b"\x2a\x08peerhost"
        b"\x30\xd2\x4a"
        b"\x3a\x07srvinfo"
    )

    decoded = parse_get_vtdu_info_response(rsp)

    assert CAMERA_SERIAL_BYTES in req
    assert VTDU_TOKEN_BYTES in req
    assert decoded.result == 0
    assert decoded.host == "1.2"
    assert decoded.port == 8554
    assert decoded.streamkey == "stream-key"
    assert decoded.peerhost == "peerhost"
    assert decoded.peerport == 9554
    assert decoded.srvinfo == "srvinfo"


def test_start_peer_and_stop_stream_protobuf_helpers() -> None:
    start_req = build_start_stream_request(
        "CAM123",
        "token-1",
        "stream-key",
        channel=2,
        stream_type=1,
        business_type=4,
        client_type=9,
        peer_host="peerhost",
        peer_port=9554,
    )
    peer_req = build_peer_stream_request(
        "CAM123",
        "token-1",
        channel=2,
        stream_type=1,
        business_type=4,
    )
    stop_req = build_stop_stream_request("ssn-123", ssn_info="info")

    start_rsp = parse_start_stream_response(
        b"\x08\x00\x12\x06header\x1a\x07ssn-123\x20\x07"
    )
    peer_rsp = parse_peer_stream_response(
        b"\x08\x00\x12\x06header\x1a\x07ssn-123\x20\x08"
    )
    stop_rsp = parse_stop_stream_response(b"\x08\x00")

    assert STREAM_KEY_BYTES in start_req
    assert PEER_HOST_BYTES in start_req
    assert CAMERA_SERIAL_BYTES in peer_req
    assert stop_req == STOP_STREAM_REQ
    assert start_rsp.streamssn == "ssn-123"
    assert start_rsp.datakey == 7
    assert peer_rsp.streamhead == "header"
    assert peer_rsp.datakey == 8
    assert stop_rsp.result == 0


def test_stream_info_response_rejects_truncated_length_delimited_field() -> None:
    with pytest.raises(PyEzvizError, match="exceeds payload"):
        parse_stream_info_response(b"\x22\x07ssn")


def test_detect_transport_and_rtp_payload() -> None:
    rtp = b"\x80\x60\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02abc"

    assert detect_transport(b"\x00\x00\x01\xba...") == StreamTransport.MPEG_PS
    assert detect_transport(b"\x47...") == StreamTransport.MPEG_TS
    assert detect_transport(rtp) == StreamTransport.RTP
    assert rtp_payload(rtp) == BODY


def test_decrypt_hikvision_ps_video_preserves_nal_header_and_decrypts_body() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    clear_payload = b"\x00\x00\x00\x01\x42\x01" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_honors_h264_nal_headers() -> None:
    key = "camera-key"
    clear_body = b"fedcba9876543210" * 2
    encrypted_body = bytes.fromhex(
        "71ec10ded9beb3a19fcdd7205152d6c6"
        "71ec10ded9beb3a19fcdd7205152d6c6"
    )
    clear_payload = b"\x00\x00\x00\x01\x65" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x65" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=1)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_decrypts_h264_nal_headers() -> None:
    key = "camera-key"
    clear_payload = b"\x00\x00\x00\x01\x65fedcba987654321"
    encrypted_payload = (
        b"\x00\x00\x00\x01" + bytes.fromhex("8fe82ee6ed094aae8d04ab3315ecf2a4")
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=0)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_decrypts_hevc_nal_headers() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_payload = b"\x00\x00\x00\x01\x40\x01hevc-header!!!"
    encrypted_header_and_body = _encrypt_hikvision_fixture_blocks(
        aes_key,
        clear_payload[4:]
    )
    encrypted_payload = b"\x00\x00\x00\x01" + encrypted_header_and_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=0)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_ignores_h264_encrypted_header_lookalikes() -> None:
    key = "camera-key"
    clear_payload = b"\x00\x00\x00\x01" + b"0000000001899711"
    encrypted_payload = (
        b"\x00\x00\x00\x01" + bytes.fromhex("00000143a299a588a28243e34f055bab")
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=0)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_keeps_short_encrypted_h264_nals() -> None:
    key = "camera-key"
    clear_nal = b"\x65fedcba987654321"
    encrypted_nal = bytes.fromhex("8fe82ee6ed094aae8d04ab3315ecf2a4")
    clear_payload = b"\x00\x00\x00\x01" + clear_nal + b"\x00\x00\x01" + clear_nal
    encrypted_payload = (
        b"\x00\x00\x00\x01" + encrypted_nal + b"\x00\x00\x01" + encrypted_nal
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=0)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_keeps_unaligned_h264_nal_boundaries() -> None:
    key = "camera-key"
    clear_nal = b"\x65fedcba987654321"
    encrypted_nal = bytes.fromhex("8fe82ee6ed094aae8d04ab3315ecf2a4")
    encrypted_partial_tail = b"tail"
    clear_payload = (
        b"\x00\x00\x00\x01"
        + clear_nal
        + encrypted_partial_tail
        + b"\x00\x00\x01"
        + clear_nal
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01"
        + encrypted_nal
        + encrypted_partial_tail
        + b"\x00\x00\x01"
        + encrypted_nal
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=0)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_preserves_h264_pes_start_continuation() -> None:
    key = "camera-key"
    clear_first = b"\x65fedcba987654321"
    clear_second = b"0000000001899711"
    encrypted_first = bytes.fromhex("8fe82ee6ed094aae8d04ab3315ecf2a4")
    encrypted_second = bytes.fromhex("00000143a299a588a28243e34f055bab")
    first_payload = b"\x00\x00\x00\x01" + encrypted_first
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(first_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + first_payload
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_second
    )

    assert decrypt_hikvision_ps_video(
        first_pes + second_pes,
        key,
        nalu_header_size=0,
    ) == (
        b"\x00\x00\x01\xe0"
        + (len(first_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01"
        + clear_first
        + b"\x00\x00\x01\xe0"
        + (len(encrypted_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_second
    )


def test_decrypt_hikvision_ps_video_starts_encrypted_header_across_pes_split() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_block = b"\x41\x9a\x00\x02local-frame!"
    encrypted_block = _encrypt_hikvision_fixture_blocks(aes_key, clear_block)
    encrypted_first_payload = b"\x00\x00\x00\x01" + encrypted_block[:8]
    encrypted_second_payload = encrypted_block[8:]
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_first_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_first_payload
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_second_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_second_payload
    )

    assert decrypt_hikvision_ps_video(
        first_pes + second_pes,
        key,
        nalu_header_size=0,
    ) == (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_first_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01"
        + clear_block[:8]
        + b"\x00\x00\x01\xe0"
        + (len(encrypted_second_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_block[8:]
    )


def test_decrypt_hikvision_ps_video_starts_later_encrypted_header_nal() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    first_clear = b"\x41\x9a\x00\x02" + (
        b"a" * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH + 16)
    )
    second_clear = b"\x41\x9a\x00\x04later-frame!"
    first_encrypted = (
        _encrypt_hikvision_fixture_blocks(
            aes_key,
            first_clear[:HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH],
        )
        + first_clear[HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH:]
    )
    second_encrypted = _encrypt_hikvision_fixture_blocks(aes_key, second_clear)
    encrypted_payload = (
        b"\x00\x00\x00\x01"
        + first_encrypted
        + b"\x00\x00\x00\x01"
        + second_encrypted
    )
    clear_payload = (
        b"\x00\x00\x00\x01"
        + first_clear
        + b"\x00\x00\x00\x01"
        + second_clear
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert decrypt_hikvision_ps_video(
        pes,
        key,
        nalu_header_size=0,
    ) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_scans_later_video_pes_after_gap() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_block = b"\x41\x9a\x00\x02local-frame!"
    encrypted_block = _encrypt_hikvision_fixture_blocks(aes_key, clear_block)
    payload = b"\x00\x00\x00\x01" + encrypted_block
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + payload
    )
    gap = b"\x00\x00\x01\xbd\x00\xffbroken-private-stream"

    assert decrypt_hikvision_ps_video(
        gap + pes,
        key,
        nalu_header_size=0,
    ) == (
        gap
        + b"\x00\x00\x01\xe0"
        + (len(payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01"
        + clear_block
    )


def test_decrypt_hikvision_ps_video_encrypted_header_resets_at_non_video_pes() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    encrypted_block = _encrypt_hikvision_fixture_blocks(
        aes_key,
        b"\x41\x9a\x00\x02split-prefix",
    )
    first_payload = b"\x00\x00\x00\x01" + encrypted_block[:8]
    second_payload = encrypted_block[8:]
    first_video_pes = (
        b"\x00\x00\x01\xe0"
        + (len(first_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + first_payload
    )
    audio_pes = b"\x00\x00\x01\xc0\x00\x04keep"
    second_video_pes = (
        b"\x00\x00\x01\xe0"
        + (len(second_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + second_payload
    )
    clip = first_video_pes + audio_pes + second_video_pes

    assert decrypt_hikvision_ps_video(clip, key, nalu_header_size=0) == clip


def test_detect_hikvision_ps_video_nalu_header_size_identifies_hevc() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 2
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01\x42\x01"
        + clear_body
    )


def test_detect_hikvision_ps_video_nalu_header_size_identifies_h264_clear_header() -> None:
    key = "camera-key"
    clear_body = b"fedcba9876543210" * 2
    encrypted_body = bytes.fromhex(
        "71ec10ded9beb3a19fcdd7205152d6c6"
        "71ec10ded9beb3a19fcdd7205152d6c6"
    )
    encrypted_payload = b"\x00\x00\x00\x01\x65" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 1
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01\x65"
        + clear_body
    )


def test_detect_hikvision_ps_video_nalu_header_size_identifies_h264_p_slice() -> None:
    key = "camera-key"
    clear_body = b"fedcba9876543210" * 2
    encrypted_body = bytes.fromhex(
        "71ec10ded9beb3a19fcdd7205152d6c6"
        "71ec10ded9beb3a19fcdd7205152d6c6"
    )
    encrypted_payload = b"\x00\x00\x00\x01\x41" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 1
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01\x41"
        + clear_body
    )


def test_detect_hikvision_ps_video_nalu_header_size_identifies_h264_encrypted_header() -> None:
    key = "camera-key"
    clear_payload = b"\x00\x00\x00\x01\x65fedcba987654321"
    encrypted_payload = (
        b"\x00\x00\x00\x01" + bytes.fromhex("8fe82ee6ed094aae8d04ab3315ecf2a4")
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 0
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_detect_hikvision_ps_video_nalu_header_size_identifies_hevc_encrypted_header() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_payload = b"\x00\x00\x00\x01\x40\x01hevc-header!!!"
    encrypted_payload = b"\x00\x00\x00\x01" + _encrypt_hikvision_fixture_blocks(
        aes_key,
        clear_payload[4:]
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 0
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_detect_hikvision_ps_video_nalu_header_size_probes_plausible_ciphertext_header() -> None:
    key = "camera-key"
    clear_payload = b"\x00\x00\x00\x01\x65fedcba9876543\x00\x8c"
    encrypted_payload = (
        b"\x00\x00\x00\x01" + bytes.fromhex("44575f999632c98e38f491889dcd98c6")
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 0
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_detect_hikvision_ps_video_nalu_header_size_keeps_hevc_probe_ties() -> None:
    key = "camera-key"
    clear_body = bytes.fromhex("000000294142434445464748494a4b4c")
    encrypted_body = bytes.fromhex("a959e9fa2429c99a36d4c7b1d0057557")
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert detect_hikvision_ps_video_nalu_header_size(pes, key) == 2
    assert decrypt_hikvision_ps_video(pes, key, nalu_header_size=None) == (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\x01\x42\x01"
        + clear_body
    )


def test_detect_hikvision_ps_video_nalu_header_size_can_defer_without_nals() -> None:
    pack_header_only = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"

    assert detect_hikvision_ps_video_nalu_header_size(pack_header_only, "camera-key") == 2
    assert (
        detect_hikvision_ps_video_nalu_header_size(
            pack_header_only,
            "camera-key",
            default=None,
        )
        is None
    )


def test_decrypt_hikvision_ps_video_leaves_nal_body_after_encrypted_prefix() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    encrypted_tail = encrypted_block
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
        + encrypted_tail
    )
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_prefix + encrypted_tail
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_preserves_short_hevc_nal_boundaries() -> None:
    key = "camera-key"
    clear_first_body = b"0123456789abcdef"
    encrypted_first_body = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    clear_second_body = b"fedcba9876543210"
    encrypted_second_body = bytes.fromhex("71ec10ded9beb3a19fcdd7205152d6c6")
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_first_body
        + b"\x00\x00\x01\x42\x01"
        + clear_second_body
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_first_body
        + b"\x00\x00\x01\x42\x01"
        + encrypted_second_body
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_preserves_sub_block_hevc_nal_boundaries() -> None:
    key = "camera-key"
    encrypted_first_body = b"tiny"
    clear_second_body = b"fedcba9876543210"
    encrypted_second_body = bytes.fromhex("71ec10ded9beb3a19fcdd7205152d6c6")
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_first_body
        + b"\x00\x00\x01\x42\x01"
        + clear_second_body
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_first_body
        + b"\x00\x00\x01\x42\x01"
        + encrypted_second_body
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_ignores_tail_start_code_lookalikes() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    preserved_tail = b"preserved-tail"
    false_nal_tail = b"\x00\x00\x01\x42\x01" + encrypted_block
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
        + preserved_tail
        + false_nal_tail
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_prefix
        + preserved_tail
        + false_nal_tail
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_ignores_long_tail_start_code_lookalikes() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    preserved_tail = b"preserved-tail"
    false_nal_tail = b"\x00\x00\x00\x01\x42\x01" + encrypted_block
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
        + preserved_tail
        + false_nal_tail
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_prefix
        + preserved_tail
        + false_nal_tail
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_keeps_scanning_real_nals_after_prefix() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    preserved_tail = b"preserved-tail"
    clear_second_body = b"fedcba9876543210"
    encrypted_second_body = bytes.fromhex("71ec10ded9beb3a19fcdd7205152d6c6")
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
        + preserved_tail
        + b"\x00\x00\x01\x26\x01"
        + clear_second_body
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_prefix
        + preserved_tail
        + b"\x00\x00\x01\x26\x01"
        + encrypted_second_body
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_keeps_exact_prefix_nal_boundary() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    clear_second_body = b"fedcba9876543210"
    encrypted_second_body = bytes.fromhex("71ec10ded9beb3a19fcdd7205152d6c6")
    clear_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + clear_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
        + b"\x00\x00\x00\x01\x42\x01"
        + clear_second_body
    )
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        + encrypted_prefix
        + b"\x00\x00\x00\x01\x42\x01"
        + encrypted_second_body
    )
    pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_preserves_pes_start_tail_lookalike() -> None:
    key = "camera-key"
    clear_block = b"0123456789abcdef"
    encrypted_block = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    encrypted_prefix = encrypted_block * (HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16)
    false_nal_tail = b"\x00\x00\x00\x01\x42\x01" + encrypted_block
    encrypted_first = b"\x00\x00\x00\x01\x42\x01" + encrypted_prefix
    clear_first = b"\x00\x00\x00\x01\x42\x01" + clear_block * (
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16
    )
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_first
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(false_nal_tail) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + false_nal_tail
    )

    assert decrypt_hikvision_ps_video(first_pes + second_pes, key) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_first
        + second_pes
    )


def test_decrypt_hikvision_ps_video_handles_all_video_pes_stream_ids() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    clear_payload = b"\x00\x00\x00\x01\x42\x01" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    pes = (
        b"\x00\x00\x01\xe1"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )

    assert (
        decrypt_hikvision_ps_video(pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe1"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_bounds_zero_length_pes_at_next_ps_packet() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    clear_payload = b"\x00\x00\x00\x01\x42\x01" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_payload
    audio_pes = b"\x00\x00\x01\xc0\x00\x04keep"

    assert (
        decrypt_hikvision_ps_video(video_pes + audio_pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + clear_payload + audio_pes
    )


def test_decrypt_hikvision_ps_video_handles_trailing_zero_length_video_pes() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    clear_payload = b"\x00\x00\x00\x01\x42\x01" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + encrypted_body
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_payload

    assert (
        decrypt_hikvision_ps_video(video_pes, key, nalu_header_size=2)
        == b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + clear_payload
    )


def test_decrypt_hikvision_ps_video_carries_nal_body_across_pes_packets() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    encrypted_first = b"\x00\x00\x00\x01\x42\x01" + encrypted_body[:20]
    encrypted_second = encrypted_body[20:]
    clear_first = b"\x00\x00\x00\x01\x42\x01" + clear_body[:20]
    clear_second = clear_body[20:]
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_first
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_second
    )

    assert decrypt_hikvision_ps_video(first_pes + second_pes, key) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_first
        + b"\x00\x00\x01\xe0"
        + (len(clear_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_second
    )


def test_decrypt_hikvision_ps_video_carries_nal_body_across_pack_header() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    pack_header = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    encrypted_first = b"\x00\x00\x00\x01\x42\x01" + encrypted_body[:20]
    encrypted_second = encrypted_body[20:]
    clear_first = b"\x00\x00\x00\x01\x42\x01" + clear_body[:20]
    clear_second = clear_body[20:]
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_first
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_second
    )

    assert decrypt_hikvision_ps_video(first_pes + pack_header + second_pes, key) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_first) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_first
        + pack_header
        + b"\x00\x00\x01\xe0"
        + (len(clear_second) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_second
    )


def test_decrypt_hikvision_ps_video_resets_after_non_video_packets() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_body = b"0123456789abcdef" * (
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH // 16
    )
    encrypted_body = bytearray()
    for pos in range(0, len(clear_body), 16):
        cipher = stream_module.AES.new(
            aes_key,
            stream_module.AES.MODE_CBC,
            iv=bytes(16),
        )
        encrypted_body.extend(cipher.encrypt(clear_body[pos : pos + 16]))

    clear_payload = b"\x00\x00\x00\x01\x42\x01" + clear_body
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + bytes(encrypted_body)
    first_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )
    second_pes = (
        b"\x00\x00\x01\xe0"
        + (len(encrypted_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + encrypted_payload
    )
    audio_pes = b"\x00\x00\x01\xc0\x00\x04keep"

    assert decrypt_hikvision_ps_video(
        first_pes + audio_pes + second_pes,
        key,
        nalu_header_size=2,
    ) == (
        b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
        + audio_pes
        + b"\x00\x00\x01\xe0"
        + (len(clear_payload) + 3).to_bytes(2, "big")
        + b"\x80\x00\x00"
        + clear_payload
    )


def test_decrypt_hikvision_ps_video_bounds_adjacent_zero_length_pes_packets() -> None:
    key = "camera-key"
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = bytes.fromhex(
        "34a1119c1a165ddeb3ad0fffba9282ec"
        "34a1119c1a165ddeb3ad0fffba9282ec"
    )
    encrypted_first = b"\x00\x00\x00\x01\x42\x01" + encrypted_body[:20]
    encrypted_second = encrypted_body[20:]
    clear_first = b"\x00\x00\x00\x01\x42\x01" + clear_body[:20]
    clear_second = clear_body[20:]
    first_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_first
    second_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_second
    audio_pes = b"\x00\x00\x01\xc0\x00\x04keep"

    assert decrypt_hikvision_ps_video(first_pes + second_pes + audio_pes, key) == (
        b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00"
        + clear_first
        + b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00"
        + clear_second
        + audio_pes
    )


def test_mpeg_ps_complete_prefix_ignores_ciphertext_start_code_lookalikes() -> None:
    pack = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    encrypted_payload = b"\x00\x00\x00\x01\x42\x01" + (
        b"ciphertext"
        b"\x00\x00\x01\xe0\x00\x04"
        b"tail"
    )
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_payload
    audio_pes = b"\x00\x00\x01\xc0\x00\x07\x80\x00\x00keep"

    assert mpeg_ps_complete_prefix_length(pack + video_pes) == len(pack)
    assert mpeg_ps_complete_prefix_length(pack + video_pes + audio_pes) == len(
        pack + video_pes + audio_pes
    )


def test_mpeg_ps_complete_prefix_ignores_ciphertext_pack_header_lookalikes() -> None:
    invalid_pack_lookalike = b"\x00\x00\x01\xba" + b"\xff" * 20
    encrypted_payload = (
        b"\x00\x00\x00\x01\x42\x01"
        b"ciphertext"
        + invalid_pack_lookalike
        + b"tail"
    )
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + encrypted_payload
    audio_pes = b"\x00\x00\x01\xc0\x00\x07\x80\x00\x00keep"

    assert mpeg_ps_complete_prefix_length(video_pes + audio_pes) == len(video_pes + audio_pes)


def test_mpeg_ps_decryptable_prefix_keeps_trailing_video_pes_run() -> None:
    first_video_pes = b"\x00\x00\x01\xe0\x00\x08\x80\x00\x00first"
    second_video_pes = b"\x00\x00\x01\xe0\x00\x09\x80\x00\x00second"
    audio_pes = b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"

    assert mpeg_ps_decryptable_prefix_length(first_video_pes) == 0
    assert mpeg_ps_decryptable_prefix_length(first_video_pes + second_video_pes) == 0
    assert mpeg_ps_decryptable_prefix_length(first_video_pes + second_video_pes + audio_pes) == len(
        first_video_pes + second_video_pes + audio_pes
    )


def test_mpeg_ps_decryptable_prefix_keeps_metadata_in_trailing_video_run() -> None:
    first_video_pes = b"\x00\x00\x01\xe0\x00\x08\x80\x00\x00first"
    pack_header = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    second_video_pes = b"\x00\x00\x01\xe0\x00\x09\x80\x00\x00second"
    audio_pes = b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"

    assert mpeg_ps_decryptable_prefix_length(first_video_pes + pack_header) == 0
    assert (
        mpeg_ps_decryptable_prefix_length(
            first_video_pes + pack_header + second_video_pes,
        )
        == 0
    )
    assert mpeg_ps_decryptable_prefix_length(
        first_video_pes + pack_header + second_video_pes + audio_pes,
    ) == len(first_video_pes + pack_header + second_video_pes + audio_pes)


def test_mpeg_ps_decryptable_prefix_keeps_all_trailing_video_stream_ids() -> None:
    first_video_pes = b"\x00\x00\x01\xe1\x00\x08\x80\x00\x00first"
    second_video_pes = b"\x00\x00\x01\xe2\x00\x09\x80\x00\x00second"
    audio_pes = b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"

    assert mpeg_ps_decryptable_prefix_length(first_video_pes) == 0
    assert mpeg_ps_decryptable_prefix_length(first_video_pes + second_video_pes) == 0
    assert mpeg_ps_decryptable_prefix_length(first_video_pes + second_video_pes + audio_pes) == len(
        first_video_pes + second_video_pes + audio_pes
    )


def test_mpeg_ps_decryptable_prefix_flushes_before_trailing_video_pes() -> None:
    audio_pes = b"\x00\x00\x01\xc0\x00\x08\x80\x00\x00audio"
    video_pes = b"\x00\x00\x01\xe0\x00\x08\x80\x00\x00video"

    assert mpeg_ps_decryptable_prefix_length(audio_pes + video_pes) == len(audio_pes)


def test_download_ezviz_cloud_replay_preserves_type_2_media(monkeypatch) -> None:
    expected_payload = b"firstsecond"
    messages = [
        stream_module._CloudReplayMessage(  # noqa: SLF001
            xml=b"<Response><Result>0</Result><Type>1</Type></Response>",
            data=b"first",
            md5_ok=True,
            result=0,
            data_type=1,
        ),
        stream_module._CloudReplayMessage(  # noqa: SLF001
            xml=b"<Response><Result>0</Result><Type>2</Type></Response>",
            data=b"second",
            md5_ok=True,
            result=0,
            data_type=2,
        ),
        stream_module._CloudReplayMessage(  # noqa: SLF001
            xml=b"<Response><Result>0</Result><Type>100</Type></Response>",
            data=b"",
            md5_ok=True,
            result=0,
            data_type=100,
        ),
    ]

    class FakeSocket:
        def __enter__(self) -> FakeSocket:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _data: bytes) -> None:
            return None

    class FakeSslContext:
        minimum_version: object

        def wrap_socket(self, raw_socket: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert server_hostname == "cloud.example.test"
            return raw_socket

    def fake_read_cloud_replay_message(
        _tls_socket: FakeSocket,
        _buffer: bytes,
    ) -> tuple[Any, bytes]:
        return messages.pop(0), b""

    monkeypatch.setattr(
        stream_module.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )
    monkeypatch.setattr(
        stream_module.ssl,
        "create_default_context",
        FakeSslContext,
    )
    monkeypatch.setattr(
        stream_module,
        "_read_cloud_replay_message",
        fake_read_cloud_replay_message,
    )

    assert (
        download_ezviz_cloud_replay(
            stream_url="cloud.example.test:32723",
            ticket="ticket",
            serial="CAM123",
            channel=1,
            seq_id=123,
            begin_cas="20260509T215000Z",
            end_cas="20260509T215010Z",
        )
        == expected_payload
    )


def test_download_ezviz_cloud_replay_rejects_short_download(monkeypatch) -> None:
    messages = [
        stream_module._CloudReplayMessage(  # noqa: SLF001
            xml=b"<Response><Result>0</Result><Type>1</Type></Response>",
            data=b"short",
            md5_ok=True,
            result=0,
            data_type=1,
        ),
        stream_module._CloudReplayMessage(  # noqa: SLF001
            xml=b"<Response><Result>0</Result><Type>100</Type></Response>",
            data=b"",
            md5_ok=True,
            result=0,
            data_type=100,
        ),
    ]

    class FakeSocket:
        def __enter__(self) -> FakeSocket:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, _data: bytes) -> None:
            return None

    class FakeSslContext:
        minimum_version: object

        def wrap_socket(self, raw_socket: FakeSocket, *, server_hostname: str) -> FakeSocket:
            assert server_hostname == "cloud.example.test"
            return raw_socket

    def fake_read_cloud_replay_message(
        _tls_socket: FakeSocket,
        _buffer: bytes,
    ) -> tuple[Any, bytes]:
        return messages.pop(0), b""

    monkeypatch.setattr(
        stream_module.socket,
        "create_connection",
        lambda address, timeout: FakeSocket(),
    )
    monkeypatch.setattr(
        stream_module.ssl,
        "create_default_context",
        FakeSslContext,
    )
    monkeypatch.setattr(
        stream_module,
        "_read_cloud_replay_message",
        fake_read_cloud_replay_message,
    )

    with pytest.raises(PyEzvizError, match="ended before expected file size"):
        download_ezviz_cloud_replay(
            stream_url="cloud.example.test:32723",
            ticket="ticket",
            serial="CAM123",
            channel=1,
            seq_id=123,
            begin_cas="20260509T215000Z",
            end_cas="20260509T215010Z",
            file_size=6,
        )


def test_find_hevc_nal_start_codes_ignores_ciphertext_start_code_lookalikes() -> None:
    payload = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x01\xe0ciphertext-lookalike"
        b"\x00\x00\x01\x26\x01idr"
    )

    assert _find_hevc_nal_start_codes(payload, 0, len(payload)) == [(0, 4), (33, 3)]


def test_vtm_stream_client_starts_and_reads_payloads() -> None:
    stream_info_body = b"\x08\x00\x22\x07ssn-123\x2a\x05key-1"
    responses = [
        encode_vtm_packet(
            stream_info_body,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            sequence=7,
        ),
        encode_vtm_packet(
            build_stream_keepalive_request("ssn-123"),
            message_code=VtmMessageCode.KEEPALIVE_REQ,
            sequence=8,
        ),
        encode_vtm_packet(
            b"\x47abc",
            channel=VtmChannel.STREAM,
            message_code=0,
            sequence=9,
        ),
    ]
    fake_socket = FakeVtmSocket(responses)
    calls: list[tuple[tuple[str, int], float | None]] = []

    def socket_factory(
        address: tuple[str, int],
        timeout: float | None,
    ) -> FakeVtmSocket:
        calls.append((address, timeout))
        return fake_socket

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        timeout=3,
        socket_factory=socket_factory,
    ) as stream:
        info = stream.start()
        payloads = list(stream.iter_payloads(max_packets=1))

    first_sent_length = int.from_bytes(fake_socket.sent[2:4], "big") + 8
    first_sent = decode_vtm_packet(fake_socket.sent[:first_sent_length])
    second_start = first_sent.length + 8
    second_sent = decode_vtm_packet(fake_socket.sent[second_start:])

    assert calls == [(("vtm.example.test", 8554), 3)]
    assert fake_socket.closed
    assert info.streamssn == "ssn-123"
    assert info.vtmstreamkey == "key-1"
    assert STREAM_URL not in first_sent.body
    assert VTM_STREAM_URL in first_sent.body
    assert first_sent.message_code == VtmMessageCode.STREAMINFO_REQ
    assert second_sent.message_code == VtmMessageCode.KEEPALIVE_RSP
    assert payloads == [b"\x47abc"]


def test_vtm_stream_client_sends_proactive_keepalive_while_streaming() -> None:
    stream_info_body = b"\x08\x00\x22\x07ssn-123\x2a\x05key-1"
    responses = [
        encode_vtm_packet(
            stream_info_body,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            sequence=7,
        ),
        encode_vtm_packet(
            b"\x47one",
            channel=VtmChannel.STREAM,
            message_code=0,
            sequence=8,
        ),
        encode_vtm_packet(
            b"\x47two",
            channel=VtmChannel.STREAM,
            message_code=0,
            sequence=9,
        ),
    ]
    fake_socket = FakeVtmSocket(responses)
    times = iter([0.0, 0.0, 6.0, 6.0])

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=lambda _address, _timeout: fake_socket,
    ) as stream:
        stream.start()
        packets = list(
            stream.iter_packets(
                max_packets=2,
                keepalive_interval=5.0,
                monotonic=lambda: next(times),
            )
        )

    sent_packets = _decode_sent_packets(fake_socket.sent)

    assert [packet.body for packet in packets] == [b"\x47one", b"\x47two"]
    assert sent_packets[-1].message_code == VtmMessageCode.KEEPALIVE_REQ
    assert sent_packets[-1].body == build_stream_keepalive_request("ssn-123")


def test_vtm_stream_client_start_follows_redirect_response() -> None:
    redirect_url = "ysproto://redirect.example.test:6000/live?dev=CAM123"
    redirect_key = "redirect-key"
    redirect_body = (
        b"\x08\xb6\x29"
        + b"\x2a"
        + bytes([len(redirect_key)])
        + redirect_key.encode()
        + b"\x3a"
        + bytes([len(redirect_url)])
        + redirect_url.encode()
    )
    success_body = b"\x08\x00\x22\x07ssn-123"
    sockets = [
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    redirect_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=7,
                )
            ]
        ),
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    success_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=8,
                )
            ]
        ),
    ]
    calls: list[tuple[str, int]] = []

    def socket_factory(
        address: tuple[str, int],
        _timeout: float | None,
    ) -> FakeVtmSocket:
        calls.append(address)
        return sockets[len(calls) - 1]

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=socket_factory,
    ) as stream:
        info = stream.start()

    second_packets = _decode_sent_packets(sockets[1].sent)

    assert calls == [
        ("vtm.example.test", 8554),
        ("redirect.example.test", 6000),
    ]
    assert sockets[0].closed
    assert sockets[1].closed
    assert stream.stream_url == redirect_url
    assert info.result == 0
    assert info.streamssn == "ssn-123"
    assert second_packets[0].message_code == VtmMessageCode.STREAMINFO_REQ
    assert redirect_url.encode() in second_packets[0].body
    assert redirect_key.encode() in second_packets[0].body


def test_vtm_stream_client_traces_sanitized_packet_metadata() -> None:
    stream_info_body = b"\x08\x00\x22\x07ssn-123\x2a\x05key-1"
    responses = [
        encode_vtm_packet(
            stream_info_body,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            sequence=7,
        ),
        encode_vtm_packet(
            b"encrypted-control",
            channel=VtmChannel.ENCRYPTED_MESSAGE,
            message_code=VtmMessageCode.STREAM_VTMSTREAM_ECDH_NOTIFY,
            sequence=8,
        ),
        encode_vtm_packet(
            b"\x47abc",
            channel=VtmChannel.STREAM,
            message_code=0,
            sequence=9,
        ),
        encode_vtm_packet(
            build_stream_keepalive_request("ssn-123"),
            message_code=VtmMessageCode.KEEPALIVE_REQ,
            sequence=10,
        ),
    ]
    fake_socket = FakeVtmSocket(responses)

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=lambda _address, _timeout: fake_socket,
    ) as stream:
        events = stream.trace_packets(max_packets=4)

    keepalive_sent = decode_vtm_packet(fake_socket.sent[-(len(KEEPALIVE_REQ) + 8) :])

    assert stream.stream_info is not None
    assert stream.stream_info.streamssn == "ssn-123"
    assert events == [
        VtmTraceEvent(
            index=0,
            channel=VtmChannel.MESSAGE,
            channel_name="MESSAGE",
            length=len(stream_info_body),
            sequence=7,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            message_name="STREAMINFO_RSP",
            encrypted=False,
            transport="UNKNOWN",
        ),
        VtmTraceEvent(
            index=1,
            channel=VtmChannel.ENCRYPTED_MESSAGE,
            channel_name="ENCRYPTED_MESSAGE",
            length=len(b"encrypted-control"),
            sequence=8,
            message_code=VtmMessageCode.STREAM_VTMSTREAM_ECDH_NOTIFY,
            message_name="STREAM_VTMSTREAM_ECDH_NOTIFY",
            encrypted=True,
            transport="UNKNOWN",
        ),
        VtmTraceEvent(
            index=2,
            channel=VtmChannel.STREAM,
            channel_name="STREAM",
            length=4,
            sequence=9,
            message_code=0,
            message_name=None,
            encrypted=False,
            transport="MPEG_TS",
        ),
        VtmTraceEvent(
            index=3,
            channel=VtmChannel.MESSAGE,
            channel_name="MESSAGE",
            length=len(KEEPALIVE_REQ),
            sequence=10,
            message_code=VtmMessageCode.KEEPALIVE_REQ,
            message_name="KEEPALIVE_REQ",
            encrypted=False,
            transport="UNKNOWN",
        ),
    ]
    assert "body" not in events[0].as_dict()
    assert keepalive_sent.message_code == VtmMessageCode.KEEPALIVE_RSP
    assert keepalive_sent.body == KEEPALIVE_REQ


def test_vtm_stream_client_trace_follows_redirect_response() -> None:
    redirect_url = "ysproto://redirect.example.test:6000/live?dev=CAM123"
    redirect_key = "redirect-key"
    redirect_body = (
        b"\x08\xb6\x29"
        + b"\x2a"
        + bytes([len(redirect_key)])
        + redirect_key.encode()
        + b"\x3a"
        + bytes([len(redirect_url)])
        + redirect_url.encode()
    )
    success_body = b"\x08\x00\x22\x07ssn-123"
    stream_body = b"\x00\x00\x01\xbaabc"
    sockets = [
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    redirect_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=7,
                )
            ]
        ),
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    success_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=8,
                ),
                encode_vtm_packet(
                    stream_body,
                    channel=VtmChannel.STREAM,
                    message_code=0,
                    sequence=9,
                ),
            ]
        ),
    ]
    calls: list[tuple[str, int]] = []

    def socket_factory(
        address: tuple[str, int],
        _timeout: float | None,
    ) -> FakeVtmSocket:
        calls.append(address)
        return sockets[len(calls) - 1]

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=socket_factory,
    ) as stream:
        events = stream.trace_packets(max_packets=3)

    second_packets = _decode_sent_packets(sockets[1].sent)

    assert calls == [
        ("vtm.example.test", 8554),
        ("redirect.example.test", 6000),
    ]
    assert sockets[0].closed
    assert stream.stream_url == redirect_url
    assert stream.stream_info is not None
    assert stream.stream_info.result == 0
    assert second_packets[0].message_code == VtmMessageCode.STREAMINFO_REQ
    assert redirect_url.encode() in second_packets[0].body
    assert redirect_key.encode() in second_packets[0].body
    assert events == [
        VtmTraceEvent(
            index=0,
            channel=VtmChannel.MESSAGE,
            channel_name="MESSAGE",
            length=len(redirect_body),
            sequence=7,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            message_name="STREAMINFO_RSP",
            encrypted=False,
            transport="UNKNOWN",
        ),
        VtmTraceEvent(
            index=1,
            channel=VtmChannel.MESSAGE,
            channel_name="MESSAGE",
            length=len(success_body),
            sequence=8,
            message_code=VtmMessageCode.STREAMINFO_RSP,
            message_name="STREAMINFO_RSP",
            encrypted=False,
            transport="UNKNOWN",
        ),
        VtmTraceEvent(
            index=2,
            channel=VtmChannel.STREAM,
            channel_name="STREAM",
            length=len(stream_body),
            sequence=9,
            message_code=0,
            message_name=None,
            encrypted=False,
            transport="MPEG_PS",
        ),
    ]


def test_vtm_stream_client_trace_follows_redirect_after_keepalive() -> None:
    redirect_url = "ysproto://redirect.example.test:6000/live?dev=CAM123"
    redirect_key = "redirect-key"
    redirect_body = (
        b"\x08\xb6\x29"
        + b"\x2a"
        + bytes([len(redirect_key)])
        + redirect_key.encode()
        + b"\x3a"
        + bytes([len(redirect_url)])
        + redirect_url.encode()
    )
    success_body = b"\x08\x00\x22\x07ssn-123"
    sockets = [
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    build_stream_keepalive_request("ssn-123"),
                    message_code=VtmMessageCode.KEEPALIVE_REQ,
                    sequence=6,
                ),
                encode_vtm_packet(
                    redirect_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=7,
                ),
            ]
        ),
        FakeVtmSocket(
            [
                encode_vtm_packet(
                    success_body,
                    message_code=VtmMessageCode.STREAMINFO_RSP,
                    sequence=8,
                ),
            ]
        ),
    ]
    calls: list[tuple[str, int]] = []

    def socket_factory(
        address: tuple[str, int],
        _timeout: float | None,
    ) -> FakeVtmSocket:
        calls.append(address)
        return sockets[len(calls) - 1]

    with VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=socket_factory,
    ) as stream:
        events = stream.trace_packets(max_packets=3)

    first_packets = _decode_sent_packets(sockets[0].sent)
    second_packets = _decode_sent_packets(sockets[1].sent)

    assert calls == [
        ("vtm.example.test", 8554),
        ("redirect.example.test", 6000),
    ]
    assert sockets[0].closed
    assert stream.stream_url == redirect_url
    assert stream.stream_info is not None
    assert stream.stream_info.result == 0
    assert first_packets[-1].message_code == VtmMessageCode.KEEPALIVE_RSP
    assert second_packets[0].message_code == VtmMessageCode.STREAMINFO_REQ
    assert redirect_url.encode() in second_packets[0].body
    assert redirect_key.encode() in second_packets[0].body
    assert [event.message_code for event in events] == [
        VtmMessageCode.KEEPALIVE_REQ,
        VtmMessageCode.STREAMINFO_RSP,
        VtmMessageCode.STREAMINFO_RSP,
    ]


def test_vtm_trace_rejects_empty_packet_count() -> None:
    stream = VtmStreamClient("ysproto://vtm.example.test:8554/live")

    with pytest.raises(PyEzvizError, match="at least one packet"):
        stream.trace_packets(max_packets=0)


def test_vtm_stream_client_rejects_closed_socket() -> None:
    stream = VtmStreamClient("ysproto://vtm.example.test:8554/live")

    with pytest.raises(PyEzvizError, match="not connected"):
        stream.read_packet()


def test_vtm_stream_timeout_raises_device_exception() -> None:
    class TimeoutSocket(FakeVtmSocket):
        def recv(self, size: int) -> bytes:
            raise TimeoutError

    stream = VtmStreamClient(
        "ysproto://vtm.example.test:8554/live",
        socket_factory=lambda *_args: TimeoutSocket([]),
    )
    stream.connect()

    with pytest.raises(DeviceException, match="offline or unreachable"):
        stream.read_packet()


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

    assert get_vtdu_token_v2(client).get("tokens") == ["token-1"]
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

    assert get_vtdu_token_v2(client).get("tokens") == ["token-2"]
    assert len(calls) == 2
    assert calls[0]["params"]["sign"] == "sign-value"
    assert calls[1]["params"]["ssid"] == client.export_token()["session_id"]
    assert calls[1]["params"]["sign"] == "fresh-sign"
    assert calls[0]["retry_401"] is False
    assert calls[1]["retry_401"] is False


def test_get_vtdu_token_v2_derives_auth_addr_when_service_returns_null(
    monkeypatch,
) -> None:
    client = EzvizClient(
        token={
            "session_id": _jwt({"s": "sign-value"}),
            "api_url": "apiieu.ezvizlife.com",
            "service_urls": {"authAddr": "https://null"},
        },
        timeout=1,
    )
    calls: list[dict[str, Any]] = []

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.headers: dict[str, str] = {}
            self.content = b"{}"
            self.text = "{}"

        def json(self) -> dict[str, Any]:
            return {"retcode": 0, "tokens": ["token-1"], "msg": "ok"}

    def fake_get_service_urls() -> dict[str, Any]:
        return {"authAddr": "https://null"}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"method": method, "url": url, **kwargs})
        return FakeResponse()

    monkeypatch.setattr(client, "get_service_urls", fake_get_service_urls)
    monkeypatch.setattr(client, "_http_request", fake_http_request)

    assert get_vtdu_token_v2(client).get("tokens") == ["token-1"]
    assert calls[0]["url"] == "https://euauth.ezvizlife.com/vtdutoken2"
    assert client.export_token()["service_urls"]["authAddr"] == "https://null"


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


def test_get_vtm_info_uses_apk_discovered_endpoint() -> None:
    calls: list[tuple[str, str]] = []

    class FakeClient:
        def _request_json(self, method: str, path: str) -> dict[str, Any]:
            calls.append((method, path))
            return {
                "streamServerConfig": {
                    "externalIp": "1.2.3.4",
                    "port": 8554,
                    "publicKey": {"version": "2", "key": "cHVi"},
                }
            }

    info = get_vtm_info(FakeClient(), "CAM123", channel=0)

    assert calls == [("GET", "/v3/streaming/vtm/CAM123/1")]
    assert info["externalIp"] == "1.2.3.4"
    assert info["port"] == 8554


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
                    "publicKey": {"version": "2", "key": "cHVi"},
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
    assert info["vtm_public_key"].version == 2
    assert info["vtm_public_key"].key_bytes == PUBLIC_KEY_BYTES
    assert parse_vtm_url(info["stream_url"])[3]["chn"] == "2"


def test_get_cloud_stream_info_can_refresh_vtm_from_app_endpoint(monkeypatch) -> None:
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
            "VTM": {"Video": {"externalIp": "1.2.3.4", "port": 8554}},
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_info",
        lambda _client, _serial, _channel: {"externalIp": "5.6.7.8", "port": 9554},
    )

    info = get_cloud_stream_info(client, "CAM123", refresh_vtm=True)
    host, port, _path, _params = parse_vtm_url(info["stream_url"])

    assert host == "5.6.7.8"
    assert port == 9554


def test_open_cloud_stream_returns_unstarted_vtm_client(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_cloud_stream_info",
        lambda *_args, **_kwargs: {
            "stream_url": "ysproto://vtm.example.test:8554/live?dev=CAM123"
        },
    )

    stream = open_cloud_stream(client, "CAM123", timeout=3)

    assert isinstance(stream, VtmStreamClient)
    assert stream.stream_url == "ysproto://vtm.example.test:8554/live?dev=CAM123"
    assert stream.timeout == 3
    assert not stream.connected


def test_copy_cloud_stream_to_mpegps_writes_clear_payloads(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    expected_payload = b"ps-1ps-2"
    calls: list[dict[str, Any]] = []

    class FakeCloudStream:
        started = False

        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            self.started = True

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert self.started
            assert max_packets == 2
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=1,
                message_code=0,
                body=b"ps-1",
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=2,
                message_code=0,
                body=b"ps-2",
            )

    def fake_open_cloud_stream(
        source_client: EzvizClient,
        serial: str,
        **kwargs: Any,
    ) -> FakeCloudStream:
        calls.append({"client": source_client, "serial": serial, **kwargs})
        return FakeCloudStream()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        fake_open_cloud_stream,
    )

    copy_cloud_stream_to_mpegps(
        client,
        "CAM123",
        output,
        channel=2,
        client_type=7,
        token_index=1,
        refresh_vtm=False,
        timeout=3.0,
        max_packets=2,
    )

    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "channel": 2,
            "client_type": 7,
            "token_index": 1,
            "refresh_vtm": False,
            "timeout": 3.0,
        }
    ]
    assert output.getvalue() == expected_payload


def test_copy_cloud_stream_to_mpegps_decrypts_bounded_payloads(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    clear_payload = b"clear-ps"
    decrypt_calls: list[dict[str, Any]] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=1,
                message_code=0,
                body=b"enc1",
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=2,
                message_code=0,
                body=b"enc2",
            )

    def fake_decrypt(
        data: bytes,
        key: str | bytes,
        *,
        nalu_header_size: int | None = None,
    ) -> bytes:
        decrypt_calls.append(
            {
                "data": data,
                "key": key,
                "nalu_header_size": nalu_header_size,
            }
        )
        return clear_payload

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr("pyezvizapi.cloud_stream.decrypt_hikvision_ps_video", fake_decrypt)

    copy_cloud_stream_to_mpegps(
        client,
        "CAM123",
        output,
        max_packets=2,
        decrypt_video=True,
        media_key="MEDIAKEY",
        nalu_header_size=1,
    )

    assert decrypt_calls == [
        {"data": b"enc1enc2", "key": "MEDIAKEY", "nalu_header_size": 1}
    ]
    assert output.getvalue() == clear_payload


def test_copy_cloud_stream_to_mpegps_requires_bounded_decrypt() -> None:
    with pytest.raises(PyEzvizError, match="requires duration_seconds or max_packets"):
        copy_cloud_stream_to_mpegps(
            _client(),
            "CAM123",
            io.BytesIO(),
            duration_seconds=None,
            max_packets=None,
            decrypt_video=True,
            media_key="MEDIAKEY",
        )


def test_copy_cloud_stream_to_mpegts_pipes_clear_payloads(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    expected_payload = b"ps-1ps-2"
    open_calls: list[str] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=1,
                message_code=0,
                body=b"ps-1",
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=4,
                sequence=2,
                message_code=0,
                body=b"ps-2",
            )

    def fake_open_remux(ffmpeg_path: str) -> subprocess.Popen[bytes]:
        open_calls.append(ffmpeg_path)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        ffmpeg_path="/usr/bin/ffmpeg",
        max_packets=2,
    )

    assert open_calls == ["/usr/bin/ffmpeg"]
    assert output.getvalue() == expected_payload


def test_copy_cloud_stream_to_mpegts_decrypts_and_remuxes(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    expected_payload = b"ts:clear"
    calls: dict[str, Any] = {}

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 1
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=3,
                sequence=1,
                message_code=0,
                body=b"enc",
            )

    class FakeRemuxProcess:
        returncode = 0

        def communicate(self, data: bytes) -> tuple[bytes, bytes]:
            calls["remux_input"] = data
            return (b"ts:" + data, b"")

    def fake_decrypt(
        data: bytes,
        key: str | bytes,
        *,
        nalu_header_size: int | None = None,
    ) -> bytes:
        calls["decrypt"] = {
            "data": data,
            "key": key,
            "nalu_header_size": nalu_header_size,
        }
        return b"clear"

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr("pyezvizapi.cloud_stream.decrypt_hikvision_ps_video", fake_decrypt)
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_mpegts_remux_process",
        lambda _ffmpeg_path: FakeRemuxProcess(),
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        max_packets=1,
        decrypt_video=True,
        media_key=b"MEDIAKEY",
        nalu_header_size=2,
    )

    assert calls == {
        "decrypt": {"data": b"enc", "key": b"MEDIAKEY", "nalu_header_size": 2},
        "remux_input": b"clear",
    }
    assert output.getvalue() == expected_payload


def test_copy_cloud_stream_rejects_encrypted_vtm_packets(monkeypatch) -> None:
    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            yield VtmPacket(
                channel=VtmChannel.ENCRYPTED_STREAM,
                length=3,
                sequence=1,
                message_code=0,
                body=b"enc",
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )

    with pytest.raises(PyEzvizError, match="Received encrypted VTM stream packet"):
        copy_cloud_stream_to_mpegps(_client(), "CAM123", io.BytesIO(), max_packets=1)


def test_open_cloud_mpegts_remux_process_builds_ffmpeg_command(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    class FakeProcess:
        pass

    def fake_popen(args: list[str], **kwargs: Any) -> FakeProcess:
        calls.append({"args": args, **kwargs})
        return FakeProcess()

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.Popen", fake_popen)

    process = cloud_stream_module._open_cloud_mpegts_remux_process(  # noqa: SLF001
        "/bin/ffmpeg"
    )

    assert isinstance(process, FakeProcess)
    assert calls == [
        {
            "args": [
                "/bin/ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "mpeg",
                "-i",
                "pipe:0",
                "-c",
                "copy",
                "-f",
                "mpegts",
                "pipe:1",
            ],
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
        }
    ]


def test_open_cloud_mpegts_remux_process_reports_launch_errors(
    monkeypatch,
) -> None:
    def fake_popen(_args: list[str], **_kwargs: Any) -> None:
        raise OSError("missing")

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.Popen", fake_popen)

    with pytest.raises(PyEzvizError, match="Could not launch FFmpeg"):
        cloud_stream_module._open_cloud_mpegts_remux_process(  # noqa: SLF001
            "/missing/ffmpeg"
        )


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
        get_cloud_stream_info(client, "CAM123", refresh_vtm=False)


def test_get_cloud_stream_info_refreshes_missing_pagelist_vtm(monkeypatch) -> None:
    client = _client()

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_page_list",
        lambda _client: {
            "resourceInfos": [
                {
                    "deviceSerial": "CAM123",
                    "resourceId": "Video",
                    "localIndex": "1",
                    "streamBizUrl": "serial=CAM123&streamtag=tag-1",
                }
            ],
            "VTM": {},
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtm_info",
        lambda _client, serial, channel: {
            "externalIp": "1.2.3.4",
            "port": 8554,
            "serial": serial,
            "channel": channel,
        },
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.get_vtdu_token_v2",
        lambda _client: {"retcode": 0, "tokens": ["token-1"]},
    )

    info = get_cloud_stream_info(client, "CAM123", refresh_vtm=True)
    host, port, _path, params = parse_vtm_url(info["stream_url"])

    assert host == "1.2.3.4"
    assert port == 8554
    assert params["streamtag"] == "tag-1"


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
