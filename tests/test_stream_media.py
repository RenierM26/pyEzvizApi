"""Tests for cloud MPEG media detection, decryption, capture, and remuxing."""

from __future__ import annotations

import base64
import importlib
import io
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace
from typing import Any, BinaryIO

from Crypto.Cipher import AES
import pytest
import requests

from pyezvizapi._stream import (
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    StreamTransport,
    VtmChannel,
    VtmMessageCode,
    VtmPacket,
    VtmStreamClient,
    _find_hevc_nal_start_codes,
    decode_vtm_packet,
    decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size,
    detect_transport,
    encode_vtm_packet,
    mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length,
    mpeg_ps_video_pts_span_seconds,
    rtp_payload,
)
from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud_stream import (
    _probe_cloud_video_duration,
    cloud_rtp_packets_have_audio,
    copy_cloud_stream_packets_to_mpegts,
    copy_cloud_stream_to_mpegps,
    copy_cloud_stream_to_mpegts,
    copy_decrypted_cloud_stream_packets_to_mpegts,
)
from pyezvizapi.exceptions import (
    EzvizIncompleteMediaError,
    EzvizNoMediaError,
    HTTPError,
    PyEzvizError,
    UnsupportedRtpVideoCodecError,
)

BODY = b"abc"
CLEAR_ANNEXB = b"clear-annexb"
EMPTY_BYTES = b""
H264_SPS_ANNEXB = b"\x00\x00\x00\x01\x67h264-sps"
HEVC_FU_ANNEXB = b"\x00\x00\x00\x01\x26\x01startmiddleend"
HEVC_DESCRIPTOR_ANNEXB = b"\x00\x00\x00\x01\x26\x01hevc"
AV_MPEGTS_PAYLOAD = b"av-mpegts"
MPEGPS_PAYLOAD = b"mpegps"
AAC_FRAME = b"aac-frame"

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


def _rtp_packet(
    payload: bytes,
    *,
    sequence: int = 1,
    payload_type: int = 96,
    marker: bool = False,
    timestamp: int = 90_000,
    extension_profile: int | None = None,
    extension_data: bytes = b"",
) -> bytes:
    """Build one minimal RTP v2 packet for cloud transport tests."""

    extension = b""
    first_byte = 0x80
    if extension_profile is not None:
        if len(extension_data) % 4:
            raise ValueError("RTP extension data must be 32-bit aligned")
        first_byte |= 0x10
        extension = (
            extension_profile.to_bytes(2, "big")
            + (len(extension_data) // 4).to_bytes(2, "big")
            + extension_data
        )
    return (
        bytes((first_byte,))
        + bytes([payload_type | (0x80 if marker else 0)])
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + b"\x55\x66\x77\x88"
        + extension
        + payload
    )

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

    def gettimeout(self) -> float | None:
        return self.timeout

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

def test_detect_transport_and_rtp_payload() -> None:
    rtp = b"\x80\x60\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02abc"

    assert detect_transport(b"\x00\x00\x01\xba...") == StreamTransport.MPEG_PS
    assert detect_transport(b"\x47...") == StreamTransport.MPEG_TS
    assert detect_transport(rtp) == StreamTransport.RTP
    assert rtp_payload(rtp) == BODY


def _timed_video_pes(pts: int) -> bytes:
    encoded = bytes(
        (
            0x20 | (((pts >> 30) & 7) << 1) | 1,
            (pts >> 22) & 0xFF,
            (((pts >> 15) & 0x7F) << 1) | 1,
            (pts >> 7) & 0xFF,
            ((pts & 0x7F) << 1) | 1,
        )
    )
    payload = b"\x00\x00\x00\x01\x26\x01frame"
    return (
        b"\x00\x00\x01\xe0"
        + (8 + len(payload)).to_bytes(2, "big")
        + b"\x80\x80\x05"
        + encoded
        + payload
    )


def test_mpeg_ps_video_pts_span_reads_clear_pes_headers() -> None:
    pack = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    payload = pack + _timed_video_pes(90_000) + pack + _timed_video_pes(1_710_000)

    assert mpeg_ps_video_pts_span_seconds(payload) == pytest.approx(18)


def test_mpeg_ps_video_pts_span_is_unknown_with_one_timestamp() -> None:
    assert mpeg_ps_video_pts_span_seconds(_timed_video_pes(90_000)) is None


def test_mpeg_ps_video_pts_span_is_ambiguous_after_forward_gap() -> None:
    payload = b"".join(
        _timed_video_pes(pts)
        for pts in (0, 45_000, 9_000_000, 9_045_000)
    )

    assert (
        mpeg_ps_video_pts_span_seconds(payload, max_gap_seconds=5.0) is None
    )


@pytest.mark.parametrize(
    ("first_pts", "last_pts", "expected_span"),
    [(90_000, 0, None), ((1 << 33) - 90_000, 90_000, 2)],
)
def test_mpeg_ps_video_pts_span_distinguishes_reset_from_wrap(
    first_pts: int, last_pts: int, expected_span: float | None
) -> None:
    payload = _timed_video_pes(first_pts) + _timed_video_pes(last_pts)

    observed = mpeg_ps_video_pts_span_seconds(payload)
    if expected_span is None:
        assert observed is None
    else:
        assert observed == pytest.approx(expected_span)


def test_mpeg_ps_video_pts_span_handles_long_capture_across_wrap() -> None:
    wrap = 1 << 33
    payload = b"".join(
        _timed_video_pes(pts)
        for pts in (wrap - 90 * 90_000, wrap - 90_000, 90_000, 90 * 90_000)
    )

    assert mpeg_ps_video_pts_span_seconds(payload) == pytest.approx(180)


@pytest.mark.parametrize(
    ("max_packets", "last_pts", "incomplete"),
    [(None, 180_000, True), (2, 180_000, False), (None, 1_710_000, False)],
)
@pytest.mark.parametrize("output_format", ["mpegps", "mpegts"])
def test_decrypted_cloud_save_rejects_short_timestamp_span_unless_packet_capped(
    monkeypatch: pytest.MonkeyPatch,
    max_packets: int | None,
    last_pts: int,
    incomplete: bool,
    output_format: str,
) -> None:
    pack = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    pts_values = (
        (90_000, last_pts)
        if incomplete or max_packets is not None
        else (*range(90_000, last_pts, 4 * 90_000), last_pts)
    )
    bodies = tuple(pack + _timed_video_pes(pts) for pts in pts_values)

    class FakeCloudStream:
        def start(self) -> None:
            return None

        def close(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            for index, body in enumerate(bodies):
                yield VtmPacket(VtmChannel.STREAM, len(body), index, 0, body)

    client = _client()
    monkeypatch.setattr(client, "get_cam_key", lambda _serial: "camera-key")
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.copy_decrypted_cloud_stream_packets_to_mpegts",
        lambda _packets, output, **_kwargs: output.write(AV_MPEGTS_PAYLOAD),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.decrypt_hikvision_ps_video",
        lambda *_args, **_kwargs: MPEGPS_PAYLOAD,
    )
    copy = (
        copy_cloud_stream_to_mpegps
        if output_format == "mpegps"
        else copy_cloud_stream_to_mpegts
    )
    output = io.BytesIO()
    if incomplete:
        with pytest.raises(EzvizIncompleteMediaError) as error:
            copy(
                client,
                "CAM123",
                output,
                duration_seconds=20,
                decrypt_video=True,
            )
        assert error.value.reason == "incomplete_media"
        assert error.value.source == "cloud"
        assert error.value.observed_pts_span_seconds == pytest.approx(1)
        assert output.getvalue() == EMPTY_BYTES
    else:
        copy(
            client,
            "CAM123",
            output,
            duration_seconds=20,
            max_packets=max_packets,
            decrypt_video=True,
        )
        assert output.getvalue() == (
            MPEGPS_PAYLOAD if output_format == "mpegps" else AV_MPEGTS_PAYLOAD
        )


@pytest.mark.parametrize("output_format", ["mpegps", "mpegts"])
@pytest.mark.parametrize("video_duration", [2.0, 18.0])
@pytest.mark.parametrize(
    "pts_values", [(90_000,), (0, 45_000, 9_000_000, 9_045_000)]
)
def test_decrypted_cloud_save_probes_ambiguous_pts_before_publication(
    monkeypatch: pytest.MonkeyPatch,
    output_format: str,
    video_duration: float,
    pts_values: tuple[int, ...],
) -> None:
    pack = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    body = b"".join(pack + _timed_video_pes(pts) for pts in pts_values)

    class FakeCloudStream:
        def start(self) -> None:
            return None

        def close(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            yield VtmPacket(VtmChannel.STREAM, len(body), 1, 0, body)

    client = _client()
    monkeypatch.setattr(client, "get_cam_key", lambda _serial: "camera-key")
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.copy_decrypted_cloud_stream_packets_to_mpegts",
        lambda _packets, output, **_kwargs: output.write(AV_MPEGTS_PAYLOAD),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.decrypt_hikvision_ps_video",
        lambda *_args, **_kwargs: MPEGPS_PAYLOAD,
    )
    def fake_probe(_path: Path, **kwargs: Any) -> float:
        assert kwargs["timeout_seconds"] == pytest.approx(40)
        return video_duration

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._probe_cloud_video_duration", fake_probe
    )
    copy = (
        copy_cloud_stream_to_mpegps
        if output_format == "mpegps"
        else copy_cloud_stream_to_mpegts
    )
    output = io.BytesIO()
    if video_duration < 10:
        with pytest.raises(EzvizIncompleteMediaError) as error:
            copy(client, "CAM123", output, duration_seconds=20, decrypt_video=True)
        assert error.value.observed_pts_span_seconds is None
        assert error.value.observed_video_duration_seconds == pytest.approx(2)
        assert output.getvalue() == EMPTY_BYTES
    else:
        copy(client, "CAM123", output, duration_seconds=20, decrypt_video=True)
        assert output.getvalue() == (
            MPEGPS_PAYLOAD if output_format == "mpegps" else AV_MPEGTS_PAYLOAD
        )


def test_cloud_video_probe_uses_video_frames_when_ps_stream_duration_is_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    calls: list[tuple[list[str], float]] = []

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((command, kwargs["timeout"]))
        if "-show_frames" in command:
            assert "capture_output" not in kwargs
            assert "csv=p=0" in command
            kwargs["stdout"].write(
                "100.0,H.264 User Data Unregistered SEI message\n102.0\n"
            )
            return SimpleNamespace(returncode=0)
        else:
            payload = {"streams": [{}], "format": {"duration": "20.0"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.run", fake_run)

    observed = _probe_cloud_video_duration(
        tmp_path / "short.ps", ffprobe_path="ffprobe", timeout_seconds=120
    )

    assert observed == pytest.approx(2)
    assert len(calls) == 2
    assert [timeout for _command, timeout in calls] == [120, 120]


@pytest.mark.parametrize(
    "timestamps",
    [
        ("100.0", "100.5", "0.0", "0.5"),
        ("0.0", "0.5", "100.0", "100.5"),
    ],
)
def test_cloud_video_probe_does_not_count_frame_timestamp_discontinuity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    timestamps: tuple[str, ...],
) -> None:
    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        if "-show_frames" in command:
            kwargs["stdout"].write("\n".join(timestamps) + "\n")
            return SimpleNamespace(returncode=0)
        else:
            payload = {
                "streams": [{"duration": "101.0"}],
                "format": {"duration": "101.0"},
            }
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload))

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.run", fake_run)

    observed = _probe_cloud_video_duration(
        tmp_path / "reset.ps", ffprobe_path="ffprobe"
    )

    assert observed == pytest.approx(1)


def test_cloud_video_probe_reports_missing_ffprobe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    def missing_ffprobe(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError("ffprobe")

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.run", missing_ffprobe)

    with pytest.raises(PyEzvizError, match="ffprobe is required"):
        _probe_cloud_video_duration(tmp_path / "short.ts", ffprobe_path="ffprobe")


def test_cloud_video_probe_reports_frame_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(command: list[str], **_kwargs: Any) -> SimpleNamespace:
        if "-show_frames" in command:
            raise subprocess.TimeoutExpired("ffprobe", 120)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"streams": [{"duration": "120.0"}]}),
        )

    monkeypatch.setattr("pyezvizapi.cloud_stream.subprocess.run", fake_run)

    with pytest.raises(PyEzvizError, match="timed out probing cloud video frames"):
        _probe_cloud_video_duration(
            tmp_path / "long.ts", ffprobe_path="ffprobe", timeout_seconds=120
        )


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


def test_decrypt_hikvision_ps_video_recovers_overlong_pes_at_valid_pack() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_body = b"0123456789abcdef" * 2
    encrypted_body = _encrypt_hikvision_fixture_blocks(aes_key, clear_body)
    # The declared PES length ends after the first AES block, but the camera
    # continues this video payload until the next valid MPEG-2 pack header.
    short_length = 3 + 4 + 2 + AES.block_size
    pes_header = b"\x00\x00\x01\xe0" + short_length.to_bytes(2, "big") + b"\x80\x00\x00"
    pack = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
    encrypted = pes_header + b"\x00\x00\x00\x01\x42\x01" + encrypted_body + pack
    expected = pes_header + b"\x00\x00\x00\x01\x42\x01" + clear_body + pack

    assert decrypt_hikvision_ps_video(encrypted, key, nalu_header_size=2) == expected

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


def test_decrypt_hikvision_ps_video_preserves_short_clear_pps_between_encrypted_nals() -> None:
    key = "camera-key"
    aes_key = key.encode().ljust(16, b"\0")[:16]
    clear_sps = b"\x67" + b"s" * 28
    clear_pps = b"\x28\xee\x3c\x80"
    clear_idr = b"\x65" + b"i" * 31

    def video_pes(nal: bytes) -> bytes:
        payload = b"\x00\x00\x00\x01" + nal
        return (
            b"\x00\x00\x01\xe0"
            + (len(payload) + 3).to_bytes(2, "big")
            + b"\x80\x00\x00"
            + payload
        )

    encrypted = (
        video_pes(_encrypt_hikvision_fixture_blocks(aes_key, clear_sps[:16]) + clear_sps[16:])
        + video_pes(clear_pps)
        + video_pes(_encrypt_hikvision_fixture_blocks(aes_key, clear_idr))
    )
    expected = video_pes(clear_sps) + video_pes(clear_pps) + video_pes(clear_idr)

    assert decrypt_hikvision_ps_video(encrypted, key, nalu_header_size=0) == expected


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

def test_find_hevc_nal_start_codes_ignores_ciphertext_start_code_lookalikes() -> None:
    payload = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x01\xe0ciphertext-lookalike"
        b"\x00\x00\x01\x26\x01idr"
    )

    assert _find_hevc_nal_start_codes(payload, 0, len(payload)) == [(0, 4), (33, 3)]

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

def test_copy_cloud_stream_to_mpegps_fetches_media_key_with_smscode(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    expected_payload = b"enc:camera-secret"
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

    def fake_get_cam_key(
        serial: str,
        *,
        smscode: str | int | None = None,
    ) -> str:
        calls["get_cam_key"] = {"serial": serial, "smscode": smscode}
        return "camera-secret"

    monkeypatch.setattr(client, "get_cam_key", fake_get_cam_key)
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.decrypt_hikvision_ps_video",
        lambda data, key, **_kwargs: b":".join((data, str(key).encode())),
    )

    copy_cloud_stream_to_mpegps(
        client,
        "CAM123",
        output,
        max_packets=1,
        decrypt_video=True,
        smscode="123456",
    )

    assert calls == {"get_cam_key": {"serial": "CAM123", "smscode": "123456"}}
    assert output.getvalue() == expected_payload

@pytest.mark.parametrize(
    "unsafe_bounds",
    [
        {},
        {"duration_seconds": 0.0},
        {"duration_seconds": -1.0},
        {"duration_seconds": float("nan")},
        {"duration_seconds": float("inf")},
        {"duration_seconds": 10**309},
        {"max_packets": 0},
        {"max_packets": -1},
        {"max_packets": float("nan")},
        {"max_packets": float("inf")},
        {"max_packets": 1, "duration_seconds": float("nan")},
        {"max_packets": 1, "duration_seconds": 10**309},
    ],
)
def test_copy_cloud_stream_to_mpegps_requires_safe_decrypt_bound(
    unsafe_bounds: dict[str, Any],
) -> None:
    with pytest.raises(
        PyEzvizError,
        match="requires a positive finite duration_seconds or max_packets",
    ):
        copy_cloud_stream_to_mpegps(
            _client(),
            "CAM123",
            io.BytesIO(),
            decrypt_video=True,
            media_key="MEDIAKEY",
            **unsafe_bounds,
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


def test_copy_cloud_stream_to_mpegts_depacketizes_clear_rtp_video(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67h264-sps", marker=True)
    open_calls: list[tuple[str, str]] = []

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
                length=len(rtp_body),
                sequence=1,
                message_code=0,
                body=rtp_body,
            )

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec))
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
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
        raising=False,
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        ffmpeg_path="/usr/bin/ffmpeg",
        max_packets=1,
    )

    assert open_calls == [("/usr/bin/ffmpeg", "h264")]
    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_uses_idmx_codec_and_payload_descriptor(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    descriptor = b"\x45\x0a\x24\x61" + (b"\xff" * 8)
    rtp_bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(
            b"\x26\x01hevc",
            sequence=2,
            payload_type=97,
            marker=True,
        ),
    )
    open_calls: list[tuple[str, str]] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            for sequence, body in enumerate(rtp_bodies, start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec))
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
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=2)

    assert open_calls == [("ffmpeg", "hevc")]
    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


def test_cloud_rtp_audio_probe_uses_idmx_payload_descriptor() -> None:
    descriptor = b"\x45\x02\x0f\x69"
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(
            b"dynamic-aac",
            sequence=2,
            payload_type=105,
        ),
    )
    packets = tuple(
        VtmPacket(
            channel=VtmChannel.STREAM,
            length=len(body),
            sequence=sequence,
            message_code=0,
            body=body,
        )
        for sequence, body in enumerate(bodies, start=1)
    )

    assert cloud_rtp_packets_have_audio(packets)


def test_copy_cloud_stream_to_mpegts_reports_descriptor_codec(monkeypatch) -> None:
    client = _client()
    descriptor = b"\x45\x0a\xb1\x1a" + (b"\xff" * 8)
    rtp_bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(
            b"\xff\xd8\xff\xe0jpeg",
            sequence=2,
            payload_type=26,
            marker=True,
        ),
    )

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            for sequence, body in enumerate(rtp_bodies, start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )

    with pytest.raises(
        UnsupportedRtpVideoCodecError,
        match="advertised by IDMX metadata: mjpeg",
    ):
        copy_cloud_stream_to_mpegts(
            client,
            "CAM123",
            io.BytesIO(),
            max_packets=2,
        )


def test_copy_cloud_stream_to_mpegts_defers_codec_fallback_past_h264_aud(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_bodies = (
        _rtp_packet(b"\x09\xf0", sequence=1),
        _rtp_packet(b"\x67h264-sps", sequence=2, marker=True),
    )
    open_calls: list[tuple[str, str]] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            for sequence, body in enumerate(rtp_bodies, start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec))
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
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=2)

    assert open_calls == [("ffmpeg", "h264")]
    assert output.getvalue() == b"\x00\x00\x00\x01\x09\xf0" + H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_accepts_late_fallback_confirmation(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    video_packet_count = 32
    rtp_bodies = (
        *(
            _rtp_packet(
                b"\x67h264-sps",
                sequence=sequence,
                marker=True,
                timestamp=sequence * 3_000,
            )
            for sequence in range(1, video_packet_count + 1)
        ),
        _rtp_packet(
            b"metadata",
            sequence=video_packet_count + 1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x60",
        ),
    )

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(rtp_bodies)
            for sequence, body in enumerate(rtp_bodies, start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        assert (ffmpeg_path, codec) == ("ffmpeg", "h264")
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
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        max_packets=len(rtp_bodies),
    )

    assert output.getvalue() == H264_SPS_ANNEXB * video_packet_count


def test_copy_cloud_stream_to_mpegts_bounds_codec_probe_by_consumed_packets(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    audio_packet_count = 32

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == audio_packet_count + 1
            for sequence in range(1, audio_packet_count + 1):
                body = _rtp_packet(
                    b"audio",
                    sequence=sequence,
                    payload_type=104,
                )
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )
            video_body = _rtp_packet(
                b"\x67h264-sps",
                sequence=audio_packet_count + 1,
                marker=True,
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=len(video_body),
                sequence=audio_packet_count + 1,
                message_code=0,
                body=video_body,
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    with pytest.raises(PyEzvizError, match="Could not detect RTP video codec"):
        copy_cloud_stream_to_mpegts(
            client,
            "CAM123",
            output,
            max_packets=audio_packet_count + 1,
        )


def test_copy_cloud_stream_to_mpegts_bounds_successful_fallback_probe(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    probe_packet_count = 32
    open_calls: list[str] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets is None
            video_body = _rtp_packet(b"\x67h264-sps", marker=True)
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=len(video_body),
                sequence=1,
                message_code=0,
                body=video_body,
            )
            for sequence in range(2, probe_packet_count + 1):
                body = _rtp_packet(
                    b"audio",
                    sequence=sequence,
                    payload_type=104,
                )
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )
            assert open_calls == ["h264"]

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    def fake_open_remux(
        _ffmpeg_path: str,
        codec: str,
        **_kwargs: object,
    ) -> subprocess.Popen[bytes]:
        open_calls.append(codec)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output)

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_skips_empty_rtp_prelude_and_body(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67h264-sps", marker=True)

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 3
            for sequence, body in enumerate((EMPTY_BYTES, rtp_body, EMPTY_BYTES), start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=3)

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_skips_unknown_prelude_before_rtp(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67h264-sps", marker=True)

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            for sequence, body in enumerate((b"\x47control", rtp_body), start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=2)

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_skips_interleaved_non_rtp_body(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67h264-sps", marker=True)

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 2
            for sequence, body in enumerate((rtp_body, b"\x80control"), start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=2)

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_to_mpegts_accepts_ezviz_headerless_hevc_fu(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_bodies = (
        _rtp_packet(b"\x62\x01\x93start", sequence=1),
        _rtp_packet(b"\x62\x01\x26middle", sequence=2),
        _rtp_packet(b"\x62\x01\x66end", sequence=3, marker=True),
    )

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 3
            for sequence, body in enumerate(rtp_bodies, start=1):
                yield VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=len(body),
                    sequence=sequence,
                    message_code=0,
                    body=body,
                )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=3)

    assert output.getvalue() == HEVC_FU_ANNEXB


def test_copy_cloud_stream_to_mpegts_rejects_incomplete_rtp_video(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x62\x01\x93incomplete", sequence=1)

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
                length=len(rtp_body),
                sequence=1,
                message_code=0,
                body=rtp_body,
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    with pytest.raises(
        PyEzvizError,
        match="did not contain a complete video NAL unit",
    ):
        copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=1)

    assert output.getvalue() == EMPTY_BYTES


def test_decrypted_cloud_rtp_rejects_parameter_sets_without_complete_frame() -> None:
    """A short C8W-style capture must not publish an empty successful clip."""

    bodies = (
        _rtp_packet(b"\x40\x01vps", sequence=1),
        _rtp_packet(b"\x42\x01sps", sequence=2),
        _rtp_packet(b"\x44\x01pps", sequence=3),
        _rtp_packet(b"\x62\x01\x93partial", sequence=4),
    )
    packets = [
        VtmPacket(VtmChannel.STREAM, len(body), index, 0, body)
        for index, body in enumerate(bodies)
    ]
    output = io.BytesIO()

    with pytest.raises(EzvizNoMediaError, match="no complete video frame") as error:
        copy_decrypted_cloud_stream_packets_to_mpegts(
            packets, output, ffmpeg_path="ffmpeg", media_key="test-key"
        )

    assert error.value.reason == "no_media"
    assert output.getvalue() == EMPTY_BYTES


def test_decrypted_cloud_rtp_rejects_unmarked_slice_from_unfinished_picture() -> None:
    body = _rtp_packet(b"\x61complete-slice", marker=False)
    packet = VtmPacket(VtmChannel.STREAM, len(body), 1, 0, body)
    output = io.BytesIO()

    with pytest.raises(EzvizNoMediaError, match="no complete video frame"):
        copy_decrypted_cloud_stream_packets_to_mpegts(
            (packet,), output, ffmpeg_path="ffmpeg", media_key="test-key"
        )

    assert output.getvalue() == EMPTY_BYTES


def test_copy_cloud_stream_to_mpegts_passes_through_mpegts(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    mpegts_body = b"\x47\x00\x00\x10" + bytes(184)

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
                length=len(mpegts_body),
                sequence=1,
                message_code=0,
                body=mpegts_body,
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_mpegts_remux_process",
        lambda *_args, **_kwargs: pytest.fail("MPEG-TS input must not be remuxed"),
    )

    copy_cloud_stream_to_mpegts(client, "CAM123", output, max_packets=1)

    assert output.getvalue() == mpegts_body


def test_copy_cloud_stream_to_mpegps_rejects_rtp_transport(monkeypatch) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67h264-sps", marker=True)

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
                length=len(rtp_body),
                sequence=1,
                message_code=0,
                body=rtp_body,
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )

    with pytest.raises(PyEzvizError, match="RTP/IDMX, not MPEG-PS"):
        copy_cloud_stream_to_mpegps(client, "CAM123", output, max_packets=1)

    assert output.getvalue() == EMPTY_BYTES

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
        def __init__(self) -> None:
            class RecordingInput(io.BytesIO):
                def close(self) -> None:
                    if self.closed:
                        return
                    calls["remux_input"] = self.getvalue()
                    super().close()

            self.stdin = RecordingInput()
            self.stdout = io.BytesIO(expected_payload)
            self.stderr = io.BytesIO()
            self.returncode = 0

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return self.returncode

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            return None


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

    def fake_get_cam_key(
        serial: str,
        *,
        smscode: str | int | None = None,
    ) -> str:
        calls["get_cam_key"] = {"serial": serial, "smscode": smscode}
        return "camera-secret"

    monkeypatch.setattr(client, "get_cam_key", fake_get_cam_key)
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
        smscode="654321",
        nalu_header_size=2,
    )

    assert calls == {
        "get_cam_key": {"serial": "CAM123", "smscode": "654321"},
        "decrypt": {"data": b"enc", "key": "camera-secret", "nalu_header_size": 2},
        "remux_input": b"clear",
    }
    assert output.getvalue() == expected_payload


def test_copy_cloud_stream_to_mpegts_decrypts_rtp_video_before_remux(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x61\x80encrypted-h264", marker=True)
    decrypt_calls: list[tuple[bytes, str | bytes, int | None]] = []
    open_calls: list[tuple[str, str]] = []

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == 3
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=len(b"vtm-prelude"),
                sequence=1,
                message_code=0,
                body=b"vtm-prelude",
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=len(rtp_body),
                sequence=2,
                message_code=0,
                body=rtp_body,
            )
            yield VtmPacket(
                channel=VtmChannel.STREAM,
                length=len(b"\x80control"),
                sequence=3,
                message_code=0,
                body=b"\x80control",
            )

    def fake_decrypt(
        data: bytes,
        key: str | bytes,
        *,
        nalu_header_size: int | None,
    ) -> bytes:
        decrypt_calls.append((data, key, nalu_header_size))
        return data[:9] + CLEAR_ANNEXB

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec))
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
        "pyezvizapi.cloud_stream.decrypt_hikvision_ps_video",
        fake_decrypt,
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        ffmpeg_path="ffmpeg-custom",
        max_packets=3,
        decrypt_video=True,
        media_key="MEDIAKEY",
    )

    expected_annexb = b"\x00\x00\x00\x01\x61\x80encrypted-h264"
    assert decrypt_calls == [
        (
            b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + expected_annexb,
            "MEDIAKEY",
            1,
        )
    ]
    assert open_calls == [("ffmpeg-custom", "h264")]
    assert output.getvalue() == CLEAR_ANNEXB


def test_bounded_cloud_decrypt_discards_conflicting_predescriptor_video(
    monkeypatch,
) -> None:
    expected_annexb = b"\x00\x00\x00\x01\x26\x01\x80new-hevc-idr"
    bodies = (
        _rtp_packet(b"\x67old-h264-sps", sequence=1, payload_type=97),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x0a\x24\x61" + (b"\xff" * 8),
        ),
        _rtp_packet(
            b"\x26\x01\x80new-hevc-idr",
            sequence=3,
            payload_type=97,
            marker=True,
        ),
    )
    packets = [
        VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)
        for sequence, body in enumerate(bodies, start=1)
    ]
    open_calls: list[tuple[str, str]] = []

    monkeypatch.setattr(
        cloud_stream_module,
        "decrypt_hikvision_ps_video",
        lambda data, *_args, **_kwargs: data,
    )

    def fake_open_remux(ffmpeg_path: str, codec: str) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec))
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_decrypted_cloud_stream_packets_to_mpegts(
        packets,
        output,
        ffmpeg_path="ffmpeg-custom",
        media_key="MEDIAKEY",
        transport=StreamTransport.RTP,
    )

    assert open_calls == [("ffmpeg-custom", "hevc")]
    assert output.getvalue() == expected_annexb


def test_cloud_packet_iterator_bounds_from_request_start() -> None:
    class RecordingStream(VtmStreamClient):
        def __init__(self) -> None:
            super().__init__("ysproto://example.invalid/live")
            self.kwargs: dict[str, Any] = {}

        def iter_packets(self, **kwargs: Any) -> Any:
            self.kwargs = kwargs
            return iter(())

    stream = RecordingStream()
    monotonic = lambda: 10.0  # noqa: E731

    assert list(
        cloud_stream_module._iter_bounded_cloud_packets(  # noqa: SLF001
            stream,
            max_packets=4,
            duration_seconds=8.0,
            first_packet_timeout=3.0,
            monotonic=monotonic,
        )
    ) == []
    assert stream.kwargs == {
        "max_packets": 4,
        "duration_seconds": 8.0,
        "duration_from_start": True,
        "first_packet_timeout": 3.0,
        "monotonic": monotonic,
    }


def test_vtm_stream_packet_inactivity_ignores_control_keepalives() -> None:
    clock = [0.0]

    class ControlOnlyStream(VtmStreamClient):
        def __init__(self) -> None:
            super().__init__("ysproto://example.invalid/live")
            self.read_count = 0

        def read_packet(self, **_kwargs: Any) -> VtmPacket:
            clock[0] += 1.0
            self.read_count += 1
            return VtmPacket(VtmChannel.MESSAGE, 0, self.read_count, 0, b"")

    stream = ControlOnlyStream()
    assert list(
        stream.iter_packets(
            stream_packet_timeout_seconds=2.0,
            keepalive_interval=None,
            monotonic=lambda: clock[0],
        )
    ) == []
    assert stream.read_count == 2


def test_cloud_stream_start_uses_configured_timeout_as_overall_deadline() -> None:
    class RecordingStream(VtmStreamClient):
        def __init__(self) -> None:
            super().__init__("ysproto://example.invalid/live")
            self.kwargs: dict[str, Any] = {}

        def start(self, **kwargs: Any) -> Any:
            self.kwargs = kwargs
            return SimpleNamespace()

    stream = RecordingStream()
    monotonic = lambda: 100.0  # noqa: E731

    cloud_stream_module._start_bounded_cloud_stream(  # noqa: SLF001
        stream,
        timeout=15.0,
        duration_seconds=8.0,
        monotonic=monotonic,
    )

    assert stream.kwargs == {"deadline": 115.0, "monotonic": monotonic}


@pytest.mark.parametrize(
    ("timeout", "duration_seconds", "expected_connect_timeout"),
    ((15.0, 8.0, 15.0), (None, 8.0, 8.0)),
)
def test_cloud_stream_start_bounds_initial_connect(
    timeout: float | None,
    duration_seconds: float,
    expected_connect_timeout: float,
) -> None:
    response = encode_vtm_packet(
        b"\x08\x00\x22\x07ssn-123\x2a\x05key-1",
        message_code=VtmMessageCode.STREAMINFO_RSP,
    )
    connect_timeouts: list[float | None] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.buffer = response
            self.timeout: float | None = None
            self.closed = False

        def gettimeout(self) -> float | None:
            return self.timeout

        def settimeout(self, value: float | None) -> None:
            self.timeout = value

        def sendall(self, _data: bytes) -> None:
            return None

        def recv(self, size: int) -> bytes:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk

        def close(self) -> None:
            self.closed = True

    fake_socket = FakeSocket()

    def socket_factory(
        _address: tuple[str, int],
        selected_timeout: float | None,
    ) -> FakeSocket:
        connect_timeouts.append(selected_timeout)
        return fake_socket

    stream = VtmStreamClient(
        "ysproto://example.invalid:8554/live",
        timeout=timeout,
        socket_factory=socket_factory,
    )
    monotonic = lambda: 100.0  # noqa: E731

    with cloud_stream_module._closing_unconnected_cloud_stream(stream):  # noqa: SLF001
        cloud_stream_module._start_bounded_cloud_stream(  # noqa: SLF001
            stream,
            timeout=timeout,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )

    assert connect_timeouts == [expected_connect_timeout]
    assert fake_socket.closed


def test_cloud_copy_reuses_startup_deadline_for_first_media(
    monkeypatch,
) -> None:
    expected_deadline = 110.0

    class Clock:
        now = 100.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()

    class SlowNegotiationStream(VtmStreamClient):
        def __init__(self) -> None:
            super().__init__("ysproto://example.invalid/live", timeout=10.0)
            self.start_deadline: float | None = None
            self.iterator_kwargs: dict[str, Any] = {}

        def start(self, **kwargs: Any) -> Any:
            self.start_deadline = kwargs["deadline"]
            clock.now = 109.0
            return SimpleNamespace()

        def iter_packets(self, **kwargs: Any) -> Any:
            self.iterator_kwargs = kwargs
            return iter(())

    stream = SlowNegotiationStream()
    monkeypatch.setattr(
        cloud_stream_module,
        "open_cloud_stream",
        lambda *_args, **_kwargs: stream,
    )

    copy_cloud_stream_to_mpegps(
        _client(),
        "CAM123",
        io.BytesIO(),
        timeout=10.0,
        duration_seconds=30.0,
        max_packets=1,
        monotonic=clock,
    )

    assert stream.start_deadline == expected_deadline
    assert stream.iterator_kwargs["first_packet_deadline"] == expected_deadline
    assert stream.iterator_kwargs["first_packet_timeout"] is None


def test_unconnected_cloud_stream_context_closes_after_start_failure() -> None:
    class FailingStream:
        closed = False

        def start(self) -> None:
            raise PyEzvizError("startup failed")

        def close(self) -> None:
            self.closed = True

    stream = FailingStream()

    with (
        pytest.raises(PyEzvizError, match="startup failed"),
        cloud_stream_module._closing_unconnected_cloud_stream(stream),  # noqa: SLF001
    ):
        cloud_stream_module._start_bounded_cloud_stream(  # noqa: SLF001
            stream,
            timeout=3.0,
            duration_seconds=8.0,
            monotonic=lambda: 100.0,
        )

    assert stream.closed


def test_cloud_packet_iterator_bounds_first_media_for_packet_only_capture() -> None:
    stream_timeout = 15.0

    class RecordingStream(VtmStreamClient):
        def __init__(self) -> None:
            super().__init__("ysproto://example.invalid/live", timeout=stream_timeout)
            self.kwargs: dict[str, Any] = {}

        def iter_packets(self, **kwargs: Any) -> Any:
            self.kwargs = kwargs
            return iter(())

    stream = RecordingStream()
    monotonic = lambda: 100.0  # noqa: E731

    assert list(
        cloud_stream_module._iter_bounded_cloud_packets(  # noqa: SLF001
            stream,
            max_packets=4,
            duration_seconds=None,
            monotonic=monotonic,
        )
    ) == []
    assert stream.kwargs["first_packet_timeout"] == stream_timeout


def test_copy_cloud_stream_to_mpegts_decrypts_rtp_aac_before_av_remux(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    media_key = b"0123456789abcdef"
    sample_rate = 16_000
    descriptor = bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            sample_rate >> 14,
            (sample_rate >> 6) & 0xFF,
            ((sample_rate & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    plain_audio = b"0123456789abcdef" + b"tail"
    encrypted_audio = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain_audio[16:]

    def rtp_with_extension(
        payload: bytes,
        *,
        sequence: int,
        payload_type: int,
        extension_profile: int,
        extension_data: bytes,
    ) -> bytes:
        return (
            b"\x90"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
            + b"\x55\x66\x77\x88"
            + extension_profile.to_bytes(2, "big")
            + (len(extension_data) // 4).to_bytes(2, "big")
            + extension_data
            + payload
        )

    bodies = (
        rtp_with_extension(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(b"\x61\x80encrypted-h264", sequence=2, marker=True),
        rtp_with_extension(
            b"\x00\x10"
            + (len(encrypted_audio) << 3).to_bytes(2, "big")
            + encrypted_audio,
            sequence=3,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
        ),
    )

    class FakeCloudStream:
        def __enter__(self) -> FakeCloudStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def start(self) -> None:
            return None

        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

    remux_calls: list[dict[str, Any]] = []

    def fake_decrypt(
        data: bytes,
        _key: str | bytes,
        *,
        nalu_header_size: int | None,
    ) -> bytes:
        assert nalu_header_size == 1
        return data[:9] + CLEAR_ANNEXB

    def fake_av_remux(
        video: bytes,
        audio: Any,
        selected_output: BinaryIO,
        *,
        ffmpeg_path: str,
        codec: str,
    ) -> None:
        remux_calls.append(
            {
                "video": video,
                "audio": audio,
                "ffmpeg_path": ffmpeg_path,
                "codec": codec,
            }
        )
        selected_output.write(AV_MPEGTS_PAYLOAD)

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.decrypt_hikvision_ps_video",
        fake_decrypt,
    )
    monkeypatch.setattr(
        "pyezvizapi.cloud_stream._remux_cloud_elementary_av_bytes_to_mpegts",
        fake_av_remux,
        raising=False,
    )

    copy_cloud_stream_to_mpegts(
        client,
        "CAM123",
        output,
        ffmpeg_path="ffmpeg-custom",
        max_packets=len(bodies),
        decrypt_video=True,
        media_key=media_key,
    )

    assert output.getvalue() == AV_MPEGTS_PAYLOAD
    assert len(remux_calls) == 1
    assert remux_calls[0]["video"] == CLEAR_ANNEXB
    assert remux_calls[0]["audio"].sample_rate == sample_rate
    assert remux_calls[0]["audio"].channels == 1
    assert remux_calls[0]["audio"].frame_count == 1
    assert remux_calls[0]["audio"].adts.endswith(plain_audio)
    assert remux_calls[0]["ffmpeg_path"] == "ffmpeg-custom"
    assert remux_calls[0]["codec"] == "h264"


def test_copy_cloud_stream_packets_to_mpegts_streams_rtp_aac_to_second_input(
    monkeypatch,
) -> None:
    media_key = b"0123456789abcdef"
    sample_rate = 16_000
    audio_descriptor = bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            sample_rate >> 14,
            (sample_rate >> 6) & 0xFF,
            ((sample_rate & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    descriptor = (
        b"\x45\x02\x90\x68"
        + audio_descriptor
    )
    plain_audio = b"0123456789abcdef" + b"tail"
    encrypted_audio = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain_audio[16:]

    def rtp_with_extension(
        payload: bytes,
        *,
        sequence: int,
        payload_type: int,
        extension_profile: int,
        extension_data: bytes,
        timestamp: int = 0,
    ) -> bytes:
        return (
            b"\x90"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + extension_profile.to_bytes(2, "big")
            + (len(extension_data) // 4).to_bytes(2, "big")
            + extension_data
            + payload
        )

    bodies = (
        rtp_with_extension(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(b"\x67h264-sps", sequence=2, marker=True),
        rtp_with_extension(
            b"\x00\x10"
            + (len(encrypted_audio) << 3).to_bytes(2, "big")
            + encrypted_audio,
            sequence=3,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
        ),
        rtp_with_extension(
            b"\x00\x10\x00\x08malformed-aac",
            sequence=4,
            payload_type=105,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
        ),
        _rtp_packet(
            b"metadata",
            sequence=5,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x0f\x69",
        ),
        rtp_with_extension(
            b"\x00\x10"
            + (len(encrypted_audio) << 3).to_bytes(2, "big")
            + encrypted_audio,
            sequence=5,
            payload_type=105,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
            timestamp=1024,
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    audio_inputs: list[Any] = []
    decrypt_calls: list[tuple[int, frozenset[int] | None]] = []
    decrypt_aac = cloud_stream_module.decrypt_idmx_aac_packets

    def tracked_decrypt_aac(packets: Any, *args: Any, **kwargs: Any) -> Any:
        packet_list = list(packets)
        decrypt_calls.append(
            (packet_list[0].payload_type, kwargs.get("audio_payload_types"))
        )
        return decrypt_aac(packet_list, *args, **kwargs)

    class FakeAudioInput:
        url = "tcp://127.0.0.1:43210"

        def __init__(self) -> None:
            self.started = False
            self.chunks: list[bytes] = []
            self.closed = False
            self.cancelled = False
            self.finish_calls: list[bool] = []
            audio_inputs.append(self)

        def start(self) -> None:
            self.started = True

        def write(self, data: bytes) -> None:
            self.chunks.append(data)

        def close_input(self) -> None:
            self.closed = True

        def cancel(self) -> None:
            self.cancelled = True

        def finish(self, *, raise_errors: bool) -> None:
            self.finish_calls.append(raise_errors)

    open_calls: list[tuple[str, str, str | None]] = []

    def fake_open_remux(
        ffmpeg_path: str,
        codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        open_calls.append((ffmpeg_path, codec, audio_url))
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(cloud_stream_module, "_CloudRtpAudioInput", FakeAudioInput)
    monkeypatch.setattr(
        cloud_stream_module,
        "decrypt_idmx_aac_packets",
        tracked_decrypt_aac,
    )
    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg-custom",
        max_packets=len(bodies),
        rtp_audio_key=media_key,
    )

    assert output.getvalue() == H264_SPS_ANNEXB
    assert open_calls == [
        ("ffmpeg-custom", "h264", "tcp://127.0.0.1:43210")
    ]
    assert len(audio_inputs) == 1
    assert audio_inputs[0].started is True
    assert audio_inputs[0].closed is True
    assert audio_inputs[0].finish_calls == [True]
    assert (105, frozenset({105})) in decrypt_calls
    assert len(audio_inputs[0].chunks) == 1
    assert all(chunk.endswith(plain_audio) for chunk in audio_inputs[0].chunks)


def test_copy_cloud_stream_packets_accepts_late_aac_fallback_confirmation(
    monkeypatch,
) -> None:
    audio_profile = bytes((0x43, 10, 0, 1, 2, 0, 250, 3, 0, 0, 3, 0xFF))
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x60" + audio_profile,
        ),
        _rtp_packet(b"aac", sequence=2, payload_type=104),
        _rtp_packet(b"\x67h264-sps", sequence=3, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=4,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x0f\x68",
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    class FakeAudioInput:
        url = "tcp://127.0.0.1:43210"

        def start(self) -> None:
            return None

        def write(self, _data: bytes) -> None:
            return None

        def close_input(self) -> None:
            return None

        def cancel(self) -> None:
            return None

        def finish(self, *, raise_errors: bool) -> None:
            return None

    def fake_decrypt(candidates: Any, *_args: Any, **_kwargs: Any) -> Any:
        candidate = next(iter(candidates))
        if candidate.payload_type != 104:
            return None
        return SimpleNamespace(
            adts=b"adts",
            sample_rate=16_000,
            channels=1,
            frame_count=1,
        )

    monkeypatch.setattr(cloud_stream_module, "_CloudRtpAudioInput", FakeAudioInput)
    monkeypatch.setattr(cloud_stream_module, "decrypt_idmx_aac_packets", fake_decrypt)
    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_packets_accepts_undispatched_late_audio_route(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x60",
        ),
        _rtp_packet(b"\x67h264-sps", sequence=2, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x0f\x68",
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"unused",
    )

    assert output.getvalue() == H264_SPS_ANNEXB


@pytest.mark.parametrize("reassigned_payload_type", [32, 96])
def test_copy_cloud_stream_packets_waits_for_delayed_payload_routes(
    monkeypatch,
    reassigned_payload_type: int,
) -> None:
    descriptor = bytes(
        (
            0x45,
            0x02,
            0x90,
            reassigned_payload_type,
            0x45,
            0x02,
            0x1B,
            0x61,
        )
    )
    bodies = (
        _rtp_packet(
            b"g711-alaw",
            sequence=1,
            payload_type=reassigned_payload_type,
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(b"\x67h264-sps", sequence=3, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_packets_rejects_midstream_route_mutation(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(b"\x67h264-sps", sequence=2, payload_type=97, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )

    with pytest.raises(PyEzvizError, match="RTP route mutation after media began"):
        copy_cloud_stream_packets_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            ffmpeg_path="ffmpeg",
            max_packets=len(bodies),
        )


def test_copy_cloud_stream_packets_accepts_predispatch_video_codec_correction(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
        _rtp_packet(b"\x26\x01hevc", sequence=3, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    open_calls: list[str] = []

    def fake_open_remux(
        _ffmpeg_path: str,
        codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        assert audio_url is None
        open_calls.append(codec)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert open_calls == ["hevc"]
    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


def test_cloud_rtp_startup_deadline_reports_no_routed_video() -> None:
    body = _rtp_packet(b"metadata", sequence=1, payload_type=112)

    class MetadataOnlyStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets is None
            for sequence in range(1, 10):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    ticks = iter((0.0, 1.0, 2.0))
    with pytest.raises(EzvizNoMediaError, match="no routed video") as error:
        copy_cloud_stream_packets_to_mpegts(
            MetadataOnlyStream(),
            io.BytesIO(),
            ffmpeg_path="ffmpeg",
            max_packets=None,
            startup_timeout_seconds=1.5,
            monotonic=lambda: next(ticks),
        )

    assert error.value.reason == "no_media"


def test_copy_cloud_stream_packets_probes_until_first_routed_video(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
        _rtp_packet(b"\x26\x01hevc", sequence=3, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    open_calls: list[str] = []

    def fake_open_remux(
        _ffmpeg_path: str,
        codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        assert audio_url is None
        open_calls.append(codec)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert open_calls == ["hevc"]
    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


def test_copy_cloud_stream_packets_falls_back_when_descriptor_route_absent(
    monkeypatch,
) -> None:
    bodies = [
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x0f",
        )
    ]
    bodies.extend(
        _rtp_packet(
            b"\x40\x01vps",
            sequence=sequence,
            payload_type=96,
            marker=True,
        )
        for sequence in range(2, 35)
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    expected_nal = b"\x00\x00\x00\x01\x40\x01vps"
    assert output.getvalue() == expected_nal * 33


def test_copy_cloud_stream_packets_bounds_missing_routed_video() -> None:
    probe_packet_limit = 64
    bodies = [
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    ]
    bodies.extend(
        _rtp_packet(
            b"metadata",
            sequence=sequence,
            payload_type=112,
        )
        for sequence in range(2, probe_packet_limit + 1)
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets is None
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    with pytest.raises(
        PyEzvizError,
        match="did not include media on its video route",
    ):
        copy_cloud_stream_packets_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            ffmpeg_path="ffmpeg",
            max_packets=None,
        )


def test_copy_cloud_stream_packets_ignores_static_video_during_route_probe() -> None:
    probe_packet_limit = 64
    bodies = [
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    ]
    bodies.extend(
        _rtp_packet(
            b"\xff\xd8foreign-mjpeg",
            sequence=sequence,
            payload_type=26,
            marker=True,
        )
        for sequence in range(2, probe_packet_limit + 1)
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets is None
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    with pytest.raises(
        PyEzvizError,
        match="did not include media on its video route",
    ):
        copy_cloud_stream_packets_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            ffmpeg_path="ffmpeg",
            max_packets=None,
        )


def test_copy_cloud_stream_packets_revalidates_buffered_video_probe(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(b"\x67stale-fallback", sequence=1),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x90\x60\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
        _rtp_packet(b"\x26\x01hevc", sequence=4, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    open_calls: list[str] = []

    def fake_open_remux(
        _ffmpeg_path: str,
        codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        assert audio_url is None
        open_calls.append(codec)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert open_calls == ["hevc"]
    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


@pytest.mark.parametrize("descriptor_on_sei", [False, True])
def test_copy_cloud_stream_packets_preserves_ambiguous_h264_route_epoch(
    monkeypatch,
    descriptor_on_sei: bool,
) -> None:
    descriptor = b"\x45\x02\x1b\x61"
    sei = _rtp_packet(
        b"\x06\x05captions",
        sequence=1,
        payload_type=97,
        extension_profile=1 if descriptor_on_sei else None,
        extension_data=descriptor if descriptor_on_sei else b"",
    )
    bodies = [sei]
    if not descriptor_on_sei:
        bodies.append(
            _rtp_packet(
                b"metadata",
                sequence=2,
                payload_type=112,
                extension_profile=1,
                extension_data=descriptor,
            )
        )
    bodies.append(
        _rtp_packet(
            b"\x67h264-sps",
            sequence=len(bodies) + 1,
            payload_type=97,
            marker=True,
        )
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert output.getvalue() == b"\x00\x00\x00\x01\x06\x05captions" + H264_SPS_ANNEXB


def test_copy_cloud_stream_packets_keeps_epochs_with_buffered_packets(
    monkeypatch,
) -> None:
    expected_annexb = (
        b"\x00\x00\x00\x01\x02\x01ordinary-hevc"
        b"\x00\x00\x00\x01\x26\x01hevc-irap"
    )
    bodies = (
        _rtp_packet(
            b"\x06stale-h264",
            sequence=1,
            payload_type=97,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x0f\x61",
        ),
        _rtp_packet(
            b"\x02\x01ordinary-hevc",
            sequence=3,
            payload_type=98,
        ),
        _rtp_packet(
            b"metadata",
            sequence=4,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x62",
        ),
        _rtp_packet(
            b"\x26\x01hevc-irap",
            sequence=5,
            payload_type=98,
            marker=True,
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(cloud_stream_module, "id", lambda _packet: 1, raising=False)
    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"unused",
    )

    assert output.getvalue() == expected_annexb


def test_copy_cloud_stream_packets_rejects_ambiguous_h264_before_hevc_route(
    monkeypatch,
) -> None:
    expected_annexb = b"\x00\x00\x00\x01\x26\x01hevc"
    bodies = (
        _rtp_packet(
            b"\x22\x01stale-h264",
            sequence=1,
            payload_type=97,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
        _rtp_packet(
            b"\x26\x01hevc",
            sequence=3,
            payload_type=97,
            marker=True,
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"unused",
    )

    assert output.getvalue() == expected_annexb


def test_copy_cloud_stream_packets_rejects_known_nonvideo_before_h264_route(
    monkeypatch,
) -> None:
    expected_annexb = b"\x00\x00\x00\x01\x65h264"
    bodies = (
        _rtp_packet(
            b"\x65stale-nonvideo",
            sequence=1,
            payload_type=97,
            extension_profile=1,
            extension_data=b"\x45\x02\xaf\x61",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(
            b"\x65h264",
            sequence=3,
            payload_type=97,
            marker=True,
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert output.getvalue() == expected_annexb


@pytest.mark.parametrize("static_payload_type", [26, 32, 99])
def test_copy_cloud_stream_packets_ignores_static_video_outside_selected_route(
    monkeypatch,
    static_payload_type: int,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        ),
        _rtp_packet(b"\x67h264-sps", sequence=2, payload_type=97, marker=True),
        _rtp_packet(
            b"\x65foreign-static-video",
            sequence=3,
            payload_type=static_payload_type,
            marker=True,
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
    )

    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_packets_refreshes_corrected_audio_metadata(
    monkeypatch,
) -> None:
    def audio_descriptor(sample_rate: int) -> bytes:
        return bytes(
            (
                0x43,
                10,
                0,
                1,
                2,
                sample_rate >> 14,
                (sample_rate >> 6) & 0xFF,
                ((sample_rate & 0x3F) << 2) | 3,
                0,
                0,
                3,
                0xFF,
            )
        )

    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=(
                b"\x45\x02\x1b\x61\x45\x02\x0f\x69" + audio_descriptor(8_000)
            ),
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=audio_descriptor(16_000),
        ),
        _rtp_packet(b"audio", sequence=3, payload_type=105),
        _rtp_packet(
            b"metadata",
            sequence=4,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x90\x69",
        ),
        _rtp_packet(b"\x67h264-sps", sequence=5, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    metadata_calls: list[tuple[int, int] | None] = []

    def fake_decrypt(candidates: Any, *_args: Any, **kwargs: Any) -> Any:
        metadata_calls.append(kwargs["audio_metadata"])
        candidate = next(iter(candidates))
        if candidate.payload_type in kwargs["audio_payload_types"]:
            return object()
        return None

    monkeypatch.setattr(cloud_stream_module, "decrypt_idmx_aac_packets", fake_decrypt)
    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **kwargs: (
            pytest.fail("stale AAC route started an audio input")
            if kwargs.get("audio_url") is not None
            else subprocess.Popen(
                ["cat"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert metadata_calls
    assert set(metadata_calls) == {(16_000, 1)}
    assert output.getvalue() == H264_SPS_ANNEXB


def test_copy_cloud_stream_packets_replays_buffered_video_before_correction(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
        ),
        _rtp_packet(b"\x26\x01hevc", sequence=2, payload_type=97, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    open_calls: list[str] = []

    def fake_open_remux(
        _ffmpeg_path: str,
        codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        assert audio_url is None
        open_calls.append(codec)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert open_calls == ["hevc"]
    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


def test_copy_cloud_stream_packets_discards_buffered_video_before_codec_correction(
    monkeypatch,
) -> None:
    bodies = (
        _rtp_packet(b"\x41\xe1stale-h264", sequence=1, payload_type=97, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        ),
        _rtp_packet(b"\x26\x01hevc", sequence=3, payload_type=97, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        lambda *_args, **_kwargs: subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ),
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert output.getvalue() == HEVC_DESCRIPTOR_ANNEXB


def test_copy_cloud_stream_packets_to_mpegts_ignores_invalid_rtp_audio(
    monkeypatch,
) -> None:
    sample_rate = 16_000
    descriptor = bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            sample_rate >> 14,
            (sample_rate >> 6) & 0xFF,
            ((sample_rate & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    bodies = (
        _rtp_packet(b"\x67h264-sps", sequence=1, marker=True),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(
            b"not-rfc3640-aac",
            sequence=3,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
        ),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    open_calls: list[str | None] = []

    def fake_open_remux(
        _ffmpeg_path: str,
        _codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        open_calls.append(audio_url)
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg-custom",
        max_packets=len(bodies),
        rtp_audio_key=b"0123456789abcdef",
    )

    assert output.getvalue() == H264_SPS_ANNEXB
    assert open_calls == [None]


def test_copy_cloud_stream_packets_to_mpegts_bounds_video_only_audio_probe(
    monkeypatch,
) -> None:
    probe_limit = cloud_stream_module._RTP_AUDIO_PROBE_MAX_PACKETS  # noqa: SLF001
    process_opened = False

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == probe_limit + 1
            for sequence in range(1, probe_limit + 2):
                if sequence > probe_limit:
                    assert process_opened is True
                body = _rtp_packet(
                    b"\x67h264-sps",
                    sequence=sequence,
                    marker=True,
                )
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    def fake_open_remux(
        _ffmpeg_path: str,
        _codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        nonlocal process_opened
        assert audio_url is None
        process_opened = True
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        io.BytesIO(),
        ffmpeg_path="ffmpeg-custom",
        max_packets=probe_limit + 1,
        rtp_audio_key=b"0123456789abcdef",
    )

    assert process_opened is True


def test_copy_cloud_stream_packets_to_mpegts_keeps_video_after_aac_gap(
    monkeypatch,
) -> None:
    media_key = b"0123456789abcdef"
    sample_rate = 16_000
    descriptor = b"\x45\x02\x1b\x60\x45\x02\x0f\x68" + bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            sample_rate >> 14,
            (sample_rate >> 6) & 0xFF,
            ((sample_rate & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    changed_descriptor = b"\x45\x02\x90\x68" + bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            8_000 >> 14,
            (8_000 >> 6) & 0xFF,
            ((8_000 & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    plain_audio = b"0123456789abcdef" + b"tail"
    encrypted_audio = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain_audio[16:]
    audio_payload = (
        b"\x00\x10"
        + (len(encrypted_audio) << 3).to_bytes(2, "big")
        + encrypted_audio
    )
    audio_extension = b"\x80\x06\x00\x01\x21\x21\x02\x01"
    bodies = (
        _rtp_packet(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        ),
        _rtp_packet(b"\x67h264-sps", sequence=2, marker=True),
        _rtp_packet(
            audio_payload,
            sequence=3,
            timestamp=0,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=audio_extension,
        ),
        _rtp_packet(
            audio_payload,
            sequence=5,
            timestamp=2048,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=audio_extension,
        ),
        _rtp_packet(
            b"metadata",
            sequence=6,
            payload_type=112,
            extension_profile=1,
            extension_data=changed_descriptor,
        ),
        _rtp_packet(b"\x68h264-pps", sequence=7, marker=True),
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Any:
            assert max_packets == len(bodies)
            for sequence, body in enumerate(bodies, start=1):
                yield VtmPacket(VtmChannel.STREAM, len(body), sequence, 0, body)

        def close(self) -> None:
            return None

    audio_inputs: list[Any] = []

    class FakeAudioInput:
        url = "tcp://127.0.0.1:43210"

        def __init__(self) -> None:
            self.chunks: list[bytes] = []
            self.close_calls = 0
            self.finish_calls: list[bool] = []
            audio_inputs.append(self)

        def start(self) -> None:
            return None

        def write(self, data: bytes) -> None:
            self.chunks.append(data)

        def close_input(self) -> None:
            self.close_calls += 1

        def cancel(self) -> None:
            return None

        def finish(self, *, raise_errors: bool) -> None:
            self.finish_calls.append(raise_errors)

    def fake_open_remux(
        _ffmpeg_path: str,
        _codec: str,
        *,
        audio_url: str | None = None,
    ) -> subprocess.Popen[bytes]:
        assert audio_url == FakeAudioInput.url
        return subprocess.Popen(
            ["cat"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    monkeypatch.setattr(cloud_stream_module, "_CloudRtpAudioInput", FakeAudioInput)
    monkeypatch.setattr(
        cloud_stream_module,
        "_open_cloud_elementary_mpegts_remux_process",
        fake_open_remux,
    )
    output = io.BytesIO()

    copy_cloud_stream_packets_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path="ffmpeg-custom",
        max_packets=len(bodies),
        rtp_audio_key=media_key,
    )

    assert output.getvalue() == H264_SPS_ANNEXB + b"\x00\x00\x00\x01\x68h264-pps"
    assert len(audio_inputs) == 1
    assert len(audio_inputs[0].chunks) == 1
    assert audio_inputs[0].close_calls >= 1
    assert audio_inputs[0].finish_calls == [False]


def test_cloud_rtp_audio_input_streams_and_cancels_active_connection() -> None:
    audio_input = cloud_stream_module._CloudRtpAudioInput()  # noqa: SLF001
    host, port_text = audio_input.url.removeprefix("tcp://").rsplit(":", 1)
    audio_input.start()
    with socket.create_connection((host, int(port_text)), timeout=1.0) as connection:
        audio_input.write(AAC_FRAME)
        assert connection.recv(len(AAC_FRAME)) == AAC_FRAME
        audio_input.cancel()
        assert connection.recv(1) == EMPTY_BYTES
    audio_input.finish(raise_errors=False)


def test_cloud_rtp_audio_input_bounds_stalled_consumer(monkeypatch) -> None:
    monkeypatch.setattr(cloud_stream_module, "_RTP_AUDIO_QUEUE_MAX_FRAMES", 1)
    monkeypatch.setattr(cloud_stream_module, "_RTP_AUDIO_QUEUE_TIMEOUT_SECONDS", 0.0)
    audio_input = cloud_stream_module._CloudRtpAudioInput()  # noqa: SLF001
    audio_input.start()
    audio_input.write(b"queued")

    with pytest.raises(PyEzvizError, match="stopped consuming"):
        audio_input.write(b"blocked")

    audio_input.finish(raise_errors=False)


def test_copy_cloud_stream_to_mpegps_rejects_decrypted_rtp_transport(
    monkeypatch,
) -> None:
    client = _client()
    output = io.BytesIO()
    rtp_body = _rtp_packet(b"\x67encrypted-h264", marker=True)

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
                length=len(rtp_body),
                sequence=1,
                message_code=0,
                body=rtp_body,
            )

    monkeypatch.setattr(
        "pyezvizapi.cloud_stream.open_cloud_stream",
        lambda *_args, **_kwargs: FakeCloudStream(),
    )

    with pytest.raises(PyEzvizError, match="RTP/IDMX, not MPEG-PS"):
        copy_cloud_stream_to_mpegps(
            client,
            "CAM123",
            output,
            max_packets=1,
            decrypt_video=True,
            media_key="MEDIAKEY",
        )

    assert output.getvalue() == EMPTY_BYTES

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
            "stderr": subprocess.PIPE,
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
