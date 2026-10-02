"""Tests for local IDMX/RTP parsing, codec routing, and packet reconstruction."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import io
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi._local_stream import (
    _decrypt_idmx_local_packets_to_adts_aac,
    _h264_annexb_packet_end_offsets,
    _hcnetsdk_command_port_media_packet,
    _hcnetsdk_command_port_media_payload,
    _idmx_audio_metadata,
    _idmx_audio_payload_types,
    _idmx_h264_annexb_packet_spans,
    _idmx_h264_packets_from_selected_annexb,
    _idmx_hevc_annexb_packet_spans,
    _idmx_local_packets_to_annexb_with_codec,
    _idmx_packets_from_selected_annexb,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegts,
    summarize_h264_annexb_idr_windows,
    summarize_h264_annexb_units,
    summarize_idmx_h264_local_packets,
)
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
)

FIRST_PREFIX = b"preface"

STREAM_TIMEOUT = 3.0

REMUXED_PAYLOAD = b"abcdef"

MPEG_PS_PAYLOAD = b"\x00\x00\x01\xbaabc\x00\x00\x01\xbadef"

LOCAL_ENCRYPTED_PAYLOAD = b"encrypted-payload"

HCNETSDK_COMMAND_PORT_TEST_KEY = bytes.fromhex(
    "3630343531663636393865353862623134313139323936386361333030663431"
)

HCNETSDK_PLAN_STEP_DELAY = 0.25

HCNETSDK_PLAN_EXTRACTED_STEP_DELAY = 0.75

LOCAL_DECRYPTED_PAYLOAD = b"decrypted"

LOCAL_DECRYPTED_TS_PAYLOAD = b"ts:decrypted"

LOCAL_DECRYPTED_WITH_KEY_PAYLOAD = b"decrypted:encrypted-payload:media-secret"

IDMX_MEDIA_KEY = b"0123456789abcdef"

def _sequential_idmx_frame_factory(
    header: bytes,
) -> Callable[[bytes], bytes]:
    sequence = int.from_bytes(header[2:4], "big")

    def idmx_frame(body: bytes) -> bytes:
        nonlocal sequence
        frame = header[:2] + sequence.to_bytes(2, "big") + header[4:] + body
        sequence = (sequence + 1) & 0xFFFF
        return len(frame).to_bytes(4, "little") + frame

    return idmx_frame

def _rtp_packet(
    payload: bytes,
    *,
    sequence: int = 1,
    payload_type: int = 96,
    extension_data: bytes = b"",
    ssrc: bytes = b"\x01\x02\x03\x04",
) -> bytes:
    extension = (
        b"\x00\x01" + (len(extension_data) // 4).to_bytes(2, "big") + extension_data
        if extension_data
        else b""
    )
    return (
        bytes((0x90 if extension_data else 0x80, payload_type))
        + sequence.to_bytes(2, "big")
        + b"\x00\x00\x00\x01"
        + ssrc
        + extension
        + payload
    )


@pytest.mark.parametrize(
    ("stream_type", "payload_type", "payload", "codec"),
    [(0x1B, 97, b"\x65h264", "h264"), (0x24, 98, b"\x26\x01hevc", "hevc")],
)
def test_local_idmx_annexb_uses_descriptor_video_payload_route(
    stream_type: int,
    payload_type: int,
    payload: bytes,
    codec: str,
) -> None:
    descriptor = bytes((0x45, 2, stream_type, payload_type))
    packets = [
        _rtp_packet(b"metadata", extension_data=descriptor, ssrc=b"\x55\x66\x77\x88"),
        _rtp_packet(
            payload,
            sequence=2,
            payload_type=payload_type,
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]

    annexb, detected_codec = _idmx_local_packets_to_annexb_with_codec(packets)

    assert detected_codec == codec
    assert annexb == b"\x00\x00\x00\x01" + payload


def test_local_idmx_annexb_uses_final_descriptor_snapshot_for_fallback() -> None:
    expected_annexb = b"\x00\x00\x00\x01\x67fallback"
    packets = [
        _rtp_packet(
            b"\x65superseded",
            payload_type=97,
            extension_data=b"\x45\x02\x1b\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"audio",
            sequence=2,
            payload_type=97,
            extension_data=b"\x45\x02\x90\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x67fallback",
            sequence=3,
            payload_type=96,
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]

    annexb, codec = _idmx_local_packets_to_annexb_with_codec(packets)

    assert codec == "h264"
    assert annexb == expected_annexb


def test_local_idmx_authoritative_video_suppresses_pt96_fallback() -> None:
    expected_annexb = b"\x00\x00\x00\x01\x26\x01hevc"
    packets = [
        _rtp_packet(
            b"\x67stale",
            payload_type=96,
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_data=b"\x45\x02\x24\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x26\x01hevc",
            sequence=3,
            payload_type=97,
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]

    annexb, codec = _idmx_local_packets_to_annexb_with_codec(packets)

    assert codec == "hevc"
    assert annexb == expected_annexb


def test_summarize_idmx_routes_accepts_predispatch_correction_on_media() -> None:
    rtp_packets = [
        _rtp_packet(
            b"\x65superseded",
            payload_type=97,
            extension_data=b"\x45\x02\x1b\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x26\x01hevc",
            sequence=2,
            payload_type=97,
            extension_data=b"\x45\x02\x24\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]
    packets = [len(packet).to_bytes(4, "little") + packet for packet in rtp_packets]

    profile = summarize_idmx_h264_local_packets(packets)["rtp_profile"]

    assert profile == {
        "media_started": True,
        "streams": [
            {
                "codec": "hevc",
                "media_kind": "video",
                "payload_type": 97,
                "ssrc": 0x55667788,
                "sample_rate": None,
                "channels": None,
                "authoritative": True,
            }
        ],
    }

def _media(
    payload: bytes,
    *,
    channel: int = 0,
    prefix: bytes = b"",
    sequence: int = 1,
) -> EzvizInterleavedRtpFrameWithPrefix:
    rtp = _rtp_packet(payload, sequence=sequence)
    return EzvizInterleavedRtpFrameWithPrefix(
        prefix=prefix,
        frame=EzvizInterleavedRtpFrame(
            header=EzvizInterleavedRtpFrameHeader(
                channel=channel,
                payload_length=len(rtp),
            ),
            payload=rtp,
        ),
    )

def _raw_media(
    payload: bytes,
    *,
    channel: int = 0,
    prefix: bytes = b"",
) -> EzvizInterleavedRtpFrameWithPrefix:
    return EzvizInterleavedRtpFrameWithPrefix(
        prefix=prefix,
        frame=EzvizInterleavedRtpFrame(
            header=EzvizInterleavedRtpFrameHeader(
                channel=channel,
                payload_length=len(payload),
            ),
            payload=payload,
        ),
    )

def _preview_request() -> EzvizLocalPreviewRequest:
    return EzvizLocalPreviewRequest(
        operation_code="op",
        channel=1,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )

class _FakeSdkClient:
    def __init__(self, *media: EzvizInterleavedRtpFrameWithPrefix) -> None:
        self.media = list(media)
        self.bootstrap_calls: list[dict[str, Any]] = []
        self.read_prefix_limits: list[int] = []
        self.closed = False

    def bootstrap_preview_from_fields(self, **kwargs: Any) -> Any:
        self.bootstrap_calls.append(kwargs)
        return SimpleNamespace(first_media=self.media.pop(0))

    def read_stream_frame_after_prefix(self, *, max_prefix_bytes: int) -> Any:
        self.read_prefix_limits.append(max_prefix_bytes)
        return self.media.pop(0)

    def close(self) -> None:
        self.closed = True

class _FakeCommandPortClient:
    def __init__(self, *media: EzvizInterleavedRtpFrameWithPrefix) -> None:
        self.media = list(media)
        self.bootstrap_calls: list[dict[str, Any]] = []
        self.read_prefix_limits: list[int] = []
        self.closed = False

    def bootstrap_media_stream(
        self,
        command_frames: tuple[bytes, ...],
        **kwargs: Any,
    ) -> Any:
        self.bootstrap_calls.append(
            {
                "command_frames": command_frames,
                **kwargs,
            }
        )
        return SimpleNamespace(first_media=self.media.pop(0))

    def read_media_frame_after_prefix(self, *, max_prefix_bytes: int) -> Any:
        self.read_prefix_limits.append(max_prefix_bytes)
        return self.media.pop(0)

    def close(self) -> None:
        self.closed = True

class _FakeSocket:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        name: str | None = None,
        events: list[str] | None = None,
    ) -> None:
        self._buffer = b"".join(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self.name = name
        self.events = events

    def recv(self, length: int) -> bytes:
        if self.name is not None and self.events is not None:
            self.events.append(f"{self.name}.recv")
        chunk = self._buffer[:length]
        self._buffer = self._buffer[length:]
        return chunk

    def sendall(self, data: bytes) -> None:
        if self.name is not None and self.events is not None:
            self.events.append(f"{self.name}.send")
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True

def _command_port_media_frame(payload: bytes, *, sequence: int = 1) -> bytes:
    rtp = _rtp_packet(payload, sequence=sequence)
    return b"\x24\x00" + (len(rtp) + 4).to_bytes(2, "little") + rtp

def test_copy_local_stream_to_decrypted_mpegts_decrypts_idmx_payload(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "assert sys.argv[sys.argv.index('-r') + 1] == '25'\n"
        "assert sys.argv.index('-r') < sys.argv.index('-i')\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    vps_plain = b"\x40\x01" + b"vps-plain-123456"
    vps_cipher = bytes.fromhex("0ac29ce603f96a3e7b95e63df730b0ad")
    slice_plain = b"slice-plain-1234"
    slice_cipher = bytes.fromhex("7a51a826f29068d1a992b0d6c59a5be9")
    ignored_parameter_frame = (
        b"\x0d\x90\xf0\x50\x37\x03\xb5\xea\xee\x55\x66\x77\x88"
        b"\x00\x01\x00\x0cignored"
    )
    vps_frame = (
        b"\x0d\x90\x60\x77\xb2\x0f\x93\x78\xfe\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
        + vps_plain[:2]
        + vps_cipher
    )
    media_frame = (
        b"\x0d\xb0\x60\x77\xb5\x0f\x93\x78\xfe\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
        b"\x62\x01\x93"
        + slice_cipher
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 3
            return [
                SimpleNamespace(body=ignored_parameter_frame),
                SimpleNamespace(body=vps_frame),
                SimpleNamespace(body=media_frame),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=3,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps_plain
        + b"\x00\x00\x00\x01"
        + b"\x26\x01"
        + slice_plain
    )

def test_copy_local_stream_to_decrypted_mpegts_muxes_idmx_aac_audio(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib\n"
        "import sys\n"
        "audio_format = sys.argv.index('aac')\n"
        "assert sys.argv[audio_format - 1] == '-f'\n"
        "assert sys.argv[audio_format + 1] == '-i'\n"
        "assert '-shortest' not in sys.argv\n"
        "audio = pathlib.Path(sys.argv[audio_format + 2]).read_bytes()\n"
        "video = sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(b'av:' + audio + b':' + video)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    vps_plain = b"\x40\x01" + b"vps-plain-123456"
    vps_cipher = bytes.fromhex("0ac29ce603f96a3e7b95e63df730b0ad")
    slice_plain = b"slice-plain-1234"
    slice_cipher = bytes.fromhex("7a51a826f29068d1a992b0d6c59a5be9")
    media_prefix = b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"

    def video_frame(body: bytes, *, sequence: int, marker: bool = False) -> bytes:
        return (
            b"\x80"
            + bytes((0xE0 if marker else 0x60,))
            + sequence.to_bytes(2, "big")
            + b"\x00\x00\x00\x64"
            + b"\x55\x66\x77\x88"
            + media_prefix
            + body
        )

    vps_frame = (
        video_frame(vps_plain[:2] + vps_cipher, sequence=1)
    )
    media_frame = video_frame(
        b"\x62\x01\x93" + slice_cipher[:8],
        sequence=2,
    )
    media_end_frame = video_frame(
        b"\x62\x01\x53" + slice_cipher[8:],
        sequence=3,
        marker=True,
    )
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
    descriptor_frame = (
        b"\x90\xf0\x00\x01\x00\x00\x00\x01\x55\x66\x77\x88"
        b"\x00\x01\x00\x03"
        + descriptor
    )
    audio_plain = b"\x00aac-plain-frame" + b"tail"
    audio_cipher = bytes.fromhex("9ad09600fb4162b8b5f84bfbd23cce0d") + b"tail"
    access_unit_header = (len(audio_cipher) << 3).to_bytes(2, "big")
    audio_frame = (
        b"\x90\xe8\x00\x02\x00\x00\x04\x00\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x21\x21\x02\x01"
        b"\x00\x10"
        + access_unit_header
        + audio_cipher
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 5
            return [
                SimpleNamespace(body=descriptor_frame),
                SimpleNamespace(body=vps_frame),
                SimpleNamespace(body=media_frame),
                SimpleNamespace(body=audio_frame),
                SimpleNamespace(body=media_end_frame),
            ]

    output = io.BytesIO()
    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=5,
    )

    adts_frame_length = len(audio_plain) + 7
    adts_header = bytes.fromhex("fff160") + bytes(
        (
            0x40 | (adts_frame_length >> 11),
            (adts_frame_length >> 3) & 0xFF,
            ((adts_frame_length & 0x07) << 5) | 0x1F,
            0xFC,
        )
    )
    assert output.getvalue() == (
        b"av:"
        + adts_header
        + audio_plain
        + b":\x00\x00\x00\x01"
        + vps_plain
        + b"\x00\x00\x00\x01\x26\x01"
        + slice_plain
    )

def test_decrypt_idmx_aac_rejects_missing_rtp_frame() -> None:
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
    descriptor_frame = (
        b"\x90\xf0\x00\x01\x00\x00\x00\x01\x55\x66\x77\x88"
        b"\x00\x01\x00\x03"
        + descriptor
    )
    audio_cipher = bytes.fromhex("9ad09600fb4162b8b5f84bfbd23cce0d") + b"tail"
    access_unit = b"\x00\x10" + (len(audio_cipher) << 3).to_bytes(2, "big") + audio_cipher

    def audio_frame(timestamp: int, sequence: int) -> bytes:
        return (
            b"\x90\xe8"
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + b"\x40\x00\x00\x02\x80\x06\x00\x01\x21\x21\x02\x01"
            + access_unit
        )

    assert (
        _decrypt_idmx_local_packets_to_adts_aac(
            [descriptor_frame, audio_frame(0, 2), audio_frame(2048, 3)],
            IDMX_MEDIA_KEY,
        )
        is None
    )


def test_decrypt_idmx_local_aac_uses_preserved_dynamic_payload_route() -> None:
    plain = b"0123456789abcdef" + b"tail"
    encrypted = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain[16:]
    access_unit = b"\x00\x10" + (len(encrypted) << 3).to_bytes(2, "big") + encrypted
    rtp = (
        b"\x90\x69\x00\x02\x00\x00\x00\x00\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x21\x21\x02\x01"
        + access_unit
    )
    selected_packet = len(rtp).to_bytes(4, "little") + rtp

    audio = _decrypt_idmx_local_packets_to_adts_aac(
        [selected_packet],
        IDMX_MEDIA_KEY,
        audio_metadata=(16_000, 1),
        audio_payload_types=frozenset({105}),
    )

    assert audio is not None
    assert audio.adts.endswith(plain)


def test_idmx_audio_payload_types_uses_startup_stream_descriptor() -> None:
    descriptor = b"\x45\x02\x90\x68\x45\x02\x0f\x69"
    rtp = (
        b"\x90\xf0\x00\x01\x00\x00\x00\x00\x55\x66\x77\x88"
        b"\x00\x01\x00\x02"
        + descriptor
    )
    startup_packet = len(rtp).to_bytes(4, "little") + rtp

    assert _idmx_audio_payload_types([startup_packet]) == frozenset({105})


def test_idmx_audio_payload_types_uses_final_descriptor_snapshot() -> None:
    first = _rtp_packet(
        b"metadata",
        payload_type=112,
        extension_data=b"\x45\x02\x0f\x69",
        ssrc=b"\x55\x66\x77\x88",
    )
    corrected = _rtp_packet(
        b"metadata",
        sequence=2,
        payload_type=112,
        extension_data=b"\x45\x02\x1b\x69",
        ssrc=b"\x55\x66\x77\x88",
    )

    assert _idmx_audio_payload_types([first, corrected]) == frozenset({104})

def test_idmx_audio_metadata_ignores_malformed_aac_before_descriptor() -> None:
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
    malformed_audio = (
        b"\x90\xe8\x00\x01\x00\x00\x00\x00\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x21\x21\x02\x01"
        b"\x00\x10\x00"
    )
    descriptor_frame = (
        b"\x90\xf0\x00\x02\x00\x00\x00\x01\x55\x66\x77\x88"
        b"\x00\x01\x00\x03"
        + descriptor
    )

    assert _idmx_audio_metadata(
        [malformed_audio, descriptor_frame],
        IDMX_MEDIA_KEY,
    ) == (sample_rate, 1)


def test_idmx_audio_metadata_uses_final_descriptor_snapshot() -> None:
    def descriptor(sample_rate: int) -> bytes:
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

    packets = [
        _rtp_packet(
            b"metadata",
            payload_type=112,
            extension_data=descriptor(8_000),
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_data=descriptor(16_000),
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]

    assert _idmx_audio_metadata(packets, b"unused") == (16_000, 1)

def test_idmx_audio_metadata_requires_native_descriptor() -> None:
    assert _idmx_audio_metadata([], IDMX_MEDIA_KEY) is None

def test_decrypt_idmx_aac_rejects_access_unit_too_large_for_adts() -> None:
    access_unit_length = 0x1FFF - 6
    access_unit = (
        b"\x00\x10"
        + (access_unit_length << 3).to_bytes(2, "big")
        + b"x" * access_unit_length
    )
    audio_frame = (
        b"\x90\xe8\x00\x01\x00\x00\x00\x00\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x21\x21\x02\x01"
        + access_unit
    )

    assert (
        _decrypt_idmx_local_packets_to_adts_aac(
            [audio_frame],
            IDMX_MEDIA_KEY,
            audio_metadata=(16_000, 1),
        )
        is None
    )

def test_idmx_packets_from_selected_annexb_keeps_audio_between_vcl_fragments() -> None:
    def frame(payload_type: int, body: bytes, *, sequence: int, timestamp: int) -> bytes:
        rtp = (
            b"\x80"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    first_nal = b"\x00\x00\x00\x01\x41before"
    selected_nal = b"\x00\x00\x00\x01\x65first-last"
    packets = [
        frame(96, b"\x41before", sequence=1, timestamp=100),
        frame(96, b"\x7c\x85first-", sequence=2, timestamp=200),
        frame(104, b"audio", sequence=10, timestamp=0),
        frame(96, b"\x7c\x45last", sequence=3, timestamp=200),
    ]

    assert _idmx_packets_from_selected_annexb(
        packets,
        full_annexb=first_nal + selected_nal,
        selected_annexb=selected_nal,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=None,
        video_input_format="h264",
    ) == packets[1:]

def test_idmx_packets_from_selected_annexb_starts_at_first_vcl_after_parameters() -> None:
    def frame(payload_type: int, body: bytes, *, sequence: int, timestamp: int) -> bytes:
        rtp = (
            b"\x80"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    parameters = b"\x00\x00\x00\x01\x67sps"
    selected_vcl = b"\x00\x00\x00\x01\x65selected"
    old_vcl = selected_vcl
    packets = [
        frame(96, b"\x65selected", sequence=1, timestamp=100),
        frame(96, b"\x67sps", sequence=2, timestamp=200),
        frame(104, b"audio-before-vcl", sequence=9, timestamp=0),
        frame(96, b"\x65selected", sequence=3, timestamp=200),
    ]

    assert _idmx_packets_from_selected_annexb(
        packets,
        full_annexb=old_vcl + parameters + selected_vcl,
        selected_annexb=parameters + selected_vcl,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=None,
        video_input_format="h264",
    ) == packets[3:]

def test_idmx_packets_from_selected_annexb_anchors_hevc_after_synthesized_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def frame(body: bytes, *, sequence: int, timestamp: int) -> bytes:
        rtp = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    irap = b"\x00\x00\x00\x01\x26\x01same"
    middle = b"\x00\x00\x00\x01\x02\x01middle"
    tail = b"\x00\x00\x00\x01\x02\x01tail"
    parameters = b"\x00\x00\x00\x01\x40\x01vps"
    full_annexb = irap + middle + irap + tail
    selected_annexb = parameters + irap + tail
    second_irap_offset = len(irap + middle)
    packets = [
        frame(b"old", sequence=1, timestamp=100),
        frame(b"middle", sequence=2, timestamp=200),
        frame(b"retained", sequence=3, timestamp=300),
        frame(b"tail", sequence=4, timestamp=300),
    ]
    spans = [
        (0, len(irap), 0, 0, 19, 0, 0),
        (len(irap), second_irap_offset, 1, 1, 1, 0, 0),
        (
            second_irap_offset,
            second_irap_offset + len(irap),
            2,
            2,
            19,
            0,
            0,
        ),
        (len(full_annexb) - len(tail), len(full_annexb), 3, 3, 1, 0, 0),
    ]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_hevc_annexb_packet_spans",
        lambda *_args, **_kwargs: (full_annexb, spans),
    )

    assert _idmx_packets_from_selected_annexb(
        packets,
        full_annexb=full_annexb,
        selected_annexb=selected_annexb,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=None,
        video_input_format="hevc",
    ) == packets[2:]

def test_idmx_hevc_span_map_records_fragment_flushed_at_eof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def frame(body: bytes, *, sequence: int) -> bytes:
        rtp = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + b"\x00\x00\x00\x64"
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        lambda nal, _key: nal,
    )
    packets = [
        frame(b"\x62\x01\x93slice-", sequence=1),
        frame(b"\x62\x01payload", sequence=2),
    ]

    expected_annexb = b"\x00\x00\x00\x01\x26\x01slice-payload"
    annexb, spans = _idmx_hevc_annexb_packet_spans(packets, IDMX_MEDIA_KEY)

    assert annexb == expected_annexb
    assert spans == [(0, len(annexb), 0, 1, 19, 0, 0)]


def test_idmx_encrypted_span_maps_use_descriptor_video_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_h264 = b"\x00\x00\x00\x01\x65dynamic"
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        lambda nal, _key, *, nalu_header_size: nal,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        lambda nal, _key: nal,
    )
    h264_packets = [
        _rtp_packet(
            b"metadata",
            payload_type=112,
            extension_data=b"\x45\x02\x1b\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x65dynamic",
            sequence=2,
            payload_type=97,
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]
    hevc_packets = [
        _rtp_packet(
            b"metadata",
            payload_type=112,
            extension_data=b"\x45\x02\x24\x61",
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x40\x01vps",
            sequence=2,
            payload_type=97,
            ssrc=b"\x55\x66\x77\x88",
        ),
        _rtp_packet(
            b"\x26\x01dynamic",
            sequence=3,
            payload_type=97,
            ssrc=b"\x55\x66\x77\x88",
        ),
    ]

    h264_annexb, h264_spans = _idmx_h264_annexb_packet_spans(
        h264_packets,
        IDMX_MEDIA_KEY,
        nalu_header_size=0,
        stream_is_clear=False,
    )
    hevc_annexb, hevc_spans = _idmx_hevc_annexb_packet_spans(
        hevc_packets,
        IDMX_MEDIA_KEY,
    )

    assert h264_annexb == expected_h264
    assert h264_spans == [(0, len(h264_annexb), 1, 1, 5, 0, 0)]
    expected_vps = b"\x00\x00\x00\x01\x40\x01vps"
    assert hevc_annexb == expected_vps + b"\x00\x00\x00\x01\x26\x01dynamic"
    assert hevc_spans == [
        (0, len(expected_vps), 1, 1, 32, 0, 0),
        (len(expected_vps), len(hevc_annexb), 2, 2, 19, 0, 0),
    ]

def test_idmx_hevc_span_map_preserves_pending_fragment_across_standalone_nal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def frame(body: bytes, *, sequence: int) -> bytes:
        rtp = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + b"\x00\x00\x00\x64"
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        lambda nal, _key: nal,
    )
    vps = b"\x40\x01vps"
    packets = [
        frame(b"\x62\x01\x93slice", sequence=1),
        frame(vps, sequence=2),
    ]

    annexb, spans = _idmx_hevc_annexb_packet_spans(packets, IDMX_MEDIA_KEY)
    vps_end = len(b"\x00\x00\x00\x01" + vps)

    assert annexb == b"\x00\x00\x00\x01" + vps + b"\x00\x00\x00\x01\x26\x01slice"
    assert spans == [
        (0, vps_end, 1, 1, 32, 0, 0),
        (vps_end, len(annexb), 0, 0, 19, 0, 0),
    ]

def test_idmx_h264_selected_packets_stop_at_selected_video_endpoint() -> None:
    def frame(payload_type: int, body: bytes, *, sequence: int, timestamp: int) -> bytes:
        rtp = (
            b"\x80"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    selected = b"\x00\x00\x00\x01\x65selected"
    packets = [
        frame(96, b"\x65selected", sequence=1, timestamp=100),
        frame(104, b"trailing-audio", sequence=2, timestamp=1024),
    ]

    assert _idmx_h264_packets_from_selected_annexb(
        packets,
        full_annexb=selected,
        selected_annexb=selected,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=None,
        stream_is_clear=True,
    ) == packets[:1]

def test_idmx_h264_selected_packets_track_vcl_inside_aggregate_packet() -> None:
    def frame(payload_type: int, body: bytes, *, sequence: int, timestamp: int) -> bytes:
        rtp = (
            b"\x80"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(rtp).to_bytes(4, "little") + rtp

    selected = b"\x00\x00\x00\x01\x65first-last"
    next_nal = b"\x00\x00\x00\x01\x41next"
    start_fu = frame(96, b"\x7c\x85first-", sequence=1, timestamp=100)
    middle_audio = frame(104, b"audio", sequence=9, timestamp=0)
    end_fu = frame(96, b"\x7c\x45last", sequence=2, timestamp=100)
    packets = [
        frame(104, b"audio-before", sequence=8, timestamp=0) + start_fu,
        middle_audio,
        end_fu
        + frame(104, b"audio-after", sequence=10, timestamp=1024)
        + frame(96, b"\x41next", sequence=3, timestamp=200),
    ]

    assert _idmx_h264_packets_from_selected_annexb(
        packets,
        full_annexb=selected + next_nal,
        selected_annexb=selected,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=None,
        stream_is_clear=True,
    ) == [start_fu, middle_audio, end_fu]

def test_copy_decrypted_mpegts_bounds_untrimmed_aac_to_video_vcl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"audio-before", b"first-vcl", b"audio", b"last-vcl", b"audio-after"]
    full_annexb = (
        b"\x00\x00\x00\x01\x65first"
        b"\x00\x00\x00\x01\x41last"
    )
    selected_packets = packets[1:4]
    selected_calls: list[tuple[bytes, bytes]] = []
    audio_calls: list[
        tuple[list[bytes], tuple[int, int] | None, frozenset[int] | None]
    ] = []
    audio = SimpleNamespace(adts=b"aac", sample_rate=16_000, channels=1)
    mux_calls: list[tuple[bytes, Any]] = []

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == len(packets)
            return [SimpleNamespace(body=packet) for packet in packets]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._local_stream_packets_are_idmx",
        lambda _packets: True,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_annexb",
        lambda *_args, **_kwargs: full_annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_have_aac",
        lambda _packets: True,
    )

    def fake_select(
        _packets: list[bytes],
        *,
        full_annexb: bytes,
        selected_annexb: bytes,
        **_kwargs: Any,
    ) -> list[bytes]:
        selected_calls.append((full_annexb, selected_annexb))
        return selected_packets

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_packets_from_selected_annexb",
        fake_select,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_audio_metadata",
        lambda *_args, **_kwargs: (16_000, 1),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_audio_payload_types",
        lambda *_args, **_kwargs: frozenset({105}),
    )

    def fake_audio(
        candidate_packets: list[bytes],
        _media_key: str | bytes,
        *,
        audio_metadata: tuple[int, int] | None = None,
        audio_payload_types: frozenset[int] | None = None,
    ) -> Any:
        audio_calls.append(
            (candidate_packets, audio_metadata, audio_payload_types)
        )
        return audio

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_adts_aac",
        fake_audio,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._copy_idmx_audio_video_to_mpegts",
        lambda video, selected_audio, *_args, **_kwargs: mux_calls.append(
            (video, selected_audio)
        ),
    )

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        io.BytesIO(),
        IDMX_MEDIA_KEY,
        max_packets=len(packets),
    )

    assert selected_calls == [(full_annexb, full_annexb)]
    assert audio_calls == [(selected_packets, (16_000, 1), frozenset({105}))]
    assert mux_calls == [(full_annexb, audio)]

def test_copy_local_stream_to_decrypted_mpegts_wait_path_keeps_aac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"startup", b"selected"]
    full_annexb = b"\x00\x00\x00\x01\x65startup\x00\x00\x00\x01\x65selected"
    selected_annexb = b"\x00\x00\x00\x01\x65selected"
    audio = SimpleNamespace(sample_rate=16_000, channels=1, adts=b"aac")
    audio_calls: list[tuple[list[bytes], dict[str, Any]]] = []
    mux_calls: list[tuple[bytes, Any]] = []

    def fake_iter_payloads(*_args: Any, **_kwargs: Any) -> Iterator[bytes]:
        yield from packets

    def fake_collect(payloads: Iterator[bytes], *_args: Any, **_kwargs: Any) -> bytes:
        assert list(payloads) == packets
        return selected_annexb

    def fake_audio(candidate_packets: list[bytes], *_args: Any, **kwargs: Any) -> Any:
        audio_calls.append((candidate_packets, kwargs))
        return audio

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        fake_iter_payloads,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window",
        fake_collect,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_annexb",
        lambda *_args, **_kwargs: full_annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_h264_packets_from_selected_annexb",
        lambda *_args, **_kwargs: packets[1:],
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_adts_aac",
        fake_audio,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_audio_metadata",
        lambda *_args, **_kwargs: (16_000, 1),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_audio_payload_types",
        lambda *_args, **_kwargs: frozenset({105}),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._copy_idmx_audio_video_to_mpegts",
        lambda video, selected_audio, *_args, **_kwargs: mux_calls.append(
            (video, selected_audio)
        ),
    )

    copy_local_stream_to_decrypted_mpegts(
        object(),
        io.BytesIO(),
        IDMX_MEDIA_KEY,
        duration_seconds=1.0,
        h264_wait_for_clean_idr_window=True,
    )

    assert audio_calls == [
        (
            packets[1:],
            {
                "audio_metadata": (16_000, 1),
                "audio_payload_types": frozenset({105}),
            },
        )
    ]
    assert mux_calls == [(selected_annexb, audio)]

def test_copy_local_stream_to_decrypted_mpegts_wait_path_without_selected_aac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"startup", b"selected"]
    full_annexb = b"\x00\x00\x00\x01\x65startup\x00\x00\x00\x01\x65selected"
    selected_annexb = b"\x00\x00\x00\x01\x65selected"
    video_calls: list[bytes] = []
    process = object()

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        lambda *_args, **_kwargs: iter(packets),
    )

    def fake_collect(payloads: Iterator[bytes], *_args: Any, **_kwargs: Any) -> bytes:
        assert list(payloads) == packets
        return selected_annexb

    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window",
        fake_collect,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_annexb",
        lambda *_args, **_kwargs: full_annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_h264_packets_from_selected_annexb",
        lambda *_args, **_kwargs: packets[1:],
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_adts_aac",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_audio_metadata",
        lambda *_args, **_kwargs: (16_000, 1),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._open_local_h264_mpegts_remux_process",
        lambda _path: process,
    )

    def fake_copy(
        payloads: Iterator[bytes] | list[bytes],
        _output: Any,
        *,
        process: Any,
    ) -> None:
        assert process is not None
        video_calls.extend(payloads)

    monkeypatch.setattr(
        "pyezvizapi.local_stream._copy_mpegps_payloads_to_mpegts",
        fake_copy,
    )

    copy_local_stream_to_decrypted_mpegts(
        object(),
        io.BytesIO(),
        IDMX_MEDIA_KEY,
        duration_seconds=1.0,
        h264_wait_for_clean_idr_window=True,
    )

    assert video_calls == [selected_annexb]

def test_copy_local_stream_to_decrypted_mpegts_wait_path_aligns_clear_video(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"startup", b"selected"]
    selected_annexb = b"\x00\x00\x00\x01\x65" + b"clear" * 8
    clear_annexb = b"\x00\x00\x00\x01\x41startup" + selected_annexb
    decrypted_annexb = b"\x00\x00\x00\x01\x41startup\x00\x00\x00\x01\x65wrong"
    mapped_full_streams: list[bytes] = []

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        lambda *_args, **_kwargs: iter(packets),
    )

    def fake_collect(payloads: Iterator[bytes], *_args: Any, **_kwargs: Any) -> bytes:
        assert list(payloads) == packets
        return selected_annexb

    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window",
        fake_collect,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_annexb",
        lambda *_args, **_kwargs: decrypted_annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_h264_annexb",
        lambda *_args, **_kwargs: clear_annexb,
    )

    def fake_selected_packets(
        candidate_packets: list[bytes],
        *,
        full_annexb: bytes,
        **_kwargs: Any,
    ) -> list[bytes]:
        mapped_full_streams.append(full_annexb)
        return candidate_packets[1:]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_h264_packets_from_selected_annexb",
        fake_selected_packets,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_adts_aac",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._open_local_h264_mpegts_remux_process",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._copy_mpegps_payloads_to_mpegts",
        lambda *_args, **_kwargs: None,
    )

    copy_local_stream_to_decrypted_mpegts(
        object(),
        io.BytesIO(),
        IDMX_MEDIA_KEY,
        duration_seconds=1.0,
        h264_wait_for_clean_idr_window=True,
    )

    assert mapped_full_streams == [clear_annexb]

def test_copy_local_stream_to_decrypted_mpegts_decrypts_direct_hevc_idmx_payload(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_hevc_nal_prefix(nal: bytes, _aes_key: bytes) -> bytes:
        decrypted_nals.append(nal)
        return nal

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        fake_decrypt_hevc_nal_prefix,
    )
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        idmx_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    vps = b"\x40\x01vps"
    first_fu = b"\x62\x01\x93slice-"
    last_fu = b"\x62\x01\x53payload"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 3
            return [
                SimpleNamespace(body=idmx_frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=idmx_frame(first_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=idmx_frame(last_fu, sequence=sequence_base + 2)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=3,
    )

    assert decrypted_nals == [b"\x26\x01slice-payload"]
    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01\x26\x01slice-payload"
    )

def test_copy_local_stream_to_decrypted_mpegts_handles_live_padded_extended_hevc_rtp(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_hevc_nal_prefix(nal: bytes, _aes_key: bytes) -> bytes:
        decrypted_nals.append(nal)
        return nal

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        fake_decrypt_hevc_nal_prefix,
    )
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def rtp_frame(
        body: bytes,
        *,
        sequence: int,
        marker: bool = False,
        padding: int = 0,
    ) -> bytes:
        first_byte = 0x90 | (0x20 if padding else 0)
        extension = b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
        padding_bytes = b"" if not padding else b"\x00" * (padding - 1) + bytes([padding])
        return (
            bytes([first_byte, 0x60 | (0x80 if marker else 0)])
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + extension
            + body
            + padding_bytes
        )

    vps = b"\x40\x01encrypted-vps"
    first_fu = b"\x62\x01\x93slice-"
    last_fu = b"\x62\x01\x66payload\x24\x00X"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 3
            return [
                SimpleNamespace(body=rtp_frame(vps, sequence=sequence_base)),
                SimpleNamespace(
                    body=rtp_frame(
                        first_fu,
                        sequence=sequence_base + 1,
                        padding=4,
                    )
                ),
                SimpleNamespace(
                    body=rtp_frame(
                        last_fu,
                        sequence=sequence_base + 2,
                        marker=True,
                        padding=4,
                    )
                ),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=3,
        decrypt_hevc_parameter_sets=True,
    )

    assert decrypted_nals == [vps, b"\x26\x01slice-payload\x24\x00X"]
    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01\x26\x01slice-payload\x24\x00X"
    )

def test_copy_local_stream_to_decrypted_mpegts_prefers_direct_hevc_before_h264_encrypted_header_fallback(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_hevc_nals: list[bytes] = []

    def fake_decrypt_hevc_nal_prefix(nal: bytes, _aes_key: bytes) -> bytes:
        decrypted_hevc_nals.append(nal)
        return nal

    def fail_h264_decrypt(
        _nal: bytes,
        _aes_key: bytes,
        *,
        nalu_header_size: int = 1,
    ) -> bytes:
        raise AssertionError("direct HEVC should not hit H.264 fallback")

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        fake_decrypt_hevc_nal_prefix,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        fail_h264_decrypt,
    )
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        idmx_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    vps = b"\x40\x01vps"
    trail_r = b"\x02\x01trail"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=idmx_frame(trail_r, sequence=sequence_base + 1)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
        nalu_header_size=0,
    )

    assert decrypted_hevc_nals == [trail_r]
    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01" + vps + b"\x00\x00\x00\x01" + trail_r
    )

def test_copy_local_stream_to_decrypted_mpegts_honors_h264_encrypted_header_without_hevc_evidence(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_h264_nal_prefix(
        nal: bytes,
        _aes_key: bytes,
        *,
        nalu_header_size: int = 1,
    ) -> bytes:
        assert nalu_header_size == 0
        decrypted_nals.append(nal)
        return b"\x65plain-" + nal[1:]

    def fail_hevc_decrypt(nal: bytes, _aes_key: bytes) -> bytes:
        raise AssertionError(f"ambiguous H.264 encrypted-header hit HEVC: {nal!r}")

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        fake_decrypt_h264_nal_prefix,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        fail_hevc_decrypt,
    )
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    ambiguous_encrypted_idr = b"\x02\x01cipher"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(ambiguous_encrypted_idr))]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
        nalu_header_size=0,
    )

    expected_output = b"h264:\x00\x00\x00\x01\x65plain-\x01cipher"
    assert decrypted_nals == [ambiguous_encrypted_idr]
    assert output.getvalue() == expected_output

def test_copy_local_stream_to_decrypted_mpegts_decrypts_h264_idmx_payload(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_h264_nal_prefix(
        nal: bytes,
        _aes_key: bytes,
        *,
        nalu_header_size: int = 1,
    ) -> bytes:
        assert nalu_header_size == 1
        decrypted_nals.append(nal)
        return nal[:1] + b"plain-" + nal[1:]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        fake_decrypt_h264_nal_prefix,
    )
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    non_idr = b"\x41cipher"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 3
            return [
                SimpleNamespace(body=idmx_frame(body))
                for body in (sps, pps, non_idr)
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=3,
    )

    assert decrypted_nals == [non_idr]
    assert output.getvalue() == (
        b"h264:\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + b"\x41plain-cipher"
    )

def test_copy_local_stream_to_decrypted_mpegts_decrypts_fragmented_h264_idmx_payload(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_h264_nal_prefix(
        nal: bytes,
        _aes_key: bytes,
        *,
        nalu_header_size: int = 1,
    ) -> bytes:
        assert nalu_header_size == 1
        decrypted_nals.append(nal)
        return nal[:1] + b"plain-" + nal[1:]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        fake_decrypt_h264_nal_prefix,
    )
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        idmx_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    first_fu = b"\x7c\x85cipher-"
    last_fu = b"\x7c\x45payload"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(first_fu, sequence=sequence_base)),
                SimpleNamespace(body=idmx_frame(last_fu, sequence=sequence_base + 1)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    expected_output = b"h264:\x00\x00\x00\x01\x65plain-cipher-payload"
    assert decrypted_nals == [b"\x65cipher-payload"]
    assert output.getvalue() == expected_output

def test_copy_local_stream_to_decrypted_mpegts_decrypts_h264_encrypted_header_idmx_payload(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_h264_nal_prefix(
        nal: bytes,
        _aes_key: bytes,
        *,
        nalu_header_size: int = 1,
    ) -> bytes:
        assert nalu_header_size == 0
        decrypted_nals.append(nal)
        return b"\x65plain-" + nal[1:]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        fake_decrypt_h264_nal_prefix,
    )
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    encrypted_idr = b"\xaecipher"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(encrypted_idr))]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
        nalu_header_size=0,
    )

    expected_output = b"h264:\x00\x00\x00\x01\x65plain-cipher"
    assert decrypted_nals == [encrypted_idr]
    assert output.getvalue() == expected_output

def test_copy_local_stream_to_decrypted_mpegts_handles_direct_hevc_fu_without_continuation_headers(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    decrypted_nals: list[bytes] = []

    def fake_decrypt_hevc_nal_prefix(nal: bytes, _aes_key: bytes) -> bytes:
        decrypted_nals.append(nal)
        return nal

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_hevc_nal_prefix",
        fake_decrypt_hevc_nal_prefix,
    )
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def idmx_frame(
        body: bytes,
        *,
        sequence: int,
        marker: bool = False,
    ) -> bytes:
        marker_payload_type = (0x80 if marker else 0x00) | 0x60
        idmx_header = (
            bytes([0x80, marker_payload_type])
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    vps = b"\x40\x01vps"
    first_fu = b"\x62\x01\x93slice-"
    middle_fu = b"\x62\x01payload-"
    last_fu = b"\x62\x01tail"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=idmx_frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=idmx_frame(first_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=idmx_frame(middle_fu, sequence=sequence_base + 2)),
                SimpleNamespace(
                    body=idmx_frame(
                        last_fu,
                        sequence=sequence_base + 3,
                        marker=True,
                    )
                ),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
    )

    assert decrypted_nals == [b"\x26\x01slice-payload-tail"]
    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01\x26\x01slice-payload-tail"
    )

def test_copy_local_stream_to_decrypted_mpegts_applies_h264_startup_trim(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    first_idr = b"\x65bad"
    second_idr = b"\x65good"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=idmx_frame(body))
                for body in (sps, pps, first_idr, second_idr)
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
        h264_skip_initial_idr_windows=1,
    )

    assert output.getvalue() == b"ts:\x00\x00\x00\x01" + second_idr

def test_copy_local_stream_to_decrypted_mpegts_prefers_h264_vcl_before_hevc_probe(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    h264_non_idr = b"\x41\x01h264-slice"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(h264_non_idr))]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == b"h264:\x00\x00\x00\x01" + h264_non_idr

def test_copy_local_stream_to_decrypted_mpegts_wait_for_clean_idr_bounds_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "    sys.exit(1)\n"
        "elif '-f' in sys.argv and sys.argv[sys.argv.index('-f') + 1] == 'null':\n"
        "    pass\n"
        "else:\n"
        "    sys.stdout.buffer.write(b'ts:' + data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    clean_idr = b"\x65clean"
    within_duration = b"\x41keep"
    second_idr = b"\x65second"
    after_duration = b"\x41drop"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    packets = [
        idmx_frame(body)
        for body in (sps, pps, clean_idr, within_duration, second_idr, after_duration)
    ]
    seen: dict[str, Any] = {}
    times = iter([0.0, 0.0, 0.1, 0.2, 0.3, 0.8, 1.5])

    def monotonic() -> float:
        return next(times, 1.5)

    def fake_iter_payloads(
        stream: Any,
        *,
        max_packets: int | None,
        duration_seconds: float | None,
        monotonic: Any,
    ) -> Iterator[bytes]:
        seen["stream"] = stream
        seen["max_packets"] = max_packets
        seen["duration_seconds"] = duration_seconds
        yield from packets

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        fake_iter_payloads,
    )
    decrypt_probe_calls: list[list[bytes]] = []

    def fake_decrypt_idmx_local_packets_to_annexb(
        probe_packets: list[bytes],
        *args: Any,
        **kwargs: Any,
    ) -> bytes:
        decrypt_probe_calls.append(list(probe_packets))
        return b"\x00\x00\x00\x01\x65bad"

    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_idmx_local_packets_to_annexb",
        fake_decrypt_idmx_local_packets_to_annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_h264_packets_from_selected_annexb",
        lambda candidate_packets, **_kwargs: candidate_packets,
    )

    output = io.BytesIO()
    stream = object()
    requested_duration = 0.25
    wait_seconds = 10.0

    copy_local_stream_to_decrypted_mpegts(
        stream,
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=requested_duration,
        monotonic=monotonic,
        h264_wait_for_clean_idr_window=True,
        h264_clean_idr_wait_seconds=wait_seconds,
    )

    assert seen["stream"] is stream
    assert seen["max_packets"] is None
    assert seen["duration_seconds"] == requested_duration + wait_seconds
    assert [len(call) for call in decrypt_probe_calls] == [1, 2, 3, 4, 6]
    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + clean_idr
        + b"\x00\x00\x00\x01"
        + within_duration
    )

def test_copy_local_stream_to_mpegts_remuxes_direct_idmx_hevc_payload(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    sps = b"\x42\x01sps"
    pps = b"\x44\x01pps"
    first_fu = b"\x62\x01\x93slice-"
    last_fu = b"\x62\x01\x53payload"
    second_vps = b"\x40\x01vps2"
    second_fu = b"\x26\x01clean"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 7
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(sps, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(pps, sequence=sequence_base + 2)),
                SimpleNamespace(body=frame(first_fu, sequence=sequence_base + 3)),
                SimpleNamespace(body=frame(last_fu, sequence=sequence_base + 4)),
                SimpleNamespace(body=frame(second_vps, sequence=sequence_base + 5)),
                SimpleNamespace(body=frame(second_fu, sequence=sequence_base + 6)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=7,
        h264_skip_initial_idr_windows=1,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + second_vps
        + b"\x00\x00\x00\x01"
        + second_fu
    )

def test_copy_local_stream_to_mpegts_strips_direct_hevc_command_trailer(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x0d\x80\x60"
            + sequence.to_bytes(2, "big")
            + b"\x36\x01\xd1\xef"
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    irap = b"\x26\x01clean"
    trailer = b"\x24\x00x"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=frame(vps + trailer, sequence=0x7000)),
                SimpleNamespace(body=frame(irap + trailer, sequence=0x7001)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01" + vps + b"\x00\x00\x00\x01" + irap
    )

def test_hcnetsdk_command_port_preserves_length_prefixed_idmx_before_rtp() -> None:
    idmx_frame = (
        b"\x80\x60"
        + (0x7000).to_bytes(2, "big")
        + b"\x36\x01\xd1\xef"
        + b"\x55\x66\x77\x88"
        + b"\x67"
        + (b"x" * 115)
    )
    assert len(idmx_frame) == 0x80
    payload = len(idmx_frame).to_bytes(4, "little") + idmx_frame

    assert _hcnetsdk_command_port_media_payload(payload) == payload

def test_hcnetsdk_command_port_preserves_length_prefixed_idmx_before_header_strip() -> None:
    idmx_frame = (
        b"\x80\x60"
        + (0x7000).to_bytes(2, "big")
        + b"\x36\x01\xd1\xef"
        + b"\x55\x66\x77\x88"
        + b"\x67"
        + (b"x" * 15)
    )
    assert len(idmx_frame) == 0x1C
    payload = len(idmx_frame).to_bytes(4, "little") + idmx_frame
    media = EzvizInterleavedRtpFrameWithPrefix(
        prefix=b"",
        frame=EzvizInterleavedRtpFrame(
            header=EzvizInterleavedRtpFrameHeader(
                channel=1,
                payload_length=len(payload),
            ),
            payload=payload,
        ),
    )

    packet = _hcnetsdk_command_port_media_packet(media)

    assert packet.body == payload
    assert packet.encrypted is True

def test_copy_local_stream_to_mpegts_trims_trailing_hevc_parameter_sets(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    sps = b"\x42\x01sps"
    pps = b"\x44\x01pps"
    idr = b"\x26\x01idr"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 7
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(sps, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(pps, sequence=sequence_base + 2)),
                SimpleNamespace(body=frame(idr, sequence=sequence_base + 3)),
                SimpleNamespace(body=frame(vps, sequence=sequence_base + 4)),
                SimpleNamespace(body=frame(sps, sequence=sequence_base + 5)),
                SimpleNamespace(body=frame(pps, sequence=sequence_base + 6)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=7,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
    )

def test_copy_local_stream_to_mpegts_skips_ezviz_hevc_fu_pseudo_headers(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int, marker: bool = False) -> bytes:
        marker_payload_type = (0x80 if marker else 0x00) | 0x60
        return (
            bytes([0x80, marker_payload_type])
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    first_fu = b"\x62\x01\x93slice-"
    middle_fu = b"\x62\x01\x26payload-"
    last_fu = b"\x62\x01\x66tail"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(first_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(middle_fu, sequence=sequence_base + 2)),
                SimpleNamespace(
                    body=frame(last_fu, sequence=sequence_base + 3, marker=True)
                ),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + b"\x26\x01slice-payload-tail"
    )

def test_copy_local_stream_to_mpegts_drops_hevc_fu_until_start(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    orphan_middle_fu = b"\x62\x01\x13orphan-"
    orphan_end_fu = b"\x62\x01\x53tail"
    valid_start_fu = b"\x62\x01\x93slice-"
    valid_end_fu = b"\x62\x01\x53payload"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 5
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(orphan_middle_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(orphan_end_fu, sequence=sequence_base + 2)),
                SimpleNamespace(body=frame(valid_start_fu, sequence=sequence_base + 3)),
                SimpleNamespace(body=frame(valid_end_fu, sequence=sequence_base + 4)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=5,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + b"\x26\x01slice-payload"
    )

def test_copy_local_stream_to_mpegts_drops_hevc_fu_on_sequence_gap(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    broken_start_fu = b"\x62\x01\x93broken-"
    broken_end_fu = b"\x62\x01\x53tail"
    valid_start_fu = b"\x62\x01\x93slice-"
    valid_end_fu = b"\x62\x01\x53payload"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 5
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(broken_start_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(broken_end_fu, sequence=sequence_base + 3)),
                SimpleNamespace(body=frame(valid_start_fu, sequence=sequence_base + 4)),
                SimpleNamespace(body=frame(valid_end_fu, sequence=sequence_base + 5)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=5,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + b"\x26\x01slice-payload"
    )

def test_copy_local_stream_to_mpegts_handles_direct_hevc_fu_without_continuation_headers(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(
        body: bytes,
        *,
        sequence: int,
        marker: bool = False,
    ) -> bytes:
        marker_payload_type = (0x80 if marker else 0x00) | 0x60
        return (
            bytes([0x80, marker_payload_type])
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    start_fu = b"\x62\x01\x93slice-"
    middle_fu = b"\x62\x01payload-"
    end_fu = b"\x62\x01tail"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(start_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(middle_fu, sequence=sequence_base + 2)),
                SimpleNamespace(
                    body=frame(end_fu, sequence=sequence_base + 3, marker=True)
                ),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + b"\x26\x01slice-payload-tail"
    )

def test_copy_local_stream_to_mpegts_preserves_hevc_payload_sentinel_bytes(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(
        body: bytes,
        *,
        sequence: int,
        marker: bool = False,
    ) -> bytes:
        marker_payload_type = (0x80 if marker else 0x00) | 0x60
        return (
            bytes([0x80, marker_payload_type])
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    vps = b"\x40\x01vps"
    start_fu = b"\x62\x01\x93slice-"
    sentinel_payload = b"aa\x80xxxxxxx\x55\x66\x77\x88bbbb"
    middle_fu = b"\x62\x01" + sentinel_payload
    end_fu = b"\x62\x01tail"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(start_fu, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(middle_fu, sequence=sequence_base + 2)),
                SimpleNamespace(
                    body=frame(end_fu, sequence=sequence_base + 3, marker=True)
                ),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + b"\x26\x01slice-"
        + sentinel_payload
        + b"tail"
    )

def test_copy_local_stream_to_mpegts_keeps_hevc_trail_n(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x3601D1EF
    sequence_base = 0x7000

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    trail_n = b"\x00\x01trail-n"
    vps = b"\x40\x01vps"
    sps = b"\x42\x01sps"
    idr = b"\x26\x01idr"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=frame(trail_n, sequence=sequence_base)),
                SimpleNamespace(body=frame(vps, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(sps, sequence=sequence_base + 2)),
                SimpleNamespace(body=frame(idr, sequence=sequence_base + 3)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=4,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + trail_n
        + b"\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + idr
    )

def test_copy_local_stream_to_mpegts_models_command_port_h264_fu_a(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x7D522A3E
    sequence_base = 0x5D5C
    first_fu = b"\x7c\x85\x88\x80\x00\x00\x1a\x48native-first"
    next_fu = b"\x7c\x05native-middle"
    last_fu = b"\x7c\x45native-last"

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        idmx_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=idmx_frame(first_fu, sequence=sequence_base)
                    + idmx_frame(next_fu, sequence=sequence_base + 1)
                    + idmx_frame(last_fu, sequence=sequence_base + 2)
                )
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        b"\x65"
        + first_fu[2:]
        + next_fu[2:]
        + last_fu[2:]
    )

def test_idmx_incomplete_h264_fu_is_not_mislabeled_as_hevc() -> None:
    rtp_timestamp = 0x7D522A3E
    sequence = 0x5D5C
    payload = b"\x7c\x85incomplete"
    rtp = (
        b"\x80\x60"
        + sequence.to_bytes(2, "big")
        + rtp_timestamp.to_bytes(4, "big")
        + b"\x55\x66\x77\x88"
        + payload
    )
    frame = len(rtp).to_bytes(4, "little") + rtp

    with pytest.raises(PyEzvizError, match=r"clear H\.264 media frames"):
        _idmx_local_packets_to_annexb_with_codec([frame])

def test_idmx_ordinary_hevc_slice_is_not_mislabeled_as_h264() -> None:
    payload = b"\x02\x01ordinary-hevc-slice"
    rtp = (
        b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
        + payload
    )
    frame = len(rtp).to_bytes(4, "little") + rtp

    annexb, codec = _idmx_local_packets_to_annexb_with_codec([frame])

    assert codec == "hevc"
    assert annexb == b"\x00\x00\x00\x01" + payload

def test_h264_packet_offsets_ignore_non_h264_payloads() -> None:
    def frame(payload: bytes, *, sequence: int) -> bytes:
        rtp = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + b"\x7d\x52\x2a\x3e\x55\x66\x77\x88"
            + payload
        )
        return len(rtp).to_bytes(4, "little") + rtp

    packets = [
        frame(b"\x02corrupt-type-2", sequence=1),
        frame(b"\x65idr", sequence=2),
    ]

    assert _h264_annexb_packet_end_offsets(packets) == [0, 8]


def test_h264_packet_offsets_use_descriptor_route_inside_aggregate() -> None:
    outer_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    first_media = _rtp_packet(
        b"\x67sps",
        sequence=2,
        payload_type=97,
        ssrc=b"\x55\x66\x77\x88",
    )
    last_media = _rtp_packet(
        b"\x65dynamic",
        sequence=3,
        payload_type=97,
        ssrc=b"\x55\x66\x77\x88",
    )
    aggregate = (
        outer_header
        + b"\x00\x10sidecar"
        + len(first_media).to_bytes(4, "little")
        + first_media
        + len(last_media).to_bytes(4, "little")
        + last_media
    )
    aggregate_packet = len(aggregate).to_bytes(4, "little") + aggregate
    descriptor = _rtp_packet(
        b"metadata",
        sequence=4,
        payload_type=112,
        extension_data=b"\x45\x02\x1b\x61",
        ssrc=b"\x55\x66\x77\x88",
    )

    assert _h264_annexb_packet_end_offsets([aggregate_packet, descriptor]) == [
        20,
        20,
    ]


def test_h264_selected_packets_slice_descriptor_routed_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pyezvizapi.local_stream._decrypt_h264_nal_prefix",
        lambda nal, _key, *, nalu_header_size: nal,
    )
    outer_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    sps = _rtp_packet(
        b"\x67sps",
        sequence=2,
        payload_type=97,
        ssrc=b"\x55\x66\x77\x88",
    )
    idr = _rtp_packet(
        b"\x65dynamic",
        sequence=3,
        payload_type=97,
        ssrc=b"\x55\x66\x77\x88",
    )
    aggregate = (
        outer_header
        + b"\x00\x10sidecar"
        + len(sps).to_bytes(4, "little")
        + sps
        + len(idr).to_bytes(4, "little")
        + idr
    )
    aggregate_packet = len(aggregate).to_bytes(4, "little") + aggregate
    descriptor = _rtp_packet(
        b"metadata",
        sequence=4,
        payload_type=112,
        extension_data=b"\x45\x02\x1b\x61",
        ssrc=b"\x55\x66\x77\x88",
    )
    full_annexb = b"\x00\x00\x00\x01\x67sps\x00\x00\x00\x01\x65dynamic"
    selected_annexb = b"\x00\x00\x00\x01\x65dynamic"

    selected = _idmx_packets_from_selected_annexb(
        [aggregate_packet, descriptor],
        full_annexb=full_annexb,
        selected_annexb=selected_annexb,
        media_key=IDMX_MEDIA_KEY,
        nalu_header_size=0,
        video_input_format="h264",
    )

    assert selected == [len(idr).to_bytes(4, "little") + idr]

def test_copy_local_stream_to_mpegts_drops_h264_fu_a_on_sequence_gap(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x7D522A3E
    sequence_base = 0x5D5C

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        idmx_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    broken_start_fu = b"\x7c\x85broken-first"
    broken_end_fu = b"\x7c\x45broken-last"
    valid_start_fu = b"\x7c\x85native-first"
    valid_end_fu = b"\x7c\x45native-last"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=idmx_frame(broken_start_fu, sequence=sequence_base)
                    + idmx_frame(broken_end_fu, sequence=sequence_base + 2)
                    + idmx_frame(valid_start_fu, sequence=sequence_base + 3)
                    + idmx_frame(valid_end_fu, sequence=sequence_base + 4)
                )
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        b"\x65"
        + valid_start_fu[2:]
        + valid_end_fu[2:]
    )

def test_copy_local_stream_to_mpegts_flattens_command_port_idmx_aggregates(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    outer_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    rtp_timestamp = 0x165477EB
    sequence_base = 0xB712
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    first_fu = b"\x7c\x85aggregate-first"
    last_fu = b"\x7c\x45aggregate-last"

    def inner_frame(body: bytes, *, sequence: int) -> bytes:
        inner_header = (
            b"\xa0\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        frame = inner_header + body
        return len(frame).to_bytes(4, "little") + frame

    aggregate_body = (
        b"\x00\x10aggregate-sidecar"
        + inner_frame(sps, sequence=sequence_base)
        + inner_frame(pps, sequence=sequence_base + 1)
        + inner_frame(first_fu, sequence=sequence_base + 2)
        + inner_frame(last_fu, sequence=sequence_base + 3)
    )
    outer_frame = outer_header + aggregate_body
    packet = len(outer_frame).to_bytes(4, "little") + outer_frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=packet)]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01\x65"
        + first_fu[2:]
        + last_fu[2:]
    )


def test_local_idmx_routes_dynamic_video_inside_aggregate() -> None:
    expected_annexb = b"\x00\x00\x00\x01\x40\x01vps\x00\x00\x00\x01\x26\x01slice"
    outer_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"

    def nested(packet: bytes) -> bytes:
        return len(packet).to_bytes(4, "little") + packet

    aggregate = (
        outer_header
        + b"\x00\x10aggregate-sidecar"
        + nested(
            _rtp_packet(
                b"\x40\x01vps",
                sequence=2,
                payload_type=97,
                ssrc=b"\x55\x66\x77\x88",
            )
        )
        + nested(
            _rtp_packet(
                b"\x26\x01slice",
                sequence=3,
                payload_type=97,
                ssrc=b"\x55\x66\x77\x88",
            )
        )
    )
    packet = len(aggregate).to_bytes(4, "little") + aggregate
    descriptor = _rtp_packet(
        b"metadata",
        payload_type=112,
        extension_data=b"\x45\x02\x24\x61",
        ssrc=b"\x55\x66\x77\x88",
    )
    descriptor_aggregate = (
        outer_header
        + b"\x00\x10metadata-sidecar"
        + nested(descriptor)
    )
    descriptor_packet = (
        len(descriptor_aggregate).to_bytes(4, "little") + descriptor_aggregate
    )

    annexb, codec = _idmx_local_packets_to_annexb_with_codec(
        [descriptor_packet, packet]
    )

    assert codec == "hevc"
    assert annexb == expected_annexb

def test_copy_local_stream_to_mpegts_splits_offset_zero_idmx_aggregates(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    rtp_timestamp = 0x165477EB
    sequence_base = 0xB712
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    packet = frame(sps, sequence=sequence_base) + frame(
        pps,
        sequence=sequence_base + 1,
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=packet)]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01" + sps + b"\x00\x00\x00\x01" + pps
    )

def test_summarize_idmx_h264_local_packets_reports_sanitized_frame_shapes() -> None:
    sequence_base = 0xB712
    rtp_timestamp = 0x165477EB
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    first_fu = b"\x7c\x85aggregate-first"
    last_fu = b"\x7c\x45aggregate-last"

    def frame(body: bytes, *, sequence: int) -> bytes:
        inner_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        idmx_frame = inner_header + body
        return len(idmx_frame).to_bytes(4, "little") + idmx_frame

    summary = summarize_idmx_h264_local_packets(
        [
            frame(sps, sequence=sequence_base),
            frame(pps, sequence=sequence_base + 1),
            frame(first_fu, sequence=sequence_base + 2),
            frame(last_fu, sequence=sequence_base + 3),
        ],
        max_frames=3,
    )

    assert summary["looks_like_idmx"] is True
    assert summary["frame_count"] == 4
    assert summary["sample_limit"] == 3
    assert [sample["kind"] for sample in summary["samples"]] == [
        "h264_nal",
        "h264_nal",
        "h264_fu_a",
    ]
    assert summary["samples"][0]["nal_type"] == 7
    assert summary["samples"][0]["rtp_payload_type"] == 96
    assert summary["samples"][0]["sequence_number"] == sequence_base
    assert summary["samples"][0]["rtp_timestamp"] == rtp_timestamp
    assert summary["samples"][0]["body_sha256"]
    assert summary["packet_shapes"]["length_prefixed_idmx"] == 4
    assert summary["packet_shapes"]["contains_idmx"] == 4
    assert summary["packet_shapes"]["samples"][0]["length_prefix"] == len(
        frame(sps, sequence=sequence_base)
    ) - 4
    assert summary["h264"] == {
        "clear_nal": 2,
        "fu_a": 2,
        "fu_a_start": 1,
        "fu_a_end": 1,
        "non_idr": 0,
        "idr": 2,
        "sei": 0,
        "sps": 1,
        "pps": 1,
        "aud": 0,
        "unknown": 0,
    }
    assert summary["h264_nal_units"] == {
        "sample_limit": 3,
        "samples": [
            {
                "nal_type": 7,
                "start_frame_index": 0,
                "end_frame_index": 0,
                "start_sequence": sequence_base,
                "end_sequence": sequence_base,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(sps),
                "complete": True,
                "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
            },
            {
                "nal_type": 8,
                "start_frame_index": 1,
                "end_frame_index": 1,
                "start_sequence": sequence_base + 1,
                "end_sequence": sequence_base + 1,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(pps),
                "complete": True,
                "sha256": "b93548b426689e9e47d544ea905fd47fe7450d55d2c37c54691c81ab583d080d",
            },
            {
                "nal_type": 5,
                "start_frame_index": 2,
                "end_frame_index": 3,
                "start_sequence": sequence_base + 2,
                "end_sequence": sequence_base + 3,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 2,
                "payload_bytes": 1 + len(first_fu[2:]) + len(last_fu[2:]),
                "complete": True,
                "sha256": "6e8dc59fcf7a0c7fb4b4cbe007426af35bfeabddf2cba6cb34e3a1c33822a8a7",
            },
        ],
        "truncated": False,
        "incomplete_fu_a": 0,
        "discarded_fu_a_fragments": 0,
        "sequence_gap_count": 0,
        "timestamp_change_count": 0,
        "restart_count": 0,
    }

def test_summarize_idmx_h264_local_packets_reports_possible_hrudp_wrappers() -> None:
    sequence_base = 0xB712
    rtp_timestamp = 0x165477EB
    idmx_frame = (
        b"\x80\x60"
        + sequence_base.to_bytes(2, "big")
        + rtp_timestamp.to_bytes(4, "big")
        + b"\x55\x66\x77\x88"
        + b"\x65idr"
    )
    hrdp_header = (
        len(idmx_frame).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
        + (0x2A).to_bytes(4, "little")
    )

    summary = summarize_idmx_h264_local_packets([hrdp_header + idmx_frame])

    assert summary["frame_count"] == 1
    assert summary["packet_shapes"]["possible_hrudp_wrapped"] == 1
    assert summary["packet_shapes"]["possible_hrudp_video"] == 1
    sample = summary["packet_shapes"]["samples"][0]
    assert sample["idmx_offset"] == 12
    assert sample["possible_hrudp"] == {
        "byte_order": "little",
        "payload_length": len(idmx_frame),
        "frame_type": 3,
        "sequence": 0x2A,
        "payload_starts_with_idmx": True,
        "payload_contains_idmx": True,
    }

def test_summarize_idmx_h264_local_packets_reports_rtp_wrapped_hrudp() -> None:
    idmx_frame = (
        b"\x80\x60\xb7\x12\x16\x54\x77\xeb\x55\x66\x77\x88"
        b"\x65idr"
    )
    hrdp_header = (
        len(idmx_frame).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
        + (0x2A).to_bytes(4, "little")
    )

    summary = summarize_idmx_h264_local_packets(
        [_rtp_packet(hrdp_header + idmx_frame)]
    )

    assert summary["packet_shapes"]["possible_hrudp_wrapped"] == 1
    assert summary["packet_shapes"]["possible_hrudp_video"] == 1
    sample = summary["packet_shapes"]["samples"][0]
    assert sample["possible_hrudp"]["rtp_wrapped"] is True
    assert sample["possible_hrudp"]["payload_starts_with_idmx"] is True

def test_hcnetsdk_command_port_media_packet_unwraps_raw_hrudp_idmx_video() -> None:
    idmx_frame = (
        b"\x80\x60\xb7\x12\x16\x54\x77\xeb\x55\x66\x77\x88"
        b"\x65idr"
    )
    hrdp_header = (
        len(idmx_frame).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
        + (0x2A).to_bytes(4, "little")
    )

    packet = _hcnetsdk_command_port_media_packet(
        _raw_media(hrdp_header + idmx_frame),
    )

    assert packet.body == idmx_frame
    assert packet.encrypted is True

def test_hcnetsdk_command_port_media_packet_unwraps_hrudp_idmx_video() -> None:
    idmx_frame = (
        b"\x80\x60\xb7\x12\x16\x54\x77\xeb\x55\x66\x77\x88"
        b"\x65idr"
    )
    hrdp_header = (
        len(idmx_frame).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
        + (0x2A).to_bytes(4, "little")
    )

    packet = _hcnetsdk_command_port_media_packet(
        _media(hrdp_header + idmx_frame),
    )

    assert packet.body == idmx_frame
    assert packet.encrypted is True

def test_hcnetsdk_command_port_media_packet_unwraps_hrudp_mpegps_video() -> None:
    hrdp_header = (
        len(MPEG_PS_PAYLOAD).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
        + (0x2A).to_bytes(4, "little")
    )

    packet = _hcnetsdk_command_port_media_packet(
        _media(hrdp_header + MPEG_PS_PAYLOAD),
    )

    assert packet.body == MPEG_PS_PAYLOAD
    assert packet.encrypted is False

def test_summarize_idmx_h264_local_packets_labels_direct_hevc_frames() -> None:
    sequence_base = 0xB712
    rtp_timestamp = 0x165477EB

    def frame(body: bytes, *, sequence: int) -> bytes:
        inner_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        idmx_frame = inner_header + body
        return len(idmx_frame).to_bytes(4, "little") + idmx_frame

    summary = summarize_idmx_h264_local_packets(
        [
            frame(b"\x40\x01vps", sequence=sequence_base),
            frame(b"\x62\x01\x93slice", sequence=sequence_base + 1),
        ],
        max_frames=2,
    )

    assert [sample["kind"] for sample in summary["samples"]] == [
        "hevc_media",
        "hevc_media",
    ]
    assert summary["samples"][0]["hevc_nal_type"] == 32
    assert summary["samples"][1]["hevc_nal_type"] == 49
    assert summary["hevc"] == {"parameter": 0, "media": 2}

def test_summarize_idmx_h264_local_packets_preserves_packet_boundaries() -> None:
    sequence_base = 0xB712
    rtp_timestamp = 0x165477EB

    def frame(body: bytes, *, sequence: int) -> bytes:
        return (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )

    embedded_idmx_lookalike = (
        b"\x02\x01real"
        + b"\x80\x60\x12\x34\x56\x78\x9a\xbc\x55\x66\x77\x88"
        + b"\x02\x01not-a-frame"
    )

    summary = summarize_idmx_h264_local_packets(
        [
            frame(embedded_idmx_lookalike, sequence=sequence_base),
            frame(b"\x02\x01second-real", sequence=sequence_base + 1),
        ],
        max_frames=4,
    )

    assert summary["frame_count"] == 2
    assert [sample["kind"] for sample in summary["samples"]] == [
        "hevc_media",
        "hevc_media",
    ]
    assert summary["samples"][0]["body_length"] == len(embedded_idmx_lookalike)

def test_summarize_h264_annexb_units_reports_sanitized_nal_shapes() -> None:
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    idr = b"\x65idr"
    non_idr = b"\x41p"

    summary = summarize_h264_annexb_units(
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
        + b"\x00\x00\x00\x01"
        + non_idr,
        max_units=3,
    )

    assert summary == {
        "byte_count": 30,
        "nal_count": 4,
        "sample_limit": 3,
        "samples": [
            {
                "index": 0,
                "start_code_offset": 0,
                "nal_offset": 4,
                "end_offset": 8,
                "nal_type": 7,
                "payload_bytes": len(sps),
                "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
            },
            {
                "index": 1,
                "start_code_offset": 8,
                "nal_offset": 12,
                "end_offset": 16,
                "nal_type": 8,
                "payload_bytes": len(pps),
                "sha256": "b93548b426689e9e47d544ea905fd47fe7450d55d2c37c54691c81ab583d080d",
            },
            {
                "index": 2,
                "start_code_offset": 16,
                "nal_offset": 20,
                "end_offset": 24,
                "nal_type": 5,
                "payload_bytes": len(idr),
                "sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
            },
        ],
        "truncated": True,
        "h264": {
            "non_idr": 1,
            "idr": 1,
            "sei": 0,
            "sps": 1,
            "pps": 1,
            "aud": 0,
            "unknown": 0,
        },
    }

def test_summarize_h264_annexb_units_accepts_short_start_codes() -> None:
    sps = b"\x67\x4d\x00\x29"
    idr = b"\x65idr"
    data = b"\x00\x00\x01" + sps + b"\x00\x00\x00\x01" + idr

    summary = summarize_h264_annexb_units(data)

    assert summary["nal_count"] == 2
    assert summary["samples"] == [
        {
            "index": 0,
            "start_code_offset": 0,
            "nal_offset": 3,
            "end_offset": 7,
            "nal_type": 7,
            "payload_bytes": len(sps),
            "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
        },
        {
            "index": 1,
            "start_code_offset": 7,
            "nal_offset": 11,
            "end_offset": 15,
            "nal_type": 5,
            "payload_bytes": len(idr),
            "sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
        },
    ]

def test_summarize_h264_annexb_idr_windows_reports_sanitized_gops() -> None:
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    idr = b"\x65idr"
    non_idr = b"\x41p"
    second_idr = b"\x65idr2"
    data = (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
        + b"\x00\x00\x00\x01"
        + non_idr
        + b"\x00\x00\x00\x01"
        + second_idr
    )

    summary = summarize_h264_annexb_idr_windows(data, max_windows=1)

    assert summary == {
        "byte_count": 39,
        "nal_count": 5,
        "idr_count": 2,
        "sample_limit": 1,
        "samples": [
            {
                "index": 0,
                "start_nal_index": 0,
                "idr_nal_index": 2,
                "end_nal_index": 4,
                "start_code_offset": 0,
                "idr_start_code_offset": 16,
                "end_offset": 30,
                "window_bytes": 30,
                "leading_nal_types": [7, 8],
                "idr_payload_bytes": len(idr),
                "idr_sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
                "window_sha256": "9834dc06d539401ab4976915d354af8f60fac683120d879456e08d18f4aed766",
            },
        ],
        "truncated": True,
    }

def test_summarize_h264_idr_windows_excludes_next_window_parameters() -> None:
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    idr = b"\x65idr"
    non_idr = b"\x41p"
    next_sps = b"\x67next"
    next_pps = b"\x68next"
    next_idr = b"\x65idr2"
    start_code = b"\x00\x00\x00\x01"
    data = b"".join(
        start_code + nal
        for nal in (sps, pps, idr, non_idr, next_sps, next_pps, next_idr)
    )
    next_window_offset = data.find(start_code + next_sps)

    summary = summarize_h264_annexb_idr_windows(data)
    samples = summary["samples"]
    assert isinstance(samples, list)

    assert samples[0]["end_nal_index"] == 4
    assert samples[0]["end_offset"] == next_window_offset
    assert samples[0]["window_bytes"] == next_window_offset
    assert samples[1]["start_code_offset"] == next_window_offset
    assert samples[1]["leading_nal_types"] == [7, 8]
