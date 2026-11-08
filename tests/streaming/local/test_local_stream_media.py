"""Tests for local MPEG capture, decryption, clean-window handling, and remuxing."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import io
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi._local_stream import (
    _ffmpeg_h264_decode_errors,
    _ffmpeg_stderr_tail,
    _start_ffmpeg_stderr_drain,
    _try_first_clean_hevc_annexb_irap_window_offset,
    collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window,
    collect_h264_idmx_annexb_after_first_clean_idr_window,
    collect_idmx_annexb_after_first_clean_video_window,
    collect_local_stream_mpegps,
    copy_hcnetsdk_real_data_to_mpegts,
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    skip_h264_annexb_initial_idr_windows,
    skip_hevc_annexb_initial_irap_windows,
    summarize_hevc_annexb_irap_windows,
    trim_h264_annexb_to_first_clean_idr_window,
    trim_h264_annexb_to_first_error_free_suffix,
    trim_hevc_annexb_to_first_clean_irap_window,
    trim_hevc_annexb_to_first_error_free_suffix,
)
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
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

def _rtp_packet(payload: bytes, *, sequence: int = 1) -> bytes:
    return (
        b"\x80\x60"
        + sequence.to_bytes(2, "big")
        + b"\x00\x00\x00\x01"
        + b"\x01\x02\x03\x04"
        + payload
    )

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

def test_copy_local_stream_to_mpegps_writes_payloads_without_ffmpeg() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"\x00\x00\x01\xbaabc"),
                SimpleNamespace(body=b"\x00\x00\x01\xbadef"),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegps(FakeStream(), output, max_packets=2)

    assert output.getvalue() == MPEG_PS_PAYLOAD

def test_collect_local_stream_mpegps_honors_duration() -> None:
    times = iter([10.0, 10.5, 11.6])

    def fake_monotonic() -> float:
        return next(times)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets is None
            return [
                SimpleNamespace(body=b"abc"),
                SimpleNamespace(body=b"def"),
                SimpleNamespace(body=b"ghi"),
            ]

    assert collect_local_stream_mpegps(
        FakeStream(),
        duration_seconds=1.5,
        monotonic=fake_monotonic,
    ) == REMUXED_PAYLOAD

def test_collect_local_stream_mpegps_starts_duration_at_first_packet() -> None:
    times = iter([105.0, 105.5, 106.6])

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=b"abc")
            yield SimpleNamespace(body=b"def")
            yield SimpleNamespace(body=b"ghi")

    assert collect_local_stream_mpegps(
        FakeStream(),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
    ) == REMUXED_PAYLOAD

def test_copy_local_stream_to_mpegts_starts_duration_at_first_packet(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    times = iter([105.0, 105.5, 106.6])

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=b"\x00\x00\x01\xbaabc")
            yield SimpleNamespace(body=b"\x00\x00\x01\xbadef")
            yield SimpleNamespace(body=b"\x00\x00\x01\xbaghi")

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD

def test_copy_local_stream_to_decrypted_mpegps_collects_and_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decrypt_calls: list[dict[str, Any]] = []

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"encrypted-"),
                SimpleNamespace(body=b"payload"),
            ]

    def fake_decrypt(
        data: bytes,
        key: str | bytes,
        *,
        nalu_header_size: int | None,
    ) -> bytes:
        decrypt_calls.append(
            {"data": data, "key": key, "nalu_header_size": nalu_header_size}
        )
        return LOCAL_DECRYPTED_PAYLOAD

    monkeypatch.setattr(
        "pyezvizapi.local_stream.decrypt_hikvision_ps_video",
        fake_decrypt,
    )
    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegps(
        FakeStream(),
        output,
        b"0123456789abcdef",
        nalu_header_size=0,
        max_packets=2,
    )

    assert output.getvalue() == LOCAL_DECRYPTED_PAYLOAD
    assert decrypt_calls == [
        {
            "data": LOCAL_ENCRYPTED_PAYLOAD,
            "key": b"0123456789abcdef",
            "nalu_header_size": 0,
        }
    ]

def test_copy_local_stream_to_decrypted_mpegps_requires_bounded_capture() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("unbounded decrypt should fail before reading")

    with pytest.raises(PyEzvizError, match="duration_seconds or max_packets"):
        copy_local_stream_to_decrypted_mpegps(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
        )

def test_copy_local_stream_to_decrypted_mpegts_remuxes_decrypted_payload(
    monkeypatch: pytest.MonkeyPatch,
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

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=b"encrypted")]

    monkeypatch.setattr(
        "pyezvizapi.local_stream.decrypt_hikvision_ps_video",
        lambda data, key, *, nalu_header_size: LOCAL_DECRYPTED_PAYLOAD,
    )
    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        "media-secret",
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == LOCAL_DECRYPTED_TS_PAYLOAD

def test_ffmpeg_stderr_drain_keeps_bounded_tail() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "sys.stderr.buffer.write(b'x' * 70000 + b'final-marker')\n"
                "sys.stderr.flush()\n"
            ),
        ],
        stderr=subprocess.PIPE,
    )

    chunks, reader = _start_ffmpeg_stderr_drain(process, max_bytes=128)
    assert reader is not None
    assert process.wait(timeout=5) == 0
    reader.join(timeout=5)

    assert _ffmpeg_stderr_tail(chunks, max_chars=64).endswith("final-marker")

def test_copy_local_stream_to_mpegts_prefers_direct_hevc_over_partial_h264(
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
    idr = b"\x26\x01idr-slice"

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 4
            return [
                SimpleNamespace(body=frame(vps, sequence=sequence_base)),
                SimpleNamespace(body=frame(sps, sequence=sequence_base + 1)),
                SimpleNamespace(body=frame(pps, sequence=sequence_base + 2)),
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
        + vps
        + b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
    )

def test_copy_local_stream_to_mpegts_prefers_hevc_idr_over_h264_sei_shape(
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
    hevc_idr_with_h264_sei_shape = b"\x26\x01idr"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(hevc_idr_with_h264_sei_shape))]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01" + hevc_idr_with_h264_sei_shape
    )

def test_copy_local_stream_to_decrypted_mpegps_rejects_idmx_payload() -> None:
    idmx_frame = (
        b"\x0d\xb0\xf0\x50\x37\x03\xb5\xea\xee\x55\x66\x77\x88"
        b"encrypted-playctrl-frame"
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame)]

    output = io.BytesIO()

    with pytest.raises(PyEzvizError, match="decrypt-video is required"):
        copy_local_stream_to_decrypted_mpegps(
            FakeStream(),
            output,
            "media-secret",
            max_packets=1,
        )

    assert not output.getvalue()

def test_copy_local_stream_to_decrypted_mpegts_rejects_unknown_idmx_before_ffmpeg(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "ffmpeg"
    fake_ffmpeg.write_text("#!/bin/sh\nexit 42\n")
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=b"\xfa\x90\x00\x00\x00\x00\x00\x00\x00\x55\x66\x77\x88"
                )
            ]

    with pytest.raises(PyEzvizError, match="did not include media frames"):
        copy_local_stream_to_decrypted_mpegts(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
            ffmpeg_path=str(fake_ffmpeg),
            max_packets=1,
        )

def test_copy_local_stream_to_decrypted_mpegts_requires_bounded_capture() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("unbounded decrypt should fail before reading")

    with pytest.raises(PyEzvizError, match="duration_seconds or max_packets"):
        copy_local_stream_to_decrypted_mpegts(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
        )

def test_copy_local_stream_to_mpegts_rejects_unbounded_clear_idmx_payload() -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    frame = idmx_header + sps
    idmx_packet = len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=idmx_packet)
            raise AssertionError("clear IDMX remux should require a bounded capture")

    with pytest.raises(PyEzvizError, match="IDMX stream remux requires"):
        copy_local_stream_to_mpegts(FakeStream(), io.BytesIO())


def test_copy_local_stream_to_mpegts_rejects_empty_capture() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return []

    with pytest.raises(PyEzvizError, match="did not include media payloads"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            max_packets=1,
        )

def test_copy_local_stream_to_mpegts_pipes_payloads(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"\x00\x00\x01\xbaabc"),
                SimpleNamespace(body=b"\x00\x00\x01\xbadef"),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD

def test_copy_local_stream_to_mpegts_remuxes_clear_h264_idmx_payload(tmp_path) -> None:
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

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(sps)),
                SimpleNamespace(body=idmx_frame(pps)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01" + sps + b"\x00\x00\x00\x01" + pps
    )

def test_copy_local_stream_to_mpegts_preserves_default_h264_idmx_codec(
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
    sps = b"\x67\x4d\x00"
    h264_p_slice_with_hevc_shape = b"\x41\x01p"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(sps)),
                SimpleNamespace(body=idmx_frame(h264_p_slice_with_hevc_shape)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == (
        b"h264:\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + h264_p_slice_with_hevc_shape
    )

def test_copy_local_stream_to_mpegts_ignores_h264_shaped_non_h264_idmx_payload(
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
    non_h264_header = b"\x80\xe8\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    h264_header = b"\x80\x60\x02\x04\x04\x05\x06\x07\x55\x66\x77\x88"
    h264_shaped_sidecar = b"\x65sidecar"
    sps = b"\x67\x4d\x00"

    def idmx_frame(header: bytes, body: bytes) -> bytes:
        frame = header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(non_h264_header, h264_shaped_sidecar)),
                SimpleNamespace(body=idmx_frame(h264_header, sps)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == b"ts:\x00\x00\x00\x01" + sps

def test_copy_local_stream_to_mpegts_can_skip_initial_h264_idr_windows(
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
    aud = b"\x09\xf0"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    idr_bad = b"\x65bad"
    non_idr = b"\x41delta"
    idr_good = b"\x65good"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 7
            return [
                SimpleNamespace(body=idmx_frame(body))
                for body in (aud, sps, pps, idr_bad, non_idr, aud, idr_good)
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=7,
        h264_skip_initial_idr_windows=1,
    )

    assert output.getvalue() == b"ts:\x00\x00\x00\x01" + idr_good

def test_skip_hevc_annexb_initial_irap_windows_requires_requested_window() -> None:
    data = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01irap"
        b"\x00\x00\x00\x01\x02\x01trail"
    )

    with pytest.raises(
        PyEzvizError,
        match="HEVC stream did not contain enough IRAP windows",
    ):
        skip_hevc_annexb_initial_irap_windows(data, 1)

def test_copy_local_stream_to_mpegts_can_preroll_before_clean_idr_trim(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    idr = b"\x65clean"
    late_non_idr = b"\x41late"
    times = iter([100.0, 101.0, 102.0, 103.1])

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            for body in (sps, pps, idr, late_non_idr):
                yield SimpleNamespace(body=idmx_frame(body))

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=0.5,
        monotonic=lambda: next(times),
        h264_trim_to_clean_idr_window=True,
        h264_clean_idr_preroll_seconds=2.0,
    )

    assert output.getvalue() == (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
    )

def test_copy_local_stream_to_mpegts_can_wait_for_clean_idr_before_duration(
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
        "else:\n"
        "    sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    bad_idr = b"\x65bad"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    clean_idr = b"\x65clean"
    late_non_idr = b"\x41late"
    second_idr = b"\x65second"
    times = iter(
        [
            0.0,
            0.5,
            1.0,
            1.5,
            2.0,
            2.25,
            2.5,
            6.0,
            6.75,
            7.0,
            7.25,
            7.5,
            7.75,
            8.0,
            8.25,
            8.5,
            8.75,
            9.0,
        ]
    )

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            for body in (bad_idr, sps, pps, clean_idr, late_non_idr, second_idr):
                yield SimpleNamespace(body=idmx_frame(body))

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
        h264_wait_for_clean_idr_window=True,
        h264_clean_idr_wait_seconds=10.0,
    )

    assert output.getvalue() == (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + clean_idr
        + b"\x00\x00\x00\x01"
        + late_non_idr
        + b"\x00\x00\x00\x01"
        + second_idr
    )

def test_copy_local_stream_to_mpegts_wait_for_clean_idr_bounds_payloads(
    monkeypatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    seen: dict[str, Any] = {}
    clean_annexb = b"\x00\x00\x00\x01\x65clean"

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
        seen["monotonic"] = monotonic
        yield b"idmx-payload"

    def fake_collect(
        packets: Iterator[bytes],
        *,
        duration_seconds: float | None,
        monotonic: Any,
        ffmpeg_path: str,
        max_windows: int,
        wait_seconds: float,
    ) -> tuple[bytes, str]:
        seen["collect_packets"] = list(packets)
        seen["collect_duration_seconds"] = duration_seconds
        seen["collect_wait_seconds"] = wait_seconds
        seen["collect_max_windows"] = max_windows
        return clean_annexb, "h264"

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        fake_iter_payloads,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._looks_like_idmx_local_payload",
        lambda payload: True,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_idmx_annexb_after_first_clean_video_window",
        fake_collect,
    )
    output = io.BytesIO()
    stream = object()
    duration_seconds = 2.5
    wait_seconds = 4.0

    copy_local_stream_to_mpegts(
        stream,
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=duration_seconds,
        max_packets=7,
        h264_wait_for_clean_idr_window=True,
        h264_clean_idr_wait_seconds=wait_seconds,
        h264_clean_idr_max_windows=11,
    )

    assert output.getvalue() == clean_annexb
    assert seen["stream"] is stream
    assert seen["max_packets"] == 7
    assert seen["duration_seconds"] == duration_seconds + wait_seconds
    assert seen["collect_packets"] == [b"idmx-payload"]
    assert seen["collect_duration_seconds"] == duration_seconds
    assert seen["collect_wait_seconds"] == wait_seconds
    assert seen["collect_max_windows"] == 11

def test_copy_local_stream_to_mpegts_wait_for_clean_irap_uses_hevc_remux(
    monkeypatch,
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
    clean_annexb = b"\x00\x00\x00\x01\x40\x01vps\x00\x00\x00\x01\x26\x01clean"

    def fake_collect(
        packets: Iterator[bytes],
        *,
        duration_seconds: float | None,
        monotonic: Any,
        ffmpeg_path: str,
        max_windows: int,
        wait_seconds: float,
    ) -> tuple[bytes, str]:
        assert list(packets) == [b"idmx-payload"]
        return clean_annexb, "hevc"

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        lambda *args, **kwargs: iter([b"idmx-payload"]),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._looks_like_idmx_local_payload",
        lambda payload: True,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_idmx_annexb_after_first_clean_video_window",
        fake_collect,
    )
    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        object(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=2.0,
        h264_wait_for_clean_idr_window=True,
    )

    assert output.getvalue() == b"hevc:" + clean_annexb

def test_collect_h264_idmx_annexb_after_clean_idr_excludes_deadline_packet(
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
        "else:\n"
        "    sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    expected_annexb = (
        b"\x00\x00\x00\x01\x67\x4d\x00"
        b"\x00\x00\x00\x01\x68\xee\x38"
        b"\x00\x00\x00\x01\x65clean"
        b"\x00\x00\x00\x01\x41inside-window"
        b"\x00\x00\x00\x01\x65next-idr"
    )
    post_deadline_body = b"\x41at-deadline"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    annexb = collect_h264_idmx_annexb_after_first_clean_idr_window(
        (
            idmx_frame(body)
            for body in (
                b"\x65bad",
                b"\x67\x4d\x00",
                b"\x68\xee\x38",
                b"\x65clean",
                b"\x41inside-window",
                b"\x65next-idr",
                post_deadline_body,
            )
        ),
        duration_seconds=1.0,
        monotonic=iter([0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.5]).__next__,
        ffmpeg_path=str(fake_ffmpeg),
        wait_seconds=10.0,
    )

    assert annexb == expected_annexb
    assert post_deadline_body not in annexb

def test_collect_idmx_annexb_after_clean_video_window_selects_hevc_irap(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "data = sys.stdin.buffer.read()\n"
        "if codec == 'h264' or b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "    sys.exit(1)\n"
        "else:\n"
        "    sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    bad_vps = b"\x40\x01bad-vps"
    bad_irap = b"\x26\x01bad-irap"
    clean_vps = b"\x40\x01clean-vps"
    clean_irap = b"\x26\x01clean-irap"
    clean_delta = b"\x02\x01clean-delta"
    next_irap = b"\x26\x01next-irap"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    annexb, codec = collect_idmx_annexb_after_first_clean_video_window(
        (
            idmx_frame(body)
            for body in (
                bad_vps,
                bad_irap,
                clean_vps,
                clean_irap,
                clean_delta,
                next_irap,
            )
        ),
        duration_seconds=0.5,
        monotonic=iter([0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5]).__next__,
        ffmpeg_path=str(fake_ffmpeg),
        wait_seconds=10.0,
    )

    assert codec == "hevc"
    assert annexb == (
        b"\x00\x00\x00\x01"
        + clean_vps
        + b"\x00\x00\x00\x01"
        + clean_irap
        + b"\x00\x00\x00\x01"
        + clean_delta
        + b"\x00\x00\x00\x01"
        + next_irap
    )

def test_collect_idmx_annexb_after_clean_video_window_keeps_hevc_probe_prefix(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "data = sys.stdin.buffer.read()\n"
        "prefix = (\n"
        "    b'\\x00\\x00\\x00\\x01\\x40\\x01vps'\n"
        "    b'\\x00\\x00\\x00\\x01\\x42\\x01sps'\n"
        "    b'\\x00\\x00\\x00\\x01\\x44\\x01pps'\n"
        ")\n"
        "if codec == 'h264' or b'bad' in data or not data.startswith(prefix):\n"
        "    sys.stderr.write('PPS id out of range\\n')\n"
        "    sys.exit(1)\n"
        "sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    parameter_sets = (
        b"\x40\x01vps",
        b"\x42\x01sps",
        b"\x44\x01pps",
    )
    bad_irap = b"\x26\x01bad-irap"
    clean_irap = b"\x26\x01clean-irap"
    clean_delta = b"\x02\x01clean-delta"
    next_irap = b"\x26\x01next-irap"
    expected_annexb = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01clean-irap"
        b"\x00\x00\x00\x01\x02\x01clean-delta"
        b"\x00\x00\x00\x01\x26\x01next-irap"
    )

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    annexb, codec = collect_idmx_annexb_after_first_clean_video_window(
        (
            idmx_frame(body)
            for body in (*parameter_sets, bad_irap, clean_irap, clean_delta, next_irap)
        ),
        duration_seconds=0.25,
        monotonic=iter([0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75]).__next__,
        ffmpeg_path=str(fake_ffmpeg),
        wait_seconds=10.0,
    )

    assert codec == "hevc"
    assert annexb == expected_annexb

def test_h264_decode_probe_accepts_success_with_warnings(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stderr.write('corrupt decoded frame\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert _ffmpeg_h264_decode_errors(
        b"\x00\x00\x00\x01\x65frame",
        ffmpeg_path=str(fake_ffmpeg),
    ) == []
    assert _ffmpeg_h264_decode_errors(
        b"\x00\x00\x00\x01\x65frame",
        ffmpeg_path=str(fake_ffmpeg),
        accept_success_with_stderr=False,
    ) == ["corrupt decoded frame"]

def test_h264_decode_probe_reports_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[int] = []

    def fake_run(*_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        timeouts.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(cmd="ffmpeg", timeout=kwargs["timeout"])

    monkeypatch.setattr("pyezvizapi.local_stream.subprocess.run", fake_run)

    assert _ffmpeg_h264_decode_errors(
        b"\x00\x00\x00\x01\x65frame",
        ffmpeg_path="fake-ffmpeg",
        accept_success_with_stderr=False,
    ) == ["ffmpeg video decode check timed out after 1s"]
    assert _ffmpeg_h264_decode_errors(
        b"\x00\x00\x00\x01\x65" + (b"frame" * 500_000),
        ffmpeg_path="fake-ffmpeg",
        accept_success_with_stderr=False,
    ) == ["ffmpeg video decode check timed out after 2s"]
    assert timeouts == [1, 2]

def test_summarize_hevc_irap_window_keeps_aud_with_parameter_sets() -> None:
    vps = b"\x40\x01vps"
    aud = b"\x46\x01aud"
    irap = b"\x26\x01irap"
    annexb = (
        b"\x00\x00\x00\x01"
        + vps
        + b"\x00\x00\x00\x01"
        + aud
        + b"\x00\x00\x00\x01"
        + irap
    )

    summary = summarize_hevc_annexb_irap_windows(annexb)
    samples = summary["samples"]
    assert isinstance(samples, list)

    assert samples[0]["start_code_offset"] == 0
    assert samples[0]["leading_nal_types"] == [32, 35]

def test_summarize_hevc_irap_windows_excludes_next_window_parameters() -> None:
    vps = b"\x40\x01vps"
    sps = b"\x42\x01sps"
    pps = b"\x44\x01pps"
    irap = b"\x26\x01irap"
    delta = b"\x02\x01p"
    next_vps = b"\x40\x01vps2"
    next_sps = b"\x42\x01sps2"
    next_pps = b"\x44\x01pps2"
    next_irap = b"\x26\x01irap2"
    start_code = b"\x00\x00\x00\x01"
    annexb = b"".join(
        start_code + nal
        for nal in (
            vps,
            sps,
            pps,
            irap,
            delta,
            next_vps,
            next_sps,
            next_pps,
            next_irap,
        )
    )
    next_window_offset = annexb.find(start_code + next_vps)

    summary = summarize_hevc_annexb_irap_windows(annexb)
    samples = summary["samples"]
    assert isinstance(samples, list)

    assert samples[0]["end_nal_index"] == 5
    assert samples[0]["end_offset"] == next_window_offset
    assert samples[0]["window_bytes"] == next_window_offset
    assert samples[1]["start_code_offset"] == next_window_offset
    assert samples[1]["leading_nal_types"] == [32, 33, 34]

def test_collect_h264_idmx_annexb_after_clean_idr_times_out(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stderr.write('decode failed\\n')\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    with pytest.raises(PyEzvizError) as exc_info:
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            (
                idmx_frame(body)
                for body in (b"\x65bad", b"\x65second-idr", b"\x41late")
            ),
            duration_seconds=1.0,
            monotonic=iter([0.0, 0.25, 0.5, 1.5]).__next__,
            ffmpeg_path=str(fake_ffmpeg),
            wait_seconds=1.0,
        )
    message = str(exc_info.value)
    assert "Timed out waiting" in message
    assert "checked" in message
    assert "complete sampled IDR windows" in message
    assert "decode failed" in message

def test_copy_local_stream_to_mpegts_wait_for_clean_idr_requires_duration() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid wait settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires duration_seconds"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_wait_for_clean_idr_window=True,
        )

def test_copy_local_stream_to_mpegts_wait_for_clean_idr_rejects_trim_combo() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid wait settings should fail before reading")

    with pytest.raises(PyEzvizError, match="cannot be combined"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_wait_for_clean_idr_window=True,
            h264_trim_to_clean_idr_window=True,
        )

def test_copy_local_stream_to_mpegts_wait_for_clean_idr_rejects_mpegps() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets is None
            return [SimpleNamespace(body=MPEG_PS_PAYLOAD)]

    with pytest.raises(PyEzvizError, match=r"require a clear H\.264 IDMX stream"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_wait_for_clean_idr_window=True,
        )

def test_copy_local_stream_to_mpegts_preroll_requires_clean_idr_trim() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid preroll settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires h264_trim_to_clean_idr_window"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_clean_idr_preroll_seconds=2.0,
        )

def test_copy_local_stream_to_mpegts_preroll_requires_duration() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid preroll settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires duration_seconds"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_trim_to_clean_idr_window=True,
            h264_clean_idr_preroll_seconds=2.0,
        )

def test_copy_local_stream_to_mpegts_passes_clean_idr_max_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    idr = b"\x65clean"
    calls: list[dict[str, Any]] = []

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    def fake_trim(data: bytes, *, ffmpeg_path: str, max_windows: int) -> bytes:
        calls.append(
            {
                "data": data,
                "ffmpeg_path": ffmpeg_path,
                "max_windows": max_windows,
            }
        )
        return data

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(idr))]

    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_clean_idr_window",
        fake_trim,
    )
    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
        h264_trim_to_clean_idr_window=True,
        h264_clean_idr_max_windows=64,
    )

    assert calls[0]["ffmpeg_path"] == str(fake_ffmpeg)
    assert calls[0]["max_windows"] == 64
    assert output.getvalue() == b"\x00\x00\x00\x01" + idr

def test_copy_local_stream_to_mpegts_passes_clean_irap_max_windows_for_hevc(
    monkeypatch: pytest.MonkeyPatch,
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
    irap = b"\x26\x01clean"
    calls: list[dict[str, Any]] = []

    def idmx_frame(body: bytes, *, sequence: int) -> bytes:
        frame = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + body
        )
        return len(frame).to_bytes(4, "little") + frame

    def fake_trim(data: bytes, *, ffmpeg_path: str, max_windows: int) -> bytes:
        calls.append(
            {
                "data": data,
                "ffmpeg_path": ffmpeg_path,
                "max_windows": max_windows,
            }
        )
        return data

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(irap, sequence=sequence_base))]

    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_hevc_annexb_to_first_clean_irap_window",
        fake_trim,
    )
    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
        h264_trim_to_clean_idr_window=True,
        h264_clean_idr_max_windows=64,
    )

    assert calls[0]["ffmpeg_path"] == str(fake_ffmpeg)
    assert calls[0]["max_windows"] == 64
    assert output.getvalue() == b"hevc:\x00\x00\x00\x01" + irap

def test_copy_local_stream_to_mpegts_rejects_invalid_clean_idr_max_windows() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid max windows should fail before reading")

    with pytest.raises(PyEzvizError, match="must be positive"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_clean_idr_max_windows=0,
        )

def test_skip_h264_annexb_initial_idr_windows_requires_enough_idrs() -> None:
    with pytest.raises(PyEzvizError, match="did not contain enough IDR"):
        skip_h264_annexb_initial_idr_windows(b"\x00\x00\x00\x01\x65only", 1)

def test_trim_h264_annexb_to_first_clean_idr_window_uses_ffmpeg(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    data = (
        b"\x00\x00\x00\x01\x67sps"
        b"\x00\x00\x00\x01\x68pps"
        b"\x00\x00\x00\x01\x65bad"
        b"\x00\x00\x00\x01\x41delta"
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )
    clean_window = (
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )

    trimmed = trim_h264_annexb_to_first_clean_idr_window(
        data,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert trimmed == clean_window

def test_trim_h264_annexb_requires_warning_free_decode(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'warn' in data:\n"
        "    sys.stderr.write('corrupt decoded frame\\n')\n"
        "elif b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    data = (
        b"\x00\x00\x00\x01\x67sps"
        b"\x00\x00\x00\x01\x68pps"
        b"\x00\x00\x00\x01\x65warn"
        b"\x00\x00\x00\x01\x41delta"
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )

    trimmed = trim_h264_annexb_to_first_clean_idr_window(
        data,
        ffmpeg_path=str(fake_ffmpeg),
    )

    expected_trimmed = (
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )
    assert trimmed == expected_trimmed

def test_trim_h264_annexb_to_first_error_free_suffix_recovers_at_later_idr(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad-tail' in data:\n"
        "    sys.stderr.write('error while decoding MB 22 34\\n')\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    first = (
        b"\x00\x00\x00\x01\x67sps"
        b"\x00\x00\x00\x01\x68pps"
        b"\x00\x00\x00\x01\x65first-idr"
        b"\x00\x00\x00\x01\x41bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65second-idr"
        b"\x00\x00\x00\x01\x41good-tail"
    )

    trimmed = trim_h264_annexb_to_first_error_free_suffix(
        first + second,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert trimmed == second

def test_h264_strict_decode_probe_ignores_missing_picture_probe_artifact(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stderr.write('[h264] missing picture in access unit with size 36\\n')\n"
        "sys.stderr.write('[h264] no frame!\\n')\n"
        "sys.stderr.write('Decoding error: Invalid data found when processing input\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    assert _ffmpeg_h264_decode_errors(
        b"\x00\x00\x00\x01\x67sps\x00\x00\x00\x01\x65idr",
        ffmpeg_path=str(fake_ffmpeg),
        accept_success_with_stderr=False,
    ) == []

def test_trim_hevc_annexb_to_first_clean_irap_window_uses_ffmpeg(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    data = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01bad"
        b"\x00\x00\x00\x01\x02\x01delta"
        b"\x00\x00\x00\x01\x40\x01vps2"
        b"\x00\x00\x00\x01\x42\x01sps2"
        b"\x00\x00\x00\x01\x44\x01pps2"
        b"\x00\x00\x00\x01\x26\x01good"
    )
    clean_window = (
        b"\x00\x00\x00\x01\x40\x01vps2"
        b"\x00\x00\x00\x01\x42\x01sps2"
        b"\x00\x00\x00\x01\x44\x01pps2"
        b"\x00\x00\x00\x01\x26\x01good"
    )

    trimmed = trim_hevc_annexb_to_first_clean_irap_window(
        data,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert trimmed == clean_window

def test_trim_hevc_clean_irap_carries_prior_parameter_sets(monkeypatch) -> None:
    parameter_sets = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
    )
    first = (
        parameter_sets
        + b"\x00\x00\x00\x01\x26\x01bad-irap"
        + b"\x00\x00\x00\x01\x02\x01bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x26\x01good-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        if data == parameter_sets + second:
            return []
        return ["PPS id out of range: 0"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    trimmed = trim_hevc_annexb_to_first_clean_irap_window(
        first + second,
        ffmpeg_path="fake-ffmpeg",
    )

    assert trimmed == parameter_sets + second

def test_trim_hevc_clean_irap_rejects_dirty_returned_suffix(monkeypatch) -> None:
    bad_tail = b"bad-tail"
    first = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01clean-early-irap"
        b"\x00\x00\x00\x01\x02\x01clean-early-tail"
    )
    dirty_later = (
        b"\x00\x00\x00\x01\x40\x01vps2"
        b"\x00\x00\x00\x01\x42\x01sps2"
        b"\x00\x00\x00\x01\x44\x01pps2"
        b"\x00\x00\x00\x01\x26\x01dirty-later-irap"
        b"\x00\x00\x00\x01\x02\x01" + bad_tail
    )
    clean_later = (
        b"\x00\x00\x00\x01\x40\x01vps3"
        b"\x00\x00\x00\x01\x42\x01sps3"
        b"\x00\x00\x00\x01\x44\x01pps3"
        b"\x00\x00\x00\x01\x26\x01clean-later-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        if data in (dirty_later, clean_later):
            return []
        if bad_tail in data:
            return ["cu_qp_delta outside valid range"]
        return []

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    trimmed = trim_hevc_annexb_to_first_clean_irap_window(
        first + dirty_later + clean_later,
        ffmpeg_path="fake-ffmpeg",
    )

    assert trimmed == clean_later

def test_probe_hevc_clean_irap_carries_prior_parameter_sets(monkeypatch) -> None:
    parameter_sets = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
    )
    first = (
        parameter_sets
        + b"\x00\x00\x00\x01\x26\x01bad-irap"
        + b"\x00\x00\x00\x01\x02\x01bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x26\x01good-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )
    third = (
        b"\x00\x00\x00\x01\x40\x01vps-next"
        b"\x00\x00\x00\x01\x42\x01sps-next"
        b"\x00\x00\x00\x01\x44\x01pps-next"
        b"\x00\x00\x00\x01\x26\x01next-irap"
    )

    def join_packets(packets: list[bytes]) -> bytes:
        return b"".join(packets)

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_hevc_annexb",
        join_packets,
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        if data == parameter_sets + second:
            return []
        return ["PPS id out of range: 0"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    probe = _try_first_clean_hevc_annexb_irap_window_offset(
        [first + second + third],
        ffmpeg_path="fake-ffmpeg",
        max_windows=4,
    )

    assert probe.start_offset == len(first)
    assert probe.prefix == parameter_sets
    assert probe.codec_name == "HEVC"
    assert probe.window_name == "IRAP"

def test_probe_hevc_clean_irap_prefixes_only_missing_parameter_sets(
    monkeypatch,
) -> None:
    prior_vps = b"\x00\x00\x00\x01\x40\x01vps"
    first = (
        prior_vps
        + b"\x00\x00\x00\x01\x26\x01bad-irap"
        + b"\x00\x00\x00\x01\x02\x01bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01good-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )
    third = b"\x00\x00\x00\x01\x26\x01next-irap"

    def join_packets(packets: list[bytes]) -> bytes:
        return b"".join(packets)

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_hevc_annexb",
        join_packets,
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        if data == prior_vps + second:
            return []
        return ["VPS 0 does not exist"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    probe = _try_first_clean_hevc_annexb_irap_window_offset(
        [first + second + third],
        ffmpeg_path="fake-ffmpeg",
        max_windows=4,
    )

    assert probe.start_offset == len(first)
    assert probe.prefix == prior_vps

def test_trim_hevc_annexb_rejects_successful_ffmpeg_with_stderr(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stderr.write('non-fatal slice warning\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    data = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01irap"
    )

    with pytest.raises(
        PyEzvizError,
        match="HEVC stream did not contain a clean sampled IRAP window",
    ):
        trim_hevc_annexb_to_first_clean_irap_window(
            data,
            ffmpeg_path=str(fake_ffmpeg),
        )

def test_try_first_clean_hevc_irap_probe_rejects_successful_ffmpeg_with_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    annexb = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01irap"
        b"\x00\x00\x00\x01\x02\x01tail"
        b"\x00\x00\x00\x01\x26\x01next-irap"
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        return ["cu_qp_delta outside valid range"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_hevc_annexb",
        lambda packets: annexb,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    result = _try_first_clean_hevc_annexb_irap_window_offset(
        [b"packet"],
        ffmpeg_path="fake-ffmpeg",
        max_windows=4,
    )

    assert result.start_offset is None
    assert result.first_decode_error == "cu_qp_delta outside valid range"

def test_trim_hevc_annexb_to_first_error_free_suffix_recovers_at_later_irap(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad-tail' in data:\n"
        "    sys.stderr.write('cu_qp_delta outside valid range\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    first = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
        b"\x00\x00\x00\x01\x26\x01first-irap"
        b"\x00\x00\x00\x01\x02\x01bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x40\x01vps2"
        b"\x00\x00\x00\x01\x42\x01sps2"
        b"\x00\x00\x00\x01\x44\x01pps2"
        b"\x00\x00\x00\x01\x26\x01second-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )

    trimmed = trim_hevc_annexb_to_first_error_free_suffix(
        first + second,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert trimmed == second

def test_trim_hevc_suffix_carries_prior_parameter_sets(monkeypatch) -> None:
    parameter_sets = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
    )
    first = (
        parameter_sets
        + b"\x00\x00\x00\x01\x26\x01first-irap"
        + b"\x00\x00\x00\x01\x02\x01bad-tail"
    )
    second = (
        b"\x00\x00\x00\x01\x26\x01second-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        if data == parameter_sets + second:
            return []
        return ["PPS id out of range: 0"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    trimmed = trim_hevc_annexb_to_first_error_free_suffix(
        first + second,
        ffmpeg_path="fake-ffmpeg",
    )

    assert trimmed == parameter_sets + second

def test_trim_hevc_suffix_probes_recent_acceptable_candidates(monkeypatch) -> None:
    parameter_sets = (
        b"\x00\x00\x00\x01\x40\x01vps"
        b"\x00\x00\x00\x01\x42\x01sps"
        b"\x00\x00\x00\x01\x44\x01pps"
    )
    dirty_windows = [
        b"\x00\x00\x00\x01\x26\x01dirty-irap-%02d"
        b"\x00\x00\x00\x01\x02\x01bad-tail" % index
        for index in range(10)
    ]
    clean_window = (
        b"\x00\x00\x00\x01\x26\x01clean-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )
    calls: list[bytes] = []

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        assert accept_success_with_stderr is False
        calls.append(data)
        if data == parameter_sets + clean_window:
            return []
        return ["cu_qp_delta outside valid range"]

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )

    trimmed = trim_hevc_annexb_to_first_error_free_suffix(
        parameter_sets + b"".join(dirty_windows) + clean_window,
        ffmpeg_path="fake-ffmpeg",
    )

    assert trimmed == parameter_sets + clean_window
    assert len(calls) == 9

def test_collect_idmx_annexb_after_first_clean_video_window_trims_hevc_suffix(
    monkeypatch,
) -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    packets = [
        idmx_frame(b"\x40\x01vps"),
        idmx_frame(b"\x42\x01sps"),
        idmx_frame(b"\x44\x01pps"),
        idmx_frame(b"\x26\x01first-irap"),
        idmx_frame(b"\x02\x01bad-tail"),
        idmx_frame(b"\x40\x01vps2"),
        idmx_frame(b"\x42\x01sps2"),
        idmx_frame(b"\x44\x01pps2"),
        idmx_frame(b"\x26\x01second-irap"),
        idmx_frame(b"\x02\x01good-tail"),
    ]
    times = iter([0.0, 0.01, 0.02, 0.03, 0.04, 0.10, 0.11, 0.12, 0.13, 0.14])

    def fake_monotonic() -> float:
        return next(times, 0.14)

    def fake_errors(
        data: bytes,
        *,
        ffmpeg_path: str,
        accept_success_with_stderr: bool = True,
    ) -> list[str]:
        assert ffmpeg_path == "fake-ffmpeg"
        first_irap_marker = b"first-irap"
        if first_irap_marker in data and not accept_success_with_stderr:
            return ["cu_qp_delta outside valid range"]
        return []

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        fake_errors,
    )
    def fake_probe(packets: list[bytes], *_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        if len(packets) < 9:
            return None, None, None, SimpleNamespace()
        return 0, "hevc", None, SimpleNamespace()

    monkeypatch.setattr(
        "pyezvizapi.local_stream._probe_first_clean_idmx_video_window",
        fake_probe,
    )

    annexb, codec = collect_idmx_annexb_after_first_clean_video_window(
        packets,
        duration_seconds=0.02,
        monotonic=fake_monotonic,
        ffmpeg_path="fake-ffmpeg",
    )

    assert codec == "hevc"
    expected_annexb = (
        b"\x00\x00\x00\x01\x40\x01vps2"
        b"\x00\x00\x00\x01\x42\x01sps2"
        b"\x00\x00\x00\x01\x44\x01pps2"
        b"\x00\x00\x00\x01\x26\x01second-irap"
        b"\x00\x00\x00\x01\x02\x01good-tail"
    )
    assert annexb == expected_annexb

def test_collect_idmx_annexb_after_first_clean_video_window_starts_hevc_duration_at_irap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    first_irap_marker = b"first-irap"
    second_irap_marker = b"second-irap"
    late_tail_marker = b"late-tail"
    packets = [
        idmx_frame(b"\x40\x01vps"),
        idmx_frame(b"\x42\x01sps"),
        idmx_frame(b"\x44\x01pps"),
        idmx_frame(b"\x26\x01" + first_irap_marker),
        idmx_frame(b"\x02\x01first-tail"),
        idmx_frame(b"\x26\x01" + second_irap_marker),
        idmx_frame(b"\x02\x01" + late_tail_marker),
    ]
    times = iter([0.0, 0.01, 0.02, 0.03, 0.04, 0.13, 0.14])

    monkeypatch.setattr(
        "pyezvizapi.local_stream._ffmpeg_hevc_decode_errors",
        lambda *_args, **_kwargs: [],
    )

    annexb, codec = collect_idmx_annexb_after_first_clean_video_window(
        packets,
        duration_seconds=0.05,
        monotonic=lambda: next(times, 0.14),
        ffmpeg_path="fake-ffmpeg",
    )

    assert codec == "hevc"
    assert first_irap_marker in annexb
    assert second_irap_marker not in annexb
    assert late_tail_marker not in annexb

def test_collect_h264_after_clean_idr_waits_for_clean_final_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    packets = [idmx_frame(b"\x65first-idr")] + [
        idmx_frame(b"\x41tail-%03d" % index) for index in range(258)
    ]
    times = iter([0.0, 0.02, *([0.05] * 257)])

    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        lambda *_args, **_kwargs: SimpleNamespace(
            start_offset=0,
            idr_start_offset=0,
            first_decode_error=None,
        ),
    )
    trim_calls = 0

    def fake_trim(
        data: bytes,
        *,
        ffmpeg_path: str,
        max_windows: int,
        accept_start_offset: Any | None = None,
    ) -> bytes:
        nonlocal trim_calls
        assert ffmpeg_path == "fake-ffmpeg"
        assert max_windows == 7
        trim_calls += 1
        if trim_calls == 1:
            raise PyEzvizError("first suffix still corrupt")
        return data

    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        fake_trim,
    )

    annexb = collect_h264_idmx_annexb_after_first_clean_idr_window(
        packets,
        duration_seconds=0.01,
        monotonic=lambda: next(times, 0.03),
        ffmpeg_path="fake-ffmpeg",
        max_windows=7,
    )

    assert trim_calls == 2
    expected_tail_marker = b"tail-255"
    assert expected_tail_marker in annexb

def test_collect_decrypted_h264_after_clean_idr_retries_final_suffix_clear_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"packet-%03d" % index for index in range(259)]
    times = iter([0.0, 0.02, *([0.05] * 257)])
    annexb_by_count: list[int] = []

    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        lambda *_args, **_kwargs: SimpleNamespace(
            start_offset=0,
            idr_start_offset=0,
            first_decode_error=None,
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._h264_annexb_packet_index_for_offset",
        lambda *_args, **_kwargs: 0,
    )

    def fake_packets_to_annexb(collected: list[bytes]) -> bytes:
        annexb_by_count.append(len(collected))
        return b"annexb-count-%d" % len(collected)

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_h264_annexb",
        fake_packets_to_annexb,
    )
    trim_calls = 0

    def fake_trim(
        data: bytes,
        *,
        ffmpeg_path: str,
        max_windows: int,
        accept_start_offset: Any | None = None,
    ) -> bytes:
        nonlocal trim_calls
        assert ffmpeg_path == "fake-ffmpeg"
        assert max_windows == 5
        trim_calls += 1
        if trim_calls == 1:
            raise PyEzvizError("deadline suffix still corrupt")
        return data

    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        fake_trim,
    )

    annexb = collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
        packets,
        IDMX_MEDIA_KEY,
        duration_seconds=0.01,
        monotonic=lambda: next(times, 0.03),
        ffmpeg_path="fake-ffmpeg",
        max_windows=5,
    )

    assert trim_calls == 2
    expected_annexb = b"annexb-count-257"
    assert annexb == expected_annexb
    assert annexb_by_count[:2] == [1, 257]

def test_collect_h264_after_clean_idr_propagates_dirty_final_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    idmx_frame = _sequential_idmx_frame_factory(idmx_header)

    packets = [idmx_frame(b"\x65first-idr")] + [
        idmx_frame(b"\x41tail-%03d" % index) for index in range(258)
    ]
    times = iter([0.0, 0.02, *([0.03] * 257)])
    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        lambda *_args, **_kwargs: SimpleNamespace(
            start_offset=0,
            idr_start_offset=0,
            first_decode_error=None,
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PyEzvizError("still dirty")
        ),
    )

    with pytest.raises(PyEzvizError, match="still dirty"):
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            duration_seconds=0.0,
            monotonic=lambda: next(times, 0.05),
            ffmpeg_path="fake-ffmpeg",
            wait_seconds=0.03,
        )

def test_collect_idmx_after_clean_video_times_out_on_dirty_final_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"packet-%03d" % index for index in range(259)]
    times = iter([0.0, 0.02, *([0.05] * 257)])
    monkeypatch.setattr(
        "pyezvizapi.local_stream._probe_first_clean_idmx_video_window",
        lambda *_args, **_kwargs: (
            0,
            "h264",
            None,
            SimpleNamespace(start_offset=0, first_decode_error=None),
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_h264_annexb",
        lambda collected: b"annexb-count-%d" % len(collected),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PyEzvizError("still dirty")
        ),
    )

    with pytest.raises(PyEzvizError, match="clean final H264 suffix"):
        collect_idmx_annexb_after_first_clean_video_window(
            packets,
            duration_seconds=0.0,
            monotonic=lambda: next(times, 0.05),
            ffmpeg_path="fake-ffmpeg",
            wait_seconds=0.03,
        )

def test_collect_decrypted_h264_after_clean_idr_times_out_on_dirty_final_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"packet-%03d" % index for index in range(259)]
    times = iter([0.0, 0.02, *([0.05] * 257)])
    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        lambda *_args, **_kwargs: SimpleNamespace(
            start_offset=0,
            idr_start_offset=0,
            first_decode_error=None,
        ),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._h264_annexb_packet_index_for_offset",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_h264_annexb",
        lambda collected: b"annexb-count-%d" % len(collected),
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PyEzvizError("still dirty")
        ),
    )

    with pytest.raises(PyEzvizError, match=r"clean final H\.264 suffix"):
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            IDMX_MEDIA_KEY,
            duration_seconds=0.0,
            monotonic=lambda: next(times, 0.05),
            ffmpeg_path="fake-ffmpeg",
            wait_seconds=0.03,
        )

def test_collect_h264_after_clean_idr_stops_after_max_dirty_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_probe(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            start_offset=None,
            first_decode_error="slice header decode failed",
            complete_window_count=3,
            idr_count=4,
            nal_count=12,
            codec_name="H.264",
            window_name="IDR",
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        fake_probe,
    )

    with pytest.raises(
        PyEzvizError,
        match=r"did not contain a clean IDR window: checked 3 complete sampled IDR windows",
    ):
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            [b"packet-0", b"packet-1"],
            duration_seconds=1.0,
            monotonic=lambda: 0.0,
            ffmpeg_path="fake-ffmpeg",
            max_windows=3,
        )

    assert calls == 1

def test_collect_idmx_after_clean_video_stops_after_max_dirty_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_probe(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal calls
        calls += 1
        return (
            None,
            None,
            "CABAC_MAX_BIN",
            SimpleNamespace(
                start_offset=None,
                first_decode_error="CABAC_MAX_BIN",
                complete_window_count=4,
                idr_count=5,
                nal_count=24,
                codec_name="HEVC",
                window_name="IRAP",
            ),
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream._probe_first_clean_idmx_video_window",
        fake_probe,
    )

    with pytest.raises(
        PyEzvizError,
        match=r"did not contain a clean video window: checked 4 complete sampled IRAP windows",
    ):
        collect_idmx_annexb_after_first_clean_video_window(
            [b"packet-0", b"packet-1"],
            duration_seconds=1.0,
            monotonic=lambda: 0.0,
            ffmpeg_path="fake-ffmpeg",
            max_windows=4,
        )

    assert calls == 1

def test_collect_idmx_after_dirty_complete_window_throttles_repeated_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fake_probe(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal calls
        calls += 1
        return (
            None,
            None,
            "CABAC_MAX_BIN",
            SimpleNamespace(
                start_offset=None,
                first_decode_error="CABAC_MAX_BIN",
                complete_window_count=1,
                idr_count=2,
                nal_count=8,
                codec_name="HEVC",
                window_name="IRAP",
            ),
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream._probe_first_clean_idmx_video_window",
        fake_probe,
    )

    with pytest.raises(PyEzvizError, match="ended before a clean video window"):
        collect_idmx_annexb_after_first_clean_video_window(
            [b"packet-%02d" % index for index in range(50)],
            duration_seconds=1.0,
            monotonic=lambda: 0.0,
            ffmpeg_path="fake-ffmpeg",
            max_windows=4,
        )

    assert calls == 17

def test_collect_idmx_after_clean_video_probes_final_buffer_after_throttle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packets = [b"packet-%02d" % index for index in range(20)]
    calls = 0

    def fake_probe(collected: list[bytes], *_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        nonlocal calls
        calls += 1
        if len(collected) == len(packets):
            return (
                0,
                "h264",
                "earlier decode failed",
                SimpleNamespace(
                    start_offset=0,
                    idr_start_offset=0,
                    first_decode_error="earlier decode failed",
                    complete_window_count=1,
                    idr_count=1,
                    nal_count=2,
                    codec_name="H.264",
                    window_name="IDR",
                ),
            )
        return (
            None,
            None,
            "earlier decode failed",
            SimpleNamespace(
                start_offset=None,
                first_decode_error="earlier decode failed",
                complete_window_count=0,
                idr_count=0,
                nal_count=0,
                codec_name="H.264",
                window_name="IDR",
            ),
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream._probe_first_clean_idmx_video_window",
        fake_probe,
    )

    def join_packets(collected: list[bytes]) -> bytes:
        return b"".join(collected)

    monkeypatch.setattr(
        "pyezvizapi.local_stream._idmx_local_packets_to_h264_annexb",
        join_packets,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_error_free_suffix",
        lambda data, **_kwargs: data,
    )

    annexb, codec = collect_idmx_annexb_after_first_clean_video_window(
        packets,
        duration_seconds=1.0,
        monotonic=lambda: 0.0,
        ffmpeg_path="fake-ffmpeg",
    )

    assert codec == "h264"
    assert annexb == b"".join(packets)
    assert calls == 16

def test_collect_decrypted_h264_after_clean_idr_stops_after_max_dirty_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_h264_annexb_idr_window_offset",
        lambda *_args, **_kwargs: SimpleNamespace(
            start_offset=None,
            first_decode_error=None,
            complete_window_count=0,
            idr_count=0,
            nal_count=0,
            codec_name="H.264",
            window_name="IDR",
        ),
    )

    def fake_decrypted_probe(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            start_offset=None,
            first_decode_error="slice header decode failed",
            complete_window_count=2,
            idr_count=3,
            nal_count=9,
            codec_name="H.264",
            window_name="IDR",
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream._try_first_clean_decrypted_h264_annexb_idr_window_offset",
        fake_decrypted_probe,
    )

    with pytest.raises(
        PyEzvizError,
        match=r"did not contain a clean IDR window: checked 2 complete sampled IDR windows",
    ):
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            [b"packet-0", b"packet-1"],
            IDMX_MEDIA_KEY,
            duration_seconds=1.0,
            monotonic=lambda: 0.0,
            ffmpeg_path="fake-ffmpeg",
            max_windows=2,
        )

    assert calls == 1

def test_clean_video_collectors_validate_window_settings() -> None:
    packets = [b"packet"]

    with pytest.raises(PyEzvizError, match="duration_seconds is required"):
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            duration_seconds=None,
        )
    with pytest.raises(PyEzvizError, match="wait_seconds cannot be negative"):
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            duration_seconds=1.0,
            wait_seconds=-1.0,
        )
    with pytest.raises(PyEzvizError, match="max_windows must be positive"):
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            duration_seconds=1.0,
            max_windows=0,
        )
    with pytest.raises(PyEzvizError, match="duration_seconds is required"):
        collect_idmx_annexb_after_first_clean_video_window(
            packets,
            duration_seconds=None,
        )
    with pytest.raises(PyEzvizError, match="wait_seconds cannot be negative"):
        collect_idmx_annexb_after_first_clean_video_window(
            packets,
            duration_seconds=1.0,
            wait_seconds=-1.0,
        )
    with pytest.raises(PyEzvizError, match="duration_seconds is required"):
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            IDMX_MEDIA_KEY,
            duration_seconds=None,
        )
    with pytest.raises(PyEzvizError, match="wait_seconds cannot be negative"):
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            IDMX_MEDIA_KEY,
            duration_seconds=1.0,
            wait_seconds=-1.0,
        )
    with pytest.raises(PyEzvizError, match="max_windows must be positive"):
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            packets,
            IDMX_MEDIA_KEY,
            duration_seconds=1.0,
            max_windows=0,
        )

def test_copy_hcnetsdk_real_data_to_mpegts_filters_and_pipes_payloads(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    output = io.BytesIO()

    copy_hcnetsdk_real_data_to_mpegts(
        [
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"sys"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"abc"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"\x00\x00\x01\xbaabc"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.AUDIO_STREAM_DATA, b"\x00\x00\x01\xbadef"),
        ],
        output,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD
