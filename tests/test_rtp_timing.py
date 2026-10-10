"""Native clock preservation through actual MPEG-PS/TS demuxers."""

from __future__ import annotations

import io
from itertools import pairwise
import json
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from pyezvizapi import cloud_stream
from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.remux import copy_remuxed_output, open_mpegts_remux_process
from pyezvizapi.rtp import RtpAacStream, RtpPacket
from pyezvizapi.rtp_timing import NativeRtpPsMuxer, timed_rtp_mpegps_payloads


def test_video_clock_wrap_preserves_forward_gaps_and_rejects_reordering() -> None:
    origin = 0xFFFFF000
    units = (b"\x65\x80frame", b"\x41\x80frame", b"\x41\x80frame")
    assert len(list(timed_rtp_mpegps_payloads(units, (origin, 808, 12808), codec="h264"))) == 3
    with pytest.raises(EzvizUnsupportedMediaError, match="nonmonotonic"):
        list(timed_rtp_mpegps_payloads(units, (1000, 9000, 8000), codec="h264"))


def test_incremental_clock_and_startup_memory_are_bounded() -> None:
    muxer = NativeRtpPsMuxer("h264", audio=False)
    assert list(muxer.video(50, b"\x67parameters")) == []
    assert list(muxer.video(100, b"\x65\x80frame"))
    assert list(muxer.video(9100, b"\x41\x80frame"))
    with pytest.raises(PyEzvizError, match="clock reset"):
        list(muxer.video(8000, b"\x41\x80frame"))
    startup = NativeRtpPsMuxer("h264", audio=False)
    with pytest.raises(PyEzvizError, match="buffer limit"):
        list(startup.video(0, b"\x67" + b"x" * 1_048_576))


@pytest.mark.skipif(not shutil.which("ffmpeg") or not shutil.which("ffprobe"), reason="FFmpeg tools unavailable")
@pytest.mark.parametrize("incremental", [False, True])
def test_native_timing_remux_preserves_variable_video_and_missing_aac(tmp_path: Path, incremental: bool) -> None:
    video_path = tmp_path / "video.h264"
    audio_path = tmp_path / "audio.aac"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=size=32x32:rate=10",
        "-frames:v", "4", "-c:v", "libx264", "-tune", "zerolatency", "-x264-params", "aud=1",
        "-f", "h264", str(video_path)], check=True, capture_output=True)
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=sample_rate=16000",
        "-ac", "1", "-frames:a", "12", "-c:a", "aac", "-f", "adts", str(audio_path)], check=True, capture_output=True)
    units = [unit for unit in re.split(b"\x00\x00(?:\x00)?\x01", video_path.read_bytes()) if unit]
    frames: list[bytes] = []
    data = audio_path.read_bytes()
    offset = 0
    while offset < len(data):
        length = ((data[offset + 3] & 3) << 11) | (data[offset + 4] << 3) | (data[offset + 5] >> 5)
        frames.append(data[offset:offset + length])
        offset += length
    times: list[int] = []
    frame_index = -1
    for unit in units:
        if unit[0] & 31 == 9:
            frame_index += 1
        times.append((1000, 10000, 28000, 37000)[frame_index])
    audio = RtpAacStream(b"".join(frames[:1] + frames[2:]), 16000, 1, len(frames) - 1,
        ((0, frames[0]), (2048, b"".join(frames[2:]))))
    if incremental:
        muxer = NativeRtpPsMuxer("h264", audio=True)
        payloads = [p for unit, timestamp in zip(units, times, strict=True) for p in muxer.video(timestamp, unit)]
        for index, frame in enumerate(frames):
            if index != 1:
                payloads.extend(muxer.audio(50_000 + index * 1024, RtpAacStream(frame, 16000, 1, 1)))
    else:
        payloads = list(timed_rtp_mpegps_payloads(units, times, codec="h264", audio=audio))
    output = io.BytesIO()
    process = open_mpegts_remux_process("ffmpeg", preserve_timestamps=True)
    def write_input(stream: BinaryIO) -> None:
        stream.write(b"".join(payloads))

    copy_remuxed_output(process, output, write_input=write_input)
    path = tmp_path / "output.ts"
    path.write_bytes(output.getvalue())
    probe = subprocess.run(["ffprobe", "-v", "error", "-show_packets", "-show_entries",
        "packet=codec_type,pts_time", "-of", "json", str(path)], check=True, capture_output=True)
    assert not probe.stderr
    packets = json.loads(probe.stdout)["packets"]
    video_times = [float(p["pts_time"]) for p in packets if p["codec_type"] == "video"]
    audio_times = [float(p["pts_time"]) for p in packets if p["codec_type"] == "audio"]
    assert len(video_times) == 4
    assert len(audio_times) == len(frames) - 1
    assert [b - a for a, b in pairwise(video_times)] == pytest.approx([0.1, 0.2, 0.1])
    assert audio_times[1] - audio_times[0] == pytest.approx(0.128)
    assert audio_times[-1] - audio_times[0] == pytest.approx((len(frames) - 1) * 1024 / 16000)
    decoded = subprocess.run(["ffmpeg", "-v", "error", "-i", str(path), "-enc_time_base", "-1",
        "-f", "null", "-"], check=True, capture_output=True)
    assert not decoded.stderr


def test_large_access_unit_has_length_delimited_pes_and_no_byte_loss() -> None:
    unit = b"\x26\x01\x80" + b"v" * 150_000
    payloads = list(timed_rtp_mpegps_payloads((unit,), (0,), codec="hevc"))
    assert len(payloads) == 3
    recovered = bytearray()
    for payload in payloads:
        start = payload.index(b"\x00\x00\x01\xe0")
        length = int.from_bytes(payload[start + 4:start + 6], "big")
        assert 0 < length <= 65535
        assert start + 6 + length == len(payload)
        recovered.extend(payload[start + 14:])
    assert recovered == b"\x00\x00\x00\x01" + unit


@pytest.mark.parametrize("invalid", [1023, 0, 0x80000000])
def test_incremental_audio_rejects_non_au_clock_steps(invalid: int) -> None:
    muxer = NativeRtpPsMuxer("h264", audio=True)
    # One empty-payload ADTS frame is enough to exercise framing/clock validation.
    audio = RtpAacStream(b"\xff\xf1\x60\x40\x00\xff\xfc", 16000, 1, 1)
    assert list(muxer.audio(0, audio))
    with pytest.raises(PyEzvizError, match="clock reset"):
        list(muxer.audio(invalid, audio))


def test_native_proxy_accepts_descriptor_backed_aac_after_startup_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    video_descriptor = b"\x42\x0e" + b"\0" * 11 + (6000 << 1).to_bytes(3, "big")
    audio_descriptor = b"\x43\x0a\0\x01\x02\0\xfa\x03\0\0\x03\xff"
    metadata = RtpPacket(b"metadata", 112, 0, 0, 1, False, 2,
        video_descriptor + audio_descriptor + b"\x45\x02\x1b\x60\x45\x02\x0f\x68", True)
    video = [RtpPacket(b"\x67parameters", 96, index, 0, 1, True, 0x4000,
        b"\x80\x06\0\x01\x10\0\0\0", True) for index in range(1, 258)]
    audio_packet = RtpPacket(b"audio", 104, 1, 0, 2, True)
    frame_payload = b"\x65\x80frame"
    frame = RtpPacket(frame_payload, 96, 258, 9000, 1, True)
    parsed = [metadata, *video, audio_packet, frame]
    raw = [SimpleNamespace(body=bytes(index.to_bytes(2, "big"))) for index in range(len(parsed))]
    monkeypatch.setattr(cloud_stream, "_parse_cloud_rtp_packet", lambda body: parsed[int.from_bytes(body, "big")])
    monkeypatch.setattr(cloud_stream, "_require_clear_cloud_packet", lambda *_a, **_kw: None)
    adts = b"\xff\xf1\x60\x40\x00\xff\xfc"
    monkeypatch.setattr(cloud_stream, "decrypt_idmx_aac_packets",
        lambda packets, *_a, **_kw: RtpAacStream(adts, 16000, 1, 1) if next(iter(packets)).payload_type == 104 else None)

    def forbidden_audio_input() -> None:
        pytest.fail("Native timed AV must not open a separate raw AAC connection")

    monkeypatch.setattr(cloud_stream, "_CloudRtpAudioInput", forbidden_audio_input)

    def remux(_path: str, **options: object) -> subprocess.Popen[bytes]:
        assert options["input_format"] == "mpeg"
        assert options["preserve_timestamps"] is True
        return subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    monkeypatch.setattr(cloud_stream, "open_mpegts_remux_process", remux)
    output = io.BytesIO()
    cloud_stream._copy_cloud_rtp_packets_to_mpegts(iter(raw), output, ffmpeg_path="synthetic", cancel_input=None, audio_key="synthetic")  # noqa: SLF001
    audio_pes_start = b"\x00\x00\x01\xc0"
    assert audio_pes_start in output.getvalue()
    assert adts in output.getvalue()
    assert frame_payload in output.getvalue()
