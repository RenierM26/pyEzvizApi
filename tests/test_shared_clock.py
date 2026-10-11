"""Opt-in source clock alignment, wrap arithmetic and output failure isolation."""

import io
from pathlib import Path

import pytest

from pyezvizapi import CaptureLimits, ClipOptions, EzvizClient, MediaMuxOptions
from pyezvizapi.clip import (
    AutoClipSource,
    CloudClipSource,
    HcNetSdkCommandPortClipSource,
    LocalSdkClipSource,
)
from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.rtp import RtpAacStream
from pyezvizapi.rtp_timing import shared_rtp_clock_offsets, timed_rtp_mpegps_payloads


@pytest.mark.parametrize("uptime", [10, 47722, 100000, 268436, 999999])
@pytest.mark.parametrize("audio_offset_samples", [-2048, 0, 2048])
def test_shared_epoch_handles_both_counter_wraps(uptime, audio_offset_samples):
    video = (uptime * 90000) % 2**32
    audio = (uptime * 16000 + audio_offset_samples) % 2**32
    offsets = shared_rtp_clock_offsets(video, audio, 16000)
    expected = abs(audio_offset_samples) * 90000 // 16000
    assert offsets == ((expected, 0) if audio_offset_samples < 0 else (0, expected))


@pytest.mark.parametrize(("video", "audio"), [(2268960982, 1166918530)])
def test_retained_clap_origin_recovers_received_offset_not_fixed_calibration(video, audio):
    assert shared_rtp_clock_offsets(video, audio, 16000) == (11547, 0)


@pytest.mark.parametrize(("video", "audio", "rate"), [
    (0, 32000, 16000), (0, 0, 44100), (-1, 0, 16000), (0, 2**32, 16000),
])
def test_shared_epoch_rejects_incompatible_or_unsupported_clocks(video, audio, rate):
    with pytest.raises(EzvizUnsupportedMediaError) as caught:
        shared_rtp_clock_offsets(video, audio, rate)
    assert caught.value.reason == "unsupported_av_clock"


def _pes_times(payloads):
    result: dict[int, list[int]] = {0xe0: [], 0xc0: []}
    for payload in payloads:
        for stream, stamps in result.items():
            marker = b"\x00\x00\x01" + bytes([stream])
            if marker not in payload:
                continue
            start = payload.index(marker)
            pts = payload[start + 9:start + 14]
            stamp = ((pts[0] & 14) << 29) | (pts[1] << 22) | ((pts[2] & 254) << 14) | (pts[3] << 7) | (pts[4] >> 1)
            stamps.append(stamp)
    return result


def test_shared_alignment_retains_all_media_gaps_and_default_independent_origins():
    frame = b"\xff\xf1\x60\x40\x00\xff\xfc"
    audio = RtpAacStream(frame * 2, 16000, 1, 2, ((0, frame), (2048, frame)), 157952)
    units = (b"\x67parameters", b"\x65\x80one", b"\x41\x80two", b"\x41\x80three")
    times = (123, 900000, 906000, 918000)
    independent = _pes_times(timed_rtp_mpegps_payloads(units, times, codec="h264", audio=audio))
    shared = _pes_times(timed_rtp_mpegps_payloads(units, times, codec="h264", audio=audio, shared_clock=True))
    assert independent == {0xe0: [0, 6000, 18000], 0xc0: [0, 11520]}
    assert shared == {0xe0: [11520, 17520, 29520], 0xc0: [0, 11520]}


@pytest.mark.parametrize("audio", [None, RtpAacStream(b"", 16000, 1, 0), RtpAacStream(b"", 16000, 1, 0, origin_timestamp=0)])
def test_shared_alignment_never_guesses_missing_audio_origin(audio):
    with pytest.raises(EzvizUnsupportedMediaError, match="source-timestamped AAC"):
        list(timed_rtp_mpegps_payloads((b"\x65\x80frame",), (0,), codec="h264", audio=audio, shared_clock=True))


@pytest.mark.parametrize("units", [(), (b"\x67parameters",), (b"\x67" + b"x" * 1048576,)])
def test_shared_alignment_requires_bounded_real_video_start(units):
    audio = RtpAacStream(b"\xff\xf1\x60\x40\x00\xff\xfc", 16000, 1, 1, origin_timestamp=0)
    with pytest.raises(EzvizUnsupportedMediaError):
        list(timed_rtp_mpegps_payloads(units, (0,) * len(units), codec="h264", audio=audio, shared_clock=True))


@pytest.mark.parametrize("source", [AutoClipSource(), CloudClipSource()])
def test_shared_high_level_requires_explicit_native_source(source):
    client = EzvizClient()
    options = ClipOptions(source=source, mux=MediaMuxOptions(native_shared_clock=True))
    with pytest.raises(PyEzvizError, match="explicit"):
        client.save_clip_with_options("camera", io.BytesIO(), options)


@pytest.mark.parametrize("destination_kind", ["file", "buffer"])
def test_shared_high_level_stages_clock_failure_and_forwards_opt_in(monkeypatch, tmp_path, destination_kind):
    client = EzvizClient()
    existing = b"existing"
    destination = tmp_path / "clip.ts" if destination_kind == "file" else io.BytesIO(existing)
    if isinstance(destination, Path):
        destination.write_bytes(existing)
    else:
        destination.seek(0, 2)
    options = ClipOptions(source=LocalSdkClipSource(), mux=MediaMuxOptions(native_shared_clock=True))
    def failing(serial, output, **kwargs):
        assert kwargs["native_shared_clock"] is True
        output.write(b"partial")
        raise EzvizUnsupportedMediaError("clock incompatible", source="rtp", reason="unsupported_av_clock")
    monkeypatch.setattr(client, "_save_local_sdk_clip", failing)
    with pytest.raises(EzvizUnsupportedMediaError):
        client.save_clip_with_options("camera", destination, options)
    assert (destination.read_bytes() if isinstance(destination, Path) else destination.getvalue()) == existing


def test_shared_high_level_commits_success_and_reports_real_destination(monkeypatch, tmp_path):
    client = EzvizClient()
    destination = tmp_path / "clip.ts"
    complete = b"complete"
    def successful(serial, output, **kwargs):
        assert kwargs["native_shared_clock"] is True
        output.write(complete)
        return {"ok": True, "format": "mpegts"}
    monkeypatch.setattr(client, "_save_local_sdk_clip", successful)
    result = client.save_clip_with_options("camera", destination, ClipOptions(
        source=LocalSdkClipSource(), mux=MediaMuxOptions(native_shared_clock=True),
        capture=CaptureLimits(duration_seconds=10),
    ))
    assert destination.read_bytes() == complete
    assert result["output"] == str(destination)
    assert result["bytes"] == 8
    assert result["content_type"] == "video/mp2t"


def test_shared_high_level_forwards_to_command_port(monkeypatch):
    client = EzvizClient()
    output = io.BytesIO()
    complete = b"complete"
    def successful(serial, target, **kwargs):
        assert kwargs["native_shared_clock"] is True
        target.write(complete)
        return {"ok": True, "format": "mpegts"}
    monkeypatch.setattr(client, "_save_hcnetsdk_command_port_clip", successful)
    client.save_clip_with_options("camera", output, ClipOptions(
        source=HcNetSdkCommandPortClipSource(),
        capture=CaptureLimits(duration_seconds=10),
        mux=MediaMuxOptions(native_shared_clock=True),
    ))
    assert output.getvalue() == complete
