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


def test_clock_probe_is_advisory_and_cannot_authenticate_an_epoch():
    from pyezvizapi import probe_native_rtp_clock  # noqa: PLC0415
    audio = RtpAacStream(b"frame", 16000, 1, 1, origin_timestamp=157952, source_keys=((2, None),))
    report = probe_native_rtp_clock(900000, audio)
    assert report.candidate_offsets_90khz == (11520, 0)
    assert report.audio_source_count == 1
    assert report.shared_epoch_verified is False
    assert report.reason is None


@pytest.mark.parametrize(("origin", "audio"), [
    (None, None), (0, None), (0, RtpAacStream(b"frame", 16000, 1, 1)),
    (0, RtpAacStream(b"frame", 8000, 1, 1, origin_timestamp=0)),
    (0, RtpAacStream(b"frame", 16000, 1, 1, origin_timestamp=32000)),
])
def test_clock_probe_reports_missing_or_incompatible_timing_without_network(origin, audio):
    from pyezvizapi import probe_native_rtp_clock  # noqa: PLC0415
    report = probe_native_rtp_clock(origin, audio)
    assert report.candidate_offsets_90khz is None
    assert report.reason
    assert report.shared_epoch_verified is False


def test_shared_clock_rejects_multiple_accepted_aac_sources_even_with_near_origins():
    from pyezvizapi import probe_native_rtp_clock  # noqa: PLC0415
    frame = b"\xff\xf1\x60\x40\x00\xff\xfc"
    audio = RtpAacStream(frame, 16000, 1, 1, origin_timestamp=0, source_keys=((2, None), (3, None)))
    report = probe_native_rtp_clock(0, audio)
    assert report.reason == "multiple AAC source clocks"
    assert report.candidate_offsets_90khz is None
    with pytest.raises(EzvizUnsupportedMediaError, match="multiple AAC"):
        list(timed_rtp_mpegps_payloads((b"\x65\x80frame",), (0,), codec="h264", audio=audio, shared_clock=True))
    # Default output retains the prior independent-origin behavior.
    assert list(timed_rtp_mpegps_payloads((b"\x65\x80frame",), (0,), codec="h264", audio=audio))


def test_encrypted_trim_combination_rejected_before_connection_and_output(monkeypatch):
    from pyezvizapi import MediaDecodeOptions  # noqa: PLC0415
    client = EzvizClient()
    existing = b"existing"
    output = io.BytesIO(existing)
    def forbidden(*args, **kwargs):
        pytest.fail("invalid timing options must be rejected before connecting")
    monkeypatch.setattr(client, "_save_hcnetsdk_command_port_clip", forbidden)
    options = ClipOptions(source=HcNetSdkCommandPortClipSource(),
                          decode=MediaDecodeOptions(decrypt_video=True),
                          mux=MediaMuxOptions(native_shared_clock=True, h264_wait_for_clean_idr_window=True))
    with pytest.raises(PyEzvizError, match="encrypted startup trimming"):
        client.save_clip_with_options("camera", output, options)
    assert output.getvalue() == existing


@pytest.mark.parametrize("source", ["local-sdk", "hcnetsdk-command-port"])
def test_long_form_save_clip_preserves_shared_opt_in_when_building_mux(monkeypatch, source):
    client = EzvizClient()
    observed = []
    def typed(serial, output, options):
        observed.append(options.resolved_mux())
        return {"ok": True}
    monkeypatch.setattr(client, "save_clip_with_options", typed)
    client.save_clip("camera", io.BytesIO(), source=source, native_shared_clock=True)
    assert observed[0].native_shared_clock is True


def test_aac_provenance_tracks_only_accepted_media_not_metadata_or_invalid_packets():
    from pyezvizapi.rtp import RtpPacket, decrypt_idmx_aac_packets  # noqa: PLC0415
    extension = b"\x80\x06\x00\x01\x21\x21\x02\x01"
    payload = b"\x00\x10\x00\x08x"
    packets = [RtpPacket(b"metadata", 112, 1, 0, 77, False),
               RtpPacket(b"bad", 104, 1, 0, 99, False),
               RtpPacket(payload, 104, 1, 0, 2, False, 0x4000, extension, True),
               RtpPacket(payload, 104, 1, 1024, 3, False, 0x4000, extension, True)]
    audio = decrypt_idmx_aac_packets(packets, b"", audio_metadata=(16000, 1), decrypt_audio=False)
    assert audio is not None
    assert audio.source_keys == ((2, None), (3, None))
    assert audio.origin_timestamp == 0


def test_native_shared_clock_rejects_multiple_completed_video_sources_before_ffmpeg(monkeypatch):
    from fractions import Fraction  # noqa: PLC0415

    from pyezvizapi import _local_stream as local  # noqa: PLC0415
    monkeypatch.setattr(local, "_idmx_local_video_payload_types", lambda *a, **k: frozenset({96}))
    monkeypatch.setattr(local, "_clear_native_rtp_packets_with_legacy_indices", lambda *a: ([], set()))
    monkeypatch.setattr(local, "idmx_video_frame_rate", lambda *a: Fraction(15))
    monkeypatch.setattr(local, "detect_rtp_video_codec", lambda *a, **k: "h264")
    def units(packets, **kwargs):
        kwargs["nal_timestamps"].extend([0, 6000])
        kwargs["nal_source_keys"].extend([(2, None), (3, None)])
        return [b"\x65\x80one", b"\x41\x80two"]
    monkeypatch.setattr(local, "rtp_packets_to_nal_units", units)
    def forbidden(*args, **kwargs):
        pytest.fail("mixed clocks must fail before starting FFmpeg")
    monkeypatch.setattr(local, "open_mpegts_remux_process", forbidden)
    with pytest.raises(EzvizUnsupportedMediaError, match="multiple video source clocks"):
        local._copy_clear_native_idmx_timed_av([], None, io.BytesIO(), ffmpeg_path="unused", native_shared_clock=True)  # noqa: SLF001


@pytest.mark.parametrize(("video", "audio", "rate"), [(True, 0, 16000), (0.0, 0, 16000), (0, 0, 16000.0)])
def test_shared_clock_rejects_non_integer_timestamp_and_rate_values(video, audio, rate):
    with pytest.raises(EzvizUnsupportedMediaError):
        shared_rtp_clock_offsets(video, audio, rate)


@pytest.mark.parametrize("value", [1, "true", None])
def test_shared_mux_assertion_must_be_boolean(value):
    with pytest.raises(PyEzvizError, match="boolean assertion"):
        MediaMuxOptions(native_shared_clock=value)


def test_encrypted_timed_path_rejects_mixed_video_sources_before_ffmpeg(monkeypatch):
    from pyezvizapi import _local_stream as local  # noqa: PLC0415
    from pyezvizapi.rtp import RtpPacket  # noqa: PLC0415
    monkeypatch.setattr(local, "_iter_idmx_local_packet_frame", lambda packet, **kwargs: (packet,))
    monkeypatch.setattr(local, "_idmx_local_frame_header_size", lambda frame: 12)
    monkeypatch.setattr(local, "_idmx_local_frame_rtp_packet",
                        lambda frame, size: RtpPacket(b"\x65\x80picture", 96, 1, 0, frame[0], True))
    monkeypatch.setattr(local, "_idmx_local_video_payload_types", lambda *a, **k: frozenset({96}))
    def forbidden(*args, **kwargs):
        pytest.fail("mixed video sources must fail before starting FFmpeg")
    monkeypatch.setattr(local, "open_mpegts_remux_process", forbidden)
    with pytest.raises(EzvizUnsupportedMediaError, match="multiple video source clocks"):
        local._copy_decrypted_native_idmx_timed_av([b"\x02", b"\x03"], b"", None, io.BytesIO(), codec="h264", ffmpeg_path="unused", native_shared_clock=True)  # noqa: SLF001


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o600])
def test_shared_atomic_replace_preserves_existing_permissions(monkeypatch, tmp_path, mode):
    import stat  # noqa: PLC0415
    client = EzvizClient()
    destination = tmp_path / "clip.ts"
    destination.write_bytes(b"existing")
    destination.chmod(mode)
    complete = b"complete"
    def successful(serial, output, **kwargs):
        output.write(complete)
        return {"ok": True, "format": "mpegts"}
    monkeypatch.setattr(client, "_save_local_sdk_clip", successful)
    client.save_clip_with_options("camera", destination, ClipOptions(
        source=LocalSdkClipSource(), mux=MediaMuxOptions(native_shared_clock=True),
    ))
    assert destination.read_bytes() == complete
    assert stat.S_IMODE(destination.stat().st_mode) == mode
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("mask", [0o022, 0o027, 0o077])
def test_shared_new_clip_uses_normal_umask_permissions(monkeypatch, tmp_path, mask):
    import os  # noqa: PLC0415
    import stat  # noqa: PLC0415
    client = EzvizClient()
    destination = tmp_path / "clip.ts"
    def successful(serial, output, **kwargs):
        output.write(b"complete")
        return {"ok": True, "format": "mpegts"}
    monkeypatch.setattr(client, "_save_local_sdk_clip", successful)
    previous = os.umask(mask)
    try:
        client.save_clip_with_options("camera", destination, ClipOptions(
            source=LocalSdkClipSource(), mux=MediaMuxOptions(native_shared_clock=True),
        ))
        normal = tmp_path / "normal.ts"
        normal.write_bytes(b"normal")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(destination.stat().st_mode) == stat.S_IMODE(normal.stat().st_mode)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o666 & ~mask


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize("chained", [True, False])
def test_shared_atomic_replace_preserves_symlink_target(monkeypatch, tmp_path, existing, chained):
    import stat  # noqa: PLC0415
    client = EzvizClient()
    target = tmp_path / "media" / "clip.ts"
    if existing:
        target.parent.mkdir()
        target.write_bytes(b"existing")
        target.chmod(0o640)
    destination = tmp_path / "output.ts"
    destination.symlink_to("media/clip.ts")
    output = destination
    if chained:
        output = tmp_path / "chain.ts"
        output.symlink_to(destination.name)
    complete = b"complete"
    def successful(serial, output, **kwargs):
        output.write(complete)
        return {"ok": True, "format": "mpegts"}
    monkeypatch.setattr(client, "_save_local_sdk_clip", successful)
    result = client.save_clip_with_options("camera", output, ClipOptions(
        source=LocalSdkClipSource(), mux=MediaMuxOptions(native_shared_clock=True),
    ))
    assert output.is_symlink()
    assert destination.is_symlink()
    assert destination.readlink().as_posix() == "media/clip.ts"
    assert target.read_bytes() == complete
    assert result["output"] == str(output)
    if existing:
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert not list(tmp_path.rglob(".*.tmp"))
