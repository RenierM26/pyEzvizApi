"""Native capture profile contracts, output isolation and real timing adapter."""

# ruff: noqa: SLF001
from dataclasses import replace
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from pyezvizapi import (
    CaptureLimits,
    ClipOptions,
    EzvizClient,
    MediaMuxOptions,
    _local_stream as local,
)
from pyezvizapi.app_capture import native_app_timed_payloads
from pyezvizapi.clip import (
    AutoClipSource,
    CloudClipSource,
    HcNetSdkCommandPortClipSource,
    LocalSdkClipSource,
)
from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.rtp import RtpAacStream

_ADTS = b"\xff\xf1\x60\x40\x00\xff\xfc"
_UNITS = (b"\x40\x01header", b"\x26\x01\x80first", b"\x02\x01\x80second")


def sound():
    return RtpAacStream(_ADTS * 2, 16000, 1, 2, ((0, _ADTS), (2048, _ADTS)), 16001, ((2, None),))


def pts(payloads):
    result: dict[int, list[int]] = {0xE0: [], 0xC0: []}
    for body in payloads:
        for stream, stamps in result.items():
            marker = b"\x00\x00\x01" + bytes((stream,))
            if marker not in body:
                continue
            start = body.index(marker)
            data = body[start + 9 : start + 14]
            stamps.append(
                ((data[0] & 14) << 29)
                | (data[1] << 22)
                | ((data[2] & 254) << 14)
                | (data[3] << 7)
                | (data[4] >> 1)
            )
    return result


def test_real_source_cadence_and_ordinary_audio_gap():
    result = pts(
        native_app_timed_payloads(_UNITS, (0, 900000, 906000), audio=sound(), frame_rate="15")
    )
    assert result == {0xE0: [0, 66 * 90], 0xC0: [0, 128 * 90]}


@pytest.mark.parametrize(
    "times,expected",
    [
        ((0, 900000, 900000 + 18000 * 90), 66),
        ((0, 900000, 899910), 66),
        ((0, 2**32 - 3000, 3000), 67),
    ],
)
def test_video_repair_and_counter_wrap(times, expected):
    result = pts(native_app_timed_payloads(_UNITS, times, audio=sound(), frame_rate="15"))
    assert result[0xE0] == [0, expected * 90]


@pytest.mark.parametrize(
    "changes",
    [
        {"origin_timestamp": None},
        {"timed_segments": ()},
        {"sample_rate": 8000},
        {"channels": 2},
        {"source_keys": ()},
        {"source_keys": ((2, None), (3, None))},
    ],
)
def test_incomplete_audio_provenance_never_falls_back(changes):
    with pytest.raises(PyEzvizError, match="app_relative_clock"):
        list(
            native_app_timed_payloads(
                _UNITS, (0, 900000, 906000), audio=replace(sound(), **changes), frame_rate="15"
            )
        )


@pytest.mark.parametrize("rate", ["0", "-15", "invalid", "2000"])
def test_invalid_frame_cadence(rate):
    with pytest.raises(PyEzvizError, match="cadence"):
        list(native_app_timed_payloads(_UNITS, (0, 900000, 906000), audio=sound(), frame_rate=rate))


@pytest.mark.parametrize("source", [AutoClipSource(), CloudClipSource()])
def test_capture_requires_explicit_native_source_before_connecting(source):
    with pytest.raises(PyEzvizError, match="app_relative_clock requires an explicit"):
        EzvizClient().save_clip_with_options(
            "camera",
            io.BytesIO(),
            ClipOptions(source=source, mux=MediaMuxOptions(app_relative_clock=True)),
        )


@pytest.mark.parametrize("source", [LocalSdkClipSource(), HcNetSdkCommandPortClipSource()])
@pytest.mark.parametrize("file_output", [False, True])
def test_capture_stages_and_preserves_failed_output(monkeypatch, tmp_path, source, file_output):
    original = b"original"
    target = tmp_path / "clip.ts" if file_output else io.BytesIO(original)
    if isinstance(target, Path):
        target.write_bytes(original)
    else:
        target.seek(0, 2)
    client = EzvizClient()

    def fail(serial, output, **kwargs):
        assert kwargs["app_relative_clock"] is True
        assert "native_shared_clock" not in kwargs
        output.write(b"partial")
        raise PyEzvizError("unsupported timing")

    method = (
        "_save_local_sdk_clip"
        if isinstance(source, LocalSdkClipSource)
        else "_save_hcnetsdk_command_port_clip"
    )
    monkeypatch.setattr(client, method, fail)
    with pytest.raises(PyEzvizError, match="unsupported timing"):
        client.save_clip_with_options(
            "camera",
            target,
            ClipOptions(
                source=source,
                capture=CaptureLimits(max_packets=10),
                mux=MediaMuxOptions(app_relative_clock=True),
            ),
        )
    assert (target.read_bytes() if isinstance(target, Path) else target.getvalue()) == original


def test_capture_commits_successful_complete_result(monkeypatch, tmp_path):
    client = EzvizClient()
    destination = tmp_path / "clip.ts"
    complete = b"complete"

    def save(serial, output, **kwargs):
        assert kwargs["app_relative_clock"] is True
        output.write(complete)
        return {"ok": True, "format": "mpegts"}

    monkeypatch.setattr(client, "_save_local_sdk_clip", save)
    result = client.save_clip_with_options(
        "camera",
        destination,
        ClipOptions(
            source=LocalSdkClipSource(),
            capture=CaptureLimits(max_packets=10),
            mux=MediaMuxOptions(app_relative_clock=True),
        ),
    )
    assert destination.read_bytes() == complete
    assert result["bytes"] == len(complete)
    assert result["output"] == str(destination)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"native_shared_clock": True},
        {"output_format": "mpegps"},
        {"h264_trim_to_clean_idr_window": True},
        {"h264_wait_for_clean_idr_window": True},
    ],
)
def test_capture_rejects_conflicting_policies(kwargs):
    with pytest.raises(PyEzvizError):
        mux = MediaMuxOptions(app_relative_clock=True, **kwargs)
        EzvizClient().save_clip_with_options(
            "camera",
            io.BytesIO(),
            ClipOptions(
                source=LocalSdkClipSource(), capture=CaptureLimits(max_packets=10), mux=mux
            ),
        )


def test_low_level_ps_rejected_without_fallback_or_output():
    stream = SimpleNamespace(
        iter_packets=lambda **kwargs: iter([SimpleNamespace(body=b"\x00\x00\x01\xba" + b"x" * 20)])
    )
    target = io.BytesIO()
    with pytest.raises(PyEzvizError, match="app_relative_clock"):
        local.copy_local_stream_to_mpegts(stream, target, max_packets=1, app_relative_clock=True)
    assert not target.getvalue()


def test_clear_capture_routes_into_app_adapter(monkeypatch):
    monkeypatch.setattr(local, "_idmx_local_video_payload_types", lambda *a, **k: frozenset({96}))
    monkeypatch.setattr(
        local, "_clear_native_rtp_packets_with_legacy_indices", lambda *a: ([], set())
    )
    monkeypatch.setattr(local, "idmx_video_frame_rate", lambda *a: "15")
    monkeypatch.setattr(local, "detect_rtp_video_codec", lambda *a, **k: "hevc")

    def units(packets, **kwargs):
        kwargs["nal_timestamps"].extend([0, 900000, 900000 + 18000 * 90])
        kwargs["nal_source_keys"].extend([(2, None)] * 3)
        return _UNITS

    monkeypatch.setattr(local, "rtp_packets_to_nal_units", units)
    sentinel = object()
    calls = []

    def open_remux(*args, **kwargs):
        calls.append(kwargs)
        return sentinel

    monkeypatch.setattr(local, "open_mpegts_remux_process", open_remux)
    output = io.BytesIO()

    def remux(process, target, *, write_input):
        assert process is sentinel
        write_input(target)

    monkeypatch.setattr(local, "copy_remuxed_output", remux)
    assert local._copy_clear_native_idmx_timed_av(
        [], sound(), output, ffmpeg_path="unused", app_relative_clock=True
    )
    assert pts([output.getvalue()])[0xE0] == [0]
    assert calls[0]["map_all_streams"] is True
    assert calls[0]["preserve_timestamps"] is True


def test_mixed_video_identity_rejected_before_mux(monkeypatch):
    monkeypatch.setattr(local, "_idmx_local_video_payload_types", lambda *a, **k: frozenset({96}))
    monkeypatch.setattr(
        local, "_clear_native_rtp_packets_with_legacy_indices", lambda *a: ([], set())
    )
    monkeypatch.setattr(local, "idmx_video_frame_rate", lambda *a: "15")
    monkeypatch.setattr(local, "detect_rtp_video_codec", lambda *a, **k: "hevc")

    def units(packets, **kwargs):
        kwargs["nal_timestamps"].extend([900000, 906000])
        kwargs["nal_source_keys"].extend([(2, None), (3, None)])
        return _UNITS[1:]

    monkeypatch.setattr(local, "rtp_packets_to_nal_units", units)
    with pytest.raises(EzvizUnsupportedMediaError, match="multiple video source clocks"):
        local._copy_clear_native_idmx_timed_av(
            [], sound(), io.BytesIO(), ffmpeg_path="unused", app_relative_clock=True
        )


@pytest.mark.parametrize("flag", [1, "yes", None])
def test_capture_flag_requires_boolean(flag):
    with pytest.raises(PyEzvizError, match="boolean"):
        MediaMuxOptions(app_relative_clock=flag)


def test_capture_rejects_unbounded_before_connecting():
    with pytest.raises(PyEzvizError, match="capture limit"):
        EzvizClient().save_clip_with_options(
            "camera",
            io.BytesIO(),
            ClipOptions(
                source=LocalSdkClipSource(),
                capture=CaptureLimits(duration_seconds=None),
                mux=MediaMuxOptions(app_relative_clock=True),
            ),
        )


@pytest.mark.parametrize("source", ["local-sdk", "hcnetsdk-command-port"])
def test_long_form_forwards_profile_without_implicit_startup_trim(monkeypatch, source):
    client = EzvizClient()
    observed = []

    def save(serial, output, options):
        observed.append(options)
        return {"ok": True}

    monkeypatch.setattr(client, "save_clip_with_options", save)
    client.save_clip(
        "camera",
        io.BytesIO(),
        source=source,
        app_relative_clock=True,
        hcnetsdk_command_generated_plan=local.hcnetsdk_command_port_native_lan_live_view_plan(),
    )
    mux = observed[0].resolved_mux()
    assert mux.app_relative_clock is True
    assert mux.h264_wait_for_clean_idr_window is False


@pytest.mark.parametrize(
    "copy", [local.copy_local_stream_to_mpegts, local.copy_local_stream_to_decrypted_mpegts]
)
def test_low_level_rejects_startup_trim_before_consuming(copy):
    kwargs = {"media_key": b"key"} if copy is local.copy_local_stream_to_decrypted_mpegts else {}
    with pytest.raises(PyEzvizError, match="full startup"):
        copy(
            None,
            io.BytesIO(),
            max_packets=10,
            app_relative_clock=True,
            h264_skip_initial_idr_windows=1,
            **kwargs,
        )


def test_decrypted_profile_rejects_synthetic_clock(monkeypatch):
    monkeypatch.setattr(local, "idmx_video_frame_rate", lambda *a: "15")
    monkeypatch.setattr(local, "_native_decrypted_rtp_timeline", lambda *a: None)
    with pytest.raises(PyEzvizError, match="cannot use synthetic"):
        local._copy_decrypted_native_idmx_timed_av(
            [],
            b"encoded",
            sound(),
            io.BytesIO(),
            codec="hevc",
            ffmpeg_path="unused",
            app_relative_clock=True,
        )
