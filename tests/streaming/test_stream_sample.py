"""Real encoded-track hashes/timing, finite subprocesses and sample budgets."""

import json
import os
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pyezvizapi import stream_sample
from pyezvizapi.client import EzvizClient
from pyezvizapi.clip import ClipOptions
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.media import CaptureLimits
from pyezvizapi.rtp_timing import NativeRtpPsMuxer
from pyezvizapi.stream_sample import (
    EncodedTrackSelection,
    capture_media_sample,
    inspect_media_sample,
    remux_media_sample,
)


@pytest.fixture(scope="module", params=["h264", "hevc"])
def encoded_sample(request) -> bytes:
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("FFmpeg and FFprobe required")
    codec = request.param
    command = [
        "ffmpeg",
        "-v",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=64x48:rate=10",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=80x48:rate=10",
        "-f",
        "lavfi",
        "-i",
        "sine=frequency=440:sample_rate=16000",
        "-t",
        "1",
        "-map",
        "0:v",
        "-map",
        "1:v",
        "-map",
        "2:a",
        "-c:v",
        "libx264" if codec == "h264" else "libx265",
        "-threads:v",
        "1",
    ]
    if codec == "hevc":
        command.extend(("-x265-params", "pools=none:frame-threads=1:log-level=error"))
    command.extend(("-c:a", "aac", "-f", "mpegts", "pipe:1"))
    generated = subprocess.run(command, capture_output=True, timeout=20, check=False)
    missing_encoder = b"Unknown encoder"
    if generated.returncode and missing_encoder in generated.stderr:
        pytest.skip(f"{codec} encoder unavailable")
    assert generated.returncode == 0, generated.stderr.decode()
    return generated.stdout


def packet_oracle(data: bytes) -> dict[int, list[tuple[Any, ...]]]:
    process = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-i",
            "pipe:0",
            "-show_packets",
            "-show_data_hash",
            "sha256",
            "-show_entries",
            "packet=stream_index,pts,dts,duration,data_hash",
            "-of",
            "json",
        ],
        input=data,
        capture_output=True,
        timeout=10,
        check=True,
    )
    streams: dict[int, list[tuple[Any, ...]]] = {}
    for packet in json.loads(process.stdout)["packets"]:
        streams.setdefault(packet["stream_index"], []).append(
            tuple(packet.get(key) for key in ("data_hash", "pts", "dts", "duration"))
        )
    return streams


def test_real_multi_track_probe_and_complete_decode(encoded_sample):
    result = inspect_media_sample(encoded_sample, decode=True)
    assert result["status"] == "observed" and result["decode_status"] == "passed"
    assert result["ha_verified"] is False
    tracks = result["tracks"]
    assert [(t["codec_type"], t.get("width")) for t in tracks] == [
        ("video", 64),
        ("video", 80),
        ("audio", None),
    ]
    assert tracks[0]["codec_name"] in {"h264", "hevc"}
    assert tracks[2]["codec_name"] == "aac"
    assert tracks[2]["sample_rate"] == "16000" and tracks[2]["channels"] == 1


def test_explicit_second_video_plus_audio_preserves_encoded_hashes_and_time(encoded_sample):
    original = packet_oracle(encoded_sample)
    result = remux_media_sample(encoded_sample, EncodedTrackSelection(1, 2))
    remuxed = packet_oracle(result)
    assert len(remuxed) == 2
    assert remuxed[0] == original[1]
    assert remuxed[1] == original[2]
    assert inspect_media_sample(result, decode=True)["decode_status"] == "passed"


def test_explicit_video_only_omits_audio_without_composing_lenses(encoded_sample):
    result = remux_media_sample(encoded_sample, EncodedTrackSelection(0))
    remuxed = packet_oracle(result)
    assert list(remuxed) == [0]
    assert remuxed[0] == packet_oracle(encoded_sample)[0]


def annexb_oracle(data: bytes, codec: str) -> list[bytes]:
    process = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            "pipe:0",
            "-map",
            "0:0",
            "-c",
            "copy",
            "-f",
            codec,
            "pipe:1",
        ],
        input=data,
        capture_output=True,
        timeout=10,
        check=True,
    )
    return [unit for unit in re.split(b"\x00\x00(?:\x00)?\x01", process.stdout) if unit]


def test_ps_without_delimiters_retains_every_original_nal(encoded_sample):
    codec = inspect_media_sample(encoded_sample)["tracks"][0]["codec_name"]
    delimiter_type = 9 if codec == "h264" else 35

    def is_delimiter(unit):
        return (unit[0] & 31 if codec == "h264" else (unit[0] >> 1) & 63) == delimiter_type

    original = [unit for unit in annexb_oracle(encoded_sample, codec) if not is_delimiter(unit)]
    muxer = NativeRtpPsMuxer(codec, audio=False)
    ps = b"".join(
        part for index, unit in enumerate(original) for part in muxer.video(index * 9000, unit)
    )
    copied = remux_media_sample(ps, EncodedTrackSelection(0))
    output_units = annexb_oracle(copied, codec)
    assert any(is_delimiter(unit) for unit in output_units)
    assert [unit for unit in output_units if not is_delimiter(unit)] == original


@pytest.mark.skipif(os.name != "posix", reason="Executable fixture uses a shebang")
def test_real_probe_timeout_reaps_the_child(tmp_path):
    pidfile = tmp_path / "pid"
    executable = tmp_path / "slow-probe"
    executable.write_text(
        f"#!{sys.executable}\nimport os,time\nopen({str(pidfile)!r},'w').write(str(os.getpid()))\ntime.sleep(30)\n"
    )
    executable.chmod(0o700)
    result = inspect_media_sample(b"x", timeout=0.5, ffprobe_path=str(executable))
    assert result["error_type"] == "TimeoutExpired"
    assert pidfile.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


@pytest.mark.parametrize(
    "selection", [EncodedTrackSelection(2), EncodedTrackSelection(0, 1), EncodedTrackSelection(63)]
)
def test_wrong_kind_or_missing_track_fails_before_remux(encoded_sample, selection):
    with pytest.raises(PyEzvizError, match="Select an observed"):
        remux_media_sample(encoded_sample, selection)


def test_remux_output_budget_never_publishes_partial_media(monkeypatch, encoded_sample):
    monkeypatch.setattr(stream_sample, "MAX_REMUX_BYTES", 1000)
    with pytest.raises(PyEzvizError, match="output budget"):
        remux_media_sample(encoded_sample, EncodedTrackSelection(1, 2))


def test_playlist_cannot_dereference_local_media(tmp_path, encoded_sample):
    path = tmp_path / "must-not-open.ts"
    path.write_bytes(encoded_sample)
    playlist = (
        f"#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1,\n{path.as_uri()}\n#EXT-X-ENDLIST\n".encode()
    )
    result = inspect_media_sample(playlist)
    assert result["status"] == "unknown"
    assert result["tracks"] == []


@pytest.mark.parametrize("data", [b"", b"x" * (stream_sample.MAX_SAMPLE_BYTES + 1), "not-bytes"])
def test_invalid_bytes_before_subprocess(monkeypatch, data):
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("subprocess"))
    with pytest.raises(ValueError):
        inspect_media_sample(data)


@pytest.mark.parametrize("timeout", [0, float("nan"), float("inf"), 31, True])
def test_invalid_process_timeout(monkeypatch, timeout):
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("subprocess"))
    with pytest.raises(ValueError):
        inspect_media_sample(b"x", timeout=timeout)


def test_probe_failure_is_unknown_and_diagnostics_stay_private():
    result = inspect_media_sample(b"not a media container")
    assert result["status"] == "unknown" and result["decode_status"] == "not_tested"
    result = inspect_media_sample(b"private-body", ffprobe_path="/no/such/private-path")
    assert result["error_type"] == "FileNotFoundError"
    assert "private" not in json.dumps(result)


def test_probe_timeout_and_decode_timeout_are_distinct(monkeypatch):
    def timeout(*_a, **_kw):
        raise subprocess.TimeoutExpired("private command", 0.1)

    monkeypatch.setattr(subprocess, "run", timeout)
    result = inspect_media_sample(b"x")
    assert result["status"] == "unknown" and result["error_type"] == "TimeoutExpired"
    count = 0

    def decoded_timeout(*_a, **_kw):
        nonlocal count
        count += 1
        if count == 1:
            return SimpleNamespace(
                returncode=0,
                stdout=b'{"streams":[{"index":0,"codec_name":"h264","codec_type":"video"}]}',
            )
        raise subprocess.TimeoutExpired("private command", 0.1)

    monkeypatch.setattr(subprocess, "run", decoded_timeout)
    result = inspect_media_sample(b"x", decode=True)
    assert result["status"] == "observed" and result["decode_status"] == "unknown"


@pytest.mark.parametrize("stdout", [b"bad-json", b"{}", b'{"streams":{}}', b"x" * 65537])
def test_malformed_or_oversized_probe_output_stays_unknown(monkeypatch, stdout):
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_kw: SimpleNamespace(returncode=0, stdout=stdout)
    )
    assert inspect_media_sample(b"x")["status"] == "unknown"


def test_unhandled_audio_is_observed_but_not_silently_dropped(monkeypatch):
    tracks = [
        {"index": 0, "codec_type": "video", "codec_name": "hevc"},
        {"index": 1, "codec_type": "audio", "codec_name": "pcm_alaw"},
    ]
    monkeypatch.setattr(
        stream_sample, "inspect_media_sample", lambda *_a, **_kw: {"tracks": tracks}
    )
    with pytest.raises(PyEzvizError, match="AAC"):
        remux_media_sample(b"x", EncodedTrackSelection(0, 1))


@pytest.mark.parametrize(
    "video,audio",
    [(True, None), (-1, None), (64, None), (1.5, None), (None, None), (0, 0), (0, True)],
)
def test_invalid_selection(video, audio):
    with pytest.raises(ValueError):
        EncodedTrackSelection(video, audio)


def test_explicit_acquisition_passes_known_options_and_bounds_returned_bytes(monkeypatch):
    calls = []

    def capture(serial, output, options):
        calls.append((serial, options))
        output.write(b"clear")

    client = cast(EzvizClient, SimpleNamespace(save_clip_with_options=capture))
    options = ClipOptions(capture=CaptureLimits(duration_seconds=1, max_packets=10))
    expected = b"clear"
    assert capture_media_sample(client, "PRIVATE-SERIAL", options) == expected
    assert calls == [("PRIVATE-SERIAL", options)]
    monkeypatch.setattr(stream_sample, "MAX_SAMPLE_BYTES", 4)
    with pytest.raises(PyEzvizError, match="output budget"):
        capture_media_sample(client, "PRIVATE-SERIAL", options)


@pytest.mark.parametrize(
    "limits",
    [
        CaptureLimits(),
        CaptureLimits(max_packets=1),
        CaptureLimits(duration_seconds=1),
        CaptureLimits(duration_seconds=31, max_packets=1),
        CaptureLimits(duration_seconds=1, max_packets=4097),
        CaptureLimits(duration_seconds=1, max_packets=1, max_bytes=100),
    ],
)
def test_unsafe_sample_acquisition_rejected_before_open(limits):
    def capture(*_a, **_kw):
        pytest.fail("camera opened")

    client = cast(EzvizClient, SimpleNamespace(save_clip_with_options=capture))
    with pytest.raises(ValueError):
        capture_media_sample(client, "PRIVATE-SERIAL", ClipOptions(capture=limits))


def test_capture_cancellation_propagates_without_retry():
    calls = []

    def capture(*_a, **_kw):
        calls.append(1)
        raise KeyboardInterrupt

    client = cast(EzvizClient, SimpleNamespace(save_clip_with_options=capture))
    with pytest.raises(KeyboardInterrupt):
        capture_media_sample(
            client,
            "PRIVATE-SERIAL",
            ClipOptions(capture=CaptureLimits(duration_seconds=1, max_packets=1)),
        )
    assert calls == [1]
