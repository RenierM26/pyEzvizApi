"""Tests for shared FFmpeg remux process lifecycle handling."""

from __future__ import annotations

import io
import json
from pathlib import Path
import shutil
import subprocess
from threading import Event
from typing import Any, cast

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.remux import (
    BoundedStderrTail,
    copy_remuxed_output,
    ffmpeg_mpegts_command,
    open_mpegts_remux_process,
    remux_bytes,
    write_aac_remux_input,
)
from pyezvizapi.rtp import RtpAacStream

PROGRAM_STREAM = b"program-stream"
TRANSPORT_STREAM = b"transport-stream"


class _FakeStreamingProcess:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        return_code: int | None = 0,
        wait_timeout: bool = False,
    ) -> None:
        self.input = bytearray()
        self.stdin: io.BytesIO = _RecordingInput(self.input)
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = return_code
        self.wait_timeout = wait_timeout
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.wait_timeout and not self.killed and timeout is not None:
            raise subprocess.TimeoutExpired(cmd="ffmpeg", timeout=timeout)
        if self.returncode is None:
            self.returncode = -15 if self.terminated else 0
        return self.returncode


class _RecordingInput(io.BytesIO):
    def __init__(self, sink: bytearray) -> None:
        super().__init__()
        self._sink = sink

    def write(self, data: Any) -> int:
        self._sink.extend(data)
        return len(data)


def _as_popen(process: Any) -> subprocess.Popen[bytes]:
    return cast(subprocess.Popen[bytes], process)


def test_ffmpeg_mpegts_command_maps_video_and_audio() -> None:
    assert ffmpeg_mpegts_command(
        "/bin/ffmpeg",
        input_format="hevc",
        frame_rate="15",
        audio_path="audio.aac",
    ) == [
        "/bin/ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "hevc",
        "-r",
        "15",
        "-i",
        "pipe:0",
        "-f",
        "aac",
        "-i",
        "audio.aac",
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-c",
        "copy",
        "-f",
        "mpegts",
        "pipe:1",
    ]


def test_ffmpeg_mpegts_command_accepts_streaming_audio_url() -> None:
    command = ffmpeg_mpegts_command(
        "ffmpeg",
        input_format="hevc",
        audio_url="tcp://127.0.0.1:43210",
    )

    assert command == [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "hevc",
        "-i",
        "pipe:0",
        "-f",
        "aac",
        "-i",
        "tcp://127.0.0.1:43210",
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-c",
        "copy",
        "-f",
        "mpegts",
        "pipe:1",
    ]


def test_ffmpeg_mpegts_command_rejects_two_audio_inputs() -> None:
    with pytest.raises(PyEzvizError, match="mutually exclusive"):
        ffmpeg_mpegts_command(
            "ffmpeg",
            audio_path="audio.aac",
            audio_url="tcp://127.0.0.1:43210",
        )


def test_open_mpegts_remux_process_wraps_launch_failure() -> None:
    def fail_launch(_args: list[str], **_kwargs: Any) -> None:
        raise OSError("not installed")

    with pytest.raises(PyEzvizError, match=r"Could not launch FFmpeg.*not installed"):
        open_mpegts_remux_process("/missing/ffmpeg", popen=fail_launch)


def test_remux_bytes_writes_successful_output() -> None:
    process = _FakeStreamingProcess(stdout=TRANSPORT_STREAM)
    output = io.BytesIO()

    remux_bytes(_as_popen(process), PROGRAM_STREAM, output)

    assert bytes(process.input) == PROGRAM_STREAM
    assert output.getvalue() == TRANSPORT_STREAM


def test_remux_bytes_reports_only_bounded_stderr_tail() -> None:
    process = _FakeStreamingProcess(
        stderr=b"discarded-prefix:" + (b"x" * 70_000) + b":useful-tail",
        return_code=2,
    )

    with pytest.raises(PyEzvizError) as error:
        remux_bytes(_as_popen(process), b"input", io.BytesIO())

    message = str(error.value)
    assert message.startswith("FFmpeg exited with status 2: ")
    assert message.endswith(":useful-tail")
    assert "discarded-prefix" not in message
    assert len(message) < 1300


def test_bounded_stderr_tail_keeps_latest_bytes() -> None:
    tail = BoundedStderrTail(max_bytes=8)

    tail.append(b"old-")
    tail.append(b"new-tail")

    assert tail.text() == "new-tail"


def test_copy_remuxed_output_streams_input_and_output() -> None:
    process = _FakeStreamingProcess(stdout=TRANSPORT_STREAM)
    output = io.BytesIO()

    def write_input(stdin: Any) -> None:
        stdin.write(PROGRAM_STREAM)

    copy_remuxed_output(_as_popen(process), output, write_input=write_input)

    assert output.getvalue() == TRANSPORT_STREAM
    assert process.terminated is False


def test_copy_remuxed_output_surfaces_source_error_before_ffmpeg_exit() -> None:
    process = _FakeStreamingProcess(return_code=1, stderr=b"secondary ffmpeg error")

    def fail_source(_stdin: Any) -> None:
        raise ValueError("source failed")

    with pytest.raises(ValueError, match="source failed"):
        copy_remuxed_output(
            _as_popen(process),
            io.BytesIO(),
            write_input=fail_source,
        )


def test_copy_remuxed_output_reports_nonzero_exit_with_stderr_tail() -> None:
    process = _FakeStreamingProcess(return_code=7, stderr=b"invalid stream")

    with pytest.raises(
        PyEzvizError,
        match="FFmpeg exited with status 7: invalid stream",
    ):
        copy_remuxed_output(
            _as_popen(process),
            io.BytesIO(),
            write_input=lambda _stdin: None,
        )


def test_copy_remuxed_output_preserves_consumer_disconnect_and_cancels_input() -> None:
    process = _FakeStreamingProcess(stdout=TRANSPORT_STREAM, return_code=None)
    cancelled = Event()

    class BrokenOutput(io.BytesIO):
        def write(self, _data: Any) -> int:
            raise BrokenPipeError("consumer disconnected")

    with pytest.raises(BrokenPipeError, match="consumer disconnected"):
        copy_remuxed_output(
            _as_popen(process),
            BrokenOutput(),
            write_input=lambda _stdin: None,
            cancel_input=cancelled.set,
        )

    assert cancelled.is_set()
    assert process.terminated is True


def test_consumer_disconnect_terminates_ffmpeg_before_cross_thread_stdin_close() -> None:
    process = _FakeStreamingProcess(stdout=TRANSPORT_STREAM, return_code=None)
    terminated = Event()
    write_started = Event()
    close_after_terminate = Event()

    class BlockingInput(io.BytesIO):
        def write(self, _data: Any) -> int:
            write_started.set()
            terminated.wait(timeout=1)
            raise BrokenPipeError

        def close(self) -> None:
            if not terminated.is_set():
                raise AssertionError("stdin closed before FFmpeg terminated")
            close_after_terminate.set()
            super().close()

    class BrokenOutput(io.BytesIO):
        def write(self, _data: Any) -> int:
            write_started.wait(timeout=1)
            raise BrokenPipeError("consumer disconnected")

    process.stdin = BlockingInput()
    original_terminate = process.terminate

    def terminate() -> None:
        original_terminate()
        terminated.set()

    def write_input(stdin: Any) -> None:
        stdin.write(PROGRAM_STREAM)

    process.terminate = terminate  # type: ignore[method-assign]

    with pytest.raises(BrokenPipeError, match="consumer disconnected"):
        copy_remuxed_output(
            _as_popen(process),
            BrokenOutput(),
            write_input=write_input,
        )

    assert close_after_terminate.is_set()


def test_copy_remuxed_output_cancels_stalled_source_after_ffmpeg_exit() -> None:
    process = _FakeStreamingProcess(return_code=4, stderr=b"bad input")
    cancelled = Event()
    writer_stopped = Event()

    def write_input(_stdin: Any) -> None:
        cancelled.wait(timeout=1)
        writer_stopped.set()

    with pytest.raises(PyEzvizError, match="FFmpeg exited with status 4"):
        copy_remuxed_output(
            _as_popen(process),
            io.BytesIO(),
            write_input=write_input,
            cancel_input=cancelled.set,
        )

    assert cancelled.is_set()
    assert writer_stopped.is_set()


def test_cleanup_induced_source_error_does_not_mask_ffmpeg_failure() -> None:
    process = _FakeStreamingProcess(return_code=5, stderr=b"unsupported codec")
    cancelled = Event()

    def write_input(_stdin: Any) -> None:
        cancelled.wait(timeout=1)
        raise PyEzvizError("socket closed during cancellation")

    with pytest.raises(
        PyEzvizError,
        match="FFmpeg exited with status 5: unsupported codec",
    ):
        copy_remuxed_output(
            _as_popen(process),
            io.BytesIO(),
            write_input=write_input,
            cancel_input=cancelled.set,
        )


def test_copy_remuxed_output_escalates_from_terminate_to_kill() -> None:
    process = _FakeStreamingProcess(return_code=None, wait_timeout=True)

    with pytest.raises(PyEzvizError, match="FFmpeg exited with status -9"):
        copy_remuxed_output(
            _as_popen(process),
            io.BytesIO(),
            write_input=lambda _stdin: None,
        )

    assert process.terminated is True
    assert process.killed is True


@pytest.mark.skipif(not shutil.which("ffmpeg") or not shutil.which("ffprobe"), reason="FFmpeg tools unavailable")
@pytest.mark.parametrize("missing_index", [1, 5])
def test_aac_gap_remux_preserves_single_frame_segment_timestamps(tmp_path: Path, missing_index: int) -> None:
    source = tmp_path / "source.aac"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
        "sine=frequency=1000:sample_rate=16000", "-ac", "1", "-frames:a", "12",
        "-c:a", "aac", "-f", "adts", str(source)], check=True, capture_output=True)
    frames = []
    data = source.read_bytes()
    offset = 0
    while offset < len(data):
        length = ((data[offset + 3] & 3) << 11) | (data[offset + 4] << 3) | (data[offset + 5] >> 5)
        frames.append(data[offset:offset + length])
        offset += length
    # Missing the second AU must remain a 128 ms jump after the first AU.
    audio = RtpAacStream(b"".join([*frames[:missing_index], *frames[missing_index + 1:]]),
        16000, 1, len(frames) - 1,
        ((0, b"".join(frames[:missing_index])),
         ((missing_index + 1) * 1024, b"".join(frames[missing_index + 1:]))))
    path, audio_format = write_aac_remux_input(audio, tmp_path)
    out = tmp_path / "output.ts"
    subprocess.run(["ffmpeg", "-v", "error", "-f", audio_format, "-i", str(path),
        "-c", "copy", "-copyts", "-f", "mpegts", "-muxdelay", "0", str(out)], check=True, capture_output=True)
    probe = subprocess.run(["ffprobe", "-v", "error", "-show_packets",
        "-show_entries", "packet=pts_time", "-of", "json", str(out)], check=True, capture_output=True)
    packets = json.loads(probe.stdout)["packets"]
    assert len(packets) == len(frames) - 1
    assert float(packets[missing_index]["pts_time"]) - float(packets[missing_index - 1]["pts_time"]) == pytest.approx(0.128)
    assert float(packets[-1]["pts_time"]) - float(packets[0]["pts_time"]) == pytest.approx((len(frames) - 1) * 1024 / 16000)


def test_concat_audio_command_keeps_explicit_format_and_video_gate() -> None:
    command = ffmpeg_mpegts_command("ffmpeg", input_format="hevc", frame_rate="15",
        audio_path="audio.ffconcat", audio_input_format="concat")
    assert command[command.index("audio.ffconcat") - 3:command.index("audio.ffconcat")] == ["-f", "concat", "-i"]
    assert "-copyinkf" not in command
    assert "-copyts" in command
