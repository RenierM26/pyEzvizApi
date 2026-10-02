"""Shared FFmpeg remux process and lifecycle helpers."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
import subprocess
from threading import Event, Lock, Thread
from typing import Any, BinaryIO, cast

from .exceptions import PyEzvizError

FFMPEG_IO_CHUNK_SIZE = 65536
FFMPEG_STOP_TIMEOUT_SECONDS = 2.0
FFMPEG_STDERR_MAX_BYTES = 65536
FFMPEG_STDERR_MAX_CHARS = 1200


class BoundedStderrTail:
    """Thread-safe bounded FFmpeg stderr byte tail."""

    def __init__(self, max_bytes: int = FFMPEG_STDERR_MAX_BYTES) -> None:
        self._max_bytes = max(0, max_bytes)
        self._data = bytearray()
        self._lock = Lock()

    def append(self, data: bytes) -> None:
        """Append bytes while retaining at most the configured tail size."""

        if not data or self._max_bytes == 0:
            return
        with self._lock:
            self._data.extend(data)
            overflow = len(self._data) - self._max_bytes
            if overflow > 0:
                del self._data[:overflow]

    def text(self, *, max_chars: int = FFMPEG_STDERR_MAX_CHARS) -> str:
        """Return the decoded, stripped stderr tail."""

        with self._lock:
            text = bytes(self._data).decode("utf-8", errors="replace").strip()
        return text[-max(0, max_chars) :]


def ffmpeg_mpegts_command(
    ffmpeg_path: str,
    *,
    input_format: str = "mpeg",
    frame_rate: str | None = None,
    audio_path: str | None = None,
    audio_url: str | None = None,
) -> list[str]:
    """Build an FFmpeg stream-copy command producing MPEG-TS on stdout."""

    if audio_path is not None and audio_url is not None:
        raise PyEzvizError("FFmpeg audio_path and audio_url are mutually exclusive")

    command = [
        ffmpeg_path,
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        input_format,
    ]
    if frame_rate is not None:
        command.extend(("-r", frame_rate))
    command.extend(("-i", "pipe:0"))
    audio_input = audio_path if audio_path is not None else audio_url
    if audio_input is not None:
        command.extend(
            (
                "-f",
                "aac",
                "-i",
                audio_input,
                "-map",
                "0:v:0",
                "-map",
                "1:a:0",
            )
        )
    command.extend(("-c", "copy", "-f", "mpegts", "pipe:1"))
    return command


def open_mpegts_remux_process(
    ffmpeg_path: str,
    *,
    input_format: str = "mpeg",
    frame_rate: str | None = None,
    audio_path: str | None = None,
    audio_url: str | None = None,
    popen: Callable[..., Any] = subprocess.Popen,
) -> subprocess.Popen[bytes]:
    """Open one FFmpeg MPEG-TS remux process with captured stderr."""

    try:
        process: subprocess.Popen[bytes] = popen(
            ffmpeg_mpegts_command(
                ffmpeg_path,
                input_format=input_format,
                frame_rate=frame_rate,
                audio_path=audio_path,
                audio_url=audio_url,
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return process
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err


def start_stderr_drain(
    process: subprocess.Popen[bytes],
    *,
    max_bytes: int = FFMPEG_STDERR_MAX_BYTES,
) -> tuple[BoundedStderrTail, Thread | None]:
    """Drain process stderr in the background into a bounded tail."""

    tail = BoundedStderrTail(max_bytes)
    stderr = process.stderr
    if stderr is None:
        return tail, None

    def _drain() -> None:
        with suppress(OSError):
            while chunk := stderr.read(4096):
                tail.append(chunk)

    reader = Thread(target=_drain, name="pyezvizapi-ffmpeg-stderr", daemon=True)
    reader.start()
    return tail, reader


def _wait_for_process(process: subprocess.Popen[bytes]) -> tuple[int, bool]:
    """Wait for FFmpeg, escalating from terminate to kill when needed."""

    terminated = False
    if process.poll() is None:
        process.terminate()
        terminated = True
    try:
        return process.wait(timeout=FFMPEG_STOP_TIMEOUT_SECONDS), terminated
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(), True


def _ffmpeg_exit_error(return_code: int, stderr_tail: str) -> PyEzvizError:
    message = f"FFmpeg exited with status {return_code}"
    if stderr_tail:
        message = f"{message}: {stderr_tail}"
    return PyEzvizError(message)


def copy_remuxed_output(  # noqa: PLR0912,PLR0915
    process: subprocess.Popen[bytes],
    output: BinaryIO,
    *,
    write_input: Callable[[BinaryIO], None],
    cancel_input: Callable[[], None] | None = None,
) -> None:
    """Run a streaming FFmpeg remux with coordinated cancellation and cleanup.

    Consumer ``BrokenPipeError`` and ``ConnectionResetError`` remain distinct
    from FFmpeg failures and are re-raised after the process and writer stop.
    """

    stdin = process.stdin
    stdout = process.stdout
    if stdin is None or stdout is None:
        with suppress(Exception):
            _wait_for_process(process)
        raise PyEzvizError("Could not open FFmpeg pipes")

    cleanup_started = Event()
    writer_errors: list[tuple[Exception, bool]] = []
    stderr_tail, stderr_reader = start_stderr_drain(process)

    def _writer() -> None:
        try:
            write_input(cast(BinaryIO, stdin))
        except (BrokenPipeError, ConnectionResetError):
            # FFmpeg may close stdin after producing all output the caller needs.
            pass
        except Exception as err:  # pragma: no cover - defensive thread handoff
            writer_errors.append((err, cleanup_started.is_set()))
        finally:
            with suppress(OSError):
                stdin.close()

    writer = Thread(target=_writer, name="pyezvizapi-ffmpeg-input", daemon=True)
    writer.start()
    output_error: Exception | None = None
    try:
        while chunk := stdout.read(FFMPEG_IO_CHUNK_SIZE):
            output.write(chunk)
            output.flush()
    except (BrokenPipeError, ConnectionResetError) as err:
        output_error = err
    finally:
        cleanup_started.set()
        input_cancelled = output_error is not None or process.poll() is not None
        if cancel_input is not None and input_cancelled:
            with suppress(Exception):
                cancel_input()
        return_code, terminated = _wait_for_process(process)
        if cancel_input is not None and terminated and not input_cancelled:
            with suppress(Exception):
                cancel_input()
        writer.join(timeout=FFMPEG_STOP_TIMEOUT_SECONDS)
        if writer.is_alive() and cancel_input is not None:
            with suppress(Exception):
                cancel_input()
            writer.join(timeout=FFMPEG_STOP_TIMEOUT_SECONDS)
        if not writer.is_alive():
            with suppress(OSError):
                stdin.close()
        if stderr_reader is not None:
            stderr_reader.join(timeout=FFMPEG_STOP_TIMEOUT_SECONDS)
        with suppress(OSError):
            stdout.close()
        if process.stderr is not None:
            with suppress(OSError):
                process.stderr.close()

    if output_error is not None:
        raise output_error
    if writer.is_alive():
        raise PyEzvizError("FFmpeg input writer did not stop after cancellation")
    for writer_error, during_cleanup in writer_errors:
        if not during_cleanup:
            raise writer_error
    if return_code != 0 and not (terminated and return_code == -15):
        raise _ffmpeg_exit_error(return_code, stderr_tail.text())


def remux_bytes(
    process: subprocess.Popen[bytes],
    data: bytes,
    output: BinaryIO,
) -> None:
    """Run an in-memory FFmpeg remux and surface bounded stderr on failure."""

    def _write_input(stdin: BinaryIO) -> None:
        stdin.write(data)

    copy_remuxed_output(process, output, write_input=_write_input)
