"""Closeable live MPEG-TS output for integration-owned HTTP routes."""

from __future__ import annotations

from contextlib import closing, suppress
from io import BufferedReader
import subprocess
import sys
from threading import Event, Lock, Thread
import time
from typing import TYPE_CHECKING, BinaryIO, cast

from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming.capture import AutoClipSource
from pyezvizapi.streaming.media.models import is_positive_finite_duration_bound
from pyezvizapi.streaming.media.remux import (
    _ffmpeg_exit_error,
    _wait_for_process,
    open_mpegts_remux_process,
    start_stderr_drain,
)
from pyezvizapi.streaming.selection import AutoMediaStream

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


class LiveStreamShutdownTimeout(PyEzvizError):
    """Shutdown is still in progress; keep ownership and call close again."""


class LiveMpegtsStream:
    """One synchronous reader, with cancellation from another thread."""

    def __init__(
        self,
        source: AutoMediaStream,
        ffmpeg_path: str,
        *,
        startup_timeout: float = 10.0,
        close_timeout: float = 15.0,
    ) -> None:
        if not is_positive_finite_duration_bound(startup_timeout):
            raise ValueError("Live startup timeout must be positive and finite")
        if not is_positive_finite_duration_bound(close_timeout):
            raise ValueError("Live close timeout must be positive and finite")
        self._source = source
        self._closed = Event()
        self._close_lock = Lock()
        self._startup_timeout = startup_timeout
        self._close_timeout = close_timeout
        self._stopper: Thread | None = None
        self._shutdown_error: Exception | None = None
        self._error: Exception | None = None
        self._process = open_mpegts_remux_process(ffmpeg_path)
        assert self._process.stdin is not None and self._process.stdout is not None
        self._stdout = cast(BufferedReader, self._process.stdout)
        self._tail, self._stderr_thread = start_stderr_drain(self._process)
        self._writer = Thread(
            target=self._feed,
            args=(self._process.stdin,),
            name="pyezvizapi-live-mpegts",
            daemon=True,
        )
        self._writer.start()

    def _feed(self, stdin: BinaryIO) -> None:
        try:
            if self._closed.is_set():
                return
            deadline = time.monotonic() + self._startup_timeout
            with closing(self._source.iter_media_packets(startup_deadline=deadline)) as packets:
                for packet in packets:
                    if self._closed.is_set():
                        return
                    if packet.metadata.encrypted or packet.metadata.source == "local_ecdh":
                        raise EzvizUnsupportedMediaError(
                            "Live MPEG-TS requires clear MPEG-PS input",
                            source=packet.metadata.source,
                            reason="unsupported_live_input",
                        )
                    stdin.write(packet.body)
                    stdin.flush()
        except BrokenPipeError:
            pass
        except Exception as error:
            self._error = error
        finally:
            with suppress(OSError):
                stdin.close()

    def read(self, size: int = 65536) -> bytes:
        """Read up to size bytes; return empty bytes on EOF or cancellation."""
        if size <= 0:
            raise ValueError("Live read size must be positive")
        if self._closed.is_set():
            return b""
        try:
            chunk = self._stdout.read1(size)
        except (OSError, ValueError):
            if self._closed.is_set():
                return b""
            raise
        if self._closed.is_set():
            return b""
        if chunk:
            return chunk
        try:
            status = self._process.wait(timeout=5)
            if self._stderr_thread is not None:
                self._stderr_thread.join(timeout=1)
            if self._error is not None:
                if isinstance(self._error, PyEzvizError):
                    raise self._error
                raise PyEzvizError("Live media input failed") from self._error
            if status:
                raise _ffmpeg_exit_error(status, self._tail.text())
            return b""
        except subprocess.TimeoutExpired as error:
            raise PyEzvizError("FFmpeg did not exit after closing its output") from error
        finally:
            self.__exit__(*sys.exc_info())

    def _stop(self) -> None:
        try:
            try:
                _wait_for_process(self._process)
            finally:
                self._source.close()
        except Exception as error:
            self._shutdown_error = error

    def close(self) -> None:
        """Interrupt reads and await shutdown, or raise with ownership retained."""
        deadline = time.monotonic() + self._close_timeout
        with self._close_lock:
            self._closed.set()
            if self._stopper is None:
                self._stopper = Thread(target=self._stop, name="pyezvizapi-live-stop", daemon=True)
                self._stopper.start()
            stopper = self._stopper
        for thread in (stopper, self._writer, self._stderr_thread):
            if thread is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
                if thread.is_alive():
                    raise LiveStreamShutdownTimeout(
                        "Live MPEG-TS shutdown timed out; stream owner retained"
                    )
        self._stdout.close()
        if self._process.stderr is not None:
            self._process.stderr.close()
        if (
            self._shutdown_error is not None
            or not self._source.capture_result["transport_closure_verified"]
        ):
            raise PyEzvizError(
                "Live MPEG-TS transport cleanup could not be verified"
            ) from self._shutdown_error

    def __enter__(self) -> LiveMpegtsStream:
        return self

    def __exit__(self, *args: object) -> None:
        if args and args[0] is not None:
            with suppress(Exception):
                self.close()
        else:
            self.close()


def open_live_mpegts_stream(
    client: EzvizClient,
    serial: str,
    *,
    channel: int | None = None,
    ffmpeg_path: str = "ffmpeg",
    source: AutoClipSource | None = None,
    close_timeout: float = 15.0,
) -> LiveMpegtsStream:
    """Open clear MPEG-PS live media using the selected transport policy."""
    options = source if source is not None else AutoClipSource()
    return LiveMpegtsStream(
        AutoMediaStream(client, serial, options, channel=channel),
        ffmpeg_path,
        startup_timeout=options.timeout,
        close_timeout=close_timeout,
    )
