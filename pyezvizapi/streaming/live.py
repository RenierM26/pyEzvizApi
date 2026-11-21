"""Closeable live MPEG-TS output for integration-owned HTTP routes."""

from __future__ import annotations

from contextlib import closing, suppress
from io import BufferedReader
import subprocess
import sys
from threading import Event, Lock, Thread
from typing import TYPE_CHECKING, BinaryIO, cast

from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming.capture import AutoClipSource
from pyezvizapi.streaming.media.remux import (
    _ffmpeg_exit_error,
    _wait_for_process,
    open_mpegts_remux_process,
    start_stderr_drain,
)
from pyezvizapi.streaming.selection import AutoMediaStream

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


class LiveMpegtsStream:
    """One synchronous reader, with cancellation from another thread."""

    def __init__(self, source: AutoMediaStream, ffmpeg_path: str) -> None:
        self._source = source
        self._closed = Event()
        self._close_lock = Lock()
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
            with closing(self._source.iter_media_packets()) as packets:
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

    def close(self) -> None:
        """Stop the subprocess and interrupt the selected transport."""
        with self._close_lock:
            if self._closed.is_set():
                return
            self._closed.set()
            try:
                _wait_for_process(self._process)
            finally:
                try:
                    self._source.close()
                finally:
                    self._writer.join(timeout=5)
                    self._stdout.close()
                    if self._stderr_thread is not None:
                        self._stderr_thread.join(timeout=1)
                    if self._process.stderr is not None:
                        self._process.stderr.close()

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
) -> LiveMpegtsStream:
    """Open clear MPEG-PS live media using the SDK's automatic source policy."""
    return LiveMpegtsStream(
        AutoMediaStream(client, serial, source or AutoClipSource(), channel=channel),
        ffmpeg_path,
    )
