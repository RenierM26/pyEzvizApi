"""Closeable live MPEG-TS output for integration-owned HTTP routes."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, suppress
from functools import partial
from itertools import chain
import socket
import subprocess
from threading import Event, Lock, Thread
import time
from typing import TYPE_CHECKING, BinaryIO

from pyezvizapi.exceptions import EzvizNoMediaError, EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming.capture import AutoClipSource
from pyezvizapi.streaming.cloud.bootstrap import (
    _copy_cloud_rtp_packets_to_mpegts,
    _decrypt_cloud_rtp_nal_unit,
    _parse_cloud_rtp_packet,
)
from pyezvizapi.streaming.cloud.protocol import VtmChannel, VtmPacket
from pyezvizapi.streaming.media.models import MediaPacket, is_positive_finite_duration_bound
from pyezvizapi.streaming.media.native_ps import LegacyPsVideoTransform, NativePsTransform
from pyezvizapi.streaming.media.remux import copy_remuxed_output, open_mpegts_remux_process
from pyezvizapi.streaming.media.rtp import RtpVideoCodec
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
        media_key: str | bytes | None = None,
        nalu_header_size: int = 2,
    ) -> None:
        if not is_positive_finite_duration_bound(startup_timeout):
            raise ValueError("Live startup timeout must be positive and finite")
        if not is_positive_finite_duration_bound(close_timeout):
            raise ValueError("Live close timeout must be positive and finite")
        self._transform: NativePsTransform | LegacyPsVideoTransform | None = None
        if media_key is not None:
            self._transform = (
                LegacyPsVideoTransform(media_key)
                if nalu_header_size == 0 and not isinstance(nalu_header_size, bool)
                else NativePsTransform(
                    media_key, nalu_header_size=nalu_header_size, recover_cloud_pes=True
                )
            )
        self._media_key = media_key
        self._source = source
        self._ffmpeg_path = ffmpeg_path
        self._closed = Event()
        self._close_lock = Lock()
        self._startup_deadline = time.monotonic() + startup_timeout
        self._started_output = False
        self._close_timeout = close_timeout
        self._stopper: Thread | None = None
        self._shutdown_error: Exception | None = None
        self._error: Exception | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._reader, self._sender = socket.socketpair()
        self._writer = Thread(target=self._feed, name="pyezvizapi-live-mpegts", daemon=True)
        self._writer.start()

    def _checked_packets(self, packets: Iterator[MediaPacket]) -> Iterator[MediaPacket]:
        for packet in packets:
            if self._closed.is_set():
                return
            if packet.metadata.encrypted or packet.metadata.source == "local_ecdh":
                raise EzvizUnsupportedMediaError(
                    "Live MPEG-TS does not support encrypted transport or local ECDH",
                    source=packet.metadata.source,
                    reason="unsupported_live_input",
                )
            if packet.body:
                yield packet

    def _set_process(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        if self._closed.is_set():
            self._terminate_process()

    def _terminate_process(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            with suppress(ProcessLookupError):
                process.kill()

    def _feed(self) -> None:
        try:
            if self._closed.is_set():
                return
            deadline = self._startup_deadline
            with (
                self._sender.makefile("wb") as output,
                closing(self._source.iter_media_packets(startup_deadline=deadline)) as packets,
            ):
                checked = self._checked_packets(packets)
                first = next(checked, None)
                if first is None:
                    return
                payloads = chain((first,), checked)
                if (
                    first.metadata.source == "cloud_vtm"
                    and _parse_cloud_rtp_packet(first.body) is not None
                ):
                    self._copy_rtp(payloads, output, deadline)
                else:
                    process = open_mpegts_remux_process(self._ffmpeg_path)
                    self._set_process(process)
                    copy_remuxed_output(
                        process,
                        output,
                        write_input=partial(self._write_ps, payloads),
                        cancel_input=self._source.close,
                        retain_input_owner=True,
                    )
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as error:
            self._error = error
        finally:
            if self._transform is not None:
                self._transform.close()
            self._media_key = None
            with suppress(OSError):
                self._sender.shutdown(socket.SHUT_WR)
            self._sender.close()

    def _write_ps(self, packets: Iterator[MediaPacket], stdin: BinaryIO) -> None:
        for packet in packets:
            body = packet.body
            if self._transform is not None:
                body = self._transform.feed(body)
            if body:
                stdin.write(body)
                stdin.flush()

    def _copy_rtp(self, packets: Iterator[MediaPacket], output: BinaryIO, deadline: float) -> None:
        media_key = self._media_key

        def decrypt(annexb: bytes, codec: RtpVideoCodec) -> bytes:
            assert media_key is not None
            return _decrypt_cloud_rtp_nal_unit(
                annexb[4:], media_key, nalu_header_size=2 if codec == "hevc" else 1
            )

        _copy_cloud_rtp_packets_to_mpegts(
            (
                VtmPacket(VtmChannel.STREAM, len(packet.body), 0, 0, packet.body)
                for packet in packets
            ),
            output,
            ffmpeg_path=self._ffmpeg_path,
            cancel_input=self._source.close,
            transform=decrypt if media_key is not None else None,
            audio_key=media_key,
            startup_deadline=deadline,
            on_process=self._set_process,
        )

    def _recv(self, size: int) -> bytes:
        if self._started_output:
            return self._reader.recv(size)
        remaining = self._startup_deadline - time.monotonic()
        self._reader.settimeout(max(0.0, remaining))
        try:
            chunk = self._reader.recv(size)
        except BlockingIOError as error:
            raise TimeoutError from error
        if chunk:
            self._reader.settimeout(None)
            self._started_output = True
        return chunk

    def read(self, size: int = 65536) -> bytes:
        """Read up to size bytes; return empty bytes on EOF or cancellation."""
        if size <= 0:
            raise ValueError("Live read size must be positive")
        if self._closed.is_set():
            return b""
        try:
            chunk = self._recv(size)
        except TimeoutError as timeout:
            if self._closed.is_set():
                return b""
            self.close()
            raise EzvizNoMediaError(
                "Live stream produced no MPEG-TS output before startup deadline"
            ) from timeout
        except OSError:
            if self._closed.is_set():
                return b""
            raise
        if self._closed.is_set():
            return b""
        if chunk:
            return chunk
        error = self._error
        if error is not None:
            with suppress(Exception):
                self.close()
            if isinstance(error, PyEzvizError):
                raise error
            raise PyEzvizError("Live media input failed") from error
        self.close()
        return b""

    def _stop(self) -> None:
        try:
            try:
                self._terminate_process()
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
                with suppress(OSError):
                    self._reader.shutdown(socket.SHUT_RDWR)
                self._reader.close()
                self._stopper = Thread(target=self._stop, name="pyezvizapi-live-stop", daemon=True)
                self._stopper.start()
            stopper = self._stopper
        for thread in (stopper, self._writer):
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                raise LiveStreamShutdownTimeout(
                    "Live MPEG-TS shutdown timed out; stream owner retained"
                )
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
    media_key: str | bytes | None = None,
    nalu_header_size: int = 2,
) -> LiveMpegtsStream:
    """Open MPEG-PS or supported cloud RTP media using the selected transport.

    Supply the camera's media key for inner video encryption. For MPEG-PS set
    ``nalu_header_size=0`` for encrypted headers, 1 for clear H.264 headers,
    or 2 for clear HEVC headers. Cloud RTP uses its detected codec. Transport-level encryption and local ECDH are not supported.
    """
    options = source if source is not None else AutoClipSource()
    if media_key is not None and options.mode != "cloud":
        raise ValueError("Live media decryption requires explicit cloud mode")
    return LiveMpegtsStream(
        AutoMediaStream(client, serial, options, channel=channel),
        ffmpeg_path,
        startup_timeout=options.timeout,
        close_timeout=close_timeout,
        media_key=media_key,
        nalu_header_size=nalu_header_size,
    )
