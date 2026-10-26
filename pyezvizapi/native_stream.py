"""Continuous local MPEG-PS to selected-track MPEG-TS, without a player/server.

One source owner and a bounded output queue. PyAV is loaded only when starting
the optional streaming feature. HA/integrations own their HTTP route and client.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from fractions import Fraction
import hashlib
from importlib import import_module
import io
import math
from queue import Empty, Queue
import sys
from threading import BoundedSemaphore, Event, Lock, Thread, current_thread
import time
from typing import TYPE_CHECKING, Any, Literal, Protocol

from .clip import AutoClipSource
from .exceptions import PyEzvizError
from .media import MediaPacket
from .native_ps import MAX_PENDING_PS_BYTES, NativePsTransform

if TYPE_CHECKING:
    from .client import EzvizClient

IO_CHUNK_BYTES = 65536
OUTPUT_QUEUE_CHUNKS = 4
_POLL_SECONDS = 0.025


async def _join_async_task[T](task: asyncio.Task[T]) -> T:
    """Wait through cancellation until an already-owned bounded task finishes."""
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
        except Exception:
            break  # Retrieve and propagate its original exception below.
    if interrupted:
        with suppress(BaseException):
            task.result()
        raise asyncio.CancelledError
    return task.result()


class NativeStreamClosed(PyEzvizError):
    """Consumer cancellation, distinct from verified finite-source EOF."""


class _Cancelled(Exception):
    """Internal cooperative worker cancellation."""


class NativePacketStream(Protocol):
    """Lazy, local packet owner. close must interrupt reads, not its generator.

    The worker alone closes the iterator. A noncooperative transport remains
    owned and a close timeout is reported; it is never called clean shutdown.
    """

    def iter_media_packets(self) -> Iterator[MediaPacket]:
        """Return normalized PS packets; no implicit count/duration limits."""
        raise NotImplementedError

    def close(self) -> None:
        """Interrupt pending source I/O and release the source transport."""
        raise NotImplementedError


@dataclass(frozen=True)
class NativeTrackSelection:
    """Observed container/PES IDs, not lens ordinals or prior-session indices."""

    video_id: int
    audio_id: int | None = None

    def __post_init__(self) -> None:
        if self.video_id is None:
            raise ValueError("Select an observed video container ID")
        for value in (self.video_id, self.audio_id):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**31
            ):
                raise ValueError("Container IDs must be nonnegative integers")
        if self.video_id == self.audio_id:
            raise ValueError("Video and audio require distinct container IDs")


@dataclass(frozen=True)
class NativeStreamOptions:
    """Finite startup/idle/shutdown budgets; session duration is not capped.

    finite_source is only for caller-attested recordings/tests. Live source
    exhaustion is always an error and cannot authorize a decryption-tail flush.
    """

    selection: NativeTrackSelection
    video_codec: Literal["h264", "hevc"]
    startup_timeout: float = 20.0
    idle_timeout: float = 10.0
    close_timeout: float = 5.0
    finite_source: bool = False

    def __post_init__(self) -> None:
        if self.video_codec not in {"h264", "hevc"}:
            raise ValueError("Select H.264 or HEVC explicitly")
        if not isinstance(self.selection, NativeTrackSelection):
            raise ValueError("Supply an explicit native track selection")
        if not isinstance(self.finite_source, bool):
            raise ValueError("Finite-source assertion must be a boolean")
        for value in (self.startup_timeout, self.idle_timeout, self.close_timeout):
            if isinstance(value, bool) or not math.isfinite(value) or not 0 < value <= 30:
                raise ValueError("Stream timeouts must be positive and at most 30 seconds")


class _PsInput(io.RawIOBase):
    def __init__(
        self,
        source: NativePacketStream,
        *,
        media_key: str | bytes | None,
        nalu_header_size: int,
        finite_source: bool,
        check_stop: Callable[[], None],
    ) -> None:
        super().__init__()
        self.check_stop = check_stop
        self.finite_source = finite_source
        self.iterator: Iterator[MediaPacket] = iter(())
        self.transform = NativePsTransform(media_key, nalu_header_size=nalu_header_size)
        self.pending = bytearray()
        self.ended = False
        self.packets = self.received = self.clear_bytes = self.peak_read_bytes = 0
        self.input_hash = hashlib.sha256()
        self.clear_hash = hashlib.sha256()
        self.failure: BaseException | None = None
        # External iterator construction may fail. Initialize cleanup-owned
        # attributes first so a partial RawIOBase can still close safely.
        self.iterator = iter(source.iter_media_packets())

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        try:
            return self._read(size)
        except BaseException as error:
            if not isinstance(error, _Cancelled):
                self.failure = error
            if not isinstance(error, Exception):
                # Never pass process-control exceptions through native I/O:
                # a backend may print SystemExit and finalize the interpreter.
                # Preserve the original for the consumer, but cross the C
                # callback boundary with an ordinary operation exception.
                raise PyEzvizError("Native source callback terminated") from error
            raise

    def _read(self, size: int) -> bytes:
        self.check_stop()
        if size == 0:
            return b""
        size = min(IO_CHUNK_BYTES, size) if size > 0 else IO_CHUNK_BYTES
        while not self.pending and not self.ended:
            self.check_stop()
            try:
                packet = next(self.iterator)
            except StopIteration:
                if not self.finite_source:
                    raise PyEzvizError("Continuous native source ended unexpectedly") from None
                clear = self.transform.finish()
                self.ended = True
            else:
                self.check_stop()
                if packet.metadata.source not in {"local_sdk", "local_ecdh"}:
                    raise PyEzvizError("Native stream accepts local PS sources only")
                body = packet.body
                if not isinstance(body, bytes) or not 0 < len(body) <= MAX_PENDING_PS_BYTES:
                    raise PyEzvizError("Native source packet exceeds its immutable byte contract")
                self.packets += 1
                self.received += len(body)
                self.input_hash.update(body)
                clear = self.transform.feed(body)
            self.check_stop()
            self.clear_hash.update(clear)
            self.clear_bytes += len(clear)
            self.pending.extend(clear)
            self.peak_read_bytes = max(self.peak_read_bytes, len(self.pending))
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result

    def close(self) -> None:
        if self.closed:
            return
        try:
            close = getattr(self.iterator, "close", None)
            if close is not None:
                close()  # Only this worker ever closes its executing iterator.
        finally:
            self.transform.close()
            self.pending.clear()
            super().close()


class _TsOutput:
    def __init__(self, publish: Callable[[bytes], None]) -> None:
        self.publish = publish

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:
        if len(data) > MAX_PENDING_PS_BYTES:
            raise PyEzvizError("Native mux write exceeds the managed byte budget")
        for offset in range(0, len(data), IO_CHUNK_BYTES):
            self.publish(bytes(data[offset : offset + IO_CHUNK_BYTES]))
        return len(data)


class NativeMpegTsStream:
    """One lazy continuous stream-copy owner; always use a context manager.

    Source factory must return a lazy interruptible local owner, not perform
    uninterruptible login. No listener, decoder, transcoder or account client
    is created here. close failure leaves the owner available for retry/recovery.
    """

    def __init__(
        self,
        source_factory: Callable[[], NativePacketStream],
        options: NativeStreamOptions,
        *,
        media_key: str | bytes | None = None,
        nalu_header_size: int | None = None,
    ) -> None:
        header = (
            nalu_header_size
            if nalu_header_size is not None
            else (2 if options.video_codec == "hevc" else 1)
        )
        # Validate crypto before ownership transfer or any source factory call.
        NativePsTransform(media_key, nalu_header_size=header).close()
        self.options = options
        self._factory = source_factory
        self._key = media_key
        self._header = header
        self._queue: Queue[bytes] = Queue(maxsize=OUTPUT_QUEUE_CHUNKS)
        self._output_slots = BoundedSemaphore(OUTPUT_QUEUE_CHUNKS)
        self._stop = Event()
        self._finished = Event()
        self._lock = Lock()
        self._source_close_lock = Lock()
        self._read_lock = Lock()
        self._source: NativePacketStream | None = None
        self._source_closed = False
        self._reader: _PsInput | None = None
        self._worker: Thread | None = None
        self._canceller: Thread | None = None
        self._closed = self._completed = self._delivered = False
        self._close_timed_out = False
        self._failure: BaseException | None = None
        self._cleanup_errors: list[str] = []
        self._tracks: list[dict[str, Any]] = []
        self._published = self._peak_queue = self._output_owned = 0
        self._read_bytes = self._discarded_bytes = self._output_owned_bytes = (
            self._peak_output_bytes
        ) = 0

    def _check_stop(self) -> None:
        if self._stop.is_set():
            raise _Cancelled

    def _publish(self, chunk: bytes) -> None:
        while not self._output_slots.acquire(timeout=_POLL_SECONDS):
            self._check_stop()
        if self._stop.is_set():
            self._output_slots.release()
            raise _Cancelled
        with self._lock:
            self._output_owned += 1
            self._output_owned_bytes += len(chunk)
            self._peak_output_bytes = max(self._peak_output_bytes, self._output_owned_bytes)
            self._peak_queue = max(self._peak_queue, self._output_owned)
            self._published += len(chunk)
        self._queue.put_nowait(chunk)  # A reserved credit guarantees capacity.

    def _return_output_credit(self, chunk: bytes, *, abandon: bool = False) -> bool:
        with self._lock:
            self._output_owned -= 1
            self._output_owned_bytes -= len(chunk)
            discarded = abandon or self._closed
            if discarded:
                self._discarded_bytes += len(chunk)
            else:
                self._read_bytes += len(chunk)
        self._output_slots.release()
        return discarded

    def start(self) -> NativeMpegTsStream:
        """Start once; optional runtime and source I/O stay in the owned worker."""
        with self._lock:
            if self._closed:
                raise NativeStreamClosed("Native stream is closed")
            if self._worker is None:
                self._worker = Thread(target=self._run, name="pyezvizapi-native-mux", daemon=True)
                self._worker.start()
        return self

    def __enter__(self) -> NativeMpegTsStream:
        return self.start()

    def __exit__(self, exc_type: object, *_args: object) -> None:
        try:
            self._check_exit_cleanup()
            self.close()
        except PyEzvizError:
            if exc_type is None:
                raise

    async def __aenter__(self) -> NativeMpegTsStream:
        # Remain lazy: optional import/source startup happens in the read worker.
        return self

    async def __aexit__(self, exc_type: object, *_args: object) -> None:
        try:
            self._check_exit_cleanup()
            await self.aclose()
        except PyEzvizError:
            if exc_type is None:
                raise

    async def aclose(self) -> None:
        """Close off-loop, waiting for owned cleanup even if cancelled again."""
        # Wake executor reads before submitting cleanup to that executor. Even
        # a saturated/shared HA executor must not delay transport cancellation.
        self._request_stop()
        await _join_async_task(asyncio.create_task(asyncio.to_thread(self.close)))

    async def async_chunks(self) -> AsyncGenerator[bytes, None]:
        """Backpressured async bridge; join any outstanding read on cancellation.

        Use inside async with. A route disconnect must close this generator or
        cancel its task; no input is accumulated while its consumer is paused.
        """
        pending: asyncio.Task[bytes] | None = None
        try:
            while True:
                pending = asyncio.create_task(asyncio.to_thread(self.read))
                chunk = await asyncio.shield(pending)
                pending = None
                if not chunk:
                    return
                yield chunk
        finally:
            primary = sys.exception()
            try:
                self._check_exit_cleanup()
                await self.aclose()
            except BaseException:  # codeql[py/catch-base-exception] lgtm[py/catch-base-exception]
                # Cleanup cannot replace the active consumer exception; a
                # normal exit still re-raises every cleanup failure.
                if primary is None:
                    raise
            finally:
                if pending is not None:
                    # close wakes read via the stop event; retrieving its result
                    # prevents an abandoned executor read after route teardown.
                    with suppress(PyEzvizError, TimeoutError, asyncio.CancelledError):
                        await _join_async_task(pending)

    def _close_source(self) -> None:
        with self._source_close_lock:
            if self._source is not None and not self._source_closed:
                try:
                    self._source.close()
                except BaseException as error:  # codeql[py/catch-base-exception] lgtm[py/catch-base-exception]
                    # This callback runs in an owned worker/canceller. A source
                    # interrupt must remain failed closure, not kill that thread
                    # before its completion/ownership evidence is published.
                    # Preserve cleanup failure independently of the stream error.
                    self._record_cleanup(error)
                else:
                    self._source_closed = True

    def _record_cleanup(self, error: BaseException) -> None:
        name = type(error).__name__
        if name not in self._cleanup_errors and len(self._cleanup_errors) < 4:
            self._cleanup_errors.append(name)

    def _selected_streams(self, container: Any) -> list[Any]:
        selected = []
        expected = [
            (self.options.selection.video_id, "video", self.options.video_codec),
            (self.options.selection.audio_id, "audio", "aac"),
        ]
        for stream_id, kind, codec in expected:
            if stream_id is None:
                continue
            matches = [stream for stream in container.streams if stream.id == stream_id]
            if (
                len(matches) != 1
                or matches[0].type != kind
                or matches[0].codec_context.name != codec
            ):
                raise PyEzvizError(
                    "Native selected container ID is absent or its codec/type changed"
                )
            stream = matches[0]
            context = stream.codec_context
            if (kind == "video" and (context.width <= 0 or context.height <= 0)) or (
                kind == "audio" and (context.sample_rate <= 0 or context.layout.nb_channels <= 0)
            ):
                raise PyEzvizError("Native selected track has unresolved codec parameters")
            self._tracks.append(dict(id=stream.id, index=stream.index, kind=kind, codec=codec))
            selected.append(stream)
        return selected

    def _run(self) -> None:
        try:
            self._check_stop()
            av = import_module("av")
            self._check_stop()
            self._source = self._factory()
            self._check_stop()
            reader = self._reader = _PsInput(
                self._source,
                media_key=self._key,
                nalu_header_size=self._header,
                finite_source=self.options.finite_source,
                check_stop=self._check_stop,
            )
            try:
                with av.open(
                    reader,
                    format="mpeg",
                    options={
                        "probesize": "1048576",
                        "analyzeduration": "5000000",
                        "max_streams": "64",
                    },
                ) as incoming:
                    selected = self._selected_streams(incoming)
                    with av.open(
                        _TsOutput(self._publish),
                        mode="w",
                        format="mpegts",
                        options={
                            "mpegts_copyts": "1",
                            "max_delay": "0",
                            "flush_packets": "1",
                            # With strictly increasing per-track DTS, a 1us
                            # interleave delta cannot accumulate a missing
                            # track's seconds of encoded packets in libav.
                            "max_interleave_delta": "1",
                            "avoid_negative_ts": "disabled",
                        },
                    ) as outgoing:
                        mapping = {
                            stream.index: outgoing.add_stream_from_template(stream)
                            for stream in selected
                        }
                        count = 0
                        last_dts: dict[int, Fraction] = {}
                        identities = {
                            stream.index: (stream.id, stream.codec_context.name)
                            for stream in selected
                        }
                        for packet in incoming.demux(selected):
                            self._check_stop()
                            if not packet.size:
                                continue  # libav demux flush sentinel, not a source picture.
                            if (
                                packet.size > MAX_PENDING_PS_BYTES
                                or packet.pts is None
                                or packet.dts is None
                                or packet.time_base is None
                            ):
                                raise PyEzvizError(
                                    "Native packet has missing timestamps or exceeds the byte budget"
                                )
                            index = packet.stream.index
                            if (packet.stream.id, packet.stream.codec_context.name) != identities[
                                index
                            ]:
                                raise PyEzvizError(
                                    "Native selected track identity or codec changed"
                                )
                            stamp = Fraction(packet.dts) * packet.time_base
                            if index in last_dts and stamp <= last_dts[index]:
                                raise PyEzvizError(
                                    "Native decode timestamp repeated or moved backwards"
                                )
                            last_dts[index] = stamp
                            packet.stream = mapping[index]
                            outgoing.mux(packet)
                            count += 1
                        if not count or not reader.ended:
                            raise PyEzvizError("Native stream did not verify its finite source end")
                self._completed = True
            finally:
                primary = sys.exception()
                try:
                    reader.close()
                except BaseException as error:  # codeql[py/catch-base-exception] lgtm[py/catch-base-exception]
                    # Iterator-close failures are recorded separately without
                    # replacing the native/source failure already in flight.
                    self._record_cleanup(error)
                    if primary is None:
                        raise
        except BaseException as error:  # codeql[py/catch-base-exception] lgtm[py/catch-base-exception]
            # Thread boundary: propagate to the consumer instead of silent EOF.
            if not self._stop.is_set():
                self._failure = (
                    self._reader.failure if self._reader and self._reader.failure else error
                )
        finally:
            self._close_source()
            self._key = None
            self._finished.set()

    def read(self) -> bytes:
        """Read at most 64 KiB; timeout/failure cancels owned source I/O.

        Empty bytes mean verified finite completion only, never source failure
        or consumer cancellation. A slow consumer bounds prefetch by queue size.
        """
        if not self._read_lock.acquire(blocking=False):
            raise PyEzvizError("Native stream supports one reader per source owner")
        try:
            return self._read_one()
        finally:
            self._read_lock.release()

    def _read_one(self) -> bytes:
        self.start()
        deadline = time.monotonic() + (
            self.options.idle_timeout if self._delivered else self.options.startup_timeout
        )
        while True:
            if self._closed:
                raise NativeStreamClosed("Native stream was cancelled")
            if self._failure is not None or self._cleanup_errors:
                error = self._failure or PyEzvizError("Native source cleanup failed")
                # Receipt preserves cleanup/ownership failure; keep the primary error.
                with suppress(PyEzvizError):
                    self.close()
                raise PyEzvizError("Native stream worker failed") from error
            try:
                chunk = self._queue.get(timeout=_POLL_SECONDS)
            except Empty:
                if self._finished.is_set():
                    if self._failure is not None or self._cleanup_errors:
                        continue
                    if not self._completed:
                        raise PyEzvizError(
                            "Native worker ended without verified completion"
                        ) from None
                    return b""
                if time.monotonic() >= deadline:
                    self._failure = TimeoutError("Native stream startup/idle deadline exceeded")
                    try:
                        self.close()
                    finally:
                        raise TimeoutError("Native stream startup/idle deadline exceeded") from None
            else:
                if self._return_output_credit(chunk):
                    raise NativeStreamClosed("Native stream was cancelled")
                self._delivered = True
                return chunk

    def __iter__(self) -> Iterator[bytes]:
        while chunk := self.read():
            yield chunk

    def close(self) -> None:
        """Interrupt transport, release backpressure and join under one deadline.

        A timed-out owner is retained; call close again after caller recovery.
        No consumer thread closes a generator while its next call is running.
        """
        self._request_stop()
        deadline = time.monotonic() + self.options.close_timeout
        worker = self._worker
        if worker is not None:
            if self._canceller is None or (
                not self._canceller.is_alive() and not self._source_closed
            ):
                self._canceller = Thread(
                    target=self._close_source, name="pyezvizapi-native-cancel", daemon=True
                )
                self._canceller.start()
            for thread in (self._canceller, worker):
                if thread is not current_thread():
                    thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if self._canceller.is_alive() or worker.is_alive():
                self._close_timed_out = True
                raise PyEzvizError("Native stream shutdown timed out; owner retained for recovery")
        self._close_timed_out = False
        while not self._queue.empty():
            try:
                chunk = self._queue.get_nowait()
                self._return_output_credit(chunk, abandon=True)
            except Empty:
                break
        self._key = None
        if self._cleanup_errors:
            raise PyEzvizError("Native source cleanup failed")

    def _request_stop(self) -> None:
        with self._lock:
            self._closed = True
            self._stop.set()

    def _check_exit_cleanup(self) -> None:
        # Context/generator exit must not silently multiply an already-failed
        # shutdown budget. Explicit close/aclose remains the recovery operation.
        if self._close_timed_out and (
            (self._worker is not None and self._worker.is_alive())
            or (self._canceller is not None and self._canceller.is_alive())
        ):
            raise PyEzvizError(
                "Native shutdown already timed out; explicit owner recovery required"
            )

    @property
    def receipt(self) -> dict[str, Any]:
        """Sanitized counters; final ownership fields are authoritative after close."""
        reader = self._reader
        return dict(
            status="failed"
            if self._failure or self._cleanup_errors or self._close_timed_out
            else "completed"
            if self._completed
            else "closed"
            if self._closed
            else "running",
            worker_joined=self._worker is None or not self._worker.is_alive(),
            cancel_joined=self._canceller is None or not self._canceller.is_alive(),
            source_closed=(
                self._source is None and (self._worker is None or self._finished.is_set())
            )
            or self._source_closed,
            queued_chunks=self._queue.qsize(),
            owned_output_chunks=self._output_owned,
            peak_owned_output_chunks=self._peak_queue,
            output_bytes=self._published,
            read_output_bytes=self._read_bytes,
            discarded_output_bytes=self._discarded_bytes,
            owned_output_bytes=self._output_owned_bytes,
            peak_owned_output_bytes=self._peak_output_bytes,
            selected_tracks=list(self._tracks),
            source_packets=reader.packets if reader else 0,
            source_bytes=reader.received if reader else 0,
            clear_bytes=reader.clear_bytes if reader else 0,
            input_sha256=reader.input_hash.hexdigest() if reader else None,
            clear_sha256=reader.clear_hash.hexdigest() if reader else None,
            peak_pending_ps_bytes=reader.transform.peak_pending_bytes if reader else 0,
            peak_read_bytes=reader.peak_read_bytes if reader else 0,
            pending_ps_bytes=reader.transform.pending_bytes if reader else 0,
            pending_read_bytes=len(reader.pending) if reader else 0,
            queue_capacity_bytes=OUTPUT_QUEUE_CHUNKS * IO_CHUNK_BYTES,
            shutdown_timed_out=self._close_timed_out,
            finite_source_end=bool(reader and reader.ended),
            error_type=type(self._failure).__name__ if self._failure else None,
            cleanup_error_types=list(self._cleanup_errors),
            ha_verified=False,
        )


def native_mpegts_stream_from_client(
    client: EzvizClient,
    serial: str,
    *,
    source: AutoClipSource,
    options: NativeStreamOptions,
    channel: int,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = None,
    decrypt_video: bool = True,
) -> NativeMpegTsStream:
    """Compose lazy native remux with the existing strictly offline packet owner.

    Supplied credentials only, no account calls, registration or cloud fallback.
    Continuous mode cannot treat an exhausted transport as a finite recording.
    Caller owns EzvizClient; this stream only owns its per-view transport.
    """
    if source.mode != "offline" or source.credentials is None or source.allow_cloud_fallback:
        raise ValueError(
            "Native HA source requires explicit offline credentials and no cloud fallback"
        )
    if options.finite_source:
        raise ValueError("A live native source cannot assert finite recording EOF")
    if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel <= 255:
        raise ValueError("Supply an explicit native preview channel")
    if not isinstance(decrypt_video, bool):
        raise ValueError("Video decryption must be an explicit boolean")
    if decrypt_video:
        media_key = media_key if media_key is not None else source.credentials.media_key
        if not media_key:
            raise ValueError("Native video decryption requires a supplied media key")
    elif media_key is not None:
        raise ValueError("A media key requires video decryption")
    return NativeMpegTsStream(
        lambda: client.open_stream(serial, source=source, channel=channel),
        options,
        media_key=media_key,
        nalu_header_size=nalu_header_size,
    )
