"""Shared packet and capture models for EZVIZ stream transports.

Transport modules keep ownership of their handshakes and wire parsing.  This
module defines the small downstream contract used by capture, decode, and mux
code after a transport has produced media packets.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
import math
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
import time
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast, runtime_checkable

from .exceptions import PyEzvizError

MediaOutputFormat = Literal["mpegps", "mpegts"]
MediaMetadataValue = str | int | float | bool | None
_ITERATOR_STOPPED = object()
_ITERATOR_TIMED_OUT = object()


class _IteratorProducer[PacketT]:
    """Manage one request-driven worker for a potentially blocking iterator."""

    def __init__(
        self,
        packets: Iterator[PacketT],
        cancel: Callable[[], None] | None,
    ) -> None:
        self._packets = packets
        self._cancel = cancel
        self._requests: Queue[object] = Queue(maxsize=1)
        self._results: Queue[tuple[bool, object]] = Queue(maxsize=1)
        self._stop = Event()
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self._requests.get()
                if self._stop.is_set():
                    return
                try:
                    packet = next(self._packets)
                except StopIteration:
                    self._results.put((True, _ITERATOR_STOPPED))
                    return
                except Exception as err:
                    self._results.put((False, err))
                    return
                if self._stop.is_set():
                    return
                self._results.put((True, packet))
        finally:
            close = getattr(self._packets, "close", None)
            if callable(close):
                with suppress(RuntimeError, ValueError):
                    close()

    def next_before(
        self,
        *,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> PacketT | object:
        remaining = deadline - monotonic()
        if remaining <= 0:
            return _ITERATOR_TIMED_OUT
        self._requests.put(object())
        try:
            succeeded, value = self._results.get(timeout=remaining)
        except Empty:
            return _ITERATOR_TIMED_OUT
        if not succeeded:
            raise cast(Exception, value)
        return value

    def close(self) -> None:
        self._stop.set()
        if self._cancel is not None:
            with suppress(Exception):
                self._cancel()
        with suppress(Full):
            self._requests.put_nowait(object())
        self._thread.join(timeout=0.01)


@dataclass
class _IterableProducerState[PacketT]:
    lock: Lock = field(default_factory=Lock)
    producer: _IteratorProducer[PacketT] | None = None


@dataclass(frozen=True)
class MediaPacketMetadata:
    """Transport-neutral metadata attached to one media payload."""

    source: str
    channel: int | None = None
    encrypted: bool = False
    sequence: int | None = None
    message_code: int | None = None
    data_type: int | None = None
    attributes: Mapping[str, MediaMetadataValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True)
class MediaPacket:
    """One immutable media payload and its transport-neutral metadata."""

    body: bytes = field(repr=False)
    metadata: MediaPacketMetadata

    @property
    def length(self) -> int:
        """Return the payload length."""

        return len(self.body)


@dataclass(frozen=True)
class CaptureLimits:
    """Common bounds for a packet capture."""

    max_packets: int | None = None
    duration_seconds: float | None = None
    max_bytes: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("max_packets", self.max_packets),
            ("duration_seconds", self.duration_seconds),
            ("max_bytes", self.max_bytes),
        ):
            if value is not None and value <= 0:
                raise PyEzvizError(f"{name} must be positive or None")
        if self.duration_seconds is not None and not math.isfinite(self.duration_seconds):
            raise PyEzvizError("duration_seconds must be finite or None")

    @property
    def bounded(self) -> bool:
        """Return whether at least one capture limit is configured."""

        return any(
            value is not None for value in (self.max_packets, self.duration_seconds, self.max_bytes)
        )

    def require_bounded(self, context: str) -> None:
        """Reject an operation that requires a finite capture."""

        if not self.bounded:
            raise PyEzvizError(f"{context} requires at least one capture limit")


@dataclass(frozen=True)
class MediaDecodeOptions:
    """Common options for optional media decryption and decode preparation."""

    decrypt_video: bool = False
    media_key: str | bytes | None = field(default=None, repr=False)
    nalu_header_size: int | None = None
    decrypt_hevc_parameter_sets: bool = False

    def __post_init__(self) -> None:
        if self.nalu_header_size is not None and self.nalu_header_size < 0:
            raise PyEzvizError("nalu_header_size must be non-negative or None")


@dataclass(frozen=True)
class MediaMuxOptions:
    """Common output and FFmpeg options for downstream muxing."""

    output_format: MediaOutputFormat = "mpegts"
    ffmpeg_path: str = "ffmpeg"
    h264_skip_initial_idr_windows: int = 0
    h264_trim_to_clean_idr_window: bool = False
    h264_clean_idr_preroll_seconds: float = 0.0
    h264_clean_idr_max_windows: int = 32
    h264_wait_for_clean_idr_window: bool = False
    h264_clean_idr_wait_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.output_format not in ("mpegps", "mpegts"):
            raise PyEzvizError("output_format must be 'mpegps' or 'mpegts'")
        if not self.ffmpeg_path:
            raise PyEzvizError("ffmpeg_path cannot be empty")
        if self.h264_skip_initial_idr_windows < 0:
            raise PyEzvizError("h264_skip_initial_idr_windows must be non-negative")
        if self.h264_clean_idr_preroll_seconds < 0:
            raise PyEzvizError("h264_clean_idr_preroll_seconds must be non-negative")
        if self.h264_clean_idr_max_windows <= 0:
            raise PyEzvizError("h264_clean_idr_max_windows must be positive")
        if self.h264_clean_idr_wait_seconds < 0:
            raise PyEzvizError("h264_clean_idr_wait_seconds must be non-negative")
        if self.h264_wait_for_clean_idr_window and (
            self.h264_skip_initial_idr_windows
            or self.h264_trim_to_clean_idr_window
            or self.h264_clean_idr_preroll_seconds
        ):
            raise PyEzvizError(
                "h264_wait_for_clean_idr_window cannot be combined with H.264 startup trim options"
            )
        if self.h264_clean_idr_preroll_seconds and not self.h264_trim_to_clean_idr_window:
            raise PyEzvizError(
                "h264_clean_idr_preroll_seconds requires h264_trim_to_clean_idr_window"
            )


@runtime_checkable
class MediaPacketSource(Protocol):
    """Transport-neutral bounded packet source."""

    @abstractmethod
    def iter_media_packets(
        self,
        *,
        limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Yield normalized packets within the requested limits."""

        raise NotImplementedError


class LegacyPacketSource[PacketT](Protocol):
    """Existing transport stream shape accepted by the compatibility adapter."""

    @abstractmethod
    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[PacketT]:
        """Yield transport packets within the existing stream limits."""

        raise NotImplementedError


class DeadlineLegacyPacketSource[PacketT](Protocol):
    """Legacy packet source that can include startup in its duration budget."""

    @abstractmethod
    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[PacketT]:
        """Yield transport packets using an optional wall-clock duration."""

        raise NotImplementedError


@dataclass(frozen=True)
class MediaPacketSourceAdapter[PacketT]:
    """Adapt an existing ``iter_packets`` stream without changing its API."""

    source: LegacyPacketSource[PacketT]
    converter: Callable[[PacketT], MediaPacket]
    duration_from_start: bool = False

    def iter_media_packets(
        self,
        *,
        limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Yield normalized packets from the wrapped transport stream."""

        selected_limits = limits or CaptureLimits()
        deadline = (
            monotonic() + selected_limits.duration_seconds
            if self.duration_from_start and selected_limits.duration_seconds is not None
            else None
        )
        emitted_bytes = 0
        if self.duration_from_start:
            packets = cast(
                DeadlineLegacyPacketSource[PacketT],
                self.source,
            ).iter_packets(
                max_packets=selected_limits.max_packets,
                duration_seconds=selected_limits.duration_seconds,
                duration_from_start=True,
                monotonic=monotonic,
            )
        else:
            packets = self.source.iter_packets(
                max_packets=selected_limits.max_packets,
                duration_seconds=selected_limits.duration_seconds,
                monotonic=monotonic,
            )
        for packet in packets:
            if deadline is not None and monotonic() >= deadline:
                break
            normalized = self.converter(packet)
            if (
                selected_limits.max_bytes is not None
                and emitted_bytes + normalized.length > selected_limits.max_bytes
            ):
                break
            emitted_bytes += normalized.length
            yield normalized
            if selected_limits.max_bytes is not None and emitted_bytes >= selected_limits.max_bytes:
                return


@dataclass(frozen=True)
class IterableMediaPacketSource[PacketT]:
    """Adapt an existing packet iterable to the common source contract."""

    packets: Iterable[PacketT]
    converter: Callable[[PacketT], MediaPacket]
    predicate: Callable[[PacketT], bool] | None = None
    cancel: Callable[[], None] | None = field(default=None, repr=False, compare=False)
    _producer_state: _IterableProducerState[Any] = field(
        default_factory=_IterableProducerState,
        init=False,
        repr=False,
        compare=False,
    )

    def iter_media_packets(  # noqa: PLR0912
        self,
        *,
        limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Yield normalized packets while enforcing common capture bounds."""

        selected_limits = limits or CaptureLimits()
        deadline = (
            monotonic() + selected_limits.duration_seconds
            if selected_limits.duration_seconds is not None
            else None
        )
        if deadline is not None and self.cancel is None:
            raise PyEzvizError(
                "Duration-bounded iterable packet sources require a cancellation callback"
            )
        emitted_packets = 0
        emitted_bytes = 0
        packets = iter(self.packets)
        producer = None
        with self._producer_state.lock:
            active = self._producer_state.producer
            if active is not None and active.alive:
                raise PyEzvizError(
                    "Packet source is still cancelling a timed-out iterator read"
                )
            self._producer_state.producer = None
            if deadline is not None:
                producer = _IteratorProducer(packets, self.cancel)
                self._producer_state.producer = producer
        try:
            while True:
                if producer is None or deadline is None:
                    try:
                        packet = next(packets)
                    except StopIteration:
                        return
                else:
                    result = producer.next_before(
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                    if result is _ITERATOR_STOPPED or result is _ITERATOR_TIMED_OUT:
                        return
                    packet = cast(PacketT, result)
                    if monotonic() >= deadline:
                        return
                if self.predicate is not None and not self.predicate(packet):
                    continue
                normalized = self.converter(packet)
                if (
                    selected_limits.max_bytes is not None
                    and emitted_bytes + normalized.length > selected_limits.max_bytes
                ):
                    break
                emitted_packets += 1
                emitted_bytes += normalized.length
                yield normalized
                if (
                    selected_limits.max_packets is not None
                    and emitted_packets >= selected_limits.max_packets
                ) or (
                    selected_limits.max_bytes is not None
                    and emitted_bytes >= selected_limits.max_bytes
                ):
                    return
        finally:
            if producer is not None:
                producer.close()
                with self._producer_state.lock:
                    if not producer.alive:
                        self._producer_state.producer = None
