"""Tests for transport-neutral media packet and capture contracts."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError
from threading import Event
import time
from typing import Any

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
    hcnetsdk_media_packet_source,
    hcnetsdk_real_data_to_media_packet,
)
from pyezvizapi.local_stream import (
    EzvizLocalStreamPacket,
    local_media_packet_source,
    local_stream_packet_to_media_packet,
)
from pyezvizapi.local_stream_ecdh import (
    EzvizLocalSdkEcdhMediaStream,
    EzvizLocalSdkEcdhStreamPacket,
    local_ecdh_media_packet_source,
    local_ecdh_packet_to_media_packet,
)
from pyezvizapi.media import (
    CaptureLimits,
    MediaDecodeOptions,
    MediaMuxOptions,
    MediaPacket,
    MediaPacketSource,
)
from pyezvizapi.stream import (
    VtmChannel,
    VtmPacket,
    vtm_media_packet_source,
    vtm_packet_to_media_packet,
)

BODY = b"abc"


class RecordingPacketStream[PacketT]:
    """Minimal legacy stream that records the compatibility adapter call."""

    def __init__(self, packets: list[PacketT]) -> None:
        self.packets = packets
        self.calls: list[tuple[int | None, float | None, Callable[[], float]]] = []

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[PacketT]:
        """Yield packets using the bounds supported by existing stream classes."""

        del duration_from_start
        self.calls.append((max_packets, duration_seconds, monotonic))
        packets = self.packets if max_packets is None else self.packets[:max_packets]
        yield from packets


@pytest.mark.parametrize("field", ["max_packets", "duration_seconds", "max_bytes"])
def test_capture_limits_reject_non_positive_values(field: str) -> None:
    """Every configured capture bound must be positive."""

    with pytest.raises(PyEzvizError, match=field):
        CaptureLimits(**{field: 0})


def test_capture_limits_require_a_bound() -> None:
    """Callers can explicitly guard operations that must terminate."""

    with pytest.raises(PyEzvizError, match="capture requires"):
        CaptureLimits().require_bounded("capture")
    CaptureLimits(max_packets=1).require_bounded("capture")


@pytest.mark.parametrize("duration", [float("inf"), float("nan")])
def test_capture_limits_reject_non_finite_duration(duration: float) -> None:
    """A nominal duration must represent a deadline that can terminate."""

    with pytest.raises(PyEzvizError, match="finite"):
        CaptureLimits(duration_seconds=duration)


def test_common_decode_and_mux_option_validation() -> None:
    """Shared downstream option models reject invalid values."""

    with pytest.raises(PyEzvizError, match="nalu_header_size"):
        MediaDecodeOptions(nalu_header_size=-1)
    with pytest.raises(PyEzvizError, match="output_format"):
        MediaMuxOptions(output_format="invalid")  # type: ignore[arg-type]
    with pytest.raises(PyEzvizError, match="ffmpeg_path"):
        MediaMuxOptions(ffmpeg_path="")
    assert MediaMuxOptions(h264_clean_idr_wait_seconds=0).h264_clean_idr_wait_seconds == 0
    with pytest.raises(PyEzvizError, match="cannot be combined"):
        MediaMuxOptions(
            h264_wait_for_clean_idr_window=True,
            h264_trim_to_clean_idr_window=True,
        )
    with pytest.raises(PyEzvizError, match="requires h264_trim"):
        MediaMuxOptions(h264_clean_idr_preroll_seconds=1.0)


def test_cloud_vtm_packet_adapter_preserves_metadata() -> None:
    """The cloud adapter preserves all VTM metadata in neutral fields."""

    packet = VtmPacket(VtmChannel.ENCRYPTED_STREAM, 3, 7, 11, BODY)

    normalized = vtm_packet_to_media_packet(packet)

    assert normalized == MediaPacket(body=BODY, metadata=normalized.metadata)
    assert normalized.length == 3
    assert normalized.metadata.source == "cloud_vtm"
    assert normalized.metadata.channel == VtmChannel.ENCRYPTED_STREAM
    assert normalized.metadata.encrypted is True
    assert normalized.metadata.sequence == 7
    assert normalized.metadata.message_code == 11


def test_media_packet_metadata_attributes_are_immutable() -> None:
    """Frozen packet metadata cannot be mutated through its mapping field."""

    normalized = local_stream_packet_to_media_packet(
        EzvizLocalStreamPacket(1, 3, BODY, prefix=b"pre")
    )

    with pytest.raises(TypeError):
        normalized.metadata.attributes["prefix_length"] = 4  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        normalized.metadata.source = "changed"  # type: ignore[misc]


def test_local_sdk_packet_adapter_preserves_metadata() -> None:
    """The local SDK adapter preserves channel, encryption, and prefix length."""

    packet = EzvizLocalStreamPacket(1, 3, BODY, encrypted=True, prefix=b"pre")

    normalized = local_stream_packet_to_media_packet(packet)

    assert normalized.body == BODY
    assert normalized.metadata.source == "local_sdk"
    assert normalized.metadata.channel == 1
    assert normalized.metadata.encrypted is True
    assert normalized.metadata.attributes == {"prefix_length": 3}


def test_local_ecdh_packet_adapter_preserves_metadata() -> None:
    """The ECDH adapter exposes already-decoded bytes and their channel."""

    normalized = local_ecdh_packet_to_media_packet(EzvizLocalSdkEcdhStreamPacket(1, BODY))

    assert normalized.body == BODY
    assert normalized.metadata.source == "local_ecdh"
    assert normalized.metadata.channel == 1
    assert normalized.metadata.encrypted is False


def test_hcnetsdk_packet_adapter_preserves_callback_metadata() -> None:
    """The HCNetSDK adapter preserves callback identity and classification."""

    normalized = hcnetsdk_real_data_to_media_packet(
        HcNetSdkRealDataPacket(
            real_handle=5,
            data_type=HcNetSdkRealDataType.STREAM_DATA,
            body=b"\x00\x00\x01\xbaabc",
        )
    )

    assert normalized.metadata.source == "hcnetsdk"
    assert normalized.metadata.data_type == HcNetSdkRealDataType.STREAM_DATA
    assert normalized.metadata.attributes == {
        "real_handle": 5,
        "payload_kind": "mpeg_ps",
    }


@pytest.mark.parametrize(
    ("packet", "factory", "source_name"),
    [
        (VtmPacket(1, 3, 1, 0, b"abc"), vtm_media_packet_source, "cloud_vtm"),
        (EzvizLocalStreamPacket(1, 3, b"abc"), local_media_packet_source, "local_sdk"),
        (
            EzvizLocalSdkEcdhStreamPacket(1, b"abc"),
            local_ecdh_media_packet_source,
            "local_ecdh",
        ),
    ],
)
def test_legacy_stream_adapters_share_limits_contract(
    packet: Any,
    factory: Callable[[Any], MediaPacketSource],
    source_name: str,
) -> None:
    """Cloud and local legacy streams accept one shared capture contract."""

    monotonic = lambda: 10.0  # noqa: E731
    stream = RecordingPacketStream([packet, packet])
    source = factory(stream)
    limits = CaptureLimits(max_packets=1, duration_seconds=2.0, max_bytes=3)

    assert isinstance(source, MediaPacketSource)
    assert [
        item.metadata.source
        for item in source.iter_media_packets(
            limits=limits,
            monotonic=monotonic,
        )
    ] == [source_name]
    assert stream.calls == [(1, 2.0, monotonic)]


def test_legacy_stream_adapter_enforces_max_bytes() -> None:
    """The compatibility layer adds byte bounds without changing old streams."""

    stream = RecordingPacketStream([VtmPacket(1, 3, 1, 0, b"abc"), VtmPacket(1, 3, 2, 0, b"def")])

    packets = list(
        vtm_media_packet_source(stream).iter_media_packets(limits=CaptureLimits(max_bytes=5))
    )

    assert [packet.body for packet in packets] == [b"abc"]


def test_vtm_adapter_applies_duration_from_iteration_start() -> None:
    """The cloud adapter requests and enforces a startup-inclusive deadline."""

    class DeadlineStream:
        duration_from_start: bool | None = None

        def iter_packets(
            self,
            *,
            max_packets: int | None = None,
            duration_seconds: float | None = None,
            duration_from_start: bool = False,
            monotonic: Callable[[], float] = time.monotonic,
        ) -> Iterator[VtmPacket]:
            del max_packets, duration_seconds, monotonic
            self.duration_from_start = duration_from_start
            yield VtmPacket(1, 3, 1, 0, BODY)

    stream = DeadlineStream()
    clock = iter((0.0, 2.0)).__next__

    packets = list(
        vtm_media_packet_source(stream).iter_media_packets(
            limits=CaptureLimits(duration_seconds=1.0),
            monotonic=clock,
        )
    )

    assert packets == []
    assert stream.duration_from_start is True


def test_legacy_stream_adapter_does_not_read_past_exact_byte_limit() -> None:
    """A filled byte budget terminates before requesting another live packet."""

    class ExactByteStream:
        def iter_packets(
            self,
            *,
            max_packets: int | None = None,
            duration_seconds: float | None = None,
            duration_from_start: bool = False,
            monotonic: Callable[[], float] = time.monotonic,
        ) -> Iterator[VtmPacket]:
            del max_packets, duration_seconds, duration_from_start, monotonic
            yield VtmPacket(1, 3, 1, 0, BODY)
            raise AssertionError("adapter advanced past the exact byte limit")

    packets = list(
        vtm_media_packet_source(ExactByteStream()).iter_media_packets(
            limits=CaptureLimits(max_bytes=3)
        )
    )

    assert [packet.body for packet in packets] == [BODY]


def test_iterable_source_does_not_read_past_packet_or_byte_limit() -> None:
    """Completed iterable limits return before a blocking second callback."""

    closed = 0

    def callback_packets() -> Iterator[HcNetSdkRealDataPacket]:
        nonlocal closed
        try:
            yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, BODY)
            raise AssertionError("adapter advanced past the completed limit")
        finally:
            closed += 1

    packet_limited = hcnetsdk_media_packet_source(callback_packets())
    byte_limited = hcnetsdk_media_packet_source(callback_packets())

    assert [
        packet.body
        for packet in packet_limited.iter_media_packets(limits=CaptureLimits(max_packets=1))
    ] == [BODY]
    assert [
        packet.body for packet in byte_limited.iter_media_packets(limits=CaptureLimits(max_bytes=3))
    ] == [BODY]
    assert closed == 2


def test_iterable_source_duration_bounds_a_blocking_next_callback() -> None:
    """A live iterable cannot block past the common duration limit."""

    release = Event()
    closed = Event()
    max_elapsed = 0.5

    def callback_packets() -> Iterator[HcNetSdkRealDataPacket]:
        try:
            yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, BODY)
            release.wait()
            yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, BODY)
        finally:
            closed.set()

    started_at = time.monotonic()
    packets = list(
        hcnetsdk_media_packet_source(
            callback_packets(),
            cancel=release.set,
        ).iter_media_packets(
            limits=CaptureLimits(duration_seconds=0.02)
        )
    )
    elapsed = time.monotonic() - started_at

    assert [packet.body for packet in packets] == [BODY]
    assert release.is_set()
    assert closed.is_set()
    assert elapsed < max_elapsed


def test_iterable_source_duration_requires_cancellation_callback() -> None:
    """A bounded capture cannot start a worker it has no way to interrupt."""

    def callback_packets() -> Iterator[HcNetSdkRealDataPacket]:
        raise AssertionError("iterator must not be started without cancellation")
        yield

    source = hcnetsdk_media_packet_source(callback_packets())

    with pytest.raises(
        PyEzvizError,
        match="require a cancellation callback",
    ):
        list(
            source.iter_media_packets(
                limits=CaptureLimits(duration_seconds=0.02)
            )
        )


def test_iterable_source_rejects_unbounded_reuse_during_slow_cancellation() -> None:
    """An unbounded retry cannot race a worker still executing next()."""

    release = Event()
    closed = Event()

    def callback_packets() -> Iterator[HcNetSdkRealDataPacket]:
        try:
            yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, BODY)
            release.wait()
            yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, BODY)
        finally:
            closed.set()

    source = hcnetsdk_media_packet_source(callback_packets(), cancel=lambda: None)

    assert [
        packet.body
        for packet in source.iter_media_packets(
            limits=CaptureLimits(duration_seconds=0.02)
        )
    ] == [BODY]
    producer = source._producer_state.producer  # noqa: SLF001
    assert producer is not None
    assert producer.alive

    with pytest.raises(PyEzvizError, match="still cancelling"):
        list(source.iter_media_packets(limits=CaptureLimits(max_packets=1)))

    release.set()
    assert closed.wait(timeout=1.0)
    assert not producer.alive


def test_ecdh_adapter_applies_duration_from_iteration_start() -> None:
    stream = object.__new__(EzvizLocalSdkEcdhMediaStream)

    assert local_ecdh_media_packet_source(stream).duration_from_start is True


def test_iterable_source_checks_duration_before_filtering() -> None:
    """Rejected callbacks cannot extend a duration-bounded capture."""

    def callback_packets() -> Iterator[HcNetSdkRealDataPacket]:
        yield HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"header")
        raise AssertionError("adapter advanced after the duration expired")

    clock = iter((0.0, 2.0)).__next__
    source = hcnetsdk_media_packet_source(callback_packets(), cancel=lambda: None)

    packets = list(
        source.iter_media_packets(
            limits=CaptureLimits(duration_seconds=1.0),
            monotonic=clock,
        )
    )

    assert packets == []


def test_hcnetsdk_source_filters_non_media_and_applies_limits() -> None:
    """Callback control packets do not leak into the common media contract."""

    source = hcnetsdk_media_packet_source(
        [
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"header"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"abc"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"def"),
        ]
    )

    packets = list(source.iter_media_packets(limits=CaptureLimits(max_packets=1)))

    assert isinstance(source, MediaPacketSource)
    assert [packet.body for packet in packets] == [b"abc"]
