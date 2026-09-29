"""Golden-fixture and cross-source stream conformance tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from hashlib import sha256
from pathlib import Path
import time
from typing import Any

import pytest

from pyezvizapi._local_stream import _idmx_local_packets_to_annexb_with_codec
from pyezvizapi.local_stream_ecdh import (
    EzvizLocalSdkEcdhStreamPacket,
    local_ecdh_media_packet_source,
    local_ecdh_packet_to_media_packet,
)
from pyezvizapi.local_stream_media import summarize_idmx_h264_local_packets
from pyezvizapi.local_stream_transport import (
    EzvizLocalStreamPacket,
    local_media_packet_source,
    local_stream_packet_to_media_packet,
)
from pyezvizapi.media import CaptureLimits, MediaPacket, MediaPacketSource
from pyezvizapi.stream_media import (
    detect_hikvision_ps_video_nalu_header_size,
    detect_transport,
    mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length,
)
from pyezvizapi.stream_transport import (
    StreamTransport,
    VtmChannel,
    VtmPacket,
    vtm_media_packet_source,
    vtm_packet_to_media_packet,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "stream"
MPEG_PS_SHA256 = "acd07afebd3b1cdc2a269489f747ca48bf3e37c95032a71937efe8702ae95dc9"
X80_IDMX_SHA256 = "997cdecebf9eb8366efb01833b79d8a2c19ff0a5f7d1743119a05167d457c036"
X80_EXPECTED_ANNEXB = (
    b"\x00\x00\x00\x01\x40\x01vps"
    b"\x00\x00\x00\x01\x42\x01sps"
    b"\x00\x00\x00\x01\x26\x01idr-frame"
)


def _hex_fixture(name: str) -> bytes:
    """Load a reviewable hexadecimal fixture while ignoring comments."""

    lines = (FIXTURE_ROOT / name).read_text(encoding="utf-8").splitlines()
    return bytes.fromhex(" ".join(line.partition("#")[0] for line in lines))


class _PacketStream:
    """Small legacy packet stream accepted by every compatibility adapter."""

    supports_startup_deadline_iter_packets = True

    def __init__(self, packets: list[Any]) -> None:
        self.packets = packets

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[Any]:
        del duration_seconds, duration_from_start, monotonic
        yield from self.packets[:max_packets]


def test_sanitized_mpeg_ps_golden_fixture() -> None:
    payload = _hex_fixture("mpeg_ps_h264.hex")

    assert len(payload) == 61
    assert sha256(payload).hexdigest() == MPEG_PS_SHA256
    assert detect_transport(payload) == StreamTransport.MPEG_PS
    assert mpeg_ps_complete_prefix_length(payload) == len(payload)
    assert mpeg_ps_decryptable_prefix_length(payload) == len(payload)
    assert (
        detect_hikvision_ps_video_nalu_header_size(
            payload,
            b"synthetic-fixture-key",
            default=None,
        )
        == 1
    )


def test_sanitized_x80_idmx_rtp_golden_fixture() -> None:
    payload = _hex_fixture("x80_idmx_hevc.hex")

    assert len(payload) == 69
    assert sha256(payload).hexdigest() == X80_IDMX_SHA256
    annexb, codec = _idmx_local_packets_to_annexb_with_codec([payload])
    assert codec == "hevc"
    assert annexb == X80_EXPECTED_ANNEXB
    summary = summarize_idmx_h264_local_packets([payload], max_frames=8)
    assert summary["packet_count"] == 1
    assert summary["frame_count"] == 3
    assert summary["looks_like_idmx"] is True
    assert summary["packet_shapes"]["length_prefixed_idmx"] == 1


@pytest.mark.parametrize(
    ("packet", "converter", "source", "channel", "encrypted"),
    [
        (
            VtmPacket(
                channel=VtmChannel.STREAM,
                length=61,
                sequence=7,
                message_code=0,
                body=_hex_fixture("mpeg_ps_h264.hex"),
            ),
            vtm_packet_to_media_packet,
            "cloud_vtm",
            VtmChannel.STREAM,
            False,
        ),
        (
            EzvizLocalStreamPacket(
                channel=2,
                length=61,
                body=_hex_fixture("mpeg_ps_h264.hex"),
                encrypted=True,
                prefix=b"synthetic",
            ),
            local_stream_packet_to_media_packet,
            "local_sdk",
            2,
            True,
        ),
        (
            EzvizLocalSdkEcdhStreamPacket(
                channel=3,
                body=_hex_fixture("mpeg_ps_h264.hex"),
            ),
            local_ecdh_packet_to_media_packet,
            "local_ecdh",
            3,
            False,
        ),
    ],
)
def test_packet_converters_share_the_media_packet_contract(
    packet: Any,
    converter: Callable[[Any], MediaPacket],
    source: str,
    channel: int,
    encrypted: bool,
) -> None:
    normalized = converter(packet)

    assert normalized.body == _hex_fixture("mpeg_ps_h264.hex")
    assert normalized.length == len(normalized.body)
    assert normalized.metadata.source == source
    assert normalized.metadata.channel == channel
    assert normalized.metadata.encrypted is encrypted


@pytest.mark.parametrize(
    ("packets", "adapter", "expected_source"),
    [
        (
            [
                VtmPacket(
                    channel=VtmChannel.STREAM,
                    length=61,
                    sequence=index,
                    message_code=0,
                    body=_hex_fixture("mpeg_ps_h264.hex"),
                )
                for index in range(2)
            ],
            vtm_media_packet_source,
            "cloud_vtm",
        ),
        (
            [
                EzvizLocalStreamPacket(
                    channel=1,
                    length=61,
                    body=_hex_fixture("mpeg_ps_h264.hex"),
                )
                for _ in range(2)
            ],
            local_media_packet_source,
            "local_sdk",
        ),
        (
            [
                EzvizLocalSdkEcdhStreamPacket(
                    channel=1,
                    body=_hex_fixture("mpeg_ps_h264.hex"),
                )
                for _ in range(2)
            ],
            local_ecdh_media_packet_source,
            "local_ecdh",
        ),
    ],
)
def test_packet_sources_apply_shared_byte_limits_consistently(
    packets: list[Any],
    adapter: Callable[[Any], MediaPacketSource],
    expected_source: str,
) -> None:
    normalized = list(
        adapter(_PacketStream(packets)).iter_media_packets(
            limits=CaptureLimits(max_packets=2, max_bytes=61),
        )
    )

    assert len(normalized) == 1
    assert normalized[0].body == _hex_fixture("mpeg_ps_h264.hex")
    assert normalized[0].metadata.source == expected_source
