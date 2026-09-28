"""Tests for the shared RTP parser, router, and video depacketizer."""

from __future__ import annotations

from pyezvizapi.rtp import (
    RtpVideoDepacketizer,
    detect_rtp_video_codec,
    parse_rtp_packet,
    rtp_media_kind,
    rtp_packets_to_annexb,
)

H264_WRAPPED_NAL = b"\x00\x00\x00\x01\x65hello-world"


def _rtp(
    payload: bytes,
    *,
    sequence: int,
    timestamp: int = 9000,
    payload_type: int = 96,
    marker: bool = False,
    ssrc: int = 1,
) -> bytes:
    return (
        b"\x80"
        + bytes([payload_type | (0x80 if marker else 0)])
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + ssrc.to_bytes(4, "big")
        + payload
    )


def test_parse_and_route_mixed_ezviz_rtp_packets() -> None:
    packets = [
        parse_rtp_packet(_rtp(b"video", sequence=1, payload_type=96)),
        parse_rtp_packet(_rtp(b"audio", sequence=2, payload_type=104, ssrc=2)),
        parse_rtp_packet(_rtp(b"metadata", sequence=3, payload_type=112, ssrc=3)),
    ]

    assert [rtp_media_kind(packet) for packet in packets] == [
        "video",
        "audio",
        "metadata",
    ]


def test_h264_depacketizer_rejects_loss_reorder_and_duplicates() -> None:
    depacketizer = RtpVideoDepacketizer("h264")
    start_payload = b"\x7c\x85start"
    packets = [
        parse_rtp_packet(_rtp(start_payload, sequence=65535)),
        parse_rtp_packet(_rtp(start_payload, sequence=65535)),
        parse_rtp_packet(_rtp(b"\x7c\x05lost", sequence=1)),
        parse_rtp_packet(_rtp(b"\x7c\x45late-end", sequence=0)),
        parse_rtp_packet(_rtp(b"\x65idr", sequence=2)),
    ]

    nals = [nal for packet in packets for nal in depacketizer.push(packet)]

    assert nals == [b"\x65idr"]
    assert depacketizer.stats.duplicates == 1
    assert depacketizer.stats.sequence_gaps == 1
    assert depacketizer.stats.reordered == 1
    assert depacketizer.stats.discarded_fragments >= 1


def test_h264_depacketizer_accepts_sequence_wrap() -> None:
    packets = [
        parse_rtp_packet(_rtp(b"\x7c\x85hello", sequence=65535)),
        parse_rtp_packet(_rtp(b"\x7c\x45-world", sequence=0, marker=True)),
    ]

    assert rtp_packets_to_annexb(packets, codec="h264") == H264_WRAPPED_NAL


def test_timestamp_change_discards_incomplete_fu() -> None:
    depacketizer = RtpVideoDepacketizer("hevc")
    start = parse_rtp_packet(_rtp(b"\x62\x01\x93start", sequence=1, timestamp=10))
    end = parse_rtp_packet(_rtp(b"\x62\x01\x53end", sequence=2, timestamp=20))

    assert depacketizer.push(start) == ()
    assert depacketizer.push(end) == ()
    assert depacketizer.stats.timestamp_changes == 1
    assert depacketizer.stats.discarded_fragments >= 1


def test_codec_detection_ignores_audio_and_metadata() -> None:
    packets = [
        parse_rtp_packet(_rtp(b"\x11audio", sequence=1, payload_type=104)),
        parse_rtp_packet(_rtp(b"\x43metadata", sequence=2, payload_type=112)),
        parse_rtp_packet(_rtp(b"\x62\x01\x93hevc", sequence=3)),
    ]

    assert detect_rtp_video_codec(packets) == "hevc"
