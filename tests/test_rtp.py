"""Tests for the shared RTP parser, router, and video depacketizer."""

from __future__ import annotations

from Crypto.Cipher import AES
import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.rtp import (
    RtpAacStream,
    RtpVideoCodec,
    RtpVideoDepacketizer,
    decrypt_idmx_aac_packets,
    detect_rtp_video_codec,
    parse_rtp_packet,
    rtp_media_kind,
    rtp_packets_to_annexb,
)

H264_WRAPPED_NAL = b"\x00\x00\x00\x01\x65hello-world"
HEVC_EZVIZ_WRAPPED_NAL = b"\x00\x00\x00\x01\x26\x01startmiddleend"


def _rtp(
    payload: bytes,
    *,
    sequence: int,
    timestamp: int = 9000,
    payload_type: int = 96,
    marker: bool = False,
    ssrc: int = 1,
    extension_profile: int | None = None,
    extension_data: bytes = b"",
) -> bytes:
    extension = b""
    first_byte = 0x80
    if extension_profile is not None:
        if len(extension_data) % 4:
            raise ValueError("RTP extension data must be 32-bit aligned")
        first_byte |= 0x10
        extension = (
            extension_profile.to_bytes(2, "big")
            + (len(extension_data) // 4).to_bytes(2, "big")
            + extension_data
        )
    return (
        bytes((first_byte,))
        + bytes([payload_type | (0x80 if marker else 0)])
        + sequence.to_bytes(2, "big")
        + timestamp.to_bytes(4, "big")
        + ssrc.to_bytes(4, "big")
        + extension
        + payload
    )


def test_decrypt_idmx_aac_packets_uses_native_descriptor() -> None:
    key = b"0123456789abcdef"
    sample_rate = 16_000
    descriptor = bytes(
        (
            0x43,
            10,
            0,
            1,
            2,
            sample_rate >> 14,
            (sample_rate >> 6) & 0xFF,
            ((sample_rate & 0x3F) << 2) | 3,
            0,
            0,
            3,
            0xFF,
        )
    )
    plain = b"0123456789abcdef" + b"tail"
    encrypted = AES.new(  # codeql[py/weak-cryptographic-algorithm]
        key,
        AES.MODE_ECB,
    ).encrypt(plain[:16]) + plain[16:]
    audio_extension = b"\x80\x06\x00\x01\x21\x21\x02\x01"
    packets = [
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=1,
                payload_type=112,
                ssrc=3,
                extension_profile=1,
                extension_data=descriptor,
            )
        ),
        parse_rtp_packet(
            _rtp(
                b"\x00\x10" + (len(encrypted) << 3).to_bytes(2, "big") + encrypted,
                sequence=2,
                timestamp=0,
                payload_type=104,
                ssrc=2,
                extension_profile=0x4000,
                extension_data=audio_extension,
            )
        ),
    ]

    audio = decrypt_idmx_aac_packets(packets, key)

    assert audio == RtpAacStream(
        adts=b"\xff\xf1`@\x03\x7f\xfc" + plain,
        sample_rate=sample_rate,
        channels=1,
        frame_count=1,
    )


def test_decrypt_idmx_aac_packets_requires_native_descriptor() -> None:
    audio_extension = b"\x80\x06\x00\x01\x21\x21\x02\x01"
    packet = parse_rtp_packet(
        _rtp(
            b"\x00\x10\x00\x08x",
            sequence=1,
            timestamp=0,
            payload_type=104,
            ssrc=2,
            extension_profile=0x4000,
            extension_data=audio_extension,
        )
    )

    assert decrypt_idmx_aac_packets([packet], b"0123456789abcdef") is None


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


def test_sequence_collision_invalidates_active_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("h264")
    packets = [
        parse_rtp_packet(_rtp(b"\x7c\x85start", sequence=1)),
        parse_rtp_packet(_rtp(b"\x7c\x05middle", sequence=2)),
        parse_rtp_packet(_rtp(b"\x7c\x05altered", sequence=2)),
        parse_rtp_packet(_rtp(b"\x7c\x45end", sequence=3)),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.sequence_conflicts == 1
    assert depacketizer.stats.discarded_fragments >= 2


def test_marker_only_sequence_collision_invalidates_hevc_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("hevc")
    packets = [
        parse_rtp_packet(_rtp(b"\x62\x01\x93start", sequence=1)),
        parse_rtp_packet(_rtp(b"\x62\x01\x26middle", sequence=2)),
        parse_rtp_packet(
            _rtp(b"\x62\x01\x26middle", sequence=2, marker=True)
        ),
        parse_rtp_packet(_rtp(b"\x62\x01\x66end", sequence=3, marker=True)),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.sequence_conflicts == 1
    assert depacketizer.stats.discarded_fragments >= 2


def test_rtp_packets_to_annexb_can_accept_ezviz_headerless_hevc_fu() -> None:
    packets = [
        parse_rtp_packet(_rtp(b"\x62\x01\x93start", sequence=1)),
        parse_rtp_packet(_rtp(b"\x62\x01\x26middle", sequence=2)),
        parse_rtp_packet(_rtp(b"\x62\x01\x66end", sequence=3, marker=True)),
    ]

    assert rtp_packets_to_annexb(
        packets,
        codec="hevc",
        allow_ezviz_headerless_hevc_fu=True,
    ) == HEVC_EZVIZ_WRAPPED_NAL


def test_h264_fu_type_change_invalidates_active_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("h264")
    packets = [
        parse_rtp_packet(_rtp(b"\x7c\x85start-type-5", sequence=1)),
        parse_rtp_packet(_rtp(b"\x7c\x01middle-type-1", sequence=2)),
        parse_rtp_packet(_rtp(b"\x7c\x45end-type-5", sequence=3)),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.discarded_fragments >= 2


def test_h264_fu_indicator_change_invalidates_active_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("h264")
    packets = [
        parse_rtp_packet(_rtp(b"\x7c\x85start-nri-3", sequence=1)),
        parse_rtp_packet(_rtp(b"\x1c\x05middle-nri-0", sequence=2)),
        parse_rtp_packet(_rtp(b"\x7c\x45end-nri-3", sequence=3)),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.discarded_fragments >= 2


def test_hevc_fu_type_change_invalidates_active_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("hevc")
    packets = [
        parse_rtp_packet(_rtp(b"\x62\x01\x93start-type-19", sequence=1)),
        parse_rtp_packet(_rtp(b"\x62\x01\x01middle-type-1", sequence=2)),
        parse_rtp_packet(
            _rtp(b"\x62\x01\x53end-type-19", sequence=3, marker=True)
        ),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.discarded_fragments >= 2


def test_hevc_fu_payload_header_change_invalidates_active_fragment() -> None:
    depacketizer = RtpVideoDepacketizer("hevc")
    packets = [
        parse_rtp_packet(_rtp(b"\x62\x01\x93start-tid-1", sequence=1)),
        parse_rtp_packet(_rtp(b"\x62\x02\x13middle-tid-2", sequence=2)),
        parse_rtp_packet(
            _rtp(b"\x62\x01\x53end-tid-1", sequence=3, marker=True)
        ),
    ]

    assert [nal for packet in packets for nal in depacketizer.push(packet)] == []
    assert depacketizer.stats.discarded_fragments >= 2


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


def test_codec_detection_defers_ambiguous_hevc_sps() -> None:
    packets = [
        parse_rtp_packet(_rtp(b"\x42\x01sps", sequence=1)),
        parse_rtp_packet(_rtp(b"\x40\x01vps", sequence=2)),
    ]

    assert detect_rtp_video_codec(packets) == "hevc"


def test_codec_detection_rejects_only_ambiguous_packets() -> None:
    packet = parse_rtp_packet(_rtp(b"\x42\x01ambiguous", sequence=1))

    with pytest.raises(PyEzvizError, match="Could not detect RTP video codec"):
        detect_rtp_video_codec([packet])


def test_codec_detection_can_defer_fallback_until_more_packets_arrive() -> None:
    aud = parse_rtp_packet(_rtp(b"\x09\xf0", sequence=1))
    sps = parse_rtp_packet(_rtp(b"\x67h264-sps", sequence=2))

    with pytest.raises(PyEzvizError, match="Could not detect RTP video codec"):
        detect_rtp_video_codec([aud], allow_fallback=False)

    assert detect_rtp_video_codec([aud, sps], allow_fallback=False) == "h264"


@pytest.mark.parametrize(
    ("codec", "start", "truncated", "end"),
    [
        ("h264", b"\x7c\x85start", b"\x7c", b"\x7c\x45end"),
        ("h264", b"\x7c\x85start", b"\x00corrupt", b"\x7c\x45end"),
        ("hevc", b"\x62\x01\x93start", b"\x62", b"\x62\x01\x53end"),
        ("hevc", b"\x62\x01\x93start", b"\x00", b"\x62\x01\x53end"),
    ],
)
def test_truncated_fu_discards_active_fragment(
    codec: RtpVideoCodec,
    start: bytes,
    truncated: bytes,
    end: bytes,
) -> None:
    depacketizer = RtpVideoDepacketizer(codec)

    assert depacketizer.push(parse_rtp_packet(_rtp(start, sequence=1))) == ()
    assert depacketizer.push(parse_rtp_packet(_rtp(truncated, sequence=2))) == ()
    assert depacketizer.push(parse_rtp_packet(_rtp(end, sequence=3))) == ()
    assert depacketizer.stats.discarded_fragments >= 2
