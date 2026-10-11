"""Tests for the shared RTP parser, router, and video depacketizer."""

from __future__ import annotations

import pytest

from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.rtp import (
    KNOWN_AUDIO_PAYLOAD_TYPES,
    KNOWN_VIDEO_PAYLOAD_TYPES,
    RtpAacStream,
    RtpPacket,
    RtpRouteProfile,
    RtpStreamDescriptor,
    RtpVideoCodec,
    RtpVideoDepacketizer,
    decrypt_idmx_aac_packets,
    detect_rtp_video_codec,
    idmx_rtp_stream_descriptors,
    idmx_video_frame_rate,
    parse_rtp_packet,
    rtp_codec_payload_types,
    rtp_media_kind,
    rtp_nal_units_have_vcl,
    rtp_packet_has_valid_idmx_aac_frame,
    rtp_packets_to_annexb,
    rtp_packets_to_nal_units,
    rtp_payload_video_codec,
)

H264_WRAPPED_NAL = b"\x00\x00\x00\x01\x65hello-world"
H264_DATA_PARTITION_NAL = b"\x00\x00\x00\x01\x62\x01h264-data-partition"
H264_DESCRIPTOR_ROUTED_NAL = b"\x00\x00\x00\x01\x65right"
H264_CUSTOM_ROUTED_NAL = b"\x00\x00\x00\x01\x67h264-sps"
HEVC_EZVIZ_WRAPPED_NAL = b"\x00\x00\x00\x01\x26\x01startmiddleend"
HEVC_DESCRIPTOR_ROUTED_NAL = b"\x00\x00\x00\x01\x26\x01hevc"


def test_parse_rtp_reports_version_failure_with_stable_reason() -> None:
    with pytest.raises(EzvizUnsupportedMediaError) as error:
        parse_rtp_packet(b"\x40" + b"\x00" * 11)
    assert error.value.source == "rtp"
    assert error.value.reason == "invalid_rtp_version"


@pytest.mark.parametrize("nal_type", [1, 2, 3, 4, 5, 19, 20, 21])
def test_h264_vcl_detection_accepts_all_slice_types(nal_type: int) -> None:
    assert rtp_nal_units_have_vcl((bytes((nal_type,)) + b"slice",), codec="h264")


def test_rtp_vcl_detection_rejects_only_parameter_sets() -> None:
    assert not rtp_nal_units_have_vcl((b"\x67sps", b"\x68pps"), codec="h264")
    assert not rtp_nal_units_have_vcl((b"\x40\x01vps",), codec="hevc")


@pytest.mark.parametrize(
    ("codec", "malformed"),
    [("h264", b"\x81\x80bad"), ("hevc", b"\x82\x01\x80bad")],
)
def test_bounded_rtp_rejects_forbidden_bit_as_media(
    codec: RtpVideoCodec, malformed: bytes
) -> None:
    packet = parse_rtp_packet(_rtp(malformed, sequence=1, marker=True))
    assert not rtp_nal_units_have_vcl((malformed,), codec=codec)
    assert rtp_packets_to_nal_units(
        (packet,), codec=codec, completed_access_units_only=True
    ) == ()


@pytest.mark.parametrize(
    "nal",
    [
        b"\x75\x80\x00\x80slice",  # 3D-AVC: two-byte extension.
        b"\x75\x00\x00\x00\x80slice",  # MVC/SVC: three-byte extension.
    ],
)
def test_bounded_rtp_accepts_type_21_first_slice(nal: bytes) -> None:
    packet = parse_rtp_packet(_rtp(nal, sequence=1, marker=True))
    assert rtp_packets_to_nal_units(
        (packet,), codec="h264", completed_access_units_only=True
    ) == (nal,)


def test_bounded_rtp_accepts_nonzero_hevc_layer_id() -> None:
    nal = b"\x02\x09\x80slice"  # VCL type 1, layer 1, temporal ID 1.
    packet = parse_rtp_packet(_rtp(nal, sequence=1, marker=True))
    assert rtp_nal_units_have_vcl((nal,), codec="hevc")
    assert rtp_packets_to_nal_units(
        (packet,), codec="hevc", completed_access_units_only=True
    ) == (nal,)


def test_bounded_rtp_damages_picture_after_forbidden_bit_nal() -> None:
    first = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1))
    malformed = parse_rtp_packet(_rtp(b"\x81\x80bad", sequence=2, marker=True))
    healthy = parse_rtp_packet(
        _rtp(b"\x61\x80healthy", sequence=3, timestamp=12000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (first, malformed, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80healthy",)


def test_bounded_rtp_damages_picture_after_codec_mismatched_video_packet() -> None:
    first = parse_rtp_packet(_rtp(b"\x61\xe0first", sequence=1))
    mismatched = parse_rtp_packet(_rtp(b"\x40\x01vps", sequence=2))
    healthy = parse_rtp_packet(
        _rtp(b"\x61\xe0healthy", sequence=3, timestamp=12000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (first, mismatched, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\xe0healthy",)


@pytest.mark.parametrize(
    ("codec", "header_only", "healthy_nal"),
    [
        ("h264", b"\x61", b"\x61\x80healthy"),
        ("hevc", b"\x02\x01", b"\x02\x01\x80healthy"),
        ("h264", b"\x75\x80\x00", b"\x75\x80\x00\x80healthy"),
    ],
)
def test_bounded_rtp_rejects_header_only_vcl(
    codec: RtpVideoCodec, header_only: bytes, healthy_nal: bytes
) -> None:
    first = parse_rtp_packet(_rtp(healthy_nal, sequence=1, marker=True))
    truncated = parse_rtp_packet(
        _rtp(header_only, sequence=2, timestamp=12000, marker=True)
    )
    assert not rtp_nal_units_have_vcl((header_only,), codec=codec)
    assert rtp_packets_to_nal_units(
        (first, truncated), codec=codec, completed_access_units_only=True
    ) == (healthy_nal,)


@pytest.mark.parametrize(
    ("codec", "header_only", "healthy_nal"),
    [
        ("h264", b"\x61", b"\x61\x80healthy"),
        ("hevc", b"\x02\x01", b"\x02\x01\x80healthy"),
    ],
)
def test_bounded_rtp_header_only_vcl_damages_prior_slice(
    codec: RtpVideoCodec, header_only: bytes, healthy_nal: bytes
) -> None:
    first = parse_rtp_packet(_rtp(healthy_nal, sequence=1))
    truncated = parse_rtp_packet(_rtp(header_only, sequence=2, marker=True))
    next_picture = parse_rtp_packet(
        _rtp(healthy_nal, sequence=3, timestamp=12000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (first, truncated, next_picture),
        codec=codec,
        completed_access_units_only=True,
    ) == (healthy_nal,)


@pytest.mark.parametrize("truncated", [b"\x61\x00", b"\x61\x00\x80"])
def test_bounded_rtp_rejects_incomplete_first_mb_code(truncated: bytes) -> None:
    first = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1, marker=True))
    malformed = parse_rtp_packet(
        _rtp(truncated, sequence=2, timestamp=12000, marker=True)
    )
    assert not rtp_nal_units_have_vcl((truncated,), codec="h264")
    assert rtp_packets_to_nal_units(
        (first, malformed), codec="h264", completed_access_units_only=True
    ) == (b"\x61\x80first",)


@pytest.mark.parametrize("truncated", [b"\x61\x80", b"\x61\xc0"])
def test_bounded_rtp_rejects_incomplete_h264_slice_fields(truncated: bytes) -> None:
    healthy = b"\x61\xe0healthy"
    packets = (
        parse_rtp_packet(_rtp(healthy, sequence=1, marker=True)),
        parse_rtp_packet(
            _rtp(truncated, sequence=2, timestamp=12000, marker=True)
        ),
    )
    assert not rtp_nal_units_have_vcl((truncated,), codec="h264")
    assert rtp_packets_to_nal_units(
        packets, codec="h264", completed_access_units_only=True
    ) == (healthy,)


@pytest.mark.parametrize("truncated", [b"\x02\x01\x80", b"\x02\x01\x80\x00"])
def test_bounded_rtp_rejects_incomplete_hevc_pps_code(truncated: bytes) -> None:
    healthy = b"\x02\x01\xc0healthy"
    packets = (
        parse_rtp_packet(_rtp(healthy, sequence=1, marker=True)),
        parse_rtp_packet(
            _rtp(truncated, sequence=2, timestamp=12000, marker=True)
        ),
    )
    assert not rtp_nal_units_have_vcl((truncated,), codec="hevc")
    assert rtp_packets_to_nal_units(
        packets, codec="hevc", completed_access_units_only=True
    ) == (healthy,)


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_encrypted_header_fu_reassembles_before_transform(
    codec: RtpVideoCodec,
) -> None:
    if codec == "h264":
        encrypted_nal = b"\x61" + bytes(range(1, 32))
        clear_nal = b"\x61\x80" + b"x" * 30
        fu_prefix = b"\x7c"
        fu_type = b"\x01"
        body = encrypted_nal[1:]
    else:
        encrypted_nal = b"\x02\x01" + bytes(range(2, 32))
        clear_nal = b"\x02\x01\xc0" + b"x" * 29
        fu_prefix = b"\x62\x01"
        fu_type = b"\x01"
        body = encrypted_nal[2:]
    packets = (
        parse_rtp_packet(_rtp(fu_prefix + bytes((0x80 | fu_type[0],)) + body[:7], sequence=1)),
        parse_rtp_packet(_rtp(fu_prefix + bytes((0x40 | fu_type[0],)) + body[7:], sequence=2, marker=True)),
    )
    seen: list[bytes] = []

    def decrypt(nal: bytes) -> bytes:
        seen.append(nal)
        return clear_nal if nal == encrypted_nal else b"invalid"

    assert rtp_packets_to_nal_units(
        packets,
        codec=codec,
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == (clear_nal,)
    assert seen[-1] == encrypted_nal


@pytest.mark.parametrize("continuation", ["pseudo-header", "headerless"])
def test_encrypted_header_hevc_ezviz_fu_reassembles_before_transform(
    continuation: str,
) -> None:
    encrypted_nal = b"\x26\x01" + bytes(range(2, 32))
    clear_nal = b"\x26\x01\xa0" + b"x" * 29
    body = encrypted_nal[2:]
    start = parse_rtp_packet(_rtp(b"\x62\x01\x93" + body[:7], sequence=1))
    end_payload = (
        b"\x62\x01\x66" + body[7:]
        if continuation == "pseudo-header"
        else b"\x62\x01" + body[7:]
    )
    end = parse_rtp_packet(_rtp(end_payload, sequence=2, marker=True))
    seen: list[bytes] = []

    def decrypt(nal: bytes) -> bytes:
        seen.append(nal)
        return clear_nal if nal == encrypted_nal else b"invalid"

    assert rtp_packets_to_nal_units(
        (start, end),
        codec="hevc",
        allow_ezviz_headerless_hevc_fu=True,
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == (clear_nal,)
    assert seen[-1] == encrypted_nal
    assert detect_rtp_video_codec(
        (start, end),
        video_payload_transform=decrypt,
        allow_ezviz_headerless_hevc_fu=True,
    ) == "hevc"


@pytest.mark.parametrize(
    ("codec", "fu_start"),
    [("h264", b"\x7c\x81"), ("hevc", b"\x62\x01\x93")],
)
def test_encrypted_header_incomplete_fu_identifies_codec_from_clear_framing(
    codec: RtpVideoCodec, fu_start: bytes
) -> None:
    packet = parse_rtp_packet(_rtp(fu_start + b"x" * 32, sequence=1))
    assert detect_rtp_video_codec(
        (packet,),
        video_payload_transform=lambda _payload: b"\x80invalid",
        allow_ezviz_headerless_hevc_fu=True,
    ) == codec


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_encrypted_single_nals_that_look_like_fu_chain_stay_single(
    codec: RtpVideoCodec,
) -> None:
    if codec == "h264":
        start_payload = b"\x7c\x81" + b"a" * 16
        end_payload = b"\x7c\x41" + b"b" * 16
        clear_nals = (b"\x61\xe0first", b"\x61\x70second")
    else:
        start_payload = b"\x62\x01\x93" + b"a" * 16
        end_payload = b"\x62\x01\x53" + b"b" * 16
        clear_nals = (b"\x26\x01\xa0first", b"\x02\x01\x70second")
    packets = (
        parse_rtp_packet(_rtp(start_payload, sequence=1)),
        parse_rtp_packet(_rtp(end_payload, sequence=2, marker=True)),
    )

    def decrypt(payload: bytes) -> bytes:
        if payload == start_payload:
            return clear_nals[0]
        if payload == end_payload:
            return clear_nals[1]
        return b"\x80invalid"

    assert rtp_packets_to_nal_units(
        packets,
        codec=codec,
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == clear_nals


def test_encrypted_fu_and_single_nal_ambiguity_is_explicit() -> None:
    packets = (
        parse_rtp_packet(_rtp(b"\x7c\x81" + b"a" * 16, sequence=1)),
        parse_rtp_packet(
            _rtp(b"\x7c\x41" + b"b" * 16, sequence=2, marker=True)
        ),
    )
    with pytest.raises(EzvizUnsupportedMediaError) as error:
        rtp_packets_to_nal_units(
            packets,
            codec="h264",
            completed_access_units_only=True,
            packet_nal_transform=lambda _payload: b"\x61\xe0slice",
        )
    assert error.value.reason == "ambiguous_encrypted_fu"


@pytest.mark.parametrize("codec", ["h264", "hevc"])
@pytest.mark.parametrize("duplicate_start", [False, True])
@pytest.mark.parametrize("nonvideo_payload_type", [112, 104])
def test_encrypted_header_fu_keeps_same_ssrc_nonvideo_continuity(
    codec: RtpVideoCodec,
    duplicate_start: bool,
    nonvideo_payload_type: int,
) -> None:
    if codec == "h264":
        encrypted_nal = b"\x61" + bytes(range(1, 32))
        clear_nal = b"\x61\x80" + b"x" * 30
        fu_prefix = b"\x7c"
        body = encrypted_nal[1:]
    else:
        encrypted_nal = b"\x02\x01" + bytes(range(2, 32))
        clear_nal = b"\x02\x01\xc0" + b"x" * 29
        fu_prefix = b"\x62\x01"
        body = encrypted_nal[2:]
    start = parse_rtp_packet(_rtp(fu_prefix + b"\x81" + body[:7], sequence=1))
    packets = (start,) + ((start,) if duplicate_start else ()) + (
        parse_rtp_packet(
            _rtp(b"other media", sequence=2, payload_type=nonvideo_payload_type)
        ),
        parse_rtp_packet(
            _rtp(fu_prefix + b"\x41" + body[7:], sequence=3, marker=True)
        ),
    )
    seen: list[bytes] = []

    def decrypt(nal: bytes) -> bytes:
        seen.append(nal)
        return clear_nal if nal == encrypted_nal else b"invalid"

    assert rtp_packets_to_nal_units(
        packets,
        codec=codec,
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == (clear_nal,)
    assert seen[-1] == encrypted_nal


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_encrypted_header_aggregation_decrypts_only_extracted_nals(
    codec: RtpVideoCodec,
) -> None:
    if codec == "h264":
        encrypted_nals = (b"\x67" + b"a" * 15, b"\x61" + b"b" * 15)
        clear_nals = (b"\x67" + b"s" * 15, b"\x61\x80" + b"v" * 14)
        wrapper = b"\x78"
    else:
        encrypted_nals = (b"\x40\x01" + b"a" * 14, b"\x02\x01" + b"b" * 13)
        clear_nals = (b"\x40\x01" + b"s" * 14, b"\x02\x01\xc0" + b"v" * 13)
        wrapper = b"\x60\x01"
    payload = wrapper + b"".join(
        len(nal).to_bytes(2, "big") + nal for nal in encrypted_nals
    )
    packet = parse_rtp_packet(_rtp(payload, sequence=1, marker=True))
    seen: list[bytes] = []

    def decrypt(nal: bytes) -> bytes:
        seen.append(nal)
        return (
            clear_nals[encrypted_nals.index(nal)]
            if nal in encrypted_nals
            else b"\x09metadata" if codec == "h264" else b"\x40\x01metadata"
        )

    assert rtp_packets_to_nal_units(
        (packet,),
        codec=codec,
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == clear_nals
    assert seen[0] == payload
    assert seen[-len(encrypted_nals) :] == list(encrypted_nals)


def test_encrypted_single_nal_that_looks_like_aggregation_stays_single() -> None:
    ciphertext = b"\x78\x00\x10" + b"x" * 16
    clear_nal = b"\x61\xe0clear"
    packet = parse_rtp_packet(_rtp(ciphertext, sequence=1, marker=True))
    seen: list[bytes] = []

    def decrypt(nal: bytes) -> bytes:
        seen.append(nal)
        return clear_nal if nal == ciphertext else b"\x09metadata"

    assert rtp_packets_to_nal_units(
        (packet,),
        codec="h264",
        completed_access_units_only=True,
        packet_nal_transform=decrypt,
    ) == (clear_nal,)
    assert seen[0] == ciphertext


def test_encrypted_aggregation_ambiguity_is_explicit() -> None:
    ciphertext = b"\x78\x00\x10" + b"x" * 16
    packet = parse_rtp_packet(_rtp(ciphertext, sequence=1, marker=True))

    with pytest.raises(EzvizUnsupportedMediaError) as error:
        rtp_packets_to_nal_units(
            (packet,),
            codec="h264",
            completed_access_units_only=True,
            packet_nal_transform=lambda _nal: b"\x61\xe0slice",
        )
    assert error.value.reason == "ambiguous_encrypted_aggregation"


@pytest.mark.parametrize(
    ("codec", "bad", "good", "wrapper"),
    [
        ("h264", b"\x81\x80bad", b"\x61\x80good", b"\x78"),
        ("hevc", b"\x82\x01\xc0bad", b"\x02\x01\xc0good", b"\x60\x01"),
    ],
)
def test_bounded_aggregation_does_not_hide_bad_nal_before_first_slice(
    codec: RtpVideoCodec, bad: bytes, good: bytes, wrapper: bytes
) -> None:
    payload = wrapper + b"".join(
        len(nal).to_bytes(2, "big") + nal for nal in (bad, good)
    )
    packet = parse_rtp_packet(_rtp(payload, sequence=1, marker=True))
    assert rtp_packets_to_nal_units(
        (packet,), codec=codec, completed_access_units_only=True
    ) == ()


def test_bounded_rtp_omits_complete_slice_from_unfinished_picture() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1))
    second_slice_start = parse_rtp_packet(_rtp(b"\x7c\x81\x00start", sequence=2))
    second_slice_end = parse_rtp_packet(
        _rtp(b"\x7c\x41end", sequence=3, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first_slice, second_slice_start),
        codec="h264",
        completed_access_units_only=True,
    ) == ()
    assert rtp_packets_to_nal_units(
        (first_slice, second_slice_start, second_slice_end),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80first", b"\x61\x00startend")


def test_bounded_rtp_accepts_previous_picture_at_timestamp_transition() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1, timestamp=9000))
    next_picture = parse_rtp_packet(_rtp(b"\x61next", sequence=2, timestamp=12000))

    assert rtp_packets_to_nal_units(
        (first_slice, next_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80first",)


def test_bounded_rtp_accepts_later_macroblock_zero_in_initial_picture() -> None:
    nonzero_first = parse_rtp_packet(_rtp(b"\x61\x40mb1", sequence=1))
    macroblock_zero = parse_rtp_packet(
        _rtp(b"\x61\x80mb0", sequence=2, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (nonzero_first,), codec="h264", completed_access_units_only=True
    ) == ()
    assert rtp_packets_to_nal_units(
        (nonzero_first, macroblock_zero),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x40mb1", b"\x61\x80mb0")


def test_bounded_rtp_does_not_close_picture_across_sequence_gap() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=1, timestamp=9000))
    # Sequence 2 was the missing final slice of the first picture.
    next_picture = parse_rtp_packet(
        _rtp(b"\x7c\x81start", sequence=3, timestamp=12000)
    )
    assert rtp_packets_to_nal_units(
        (first_slice, next_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == ()


def test_bounded_h264_does_not_clear_new_picture_gap_with_macroblock_zero() -> None:
    previous = parse_rtp_packet(
        _rtp(b"\x61\xe0previous", sequence=1, timestamp=9000, marker=True)
    )
    # Missing sequence 2 could be an earlier ASO/FMO slice of this picture.
    uncertain = parse_rtp_packet(
        _rtp(b"\x61\xe0mb0", sequence=3, timestamp=12000, marker=True)
    )
    healthy = parse_rtp_packet(
        _rtp(b"\x61\xe0healthy", sequence=4, timestamp=15000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (previous, uncertain, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\xe0previous", b"\x61\xe0healthy")


def test_bounded_rtp_rejects_sequence_conflict_before_timestamp_boundary() -> None:
    first = parse_rtp_packet(_rtp(b"\x61first", sequence=1, timestamp=9000))
    conflict = parse_rtp_packet(_rtp(b"\x61altered", sequence=1, timestamp=9000))
    next_picture = parse_rtp_packet(
        _rtp(b"\x61\x80next", sequence=2, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first, conflict, next_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80next",)


def test_bounded_rtp_keeps_picture_after_identical_duplicate() -> None:
    first = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1, timestamp=9000))
    next_picture = parse_rtp_packet(
        _rtp(b"\x61next", sequence=2, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first, first, next_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80first", b"\x61next")


@pytest.mark.parametrize(
    ("codec", "trailing_slice", "complete_slice"),
    [
        ("h264", b"\x61\x00tail", b"\x61\x80whole"),
        ("hevc", b"\x02\x01\x00tail", b"\x02\x01\x80whole"),
    ],
)
def test_bounded_rtp_rejects_initial_trailing_slice(
    codec: RtpVideoCodec, trailing_slice: bytes, complete_slice: bytes
) -> None:
    first = parse_rtp_packet(_rtp(trailing_slice, sequence=1, marker=True))
    next_picture = parse_rtp_packet(
        _rtp(complete_slice, sequence=2, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first,), codec=codec, completed_access_units_only=True
    ) == ()
    assert rtp_packets_to_nal_units(
        (first, next_picture), codec=codec, completed_access_units_only=True
    ) == (complete_slice,)


@pytest.mark.parametrize("nal_type", [2, 3, 4])
def test_bounded_rtp_rejects_unverifiable_h264_data_partitions(
    nal_type: int,
) -> None:
    # Partition B/C can start with a zero slice_id; its first bit is not
    # first_mb_in_slice and cannot prove that partition A was captured.
    payload = bytes((0x60 | nal_type, 0x80)) + b"partition"
    packet = parse_rtp_packet(_rtp(payload, sequence=1, marker=True))

    with pytest.raises(EzvizUnsupportedMediaError) as error:
        rtp_packets_to_nal_units(
            (packet,), codec="h264", completed_access_units_only=True
        )
    assert error.value.source == "rtp"
    assert error.value.reason == "unsupported_h264_data_partition"
    assert rtp_packets_to_nal_units((packet,), codec="h264") == (payload,)


@pytest.mark.parametrize(
    ("codec", "aggregation", "slice_nal"),
    [
        ("h264", b"\x78", b"\x61slice"),
        ("hevc", b"\x60\x01", b"\x02\x01slice"),
    ],
)
def test_bounded_rtp_rejects_partial_marked_aggregation(
    codec: RtpVideoCodec, aggregation: bytes, slice_nal: bytes
) -> None:
    partial = aggregation + len(slice_nal).to_bytes(2, "big") + slice_nal + b"\x00\x08bad"
    packet = parse_rtp_packet(_rtp(partial, sequence=1, marker=True))

    assert rtp_packets_to_nal_units(
        (packet,), codec=codec, completed_access_units_only=True
    ) == ()
    assert RtpVideoDepacketizer(codec).push(packet) == ()


def test_bounded_rtp_does_not_close_marked_picture_after_sequence_gap() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=1))
    final_slice = parse_rtp_packet(_rtp(b"\x61last", sequence=3, marker=True))
    assert rtp_packets_to_nal_units(
        (first_slice, final_slice),
        codec="h264",
        completed_access_units_only=True,
    ) == ()


def test_bounded_rtp_discards_damaged_picture_before_later_healthy_one() -> None:
    config = parse_rtp_packet(_rtp(b"\x67sps", sequence=1, timestamp=9000))
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=2, timestamp=9000))
    damaged_slice = parse_rtp_packet(_rtp(b"\x61damaged", sequence=4, timestamp=9000))
    healthy_picture = parse_rtp_packet(
        _rtp(b"\x61\x80healthy", sequence=5, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (config, first_slice, damaged_slice, healthy_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x67sps", b"\x61\x80healthy")


def test_bounded_rtp_keeps_fragment_continuity_across_same_ssrc_metadata() -> None:
    start = parse_rtp_packet(_rtp(b"\x7c\x81\x80start", sequence=2))
    metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=3, payload_type=112)
    )
    end = parse_rtp_packet(_rtp(b"\x7c\x41end", sequence=4, marker=True))

    assert rtp_packets_to_nal_units(
        (start, metadata, end),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80startend",)


def test_bounded_rtp_detects_real_gap_before_same_ssrc_metadata() -> None:
    start = parse_rtp_packet(_rtp(b"\x7c\x81start", sequence=2))
    # Video packet 3 was lost; the next observed RTP packet is metadata 4.
    metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=4, payload_type=112)
    )
    end = parse_rtp_packet(_rtp(b"\x7c\x41end", sequence=5, marker=True))

    assert rtp_packets_to_nal_units(
        (start, metadata, end),
        codec="h264",
        completed_access_units_only=True,
    ) == ()


def test_bounded_rtp_carries_metadata_gap_across_video_timestamp() -> None:
    first = parse_rtp_packet(
        _rtp(b"\x61\x80first", sequence=1, timestamp=9000, marker=True)
    )
    # Sequence 2 is the missing first slice at timestamp 12000.
    metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=3, timestamp=12000, payload_type=112)
    )
    trailing = parse_rtp_packet(
        _rtp(b"\x61\x00tail", sequence=4, timestamp=12000, marker=True)
    )
    healthy = parse_rtp_packet(
        _rtp(b"\x61\x80healthy", sequence=5, timestamp=15000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first, metadata, trailing, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80first", b"\x61\x80healthy")


@pytest.mark.parametrize("nonvideo_payload_type", [104, 112])
def test_bounded_rtp_keeps_multiplexed_gap_across_different_timestamp_clocks(
    nonvideo_payload_type: int,
) -> None:
    previous = parse_rtp_packet(
        _rtp(b"\x61\xe0previous", sequence=1, timestamp=9000, marker=True)
    )
    # Sequence 2 could be the next video's first slice. Audio/metadata use
    # another timestamp clock, so their timestamp cannot assign the loss.
    other_media = parse_rtp_packet(
        _rtp(
            b"other media",
            sequence=3,
            timestamp=777_777,
            payload_type=nonvideo_payload_type,
        )
    )
    trailing = parse_rtp_packet(
        _rtp(b"\x61\x00tail", sequence=4, timestamp=12000, marker=True)
    )
    healthy = parse_rtp_packet(
        _rtp(b"\x61\xe0healthy", sequence=5, timestamp=15000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (previous, other_media, trailing, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\xe0previous", b"\x61\xe0healthy")


def test_bounded_h264_keeps_new_timestamp_metadata_gap_despite_mb_zero() -> None:
    previous = parse_rtp_packet(
        _rtp(b"\x61\xe0previous", sequence=1, timestamp=9000, marker=True)
    )
    metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=3, timestamp=12000, payload_type=112)
    )
    uncertain = parse_rtp_packet(
        _rtp(b"\x61\xe0mb0", sequence=4, timestamp=12000, marker=True)
    )
    healthy = parse_rtp_packet(
        _rtp(b"\x61\xe0healthy", sequence=5, timestamp=15000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (previous, metadata, uncertain, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\xe0previous", b"\x61\xe0healthy")


def test_bounded_h264_keeps_new_timestamp_metadata_conflict() -> None:
    previous = parse_rtp_packet(
        _rtp(b"\x61\xe0previous", sequence=1, timestamp=9000, marker=True)
    )
    # Reusing sequence 1 with changed timestamp/payload is a conflict, not a
    # duplicate. Its damage belongs to the picture at timestamp 12000.
    conflict = parse_rtp_packet(
        _rtp(b"metadata", sequence=1, timestamp=12000, payload_type=112)
    )
    uncertain = parse_rtp_packet(
        _rtp(b"\x61\xe0mb0", sequence=2, timestamp=12000, marker=True)
    )
    healthy = parse_rtp_packet(
        _rtp(b"\x61\xe0healthy", sequence=3, timestamp=15000, marker=True)
    )
    assert rtp_packets_to_nal_units(
        (previous, conflict, uncertain, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\xe0previous", b"\x61\xe0healthy")


@pytest.mark.parametrize(
    ("video_nal", "expected"),
    [
        (b"\x61\x80first", ()),
        (b"\x61\x00tail", ()),
    ],
)
def test_bounded_h264_preserves_pre_video_metadata_gap_with_macroblock_zero(
    video_nal: bytes, expected: tuple[bytes, ...]
) -> None:
    first_metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=1, payload_type=112)
    )
    # Missing sequence 2 was before any observed video timestamp.
    second_metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=3, payload_type=112)
    )
    video = parse_rtp_packet(_rtp(video_nal, sequence=4, marker=True))
    assert rtp_packets_to_nal_units(
        (first_metadata, second_metadata, video),
        codec="h264",
        completed_access_units_only=True,
    ) == expected


@pytest.mark.parametrize(
    ("first_slice_bit", "expected"),
    [
        (b"\x80", ()),
        (b"\x00", ()),
    ],
)
def test_bounded_h264_preserves_pre_video_gap_after_fu_reassembly(
    first_slice_bit: bytes, expected: tuple[bytes, ...]
) -> None:
    first_metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=1, payload_type=112)
    )
    second_metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=3, payload_type=112)
    )
    start = parse_rtp_packet(
        _rtp(b"\x7c\x81" + first_slice_bit + b"start", sequence=4)
    )
    end = parse_rtp_packet(_rtp(b"\x7c\x41end", sequence=5, marker=True))
    assert rtp_packets_to_nal_units(
        (first_metadata, second_metadata, start, end),
        codec="h264",
        completed_access_units_only=True,
    ) == expected


def test_bounded_h264_rejects_macroblock_zero_after_timestamp_gap() -> None:
    damaged = parse_rtp_packet(_rtp(b"\x61\x80old", sequence=1, timestamp=9000))
    # The missing sequence 2 was the prior picture's final slice.
    start = parse_rtp_packet(
        _rtp(b"\x7c\x81\x80new", sequence=3, timestamp=12000)
    )
    end = parse_rtp_packet(
        _rtp(b"\x7c\x41-end", sequence=4, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (damaged, start, end), codec="h264", completed_access_units_only=True
    ) == ()


def test_bounded_rtp_rejects_malformed_marked_fu_after_complete_slice() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=1))
    fu_start = parse_rtp_packet(_rtp(b"\x7c\x81start", sequence=2))
    # This FU ends a different NAL type; the depacketizer discards it.
    malformed_end = parse_rtp_packet(
        _rtp(b"\x7c\x45end", sequence=3, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first_slice, fu_start, malformed_end),
        codec="h264",
        completed_access_units_only=True,
    ) == ()


def test_bounded_rtp_rejects_unmarked_malformed_fu_before_timestamp_change() -> None:
    first = parse_rtp_packet(_rtp(b"\x61\x80first", sequence=1, timestamp=9000))
    malformed_fu = parse_rtp_packet(_rtp(b"\x7c", sequence=2, timestamp=9000))
    healthy = parse_rtp_packet(
        _rtp(b"\x61\x80healthy", sequence=3, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first, malformed_fu, healthy),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61\x80healthy",)


@pytest.mark.parametrize(
    ("codec", "malformed_fu"),
    [
        ("h264", b"\x7c\xc1\x80slice"),
        ("hevc", b"\x62\x01\xc1\x80slice"),
    ],
)
def test_bounded_rtp_rejects_fu_with_start_and_end_flags(
    codec: RtpVideoCodec, malformed_fu: bytes
) -> None:
    packet = parse_rtp_packet(_rtp(malformed_fu, sequence=1, marker=True))
    assert RtpVideoDepacketizer(codec).push(packet) == ()
    assert rtp_packets_to_nal_units(
        (packet,), codec=codec, completed_access_units_only=True
    ) == ()


def test_bounded_rtp_rejects_picture_with_open_fragment_at_timestamp_change() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=1, timestamp=9000))
    fu_start = parse_rtp_packet(
        _rtp(b"\x7c\x81start", sequence=2, timestamp=9000)
    )
    next_picture = parse_rtp_packet(
        _rtp(b"\x61healthy", sequence=3, timestamp=12000, marker=True)
    )

    assert rtp_packets_to_nal_units(
        (first_slice, fu_start, next_picture),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x61healthy",)


def test_bounded_rtp_rejects_marked_nal_that_discards_prior_fragment() -> None:
    first_slice = parse_rtp_packet(_rtp(b"\x61first", sequence=1))
    fu_start = parse_rtp_packet(_rtp(b"\x7c\x81start", sequence=2))
    marked_sei = parse_rtp_packet(_rtp(b"\x66sei", sequence=3, marker=True))

    assert rtp_packets_to_nal_units(
        (first_slice, fu_start, marked_sei),
        codec="h264",
        completed_access_units_only=True,
    ) == (b"\x66sei",)


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
    encrypted = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain[16:]
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


def test_decrypt_idmx_aac_packets_uses_latest_corrected_metadata() -> None:
    key = b"0123456789abcdef"

    def audio_descriptor(sample_rate: int) -> bytes:
        return bytes(
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
    encrypted = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain[16:]
    audio_extension = b"\x80\x06\x00\x01\x21\x21\x02\x01"
    packets = [
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=1,
                payload_type=112,
                extension_profile=1,
                extension_data=b"\x45\x02\x0f\x69" + audio_descriptor(8_000),
            )
        ),
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=2,
                payload_type=112,
                extension_profile=1,
                extension_data=audio_descriptor(16_000),
            )
        ),
        parse_rtp_packet(
            _rtp(
                b"\x00\x10" + (len(encrypted) << 3).to_bytes(2, "big") + encrypted,
                sequence=3,
                timestamp=0,
                payload_type=105,
                extension_profile=0x4000,
                extension_data=audio_extension,
            )
        ),
    ]

    audio = decrypt_idmx_aac_packets(packets, key)

    assert audio is not None
    assert audio.sample_rate == 16_000
    assert audio.channels == 1


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


@pytest.mark.parametrize(
    ("payload", "extension_data"),
    [
        (b"\x00\x10\x00\x08malformed", b"\x80\x06\x00\x01\x21\x21\x02\x01"),
        (b"\x00\x10\x00\x28valid", b"\x00\x06\x00\x01\x21\x21\x02\x01"),
    ],
)
def test_idmx_aac_frame_validation_rejects_malformed_packet(
    payload: bytes,
    extension_data: bytes,
) -> None:
    packet = parse_rtp_packet(
        _rtp(
            payload,
            sequence=1,
            payload_type=104,
            extension_profile=0x4000,
            extension_data=extension_data,
        )
    )

    assert not rtp_packet_has_valid_idmx_aac_frame(packet)


def test_decrypt_idmx_aac_packets_uses_descriptor_payload_route() -> None:
    key = b"0123456789abcdef"
    sample_rate = 16_000
    stream_descriptor = (
        b"\x45\x02\x90\x68"
        b"\x45\x0a\x0f\x69"
        + (b"\xff" * 8)
    )
    audio_descriptor = bytes(
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
    encrypted = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain[16:]
    packets = [
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=1,
                payload_type=112,
                extension_profile=1,
                extension_data=stream_descriptor + audio_descriptor,
            )
        ),
        parse_rtp_packet(
            _rtp(
                b"g711-alaw",
                sequence=2,
                timestamp=0,
                payload_type=104,
            )
        ),
        parse_rtp_packet(
            _rtp(
                b"\x00\x10" + (len(encrypted) << 3).to_bytes(2, "big") + encrypted,
                sequence=3,
                timestamp=0,
                payload_type=105,
                extension_profile=0x4000,
                extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
            )
        ),
    ]

    audio = decrypt_idmx_aac_packets(packets, key)

    assert audio is not None
    assert audio.adts == b"\xff\xf1`@\x03\x7f\xfc" + plain


def test_decrypt_idmx_aac_packet_uses_native_extension_after_descriptor_probe() -> None:
    key = b"0123456789abcdef"
    plain = b"0123456789abcdef" + b"tail"
    encrypted = bytes.fromhex("72727e881edcfd0100a718687909b565") + plain[16:]
    packet = parse_rtp_packet(
        _rtp(
            b"\x00\x10" + (len(encrypted) << 3).to_bytes(2, "big") + encrypted,
            sequence=2,
            timestamp=0,
            payload_type=105,
            extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01",
        )
    )

    audio = decrypt_idmx_aac_packets(
        (packet,),
        key,
        audio_metadata=(16_000, 1),
        audio_payload_types=frozenset({105}),
        require_contiguous=False,
    )

    assert audio is not None
    assert audio.adts == b"\xff\xf1`@\x03\x7f\xfc" + plain


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


def test_official_app_payload_type_families_are_classified() -> None:
    assert frozenset({26, 32, 96, 99}) == KNOWN_VIDEO_PAYLOAD_TYPES
    assert frozenset(
        {0, 4, 8, 11, 14, 18, 98, 100, 102, 103, 104, 115}
    ) == KNOWN_AUDIO_PAYLOAD_TYPES


def test_idmx_stream_descriptor_routes_non_default_hevc_payload_type() -> None:
    descriptor = b"\x45\x0a\x24\x61" + (b"\xff" * 8)
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            ssrc=3,
            extension_profile=1,
            extension_data=descriptor,
        )
    )
    video = parse_rtp_packet(
        _rtp(
            b"\x26\x01hevc",
            sequence=2,
            payload_type=97,
            ssrc=2,
        )
    )

    streams = idmx_rtp_stream_descriptors([metadata, video])

    assert streams == (
        RtpStreamDescriptor(
            stream_type=0x24,
            payload_type=97,
            codec="hevc",
            media_kind="video",
        ),
    )
    assert rtp_media_kind(video, stream_descriptors=streams) == "video"
    assert detect_rtp_video_codec([metadata, video]) == "hevc"
    assert rtp_packets_to_annexb(
        [metadata, video],
        codec="hevc",
    ) == HEVC_DESCRIPTOR_ROUTED_NAL


def test_rtp_annexb_discards_conflicting_video_before_delayed_descriptor() -> None:
    expected_annexb = b"\x00\x00\x00\x01\x26\x01new-hevc-idr"
    packets = (
        parse_rtp_packet(
            _rtp(b"\x67old-h264-sps", sequence=1, payload_type=97)
        ),
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=2,
                payload_type=112,
                extension_profile=1,
                extension_data=b"\x45\x0a\x24\x61" + (b"\xff" * 8),
            )
        ),
        parse_rtp_packet(
            _rtp(b"\x26\x01new-hevc-idr", sequence=3, payload_type=97)
        ),
    )

    assert detect_rtp_video_codec(packets) == "hevc"
    assert rtp_packets_to_annexb(packets, codec="hevc") == expected_annexb


def test_rtp_annexb_preserves_descriptor_free_h264_data_partition() -> None:
    packet = parse_rtp_packet(
        _rtp(b"\x62\x01h264-data-partition", sequence=1)
    )

    assert rtp_payload_video_codec(packet.payload) == "hevc"
    assert rtp_packets_to_annexb((packet,), codec="h264") == H264_DATA_PARTITION_NAL


def test_route_profile_absorbs_delayed_descriptor_before_media_dispatch() -> None:
    profile = RtpRouteProfile()
    early = parse_rtp_packet(_rtp(b"\x67early", sequence=1, payload_type=96))
    descriptor = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x90\x60\x45\x02\x1b\x61",
        )
    )

    profile.absorb(early)
    profile.absorb(descriptor)

    assert profile.media_kind(early) == "audio"
    assert profile.codec_payload_types(
        "h264", fallback_payload_types=frozenset({96})
    ) == frozenset({97})


def test_route_profile_rejects_descriptor_mutation_after_media_dispatch() -> None:
    profile = RtpRouteProfile()
    descriptor = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    )
    video = parse_rtp_packet(_rtp(b"\x67video", sequence=2, payload_type=97, ssrc=9))
    repeated = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    )
    mutation = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=4,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x61",
        )
    )
    profile.absorb(descriptor)
    profile.mark_media(video)
    profile.absorb(repeated)

    with pytest.raises(PyEzvizError, match="RTP route mutation after media began"):
        profile.absorb(mutation)


def test_route_profile_rejects_new_incompatible_video_route_after_dispatch() -> None:
    profile = RtpRouteProfile()
    h264_descriptor = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    )
    video = parse_rtp_packet(_rtp(b"\x67video", sequence=2, payload_type=97))
    new_hevc_route = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x62",
        )
    )
    profile.absorb(h264_descriptor)
    profile.mark_media(video)

    with pytest.raises(PyEzvizError, match="RTP route mutation after media began"):
        profile.absorb(new_hevc_route)


def test_route_profile_accepts_codec_alias_repeat_after_media_dispatch() -> None:
    profile = RtpRouteProfile()
    descriptor = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    )
    video = parse_rtp_packet(_rtp(b"\x67video", sequence=2, payload_type=97))
    alias = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\xb0\x61",
        )
    )

    profile.absorb(descriptor)
    profile.mark_media(video)
    profile.absorb(alias)

    assert profile.descriptors[0].stream_type == 0xB0
    assert profile.descriptors[0].codec == "h264"


def test_route_profile_rejects_mutation_of_selected_video_fallback() -> None:
    profile = RtpRouteProfile()
    video = parse_rtp_packet(_rtp(b"\x67video", sequence=1))
    mutation = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=2,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x60",
        )
    )
    profile.select_video_fallback(96, "h264")
    profile.mark_media(video)

    with pytest.raises(PyEzvizError, match="RTP route mutation after media began"):
        profile.absorb(mutation)


@pytest.mark.parametrize(
    ("payload_type", "codec"),
    ((26, "mjpeg"), (32, "mpeg2video"), (99, "svac")),
)
def test_route_profile_reports_static_video_codec(
    payload_type: int,
    codec: str,
) -> None:
    profile = RtpRouteProfile()
    video = parse_rtp_packet(
        _rtp(b"video", sequence=1, payload_type=payload_type, ssrc=7)
    )

    profile.mark_media(video)

    assert profile.streams() == (
        {
            "codec": codec,
            "media_kind": "video",
            "payload_type": payload_type,
            "ssrc": 7,
            "sample_rate": None,
            "channels": None,
            "authoritative": False,
        },
    )


def test_route_profile_reports_audio_metadata_and_sanitized_diagnostics() -> None:
    profile = RtpRouteProfile()
    descriptor = b"\x45\x02\x0f\x69" + bytes(
        (0x43, 10, 0, 1, 2, 0, 250, 3, 0, 0, 3, 0xFF)
    )
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata-secret",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        )
    )
    audio = parse_rtp_packet(
        _rtp(b"media-secret", sequence=2, payload_type=105, ssrc=0x12345678)
    )
    profile.absorb(metadata)
    profile.mark_media(audio)

    assert profile.streams() == (
        {
            "codec": "aac",
            "media_kind": "audio",
            "payload_type": 105,
            "ssrc": 0x12345678,
            "sample_rate": 16000,
            "channels": 1,
            "authoritative": True,
        },
    )
    diagnostic = profile.diagnostics()
    assert diagnostic == {"media_started": True, "streams": list(profile.streams())}
    assert "secret" not in repr(diagnostic)


def test_route_profile_accepts_audio_metadata_after_consumer_is_disabled() -> None:
    profile = RtpRouteProfile()
    metadata_16k = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x0f\x69" + bytes(
                (0x43, 10, 0, 1, 2, 0, 250, 3, 0, 0, 3, 0xFF)
            ),
        )
    )
    audio = parse_rtp_packet(_rtp(b"audio", sequence=2, payload_type=105))
    metadata_8k = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=3,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x90\x69" + bytes(
                (0x43, 10, 0, 1, 2, 0, 125, 3, 0, 0, 3, 0xFF)
            ),
        )
    )
    profile.absorb(metadata_16k)
    profile.mark_media(audio)
    profile.deactivate_audio()

    profile.absorb(metadata_8k)

    assert profile.audio_metadata == (8_000, 1)
    assert profile.codec_payload_types("g711-alaw") == frozenset({105})


@pytest.mark.parametrize(
    ("payload_type", "codec", "sample_rate", "channels"),
    [
        (0, "g711-mulaw", 8000, 1),
        (8, "g711-alaw", 8000, 1),
        (115, "opus", None, None),
        (104, "unknown", None, None),
    ],
)
def test_route_profile_only_names_unambiguous_descriptor_free_audio(
    payload_type: int,
    codec: str,
    sample_rate: int | None,
    channels: int | None,
) -> None:
    profile = RtpRouteProfile()
    packet = parse_rtp_packet(
        _rtp(b"audio", sequence=1, payload_type=payload_type, ssrc=7)
    )
    profile.mark_media(packet)

    stream = profile.streams()[0]
    assert stream["codec"] == codec
    assert stream["sample_rate"] == sample_rate
    assert stream["channels"] == channels


def test_descriptor_routes_replace_conflicting_default_video_payload_type() -> None:
    descriptors = b"\x45\x02\x90\x60\x45\x02\x1b\x61"
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptors,
        )
    )
    reassigned_audio = parse_rtp_packet(
        _rtp(b"\x65wrong", sequence=2, payload_type=96)
    )
    video = parse_rtp_packet(
        _rtp(b"\x65right", sequence=3, payload_type=97)
    )
    routes = idmx_rtp_stream_descriptors((metadata,))

    assert rtp_codec_payload_types(
        routes,
        "h264",
        fallback_payload_types=frozenset({96}),
    ) == frozenset({97})
    assert rtp_packets_to_annexb(
        (metadata, reassigned_audio, video),
        codec="h264",
    ) == H264_DESCRIPTOR_ROUTED_NAL


def test_authoritative_video_descriptor_disables_legacy_pt96_fallback() -> None:
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x1b\x61",
        )
    )
    legacy = parse_rtp_packet(_rtp(b"\x65wrong", sequence=2, payload_type=96))
    routed = parse_rtp_packet(_rtp(b"\x65right", sequence=3, payload_type=97))
    routes = idmx_rtp_stream_descriptors((metadata,))

    assert rtp_media_kind(legacy, stream_descriptors=routes) == "unknown"
    assert (
        rtp_packets_to_annexb((metadata, legacy, routed), codec="h264")
        == H264_DESCRIPTOR_ROUTED_NAL
    )


def test_absent_video_descriptor_route_falls_back_to_observed_pt96() -> None:
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=b"\x45\x02\x24\x0f",
        )
    )
    video = parse_rtp_packet(
        _rtp(b"\x40\x01vps", sequence=2, payload_type=96)
    )

    expected = b"\x00\x00\x00\x01\x40\x01vps"
    assert rtp_packets_to_annexb((metadata, video), codec="hevc") == expected


def test_unknown_descriptor_claims_shared_payload_from_video_fallback() -> None:
    descriptor = b"\x45\x02\xaf\x60"
    metadata = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        )
    )
    future_codec = parse_rtp_packet(
        _rtp(b"\x67not-h264", sequence=2, payload_type=96)
    )

    routes = idmx_rtp_stream_descriptors((metadata,))

    assert routes == (
        RtpStreamDescriptor(
            stream_type=0xAF,
            payload_type=96,
            codec="unknown",
            media_kind="unknown",
        ),
    )
    assert rtp_media_kind(future_codec, stream_descriptors=routes) == "unknown"
    with pytest.raises(PyEzvizError, match="Could not detect RTP video codec"):
        detect_rtp_video_codec((metadata, future_codec))


def test_codec_detection_reports_metadata_declared_unsupported_video_codec() -> None:
    descriptor = b"\x45\x0a\xb1\x1a" + (b"\xff" * 8)
    packet = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptor,
        )
    )

    with pytest.raises(
        PyEzvizError,
        match="Unsupported RTP video codec advertised by IDMX metadata: mjpeg",
    ):
        detect_rtp_video_codec([packet])


def test_codec_detection_rejects_conflicting_video_descriptors() -> None:
    descriptors = (
        b"\x45\x02\x1b\x60"
        b"\x45\x02\x24\x61"
    )
    packet = parse_rtp_packet(
        _rtp(
            b"metadata",
            sequence=1,
            payload_type=112,
            extension_profile=1,
            extension_data=descriptors,
        )
    )

    with pytest.raises(
        PyEzvizError,
        match=(
            "Conflicting RTP video codecs advertised by IDMX metadata: h264, hevc"
        ),
    ):
        detect_rtp_video_codec([packet])


@pytest.mark.parametrize(
    ("payload_type", "payload", "codec"),
    [
        (26, b"\xff\xd8\xff\xe0jpeg", "mjpeg"),
        (32, b"\x00\x00\x01\xb3mpeg2", "mpeg2video"),
        (99, b"\x00\x00\x01svac", "svac"),
    ],
)
def test_codec_detection_rejects_official_unsupported_static_video_payloads(
    payload_type: int,
    payload: bytes,
    codec: str,
) -> None:
    packet = parse_rtp_packet(
        _rtp(payload, sequence=1, payload_type=payload_type)
    )

    with pytest.raises(PyEzvizError, match=f"Unsupported RTP video codec: {codec}"):
        detect_rtp_video_codec([packet])


def test_static_unsupported_video_is_not_masked_by_shared_payload_packet() -> None:
    packets = (
        parse_rtp_packet(
            _rtp(b"\x00\x00\x01\xb3mpeg2", sequence=1, payload_type=32)
        ),
        parse_rtp_packet(
            _rtp(b"dynamic-audio", sequence=2, payload_type=96)
        ),
    )

    with pytest.raises(
        PyEzvizError,
        match="Unsupported RTP video codec: mpeg2video",
    ):
        detect_rtp_video_codec(packets)


def test_descriptor_reassignment_overrides_static_video_payload_type() -> None:
    descriptor = b"\x45\x02\x90\x20"
    packets = (
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=1,
                payload_type=112,
                extension_profile=1,
                extension_data=descriptor,
            )
        ),
        parse_rtp_packet(
            _rtp(b"g711-alaw", sequence=2, payload_type=32)
        ),
        parse_rtp_packet(
            _rtp(b"\x67h264-sps", sequence=3, payload_type=96)
        ),
    )

    assert detect_rtp_video_codec(packets) == "h264"


def test_descriptor_non_video_route_is_excluded_from_codec_fallback() -> None:
    descriptor = b"\x45\x02\x90\x60"
    packets = (
        parse_rtp_packet(
            _rtp(
                b"metadata",
                sequence=1,
                payload_type=112,
                extension_profile=1,
                extension_data=descriptor,
            )
        ),
        parse_rtp_packet(
            _rtp(b"\x67not-video", sequence=2, payload_type=96)
        ),
    )

    with pytest.raises(PyEzvizError, match="Could not detect RTP video codec"):
        detect_rtp_video_codec(packets)


def test_explicit_video_payload_route_overrides_static_codec_default() -> None:
    packet = parse_rtp_packet(
        _rtp(b"\x67h264-sps", sequence=1, payload_type=99)
    )
    custom_route = frozenset({99})

    assert detect_rtp_video_codec(
        (packet,),
        video_payload_types=custom_route,
    ) == "h264"
    assert rtp_packets_to_annexb(
        (packet,),
        codec="h264",
        video_payload_types=custom_route,
    ) == H264_CUSTOM_ROUTED_NAL


@pytest.mark.parametrize(
    ("payload", "codec"),
    [
        (b"\x00\x00\x01\xb6mpeg4-vop", "mpeg4video"),
        (b"\x00\x00\x01\xb3mpeg2-sequence", "mpeg2video"),
    ],
)
def test_codec_detection_rejects_start_coded_video_on_shared_payload_type(
    payload: bytes,
    codec: str,
) -> None:
    packet = parse_rtp_packet(_rtp(payload, sequence=1, payload_type=96))

    with pytest.raises(PyEzvizError, match=f"Unsupported RTP video codec: {codec}"):
        detect_rtp_video_codec([packet])


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


@pytest.mark.parametrize("video_sequence", [100, 65535])
@pytest.mark.parametrize("audio_sequence", [100, 200, 40000])
@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_idmx_independent_counters_preserve_video_fu(
    video_sequence: int, audio_sequence: int, codec: RtpVideoCodec
) -> None:
    ssrc = 0x55667788
    start_payload = b"\x7c\x85\x80start" if codec == "h264" else b"\x62\x01\x93\x80start"
    end_payload = b"\x7c\x45end" if codec == "h264" else b"\x62\x01\x53end"
    start = parse_rtp_packet(
        _rtp(start_payload, sequence=video_sequence, ssrc=ssrc), idmx=True
    )
    audio = parse_rtp_packet(
        _rtp(b"audio", sequence=audio_sequence, payload_type=104, ssrc=ssrc), idmx=True
    )
    metadata = parse_rtp_packet(
        _rtp(b"metadata", sequence=300, payload_type=112, ssrc=ssrc), idmx=True
    )
    end = parse_rtp_packet(
        _rtp(
            end_payload,
            sequence=(video_sequence + 1) & 0xFFFF,
            marker=True,
            ssrc=ssrc,
        ),
        idmx=True,
    )
    expected = b"\x65\x80startend" if codec == "h264" else b"\x26\x01\x80startend"
    depacketizer = RtpVideoDepacketizer(codec)
    assert depacketizer.push(start) == ()
    depacketizer.observe_nonvideo_packet(audio)
    depacketizer.observe_nonvideo_packet(metadata)
    assert depacketizer.has_incomplete_nal(ssrc)
    assert depacketizer.has_incomplete_nal(ssrc, payload_type=96)
    assert not depacketizer.has_incomplete_nal(ssrc, payload_type=104)
    assert depacketizer.push(end) == (expected,)
    assert depacketizer.stats.sequence_gaps == 0
    assert rtp_packets_to_nal_units(
        (start, audio, metadata, end),
        codec=codec,
        completed_access_units_only=True,
    ) == (expected,)
    # Also exercise clear FU scanning ahead of encrypted-NAL transforms.
    assert rtp_packets_to_nal_units(
        (start, audio, metadata, end),
        codec=codec,
        completed_access_units_only=True,
        packet_nal_transform=lambda nal: b"" if nal.startswith(start_payload[:1]) else nal,
    ) == (expected,)


def test_idmx_independent_counters_do_not_hide_video_loss() -> None:
    ssrc = 0x55667788
    start = parse_rtp_packet(_rtp(b"\x7c\x85\x80start", sequence=100, ssrc=ssrc), idmx=True)
    audio = parse_rtp_packet(
        _rtp(b"audio", sequence=101, payload_type=104, ssrc=ssrc), idmx=True
    )
    end = parse_rtp_packet(
        _rtp(b"\x7c\x45end", sequence=102, marker=True, ssrc=ssrc), idmx=True
    )
    assert rtp_packets_to_nal_units(
        (start, audio, end), codec="h264", completed_access_units_only=True
    ) == ()
    depacketizer = RtpVideoDepacketizer("h264")
    depacketizer.push(start)
    depacketizer.observe_nonvideo_packet(audio)
    assert depacketizer.push(end) == ()
    assert depacketizer.stats.sequence_gaps == 1


def test_ordinary_rtp_may_share_idmx_marker_without_independent_counters() -> None:
    ssrc = 0x55667788
    start = parse_rtp_packet(_rtp(b"\x7c\x85\x80start", sequence=100, ssrc=ssrc))
    audio = parse_rtp_packet(
        _rtp(b"audio", sequence=101, payload_type=104, ssrc=ssrc)
    )
    end = parse_rtp_packet(
        _rtp(b"\x7c\x45end", sequence=102, marker=True, ssrc=ssrc)
    )
    assert not start.idmx
    expected = b"\x65\x80startend"
    depacketizer = RtpVideoDepacketizer("h264")
    depacketizer.push(start)
    depacketizer.observe_nonvideo_packet(audio)
    assert depacketizer.has_incomplete_nal(ssrc, payload_type=96)
    assert depacketizer.push(end) == (expected,)
    assert rtp_packets_to_nal_units(
        (start, audio, end), codec="h264", completed_access_units_only=True
    ) == (expected,)


def _native_video_period_packet(period: int, *, idmx: bool = True) -> RtpPacket:
    descriptor = b"\x42\x0e" + b"\x00" * 11 + (period << 1).to_bytes(3, "big")
    return parse_rtp_packet(
        _rtp(b"metadata", sequence=1, payload_type=112,
             extension_profile=2, extension_data=descriptor), idmx=idmx,
    )


@pytest.mark.parametrize(("period", "rate"), [(6000, "15"), (3003, "30000/1001"), (3600, "25")])
def test_native_video_descriptor_retains_exact_frame_rate(period: int, rate: str) -> None:
    assert idmx_video_frame_rate((_native_video_period_packet(period),)) == rate


@pytest.mark.parametrize("period", [0, 186, 1530001, 0x7FFFFE, 0x7FFFFF])
def test_native_video_descriptor_does_not_invent_reserved_timing(period: int) -> None:
    assert idmx_video_frame_rate((_native_video_period_packet(period),)) is None


def test_native_video_descriptor_requires_native_provenance() -> None:
    assert idmx_video_frame_rate((_native_video_period_packet(6000, idmx=False),)) is None


def test_native_video_descriptor_uses_corrected_startup_period() -> None:
    assert idmx_video_frame_rate((
        _native_video_period_packet(3600), _native_video_period_packet(6000),
        _native_video_period_packet(0x7FFFFF),
    )) == "15"


def test_native_video_descriptor_ignores_truncated_extension() -> None:
    packet = parse_rtp_packet(_rtp(b"media", sequence=1, extension_profile=2,
        extension_data=b"\x42\x0e" + b"\x00" * 10), idmx=True)
    assert idmx_video_frame_rate((packet,)) is None


@pytest.mark.parametrize("origin", [0, 0xFFFFFC00])
def test_bounded_aac_retains_missing_au_sample_offsets_across_wrap(origin: int) -> None:
    packets = [parse_rtp_packet(_rtp(b"metadata", sequence=0, payload_type=112,
        extension_profile=2, extension_data=bytes.fromhex("430a0090fe00fa0301f403ff")), idmx=True)]
    for sequence, offset in enumerate([0, 1024, 4096, 5120], start=1):
        packets.append(parse_rtp_packet(_rtp(b"\x00\x10\x00\x10xy", sequence=sequence,
            timestamp=(origin + offset) & 0xFFFFFFFF, payload_type=104,
            extension_profile=0x4000, extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01"), idmx=True))
    assert decrypt_idmx_aac_packets(packets, b"key") is None
    audio = decrypt_idmx_aac_packets(packets, b"key", require_contiguous=False)
    assert audio is not None
    assert audio.frame_count == 4
    assert [offset for offset, _data in audio.timed_segments] == [0, 4096]
    assert b"".join(data for _offset, data in audio.timed_segments) == audio.adts


@pytest.mark.parametrize("delta", [0, 1023, 0xFFFFFFFF])
def test_bounded_aac_does_not_convert_reorder_or_invalid_clock_to_gap(delta: int) -> None:
    packets = [parse_rtp_packet(_rtp(b"metadata", sequence=0, payload_type=112,
        extension_profile=2, extension_data=bytes.fromhex("430a0090fe00fa0301f403ff")), idmx=True)]
    for sequence, timestamp in enumerate([0, delta], start=1):
        packets.append(parse_rtp_packet(_rtp(b"\x00\x10\x00\x10xy", sequence=sequence,
            timestamp=timestamp, payload_type=104, extension_profile=0x4000,
            extension_data=b"\x80\x06\x00\x01\x21\x21\x02\x01"), idmx=True))
    assert decrypt_idmx_aac_packets(packets, b"key", require_contiguous=False) is None
