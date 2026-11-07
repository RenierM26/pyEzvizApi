"""Pure local IDMX/RTP/Annex-B packet parsing and window metadata; no transport ownership."""

from __future__ import annotations

from dataclasses import dataclass, replace

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.media.rtp import RtpPacket, RtpRouteProfile, RtpStreamDescriptor, parse_rtp_packet
from pyezvizapi.streaming.media.containers import ANNEX_B_LONG_START_CODE, MPEG_START_CODE_PREFIX


@dataclass(frozen=True)
class _H264CleanIdrProbeResult:
    """Result of probing partial H.264 Annex-B IDR windows."""

    start_offset: int | None
    idr_start_offset: int | None = None
    prefix: bytes = b""
    first_decode_error: str | None = None
    idr_count: int = 0
    sampled_window_count: int = 0
    complete_window_count: int = 0
    nal_count: int = 0
    codec_name: str = "H.264"
    window_name: str = "IDR"


@dataclass
class _RtpFragmentedNal:
    """In-progress fragmented NAL with RTP continuity state."""

    data: bytearray
    last_sequence: int | None
    rtp_timestamp: int | None


IDMX_LOCAL_FRAME_SENTINEL = b"\x55\x66\x77\x88"


IDMX_LOCAL_FRAME_SENTINEL_OFFSETS = (8, 9)


HEVC_NAL_HEADER_SIZE = 2


H264_FU_A_NAL_TYPE = 28


IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET = 12


IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX = b"\x24\0"


def _h264_clean_idr_timeout_suffix(
    *,
    first_decode_error: str | None,
    probe: _H264CleanIdrProbeResult,
) -> str:
    """Return concise diagnostic context for a failed clean-IDR wait."""

    details = (
        f"checked {probe.complete_window_count} complete sampled "
        f"{probe.window_name} windows from {probe.idr_count} "
        f"{probe.window_name}s/{probe.nal_count} {probe.codec_name} NALs"
    )
    if first_decode_error:
        return f": {details}; first decode error: {first_decode_error}"
    if probe.idr_count or probe.nal_count:
        return f": {details}"
    return ""


def _annexb_vcl_bounds(
    data: bytes,
    *,
    video_input_format: str,
) -> tuple[int, int] | None:
    bounds: list[tuple[int, int]] = []
    for start_code_offset, nal_start, end in _h264_annexb_nal_spans(data):
        nal = data[nal_start:end]
        if video_input_format == "h264":
            is_vcl = 1 <= _h264_nal_type(nal) <= 5
        elif video_input_format == "hevc":
            is_vcl = _hevc_nal_type(nal) <= 31
        else:
            raise PyEzvizError(f"Unsupported IDMX video input format: {video_input_format}")
        if is_vcl:
            bounds.append((start_code_offset, end))
    return (bounds[0][0], bounds[-1][1]) if bounds else None


def _annexb_first_vcl_unit(data: bytes, *, video_input_format: str) -> bytes | None:
    for start_code_offset, nal_start, end in _h264_annexb_nal_spans(data):
        nal = data[nal_start:end]
        if video_input_format == "h264":
            is_vcl = 1 <= _h264_nal_type(nal) <= 5
        elif video_input_format == "hevc":
            is_vcl = _hevc_nal_type(nal) <= 31
        else:
            raise PyEzvizError(f"Unsupported IDMX video input format: {video_input_format}")
        if is_vcl:
            return data[start_code_offset:end]
    return None


def _annexb_contains_selected_vcl(
    full_annexb: bytes,
    selected_annexb: bytes,
    *,
    video_input_format: str,
) -> bool:
    """Return whether a full stream contains the selected suffix or first VCL."""

    if selected_annexb in full_annexb:
        return True
    first_vcl = _annexb_first_vcl_unit(
        selected_annexb,
        video_input_format=video_input_format,
    )
    return first_vcl is not None and first_vcl in full_annexb


def _h264_annexb_idr_window_start_index(
    nal_types: list[int],
    idr_nal_index: int,
) -> int:
    start = idr_nal_index
    while start > 0 and nal_types[start - 1] in {6, 7, 8, 9}:
        start -= 1
    return start


def _idmx_local_rtp_frame(frame: bytes) -> bytes | None:
    """Locate ordinary RTP or X80's one-byte-prefixed RTP record."""

    for offset in (0, 1):
        if (
            len(frame) >= offset + 12
            and (offset == 0 or frame[0] == 0x0D)
            and frame[offset] >> 6 == 2
            and frame[offset + 8 : offset + 12] == IDMX_LOCAL_FRAME_SENTINEL
        ):
            rtp_frame = frame[offset:]
            try:
                parse_rtp_packet(rtp_frame)
            except PyEzvizError:
                if offset == 1:
                    # 0x0d identifies shimmed RTP independently of media codec.
                    # Legacy 0xfa command records are handled outside this path.
                    raise
                continue
            return rtp_frame
    return None


def _is_complete_idmx_rtp_frame(frame: bytes) -> bool:
    """Return whether ``frame`` contains one complete standards-shaped RTP packet."""

    rtp_frame = _idmx_local_rtp_frame(frame)
    if rtp_frame is None:
        return False
    try:
        parse_rtp_packet(rtp_frame)
    except PyEzvizError:
        return False
    return True


def _idmx_local_frame_media_body(frame: bytes, header_size: int) -> bytes:
    """Return media bytes after RTP extensions/padding or a legacy IDMX header."""

    rtp_frame = _idmx_local_rtp_frame(frame)
    if rtp_frame is not None:
        packet = parse_rtp_packet(rtp_frame)
        if header_size == 13 and _looks_like_idmx_hevc_media_frame(frame[header_size:]):
            # Retain the native HEVC wrapper's encrypted-parameter-set signal,
            # but never append RTP padding to the fragmented NAL body.
            return (
                frame[header_size : header_size + IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET] + packet.payload
            )
        return (
            _strip_idmx_command_h264_record_trailer(packet.payload)
            if header_size == 13 and packet.extension_profile is None
            else packet.payload
        )
    return _strip_idmx_command_h264_record_trailer(frame[header_size:])


def _strip_legacy_idmx_video_wrapper(packet: RtpPacket) -> RtpPacket:
    """Normalize an in-body native video wrapper, not an audio wrapper."""

    payload = packet.payload
    if _looks_like_idmx_hevc_media_frame(payload) and payload[8] & 0xF0 == 0x10:
        return replace(packet, payload=payload[IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET:])
    return packet


def _rtp_fragment_continues(
    active_fu: _RtpFragmentedNal | None,
    *,
    sequence_number: int | None,
    rtp_timestamp: int | None,
) -> bool:
    if active_fu is None:
        return False
    if (
        active_fu.rtp_timestamp is not None
        and rtp_timestamp is not None
        and active_fu.rtp_timestamp != rtp_timestamp
    ):
        return False
    return not (
        active_fu.last_sequence is not None
        and sequence_number is not None
        and ((active_fu.last_sequence + 1) & 0xFFFF) != sequence_number
    )


def _idmx_local_frame_header_size(payload: bytes) -> int | None:
    for sentinel_offset in IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
        header_size = sentinel_offset + len(IDMX_LOCAL_FRAME_SENTINEL)
        if (
            len(payload) >= header_size
            and payload[sentinel_offset:header_size] == IDMX_LOCAL_FRAME_SENTINEL
        ):
            return header_size
    return None


def _idmx_local_frame_header_score(
    payload: bytes,
    header_size: int | None,
) -> int | None:
    if header_size is None or len(payload) < header_size:
        return None
    lead = payload[0]
    if header_size == 13 and lead in {0x0D, 0xFA}:
        return 0
    if header_size == 12 and lead in {0x80, 0x90, 0xA0}:
        return 0
    if header_size == 13 and payload[1] in {0x80, 0x90, 0xA0}:
        return 1
    return None


def _idmx_frame_end_before_next_prefix(payload: bytes, next_frame_start: int) -> int:
    prefix_start = next_frame_start - 4
    if prefix_start < 0:
        return next_frame_start
    prefixed_length = int.from_bytes(payload[prefix_start:next_frame_start], "little")
    remaining_after_prefix = len(payload) - next_frame_start
    if 0 < prefixed_length <= remaining_after_prefix:
        return prefix_start
    return next_frame_start


def _rtp_packet_route_descriptor(
    profile: RtpRouteProfile,
    packet: RtpPacket,
) -> RtpStreamDescriptor | None:
    """Return the descriptor active for one packet, or None before discovery."""

    return next(
        (
            descriptor
            for descriptor in profile.descriptors
            if descriptor.payload_type == packet.payload_type
        ),
        None,
    )


def _rtp_packet_matches_codec_epoch(
    profile: RtpRouteProfile,
    packet: RtpPacket,
    codec: str,
) -> bool:
    """Accept one codec only in its active or genuinely unclassified epoch."""

    descriptor = _rtp_packet_route_descriptor(profile, packet)
    return descriptor is None or descriptor.codec == codec


def _looks_like_idmx_hevc_parameter_frame(body: bytes) -> bool:
    return len(body) > 4 and body[:2] in (
        b"\x00\x01",
        b"\x00\x02",
    )


def _looks_like_idmx_hevc_media_frame(body: bytes) -> bool:
    return len(body) > IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET and body.startswith(
        b"\x40\x00\x00\x02\x80\x06"
    )


def _looks_like_idmx_hevc_direct_frame(body: bytes) -> bool:
    if len(body) < HEVC_NAL_HEADER_SIZE or body[0] & 0x80 or body[1] & 0x07 == 0:
        return False
    nal_type = _hevc_nal_type(body)
    return 0 <= nal_type <= 40 or nal_type == 49


def _looks_like_idmx_hevc_evidence_frame(body: bytes) -> bool:
    if not _looks_like_idmx_hevc_direct_frame(body):
        return False
    nal_type = _hevc_nal_type(body)
    if nal_type in {32, 33, 34}:
        return body[1] & 0xF8 == 0
    return nal_type == 49


def _looks_like_idmx_h264_fu_a_frame(body: bytes) -> bool:
    return len(body) > 2 and body[0] & 0x1F == H264_FU_A_NAL_TYPE


def _looks_like_idmx_h264_clear_nal(body: bytes) -> bool:
    if not body:
        return False
    return (body[0] & 0x1F) in {1, 5, 6, 7, 8, 9}


def _strip_idmx_command_h264_record_trailer(body: bytes) -> bytes:
    if len(body) <= 4:
        return body
    if not (
        _looks_like_idmx_h264_fu_a_frame(body)
        or _looks_like_idmx_h264_clear_nal(body)
        or _looks_like_idmx_hevc_direct_frame(body)
    ):
        return body
    if body[-3:-1] == IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX:
        return body[:-3]
    if body[-4:-2] == IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX:
        return body[:-4]
    return body


def _append_h264_nal(output: bytearray, nal: bytes) -> None:
    if not _is_plausible_h264_nal(nal):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(nal)


def _is_plausible_hevc_nal(nal: bytes) -> bool:
    nal_type = _hevc_nal_type(nal)
    return (
        len(nal) >= HEVC_NAL_HEADER_SIZE
        and not nal[0] & 0x80
        and nal[1] & 0x07 != 0
        and 0 <= nal_type <= 40
    )


def _is_plausible_h264_nal(nal: bytes) -> bool:
    return (
        len(nal) >= 3
        and nal[0] & 0x80 == 0
        and _h264_nal_type(nal)
        in {
            1,
            5,
            6,
            7,
            8,
            9,
        }
    )


def _h264_nal_type(nal: bytes) -> int:
    return nal[0] & 0x1F if nal else 0


def _h264_annexb_nal_spans(data: bytes) -> list[tuple[int, int, int]]:
    spans: list[tuple[int, int, int]] = []
    start = 0
    while True:
        start_code = _find_h264_annexb_start_code(data, start)
        if start_code is None:
            break
        offset, nal_start = start_code
        spans.append((offset, nal_start, len(data)))
        start = nal_start
    if not spans:
        return spans
    return [
        (offset, nal_start, spans[index + 1][0] if index + 1 < len(spans) else len(data))
        for index, (offset, nal_start, _end) in enumerate(spans)
    ]


def _find_h264_annexb_start_code(data: bytes, start: int) -> tuple[int, int] | None:
    offset = data.find(MPEG_START_CODE_PREFIX, start)
    if offset < 0:
        return None
    if offset > 0 and data[offset - 1] == 0:
        return offset - 1, offset + len(MPEG_START_CODE_PREFIX)
    return offset, offset + len(MPEG_START_CODE_PREFIX)


def _annexb_looks_like_h264(data: bytes) -> bool:
    return any(
        _h264_nal_type(data[nal_start:end]) in {1, 5, 6, 7, 8, 9}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _annexb_has_h264_vcl(data: bytes) -> bool:
    return any(
        _h264_nal_type(data[nal_start:end]) in {1, 5}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _annexb_looks_like_hevc(data: bytes) -> bool:
    return any(
        _is_plausible_hevc_nal(data[nal_start:end])
        and _hevc_nal_type(data[nal_start:end]) in {16, 17, 18, 19, 20, 21, 32, 33, 34, 39, 40}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _hevc_nal_type(nal: bytes) -> int:
    return (nal[0] >> 1) & 0x3F if nal else 0
