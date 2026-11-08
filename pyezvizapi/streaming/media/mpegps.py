"""Shared MPEG-PS packet bounds and timestamps; no transport dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from pyezvizapi.exceptions import PyEzvizError

MPEG_START_CODE_PREFIX = b"\x00\x00\x01"


_PACK_HEADER_STREAM_ID = 0xBA


_SYSTEM_HEADER_STREAM_ID = 0xBB


_PROGRAM_STREAM_MAP_ID = 0xBC


_PRIVATE_STREAM_1_ID = 0xBD


_PADDING_STREAM_ID = 0xBE


_PRIVATE_STREAM_2_ID = 0xBF


def _video_pes_payload_ranges(data: bytes) -> list[tuple[int, int]]:
    """Return bounded-capture video payloads from authoritative PS packet bounds.

    Scanning every byte for a video start code can mistake AAC payload bytes
    for PES headers and stop decryption of the remaining capture. The common
    packet walker skips non-video bodies by their lengths and retains existing
    pack-anchored recovery for overlong vendor video PES runs.
    """

    ranges: list[tuple[int, int]] = []
    packets = {packet.start: packet for packet in _mpeg_ps_video_decrypt_ranges(data)}
    offset = 0
    while offset < len(data) - 9:
        # Prefer authoritative bounds, including pack-anchored vendor recovery.
        # Between those ranges resynchronize one byte at a time, but always skip
        # a complete non-video packet's body rather than scanning its payload.
        packet = packets.get(offset)
        packet_end = packet.end if packet is not None else _mpeg_ps_packet_end(data, offset)
        if packet_end is None:
            if _is_zero_length_video_pes_start(data, offset):
                payload_start = _pes_payload_start(data, offset)
                assert payload_start is not None
                packet_end = _next_unbounded_video_pes_boundary(data, payload_start)
                packet_end = len(data) if packet_end is None else packet_end
            else:
                offset += 1
                continue
        if _is_video_pes_stream_id(data[offset + 3]):
            payload_start = _pes_payload_start(data, offset)
            if payload_start is not None and payload_start < packet_end:
                ranges.append((payload_start, packet_end))
        offset = packet_end
    return ranges


def _has_non_video_pes_packet(data: bytes, start: int, end: int) -> bool:
    """Return True when a non-video PES packet appears in the byte range."""

    i = start
    while i < end - 3:
        if data[i : i + 3] != MPEG_START_CODE_PREFIX:
            i += 1
            continue
        stream_id = data[i + 3]
        if _is_mpeg_ps_metadata_stream_id(stream_id):
            i += 4
            continue
        if _is_mpeg_ps_packet_start_id(stream_id) and not _is_video_pes_stream_id(stream_id):
            return True
        i += 4
    return False


@dataclass(frozen=True)
class _MpegPsPacketRange:
    """Parsed MPEG-PS packet bounds."""

    start: int
    end: int
    stream_id: int


def mpeg_ps_complete_prefix_length(data: bytes | bytearray) -> int:
    """Return the length of the fully parsed MPEG-PS packet prefix."""

    ranges = _mpeg_ps_complete_packet_ranges(data)
    return ranges[-1].end if ranges else 0


def mpeg_ps_decryptable_prefix_length(data: bytes | bytearray) -> int:
    """Return complete MPEG-PS bytes that are safe to decrypt independently.

    A video NAL can continue across adjacent video PES packets. Keep any trailing
    video PES run buffered until a following non-video packet or stream end lets
    the decryptor see the full run in one call.
    """

    ranges = _mpeg_ps_complete_packet_ranges(data)
    if not ranges:
        return 0

    decryptable_end = ranges[-1].end
    trailing_video_start = decryptable_end
    for packet_range in reversed(ranges):
        if _is_mpeg_ps_metadata_stream_id(packet_range.stream_id):
            continue
        if not _is_video_pes_stream_id(packet_range.stream_id):
            break
        trailing_video_start = packet_range.start
    return trailing_video_start if trailing_video_start != decryptable_end else decryptable_end


def _mpeg_ps_complete_packet_ranges(
    data: bytes | bytearray,
    *,
    include_trailing_unbounded_video: bool = False,
    start_offset: int = 0,
) -> list[_MpegPsPacketRange]:
    """Return complete packet ranges with absolute bounds from ``start_offset``."""

    view = data if isinstance(data, bytes) else bytes(data)
    ranges: list[_MpegPsPacketRange] = []
    i = start_offset
    while i < len(view):
        packet_end = _mpeg_ps_packet_end(view, i)
        if packet_end is not None:
            ranges.append(_MpegPsPacketRange(i, packet_end, view[i + 3]))
            i = packet_end
            continue

        if (
            i + 9 <= len(view)
            and view[i : i + 3] == MPEG_START_CODE_PREFIX
            and 0xC0 <= view[i + 3] <= 0xEF
            and int.from_bytes(view[i + 4 : i + 6], "big") == 0
        ):
            payload_start = _pes_payload_start(view, i)
            if payload_start is None:
                break
            next_start = _next_unbounded_video_pes_boundary(view, payload_start)
            if next_start is None:
                if (
                    include_trailing_unbounded_video
                    and _is_video_pes_stream_id(view[i + 3])
                    and payload_start <= len(view)
                ):
                    ranges.append(_MpegPsPacketRange(i, len(view), view[i + 3]))
                    i = len(view)
                    continue
                break
            ranges.append(_MpegPsPacketRange(i, next_start, view[i + 3]))
            i = next_start
            continue

        break
    return ranges


def _mpeg_ps_anchored_recovery_start(data: bytes, start: int, pack_start: int) -> int:
    """Find a packet chain reaching the known pack, not an isolated lookalike.

    Ciphertext can contain locally valid packet headers. Only boundaries whose
    declared ends lead contiguously to the pack are evidence of real framing.
    Resolve candidates backward once, avoiding repeated suffix walks/copies.
    """

    candidates: list[tuple[int, int | None]] = []
    candidate = data.find(MPEG_START_CODE_PREFIX, start, pack_start)
    while candidate >= 0:
        packet_end = _mpeg_ps_packet_end(data, candidate)
        if packet_end is not None or _is_zero_length_video_pes_start(data, candidate):
            candidates.append((candidate, packet_end))
        candidate = data.find(MPEG_START_CODE_PREFIX, candidate + 3, pack_start)

    anchored = {pack_start}
    next_boundary = pack_start
    recovery_start = pack_start
    for candidate, packet_end in reversed(candidates):
        # The normal walker bounds a zero-length video at the next locally
        # valid packet; require that boundary to be independently anchored too.
        boundary = next_boundary if packet_end is None else packet_end
        if boundary in anchored:
            anchored.add(candidate)
            recovery_start = candidate
        next_boundary = candidate
    return recovery_start


def _mpeg_ps_video_decrypt_ranges(data: bytes) -> list[_MpegPsPacketRange]:
    """Recover overlong EZVIZ video PES runs for the bounded decrypt pass.

    Some cloud cameras advertise a capped PES length while continuing the
    encrypted video payload until the next pack. The strict parser must retain
    its prefix semantics for streaming; only the complete-capture decrypt pass
    may bridge such a gap, anchored by a valid MPEG-2 pack header.
    """

    ranges: list[_MpegPsPacketRange] = []
    offset = 0
    while offset < len(data):
        parsed = _mpeg_ps_complete_packet_ranges(
            data, include_trailing_unbounded_video=True, start_offset=offset
        )
        if not parsed:
            break
        ranges.extend(parsed)
        parsed_end = ranges[-1].end
        if parsed_end >= len(data):
            break
        next_pack = data.find(b"\x00\x00\x01\xba", parsed_end)
        while next_pack >= 0 and not (
            next_pack + 14 <= len(data) and _is_mpeg2_pack_header(data, next_pack)
        ):
            next_pack = data.find(b"\x00\x00\x01\xba", next_pack + 4)
        if next_pack < 0:
            break
        if _is_video_pes_stream_id(ranges[-1].stream_id):
            previous = ranges[-1]
            # A vendor continuation can bridge unparsed bytes, but must never
            # include any later packet's clear header in the video payload.
            # Resume the authoritative walker at that packet so its body is
            # bounded independently, including zero-length video PES packets.
            recovery_end = _mpeg_ps_anchored_recovery_start(data, parsed_end, next_pack)
            ranges[-1] = _MpegPsPacketRange(previous.start, recovery_end, previous.stream_id)
            offset = recovery_end
            continue
        offset = next_pack
    return ranges


def _mpeg_ps_packet_pts(data: bytes, start: int, end: int) -> int | None:
    """Read a complete, marker-validated MPEG-2 PES presentation timestamp."""

    if start + 14 > end or (data[start + 6] & 0xC0) != 0x80 or data[start + 8] < 5:
        return None
    if start + 9 + data[start + 8] > end:
        return None
    flags = data[start + 7] & 0xC0
    if flags not in (0x80, 0xC0) or (flags == 0xC0 and data[start + 8] < 10):
        return None
    encoded = data[start + 9 : start + 14]
    prefix = 0x20 if flags == 0x80 else 0x30
    if (encoded[0] & 0xF0) != prefix or not all(encoded[index] & 1 for index in (0, 2, 4)):
        return None
    if flags == 0xC0:
        dts = data[start + 14 : start + 19]
        if (dts[0] & 0xF0) != 0x10 or not all(dts[index] & 1 for index in (0, 2, 4)):
            return None
    return (
        ((encoded[0] >> 1) & 7) << 30
        | encoded[1] << 22
        | (encoded[2] >> 1) << 15
        | encoded[3] << 7
        | encoded[4] >> 1
    )


def mpeg_ps_video_pts_span_seconds(
    data: bytes, *, max_gap_seconds: float | None = None
) -> float | None:
    """Measure video presentation span from clear MPEG-PS PES headers.

    Video bodies may be encrypted, but their PES timestamps remain clear. Return
    ``None`` when no valid video PTS is available rather than guessing from bytes.
    ``max_gap_seconds`` treats sparse or jumped adjacent timestamps as ambiguous.
    """

    timestamps: list[int] = []
    for packet in _mpeg_ps_video_decrypt_ranges(data):
        start = packet.start
        if not _is_video_pes_stream_id(packet.stream_id) or start + 14 > len(data):
            continue
        pts = _mpeg_ps_packet_pts(data, start, packet.end)
        if pts is None:
            continue
        timestamps.append(pts)
    if len(timestamps) < 2:
        return None
    wrap = 1 << 33
    transition_window = 5 * 90_000
    wraps = 0
    for previous, current in pairwise(timestamps):
        if current >= previous:
            if max_gap_seconds is not None and current - previous > max_gap_seconds * 90_000:
                # Sparse or discontinuous PES timing cannot prove coverage.
                return None
            continue
        if (
            previous >= wrap - transition_window
            and current <= transition_window
            and wrap - previous + current <= transition_window
        ):
            wraps += 1
            continue
        # A reset, reordered PTS, or sparse boundary crossing is ambiguous;
        # the caller must probe the staged media instead of guessing a span.
        return None
    return (timestamps[-1] + wraps * wrap - timestamps[0]) / 90_000


def _mpeg_ps_packet_end(data: bytes, start: int) -> int | None:
    """Return the end offset for a complete MPEG-PS packet at ``start``."""

    packet_end = None
    if start + 4 <= len(data) and data[start : start + 3] == MPEG_START_CODE_PREFIX:
        stream_id = data[start + 3]
        if (
            stream_id == _PACK_HEADER_STREAM_ID
            and start + 14 <= len(data)
            and _is_mpeg2_pack_header(data, start)
        ):
            stuffing_length = data[start + 13] & 0x07
            candidate_end = start + 14 + stuffing_length
            if candidate_end <= len(data):
                packet_end = candidate_end
        elif _is_mpeg_ps_packet_start_id(stream_id) and start + 6 <= len(data):
            packet_length = int.from_bytes(data[start + 4 : start + 6], "big")
            candidate_end = start + 6 + packet_length
            if packet_length and candidate_end <= len(data):
                if _is_video_pes_stream_id(stream_id) or (stream_id == _PRIVATE_STREAM_1_ID):
                    payload_start = _pes_payload_start(data, start)
                elif 0xC0 <= stream_id <= 0xDF:
                    payload_start = _pes_payload_start(data, start) or start + 6
                else:
                    payload_start = start + 6
                if payload_start is not None and payload_start <= candidate_end:
                    packet_end = candidate_end
    return packet_end


def _is_mpeg2_pack_header(data: bytes, start: int) -> bool:
    """Return True when ``start`` has MPEG-2 pack-header marker bits."""

    return (
        (data[start + 4] & 0xC4) == 0x44
        and (data[start + 6] & 0x04) == 0x04
        and (data[start + 8] & 0x04) == 0x04
        and (data[start + 12] & 0x01) == 0x01
        and (data[start + 13] & 0xF8) == 0xF8
    )


def _pes_payload_start(data: bytes, packet_start: int) -> int | None:
    """Return the payload start for a complete-enough PES header."""

    if packet_start + 9 > len(data):
        return None
    stream_id = data[packet_start + 3]
    flags = data[packet_start + 6]
    if (flags & 0xC0) == 0x80:
        return packet_start + 9 + data[packet_start + 8]
    if 0xC0 <= stream_id <= 0xEF or stream_id == _PRIVATE_STREAM_1_ID:
        return None
    return packet_start + 6


def _next_complete_mpeg_ps_packet_start(data: bytes, start: int) -> int | None:
    """Return the next start code that parses as a complete MPEG-PS packet."""

    i = start
    while i < len(data) - 3:
        if _mpeg_ps_packet_end(data, i) is not None:
            return i
        i += 1
    return None


def _next_unbounded_video_pes_boundary(data: bytes, start: int) -> int | None:
    """Return the next packet boundary after a zero-length video PES payload."""

    i = start
    while i < len(data) - 3:
        if _mpeg_ps_packet_end(data, i) is not None or _is_zero_length_video_pes_start(
            data,
            i,
        ):
            return i
        i += 1
    return None


def _is_zero_length_video_pes_start(data: bytes, start: int) -> bool:
    """Return True for a complete-enough zero-length video PES header."""

    return (
        start + 9 <= len(data)
        and data[start : start + 3] == MPEG_START_CODE_PREFIX
        and _is_video_pes_stream_id(data[start + 3])
        and int.from_bytes(data[start + 4 : start + 6], "big") == 0
        and _pes_payload_start(data, start) is not None
    )


def _is_video_pes_stream_id(stream_id: int) -> bool:
    """Return True for MPEG-PS video PES stream IDs."""

    return 0xE0 <= stream_id <= 0xEF


def _is_mpeg_ps_metadata_stream_id(stream_id: int) -> bool:
    """Return True for MPEG-PS container metadata that carries no ES bytes."""

    return stream_id in {
        _PACK_HEADER_STREAM_ID,
        _SYSTEM_HEADER_STREAM_ID,
        _PROGRAM_STREAM_MAP_ID,
        _PADDING_STREAM_ID,
    }


def _is_mpeg_ps_packet_start_id(stream_id: int) -> bool:
    """Return True for MPEG-PS packet start codes, excluding Annex B NAL IDs."""

    return (
        stream_id
        in {
            _PACK_HEADER_STREAM_ID,
            _SYSTEM_HEADER_STREAM_ID,
            _PROGRAM_STREAM_MAP_ID,
            _PRIVATE_STREAM_1_ID,
            _PADDING_STREAM_ID,
            _PRIVATE_STREAM_2_ID,
        }
        or 0xC0 <= stream_id <= 0xEF
    )


def _next_mpeg_ps_packet_start(data: bytes, start: int) -> int | None:
    """Return the next plausible MPEG-PS packet start code at or after ``start``."""

    i = start
    while i < len(data) - 3:
        if data[i : i + 3] == MPEG_START_CODE_PREFIX and _is_mpeg_ps_packet_start_id(data[i + 3]):
            return i
        i += 1
    return None


def validate_sd_playback_framing(
    data: bytes, *, vendor_trailer: bytes = b"\x24kih\x04\x03\x02\x01"
) -> None:
    """Require complete contiguous PS framing, including the final packet.

    Reuse the bounded vendor-video recovery used by the decryptor, but never
    let its successfully parsed prefix hide an incomplete PES or skipped gap.
    Zero-length video PES may legitimately run to EOF; a recognizable PS packet
    start inside that payload must not hide a truncated following packet.
    """
    framed = data.removesuffix(vendor_trailer)
    framed = framed[:-4] if framed.endswith(b"\x00\x00\x01\xb9") else framed
    cursor = 0
    for packet in _mpeg_ps_video_decrypt_ranges(framed):
        if packet.start != cursor:
            raise PyEzvizError("SD playback has incomplete MPEG-PS framing")
        if (
            0xE0 <= packet.stream_id <= 0xEF
            and int.from_bytes(framed[packet.start + 4 : packet.start + 6], "big") == 0
        ):
            payload = _pes_payload_start(framed, packet.start)
            boundary = _next_mpeg_ps_packet_start(framed, payload) if payload is not None else None
            if boundary is not None and boundary < packet.end:
                raise PyEzvizError("SD playback has incomplete MPEG-PS framing")
        cursor = packet.end
    if cursor != len(framed):
        raise PyEzvizError("SD playback has incomplete MPEG-PS framing")
