# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""payloads implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media.remux import BoundedStderrTail as _StaticBoundedStderrTail

if TYPE_CHECKING:
    import pyezvizapi._typing.local_stream as _owner_types


def _idmx_local_frame_rtp_packet(
    frame: bytes, header_size: int, *, _owner: _ModuleType
) -> _owner_types.RtpPacket | None:
    """Normalize standards-shaped and legacy IDMX headers into one RTP model."""
    rtp_frame = _owner._idmx_local_rtp_frame(frame)
    if rtp_frame is not None:
        packet = _owner.parse_rtp_packet(rtp_frame, idmx=True)
        if header_size == 13 and packet.extension_profile is None:
            packet = _owner.replace(
                packet, payload=_owner._strip_idmx_command_h264_record_trailer(packet.payload)
            )
        return _owner._strip_legacy_idmx_video_wrapper(packet)
    transport = _owner._idmx_local_frame_transport_fields(frame, header_size)
    payload_type = transport.get("rtp_payload_type")
    sequence = transport.get("sequence_number")
    timestamp = transport.get("rtp_timestamp")
    if not all(isinstance(value, int) for value in (payload_type, sequence, timestamp)):
        return None
    return _owner._strip_legacy_idmx_video_wrapper(
        _owner.RtpPacket(
            payload=_owner._idmx_local_frame_media_body(frame, header_size),
            payload_type=_owner.cast("int", payload_type),
            sequence=_owner.cast("int", sequence),
            timestamp=_owner.cast("int", timestamp),
            ssrc=0,
            marker=bool(transport.get("rtp_marker")),
        )
    )


def _summarize_idmx_h264_local_frame(  # noqa: PLR0911 -- explicit runtime context plus retained signature
    frame: bytes, frame_index: int, *, h264_payload_types: frozenset[int], _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    header_size = _owner._idmx_local_frame_header_size(frame)
    sample: dict[str, _owner_types.Any] = {
        "index": frame_index,
        "frame_length": len(frame),
        "header_size": header_size,
    }
    if header_size is None:
        sample["kind"] = "unknown"
        sample["body_length"] = len(frame)
        sample["body_sha256"] = _owner.hashlib.sha256(frame).hexdigest()
        return sample
    transport = _owner._idmx_local_frame_transport_fields(frame, header_size)
    sample.update(transport)
    body = _owner._idmx_local_frame_media_body(frame, header_size)
    sample["body_length"] = len(body)
    sample["body_sha256"] = _owner.hashlib.sha256(body).hexdigest()
    is_h264_transport = _owner._idmx_local_frame_is_h264_transport(
        frame, header_size, payload_types=h264_payload_types
    )
    if is_h264_transport and _owner._looks_like_idmx_h264_fu_a_frame(body):
        fu_header = body[1]
        sample["kind"] = "h264_fu_a"
        sample["nal_type"] = fu_header & 31
        sample["fu_start"] = bool(fu_header & 128)
        sample["fu_end"] = bool(fu_header & 64)
        return sample
    if is_h264_transport and _owner._looks_like_idmx_h264_clear_nal(body):
        sample["kind"] = "h264_nal"
        sample["nal_type"] = _owner._h264_nal_type(body)
        return sample
    if _owner._looks_like_idmx_hevc_parameter_frame(body):
        sample["kind"] = "hevc_parameter"
        return sample
    if _owner._looks_like_idmx_hevc_media_frame(body):
        sample["kind"] = "hevc_media"
        return sample
    if is_h264_transport and _owner._looks_like_idmx_hevc_direct_frame(body):
        sample["kind"] = "hevc_media"
        sample["hevc_nal_type"] = _owner._hevc_nal_type(body)
        return sample
    sample["kind"] = "unknown"
    return sample


def _idmx_local_frame_transport_fields(
    frame: bytes, header_size: int, *, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized RTP-like fields from an IDMX local frame header."""
    if _owner._is_complete_idmx_rtp_frame(frame):
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        assert packet is not None
        return {
            "rtp_marker": packet.marker,
            "rtp_payload_type": packet.payload_type,
            "sequence_number": packet.sequence,
            "rtp_timestamp": packet.timestamp,
        }
    sentinel_offset = header_size - len(_owner.IDMX_LOCAL_FRAME_SENTINEL)
    rtp_header_offset = sentinel_offset - 8
    if rtp_header_offset < 0 or len(frame) < sentinel_offset:
        return {}
    header = frame[rtp_header_offset:sentinel_offset]
    if len(header) < 8:
        return {}
    return {
        "rtp_marker": bool(header[1] & 128),
        "rtp_payload_type": header[1] & 127,
        "sequence_number": int.from_bytes(header[2:4], "big"),
        "rtp_timestamp": int.from_bytes(header[4:8], "big"),
    }


def _idmx_local_frame_is_h264_transport(
    frame: bytes, header_size: int, *, payload_types: frozenset[int], _owner: _ModuleType
) -> bool:
    transport = _owner._idmx_local_frame_transport_fields(frame, header_size)
    return transport.get("rtp_payload_type") in payload_types


def _idmx_local_frame_sequence_number(
    frame: bytes, header_size: int, *, _owner: _ModuleType
) -> int | None:
    value = _owner._idmx_local_frame_transport_fields(frame, header_size).get("sequence_number")
    return value if isinstance(value, int) else None


def _idmx_local_frame_rtp_timestamp(
    frame: bytes, header_size: int, *, _owner: _ModuleType
) -> int | None:
    value = _owner._idmx_local_frame_transport_fields(frame, header_size).get("rtp_timestamp")
    return value if isinstance(value, int) else None


def _idmx_local_frame_rtp_marker(frame: bytes, header_size: int, *, _owner: _ModuleType) -> bool:
    return bool(_owner._idmx_local_frame_transport_fields(frame, header_size).get("rtp_marker"))


def _idmx_rtp_extension(frame: bytes, *, _owner: _ModuleType) -> tuple[int, bytes] | None:
    """Return the profile and bytes from a complete RTP header extension."""
    if not _owner._is_complete_idmx_rtp_frame(frame):
        return None
    packet = _owner.parse_rtp_packet(_owner._idmx_local_rtp_frame(frame) or frame)
    if packet.extension_profile is None:
        return None
    return (packet.extension_profile, packet.extension_data)


def _idmx_audio_descriptor(packets: list[bytes], *, _owner: _ModuleType) -> tuple[int, int] | None:
    """Read sample rate and channels from an IDMX 0x43 audio descriptor."""
    profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile.audio_metadata


def _idmx_audio_metadata(
    packets: list[bytes], _media_key: str | bytes, *, _owner: _ModuleType
) -> tuple[int, int] | None:
    """Return authoritative AAC metadata from the native stream descriptor."""
    return _owner._idmx_audio_descriptor(packets)


def _idmx_audio_payload_types(packets: list[bytes], *, _owner: _ModuleType) -> frozenset[int]:
    """Return the AAC payload route advertised by startup stream metadata."""
    profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile.codec_payload_types(
        "aac", fallback_payload_types=_owner.DEFAULT_AAC_PAYLOAD_TYPES
    )


def _idmx_local_packets_have_aac(packets: list[bytes], *, _owner: _ModuleType) -> bool:
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None and _owner.rtp_packet_is_idmx_aac(packet):
            return True
    return False


def _idmx_local_video_frame_rate(packets: list[bytes], *, _owner: _ModuleType) -> str | None:
    """Estimate video frame rate from the standard 90 kHz RTP timestamp clock."""
    rtp_packets: list[_owner_types.RtpPacket] = []
    native_wrapper = False
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            if packet.extension_profile == 16384 and packet.extension_data.startswith(b"\x80\x06"):
                native_wrapper = True
            rtp_packets.append(packet)
    advertised_rate = _owner.idmx_video_frame_rate(rtp_packets)
    if advertised_rate is not None:
        return advertised_rate
    if native_wrapper:
        return None
    h264_types, hevc_types = _owner._idmx_local_supported_video_payload_types(packets)
    routed_video_payload_types = h264_types | hevc_types
    route_epoch_profile = _owner.RtpRouteProfile()
    timestamps: list[int] = []
    for packet in rtp_packets:
        route_epoch_profile.absorb(packet)
        active_route_descriptor = _owner._rtp_packet_route_descriptor(route_epoch_profile, packet)
        if (
            packet.payload_type in routed_video_payload_types
            and (active_route_descriptor is None or active_route_descriptor.media_kind == "video")
        ) and (not timestamps or timestamps[-1] != packet.timestamp):
            timestamps.append(packet.timestamp)
    deltas = sorted(
        (
            delta
            for previous, current in _owner.pairwise(timestamps)
            if 0 < (delta := (current - previous & 4294967295)) <= _owner.IDMX_VIDEO_RTP_CLOCK_RATE
        )
    )
    if not deltas:
        return str(_owner.IDMX_DEFAULT_VIDEO_FRAME_RATE)
    median_delta = deltas[len(deltas) // 2]
    rate = _owner.Fraction(_owner.IDMX_VIDEO_RTP_CLOCK_RATE, median_delta).limit_denominator(1001)
    return str(rate.numerator) if rate.denominator == 1 else f"{rate.numerator}/{rate.denominator}"


def _merge_idmx_h264_frame_summary(
    summary: dict[str, _owner_types.Any],
    frame_summary: dict[str, _owner_types.Any],
    *,
    _owner: _ModuleType,
) -> None:
    h264 = summary["h264"]
    hevc = summary["hevc"]
    assert isinstance(h264, dict)
    assert isinstance(hevc, dict)
    kind = frame_summary.get("kind")
    if kind == "h264_fu_a":
        h264["fu_a"] = int(h264["fu_a"]) + 1
        if frame_summary.get("fu_start"):
            h264["fu_a_start"] = int(h264["fu_a_start"]) + 1
        if frame_summary.get("fu_end"):
            h264["fu_a_end"] = int(h264["fu_a_end"]) + 1
        _owner._increment_h264_nal_type_count(h264, frame_summary.get("nal_type"))
        return
    if kind == "h264_nal":
        h264["clear_nal"] = int(h264["clear_nal"]) + 1
        _owner._increment_h264_nal_type_count(h264, frame_summary.get("nal_type"))
        return
    if kind == "hevc_parameter":
        hevc["parameter"] = int(hevc["parameter"]) + 1
        return
    if kind == "hevc_media":
        hevc["media"] = int(hevc["media"]) + 1
        return
    h264["unknown"] = int(h264["unknown"]) + 1


def _increment_h264_nal_type_count(
    h264: dict[str, _owner_types.Any], nal_type: _owner_types.Any, *, _owner: _ModuleType
) -> None:
    names = {1: "non_idr", 5: "idr", 6: "sei", 7: "sps", 8: "pps", 9: "aud"}
    name = names.get(nal_type)
    if name is None:
        h264["unknown"] = int(h264["unknown"]) + 1
        return
    h264[name] = int(h264[name]) + 1


def _record_idmx_h264_nal_unit_summary(  # noqa: PLR0911, PLR0912 -- explicit runtime context plus retained signature
    summary: dict[str, _owner_types.Any],
    frame: bytes,
    frame_summary: dict[str, _owner_types.Any],
    *,
    active_fu: dict[str, _owner_types.Any] | None,
    h264_payload_types: frozenset[int],
    _owner: _ModuleType,
) -> dict[str, _owner_types.Any] | None:
    header_size = frame_summary.get("header_size")
    if not isinstance(header_size, int):
        return active_fu
    if not _owner._idmx_local_frame_is_h264_transport(
        frame, header_size, payload_types=h264_payload_types
    ):
        return active_fu
    body = _owner._idmx_local_frame_media_body(frame, header_size)
    if _owner._looks_like_idmx_h264_clear_nal(body):
        _owner._append_idmx_h264_nal_unit_sample(
            summary,
            {
                "nal_type": _owner._h264_nal_type(body),
                "start_frame_index": frame_summary["index"],
                "start_sequence": frame_summary.get("sequence_number"),
                "end_sequence": frame_summary.get("sequence_number"),
                "rtp_timestamp": frame_summary.get("rtp_timestamp"),
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(body),
                "sha256": _owner.hashlib.sha256(body),
            },
            complete=True,
            end_frame_index=frame_summary["index"],
        )
        return None
    if not _owner._looks_like_idmx_h264_fu_a_frame(body):
        return active_fu
    fu_header = body[1]
    is_start = bool(fu_header & 128)
    is_end = bool(fu_header & 64)
    nal_type = fu_header & 31
    sequence_number = frame_summary.get("sequence_number")
    rtp_timestamp = frame_summary.get("rtp_timestamp")
    if not is_start and active_fu is None:
        _owner._increment_idmx_h264_nal_unit_counter(summary, "discarded_fu_a_fragments")
        return None
    if is_start and active_fu is not None:
        _owner._increment_idmx_h264_nal_unit_counter(summary, "restart_count")
        _owner._increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _owner._append_idmx_h264_nal_unit_sample(
            summary, active_fu, complete=False, end_frame_index=None
        )
        active_fu = None
    if active_fu is not None and (
        not _owner._rtp_fragment_continues(
            _owner._RtpFragmentedNal(
                data=bytearray(),
                last_sequence=active_fu.get("last_sequence")
                if isinstance(active_fu.get("last_sequence"), int)
                else None,
                rtp_timestamp=active_fu.get("rtp_timestamp")
                if isinstance(active_fu.get("rtp_timestamp"), int)
                else None,
            ),
            sequence_number=sequence_number if isinstance(sequence_number, int) else None,
            rtp_timestamp=rtp_timestamp if isinstance(rtp_timestamp, int) else None,
        )
    ):
        if (
            isinstance(active_fu.get("last_sequence"), int)
            and isinstance(sequence_number, int)
            and (int(active_fu["last_sequence"]) + 1 & 65535 != sequence_number)
        ):
            active_fu["sequence_gap_count"] = int(active_fu["sequence_gap_count"]) + 1
            _owner._increment_idmx_h264_nal_unit_counter(summary, "sequence_gap_count")
        if (
            isinstance(active_fu.get("rtp_timestamp"), int)
            and isinstance(rtp_timestamp, int)
            and (int(active_fu["rtp_timestamp"]) != rtp_timestamp)
        ):
            _owner._increment_idmx_h264_nal_unit_counter(summary, "timestamp_change_count")
        _owner._increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _owner._append_idmx_h264_nal_unit_sample(
            summary, active_fu, complete=False, end_frame_index=None
        )
        _owner._increment_idmx_h264_nal_unit_counter(summary, "discarded_fu_a_fragments")
        return None
    if is_start:
        reconstructed_header = bytes([body[0] & 224 | nal_type])
        active_fu = {
            "nal_type": nal_type,
            "start_frame_index": frame_summary["index"],
            "start_sequence": sequence_number,
            "end_sequence": sequence_number,
            "rtp_timestamp": rtp_timestamp,
            "last_sequence": None,
            "sequence_gap_count": 0,
            "fragment_count": 0,
            "payload_bytes": len(reconstructed_header),
            "sha256": _owner.hashlib.sha256(reconstructed_header),
        }
    if active_fu is None:
        return None
    if isinstance(sequence_number, int):
        active_fu["last_sequence"] = sequence_number
        active_fu["end_sequence"] = sequence_number
    hasher = active_fu["sha256"]
    assert hasattr(hasher, "update")
    hasher.update(body[2:])
    active_fu["fragment_count"] = int(active_fu["fragment_count"]) + 1
    active_fu["payload_bytes"] = int(active_fu["payload_bytes"]) + max(len(body) - 2, 0)
    if is_end:
        _owner._append_idmx_h264_nal_unit_sample(
            summary, active_fu, complete=True, end_frame_index=frame_summary["index"]
        )
        return None
    return active_fu


def _increment_idmx_h264_nal_unit_counter(
    summary: dict[str, _owner_types.Any], name: str, *, _owner: _ModuleType
) -> None:
    nal_units = summary["h264_nal_units"]
    assert isinstance(nal_units, dict)
    nal_units[name] = int(nal_units.get(name, 0)) + 1


def _append_idmx_h264_nal_unit_sample(
    summary: dict[str, _owner_types.Any],
    unit: dict[str, _owner_types.Any],
    *,
    complete: bool,
    end_frame_index: _owner_types.Any,
    _owner: _ModuleType,
) -> None:
    nal_units = summary["h264_nal_units"]
    assert isinstance(nal_units, dict)
    samples = nal_units["samples"]
    assert isinstance(samples, list)
    if len(samples) >= int(nal_units["sample_limit"]):
        nal_units["truncated"] = True
        return
    hasher = unit["sha256"]
    assert hasattr(hasher, "hexdigest")
    samples.append(
        {
            "nal_type": unit["nal_type"],
            "start_frame_index": unit["start_frame_index"],
            "end_frame_index": end_frame_index,
            "start_sequence": unit.get("start_sequence"),
            "end_sequence": unit.get("end_sequence"),
            "rtp_timestamp": unit.get("rtp_timestamp"),
            "sequence_gap_count": unit.get("sequence_gap_count"),
            "fragment_count": unit["fragment_count"],
            "payload_bytes": unit["payload_bytes"],
            "complete": complete,
            "sha256": hasher.hexdigest(),
        }
    )


def _looks_like_idmx_local_payload(payload: bytes, *, _owner: _ModuleType) -> bool:
    return _owner._idmx_local_frame_header_size(payload) is not None or any(
        _owner._iter_idmx_local_frames(payload)
    )


def _looks_like_length_prefixed_idmx_local_payload(payload: bytes, *, _owner: _ModuleType) -> bool:
    if len(payload) < 4:
        return False
    prefixed_length = int.from_bytes(payload[:4], "little")
    frame = payload[4:]
    header_size = _owner._idmx_local_frame_header_size(frame)
    return (
        header_size is not None
        and prefixed_length >= header_size
        and (prefixed_length <= len(frame))
        and (_owner._idmx_local_frame_header_score(frame, header_size) is not None)
    )


def _iter_idmx_local_frames(payload: bytes, *, _owner: _ModuleType) -> _owner_types.Iterator[bytes]:  # noqa: PLR0912 -- explicit runtime context plus retained signature
    search_start = 0
    while True:
        sentinel_offset = payload.find(_owner.IDMX_LOCAL_FRAME_SENTINEL, search_start)
        if sentinel_offset < 0:
            break
        valid_frame_starts: list[tuple[int, int]] = []
        prefixed_frames: list[tuple[int, int, int]] = []
        for local_sentinel_offset in _owner.IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
            frame_start = sentinel_offset - local_sentinel_offset
            if frame_start < 0:
                continue
            header_size = _owner._idmx_local_frame_header_size(payload[frame_start:])
            header_score = _owner._idmx_local_frame_header_score(payload[frame_start:], header_size)
            if header_size is None or header_score is None:
                continue
            prefix_start = frame_start - 4
            if prefix_start >= 0:
                prefixed_length = int.from_bytes(payload[prefix_start:frame_start], "little")
                frame_end = frame_start + prefixed_length
                if prefixed_length >= header_size and frame_end <= len(payload):
                    prefixed_frames.append((frame_start, frame_end, header_score))
                else:
                    valid_frame_starts.append((frame_start, header_score))
            else:
                valid_frame_starts.append((frame_start, header_score))
        if prefixed_frames:
            frame_start, frame_end, _score = min(
                prefixed_frames, key=lambda item: (item[1], item[2])
            )
            yield from _owner._iter_idmx_local_frame_or_nested(payload[frame_start:frame_end])
            search_start = frame_end
            continue
        if valid_frame_starts:
            frame_start, _score = min(valid_frame_starts, key=lambda item: item[1])
            next_sentinel_offset = payload.find(
                _owner.IDMX_LOCAL_FRAME_SENTINEL, sentinel_offset + 1
            )
            if next_sentinel_offset < 0:
                yield payload[frame_start:]
                break
            frame_end = next_sentinel_offset
            next_frame_starts: list[tuple[int, int]] = []
            for local_sentinel_offset in _owner.IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
                next_frame_start = next_sentinel_offset - local_sentinel_offset
                next_header_size = _owner._idmx_local_frame_header_size(payload[next_frame_start:])
                next_header_score = _owner._idmx_local_frame_header_score(
                    payload[next_frame_start:], next_header_size
                )
                if (
                    next_frame_start > frame_start
                    and next_header_size is not None
                    and (next_header_score is not None)
                ):
                    next_frame_starts.append((next_frame_start, next_header_score))
            if next_frame_starts:
                next_frame_start, _score = min(
                    next_frame_starts, key=lambda item: (item[1], item[0])
                )
                frame_end = _owner._idmx_frame_end_before_next_prefix(payload, next_frame_start)
            yield from _owner._iter_idmx_local_frame_or_nested(payload[frame_start:frame_end])
            search_start = frame_end
            continue
        search_start = sentinel_offset + 1


def _iter_idmx_local_frame_or_nested(
    frame: bytes, *, video_payload_types: frozenset[int], _owner: _ModuleType
) -> _owner_types.Iterator[bytes]:
    """Yield one IDMX frame, or nested frames from command-port aggregate records."""
    header_size = _owner._idmx_local_frame_header_size(frame)
    if header_size is None:
        yield frame
        return
    body = frame[header_size:]
    if not body.startswith(b"\x00\x10") or not body.count(_owner.IDMX_LOCAL_FRAME_SENTINEL):
        yield frame
        return
    nested_frames = tuple(_owner._iter_idmx_local_frames(body))
    contains_media = _owner._idmx_local_frames_contain_routed_media(
        nested_frames, video_payload_types=video_payload_types
    )
    contains_descriptors = any(
        _owner.idmx_rtp_stream_descriptors((packet,))
        for nested in nested_frames
        if (nested_header_size := _owner._idmx_local_frame_header_size(nested)) is not None
        if (packet := _owner._idmx_local_frame_rtp_packet(nested, nested_header_size)) is not None
    )
    if not contains_media and (not contains_descriptors):
        yield frame
        return
    yield from nested_frames


def _iter_idmx_local_packet_frame(
    packet: bytes, *, video_payload_types: frozenset[int], _owner: _ModuleType
) -> _owner_types.Iterator[bytes]:
    if len(packet) >= 4:
        prefixed_length = int.from_bytes(packet[:4], "little")
        prefixed_frame = packet[4 : 4 + prefixed_length]
        prefixed_header_size = _owner._idmx_local_frame_header_size(prefixed_frame)
        if (
            prefixed_length == len(packet) - 4
            and prefixed_header_size is not None
            and (
                _owner._idmx_local_frame_header_score(prefixed_frame, prefixed_header_size)
                is not None
            )
        ):
            yield from _owner._iter_idmx_local_frame_or_nested(
                prefixed_frame, video_payload_types=video_payload_types
            )
            return
    if (
        _owner._is_complete_idmx_rtp_frame(packet)
        and (
            not _owner._idmx_local_packet_contains_aggregate_media_frame(
                packet, video_payload_types=video_payload_types
            )
        )
        and (not _owner._idmx_local_packet_contains_aggregate_descriptors(packet))
    ):
        yield packet
        return
    header_size = _owner._idmx_local_frame_header_size(packet)
    if (
        header_size is not None
        and _owner._idmx_local_frame_header_score(packet, header_size) is not None
    ):
        if _owner._idmx_local_packet_contains_aggregate_media_frame(
            packet, video_payload_types=video_payload_types
        ):
            yield from _owner._iter_idmx_local_frames(packet)
            return
        yield from _owner._iter_idmx_local_frame_or_nested(
            packet, video_payload_types=video_payload_types
        )
        return
    for frame in _owner._iter_idmx_local_frames(packet):
        yield from _owner._iter_idmx_local_frame_or_nested(
            frame, video_payload_types=video_payload_types
        )


def _idmx_local_packet_contains_aggregate_media_frame(
    packet: bytes, *, video_payload_types: frozenset[int], _owner: _ModuleType
) -> bool:
    frames = tuple(_owner._iter_idmx_local_frames(packet))
    if len(frames) <= 1:
        return False
    previous_sequence = _owner._idmx_local_packet_frame_sequence_number(frames[0])
    for frame in frames[1:]:
        sequence = _owner._idmx_local_packet_frame_sequence_number(frame)
        if (
            previous_sequence is None
            or sequence is None
            or sequence != previous_sequence + 1 & 65535
        ):
            return False
        previous_sequence = sequence
    return _owner._idmx_local_frames_contain_routed_media(
        frames, video_payload_types=video_payload_types
    )


def _idmx_local_packet_contains_aggregate_descriptors(
    packet: bytes, *, _owner: _ModuleType
) -> bool:
    frames = tuple(_owner._iter_idmx_local_frames(packet))
    if len(frames) <= 1:
        return False
    return any(
        _owner.idmx_rtp_stream_descriptors((parsed,))
        for frame in frames[1:]
        if (header_size := _owner._idmx_local_frame_header_size(frame)) is not None
        if (parsed := _owner._idmx_local_frame_rtp_packet(frame, header_size)) is not None
    )


def _idmx_local_frames_contain_routed_media(
    frames: tuple[bytes, ...], *, video_payload_types: frozenset[int], _owner: _ModuleType
) -> bool:
    """Return whether nested frames contain video under their final route profile."""
    parsed: list[tuple[_owner_types.RtpPacket, bytes]] = []
    profile = _owner.RtpRouteProfile()
    for frame in frames:
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is None:
            continue
        parsed.append((packet, _owner._idmx_local_frame_media_body(frame, header_size)))
        profile.absorb(packet)
    return any(
        (
            (profile.media_kind(packet) == "video" or packet.payload_type in video_payload_types)
            and (
                _owner._looks_like_idmx_hevc_direct_frame(body)
                or _owner._looks_like_idmx_h264_fu_a_frame(body)
                or _owner._looks_like_idmx_h264_clear_nal(body)
            )
            for packet, body in parsed
        )
    ) or any(_owner._idmx_local_frame_contains_media(frame) for frame in frames)


def _idmx_local_packet_frame_sequence_number(frame: bytes, *, _owner: _ModuleType) -> int | None:
    header_size = _owner._idmx_local_frame_header_size(frame)
    if header_size is None:
        return None
    return _owner._idmx_local_frame_sequence_number(frame, header_size)


def _iter_idmx_local_packet_frames(
    packets: list[bytes], *, _owner: _ModuleType
) -> _owner_types.Iterator[bytes]:
    profile = _owner.RtpRouteProfile()
    for packet in packets:
        for frame in _owner._iter_idmx_local_packet_frame(packet):
            header_size = _owner._idmx_local_frame_header_size(frame)
            if header_size is not None:
                parsed = _owner._idmx_local_frame_rtp_packet(frame, header_size)
                if parsed is not None:
                    profile.absorb(parsed)
    video_payload_types = frozenset(
        descriptor.payload_type
        for descriptor in profile.descriptors
        if descriptor.media_kind == "video"
    )
    for packet in packets:
        yield from _owner._iter_idmx_local_packet_frame(
            packet, video_payload_types=video_payload_types
        )


def _idmx_local_frame_contains_media(frame: bytes, *, _owner: _ModuleType) -> bool:
    header_size = _owner._idmx_local_frame_header_size(frame)
    if header_size is None:
        return False
    body = _owner._idmx_local_frame_media_body(frame, header_size)
    h264_transport = _owner._idmx_local_frame_is_h264_transport(frame, header_size)
    return (
        _owner._looks_like_idmx_hevc_parameter_frame(body)
        or _owner._looks_like_idmx_hevc_media_frame(body)
        or (h264_transport and _owner._looks_like_idmx_hevc_direct_frame(body))
        or (h264_transport and _owner._looks_like_idmx_h264_fu_a_frame(body))
        or (h264_transport and _owner._looks_like_idmx_h264_clear_nal(body))
    )


def _local_stream_packets_are_idmx(packets: list[bytes], *, _owner: _ModuleType) -> bool:
    return bool(packets) and _owner._looks_like_idmx_local_payload(packets[0])


def _unsupported_idmx_local_payload_error(*, _owner: _ModuleType) -> _owner_types.PyEzvizError:
    return _owner.PyEzvizError(
        "Unsupported encrypted EZVIZ local IDMX stream payload: decrypt-video is required"
    )


def _decrypt_idmx_local_packets_to_annexb(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    decrypt_hevc_parameter_sets: bool,
    _owner: _ModuleType,
) -> bytes:
    annexb, _authoritative_codec = _owner._decrypt_idmx_local_packets_to_annexb_with_codec(
        packets,
        media_key,
        nalu_header_size=nalu_header_size,
        decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
    )
    return annexb


def _decrypt_idmx_local_packets_to_annexb_with_codec(  # noqa: PLR0912, PLR0915 -- explicit runtime context plus retained signature
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    decrypt_hevc_parameter_sets: bool,
    _owner: _ModuleType,
) -> tuple[bytes, _owner_types.RtpVideoCodec | None]:
    """Decrypt local video and retain an authoritative descriptor codec."""
    routed_h264_payload_types, routed_hevc_payload_types = (
        _owner._idmx_local_supported_video_payload_types(packets)
    )
    if (
        routed_h264_payload_types
        and routed_hevc_payload_types
        and (routed_h264_payload_types != routed_hevc_payload_types)
    ):
        raise _owner.PyEzvizError(
            "Conflicting H.264 and HEVC routes in encrypted EZVIZ local stream"
        )
    final_route_is_authoritative_hevc = bool(
        routed_hevc_payload_types and (not routed_h264_payload_types)
    )
    authoritative_codec: _owner_types.RtpVideoCodec | None = None
    if final_route_is_authoritative_hevc:
        authoritative_codec = "hevc"
    elif routed_h264_payload_types and (not routed_hevc_payload_types):
        authoritative_codec = "h264"
    aes_key = _owner._local_media_aes_key(media_key)
    h264_nalu_header_size = (
        _owner.H264_NAL_HEADER_SIZE if nalu_header_size is None else nalu_header_size
    )
    output = bytearray()
    active_fu: _owner_types._RtpFragmentedNal | None = None
    active_h264_fu: _owner_types._RtpFragmentedNal | None = None
    hevc_evidence_seen = False
    route_epoch_profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            raise _owner.PyEzvizError("Mixed EZVIZ local stream payload formats are unsupported")
        body = _owner._idmx_local_frame_media_body(frame, header_size)
        rtp_packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if rtp_packet is not None:
            route_epoch_profile.absorb(rtp_packet)
        active_route_descriptor = next(
            (
                descriptor
                for descriptor in route_epoch_profile.descriptors
                if rtp_packet is not None and descriptor.payload_type == rtp_packet.payload_type
            ),
            None,
        )
        h264_transport = bool(
            rtp_packet is not None and rtp_packet.payload_type in routed_h264_payload_types
        )
        hevc_transport = bool(
            rtp_packet is not None and rtp_packet.payload_type in routed_hevc_payload_types
        )
        hevc_codec_compatible = bool(
            hevc_transport
            and (active_route_descriptor is None or active_route_descriptor.codec == "hevc")
        )
        h264_codec_compatible = bool(
            h264_transport
            and (not final_route_is_authoritative_hevc)
            and (active_route_descriptor is None or active_route_descriptor.codec == "h264")
        )
        if _owner._looks_like_idmx_hevc_parameter_frame(body):
            continue
        if hevc_codec_compatible and _owner._looks_like_idmx_hevc_media_frame(body):
            hevc_evidence_seen = True
            active_fu = _owner._append_idmx_hevc_media_payload(
                output,
                body[_owner.IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET :],
                aes_key,
                active_fu=active_fu,
                sequence_number=_owner._idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_owner._idmx_local_frame_rtp_timestamp(frame, header_size),
                rtp_marker=_owner._idmx_local_frame_rtp_marker(frame, header_size),
            )
            continue
        if (
            h264_codec_compatible
            and (not hevc_evidence_seen)
            and _owner._looks_like_idmx_h264_fu_a_frame(body)
        ):
            active_h264_fu = _owner._append_idmx_h264_fu_a_payload(
                output,
                body,
                active_fu=active_h264_fu,
                sequence_number=_owner._idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_owner._idmx_local_frame_rtp_timestamp(frame, header_size),
                aes_key=aes_key,
                nalu_header_size=h264_nalu_header_size,
            )
            continue
        if (
            h264_codec_compatible
            and (not hevc_evidence_seen)
            and _owner._looks_like_idmx_h264_clear_nal(body)
        ):
            active_h264_fu = None
            _owner._append_decrypted_h264_nal(
                output, body, aes_key, nalu_header_size=h264_nalu_header_size
            )
            continue
        hevc_direct_evidence = _owner._looks_like_idmx_hevc_evidence_frame(body)
        conflicting_h264_route = bool(
            rtp_packet is not None
            and rtp_packet.payload_type in route_epoch_profile.codec_payload_types("h264")
        )
        if (
            hevc_codec_compatible
            and (final_route_is_authoritative_hevc or hevc_evidence_seen or hevc_direct_evidence)
            and _owner._idmx_hevc_direct_frame_matches_route(
                body,
                authoritative_hevc=final_route_is_authoritative_hevc,
                conflicting_h264_route=conflicting_h264_route,
            )
        ):
            hevc_evidence_seen = True
            active_fu = _owner._append_idmx_hevc_media_payload(
                output,
                body,
                aes_key,
                active_fu=active_fu,
                sequence_number=_owner._idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_owner._idmx_local_frame_rtp_timestamp(frame, header_size),
                rtp_marker=_owner._idmx_local_frame_rtp_marker(frame, header_size),
                decrypt_parameter_sets=decrypt_hevc_parameter_sets,
            )
            continue
        if h264_codec_compatible and h264_nalu_header_size == 0 and body:
            active_h264_fu = None
            _owner._append_decrypted_h264_nal(
                output, body, aes_key, nalu_header_size=h264_nalu_header_size
            )
            continue
    if active_fu is not None:
        _owner._append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
    if not output:
        raise _owner.PyEzvizError("EZVIZ local IDMX stream did not include media frames")
    return (bytes(output), authoritative_codec)


def _decrypt_idmx_local_packets_to_adts_aac(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    audio_metadata: tuple[int, int] | None,
    audio_payload_types: frozenset[int] | None,
    require_contiguous: bool,
    decrypt_audio: bool,
    allow_timestamp_jitter: bool,
    _owner: _ModuleType,
) -> _owner_types._IdmxAacStream | None:
    """Return supported encrypted IDMX AAC as ADTS, or None for other audio."""
    final_profile = _owner._idmx_local_route_profile(packets)
    descriptor_aac_payload_types = final_profile.codec_payload_types("aac")
    selected_audio_payload_types = (
        audio_payload_types
        if audio_payload_types is not None
        else final_profile.codec_payload_types(
            "aac", fallback_payload_types=_owner.DEFAULT_AAC_PAYLOAD_TYPES
        )
    )
    rtp_packets: list[_owner_types.RtpPacket] = []
    route_epoch_profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None or not _owner._is_complete_idmx_rtp_frame(frame):
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is None:
            continue
        route_epoch_profile.absorb(packet)
        if packet.payload_type not in selected_audio_payload_types:
            rtp_packets.append(packet)
            continue
        if packet.payload_type in descriptor_aac_payload_types and (
            not _owner._rtp_packet_matches_codec_epoch(route_epoch_profile, packet, "aac")
        ):
            continue
        if (
            packet.payload_type in descriptor_aac_payload_types
            and _owner._rtp_packet_route_descriptor(route_epoch_profile, packet) is None
            and decrypt_audio
            and (not _owner.rtp_packet_has_valid_idmx_aac_frame(packet))
        ):
            continue
        rtp_packets.append(packet)
    return _owner.decrypt_idmx_aac_packets(
        rtp_packets,
        media_key,
        audio_metadata=audio_metadata,
        audio_payload_types=selected_audio_payload_types,
        require_contiguous=require_contiguous,
        decrypt_audio=decrypt_audio,
        allow_timestamp_jitter=allow_timestamp_jitter,
        preserve_clear_timestamps=not decrypt_audio and (not require_contiguous),
    )


def _idmx_local_packets_to_h264_annexb(packets: list[bytes], *, _owner: _ModuleType) -> bytes:
    output = bytearray()
    depacketizer = _owner.RtpVideoDepacketizer("h264")
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec="h264")
    route_epoch_profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            route_epoch_profile.absorb(packet)
        if packet is None or packet.payload_type not in routed_payload_types:
            continue
        if not _owner._rtp_packet_matches_codec_epoch(route_epoch_profile, packet, "h264"):
            continue
        if not (
            _owner._looks_like_idmx_h264_fu_a_frame(packet.payload)
            or _owner._looks_like_idmx_h264_clear_nal(packet.payload)
        ):
            continue
        for nal in depacketizer.push(packet):
            _owner._append_h264_nal(output, nal)
    if not output:
        raise _owner.PyEzvizError(
            "EZVIZ local IDMX stream did not include clear H.264 media frames"
        )
    return _owner._trim_trailing_h264_non_vcl_nals(bytes(output))


def _h264_annexb_packet_end_offsets(packets: list[bytes], *, _owner: _ModuleType) -> list[int]:
    output = bytearray()
    depacketizer = _owner.RtpVideoDepacketizer("h264")
    end_offsets: list[int] = []
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec="h264")
    route_epoch_profile = _owner.RtpRouteProfile()
    for packet in packets:
        for frame in _owner._iter_idmx_local_packet_frame(
            packet, video_payload_types=routed_payload_types
        ):
            header_size = _owner._idmx_local_frame_header_size(frame)
            if header_size is None:
                continue
            rtp_packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if rtp_packet is None or rtp_packet.payload_type not in routed_payload_types:
                continue
            if not _owner._rtp_packet_matches_codec_epoch(route_epoch_profile, rtp_packet, "h264"):
                continue
            if not (
                _owner._looks_like_idmx_h264_fu_a_frame(rtp_packet.payload)
                or _owner._looks_like_idmx_h264_clear_nal(rtp_packet.payload)
            ):
                continue
            for nal in depacketizer.push(rtp_packet):
                _owner._append_h264_nal(output, nal)
        end_offsets.append(len(output))
    return end_offsets


def _idmx_local_packets_to_hevc_annexb(
    packets: list[bytes], *, trim_trailing_non_vcl: bool, _owner: _ModuleType
) -> bytes:
    output = bytearray()
    depacketizer = _owner.RtpVideoDepacketizer("hevc", allow_ezviz_headerless_hevc_fu=True)
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec="hevc")
    route_epoch_profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            route_epoch_profile.absorb(packet)
        if packet is None or packet.payload_type not in routed_payload_types:
            continue
        if (
            not _owner._rtp_packet_matches_codec_epoch(route_epoch_profile, packet, "hevc")
            or _owner.rtp_payload_video_codec(packet.payload) == "h264"
            or (not _owner._looks_like_idmx_hevc_direct_frame(packet.payload))
        ):
            continue
        for nal in depacketizer.push(packet):
            _owner._append_hevc_nal(output, nal)
    if not output:
        raise _owner.PyEzvizError("EZVIZ local IDMX stream did not include clear HEVC media frames")
    annexb = bytes(output)
    if trim_trailing_non_vcl:
        return _owner._trim_trailing_hevc_non_vcl_nals(annexb)
    return annexb


def _hevc_annexb_packet_end_offsets(packets: list[bytes], *, _owner: _ModuleType) -> list[int]:
    output = bytearray()
    depacketizer = _owner.RtpVideoDepacketizer("hevc", allow_ezviz_headerless_hevc_fu=True)
    end_offsets: list[int] = []
    routed_payload_types = _owner._idmx_local_video_payload_types(packets, codec="hevc")
    route_epoch_profile = _owner.RtpRouteProfile()
    for packet in packets:
        for frame in _owner._iter_idmx_local_packet_frame(
            packet, video_payload_types=routed_payload_types
        ):
            header_size = _owner._idmx_local_frame_header_size(frame)
            if header_size is None:
                continue
            rtp_packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if (
                rtp_packet is None
                or rtp_packet.payload_type not in routed_payload_types
                or (
                    not _owner._rtp_packet_matches_codec_epoch(
                        route_epoch_profile, rtp_packet, "hevc"
                    )
                )
                or (_owner.rtp_payload_video_codec(rtp_packet.payload) == "h264")
                or (not _owner._looks_like_idmx_hevc_direct_frame(rtp_packet.payload))
            ):
                continue
            for nal in depacketizer.push(rtp_packet):
                _owner._append_hevc_nal(output, nal)
        end_offsets.append(len(output))
    return end_offsets


def _idmx_local_video_payload_types(
    packets: list[bytes], *, codec: _owner_types.RtpVideoCodec | None, _owner: _ModuleType
) -> frozenset[int]:
    """Return descriptor-owned local video routes with legacy PT 96 fallback."""
    if codec is not None:
        h264_types, hevc_types = _owner._idmx_local_supported_video_payload_types(packets)
        return h264_types if codec == "h264" else hevc_types
    profile = _owner._idmx_local_route_profile(packets)
    descriptor_video_payload_types = frozenset(
        descriptor.payload_type
        for descriptor in profile.descriptors
        if descriptor.media_kind == "video"
    )
    if descriptor_video_payload_types:
        return descriptor_video_payload_types
    assigned = frozenset(descriptor.payload_type for descriptor in profile.descriptors)
    return frozenset({_owner.IDMX_H264_RTP_PAYLOAD_TYPE}) - assigned


def _idmx_local_route_profile(
    packets: list[bytes], *, _owner: _ModuleType
) -> _owner_types.RtpRouteProfile:
    """Return the final authoritative route snapshot for local IDMX packets."""
    profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile


def _idmx_local_supported_video_payload_types(
    packets: list[bytes], *, _owner: _ModuleType
) -> tuple[frozenset[int], frozenset[int]]:
    """Return H.264/HEVC routes, rejecting unsupported-only video profiles."""
    profile = _owner._idmx_local_route_profile(packets)
    video_descriptors = tuple(
        descriptor for descriptor in profile.descriptors if descriptor.media_kind == "video"
    )
    if video_descriptors:
        h264_payload_types = profile.codec_payload_types("h264")
        hevc_payload_types = profile.codec_payload_types("hevc")
        assigned = frozenset(descriptor.payload_type for descriptor in profile.descriptors)
        advertised_video = h264_payload_types | hevc_payload_types
        if _owner.IDMX_H264_RTP_PAYLOAD_TYPE not in assigned:
            observed_advertised = False
            hevc_evidence = 0
            h264_evidence = 0
            for frame in _owner._iter_idmx_local_packet_frames(packets):
                header_size = _owner._idmx_local_frame_header_size(frame)
                if header_size is None:
                    continue
                packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
                if packet is None:
                    continue
                if packet.payload_type in advertised_video:
                    observed_advertised = True
                    break
                if packet.payload_type != _owner.IDMX_H264_RTP_PAYLOAD_TYPE:
                    continue
                body = _owner._idmx_local_frame_media_body(frame, header_size)
                hevc_evidence += bool(
                    _owner._looks_like_idmx_hevc_media_frame(body)
                    or _owner._looks_like_idmx_hevc_evidence_frame(body)
                )
                h264_evidence += bool(
                    _owner._looks_like_idmx_h264_fu_a_frame(body)
                    or _owner._looks_like_idmx_h264_clear_nal(body)
                )
            if not observed_advertised:
                if hevc_payload_types and (not h264_payload_types) and (hevc_evidence >= 2):
                    hevc_payload_types |= frozenset({_owner.IDMX_H264_RTP_PAYLOAD_TYPE})
                elif h264_payload_types and (not hevc_payload_types) and (h264_evidence >= 2):
                    h264_payload_types |= frozenset({_owner.IDMX_H264_RTP_PAYLOAD_TYPE})
    else:
        fallback_payload_types = frozenset({_owner.IDMX_H264_RTP_PAYLOAD_TYPE})
        h264_payload_types = profile.codec_payload_types(
            "h264", fallback_payload_types=fallback_payload_types
        )
        hevc_payload_types = profile.codec_payload_types(
            "hevc", fallback_payload_types=fallback_payload_types
        )
    if video_descriptors and (not (h264_payload_types or hevc_payload_types)):
        codecs = ", ".join(sorted({descriptor.codec for descriptor in video_descriptors}))
        raise _owner.PyEzvizError(f"Unsupported encrypted EZVIZ local video codec: {codecs}")
    return (h264_payload_types, hevc_payload_types)


def _idmx_local_packets_to_annexb(packets: list[bytes], *, _owner: _ModuleType) -> bytes:
    annexb, _codec = _owner._idmx_local_packets_to_annexb_with_codec(packets)
    return annexb


def _idmx_local_packets_to_annexb_with_codec(
    packets: list[bytes], *, _owner: _ModuleType
) -> tuple[bytes, str]:
    route_profile = _owner._idmx_local_route_profile(packets)
    authoritative_hevc = any(
        descriptor.media_kind == "video" and descriptor.codec == "hevc"
        for descriptor in route_profile.descriptors
    )
    try:
        h264_annexb = _owner._idmx_local_packets_to_h264_annexb(packets)
    except _owner.PyEzvizError as h264_error:
        try:
            return (_owner._idmx_local_packets_to_hevc_annexb(packets), "hevc")
        except _owner.PyEzvizError as hevc_error:
            raise h264_error from hevc_error
    if _owner._annexb_has_h264_vcl(h264_annexb):
        return (h264_annexb, "h264")
    try:
        hevc_annexb = _owner._idmx_local_packets_to_hevc_annexb(packets)
    except _owner.PyEzvizError:
        return (h264_annexb, "h264")
    if (
        authoritative_hevc
        or _owner._idmx_local_packets_have_direct_hevc_media(packets)
        or _owner._annexb_looks_like_hevc(hevc_annexb)
    ):
        return (hevc_annexb, "hevc")
    return (h264_annexb, "h264")


def _idmx_local_packets_to_h264_annexb_with_codec(
    packets: list[bytes], *, _owner: _ModuleType
) -> tuple[bytes, str]:
    try:
        h264_annexb = _owner._idmx_local_packets_to_h264_annexb(packets)
    except _owner.PyEzvizError:
        return _owner._idmx_local_packets_to_annexb_with_codec(packets)
    if _owner._annexb_has_h264_vcl(h264_annexb):
        return (h264_annexb, "h264")
    return _owner._idmx_local_packets_to_annexb_with_codec(packets)


def _idmx_local_packets_have_direct_hevc_media(
    packets: list[bytes], *, _owner: _ModuleType
) -> bool:
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        body = _owner._idmx_local_frame_media_body(frame, header_size)
        if not _owner._idmx_local_frame_is_h264_transport(frame, header_size):
            continue
        if _owner._looks_like_idmx_hevc_evidence_frame(body):
            return True
    return False


def _local_media_aes_key(media_key: str | bytes, *, _owner: _ModuleType) -> bytes:
    key_bytes = media_key.encode() if isinstance(media_key, str) else media_key
    return key_bytes.ljust(16, b"\x00")[:16]


def _idmx_hevc_direct_frame_matches_route(
    body: bytes, *, authoritative_hevc: bool, conflicting_h264_route: bool, _owner: _ModuleType
) -> bool:
    if not _owner._looks_like_idmx_hevc_direct_frame(body):
        return False
    return not authoritative_hevc or (
        not conflicting_h264_route and _owner.rtp_payload_video_codec(body) != "h264"
    )


def _append_idmx_hevc_media_payload(
    output: bytearray,
    payload: bytes,
    aes_key: bytes,
    *,
    active_fu: _owner_types._RtpFragmentedNal | None,
    sequence_number: int | None,
    rtp_timestamp: int | None,
    rtp_marker: bool,
    decrypt_parameter_sets: bool,
    _owner: _ModuleType,
) -> _owner_types._RtpFragmentedNal | None:
    if len(payload) < _owner.HEVC_NAL_HEADER_SIZE:
        return active_fu
    nal_type = payload[0] >> 1 & 63
    if nal_type != 49:
        if _owner._is_plausible_hevc_nal(payload):
            if not decrypt_parameter_sets and nal_type in {32, 33, 34, 39, 40}:
                _owner._append_hevc_nal(output, payload)
            else:
                _owner._append_decrypted_hevc_nal(output, payload, aes_key)
        return active_fu
    if len(payload) < 3:
        return active_fu
    fu_header = payload[2]
    is_start = bool(fu_header & 128)
    original_type = fu_header & 63
    if not is_start and (
        not _owner._rtp_fragment_continues(
            active_fu, sequence_number=sequence_number, rtp_timestamp=rtp_timestamp
        )
    ):
        return None
    reconstructed_header = bytes([payload[0] & 129 | original_type << 1, payload[1]])
    if is_start:
        active_fu = _owner._RtpFragmentedNal(
            data=bytearray(reconstructed_header),
            last_sequence=sequence_number,
            rtp_timestamp=rtp_timestamp,
        )
    assert active_fu is not None
    active_original_type = _owner._hevc_nal_type(
        bytes(active_fu.data[: _owner.HEVC_NAL_HEADER_SIZE])
    )
    active_header0 = active_fu.data[0] if active_fu.data else 0
    has_ezviz_pseudo_header = fu_header in {active_header0, active_header0 | 64}
    has_fu_header = is_start or original_type == active_original_type or has_ezviz_pseudo_header
    active_fu.data.extend(payload[3:] if has_fu_header else payload[2:])
    active_fu.last_sequence = sequence_number
    active_fu.rtp_timestamp = rtp_timestamp
    if (has_fu_header and bool(fu_header & 64)) or (not has_fu_header and rtp_marker):
        _owner._append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
        return None
    return active_fu


def _append_idmx_h264_fu_a_payload(
    output: bytearray,
    payload: bytes,
    *,
    active_fu: _owner_types._RtpFragmentedNal | None,
    sequence_number: int | None,
    rtp_timestamp: int | None,
    aes_key: bytes | None,
    nalu_header_size: int,
    _owner: _ModuleType,
) -> _owner_types._RtpFragmentedNal | None:
    fu_header = payload[1]
    is_start = bool(fu_header & 128)
    is_end = bool(fu_header & 64)
    if not is_start and (
        not _owner._rtp_fragment_continues(
            active_fu, sequence_number=sequence_number, rtp_timestamp=rtp_timestamp
        )
    ):
        return None
    reconstructed_header = bytes([payload[0] & 224 | fu_header & 31])
    if is_start:
        active_fu = _owner._RtpFragmentedNal(
            data=bytearray(reconstructed_header),
            last_sequence=sequence_number,
            rtp_timestamp=rtp_timestamp,
        )
    assert active_fu is not None
    active_fu.data.extend(payload[2:])
    active_fu.last_sequence = sequence_number
    active_fu.rtp_timestamp = rtp_timestamp
    if is_end:
        if aes_key is None:
            _owner._append_h264_nal(output, bytes(active_fu.data))
        else:
            _owner._append_decrypted_h264_nal(
                output,
                bytes(active_fu.data),
                aes_key,
                nalu_header_size=max(nalu_header_size, _owner.H264_NAL_HEADER_SIZE),
            )
        return None
    return active_fu


def _append_decrypted_hevc_nal(
    output: bytearray, nal: bytes, aes_key: bytes, *, _owner: _ModuleType
) -> None:
    if not _owner._is_plausible_hevc_nal(nal):
        return
    output.extend(_owner.ANNEX_B_LONG_START_CODE)
    output.extend(_owner._decrypt_hevc_nal_prefix(nal, aes_key))


def _append_decrypted_h264_nal(
    output: bytearray, nal: bytes, aes_key: bytes, *, nalu_header_size: int, _owner: _ModuleType
) -> None:
    if nalu_header_size != 0 and (not _owner._is_plausible_h264_nal(nal)):
        return
    if _owner._is_plausible_h264_nal(nal) and _owner._h264_nal_type(nal) not in {1, 5}:
        output.extend(_owner.ANNEX_B_LONG_START_CODE)
        output.extend(nal)
        return
    decrypted = _owner._decrypt_h264_nal_prefix(nal, aes_key, nalu_header_size=nalu_header_size)
    if not _owner._is_plausible_h264_nal(decrypted):
        return
    output.extend(_owner.ANNEX_B_LONG_START_CODE)
    output.extend(decrypted)


def _append_hevc_nal(output: bytearray, nal: bytes, *, _owner: _ModuleType) -> None:
    if not _owner._is_plausible_hevc_nal(nal):
        return
    output.extend(_owner.ANNEX_B_LONG_START_CODE)
    output.extend(nal)


def _trim_trailing_h264_non_vcl_nals(data: bytes, *, _owner: _ModuleType) -> bytes:
    spans = _owner._h264_annexb_nal_spans(data)
    if not spans:
        return data
    last_vcl_end: int | None = None
    last_vcl_index: int | None = None
    for index, (_offset, nal_start, end) in enumerate(spans):
        nal_type = _owner._h264_nal_type(data[nal_start:end])
        if nal_type in {1, 5}:
            last_vcl_end = end
            last_vcl_index = index
    if last_vcl_end is None:
        return data
    if last_vcl_index == len(spans) - 1:
        return data
    return data[:last_vcl_end]


def _trim_trailing_hevc_non_vcl_nals(data: bytes, *, _owner: _ModuleType) -> bytes:
    spans = _owner._h264_annexb_nal_spans(data)
    if not spans:
        return data
    last_vcl_end: int | None = None
    last_vcl_index: int | None = None
    for index, (_offset, nal_start, end) in enumerate(spans):
        nal_type = _owner._hevc_nal_type(data[nal_start:end])
        if 0 <= nal_type <= 31:
            last_vcl_end = end
            last_vcl_index = index
    if last_vcl_end is None:
        return data
    if last_vcl_index == len(spans) - 1:
        return data
    return data[:last_vcl_end]


def _decrypt_hevc_nal_prefix(nal: bytes, aes_key: bytes, *, _owner: _ModuleType) -> bytes:
    frame = bytearray(nal)
    decrypt_length = min(
        _owner.HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH, len(frame) - _owner.HEVC_NAL_HEADER_SIZE
    )
    decrypt_length -= decrypt_length % _owner.AES.block_size
    if decrypt_length > 0:
        cipher = _owner._hikvision_aes_ecb_cipher(aes_key)
        decrypt_end = _owner.HEVC_NAL_HEADER_SIZE + decrypt_length
        frame[_owner.HEVC_NAL_HEADER_SIZE : decrypt_end] = cipher.decrypt(
            bytes(frame[_owner.HEVC_NAL_HEADER_SIZE : decrypt_end])
        )
    return bytes(frame)


def _decrypt_h264_nal_prefix(
    nal: bytes, aes_key: bytes, *, nalu_header_size: int, _owner: _ModuleType
) -> bytes:
    frame = bytearray(nal)
    decrypt_length = min(
        _owner.HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH, len(frame) - nalu_header_size
    )
    decrypt_length -= decrypt_length % _owner.AES.block_size
    if decrypt_length > 0:
        cipher = _owner._hikvision_aes_ecb_cipher(aes_key)
        decrypt_end = nalu_header_size + decrypt_length
        frame[nalu_header_size:decrypt_end] = cipher.decrypt(
            bytes(frame[nalu_header_size:decrypt_end])
        )
    return bytes(frame)


def _iter_local_stream_payloads(
    stream: _owner_types.Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> _owner_types.Iterator[bytes]:
    if getattr(stream, "supports_deadline_iter_packets", False):
        for packet in stream.iter_packets(
            max_packets=max_packets, duration_seconds=duration_seconds, monotonic=monotonic
        ):
            yield packet.body
        return
    deadline: float | None = None
    for packet in stream.iter_packets(max_packets=max_packets):
        if duration_seconds is not None:
            now = monotonic()
            if deadline is None:
                deadline = now + duration_seconds
            elif now >= deadline:
                break
        yield packet.body


def _copy_mpegps_payloads_to_mpegts(
    payloads: _owner_types.Iterable[bytes],
    output: _owner_types.BinaryIO,
    *,
    process: _owner_types.subprocess.Popen[bytes],
    _owner: _ModuleType,
) -> None:

    def _write_input(stdin: _owner_types.BinaryIO) -> None:
        for payload in payloads:
            stdin.write(payload)
            stdin.flush()

    _owner.copy_remuxed_output(process, output, write_input=_write_input)


def _copy_idmx_audio_video_to_mpegts(
    annexb: bytes,
    audio: _owner_types._IdmxAacStream,
    output: _owner_types.BinaryIO,
    *,
    ffmpeg_path: str,
    video_input_format: str,
    video_frame_rate: str | None,
    _owner: _ModuleType,
) -> None:
    """Mux decrypted IDMX elementary video and AAC into MPEG-TS."""
    with _owner.tempfile.TemporaryDirectory(prefix="pyezvizapi-idmx-") as directory:
        audio_path, audio_format = _owner.write_aac_remux_input(audio, _owner.Path(directory))
        if audio_format == "concat":
            process = _owner.open_mpegts_remux_process(
                ffmpeg_path,
                input_format=video_input_format,
                frame_rate=video_frame_rate,
                audio_path=str(audio_path),
                audio_input_format=audio_format,
                popen=_owner.subprocess.Popen,
            )
            _owner._copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
            return
        process = _owner._open_local_idmx_audio_video_mpegts_remux_process(
            ffmpeg_path,
            video_input_format=video_input_format,
            audio_path=str(audio_path),
            video_frame_rate=video_frame_rate,
        )
        _owner._copy_mpegps_payloads_to_mpegts([annexb], output, process=process)


def _start_ffmpeg_stderr_drain(
    process: _owner_types.subprocess.Popen[bytes], *, max_bytes: int, _owner: _ModuleType
) -> tuple[_owner_types.BoundedStderrTail, _owner_types.Thread | None]:
    tail, reader = _owner.start_stderr_drain(process, max_bytes=max_bytes)
    return (tail, reader)


def _ffmpeg_stderr_tail(
    chunks: list[bytes] | _owner_types.BoundedStderrTail, *, max_chars: int, _owner: _ModuleType
) -> str:
    if isinstance(chunks, _StaticBoundedStderrTail):
        return chunks.text(max_chars=max_chars)
    text = b"".join(chunks).decode("utf-8", errors="replace").strip()
    return text[-max_chars:]


def _write_local_stream_payloads(
    stream: _owner_types.Any,
    output: _owner_types.BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> None:
    for payload in _owner._iter_local_stream_payloads(
        stream, max_packets=max_packets, duration_seconds=duration_seconds, monotonic=monotonic
    ):
        output.write(payload)
        output.flush()
