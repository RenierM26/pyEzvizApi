# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""diagnostics implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi._typing.local_stream as _owner_types


def collect_local_stream_media_packets(
    stream: _owner_types.Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: _owner_types.Callable[[], float],
    _owner: _ModuleType,
) -> list[bytes]:
    """Collect bounded local media payloads while preserving RTP packet boundaries."""
    return list(
        _owner._iter_local_stream_payloads(
            stream, max_packets=max_packets, duration_seconds=duration_seconds, monotonic=monotonic
        )
    )


def summarize_idmx_h264_local_packets(
    packets: _owner_types.Iterable[bytes], *, max_frames: int, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized IDMX/H.264 frame-shape metadata for local media packets."""
    payloads = list(packets)
    summary: dict[str, _owner_types.Any] = {
        "packet_count": len(payloads),
        "payload_bytes": sum(len(payload) for payload in payloads),
        "looks_like_idmx": _owner._local_stream_packets_are_idmx(payloads),
        "frame_count": 0,
        "sample_limit": max_frames,
        "samples": [],
        "h264": {
            "clear_nal": 0,
            "fu_a": 0,
            "fu_a_start": 0,
            "fu_a_end": 0,
            "non_idr": 0,
            "idr": 0,
            "sei": 0,
            "sps": 0,
            "pps": 0,
            "aud": 0,
            "unknown": 0,
        },
        "hevc": {"parameter": 0, "media": 0},
        "packet_shapes": _owner._summarize_idmx_packet_shapes(payloads, max_samples=max_frames),
        "rtp_profile": _owner._idmx_route_diagnostics(payloads),
        "h264_nal_units": {
            "sample_limit": max_frames,
            "samples": [],
            "truncated": False,
            "incomplete_fu_a": 0,
            "discarded_fu_a_fragments": 0,
            "sequence_gap_count": 0,
            "timestamp_change_count": 0,
            "restart_count": 0,
        },
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    h264_payload_types = _owner._idmx_local_video_payload_types(payloads, codec="h264")
    active_h264_fu: dict[str, _owner_types.Any] | None = None
    for frame_index, frame in enumerate(_owner._iter_idmx_local_packet_frames(payloads)):
        summary["frame_count"] = frame_index + 1
        frame_summary = _owner._summarize_idmx_h264_local_frame(
            frame, frame_index, h264_payload_types=h264_payload_types
        )
        _owner._merge_idmx_h264_frame_summary(summary, frame_summary)
        active_h264_fu = _owner._record_idmx_h264_nal_unit_summary(
            summary,
            frame,
            frame_summary,
            active_fu=active_h264_fu,
            h264_payload_types=h264_payload_types,
        )
        if len(samples) < max_frames:
            samples.append(frame_summary)
    if active_h264_fu is not None:
        _owner._increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _owner._append_idmx_h264_nal_unit_sample(
            summary, active_h264_fu, complete=False, end_frame_index=None
        )
    return summary


def _idmx_route_diagnostics(packets: list[bytes], *, _owner: _ModuleType) -> dict[str, object]:
    """Return sanitized codec/ownership metadata for a local IDMX capture."""
    parsed: list[_owner_types.RtpPacket] = []
    profile = _owner.RtpRouteProfile()
    for frame in _owner._iter_idmx_local_packet_frames(packets):
        header_size = _owner._idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _owner._idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            parsed.append(packet)
            profile.absorb(packet)
    for packet in parsed:
        if profile.media_kind(packet) in {"video", "audio"}:
            profile.mark_media(packet, absorb=False)
    return profile.diagnostics()


def _summarize_idmx_packet_shapes(
    packets: list[bytes], *, max_samples: int, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return bounded packet-wrapper diagnostics for IDMX captures."""
    summary: dict[str, _owner_types.Any] = {
        "sample_limit": max_samples,
        "samples": [],
        "truncated": False,
        "idmx_at_offset_0": 0,
        "length_prefixed_idmx": 0,
        "contains_idmx": 0,
        "possible_hrudp_wrapped": 0,
        "possible_hrudp_video": 0,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    for packet_index, packet in enumerate(packets):
        shape = _owner._summarize_idmx_packet_shape(packet, packet_index)
        if shape["idmx_offset"] == 0:
            summary["idmx_at_offset_0"] = int(summary["idmx_at_offset_0"]) + 1
        if shape.get("length_prefix") is not None:
            summary["length_prefixed_idmx"] = int(summary["length_prefixed_idmx"]) + 1
        if shape["idmx_offset"] is not None:
            summary["contains_idmx"] = int(summary["contains_idmx"]) + 1
        hrdp_shape = shape.get("possible_hrudp")
        if isinstance(hrdp_shape, dict):
            summary["possible_hrudp_wrapped"] = int(summary["possible_hrudp_wrapped"]) + 1
            if hrdp_shape.get("frame_type") == _owner.HCNETSDK_HRUDP_VIDEO_FRAME_TYPE:
                summary["possible_hrudp_video"] = int(summary["possible_hrudp_video"]) + 1
        if len(samples) >= max_samples:
            summary["truncated"] = True
            continue
        samples.append(shape)
    return summary


def _summarize_idmx_packet_shape(
    packet: bytes, packet_index: int, *, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized shape metadata for one sampled command-port packet."""
    idmx_offset = packet.find(_owner.IDMX_LOCAL_FRAME_SENTINEL)
    if idmx_offset >= 0:
        frame_offsets: list[tuple[int, int]] = []
        for sentinel_offset in _owner.IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
            frame_offset = idmx_offset - sentinel_offset
            if frame_offset < 0:
                continue
            header_size = _owner._idmx_local_frame_header_size(packet[frame_offset:])
            header_score = _owner._idmx_local_frame_header_score(packet[frame_offset:], header_size)
            if header_score is not None:
                frame_offsets.append((frame_offset, header_score))
        idmx_frame_offset = (
            min(frame_offsets, key=lambda item: (item[1], item[0]))[0] if frame_offsets else None
        )
    else:
        idmx_frame_offset = None
    shape: dict[str, _owner_types.Any] = {
        "index": packet_index,
        "packet_length": len(packet),
        "sha256": _owner.hashlib.sha256(packet).hexdigest(),
        "idmx_offset": idmx_frame_offset,
    }
    if idmx_frame_offset is not None and idmx_frame_offset >= 4:
        prefixed_length = int.from_bytes(
            packet[idmx_frame_offset - 4 : idmx_frame_offset], "little"
        )
        if (
            prefixed_length >= _owner.IDMX_LOCAL_FRAME_HEADER_SIZE
            and idmx_frame_offset + prefixed_length <= len(packet)
        ):
            shape["length_prefix"] = prefixed_length
    hrdp_shape = _owner._possible_hcnetsdk_hrudp_packet_shape(packet)
    if hrdp_shape is not None:
        shape["possible_hrudp"] = hrdp_shape
    else:
        try:
            unwrapped = _owner.rtp_payload(packet)
        except _owner.PyEzvizError:
            pass
        else:
            hrdp_shape = _owner._possible_hcnetsdk_hrudp_packet_shape(unwrapped)
            if hrdp_shape is not None:
                hrdp_shape = dict(hrdp_shape)
                hrdp_shape["rtp_wrapped"] = True
                shape["possible_hrudp"] = hrdp_shape
    return shape


def _possible_hcnetsdk_hrudp_packet_shape(
    packet: bytes, *, _owner: _ModuleType
) -> dict[str, _owner_types.Any] | None:
    """Return likely HCPreview HRUDP wrapper fields when a packet is self-bounded."""
    if len(packet) < _owner.HCNETSDK_HRUDP_FRAME_HEADER_SIZE:
        return None
    for byte_order in ("little", "big"):
        payload_length = int.from_bytes(packet[0:4], byte_order)
        if payload_length + _owner.HCNETSDK_HRUDP_FRAME_HEADER_SIZE != len(packet):
            continue
        frame_type = int.from_bytes(packet[4:8], byte_order)
        sequence = int.from_bytes(packet[8:12], byte_order)
        if frame_type > 16:
            continue
        return {
            "byte_order": byte_order,
            "payload_length": payload_length,
            "frame_type": frame_type,
            "sequence": sequence,
            "payload_starts_with_idmx": _owner._idmx_local_frame_header_size(
                packet[_owner.HCNETSDK_HRUDP_FRAME_HEADER_SIZE :]
            )
            is not None,
            "payload_contains_idmx": _owner.IDMX_LOCAL_FRAME_SENTINEL
            in packet[_owner.HCNETSDK_HRUDP_FRAME_HEADER_SIZE :],
        }
    return None


def summarize_h264_annexb_units(
    data: bytes, *, max_units: int, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized H.264 Annex-B NAL-unit metadata."""
    summary: dict[str, _owner_types.Any] = {
        "byte_count": len(data),
        "nal_count": 0,
        "sample_limit": max_units,
        "samples": [],
        "truncated": False,
        "h264": {"non_idr": 0, "idr": 0, "sei": 0, "sps": 0, "pps": 0, "aud": 0, "unknown": 0},
    }
    samples = summary["samples"]
    h264 = summary["h264"]
    assert isinstance(samples, list)
    assert isinstance(h264, dict)
    for index, (start_code_offset, nal_start, end) in enumerate(
        _owner._h264_annexb_nal_spans(data)
    ):
        nal = data[nal_start:end]
        nal_type = _owner._h264_nal_type(nal)
        summary["nal_count"] = index + 1
        _owner._increment_h264_nal_type_count(h264, nal_type)
        if len(samples) >= max_units:
            summary["truncated"] = True
            continue
        samples.append(
            {
                "index": index,
                "start_code_offset": start_code_offset,
                "nal_offset": nal_start,
                "end_offset": end,
                "nal_type": nal_type,
                "payload_bytes": len(nal),
                "sha256": _owner.hashlib.sha256(nal).hexdigest(),
            }
        )
    return summary


def summarize_h264_annexb_idr_windows(
    data: bytes, *, max_windows: int, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized IDR-started H.264 Annex-B window metadata."""
    spans = _owner._h264_annexb_nal_spans(data)
    nal_types = [_owner._h264_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    idr_indexes = [index for index, nal_type in enumerate(nal_types) if nal_type == 5]
    summary: dict[str, _owner_types.Any] = {
        "byte_count": len(data),
        "nal_count": len(spans),
        "idr_count": len(idr_indexes),
        "sample_limit": max_windows,
        "samples": [],
        "truncated": False,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    for sample_index, idr_nal_index in enumerate(idr_indexes):
        if len(samples) >= max_windows:
            summary["truncated"] = True
            break
        start_nal_index = _owner._h264_annexb_idr_window_start_index(nal_types, idr_nal_index)
        next_idr_nal_index = (
            idr_indexes[sample_index + 1] if sample_index + 1 < len(idr_indexes) else None
        )
        next_window_start_nal_index = (
            _owner._h264_annexb_idr_window_start_index(nal_types, next_idr_nal_index)
            if next_idr_nal_index is not None
            else None
        )
        end_nal_index = (
            next_window_start_nal_index if next_window_start_nal_index is not None else len(spans)
        )
        start_offset = spans[start_nal_index][0]
        end_offset = (
            spans[next_window_start_nal_index][0]
            if next_window_start_nal_index is not None
            else len(data)
        )
        idr_start_code_offset, idr_nal_offset, idr_end_offset = spans[idr_nal_index]
        samples.append(
            {
                "index": sample_index,
                "start_nal_index": start_nal_index,
                "idr_nal_index": idr_nal_index,
                "end_nal_index": end_nal_index,
                "start_code_offset": start_offset,
                "idr_start_code_offset": idr_start_code_offset,
                "end_offset": end_offset,
                "window_bytes": max(end_offset - start_offset, 0),
                "leading_nal_types": nal_types[start_nal_index:idr_nal_index],
                "idr_payload_bytes": max(idr_end_offset - idr_nal_offset, 0),
                "idr_sha256": _owner.hashlib.sha256(
                    data[idr_nal_offset:idr_end_offset]
                ).hexdigest(),
                "window_sha256": _owner.hashlib.sha256(data[start_offset:end_offset]).hexdigest(),
            }
        )
    return summary


def summarize_hevc_annexb_irap_windows(
    data: bytes, *, max_windows: int, _owner: _ModuleType
) -> dict[str, _owner_types.Any]:
    """Return sanitized IRAP-started HEVC Annex-B window metadata."""
    spans = _owner._h264_annexb_nal_spans(data)
    nal_types = [_owner._hevc_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    irap_indexes = [index for index, nal_type in enumerate(nal_types) if 16 <= nal_type <= 21]
    summary: dict[str, _owner_types.Any] = {
        "byte_count": len(data),
        "nal_count": len(spans),
        "irap_count": len(irap_indexes),
        "sample_limit": max_windows,
        "samples": [],
        "truncated": False,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    for sample_index, irap_nal_index in enumerate(irap_indexes):
        if len(samples) >= max_windows:
            summary["truncated"] = True
            break
        start_nal_index = _owner._hevc_annexb_irap_window_start_index(nal_types, irap_nal_index)
        next_irap_nal_index = (
            irap_indexes[sample_index + 1] if sample_index + 1 < len(irap_indexes) else None
        )
        next_window_start_nal_index = (
            _owner._hevc_annexb_irap_window_start_index(nal_types, next_irap_nal_index)
            if next_irap_nal_index is not None
            else None
        )
        end_nal_index = (
            next_window_start_nal_index if next_window_start_nal_index is not None else len(spans)
        )
        start_offset = spans[start_nal_index][0]
        end_offset = (
            spans[next_window_start_nal_index][0]
            if next_window_start_nal_index is not None
            else len(data)
        )
        irap_start_code_offset, irap_nal_offset, irap_end_offset = spans[irap_nal_index]
        samples.append(
            {
                "index": sample_index,
                "start_nal_index": start_nal_index,
                "irap_nal_index": irap_nal_index,
                "end_nal_index": end_nal_index,
                "start_code_offset": start_offset,
                "irap_start_code_offset": irap_start_code_offset,
                "end_offset": end_offset,
                "window_bytes": max(end_offset - start_offset, 0),
                "leading_nal_types": nal_types[start_nal_index:irap_nal_index],
                "irap_payload_bytes": max(irap_end_offset - irap_nal_offset, 0),
                "irap_sha256": _owner.hashlib.sha256(
                    data[irap_nal_offset:irap_end_offset]
                ).hexdigest(),
                "window_sha256": _owner.hashlib.sha256(data[start_offset:end_offset]).hexdigest(),
            }
        )
    return summary


def skip_h264_annexb_initial_idr_windows(data: bytes, count: int, *, _owner: _ModuleType) -> bytes:
    """Return Annex-B bytes starting at the requested IDR window."""
    if count < 0:
        raise _owner.PyEzvizError("H.264 IDR-window skip count cannot be negative")
    if count == 0:
        return data
    spans = _owner._h264_annexb_nal_spans(data)
    nal_types = [_owner._h264_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    idr_indexes = [index for index, nal_type in enumerate(nal_types) if nal_type == 5]
    if count >= len(idr_indexes):
        raise _owner.PyEzvizError(
            f"H.264 stream did not contain enough IDR windows to skip {count} startup window(s)"
        )
    start_index = _owner._h264_annexb_idr_window_start_index(nal_types, idr_indexes[count])
    return data[spans[start_index][0] :]


def skip_hevc_annexb_initial_irap_windows(data: bytes, count: int, *, _owner: _ModuleType) -> bytes:
    """Return HEVC Annex-B bytes starting at the requested IRAP window."""
    if count < 0:
        raise _owner.PyEzvizError("HEVC IRAP-window skip count cannot be negative")
    if count == 0:
        return data
    spans = _owner._h264_annexb_nal_spans(data)
    nal_types = [_owner._hevc_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    irap_indexes = [index for index, nal_type in enumerate(nal_types) if 16 <= nal_type <= 21]
    if count >= len(irap_indexes):
        raise _owner.PyEzvizError(
            f"HEVC stream did not contain enough IRAP windows to skip {count} startup window(s)"
        )
    start_index = _owner._hevc_annexb_irap_window_start_index(nal_types, irap_indexes[count])
    return data[spans[start_index][0] :]
