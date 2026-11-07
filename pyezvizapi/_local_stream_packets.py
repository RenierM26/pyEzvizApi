"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.packets`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import packets as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.packets import (
    ANNEX_B_LONG_START_CODE as ANNEX_B_LONG_START_CODE,
    H264_FU_A_NAL_TYPE as H264_FU_A_NAL_TYPE,
    HEVC_NAL_HEADER_SIZE as HEVC_NAL_HEADER_SIZE,
    IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX as IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX,
    IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET as IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET,
    IDMX_LOCAL_FRAME_SENTINEL as IDMX_LOCAL_FRAME_SENTINEL,
    IDMX_LOCAL_FRAME_SENTINEL_OFFSETS as IDMX_LOCAL_FRAME_SENTINEL_OFFSETS,
    MPEG_START_CODE_PREFIX as MPEG_START_CODE_PREFIX,
    PyEzvizError as PyEzvizError,
    RtpPacket as RtpPacket,
    RtpRouteProfile as RtpRouteProfile,
    RtpStreamDescriptor as RtpStreamDescriptor,
    _H264CleanIdrProbeResult as _H264CleanIdrProbeResult,
    _RtpFragmentedNal as _RtpFragmentedNal,
    _annexb_contains_selected_vcl as _annexb_contains_selected_vcl,
    _annexb_first_vcl_unit as _annexb_first_vcl_unit,
    _annexb_has_h264_vcl as _annexb_has_h264_vcl,
    _annexb_looks_like_h264 as _annexb_looks_like_h264,
    _annexb_looks_like_hevc as _annexb_looks_like_hevc,
    _annexb_vcl_bounds as _annexb_vcl_bounds,
    _append_h264_nal as _append_h264_nal,
    _find_h264_annexb_start_code as _find_h264_annexb_start_code,
    _h264_annexb_idr_window_start_index as _h264_annexb_idr_window_start_index,
    _h264_annexb_nal_spans as _h264_annexb_nal_spans,
    _h264_clean_idr_timeout_suffix as _h264_clean_idr_timeout_suffix,
    _h264_nal_type as _h264_nal_type,
    _hevc_nal_type as _hevc_nal_type,
    _idmx_frame_end_before_next_prefix as _idmx_frame_end_before_next_prefix,
    _idmx_local_frame_header_score as _idmx_local_frame_header_score,
    _idmx_local_frame_header_size as _idmx_local_frame_header_size,
    _idmx_local_frame_media_body as _idmx_local_frame_media_body,
    _idmx_local_rtp_frame as _idmx_local_rtp_frame,
    _is_complete_idmx_rtp_frame as _is_complete_idmx_rtp_frame,
    _is_plausible_h264_nal as _is_plausible_h264_nal,
    _is_plausible_hevc_nal as _is_plausible_hevc_nal,
    _looks_like_idmx_h264_clear_nal as _looks_like_idmx_h264_clear_nal,
    _looks_like_idmx_h264_fu_a_frame as _looks_like_idmx_h264_fu_a_frame,
    _looks_like_idmx_hevc_direct_frame as _looks_like_idmx_hevc_direct_frame,
    _looks_like_idmx_hevc_evidence_frame as _looks_like_idmx_hevc_evidence_frame,
    _looks_like_idmx_hevc_media_frame as _looks_like_idmx_hevc_media_frame,
    _looks_like_idmx_hevc_parameter_frame as _looks_like_idmx_hevc_parameter_frame,
    _rtp_fragment_continues as _rtp_fragment_continues,
    _rtp_packet_matches_codec_epoch as _rtp_packet_matches_codec_epoch,
    _rtp_packet_route_descriptor as _rtp_packet_route_descriptor,
    _strip_idmx_command_h264_record_trailer as _strip_idmx_command_h264_record_trailer,
    _strip_legacy_idmx_video_wrapper as _strip_legacy_idmx_video_wrapper,
    annotations as annotations,
    dataclass as dataclass,
    parse_rtp_packet as parse_rtp_packet,
    replace as replace,
    )

sys.modules[__name__] = _implementation
