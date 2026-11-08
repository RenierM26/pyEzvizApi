# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.packets`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import packets as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.packets as _compat_module_0

    ANNEX_B_LONG_START_CODE = _compat_module_0.ANNEX_B_LONG_START_CODE
    H264_FU_A_NAL_TYPE = _compat_module_0.H264_FU_A_NAL_TYPE
    HEVC_NAL_HEADER_SIZE = _compat_module_0.HEVC_NAL_HEADER_SIZE
    IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX = (
        _compat_module_0.IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX
    )
    IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET = _compat_module_0.IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET
    IDMX_LOCAL_FRAME_SENTINEL = _compat_module_0.IDMX_LOCAL_FRAME_SENTINEL
    IDMX_LOCAL_FRAME_SENTINEL_OFFSETS = _compat_module_0.IDMX_LOCAL_FRAME_SENTINEL_OFFSETS
    MPEG_START_CODE_PREFIX = _compat_module_0.MPEG_START_CODE_PREFIX
    PyEzvizError = _compat_module_0.PyEzvizError
    RtpPacket = _compat_module_0.RtpPacket
    RtpRouteProfile = _compat_module_0.RtpRouteProfile
    RtpStreamDescriptor = _compat_module_0.RtpStreamDescriptor
    _annexb_contains_selected_vcl = _compat_module_0._annexb_contains_selected_vcl
    _annexb_first_vcl_unit = _compat_module_0._annexb_first_vcl_unit
    _annexb_has_h264_vcl = _compat_module_0._annexb_has_h264_vcl
    _annexb_looks_like_h264 = _compat_module_0._annexb_looks_like_h264
    _annexb_looks_like_hevc = _compat_module_0._annexb_looks_like_hevc
    _annexb_vcl_bounds = _compat_module_0._annexb_vcl_bounds
    _append_h264_nal = _compat_module_0._append_h264_nal
    _find_h264_annexb_start_code = _compat_module_0._find_h264_annexb_start_code
    _h264_annexb_idr_window_start_index = _compat_module_0._h264_annexb_idr_window_start_index
    _h264_annexb_nal_spans = _compat_module_0._h264_annexb_nal_spans
    _h264_clean_idr_timeout_suffix = _compat_module_0._h264_clean_idr_timeout_suffix
    _h264_nal_type = _compat_module_0._h264_nal_type
    _H264CleanIdrProbeResult = _compat_module_0._H264CleanIdrProbeResult
    _hevc_nal_type = _compat_module_0._hevc_nal_type
    _idmx_frame_end_before_next_prefix = _compat_module_0._idmx_frame_end_before_next_prefix
    _idmx_local_frame_header_score = _compat_module_0._idmx_local_frame_header_score
    _idmx_local_frame_header_size = _compat_module_0._idmx_local_frame_header_size
    _idmx_local_frame_media_body = _compat_module_0._idmx_local_frame_media_body
    _idmx_local_rtp_frame = _compat_module_0._idmx_local_rtp_frame
    _is_complete_idmx_rtp_frame = _compat_module_0._is_complete_idmx_rtp_frame
    _is_plausible_h264_nal = _compat_module_0._is_plausible_h264_nal
    _is_plausible_hevc_nal = _compat_module_0._is_plausible_hevc_nal
    _looks_like_idmx_h264_clear_nal = _compat_module_0._looks_like_idmx_h264_clear_nal
    _looks_like_idmx_h264_fu_a_frame = _compat_module_0._looks_like_idmx_h264_fu_a_frame
    _looks_like_idmx_hevc_direct_frame = _compat_module_0._looks_like_idmx_hevc_direct_frame
    _looks_like_idmx_hevc_evidence_frame = _compat_module_0._looks_like_idmx_hevc_evidence_frame
    _looks_like_idmx_hevc_media_frame = _compat_module_0._looks_like_idmx_hevc_media_frame
    _looks_like_idmx_hevc_parameter_frame = _compat_module_0._looks_like_idmx_hevc_parameter_frame
    _rtp_fragment_continues = _compat_module_0._rtp_fragment_continues
    _rtp_packet_matches_codec_epoch = _compat_module_0._rtp_packet_matches_codec_epoch
    _rtp_packet_route_descriptor = _compat_module_0._rtp_packet_route_descriptor
    _RtpFragmentedNal = _compat_module_0._RtpFragmentedNal
    _strip_idmx_command_h264_record_trailer = (
        _compat_module_0._strip_idmx_command_h264_record_trailer
    )
    _strip_legacy_idmx_video_wrapper = _compat_module_0._strip_legacy_idmx_video_wrapper
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    parse_rtp_packet = _compat_module_0.parse_rtp_packet
    replace = _compat_module_0.replace

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        ANNEX_B_LONG_START_CODE,
        H264_FU_A_NAL_TYPE,
        HEVC_NAL_HEADER_SIZE,
        IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX,
        IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET,
        IDMX_LOCAL_FRAME_SENTINEL,
        IDMX_LOCAL_FRAME_SENTINEL_OFFSETS,
        MPEG_START_CODE_PREFIX,
        PyEzvizError,
        RtpPacket,
        RtpRouteProfile,
        RtpStreamDescriptor,
        _annexb_contains_selected_vcl,
        _annexb_first_vcl_unit,
        _annexb_has_h264_vcl,
        _annexb_looks_like_h264,
        _annexb_looks_like_hevc,
        _annexb_vcl_bounds,
        _append_h264_nal,
        _find_h264_annexb_start_code,
        _h264_annexb_idr_window_start_index,
        _h264_annexb_nal_spans,
        _h264_clean_idr_timeout_suffix,
        _h264_nal_type,
        _H264CleanIdrProbeResult,
        _hevc_nal_type,
        _idmx_frame_end_before_next_prefix,
        _idmx_local_frame_header_score,
        _idmx_local_frame_header_size,
        _idmx_local_frame_media_body,
        _idmx_local_rtp_frame,
        _is_complete_idmx_rtp_frame,
        _is_plausible_h264_nal,
        _is_plausible_hevc_nal,
        _looks_like_idmx_h264_clear_nal,
        _looks_like_idmx_h264_fu_a_frame,
        _looks_like_idmx_hevc_direct_frame,
        _looks_like_idmx_hevc_evidence_frame,
        _looks_like_idmx_hevc_media_frame,
        _looks_like_idmx_hevc_parameter_frame,
        _rtp_fragment_continues,
        _rtp_packet_matches_codec_epoch,
        _rtp_packet_route_descriptor,
        _RtpFragmentedNal,
        _strip_idmx_command_h264_record_trailer,
        _strip_legacy_idmx_video_wrapper,
        annotations,
        dataclass,
        parse_rtp_packet,
        replace,
    )

sys.modules[__name__] = _implementation
