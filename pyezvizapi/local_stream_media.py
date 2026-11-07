# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.media`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import media as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.media as _compat_module_0
    IDMX_LOCAL_FRAME_HEADER_SIZE = _compat_module_0.IDMX_LOCAL_FRAME_HEADER_SIZE
    IDMX_LOCAL_FRAME_SENTINEL = _compat_module_0.IDMX_LOCAL_FRAME_SENTINEL
    LocalSdkOutputFormat = _compat_module_0.LocalSdkOutputFormat
    _idmx_local_packets_to_annexb_with_codec = _compat_module_0._idmx_local_packets_to_annexb_with_codec
    collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window = _compat_module_0.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window
    collect_h264_idmx_annexb_after_first_clean_idr_window = _compat_module_0.collect_h264_idmx_annexb_after_first_clean_idr_window
    collect_idmx_annexb_after_first_clean_video_window = _compat_module_0.collect_idmx_annexb_after_first_clean_video_window
    collect_local_stream_media_packets = _compat_module_0.collect_local_stream_media_packets
    collect_local_stream_mpegps = _compat_module_0.collect_local_stream_mpegps
    copy_hcnetsdk_real_data_to_mpegts = _compat_module_0.copy_hcnetsdk_real_data_to_mpegts
    copy_local_stream_to_decrypted_mpegps = _compat_module_0.copy_local_stream_to_decrypted_mpegps
    copy_local_stream_to_decrypted_mpegts = _compat_module_0.copy_local_stream_to_decrypted_mpegts
    copy_local_stream_to_mpegps = _compat_module_0.copy_local_stream_to_mpegps
    copy_local_stream_to_mpegts = _compat_module_0.copy_local_stream_to_mpegts
    h264_clean_idr_capture_budgets = _compat_module_0.h264_clean_idr_capture_budgets
    skip_h264_annexb_initial_idr_windows = _compat_module_0.skip_h264_annexb_initial_idr_windows
    skip_hevc_annexb_initial_irap_windows = _compat_module_0.skip_hevc_annexb_initial_irap_windows
    summarize_h264_annexb_idr_windows = _compat_module_0.summarize_h264_annexb_idr_windows
    summarize_h264_annexb_units = _compat_module_0.summarize_h264_annexb_units
    summarize_hevc_annexb_irap_windows = _compat_module_0.summarize_hevc_annexb_irap_windows
    summarize_idmx_h264_local_packets = _compat_module_0.summarize_idmx_h264_local_packets
    trim_h264_annexb_to_first_clean_idr_window = _compat_module_0.trim_h264_annexb_to_first_clean_idr_window
    trim_h264_annexb_to_first_error_free_suffix = _compat_module_0.trim_h264_annexb_to_first_error_free_suffix
    trim_hevc_annexb_to_first_clean_irap_window = _compat_module_0.trim_hevc_annexb_to_first_clean_irap_window
    trim_hevc_annexb_to_first_error_free_suffix = _compat_module_0.trim_hevc_annexb_to_first_error_free_suffix

sys.modules[__name__] = _implementation
