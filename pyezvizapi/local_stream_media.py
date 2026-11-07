# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.media`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import media as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.media import (
    IDMX_LOCAL_FRAME_HEADER_SIZE as IDMX_LOCAL_FRAME_HEADER_SIZE,
    IDMX_LOCAL_FRAME_SENTINEL as IDMX_LOCAL_FRAME_SENTINEL,
    LocalSdkOutputFormat as LocalSdkOutputFormat,
    _idmx_local_packets_to_annexb_with_codec as _idmx_local_packets_to_annexb_with_codec,
    collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window as collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window,
    collect_h264_idmx_annexb_after_first_clean_idr_window as collect_h264_idmx_annexb_after_first_clean_idr_window,
    collect_idmx_annexb_after_first_clean_video_window as collect_idmx_annexb_after_first_clean_video_window,
    collect_local_stream_media_packets as collect_local_stream_media_packets,
    collect_local_stream_mpegps as collect_local_stream_mpegps,
    copy_hcnetsdk_real_data_to_mpegts as copy_hcnetsdk_real_data_to_mpegts,
    copy_local_stream_to_decrypted_mpegps as copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts as copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps as copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts as copy_local_stream_to_mpegts,
    h264_clean_idr_capture_budgets as h264_clean_idr_capture_budgets,
    skip_h264_annexb_initial_idr_windows as skip_h264_annexb_initial_idr_windows,
    skip_hevc_annexb_initial_irap_windows as skip_hevc_annexb_initial_irap_windows,
    summarize_h264_annexb_idr_windows as summarize_h264_annexb_idr_windows,
    summarize_h264_annexb_units as summarize_h264_annexb_units,
    summarize_hevc_annexb_irap_windows as summarize_hevc_annexb_irap_windows,
    summarize_idmx_h264_local_packets as summarize_idmx_h264_local_packets,
    trim_h264_annexb_to_first_clean_idr_window as trim_h264_annexb_to_first_clean_idr_window,
    trim_h264_annexb_to_first_error_free_suffix as trim_h264_annexb_to_first_error_free_suffix,
    trim_hevc_annexb_to_first_clean_irap_window as trim_hevc_annexb_to_first_clean_irap_window,
    trim_hevc_annexb_to_first_error_free_suffix as trim_hevc_annexb_to_first_error_free_suffix,
    )

sys.modules[__name__] = _implementation
