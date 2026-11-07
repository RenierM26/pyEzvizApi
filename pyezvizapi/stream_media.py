"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.containers`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import containers as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.containers import (
    ANNEX_B_LONG_START_CODE as ANNEX_B_LONG_START_CODE,
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH as HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    MPEG_PS_START_CODE as MPEG_PS_START_CODE,
    MPEG_START_CODE_PREFIX as MPEG_START_CODE_PREFIX,
    MPEG_TS_SYNC_BYTE as MPEG_TS_SYNC_BYTE,
    _find_hevc_nal_start_codes as _find_hevc_nal_start_codes,
    _hikvision_aes_ecb_cipher as _hikvision_aes_ecb_cipher,
    _is_mpeg_ps_packet_start_id as _is_mpeg_ps_packet_start_id,
    decrypt_hikvision_ps_video as decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size as detect_hikvision_ps_video_nalu_header_size,
    detect_transport as detect_transport,
    mpeg_ps_complete_prefix_length as mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length as mpeg_ps_decryptable_prefix_length,
    mpeg_ps_video_pts_span_seconds as mpeg_ps_video_pts_span_seconds,
    )

sys.modules[__name__] = _implementation
