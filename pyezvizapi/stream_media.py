# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.containers`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import containers as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.containers as _compat_module_0

    ANNEX_B_LONG_START_CODE = _compat_module_0.ANNEX_B_LONG_START_CODE
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH = _compat_module_0.HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
    MPEG_PS_START_CODE = _compat_module_0.MPEG_PS_START_CODE
    MPEG_START_CODE_PREFIX = _compat_module_0.MPEG_START_CODE_PREFIX
    MPEG_TS_SYNC_BYTE = _compat_module_0.MPEG_TS_SYNC_BYTE
    _find_hevc_nal_start_codes = _compat_module_0._find_hevc_nal_start_codes
    _hikvision_aes_ecb_cipher = _compat_module_0._hikvision_aes_ecb_cipher
    _is_mpeg_ps_packet_start_id = _compat_module_0._is_mpeg_ps_packet_start_id
    decrypt_hikvision_ps_video = _compat_module_0.decrypt_hikvision_ps_video
    detect_hikvision_ps_video_nalu_header_size = (
        _compat_module_0.detect_hikvision_ps_video_nalu_header_size
    )
    detect_transport = _compat_module_0.detect_transport
    mpeg_ps_complete_prefix_length = _compat_module_0.mpeg_ps_complete_prefix_length
    mpeg_ps_decryptable_prefix_length = _compat_module_0.mpeg_ps_decryptable_prefix_length
    mpeg_ps_video_pts_span_seconds = _compat_module_0.mpeg_ps_video_pts_span_seconds

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        ANNEX_B_LONG_START_CODE,
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        MPEG_PS_START_CODE,
        MPEG_START_CODE_PREFIX,
        MPEG_TS_SYNC_BYTE,
        _find_hevc_nal_start_codes,
        _hikvision_aes_ecb_cipher,
        _is_mpeg_ps_packet_start_id,
        decrypt_hikvision_ps_video,
        detect_hikvision_ps_video_nalu_header_size,
        detect_transport,
        mpeg_ps_complete_prefix_length,
        mpeg_ps_decryptable_prefix_length,
        mpeg_ps_video_pts_span_seconds,
    )

sys.modules[__name__] = _implementation
