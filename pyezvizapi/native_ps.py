# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.native_ps`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import native_ps as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.native_ps as _compat_module_0
    _PS_START = _compat_module_0._PS_START
    MAX_PENDING_PS_BYTES = _compat_module_0.MAX_PENDING_PS_BYTES
    NativePsTransform = _compat_module_0.NativePsTransform
    PyEzvizError = _compat_module_0.PyEzvizError
    _decrypt_hikvision_ps_video_packets = _compat_module_0._decrypt_hikvision_ps_video_packets
    _MpegPsVideoDecryptState = _compat_module_0._MpegPsVideoDecryptState
    annotations = _compat_module_0.annotations
    mpeg_ps_complete_prefix_length = _compat_module_0.mpeg_ps_complete_prefix_length

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _PS_START,
        MAX_PENDING_PS_BYTES,
        NativePsTransform,
        PyEzvizError,
        _decrypt_hikvision_ps_video_packets,
        _MpegPsVideoDecryptState,
        annotations,
        mpeg_ps_complete_prefix_length,
    )

sys.modules[__name__] = _implementation
