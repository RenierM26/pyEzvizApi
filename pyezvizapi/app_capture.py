# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.app_capture`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import app_capture as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.app_capture as _compat_module_0
    _CHUNK_BYTES = _compat_module_0._CHUNK_BYTES
    _RTP_WRAP = _compat_module_0._RTP_WRAP
    _VIDEO_TICKS_PER_MS = _compat_module_0._VIDEO_TICKS_PER_MS
    ANNEX_B_START_CODE = _compat_module_0.ANNEX_B_START_CODE
    AppPlaybackClock = _compat_module_0.AppPlaybackClock
    AppTimedFrame = _compat_module_0.AppTimedFrame
    Fraction = _compat_module_0.Fraction
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    PyEzvizError = _compat_module_0.PyEzvizError
    RtpAacStream = _compat_module_0.RtpAacStream
    _audio_events = _compat_module_0._audio_events
    _pack_header = _compat_module_0._pack_header
    _pes = _compat_module_0._pes
    _program_stream_map = _compat_module_0._program_stream_map
    annotations = _compat_module_0.annotations
    chain = _compat_module_0.chain
    groupby = _compat_module_0.groupby
    merge = _compat_module_0.merge
    native_app_timed_payloads = _compat_module_0.native_app_timed_payloads
    rtp_nal_units_have_vcl = _compat_module_0.rtp_nal_units_have_vcl

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _CHUNK_BYTES,
        _RTP_WRAP,
        _VIDEO_TICKS_PER_MS,
        ANNEX_B_START_CODE,
        AppPlaybackClock,
        AppTimedFrame,
        Fraction,
        Iterable,
        Iterator,
        PyEzvizError,
        RtpAacStream,
        _audio_events,
        _pack_header,
        _pes,
        _program_stream_map,
        annotations,
        chain,
        groupby,
        merge,
        native_app_timed_payloads,
        rtp_nal_units_have_vcl,
    )

sys.modules[__name__] = _implementation
