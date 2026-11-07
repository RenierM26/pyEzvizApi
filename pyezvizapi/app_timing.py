# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.app_timing`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import app_timing as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.app_timing as _compat_module_0
    _PES_CHUNK_BYTES = _compat_module_0._PES_CHUNK_BYTES
    _TICKS_PER_MS = _compat_module_0._TICKS_PER_MS
    AppPlaybackClock = _compat_module_0.AppPlaybackClock
    AppTimedFrame = _compat_module_0.AppTimedFrame
    BinaryIO = _compat_module_0.BinaryIO
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    Literal = _compat_module_0.Literal
    PyEzvizError = _compat_module_0.PyEzvizError
    _mpeg_crc32 = _compat_module_0._mpeg_crc32
    _pack_header = _compat_module_0._pack_header
    _pes = _compat_module_0._pes
    _stream_map = _compat_module_0._stream_map
    _TrackClock = _compat_module_0._TrackClock
    _validate_frame = _compat_module_0._validate_frame
    annotations = _compat_module_0.annotations
    app_timed_mpegps_payloads = _compat_module_0.app_timed_mpegps_payloads
    chain = _compat_module_0.chain
    copy_app_timed_frames_to_mpegts = _compat_module_0.copy_app_timed_frames_to_mpegts
    copy_remuxed_output = _compat_module_0.copy_remuxed_output
    dataclass = _compat_module_0.dataclass
    open_mpegts_remux_process = _compat_module_0.open_mpegts_remux_process
    subprocess = _compat_module_0.subprocess

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _PES_CHUNK_BYTES,
        _TICKS_PER_MS,
        AppPlaybackClock,
        AppTimedFrame,
        BinaryIO,
        Iterable,
        Iterator,
        Literal,
        PyEzvizError,
        _mpeg_crc32,
        _pack_header,
        _pes,
        _stream_map,
        _TrackClock,
        _validate_frame,
        annotations,
        app_timed_mpegps_payloads,
        chain,
        copy_app_timed_frames_to_mpegts,
        copy_remuxed_output,
        dataclass,
        open_mpegts_remux_process,
        subprocess,
    )

sys.modules[__name__] = _implementation
