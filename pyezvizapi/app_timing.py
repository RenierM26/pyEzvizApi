"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.app_timing`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import app_timing as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.app_timing import (
    AppPlaybackClock as AppPlaybackClock,
    AppTimedFrame as AppTimedFrame,
    BinaryIO as BinaryIO,
    Iterable as Iterable,
    Iterator as Iterator,
    Literal as Literal,
    PyEzvizError as PyEzvizError,
    _PES_CHUNK_BYTES as _PES_CHUNK_BYTES,
    _TICKS_PER_MS as _TICKS_PER_MS,
    _TrackClock as _TrackClock,
    _mpeg_crc32 as _mpeg_crc32,
    _pack_header as _pack_header,
    _pes as _pes,
    _stream_map as _stream_map,
    _validate_frame as _validate_frame,
    annotations as annotations,
    app_timed_mpegps_payloads as app_timed_mpegps_payloads,
    chain as chain,
    copy_app_timed_frames_to_mpegts as copy_app_timed_frames_to_mpegts,
    copy_remuxed_output as copy_remuxed_output,
    dataclass as dataclass,
    open_mpegts_remux_process as open_mpegts_remux_process,
    subprocess as subprocess,
    )

sys.modules[__name__] = _implementation
