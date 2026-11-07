# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.app_capture`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import app_capture as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.app_capture import (
        _CHUNK_BYTES as _CHUNK_BYTES,
        _RTP_WRAP as _RTP_WRAP,
        _VIDEO_TICKS_PER_MS as _VIDEO_TICKS_PER_MS,
        ANNEX_B_START_CODE as ANNEX_B_START_CODE,
        AppPlaybackClock as AppPlaybackClock,
        AppTimedFrame as AppTimedFrame,
        Fraction as Fraction,
        Iterable as Iterable,
        Iterator as Iterator,
        PyEzvizError as PyEzvizError,
        RtpAacStream as RtpAacStream,
        _audio_events as _audio_events,
        _pack_header as _pack_header,
        _pes as _pes,
        _program_stream_map as _program_stream_map,
        annotations as annotations,
        chain as chain,
        groupby as groupby,
        merge as merge,
        native_app_timed_payloads as native_app_timed_payloads,
        rtp_nal_units_have_vcl as rtp_nal_units_have_vcl,
    )

sys.modules[__name__] = _implementation
