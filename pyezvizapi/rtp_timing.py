"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.rtp_timing`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import rtp_timing as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.rtp_timing import (
    ANNEX_B_START_CODE as ANNEX_B_START_CODE,
    EzvizUnsupportedMediaError as EzvizUnsupportedMediaError,
    Iterable as Iterable,
    Iterator as Iterator,
    NativeRtpClockProbe as NativeRtpClockProbe,
    NativeRtpPsMuxer as NativeRtpPsMuxer,
    PyEzvizError as PyEzvizError,
    RtpAacStream as RtpAacStream,
    RtpVideoCodec as RtpVideoCodec,
    _ADTS_HEADER_PREFIX as _ADTS_HEADER_PREFIX,
    _PES_CHUNK_BYTES as _PES_CHUNK_BYTES,
    _RTP_VIDEO_CLOCK as _RTP_VIDEO_CLOCK,
    _aac_timestamp_delta_is_supported as _aac_timestamp_delta_is_supported,
    _audio_events as _audio_events,
    _mpeg_crc32 as _mpeg_crc32,
    _pack_header as _pack_header,
    _pes as _pes,
    _program_stream_map as _program_stream_map,
    _rtp_nal_starts_picture as _rtp_nal_starts_picture,
    _shared_clock_error as _shared_clock_error,
    _video_events as _video_events,
    annotations as annotations,
    chain as chain,
    dataclass as dataclass,
    field as field,
    groupby as groupby,
    merge as merge,
    probe_native_rtp_clock as probe_native_rtp_clock,
    rtp_nal_units_have_vcl as rtp_nal_units_have_vcl,
    shared_rtp_clock_offsets as shared_rtp_clock_offsets,
    tee as tee,
    timed_rtp_mpegps_payloads as timed_rtp_mpegps_payloads,
    )

sys.modules[__name__] = _implementation
