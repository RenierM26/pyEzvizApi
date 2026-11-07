# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.rtp_timing`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import rtp_timing as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.rtp_timing as _compat_module_0
    _ADTS_HEADER_PREFIX = _compat_module_0._ADTS_HEADER_PREFIX
    _PES_CHUNK_BYTES = _compat_module_0._PES_CHUNK_BYTES
    _RTP_VIDEO_CLOCK = _compat_module_0._RTP_VIDEO_CLOCK
    ANNEX_B_START_CODE = _compat_module_0.ANNEX_B_START_CODE
    EzvizUnsupportedMediaError = _compat_module_0.EzvizUnsupportedMediaError
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    NativeRtpClockProbe = _compat_module_0.NativeRtpClockProbe
    NativeRtpPsMuxer = _compat_module_0.NativeRtpPsMuxer
    PyEzvizError = _compat_module_0.PyEzvizError
    RtpAacStream = _compat_module_0.RtpAacStream
    RtpVideoCodec = _compat_module_0.RtpVideoCodec
    _aac_timestamp_delta_is_supported = _compat_module_0._aac_timestamp_delta_is_supported
    _audio_events = _compat_module_0._audio_events
    _mpeg_crc32 = _compat_module_0._mpeg_crc32
    _pack_header = _compat_module_0._pack_header
    _pes = _compat_module_0._pes
    _program_stream_map = _compat_module_0._program_stream_map
    _rtp_nal_starts_picture = _compat_module_0._rtp_nal_starts_picture
    _shared_clock_error = _compat_module_0._shared_clock_error
    _video_events = _compat_module_0._video_events
    annotations = _compat_module_0.annotations
    chain = _compat_module_0.chain
    dataclass = _compat_module_0.dataclass
    field = _compat_module_0.field
    groupby = _compat_module_0.groupby
    merge = _compat_module_0.merge
    probe_native_rtp_clock = _compat_module_0.probe_native_rtp_clock
    rtp_nal_units_have_vcl = _compat_module_0.rtp_nal_units_have_vcl
    shared_rtp_clock_offsets = _compat_module_0.shared_rtp_clock_offsets
    tee = _compat_module_0.tee
    timed_rtp_mpegps_payloads = _compat_module_0.timed_rtp_mpegps_payloads

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _ADTS_HEADER_PREFIX,
        _PES_CHUNK_BYTES,
        _RTP_VIDEO_CLOCK,
        ANNEX_B_START_CODE,
        EzvizUnsupportedMediaError,
        Iterable,
        Iterator,
        NativeRtpClockProbe,
        NativeRtpPsMuxer,
        PyEzvizError,
        RtpAacStream,
        RtpVideoCodec,
        _aac_timestamp_delta_is_supported,
        _audio_events,
        _mpeg_crc32,
        _pack_header,
        _pes,
        _program_stream_map,
        _rtp_nal_starts_picture,
        _shared_clock_error,
        _video_events,
        annotations,
        chain,
        dataclass,
        field,
        groupby,
        merge,
        probe_native_rtp_clock,
        rtp_nal_units_have_vcl,
        shared_rtp_clock_offsets,
        tee,
        timed_rtp_mpegps_payloads,
    )

sys.modules[__name__] = _implementation
