# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.models`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import models as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.models as _compat_module_0
    _ITERATOR_CLOSE_TIMEOUT_SECONDS = _compat_module_0._ITERATOR_CLOSE_TIMEOUT_SECONDS
    _ITERATOR_STOPPED = _compat_module_0._ITERATOR_STOPPED
    _ITERATOR_TIMED_OUT = _compat_module_0._ITERATOR_TIMED_OUT
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    CaptureLimits = _compat_module_0.CaptureLimits
    DeadlineLegacyPacketSource = _compat_module_0.DeadlineLegacyPacketSource
    Empty = _compat_module_0.Empty
    Event = _compat_module_0.Event
    Full = _compat_module_0.Full
    Iterable = _compat_module_0.Iterable
    IterableMediaPacketSource = _compat_module_0.IterableMediaPacketSource
    Iterator = _compat_module_0.Iterator
    LegacyPacketSource = _compat_module_0.LegacyPacketSource
    Literal = _compat_module_0.Literal
    Lock = _compat_module_0.Lock
    Mapping = _compat_module_0.Mapping
    MappingProxyType = _compat_module_0.MappingProxyType
    MediaDecodeOptions = _compat_module_0.MediaDecodeOptions
    MediaMetadataValue = _compat_module_0.MediaMetadataValue
    MediaMuxOptions = _compat_module_0.MediaMuxOptions
    MediaOutputFormat = _compat_module_0.MediaOutputFormat
    MediaPacket = _compat_module_0.MediaPacket
    MediaPacketMetadata = _compat_module_0.MediaPacketMetadata
    MediaPacketSource = _compat_module_0.MediaPacketSource
    MediaPacketSourceAdapter = _compat_module_0.MediaPacketSourceAdapter
    Protocol = _compat_module_0.Protocol
    PyEzvizError = _compat_module_0.PyEzvizError
    Queue = _compat_module_0.Queue
    Thread = _compat_module_0.Thread
    TypedDict = _compat_module_0.TypedDict
    _app_remux_options = _compat_module_0._app_remux_options
    _AppRemuxOptions = _compat_module_0._AppRemuxOptions
    _hevc_parameter_options = _compat_module_0._hevc_parameter_options
    _HevcParameterOptions = _compat_module_0._HevcParameterOptions
    _IterableProducerState = _compat_module_0._IterableProducerState
    _IteratorProducer = _compat_module_0._IteratorProducer
    _native_timing_options = _compat_module_0._native_timing_options
    _NativeTimingOptions = _compat_module_0._NativeTimingOptions
    abstractmethod = _compat_module_0.abstractmethod
    annotations = _compat_module_0.annotations
    cast = _compat_module_0.cast
    dataclass = _compat_module_0.dataclass
    field = _compat_module_0.field
    has_positive_finite_capture_bound = _compat_module_0.has_positive_finite_capture_bound
    is_positive_capture_count_bound = _compat_module_0.is_positive_capture_count_bound
    is_positive_finite_duration_bound = _compat_module_0.is_positive_finite_duration_bound
    math = _compat_module_0.math
    runtime_checkable = _compat_module_0.runtime_checkable
    suppress = _compat_module_0.suppress
    time = _compat_module_0.time

sys.modules[__name__] = _implementation
