"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.models`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import models as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.models import (
    Any as Any,
    Callable as Callable,
    CaptureLimits as CaptureLimits,
    DeadlineLegacyPacketSource as DeadlineLegacyPacketSource,
    Empty as Empty,
    Event as Event,
    Full as Full,
    Iterable as Iterable,
    IterableMediaPacketSource as IterableMediaPacketSource,
    Iterator as Iterator,
    LegacyPacketSource as LegacyPacketSource,
    Literal as Literal,
    Lock as Lock,
    Mapping as Mapping,
    MappingProxyType as MappingProxyType,
    MediaDecodeOptions as MediaDecodeOptions,
    MediaMetadataValue as MediaMetadataValue,
    MediaMuxOptions as MediaMuxOptions,
    MediaOutputFormat as MediaOutputFormat,
    MediaPacket as MediaPacket,
    MediaPacketMetadata as MediaPacketMetadata,
    MediaPacketSource as MediaPacketSource,
    MediaPacketSourceAdapter as MediaPacketSourceAdapter,
    Protocol as Protocol,
    PyEzvizError as PyEzvizError,
    Queue as Queue,
    Thread as Thread,
    TypedDict as TypedDict,
    _AppRemuxOptions as _AppRemuxOptions,
    _HevcParameterOptions as _HevcParameterOptions,
    _ITERATOR_CLOSE_TIMEOUT_SECONDS as _ITERATOR_CLOSE_TIMEOUT_SECONDS,
    _ITERATOR_STOPPED as _ITERATOR_STOPPED,
    _ITERATOR_TIMED_OUT as _ITERATOR_TIMED_OUT,
    _IterableProducerState as _IterableProducerState,
    _IteratorProducer as _IteratorProducer,
    _NativeTimingOptions as _NativeTimingOptions,
    _app_remux_options as _app_remux_options,
    _hevc_parameter_options as _hevc_parameter_options,
    _native_timing_options as _native_timing_options,
    abstractmethod as abstractmethod,
    annotations as annotations,
    cast as cast,
    dataclass as dataclass,
    field as field,
    has_positive_finite_capture_bound as has_positive_finite_capture_bound,
    is_positive_capture_count_bound as is_positive_capture_count_bound,
    is_positive_finite_duration_bound as is_positive_finite_duration_bound,
    math as math,
    runtime_checkable as runtime_checkable,
    suppress as suppress,
    time as time,
    )

sys.modules[__name__] = _implementation
