# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.native_session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import native_session as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.native_session as _compat_module_0
    _POLL_SECONDS = _compat_module_0._POLL_SECONDS
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    Event = _compat_module_0.Event
    ExitStack = _compat_module_0.ExitStack
    Fraction = _compat_module_0.Fraction
    Lock = _compat_module_0.Lock
    NativeMediaCompletion = _compat_module_0.NativeMediaCompletion
    NativeMpegTsSession = _compat_module_0.NativeMpegTsSession
    NativeMpegTsStream = _compat_module_0.NativeMpegTsStream
    NativePacketStream = _compat_module_0.NativePacketStream
    NativeSourceClock = _compat_module_0.NativeSourceClock
    NativeStreamClosed = _compat_module_0.NativeStreamClosed
    NativeStreamOptions = _compat_module_0.NativeStreamOptions
    PyEzvizError = _compat_module_0.PyEzvizError
    _Binding = _compat_module_0._Binding
    _Cancelled = _compat_module_0._Cancelled
    _no_source = _compat_module_0._no_source
    _PsInput = _compat_module_0._PsInput
    _SessionOutput = _compat_module_0._SessionOutput
    _TsOutput = _compat_module_0._TsOutput
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    math = _compat_module_0.math
    replace = _compat_module_0.replace
    self_contained_idr = _compat_module_0.self_contained_idr
    suppress = _compat_module_0.suppress
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _POLL_SECONDS,
        Any,
        Callable,
        Event,
        ExitStack,
        Fraction,
        Lock,
        NativeMediaCompletion,
        NativeMpegTsSession,
        NativeMpegTsStream,
        NativePacketStream,
        NativeSourceClock,
        NativeStreamClosed,
        NativeStreamOptions,
        PyEzvizError,
        _Binding,
        _Cancelled,
        _no_source,
        _PsInput,
        _SessionOutput,
        _TsOutput,
        annotations,
        dataclass,
        math,
        replace,
        self_contained_idr,
        suppress,
        time,
    )

sys.modules[__name__] = _implementation
