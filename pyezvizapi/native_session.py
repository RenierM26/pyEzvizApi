# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.native_session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import native_session as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.native_session import (
        _POLL_SECONDS as _POLL_SECONDS,
        Any as Any,
        Callable as Callable,
        Event as Event,
        ExitStack as ExitStack,
        Fraction as Fraction,
        Lock as Lock,
        NativeMediaCompletion as NativeMediaCompletion,
        NativeMpegTsSession as NativeMpegTsSession,
        NativeMpegTsStream as NativeMpegTsStream,
        NativePacketStream as NativePacketStream,
        NativeSourceClock as NativeSourceClock,
        NativeStreamClosed as NativeStreamClosed,
        NativeStreamOptions as NativeStreamOptions,
        PyEzvizError as PyEzvizError,
        _Binding as _Binding,
        _Cancelled as _Cancelled,
        _no_source as _no_source,
        _PsInput as _PsInput,
        _SessionOutput as _SessionOutput,
        _TsOutput as _TsOutput,
        annotations as annotations,
        dataclass as dataclass,
        math as math,
        replace as replace,
        self_contained_idr as self_contained_idr,
        suppress as suppress,
        time as time,
    )

sys.modules[__name__] = _implementation
