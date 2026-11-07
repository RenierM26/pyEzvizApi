# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.native_stream`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import native_stream as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.native_stream as _compat_module_0
    _POLL_SECONDS = _compat_module_0._POLL_SECONDS
    IO_CHUNK_BYTES = _compat_module_0.IO_CHUNK_BYTES
    MAX_PENDING_PS_BYTES = _compat_module_0.MAX_PENDING_PS_BYTES
    OUTPUT_QUEUE_CHUNKS = _compat_module_0.OUTPUT_QUEUE_CHUNKS
    Any = _compat_module_0.Any
    AsyncGenerator = _compat_module_0.AsyncGenerator
    AutoClipSource = _compat_module_0.AutoClipSource
    BoundedSemaphore = _compat_module_0.BoundedSemaphore
    Callable = _compat_module_0.Callable
    Empty = _compat_module_0.Empty
    Event = _compat_module_0.Event
    Fraction = _compat_module_0.Fraction
    Iterator = _compat_module_0.Iterator
    Literal = _compat_module_0.Literal
    Lock = _compat_module_0.Lock
    MediaPacket = _compat_module_0.MediaPacket
    NativeMediaCompletion = _compat_module_0.NativeMediaCompletion
    NativeMpegTsStream = _compat_module_0.NativeMpegTsStream
    NativePacketStream = _compat_module_0.NativePacketStream
    NativePsTransform = _compat_module_0.NativePsTransform
    NativeSourceClock = _compat_module_0.NativeSourceClock
    NativeStreamClosed = _compat_module_0.NativeStreamClosed
    NativeStreamOptions = _compat_module_0.NativeStreamOptions
    NativeTrackCompletion = _compat_module_0.NativeTrackCompletion
    NativeTrackSelection = _compat_module_0.NativeTrackSelection
    Protocol = _compat_module_0.Protocol
    PyEzvizError = _compat_module_0.PyEzvizError
    Queue = _compat_module_0.Queue
    Thread = _compat_module_0.Thread
    _CallOutcome = _compat_module_0._CallOutcome
    _Cancelled = _compat_module_0._Cancelled
    _join_async_task = _compat_module_0._join_async_task
    _owned_thread_call = _compat_module_0._owned_thread_call
    _PsInput = _compat_module_0._PsInput
    _TsOutput = _compat_module_0._TsOutput
    _unwrap_call = _compat_module_0._unwrap_call
    annotations = _compat_module_0.annotations
    asyncio = _compat_module_0.asyncio
    cast = _compat_module_0.cast
    current_thread = _compat_module_0.current_thread
    dataclass = _compat_module_0.dataclass
    hashlib = _compat_module_0.hashlib
    import_module = _compat_module_0.import_module
    io = _compat_module_0.io
    math = _compat_module_0.math
    native_mpegts_stream_from_client = _compat_module_0.native_mpegts_stream_from_client
    secrets = _compat_module_0.secrets
    suppress = _compat_module_0.suppress
    sys = _compat_module_0.sys
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _POLL_SECONDS,
        IO_CHUNK_BYTES,
        MAX_PENDING_PS_BYTES,
        OUTPUT_QUEUE_CHUNKS,
        Any,
        AsyncGenerator,
        AutoClipSource,
        BoundedSemaphore,
        Callable,
        Empty,
        Event,
        Fraction,
        Iterator,
        Literal,
        Lock,
        MediaPacket,
        NativeMediaCompletion,
        NativeMpegTsStream,
        NativePacketStream,
        NativePsTransform,
        NativeSourceClock,
        NativeStreamClosed,
        NativeStreamOptions,
        NativeTrackCompletion,
        NativeTrackSelection,
        Protocol,
        PyEzvizError,
        Queue,
        Thread,
        _CallOutcome,
        _Cancelled,
        _join_async_task,
        _owned_thread_call,
        _PsInput,
        _TsOutput,
        _unwrap_call,
        annotations,
        asyncio,
        cast,
        current_thread,
        dataclass,
        hashlib,
        import_module,
        io,
        math,
        native_mpegts_stream_from_client,
        secrets,
        suppress,
        sys,
        time,
    )

sys.modules[__name__] = _implementation
