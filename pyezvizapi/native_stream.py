# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.native_stream`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import native_stream as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.native_stream import (
        _POLL_SECONDS as _POLL_SECONDS,
        IO_CHUNK_BYTES as IO_CHUNK_BYTES,
        MAX_PENDING_PS_BYTES as MAX_PENDING_PS_BYTES,
        OUTPUT_QUEUE_CHUNKS as OUTPUT_QUEUE_CHUNKS,
        TYPE_CHECKING as TYPE_CHECKING,
        Any as Any,
        AsyncGenerator as AsyncGenerator,
        AutoClipSource as AutoClipSource,
        BoundedSemaphore as BoundedSemaphore,
        Callable as Callable,
        Empty as Empty,
        Event as Event,
        Fraction as Fraction,
        Iterator as Iterator,
        Literal as Literal,
        Lock as Lock,
        MediaPacket as MediaPacket,
        NativeMediaCompletion as NativeMediaCompletion,
        NativeMpegTsStream as NativeMpegTsStream,
        NativePacketStream as NativePacketStream,
        NativePsTransform as NativePsTransform,
        NativeSourceClock as NativeSourceClock,
        NativeStreamClosed as NativeStreamClosed,
        NativeStreamOptions as NativeStreamOptions,
        NativeTrackCompletion as NativeTrackCompletion,
        NativeTrackSelection as NativeTrackSelection,
        Protocol as Protocol,
        PyEzvizError as PyEzvizError,
        Queue as Queue,
        Thread as Thread,
        _CallOutcome as _CallOutcome,
        _Cancelled as _Cancelled,
        _join_async_task as _join_async_task,
        _owned_thread_call as _owned_thread_call,
        _PsInput as _PsInput,
        _TsOutput as _TsOutput,
        _unwrap_call as _unwrap_call,
        annotations as annotations,
        asyncio as asyncio,
        cast as cast,
        current_thread as current_thread,
        dataclass as dataclass,
        hashlib as hashlib,
        import_module as import_module,
        io as io,
        math as math,
        native_mpegts_stream_from_client as native_mpegts_stream_from_client,
        secrets as secrets,
        suppress as suppress,
        sys as sys,
        time as time,
    )

sys.modules[__name__] = _implementation
