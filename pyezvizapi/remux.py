"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.remux`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import remux as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.remux import (
    Any as Any,
    BinaryIO as BinaryIO,
    BoundedStderrTail as BoundedStderrTail,
    Callable as Callable,
    Event as Event,
    FFMPEG_IO_CHUNK_SIZE as FFMPEG_IO_CHUNK_SIZE,
    FFMPEG_STDERR_MAX_BYTES as FFMPEG_STDERR_MAX_BYTES,
    FFMPEG_STDERR_MAX_CHARS as FFMPEG_STDERR_MAX_CHARS,
    FFMPEG_STOP_TIMEOUT_SECONDS as FFMPEG_STOP_TIMEOUT_SECONDS,
    Literal as Literal,
    Lock as Lock,
    Path as Path,
    PyEzvizError as PyEzvizError,
    RtpAacStream as RtpAacStream,
    Thread as Thread,
    _ffmpeg_exit_error as _ffmpeg_exit_error,
    _wait_for_process as _wait_for_process,
    annotations as annotations,
    cast as cast,
    copy_remuxed_output as copy_remuxed_output,
    ffmpeg_mpegts_command as ffmpeg_mpegts_command,
    open_mpegts_remux_process as open_mpegts_remux_process,
    remux_bytes as remux_bytes,
    start_stderr_drain as start_stderr_drain,
    subprocess as subprocess,
    suppress as suppress,
    write_aac_remux_input as write_aac_remux_input,
    )

sys.modules[__name__] = _implementation
