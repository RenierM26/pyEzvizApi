# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.remux`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import remux as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.remux as _compat_module_0
    FFMPEG_IO_CHUNK_SIZE = _compat_module_0.FFMPEG_IO_CHUNK_SIZE
    FFMPEG_STDERR_MAX_BYTES = _compat_module_0.FFMPEG_STDERR_MAX_BYTES
    FFMPEG_STDERR_MAX_CHARS = _compat_module_0.FFMPEG_STDERR_MAX_CHARS
    FFMPEG_STOP_TIMEOUT_SECONDS = _compat_module_0.FFMPEG_STOP_TIMEOUT_SECONDS
    Any = _compat_module_0.Any
    BinaryIO = _compat_module_0.BinaryIO
    BoundedStderrTail = _compat_module_0.BoundedStderrTail
    Callable = _compat_module_0.Callable
    Event = _compat_module_0.Event
    Literal = _compat_module_0.Literal
    Lock = _compat_module_0.Lock
    Path = _compat_module_0.Path
    PyEzvizError = _compat_module_0.PyEzvizError
    RtpAacStream = _compat_module_0.RtpAacStream
    Thread = _compat_module_0.Thread
    _ffmpeg_exit_error = _compat_module_0._ffmpeg_exit_error
    _wait_for_process = _compat_module_0._wait_for_process
    annotations = _compat_module_0.annotations
    cast = _compat_module_0.cast
    copy_remuxed_output = _compat_module_0.copy_remuxed_output
    ffmpeg_mpegts_command = _compat_module_0.ffmpeg_mpegts_command
    open_mpegts_remux_process = _compat_module_0.open_mpegts_remux_process
    remux_bytes = _compat_module_0.remux_bytes
    start_stderr_drain = _compat_module_0.start_stderr_drain
    subprocess = _compat_module_0.subprocess
    suppress = _compat_module_0.suppress
    write_aac_remux_input = _compat_module_0.write_aac_remux_input

sys.modules[__name__] = _implementation
