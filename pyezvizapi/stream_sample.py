# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.sample`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import sample as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.sample as _compat_module_0
    MAX_PROBE_JSON_BYTES = _compat_module_0.MAX_PROBE_JSON_BYTES
    MAX_PROBE_STREAMS = _compat_module_0.MAX_PROBE_STREAMS
    MAX_REMUX_BYTES = _compat_module_0.MAX_REMUX_BYTES
    MAX_SAMPLE_BYTES = _compat_module_0.MAX_SAMPLE_BYTES
    MAX_SAMPLE_PACKETS = _compat_module_0.MAX_SAMPLE_PACKETS
    Any = _compat_module_0.Any
    BinaryIO = _compat_module_0.BinaryIO
    ClipOptions = _compat_module_0.ClipOptions
    EncodedTrackSelection = _compat_module_0.EncodedTrackSelection
    PyEzvizError = _compat_module_0.PyEzvizError
    TemporaryFile = _compat_module_0.TemporaryFile
    _input_args = _compat_module_0._input_args
    _SampleBuffer = _compat_module_0._SampleBuffer
    _validate_timeout = _compat_module_0._validate_timeout
    annotations = _compat_module_0.annotations
    capture_media_sample = _compat_module_0.capture_media_sample
    cast = _compat_module_0.cast
    dataclass = _compat_module_0.dataclass
    hashlib = _compat_module_0.hashlib
    inspect_media_sample = _compat_module_0.inspect_media_sample
    io = _compat_module_0.io
    json = _compat_module_0.json
    math = _compat_module_0.math
    remux_media_sample = _compat_module_0.remux_media_sample
    subprocess = _compat_module_0.subprocess
    validate_media_sample = _compat_module_0.validate_media_sample

sys.modules[__name__] = _implementation
