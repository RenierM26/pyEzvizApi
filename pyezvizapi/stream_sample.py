"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.sample`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import sample as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.sample import (
    Any as Any,
    BinaryIO as BinaryIO,
    ClipOptions as ClipOptions,
    EncodedTrackSelection as EncodedTrackSelection,
    MAX_PROBE_JSON_BYTES as MAX_PROBE_JSON_BYTES,
    MAX_PROBE_STREAMS as MAX_PROBE_STREAMS,
    MAX_REMUX_BYTES as MAX_REMUX_BYTES,
    MAX_SAMPLE_BYTES as MAX_SAMPLE_BYTES,
    MAX_SAMPLE_PACKETS as MAX_SAMPLE_PACKETS,
    PyEzvizError as PyEzvizError,
    TYPE_CHECKING as TYPE_CHECKING,
    TemporaryFile as TemporaryFile,
    _SampleBuffer as _SampleBuffer,
    _input_args as _input_args,
    _validate_timeout as _validate_timeout,
    annotations as annotations,
    capture_media_sample as capture_media_sample,
    cast as cast,
    dataclass as dataclass,
    hashlib as hashlib,
    inspect_media_sample as inspect_media_sample,
    io as io,
    json as json,
    math as math,
    remux_media_sample as remux_media_sample,
    subprocess as subprocess,
    validate_media_sample as validate_media_sample,
    )

sys.modules[__name__] = _implementation
