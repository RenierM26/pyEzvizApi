"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.header`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import header as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.header import (
    ET as ET,
    EzvizStreamHeader as EzvizStreamHeader,
    PyEzvizError as PyEzvizError,
    _AUDIO_CODECS as _AUDIO_CODECS,
    _STREAM_HEADER_MAGIC as _STREAM_HEADER_MAGIC,
    _VIDEO_CODECS as _VIDEO_CODECS,
    annotations as annotations,
    base64 as base64,
    binascii as binascii,
    dataclass as dataclass,
    parse_ezviz_stream_header as parse_ezviz_stream_header,
    stream_header_from_preview as stream_header_from_preview,
    struct as struct,
    )

sys.modules[__name__] = _implementation
