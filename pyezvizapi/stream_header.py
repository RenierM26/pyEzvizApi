# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.header`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import header as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.header import (
        _AUDIO_CODECS as _AUDIO_CODECS,
        _STREAM_HEADER_MAGIC as _STREAM_HEADER_MAGIC,
        _VIDEO_CODECS as _VIDEO_CODECS,
        ET as ET,
        EzvizStreamHeader as EzvizStreamHeader,
        PyEzvizError as PyEzvizError,
        annotations as annotations,
        base64 as base64,
        binascii as binascii,
        dataclass as dataclass,
        parse_ezviz_stream_header as parse_ezviz_stream_header,
        stream_header_from_preview as stream_header_from_preview,
        struct as struct,
    )

sys.modules[__name__] = _implementation
