# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.header`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import header as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.header as _compat_module_0
    _AUDIO_CODECS = _compat_module_0._AUDIO_CODECS
    _STREAM_HEADER_MAGIC = _compat_module_0._STREAM_HEADER_MAGIC
    _VIDEO_CODECS = _compat_module_0._VIDEO_CODECS
    ET = _compat_module_0.ET
    EzvizStreamHeader = _compat_module_0.EzvizStreamHeader
    PyEzvizError = _compat_module_0.PyEzvizError
    annotations = _compat_module_0.annotations
    base64 = _compat_module_0.base64
    binascii = _compat_module_0.binascii
    dataclass = _compat_module_0.dataclass
    parse_ezviz_stream_header = _compat_module_0.parse_ezviz_stream_header
    stream_header_from_preview = _compat_module_0.stream_header_from_preview
    struct = _compat_module_0.struct

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _AUDIO_CODECS,
        _STREAM_HEADER_MAGIC,
        _VIDEO_CODECS,
        ET,
        EzvizStreamHeader,
        PyEzvizError,
        annotations,
        base64,
        binascii,
        dataclass,
        parse_ezviz_stream_header,
        stream_header_from_preview,
        struct,
    )

sys.modules[__name__] = _implementation
