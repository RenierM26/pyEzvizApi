# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.completion`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import completion as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.completion as _compat_module_0
    Literal = _compat_module_0.Literal
    NativeMediaCompletion = _compat_module_0.NativeMediaCompletion
    NativeTrackCompletion = _compat_module_0.NativeTrackCompletion
    dataclass = _compat_module_0.dataclass

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Literal,
        NativeMediaCompletion,
        NativeTrackCompletion,
        dataclass,
    )

sys.modules[__name__] = _implementation
