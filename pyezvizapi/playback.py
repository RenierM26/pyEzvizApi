# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.playback`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import playback as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.playback as _compat_module_0
    Any = _compat_module_0.Any
    EzvizAppPlaybackSupport = _compat_module_0.EzvizAppPlaybackSupport
    Mapping = _compat_module_0.Mapping
    _capability_integer = _compat_module_0._capability_integer
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    inspect_app_playback_support = _compat_module_0.inspect_app_playback_support
    json = _compat_module_0.json
    re = _compat_module_0.re

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        EzvizAppPlaybackSupport,
        Mapping,
        _capability_integer,
        annotations,
        dataclass,
        inspect_app_playback_support,
        json,
        re,
    )

sys.modules[__name__] = _implementation
