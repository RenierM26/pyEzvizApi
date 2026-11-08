# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.access`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import access as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.media.access as _compat_module_0

    _PREFIX_BYTES = _compat_module_0._PREFIX_BYTES
    _START = _compat_module_0._START
    MAX_PENDING_PS_BYTES = _compat_module_0.MAX_PENDING_PS_BYTES
    Iterator = _compat_module_0.Iterator
    _Bits = _compat_module_0._Bits
    _check_idr = _compat_module_0._check_idr
    _hevc_sps = _compat_module_0._hevc_sps
    _units = _compat_module_0._units
    annotations = _compat_module_0.annotations
    re = _compat_module_0.re
    self_contained_idr = _compat_module_0.self_contained_idr

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _PREFIX_BYTES,
        _START,
        MAX_PENDING_PS_BYTES,
        Iterator,
        _Bits,
        _check_idr,
        _hevc_sps,
        _units,
        annotations,
        re,
        self_contained_idr,
    )

sys.modules[__name__] = _implementation
