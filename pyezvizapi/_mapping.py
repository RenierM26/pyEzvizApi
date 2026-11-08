# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.mapping`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import mapping as _implementation

if TYPE_CHECKING:
    import pyezvizapi._shared.mapping as _compat_module_0

    _MISSING = _compat_module_0._MISSING
    WILDCARD_STEP = _compat_module_0.WILDCARD_STEP
    Any = _compat_module_0.Any
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    PathComponent = _compat_module_0.PathComponent
    annotations = _compat_module_0.annotations
    deep_merge = _compat_module_0.deep_merge
    fetch_nested_value = _compat_module_0.fetch_nested_value
    first_nested = _compat_module_0.first_nested
    iter_nested = _compat_module_0.iter_nested

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _MISSING,
        WILDCARD_STEP,
        Any,
        Iterable,
        Iterator,
        PathComponent,
        annotations,
        deep_merge,
        fetch_nested_value,
        first_nested,
        iter_nested,
    )

sys.modules[__name__] = _implementation
