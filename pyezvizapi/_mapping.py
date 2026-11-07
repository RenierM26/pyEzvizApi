"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.mapping`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import mapping as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.mapping import (
    Any as Any,
    Iterable as Iterable,
    Iterator as Iterator,
    PathComponent as PathComponent,
    WILDCARD_STEP as WILDCARD_STEP,
    _MISSING as _MISSING,
    annotations as annotations,
    deep_merge as deep_merge,
    fetch_nested_value as fetch_nested_value,
    first_nested as first_nested,
    iter_nested as iter_nested,
    )

sys.modules[__name__] = _implementation
