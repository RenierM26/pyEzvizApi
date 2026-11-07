# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.mapping`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import mapping as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.mapping import (
        _MISSING as _MISSING,
        WILDCARD_STEP as WILDCARD_STEP,
        Any as Any,
        Iterable as Iterable,
        Iterator as Iterator,
        PathComponent as PathComponent,
        annotations as annotations,
        deep_merge as deep_merge,
        fetch_nested_value as fetch_nested_value,
        first_nested as first_nested,
        iter_nested as iter_nested,
    )

sys.modules[__name__] = _implementation
