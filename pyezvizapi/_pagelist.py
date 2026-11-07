# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.pagination`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import pagination as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.pagination import (
        MAX_PAGELIST_PAGES as MAX_PAGELIST_PAGES,
        Any as Any,
        Callable as Callable,
        Mapping as Mapping,
        PyEzvizError as PyEzvizError,
        annotations as annotations,
        collect_pagelist as collect_pagelist,
        deep_merge as deep_merge,
        json as json,
        sha256 as sha256,
    )

sys.modules[__name__] = _implementation
