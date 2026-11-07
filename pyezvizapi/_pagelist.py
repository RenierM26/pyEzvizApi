# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.pagination`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import pagination as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.pagination as _compat_module_0
    MAX_PAGELIST_PAGES = _compat_module_0.MAX_PAGELIST_PAGES
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    Mapping = _compat_module_0.Mapping
    PyEzvizError = _compat_module_0.PyEzvizError
    annotations = _compat_module_0.annotations
    collect_pagelist = _compat_module_0.collect_pagelist
    deep_merge = _compat_module_0.deep_merge
    json = _compat_module_0.json
    sha256 = _compat_module_0.sha256

sys.modules[__name__] = _implementation
