# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.discovery`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import discovery as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.discovery as _compat_module_0

    Callable = _compat_module_0.Callable
    EzvizStreamHeader = _compat_module_0.EzvizStreamHeader
    Literal = _compat_module_0.Literal
    LocalStreamDiscovery = _compat_module_0.LocalStreamDiscovery
    LocalStreamDiscoveryCache = _compat_module_0.LocalStreamDiscoveryCache
    Lock = _compat_module_0.Lock
    OrderedDict = _compat_module_0.OrderedDict
    PyEzvizError = _compat_module_0.PyEzvizError
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    math = _compat_module_0.math
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Callable,
        EzvizStreamHeader,
        Literal,
        LocalStreamDiscovery,
        LocalStreamDiscoveryCache,
        Lock,
        OrderedDict,
        PyEzvizError,
        annotations,
        dataclass,
        math,
        time,
    )

sys.modules[__name__] = _implementation
