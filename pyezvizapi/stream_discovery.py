"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.discovery`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import discovery as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.discovery import (
    Callable as Callable,
    EzvizStreamHeader as EzvizStreamHeader,
    Literal as Literal,
    LocalStreamDiscovery as LocalStreamDiscovery,
    LocalStreamDiscoveryCache as LocalStreamDiscoveryCache,
    Lock as Lock,
    OrderedDict as OrderedDict,
    PyEzvizError as PyEzvizError,
    annotations as annotations,
    dataclass as dataclass,
    math as math,
    time as time,
    )

sys.modules[__name__] = _implementation
