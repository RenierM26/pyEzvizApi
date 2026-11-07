"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.resolver`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import resolver as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.resolver import (
    Any as Any,
    BoundedResolver as BoundedResolver,
    Callable as Callable,
    DEFAULT_RESOLVER as DEFAULT_RESOLVER,
    Empty as Empty,
    Event as Event,
    Full as Full,
    Lock as Lock,
    Queue as Queue,
    ResolverBusy as ResolverBusy,
    ResolverClosed as ResolverClosed,
    Thread as Thread,
    _Request as _Request,
    _STOP as _STOP,
    annotations as annotations,
    cast as cast,
    dataclass as dataclass,
    field as field,
    math as math,
    socket as socket,
    suppress as suppress,
    )

sys.modules[__name__] = _implementation
