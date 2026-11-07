# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.resolver`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import resolver as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.resolver import (
        _STOP as _STOP,
        DEFAULT_RESOLVER as DEFAULT_RESOLVER,
        Any as Any,
        BoundedResolver as BoundedResolver,
        Callable as Callable,
        Empty as Empty,
        Event as Event,
        Full as Full,
        Lock as Lock,
        Queue as Queue,
        ResolverBusy as ResolverBusy,
        ResolverClosed as ResolverClosed,
        Thread as Thread,
        _Request as _Request,
        annotations as annotations,
        cast as cast,
        dataclass as dataclass,
        field as field,
        math as math,
        socket as socket,
        suppress as suppress,
    )

sys.modules[__name__] = _implementation
