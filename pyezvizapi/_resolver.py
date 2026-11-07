# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.resolver`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import resolver as _implementation

if TYPE_CHECKING:
    import pyezvizapi._shared.resolver as _compat_module_0
    _STOP = _compat_module_0._STOP
    DEFAULT_RESOLVER = _compat_module_0.DEFAULT_RESOLVER
    Any = _compat_module_0.Any
    BoundedResolver = _compat_module_0.BoundedResolver
    Callable = _compat_module_0.Callable
    Empty = _compat_module_0.Empty
    Event = _compat_module_0.Event
    Full = _compat_module_0.Full
    Lock = _compat_module_0.Lock
    Queue = _compat_module_0.Queue
    ResolverBusy = _compat_module_0.ResolverBusy
    ResolverClosed = _compat_module_0.ResolverClosed
    Thread = _compat_module_0.Thread
    _Request = _compat_module_0._Request
    annotations = _compat_module_0.annotations
    cast = _compat_module_0.cast
    dataclass = _compat_module_0.dataclass
    field = _compat_module_0.field
    math = _compat_module_0.math
    socket = _compat_module_0.socket
    suppress = _compat_module_0.suppress

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _STOP,
        DEFAULT_RESOLVER,
        Any,
        BoundedResolver,
        Callable,
        Empty,
        Event,
        Full,
        Lock,
        Queue,
        ResolverBusy,
        ResolverClosed,
        Thread,
        _Request,
        annotations,
        cast,
        dataclass,
        field,
        math,
        socket,
        suppress,
    )

sys.modules[__name__] = _implementation
