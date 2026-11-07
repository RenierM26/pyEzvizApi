# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.worker`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import worker as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.longlink.worker as _compat_module_0
    _LOGGER = _compat_module_0._LOGGER
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    Event = _compat_module_0.Event
    EzvizPushFatalError = _compat_module_0.EzvizPushFatalError
    Lock = _compat_module_0.Lock
    Protocol = _compat_module_0.Protocol
    PushSession = _compat_module_0.PushSession
    PushWorker = _compat_module_0.PushWorker
    Thread = _compat_module_0.Thread
    annotations = _compat_module_0.annotations
    current_thread = _compat_module_0.current_thread
    logging = _compat_module_0.logging

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _LOGGER,
        Any,
        Callable,
        Event,
        EzvizPushFatalError,
        Lock,
        Protocol,
        PushSession,
        PushWorker,
        Thread,
        annotations,
        current_thread,
        logging,
    )

sys.modules[__name__] = _implementation
