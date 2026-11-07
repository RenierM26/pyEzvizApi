# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import transport as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.longlink.transport as _compat_module_0
    MAX_LENGTH_BYTES = _compat_module_0.MAX_LENGTH_BYTES
    MAX_PAYLOAD = _compat_module_0.MAX_PAYLOAD
    Callable = _compat_module_0.Callable
    LbsConnection = _compat_module_0.LbsConnection
    TracebackType = _compat_module_0.TracebackType
    annotations = _compat_module_0.annotations
    socket = _compat_module_0.socket
    suppress = _compat_module_0.suppress
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        MAX_LENGTH_BYTES,
        MAX_PAYLOAD,
        Callable,
        LbsConnection,
        TracebackType,
        annotations,
        socket,
        suppress,
        time,
    )

sys.modules[__name__] = _implementation
