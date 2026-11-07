"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import transport as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.transport import (
    Callable as Callable,
    LbsConnection as LbsConnection,
    MAX_LENGTH_BYTES as MAX_LENGTH_BYTES,
    MAX_PAYLOAD as MAX_PAYLOAD,
    TracebackType as TracebackType,
    annotations as annotations,
    socket as socket,
    suppress as suppress,
    time as time,
    )

sys.modules[__name__] = _implementation
