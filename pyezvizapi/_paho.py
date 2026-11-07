"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.paho`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push import paho as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.paho import (
    Client as Client,
    set_keepalive as set_keepalive,
    )

sys.modules[__name__] = _implementation
