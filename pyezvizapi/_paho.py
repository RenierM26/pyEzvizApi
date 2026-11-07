# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.paho`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push import paho as _implementation

if TYPE_CHECKING:
    from paho.mqtt.client import Client as Client

    from pyezvizapi.push.paho import (
        set_keepalive as set_keepalive,
    )

sys.modules[__name__] = _implementation
