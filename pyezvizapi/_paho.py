# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.paho`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push import paho as _implementation

if TYPE_CHECKING:
    import paho.mqtt.client as _compat_module_0
    Client = _compat_module_0.Client

    import pyezvizapi.push.paho as _compat_module_1
    set_keepalive = _compat_module_1.set_keepalive

sys.modules[__name__] = _implementation
