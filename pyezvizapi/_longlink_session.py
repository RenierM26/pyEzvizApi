# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import session as _implementation

if TYPE_CHECKING:
    import paho.mqtt.enums as _compat_module_0
    CallbackAPIVersion = _compat_module_0.CallbackAPIVersion

    import pyezvizapi.push.longlink.session as _compat_module_1
    _MQTT_SETUP_TIMEOUT = _compat_module_1._MQTT_SETUP_TIMEOUT
    _PERMANENT_CONNACK_REASONS = _compat_module_1._PERMANENT_CONNACK_REASONS
    Any = _compat_module_1.Any
    Callable = _compat_module_1.Callable
    Channel99Session = _compat_module_1.Channel99Session
    Event = _compat_module_1.Event
    EzvizPushFatalError = _compat_module_1.EzvizPushFatalError
    LbsConnection = _compat_module_1.LbsConnection
    Lock = _compat_module_1.Lock
    PushCredentials = _compat_module_1.PushCredentials
    annotations = _compat_module_1.annotations
    authenticate = _compat_module_1.authenticate
    json = _compat_module_1.json
    monotonic = _compat_module_1.monotonic
    mqtt = _compat_module_1.mqtt
    set_keepalive = _compat_module_1.set_keepalive
    socket = _compat_module_1.socket
    wire = _compat_module_1.wire

sys.modules[__name__] = _implementation
