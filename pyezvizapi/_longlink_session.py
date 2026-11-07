"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import session as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.session import (
    Any as Any,
    Callable as Callable,
    CallbackAPIVersion as CallbackAPIVersion,
    Channel99Session as Channel99Session,
    Event as Event,
    EzvizPushFatalError as EzvizPushFatalError,
    LbsConnection as LbsConnection,
    Lock as Lock,
    PushCredentials as PushCredentials,
    _MQTT_SETUP_TIMEOUT as _MQTT_SETUP_TIMEOUT,
    _PERMANENT_CONNACK_REASONS as _PERMANENT_CONNACK_REASONS,
    annotations as annotations,
    authenticate as authenticate,
    json as json,
    monotonic as monotonic,
    mqtt as mqtt,
    set_keepalive as set_keepalive,
    socket as socket,
    wire as wire,
    )

sys.modules[__name__] = _implementation
