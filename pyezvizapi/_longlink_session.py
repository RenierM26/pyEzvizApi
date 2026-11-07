# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import session as _implementation

if TYPE_CHECKING:
    from paho.mqtt.enums import CallbackAPIVersion as CallbackAPIVersion

    from pyezvizapi.push.longlink.session import (
        _MQTT_SETUP_TIMEOUT as _MQTT_SETUP_TIMEOUT,
        _PERMANENT_CONNACK_REASONS as _PERMANENT_CONNACK_REASONS,
        Any as Any,
        Callable as Callable,
        Channel99Session as Channel99Session,
        Event as Event,
        EzvizPushFatalError as EzvizPushFatalError,
        LbsConnection as LbsConnection,
        Lock as Lock,
        PushCredentials as PushCredentials,
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
