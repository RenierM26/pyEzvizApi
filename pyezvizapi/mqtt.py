"""HA compatibility exports; new code should use :mod:`pyezvizapi.push.mqtt`."""

from pyezvizapi.push.mqtt import (
    MQTTClient,
)

__all__ = ["MQTTClient"]
