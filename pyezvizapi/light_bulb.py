# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.light_bulb`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import light_bulb as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.light_bulb import (
    Any as Any,
    DeviceSwitchType as DeviceSwitchType,
    EzvizDeviceRecord as EzvizDeviceRecord,
    EzvizLightBulb as EzvizLightBulb,
    PyEzvizError as PyEzvizError,
    annotations as annotations,
    fetch_nested_value as fetch_nested_value,
    json as json,
    local_ip_address as local_ip_address,
    switch_values as switch_values,
    )

sys.modules[__name__] = _implementation
