"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.smart_plug`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import smart_plug as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.smart_plug import (
    Any as Any,
    DeviceSwitchType as DeviceSwitchType,
    EzvizDeviceRecord as EzvizDeviceRecord,
    EzvizSmartPlug as EzvizSmartPlug,
    annotations as annotations,
    fetch_nested_value as fetch_nested_value,
    local_ip_address as local_ip_address,
    switch_values as switch_values,
    )

sys.modules[__name__] = _implementation
