# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.smart_plug`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import smart_plug as _implementation

if TYPE_CHECKING:
    import pyezvizapi.devices.smart_plug as _compat_module_0
    Any = _compat_module_0.Any
    DeviceSwitchType = _compat_module_0.DeviceSwitchType
    EzvizDeviceRecord = _compat_module_0.EzvizDeviceRecord
    EzvizSmartPlug = _compat_module_0.EzvizSmartPlug
    annotations = _compat_module_0.annotations
    fetch_nested_value = _compat_module_0.fetch_nested_value
    local_ip_address = _compat_module_0.local_ip_address
    switch_values = _compat_module_0.switch_values

sys.modules[__name__] = _implementation
