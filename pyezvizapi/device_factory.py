# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.factory`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import factory as _implementation

if TYPE_CHECKING:
    import pyezvizapi.devices.factory as _compat_module_0

    Any = _compat_module_0.Any
    EzvizCamera = _compat_module_0.EzvizCamera
    EzvizLightBulb = _compat_module_0.EzvizLightBulb
    EzvizSmartPlug = _compat_module_0.EzvizSmartPlug
    annotations = _compat_module_0.annotations
    camera_status = _compat_module_0.camera_status
    cast = _compat_module_0.cast
    light_bulb_status = _compat_module_0.light_bulb_status
    smart_plug_status = _compat_module_0.smart_plug_status

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        EzvizCamera,
        EzvizLightBulb,
        EzvizSmartPlug,
        annotations,
        camera_status,
        cast,
        light_bulb_status,
        smart_plug_status,
    )

sys.modules[__name__] = _implementation
