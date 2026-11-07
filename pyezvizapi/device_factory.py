"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.factory`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import factory as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.factory import (
    Any as Any,
    EzvizCamera as EzvizCamera,
    EzvizLightBulb as EzvizLightBulb,
    EzvizSmartPlug as EzvizSmartPlug,
    annotations as annotations,
    camera_status as camera_status,
    cast as cast,
    light_bulb_status as light_bulb_status,
    smart_plug_status as smart_plug_status,
    )

sys.modules[__name__] = _implementation
