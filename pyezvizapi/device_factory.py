# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.factory`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
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
