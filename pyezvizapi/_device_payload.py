# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.payload`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import payload as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.payload import (
    Any as Any,
    Mapping as Mapping,
    local_ip_address as local_ip_address,
    switch_values as switch_values,
    )

sys.modules[__name__] = _implementation
