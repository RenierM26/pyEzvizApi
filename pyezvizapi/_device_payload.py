# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.payload`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import payload as _implementation

if TYPE_CHECKING:
    import pyezvizapi.devices.payload as _compat_module_0

    Any = _compat_module_0.Any
    Mapping = _compat_module_0.Mapping
    local_ip_address = _compat_module_0.local_ip_address
    switch_values = _compat_module_0.switch_values

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        Mapping,
        local_ip_address,
        switch_values,
    )

sys.modules[__name__] = _implementation
