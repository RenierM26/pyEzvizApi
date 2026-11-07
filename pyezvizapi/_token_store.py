# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.token_store`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import token_store as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.token_store as _compat_module_0

    Any = _compat_module_0.Any
    Path = _compat_module_0.Path
    json = _compat_module_0.json
    os = _compat_module_0.os
    save_private_token = _compat_module_0.save_private_token
    tempfile = _compat_module_0.tempfile

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        Path,
        json,
        os,
        save_private_token,
        tempfile,
    )

sys.modules[__name__] = _implementation
