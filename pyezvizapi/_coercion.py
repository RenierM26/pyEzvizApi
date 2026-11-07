# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.coercion`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import coercion as _implementation

if TYPE_CHECKING:
    import pyezvizapi._shared.coercion as _compat_module_0
    Any = _compat_module_0.Any
    annotations = _compat_module_0.annotations
    coerce_int = _compat_module_0.coerce_int
    convert_to_dict = _compat_module_0.convert_to_dict
    decode_json = _compat_module_0.decode_json
    json = _compat_module_0.json
    string_to_list = _compat_module_0.string_to_list

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        annotations,
        coerce_int,
        convert_to_dict,
        decode_json,
        json,
        string_to_list,
    )

sys.modules[__name__] = _implementation
