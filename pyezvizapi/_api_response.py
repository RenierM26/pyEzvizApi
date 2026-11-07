# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.responses`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import responses as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.responses as _compat_module_0

    Any = _compat_module_0.Any
    JsonDict = _compat_module_0.JsonDict
    Mapping = _compat_module_0.Mapping
    PyEzvizError = _compat_module_0.PyEzvizError
    annotations = _compat_module_0.annotations
    body_debug_summary = _compat_module_0.body_debug_summary
    is_ok = _compat_module_0.is_ok
    islice = _compat_module_0.islice
    json = _compat_module_0.json
    meta_code = _compat_module_0.meta_code
    normalize_json_payload = _compat_module_0.normalize_json_payload
    object_section = _compat_module_0.object_section
    parse_json = _compat_module_0.parse_json
    requests = _compat_module_0.requests
    response_code = _compat_module_0.response_code
    response_summary = _compat_module_0.response_summary
    summarize_payload = _compat_module_0.summarize_payload

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        JsonDict,
        Mapping,
        PyEzvizError,
        annotations,
        body_debug_summary,
        is_ok,
        islice,
        json,
        meta_code,
        normalize_json_payload,
        object_section,
        parse_json,
        requests,
        response_code,
        response_summary,
        summarize_payload,
    )

sys.modules[__name__] = _implementation
