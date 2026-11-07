# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.responses`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import responses as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.responses import (
    Any as Any,
    JsonDict as JsonDict,
    Mapping as Mapping,
    PyEzvizError as PyEzvizError,
    annotations as annotations,
    body_debug_summary as body_debug_summary,
    is_ok as is_ok,
    islice as islice,
    json as json,
    meta_code as meta_code,
    normalize_json_payload as normalize_json_payload,
    object_section as object_section,
    parse_json as parse_json,
    requests as requests,
    response_code as response_code,
    response_summary as response_summary,
    summarize_payload as summarize_payload,
    )

sys.modules[__name__] = _implementation
