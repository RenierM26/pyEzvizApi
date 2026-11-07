"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.coercion`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import coercion as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.coercion import (
    Any as Any,
    annotations as annotations,
    coerce_int as coerce_int,
    convert_to_dict as convert_to_dict,
    decode_json as decode_json,
    json as json,
    string_to_list as string_to_list,
    )

sys.modules[__name__] = _implementation
