"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.token_store`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import token_store as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.token_store import (
    Any as Any,
    Path as Path,
    json as json,
    os as os,
    save_private_token as save_private_token,
    tempfile as tempfile,
    )

sys.modules[__name__] = _implementation
