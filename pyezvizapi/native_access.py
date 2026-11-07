"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.access`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import access as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.access import (
    Iterator as Iterator,
    MAX_PENDING_PS_BYTES as MAX_PENDING_PS_BYTES,
    _Bits as _Bits,
    _PREFIX_BYTES as _PREFIX_BYTES,
    _START as _START,
    _check_idr as _check_idr,
    _hevc_sps as _hevc_sps,
    _units as _units,
    annotations as annotations,
    re as re,
    self_contained_idr as self_contained_idr,
    )

sys.modules[__name__] = _implementation
