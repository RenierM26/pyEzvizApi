"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.completion`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import completion as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.completion import (
    Literal as Literal,
    NativeMediaCompletion as NativeMediaCompletion,
    NativeTrackCompletion as NativeTrackCompletion,
    dataclass as dataclass,
    )

sys.modules[__name__] = _implementation
