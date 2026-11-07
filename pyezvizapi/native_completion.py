# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.completion`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
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
