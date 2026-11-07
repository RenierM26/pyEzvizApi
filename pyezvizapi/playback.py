"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.playback`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import playback as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.playback import (
    Any as Any,
    EzvizAppPlaybackSupport as EzvizAppPlaybackSupport,
    Mapping as Mapping,
    _capability_integer as _capability_integer,
    annotations as annotations,
    dataclass as dataclass,
    inspect_app_playback_support as inspect_app_playback_support,
    json as json,
    re as re,
    )

sys.modules[__name__] = _implementation
