"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.hcnetsdk.parameters`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk import parameters as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.hcnetsdk.parameters import (
    HcNetSdkConfiguredMedia as HcNetSdkConfiguredMedia,
    Literal as Literal,
    _AUDIO_ENCODINGS as _AUDIO_ENCODINGS,
    _AUDIO_SAMPLE_RATES as _AUDIO_SAMPLE_RATES,
    _FORMATS as _FORMATS,
    _FRAME_RATES as _FRAME_RATES,
    _VIDEO_BITRATES as _VIDEO_BITRATES,
    _VIDEO_ENCODINGS as _VIDEO_ENCODINGS,
    annotations as annotations,
    dataclass as dataclass,
    normalize_hcnetsdk_parameters as normalize_hcnetsdk_parameters,
    )

sys.modules[__name__] = _implementation
