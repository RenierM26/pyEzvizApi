# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.hcnetsdk.parameters`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk import parameters as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.hcnetsdk.parameters as _compat_module_0
    _AUDIO_ENCODINGS = _compat_module_0._AUDIO_ENCODINGS
    _AUDIO_SAMPLE_RATES = _compat_module_0._AUDIO_SAMPLE_RATES
    _FORMATS = _compat_module_0._FORMATS
    _FRAME_RATES = _compat_module_0._FRAME_RATES
    _VIDEO_BITRATES = _compat_module_0._VIDEO_BITRATES
    _VIDEO_ENCODINGS = _compat_module_0._VIDEO_ENCODINGS
    HcNetSdkConfiguredMedia = _compat_module_0.HcNetSdkConfiguredMedia
    Literal = _compat_module_0.Literal
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    normalize_hcnetsdk_parameters = _compat_module_0.normalize_hcnetsdk_parameters

sys.modules[__name__] = _implementation
