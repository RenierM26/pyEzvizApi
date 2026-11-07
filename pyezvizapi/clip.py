# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.capture`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import capture as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.capture as _compat_module_0
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = _compat_module_0.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
    MAX_RETRIES = _compat_module_0.MAX_RETRIES
    Any = _compat_module_0.Any
    AutoClipSource = _compat_module_0.AutoClipSource
    Callable = _compat_module_0.Callable
    CaptureLimits = _compat_module_0.CaptureLimits
    ClipOptions = _compat_module_0.ClipOptions
    ClipOutputFormat = _compat_module_0.ClipOutputFormat
    ClipSource = _compat_module_0.ClipSource
    ClipSourceOptions = _compat_module_0.ClipSourceOptions
    CloudClipSource = _compat_module_0.CloudClipSource
    EzvizLocalSdkCredentials = _compat_module_0.EzvizLocalSdkCredentials
    HcNetSdkCommandPortClipSource = _compat_module_0.HcNetSdkCommandPortClipSource
    HcNetSdkCommandPortGeneratedMultiSocketPlan = _compat_module_0.HcNetSdkCommandPortGeneratedMultiSocketPlan
    HcNetSdkCommandPortMultiSocketPlan = _compat_module_0.HcNetSdkCommandPortMultiSocketPlan
    Iterable = _compat_module_0.Iterable
    Literal = _compat_module_0.Literal
    LocalSdkClipSource = _compat_module_0.LocalSdkClipSource
    LocalSdkEcdhClipSource = _compat_module_0.LocalSdkEcdhClipSource
    LocalStreamDiscoveryCache = _compat_module_0.LocalStreamDiscoveryCache
    MediaDecodeOptions = _compat_module_0.MediaDecodeOptions
    MediaMuxOptions = _compat_module_0.MediaMuxOptions
    PyEzvizError = _compat_module_0.PyEzvizError
    _LegacyClipOptions = _compat_module_0._LegacyClipOptions
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    field = _compat_module_0.field
    math = _compat_module_0.math

sys.modules[__name__] = _implementation
