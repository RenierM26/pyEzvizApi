"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.capture`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import capture as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.capture import (
    Any as Any,
    AutoClipSource as AutoClipSource,
    Callable as Callable,
    CaptureLimits as CaptureLimits,
    ClipOptions as ClipOptions,
    ClipOutputFormat as ClipOutputFormat,
    ClipSource as ClipSource,
    ClipSourceOptions as ClipSourceOptions,
    CloudClipSource as CloudClipSource,
    EzvizLocalSdkCredentials as EzvizLocalSdkCredentials,
    HcNetSdkCommandPortClipSource as HcNetSdkCommandPortClipSource,
    HcNetSdkCommandPortGeneratedMultiSocketPlan as HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortMultiSocketPlan as HcNetSdkCommandPortMultiSocketPlan,
    Iterable as Iterable,
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT as LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    Literal as Literal,
    LocalSdkClipSource as LocalSdkClipSource,
    LocalSdkEcdhClipSource as LocalSdkEcdhClipSource,
    LocalStreamDiscoveryCache as LocalStreamDiscoveryCache,
    MAX_RETRIES as MAX_RETRIES,
    MediaDecodeOptions as MediaDecodeOptions,
    MediaMuxOptions as MediaMuxOptions,
    PyEzvizError as PyEzvizError,
    _LegacyClipOptions as _LegacyClipOptions,
    annotations as annotations,
    dataclass as dataclass,
    field as field,
    math as math,
    )

sys.modules[__name__] = _implementation
