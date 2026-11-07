"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.probe`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import probe as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.probe import (
    Any as Any,
    EzvizLocalSdkDeadlineExpired as EzvizLocalSdkDeadlineExpired,
    Literal as Literal,
    LocalSdkProtocolDetector as LocalSdkProtocolDetector,
    LocalSdkProtocolProbeResult as LocalSdkProtocolProbeResult,
    annotations as annotations,
    dataclass as dataclass,
    math as math,
    probe_local_sdk_stream_from_client as probe_local_sdk_stream_from_client,
    time as time,
    )

sys.modules[__name__] = _implementation
