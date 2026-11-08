# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.probe`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import probe as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.probe as _compat_module_0

    Any = _compat_module_0.Any
    EzvizLocalSdkDeadlineExpired = _compat_module_0.EzvizLocalSdkDeadlineExpired
    Literal = _compat_module_0.Literal
    LocalSdkProtocolDetector = _compat_module_0.LocalSdkProtocolDetector
    LocalSdkProtocolProbeResult = _compat_module_0.LocalSdkProtocolProbeResult
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    math = _compat_module_0.math
    probe_local_sdk_stream_from_client = _compat_module_0.probe_local_sdk_stream_from_client
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        EzvizLocalSdkDeadlineExpired,
        Literal,
        LocalSdkProtocolDetector,
        LocalSdkProtocolProbeResult,
        annotations,
        dataclass,
        math,
        probe_local_sdk_stream_from_client,
        time,
    )

sys.modules[__name__] = _implementation
