# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.capabilities`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import capabilities as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.capabilities as _compat_module_0

    MAX_FLEET_SAMPLE_BYTES = _compat_module_0.MAX_FLEET_SAMPLE_BYTES
    MAX_FLEET_TARGETS = _compat_module_0.MAX_FLEET_TARGETS
    UTC = _compat_module_0.UTC
    Any = _compat_module_0.Any
    HcNetSdkLanEndpoint = _compat_module_0.HcNetSdkLanEndpoint
    HcNetSdkLoginCandidate = _compat_module_0.HcNetSdkLoginCandidate
    PyEzvizError = _compat_module_0.PyEzvizError
    Sequence = _compat_module_0.Sequence
    StreamCapabilityTarget = _compat_module_0.StreamCapabilityTarget
    StreamSampleEvidence = _compat_module_0.StreamSampleEvidence
    _advertised_codecs = _compat_module_0._advertised_codecs
    _codec_choices = _compat_module_0._codec_choices
    annotations = _compat_module_0.annotations
    dataclass = _compat_module_0.dataclass
    datetime = _compat_module_0.datetime
    discover_hcnetsdk_stream_details_for_login = (
        _compat_module_0.discover_hcnetsdk_stream_details_for_login
    )
    field = _compat_module_0.field
    inspect_media_sample = _compat_module_0.inspect_media_sample
    math = _compat_module_0.math
    normalize_hcnetsdk_parameters = _compat_module_0.normalize_hcnetsdk_parameters
    probe_stream_capabilities = _compat_module_0.probe_stream_capabilities
    ssl = _compat_module_0.ssl
    validate_media_sample = _compat_module_0.validate_media_sample

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        MAX_FLEET_SAMPLE_BYTES,
        MAX_FLEET_TARGETS,
        UTC,
        Any,
        HcNetSdkLanEndpoint,
        HcNetSdkLoginCandidate,
        PyEzvizError,
        Sequence,
        StreamCapabilityTarget,
        StreamSampleEvidence,
        _advertised_codecs,
        _codec_choices,
        annotations,
        dataclass,
        datetime,
        discover_hcnetsdk_stream_details_for_login,
        field,
        inspect_media_sample,
        math,
        normalize_hcnetsdk_parameters,
        probe_stream_capabilities,
        ssl,
        validate_media_sample,
    )

sys.modules[__name__] = _implementation
