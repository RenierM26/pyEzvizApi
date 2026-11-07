"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.capabilities`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import capabilities as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.capabilities import (
    Any as Any,
    HcNetSdkLanEndpoint as HcNetSdkLanEndpoint,
    HcNetSdkLoginCandidate as HcNetSdkLoginCandidate,
    MAX_FLEET_SAMPLE_BYTES as MAX_FLEET_SAMPLE_BYTES,
    MAX_FLEET_TARGETS as MAX_FLEET_TARGETS,
    PyEzvizError as PyEzvizError,
    Sequence as Sequence,
    StreamCapabilityTarget as StreamCapabilityTarget,
    StreamSampleEvidence as StreamSampleEvidence,
    UTC as UTC,
    _advertised_codecs as _advertised_codecs,
    _codec_choices as _codec_choices,
    annotations as annotations,
    dataclass as dataclass,
    datetime as datetime,
    discover_hcnetsdk_stream_details_for_login as discover_hcnetsdk_stream_details_for_login,
    field as field,
    inspect_media_sample as inspect_media_sample,
    math as math,
    normalize_hcnetsdk_parameters as normalize_hcnetsdk_parameters,
    probe_stream_capabilities as probe_stream_capabilities,
    ssl as ssl,
    validate_media_sample as validate_media_sample,
    )

sys.modules[__name__] = _implementation
