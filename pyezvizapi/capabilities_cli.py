# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.capabilities`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import capabilities as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cli.capabilities as _compat_module_0

    MAX_FLEET_SAMPLE_BYTES = _compat_module_0.MAX_FLEET_SAMPLE_BYTES
    MAX_FLEET_TARGETS = _compat_module_0.MAX_FLEET_TARGETS
    MAX_SAMPLE_BYTES = _compat_module_0.MAX_SAMPLE_BYTES
    HcNetSdkLanEndpoint = _compat_module_0.HcNetSdkLanEndpoint
    HcNetSdkLoginCandidate = _compat_module_0.HcNetSdkLoginCandidate
    Path = _compat_module_0.Path
    StreamCapabilityTarget = _compat_module_0.StreamCapabilityTarget
    StreamSampleEvidence = _compat_module_0.StreamSampleEvidence
    annotations = _compat_module_0.annotations
    argparse = _compat_module_0.argparse
    json = _compat_module_0.json
    load_inventory = _compat_module_0.load_inventory
    main = _compat_module_0.main
    os = _compat_module_0.os
    probe_stream_capabilities = _compat_module_0.probe_stream_capabilities
    sys = _compat_module_0.sys

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        MAX_FLEET_SAMPLE_BYTES,
        MAX_FLEET_TARGETS,
        MAX_SAMPLE_BYTES,
        HcNetSdkLanEndpoint,
        HcNetSdkLoginCandidate,
        Path,
        StreamCapabilityTarget,
        StreamSampleEvidence,
        annotations,
        argparse,
        json,
        load_inventory,
        main,
        os,
        probe_stream_capabilities,
        sys,
    )

if __name__ == "__main__":
    sys.exit(_implementation.main())
else:
    sys.modules[__name__] = _implementation
