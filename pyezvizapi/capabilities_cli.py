"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.capabilities`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import capabilities as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cli.capabilities import (
    HcNetSdkLanEndpoint as HcNetSdkLanEndpoint,
    HcNetSdkLoginCandidate as HcNetSdkLoginCandidate,
    MAX_FLEET_SAMPLE_BYTES as MAX_FLEET_SAMPLE_BYTES,
    MAX_FLEET_TARGETS as MAX_FLEET_TARGETS,
    MAX_SAMPLE_BYTES as MAX_SAMPLE_BYTES,
    Path as Path,
    StreamCapabilityTarget as StreamCapabilityTarget,
    StreamSampleEvidence as StreamSampleEvidence,
    annotations as annotations,
    argparse as argparse,
    json as json,
    load_inventory as load_inventory,
    main as main,
    os as os,
    probe_stream_capabilities as probe_stream_capabilities,
    sys as sys,
    )

if __name__ == "__main__":
    sys.exit(_implementation.main())
else:
    sys.modules[__name__] = _implementation
