"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.protocol`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import protocol as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.protocol import (
    LocalSdkProtocolDetector as LocalSdkProtocolDetector,
    MPEG_START_CODE_PREFIX as MPEG_START_CODE_PREFIX,
    PyEzvizError as PyEzvizError,
    _LEGACY_PS_EVIDENCE_PACKETS as _LEGACY_PS_EVIDENCE_PACKETS,
    _is_mpeg_ps_packet_start_id as _is_mpeg_ps_packet_start_id,
    annotations as annotations,
    parse_rtp_packet as parse_rtp_packet,
    rtp_payload as rtp_payload,
    )

sys.modules[__name__] = _implementation
