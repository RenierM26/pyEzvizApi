# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.protocol`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import protocol as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.protocol import (
        _LEGACY_PS_EVIDENCE_PACKETS as _LEGACY_PS_EVIDENCE_PACKETS,
        MPEG_START_CODE_PREFIX as MPEG_START_CODE_PREFIX,
        LocalSdkProtocolDetector as LocalSdkProtocolDetector,
        PyEzvizError as PyEzvizError,
        _is_mpeg_ps_packet_start_id as _is_mpeg_ps_packet_start_id,
        annotations as annotations,
        parse_rtp_packet as parse_rtp_packet,
        rtp_payload as rtp_payload,
    )

sys.modules[__name__] = _implementation
