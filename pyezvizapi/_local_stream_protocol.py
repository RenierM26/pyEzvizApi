# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.protocol`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import protocol as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.protocol as _compat_module_0
    _LEGACY_PS_EVIDENCE_PACKETS = _compat_module_0._LEGACY_PS_EVIDENCE_PACKETS
    MPEG_START_CODE_PREFIX = _compat_module_0.MPEG_START_CODE_PREFIX
    LocalSdkProtocolDetector = _compat_module_0.LocalSdkProtocolDetector
    PyEzvizError = _compat_module_0.PyEzvizError
    _is_mpeg_ps_packet_start_id = _compat_module_0._is_mpeg_ps_packet_start_id
    annotations = _compat_module_0.annotations
    parse_rtp_packet = _compat_module_0.parse_rtp_packet
    rtp_payload = _compat_module_0.rtp_payload

sys.modules[__name__] = _implementation
