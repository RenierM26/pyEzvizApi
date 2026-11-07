# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.rtsp_compat`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import rtsp_compat as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.rtsp_compat as _compat_module_0
    RTSPDetails = _compat_module_0.RTSPDetails
    TestRTSPAuth = _compat_module_0.TestRTSPAuth
    _decode_response = _compat_module_0._decode_response
    genmsg_describe = _compat_module_0.genmsg_describe

sys.modules[__name__] = _implementation
