# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.rtsp_compat`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import rtsp_compat as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.rtsp_compat import (
    RTSPDetails as RTSPDetails,
    TestRTSPAuth as TestRTSPAuth,
    _decode_response as _decode_response,
    genmsg_describe as genmsg_describe,
    )

sys.modules[__name__] = _implementation
