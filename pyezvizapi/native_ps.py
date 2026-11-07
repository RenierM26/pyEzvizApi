"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.native_ps`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import native_ps as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.media.native_ps import (
    MAX_PENDING_PS_BYTES as MAX_PENDING_PS_BYTES,
    NativePsTransform as NativePsTransform,
    PyEzvizError as PyEzvizError,
    _MpegPsVideoDecryptState as _MpegPsVideoDecryptState,
    _PS_START as _PS_START,
    _decrypt_hikvision_ps_video_packets as _decrypt_hikvision_ps_video_packets,
    annotations as annotations,
    mpeg_ps_complete_prefix_length as mpeg_ps_complete_prefix_length,
    )

sys.modules[__name__] = _implementation
