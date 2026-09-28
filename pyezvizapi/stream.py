"""Compatibility alias for the former combined stream module.

New code should import cloud protocol helpers from :mod:`stream_transport` and
MPEG/decryption helpers from :mod:`stream_media`.
"""

# ruff: noqa: F403, PLC0414

import sys

from . import _stream as _implementation
from ._stream import *
from ._stream import _find_hevc_nal_start_codes as _find_hevc_nal_start_codes

sys.modules[__name__] = _implementation
