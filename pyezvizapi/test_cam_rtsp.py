"""Compatibility imports for the RTSP authentication probe (not a test suite)."""
from .rtsp_auth import RTSPDetails, TestRTSPAuth, _decode_response, genmsg_describe

__test__ = False
__all__ = ["RTSPDetails", "TestRTSPAuth", "_decode_response", "genmsg_describe"]
