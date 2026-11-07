# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.rtsp_auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import rtsp_auth as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.rtsp_auth as _compat_module_0

    _HEADER_END = _compat_module_0._HEADER_END
    _LOGGER = _compat_module_0._LOGGER
    AuthTestResultFailed = _compat_module_0.AuthTestResultFailed
    InvalidHost = _compat_module_0.InvalidHost
    RTSPDetails = _compat_module_0.RTSPDetails
    TestRTSPAuth = _compat_module_0.TestRTSPAuth
    TypedDict = _compat_module_0.TypedDict
    _decode_response = _compat_module_0._decode_response
    _unfold_header_lines = _compat_module_0._unfold_header_lines
    annotations = _compat_module_0.annotations
    base64 = _compat_module_0.base64
    genmsg_describe = _compat_module_0.genmsg_describe
    hashlib = _compat_module_0.hashlib
    is_positive_finite_duration_bound = _compat_module_0.is_positive_finite_duration_bound
    logging = _compat_module_0.logging
    parse_dict_header = _compat_module_0.parse_dict_header
    re = _compat_module_0.re
    socket = _compat_module_0.socket
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _HEADER_END,
        _LOGGER,
        AuthTestResultFailed,
        InvalidHost,
        RTSPDetails,
        TestRTSPAuth,
        TypedDict,
        _decode_response,
        _unfold_header_lines,
        annotations,
        base64,
        genmsg_describe,
        hashlib,
        is_positive_finite_duration_bound,
        logging,
        parse_dict_header,
        re,
        socket,
        time,
    )

sys.modules[__name__] = _implementation
