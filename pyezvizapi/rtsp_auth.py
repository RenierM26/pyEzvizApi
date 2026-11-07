# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.rtsp_auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import rtsp_auth as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.rtsp_auth import (
        _HEADER_END as _HEADER_END,
        _LOGGER as _LOGGER,
        AuthTestResultFailed as AuthTestResultFailed,
        InvalidHost as InvalidHost,
        RTSPDetails as RTSPDetails,
        TestRTSPAuth as TestRTSPAuth,
        TypedDict as TypedDict,
        _decode_response as _decode_response,
        _unfold_header_lines as _unfold_header_lines,
        annotations as annotations,
        base64 as base64,
        genmsg_describe as genmsg_describe,
        hashlib as hashlib,
        is_positive_finite_duration_bound as is_positive_finite_duration_bound,
        logging as logging,
        parse_dict_header as parse_dict_header,
        re as re,
        socket as socket,
        time as time,
    )

sys.modules[__name__] = _implementation
