# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.codec`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import codec as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.longlink.codec as _compat_module_0
    IV = _compat_module_0.IV
    Any = _compat_module_0.Any
    AuthenticationRejected = _compat_module_0.AuthenticationRejected
    Cipher = _compat_module_0.Cipher
    _auth_iv_status = _compat_module_0._auth_iv_status
    algorithms = _compat_module_0.algorithms
    annotations = _compat_module_0.annotations
    authentication_i = _compat_module_0.authentication_i
    authentication_ii = _compat_module_0.authentication_ii
    authentication_iii_create = _compat_module_0.authentication_iii_create
    authentication_iii_existing = _compat_module_0.authentication_iii_existing
    authentication_iv_create = _compat_module_0.authentication_iv_create
    authentication_iv_existing = _compat_module_0.authentication_iv_existing
    control_keepalive = _compat_module_0.control_keepalive
    das_request = _compat_module_0.das_request
    das_response = _compat_module_0.das_response
    decode_event_envelope = _compat_module_0.decode_event_envelope
    decode_mobile_body = _compat_module_0.decode_mobile_body
    decrypt = _compat_module_0.decrypt
    encode_application_ack = _compat_module_0.encode_application_ack
    encrypt = _compat_module_0.encrypt
    hashlib = _compat_module_0.hashlib
    header = _compat_module_0.header
    hmac = _compat_module_0.hmac
    json = _compat_module_0.json
    master_key = _compat_module_0.master_key
    modes = _compat_module_0.modes
    padding = _compat_module_0.padding
    re = _compat_module_0.re
    refresh_i = _compat_module_0.refresh_i
    refresh_ii = _compat_module_0.refresh_ii
    refresh_iii = _compat_module_0.refresh_iii
    share_key = _compat_module_0.share_key
    signature = _compat_module_0.signature
    struct = _compat_module_0.struct

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        IV,
        Any,
        AuthenticationRejected,
        Cipher,
        _auth_iv_status,
        algorithms,
        annotations,
        authentication_i,
        authentication_ii,
        authentication_iii_create,
        authentication_iii_existing,
        authentication_iv_create,
        authentication_iv_existing,
        control_keepalive,
        das_request,
        das_response,
        decode_event_envelope,
        decode_mobile_body,
        decrypt,
        encode_application_ack,
        encrypt,
        hashlib,
        header,
        hmac,
        json,
        master_key,
        modes,
        padding,
        re,
        refresh_i,
        refresh_ii,
        refresh_iii,
        share_key,
        signature,
        struct,
    )

sys.modules[__name__] = _implementation
