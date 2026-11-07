# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.codec`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import codec as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.codec import (
        IV as IV,
        Any as Any,
        AuthenticationRejected as AuthenticationRejected,
        Cipher as Cipher,
        _auth_iv_status as _auth_iv_status,
        algorithms as algorithms,
        annotations as annotations,
        authentication_i as authentication_i,
        authentication_ii as authentication_ii,
        authentication_iii_create as authentication_iii_create,
        authentication_iii_existing as authentication_iii_existing,
        authentication_iv_create as authentication_iv_create,
        authentication_iv_existing as authentication_iv_existing,
        control_keepalive as control_keepalive,
        das_request as das_request,
        das_response as das_response,
        decode_event_envelope as decode_event_envelope,
        decode_mobile_body as decode_mobile_body,
        decrypt as decrypt,
        encode_application_ack as encode_application_ack,
        encrypt as encrypt,
        hashlib as hashlib,
        header as header,
        hmac as hmac,
        json as json,
        master_key as master_key,
        modes as modes,
        padding as padding,
        re as re,
        refresh_i as refresh_i,
        refresh_ii as refresh_ii,
        refresh_iii as refresh_iii,
        share_key as share_key,
        signature as signature,
        struct as struct,
    )

sys.modules[__name__] = _implementation
