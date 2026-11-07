# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.cas`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import cas as _implementation

if TYPE_CHECKING:
    from Crypto.Cipher import AES as AES

    from pyezvizapi.cloud.cas import (
        _LOGGER as _LOGGER,
        CAS_ANDROID_CLIENT_TYPE as CAS_ANDROID_CLIENT_TYPE,
        CAS_CERT_HAS_EXPIRED_VERIFY_CODE as CAS_CERT_HAS_EXPIRED_VERIFY_CODE,
        CAS_COMMAND_DEVICE_MESSAGE as CAS_COMMAND_DEVICE_MESSAGE,
        CAS_COMMAND_GET_OPERATION_CODE as CAS_COMMAND_GET_OPERATION_CODE,
        CAS_COMMAND_VERIFY as CAS_COMMAND_VERIFY,
        CAS_FRAME_HEADER_SIZE as CAS_FRAME_HEADER_SIZE,
        CAS_FRAME_MAGIC as CAS_FRAME_MAGIC,
        CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE as CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE,
        CAS_RANDOM_TRAILER_SIZE as CAS_RANDOM_TRAILER_SIZE,
        CAS_RESPONSE_DIGEST_SIZE as CAS_RESPONSE_DIGEST_SIZE,
        CAS_SOCKET_TIMEOUT as CAS_SOCKET_TIMEOUT,
        CAS_TLS_CIPHERS as CAS_TLS_CIPHERS,
        CAS_VERSION_MARKER as CAS_VERSION_MARKER,
        FEATURE_CODE as FEATURE_CODE,
        XOR_KEY as XOR_KEY,
        Any as Any,
        BytesIO as BytesIO,
        CasDeviceSession as CasDeviceSession,
        CasFrameHeader as CasFrameHeader,
        CasTransportResult as CasTransportResult,
        ExpatError as ExpatError,
        EzvizCAS as EzvizCAS,
        InvalidHost as InvalidHost,
        PyEzvizError as PyEzvizError,
        _build_defence_plaintext as _build_defence_plaintext,
        _build_defence_request as _build_defence_request,
        _build_operation_code_request as _build_operation_code_request,
        _cas_frame_header as _cas_frame_header,
        _cas_response_body as _cas_response_body,
        _cas_tls_context as _cas_tls_context,
        _certificate_matches_host as _certificate_matches_host,
        _certificate_not_valid_after as _certificate_not_valid_after,
        _dns_name_matches as _dns_name_matches,
        _is_certificate_expired_error as _is_certificate_expired_error,
        _normalize_dns_name as _normalize_dns_name,
        _random_hex_trailer as _random_hex_trailer,
        _recv_cas_frame as _recv_cas_frame,
        _recv_exact as _recv_exact,
        _send_all as _send_all,
        _verify_expired_cas_certificate_hostname as _verify_expired_cas_certificate_hostname,
        annotations as annotations,
        cast as cast,
        cycle as cycle,
        dataclass as dataclass,
        dt as dt,
        ipaddress as ipaddress,
        logging as logging,
        random as random,
        socket as socket,
        ssl as ssl,
        struct as struct,
        validate_feature_code as validate_feature_code,
        x509 as x509,
        xmltodict as xmltodict,
        xor_enc_dec as xor_enc_dec,
    )

sys.modules[__name__] = _implementation
