# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.cas`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import cas as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher as _compat_module_0
    AES = _compat_module_0.AES

    import pyezvizapi.cloud.cas as _compat_module_1
    _LOGGER = _compat_module_1._LOGGER
    CAS_ANDROID_CLIENT_TYPE = _compat_module_1.CAS_ANDROID_CLIENT_TYPE
    CAS_CERT_HAS_EXPIRED_VERIFY_CODE = _compat_module_1.CAS_CERT_HAS_EXPIRED_VERIFY_CODE
    CAS_COMMAND_DEVICE_MESSAGE = _compat_module_1.CAS_COMMAND_DEVICE_MESSAGE
    CAS_COMMAND_GET_OPERATION_CODE = _compat_module_1.CAS_COMMAND_GET_OPERATION_CODE
    CAS_COMMAND_VERIFY = _compat_module_1.CAS_COMMAND_VERIFY
    CAS_FRAME_HEADER_SIZE = _compat_module_1.CAS_FRAME_HEADER_SIZE
    CAS_FRAME_MAGIC = _compat_module_1.CAS_FRAME_MAGIC
    CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE = _compat_module_1.CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE
    CAS_RANDOM_TRAILER_SIZE = _compat_module_1.CAS_RANDOM_TRAILER_SIZE
    CAS_RESPONSE_DIGEST_SIZE = _compat_module_1.CAS_RESPONSE_DIGEST_SIZE
    CAS_SOCKET_TIMEOUT = _compat_module_1.CAS_SOCKET_TIMEOUT
    CAS_TLS_CIPHERS = _compat_module_1.CAS_TLS_CIPHERS
    CAS_VERSION_MARKER = _compat_module_1.CAS_VERSION_MARKER
    FEATURE_CODE = _compat_module_1.FEATURE_CODE
    XOR_KEY = _compat_module_1.XOR_KEY
    Any = _compat_module_1.Any
    BytesIO = _compat_module_1.BytesIO
    CasDeviceSession = _compat_module_1.CasDeviceSession
    CasFrameHeader = _compat_module_1.CasFrameHeader
    CasTransportResult = _compat_module_1.CasTransportResult
    ExpatError = _compat_module_1.ExpatError
    EzvizCAS = _compat_module_1.EzvizCAS
    InvalidHost = _compat_module_1.InvalidHost
    PyEzvizError = _compat_module_1.PyEzvizError
    _build_defence_plaintext = _compat_module_1._build_defence_plaintext
    _build_defence_request = _compat_module_1._build_defence_request
    _build_operation_code_request = _compat_module_1._build_operation_code_request
    _cas_frame_header = _compat_module_1._cas_frame_header
    _cas_response_body = _compat_module_1._cas_response_body
    _cas_tls_context = _compat_module_1._cas_tls_context
    _certificate_matches_host = _compat_module_1._certificate_matches_host
    _certificate_not_valid_after = _compat_module_1._certificate_not_valid_after
    _dns_name_matches = _compat_module_1._dns_name_matches
    _is_certificate_expired_error = _compat_module_1._is_certificate_expired_error
    _normalize_dns_name = _compat_module_1._normalize_dns_name
    _random_hex_trailer = _compat_module_1._random_hex_trailer
    _recv_cas_frame = _compat_module_1._recv_cas_frame
    _recv_exact = _compat_module_1._recv_exact
    _send_all = _compat_module_1._send_all
    _verify_expired_cas_certificate_hostname = _compat_module_1._verify_expired_cas_certificate_hostname
    annotations = _compat_module_1.annotations
    cast = _compat_module_1.cast
    cycle = _compat_module_1.cycle
    dataclass = _compat_module_1.dataclass
    dt = _compat_module_1.dt
    ipaddress = _compat_module_1.ipaddress
    logging = _compat_module_1.logging
    random = _compat_module_1.random
    socket = _compat_module_1.socket
    ssl = _compat_module_1.ssl
    struct = _compat_module_1.struct
    validate_feature_code = _compat_module_1.validate_feature_code
    x509 = _compat_module_1.x509
    xmltodict = _compat_module_1.xmltodict
    xor_enc_dec = _compat_module_1.xor_enc_dec

sys.modules[__name__] = _implementation
