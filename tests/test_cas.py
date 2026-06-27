from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from typing import Any

from Crypto.Cipher import AES
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from pyezvizapi.cas import (
    CAS_ANDROID_CLIENT_TYPE,
    CAS_COMMAND_DEVICE_MESSAGE,
    CAS_COMMAND_GET_OPERATION_CODE,
    CAS_COMMAND_VERIFY,
    CAS_FRAME_HEADER_SIZE,
    CAS_FRAME_MAGIC,
    CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE,
    CAS_RANDOM_TRAILER_SIZE,
    CAS_VERSION_MARKER,
    CasDeviceSession,
    CasFrameHeader,
    EzvizCAS,
    xor_enc_dec,
)
from pyezvizapi.exceptions import PyEzvizError

DEV_SERIAL_XML = b"<DevSerial>CAM123</DevSerial>"
CLIENT_SESSION_XML = b'ClientSession="session-id"'
ANDROID_CLIENT_TYPE_XML = (
    f"<ClientType>{CAS_ANDROID_CLIENT_TYPE}</ClientType>".encode("latin1")
)
ANDROID_DEFENCE_CLIENT_TYPE_XML = (
    f'ClientType="{CAS_ANDROID_CLIENT_TYPE}"'.encode("latin1")
)
CUSTOM_CLIENT_TYPE_XML = b"<ClientType>1</ClientType>"
LOCAL_RESPONSE = b"local-response"
OPERATION_CODE_XML = b"<OperationCode>0123456</OperationCode>"


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _cas_response(
    body: bytes,
    *,
    command: int = CAS_COMMAND_GET_OPERATION_CODE,
    tail: bytes = b"t" * 32,
) -> bytes:
    return (
        CAS_FRAME_MAGIC
        + CAS_VERSION_MARKER
        + _u32(5)
        + _u32(0)
        + _u32(command)
        + _u32(0)
        + _u32(len(body))
        + _u32(len(tail))
        + body
        + tail
    )


_TEST_CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_CA_SUBJECT = x509.Name(
    [x509.NameAttribute(NameOID.COMMON_NAME, "pyezvizapi test CA")]
)
_TEST_CA_CERT = (
    x509.CertificateBuilder()
    .subject_name(_TEST_CA_SUBJECT)
    .issuer_name(_TEST_CA_SUBJECT)
    .public_key(_TEST_CA_KEY.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
    .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.UTC))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(_TEST_CA_KEY.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(_TEST_CA_KEY.public_key()),
        critical=False,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(_TEST_CA_KEY, hashes.SHA256())
)


def _test_certificate(
    *,
    dns_names: tuple[str, ...] = ("cas.example.test",),
    ip_addresses: tuple[str, ...] = (),
    common_names: tuple[str, ...] = (),
    issuer_key: rsa.RSAPrivateKey = _TEST_CA_KEY,
    issuer_cert: x509.Certificate = _TEST_CA_CERT,
    expired: bool = True,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_name = common_names[0] if common_names else (dns_names[0] if dns_names else "cas")
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.UTC))
        .not_valid_after(
            dt.datetime(2026, 6, 27, tzinfo=dt.UTC)
            if expired
            else dt.datetime(2036, 1, 1, tzinfo=dt.UTC)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    if dns_names or ip_addresses:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    *[x509.DNSName(dns_name) for dns_name in dns_names],
                    *[
                        x509.IPAddress(ipaddress.ip_address(ip_address))
                        for ip_address in ip_addresses
                    ],
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.DER
    )


class FakeSocket:
    def __init__(
        self,
        response: bytes = b"",
        cert: bytes | None = None,
        verify_error: ssl.SSLCertVerificationError | None = None,
    ) -> None:
        self.response = response
        self.cert = cert if cert is not None else _test_certificate()
        self.verify_error = verify_error
        self.sent: list[bytes] = []
        self.closed = False
        self.ssl_context: FakeSSLContext | None = None
        self.server_hostname: str | None = None

    def send(self, payload: bytes) -> int:
        self.sent.append(payload)
        return len(payload)

    def recv(self, size: int = 1024) -> bytes:
        chunk = self.response[:size]
        self.response = self.response[size:]
        return chunk

    def getpeercert(self, binary_form: bool = False) -> bytes | dict[str, Any]:
        if binary_form:
            return self.cert
        return {}

    def get_unverified_chain(self) -> list[bytes]:
        return [self.cert]

    def close(self) -> None:
        self.closed = True


class FakeSSLContext:
    def __init__(self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> None:
        self.purpose = purpose
        self.ciphers: str | None = None
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.default_cert_purpose: ssl.Purpose | None = None

    def load_default_certs(self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> None:
        self.default_cert_purpose = purpose

    def set_ciphers(self, ciphers: str) -> None:
        self.ciphers = ciphers

    def wrap_socket(self, sock: FakeSocket, *, server_hostname: str) -> FakeSocket:
        if self.verify_mode == ssl.CERT_REQUIRED and sock.verify_error is not None:
            raise sock.verify_error
        sock.ssl_context = self
        sock.server_hostname = server_hostname
        return sock


def _token(host: str = "cas.example.test") -> dict[str, Any]:
    sys_conf: list[Any] = [None] * 17
    sys_conf[15] = host
    sys_conf[16] = 443
    return {"session_id": "session-id", "service_urls": {"sysConf": sys_conf}}


def _cas_client() -> EzvizCAS:
    return EzvizCAS(_token())


def _certificate_expired_error() -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError("certificate has expired")


def _self_signed_error() -> ssl.SSLCertVerificationError:
    return ssl.SSLCertVerificationError("self-signed certificate")


def test_xor_enc_dec_round_trips_payload() -> None:
    payload = b"CAM123456"

    encoded = xor_enc_dec(payload)

    assert encoded != payload
    assert xor_enc_dec(encoded) == payload


def test_cas_requires_service_urls_in_token() -> None:
    with pytest.raises(PyEzvizError, match="Missing service_urls"):
        EzvizCAS({"session_id": "session-id"})


def test_cas_get_encryption_parses_xml_response(monkeypatch) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    fake_socket = FakeSocket(_cas_response(body))
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = _cas_client().cas_get_encryption("CAM123")

    assert connect_calls == [("cas.example.test", 443)]
    assert fake_socket.server_hostname == "cas.example.test"
    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert result["Response"]["Session"]["@OperationCode"] == "0123456789"
    device_session = CasDeviceSession.from_response(result)
    assert device_session.key == "1234567890abcdef"
    assert device_session.operation_code == "0123456789"
    assert device_session.encrypt_type == 2
    assert DEV_SERIAL_XML in fake_socket.sent[0]
    assert ANDROID_CLIENT_TYPE_XML in fake_socket.sent[0]
    assert fake_socket.ssl_context is not None
    assert fake_socket.ssl_context.check_hostname is True
    assert fake_socket.ssl_context.verify_mode == ssl.CERT_REQUIRED
    header = CasFrameHeader.parse(fake_socket.sent[0])
    assert header.version_marker == CAS_VERSION_MARKER
    assert header.sequence == 5
    assert header.command == CAS_COMMAND_GET_OPERATION_CODE
    assert header.body_size_hint == (
        len(fake_socket.sent[0])
        - CAS_FRAME_HEADER_SIZE
        - CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE
    )
    assert len(fake_socket.sent[0][-CAS_OPERATION_CODE_RANDOM_TRAILER_SIZE:]) == 32
    assert fake_socket.closed is True


def test_cas_get_encryption_allows_custom_client_type(monkeypatch) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    fake_socket = FakeSocket(_cas_response(body))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token(), client_type=1).cas_get_encryption("CAM123")

    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert CUSTOM_CLIENT_TYPE_XML in fake_socket.sent[0]
    assert ANDROID_CLIENT_TYPE_XML not in fake_socket.sent[0]


def test_cas_get_encryption_reads_chunked_framed_response(monkeypatch) -> None:
    class ChunkedSocket(FakeSocket):
        def recv(self, size: int = 1024) -> bytes:
            return super().recv(min(size, 7))

    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    fake_socket = ChunkedSocket(_cas_response(body))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = _cas_client().cas_get_encryption("CAM123")

    assert result["Response"]["Session"]["@OperationCode"] == "0123456789"


def test_cas_get_encryption_can_require_tls_certificate_validation(
    monkeypatch,
) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    fake_socket = FakeSocket(_cas_response(body))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(
        _token(),
        verify_tls_certificate=True,
    ).cas_get_encryption("CAM123")

    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert fake_socket.ssl_context is not None
    assert fake_socket.ssl_context.check_hostname is True
    assert fake_socket.ssl_context.verify_mode == ssl.CERT_REQUIRED


def test_cas_get_encryption_tolerates_only_expired_tls_certificate(
    monkeypatch,
) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    verified_socket = FakeSocket(verify_error=_certificate_expired_error())
    relaxed_socket = FakeSocket(_cas_response(body))
    sockets = [verified_socket, relaxed_socket]
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return sockets.pop(0)

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = _cas_client().cas_get_encryption("CAM123")

    assert connect_calls == [("cas.example.test", 443), ("cas.example.test", 443)]
    assert verified_socket.closed is True
    assert relaxed_socket.ssl_context is not None
    assert relaxed_socket.ssl_context.check_hostname is False
    assert relaxed_socket.ssl_context.verify_mode == ssl.CERT_NONE
    assert relaxed_socket.server_hostname == "cas.example.test"
    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"


def test_cas_get_encryption_strict_tls_rejects_expired_certificate(
    monkeypatch,
) -> None:
    fake_socket = FakeSocket(verify_error=_certificate_expired_error())

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="CAS TLS handshake failed"):
        EzvizCAS(
            _token(),
            verify_tls_certificate=True,
        ).cas_get_encryption("CAM123")

    assert fake_socket.closed is True


def test_cas_get_encryption_rejects_non_expiry_tls_errors(
    monkeypatch,
) -> None:
    fake_socket = FakeSocket(verify_error=_self_signed_error())
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="CAS TLS handshake failed"):
        _cas_client().cas_get_encryption("CAM123")

    assert connect_calls == [("cas.example.test", 443)]
    assert fake_socket.closed is True


def test_cas_get_encryption_accepts_wildcard_certificate_hostname(
    monkeypatch,
) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    verified_socket = FakeSocket(verify_error=_certificate_expired_error())
    relaxed_socket = FakeSocket(
        _cas_response(body),
        cert=_test_certificate(dns_names=("*.ezvizlife.com",)),
    )
    sockets = [verified_socket, relaxed_socket]

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: sockets.pop(0),
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token("eucas.ezvizlife.com")).cas_get_encryption("CAM123")

    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert relaxed_socket.server_hostname == "eucas.ezvizlife.com"
    assert relaxed_socket.closed is True


def test_cas_get_encryption_rejects_common_name_only_certificate(
    monkeypatch,
) -> None:
    verified_socket = FakeSocket(verify_error=_certificate_expired_error())
    relaxed_socket = FakeSocket(
        _cas_response(b"<Response />"),
        cert=_test_certificate(dns_names=(), common_names=("cas.example.test",)),
    )
    sockets = [verified_socket, relaxed_socket]

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: sockets.pop(0),
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="not valid"):
        _cas_client().cas_get_encryption("CAM123")
    assert relaxed_socket.closed is True


def test_cas_get_encryption_rejects_mismatched_certificate_hostname(
    monkeypatch,
) -> None:
    verified_socket = FakeSocket(verify_error=_certificate_expired_error())
    relaxed_socket = FakeSocket(
        _cas_response(b"<Response />"),
        cert=_test_certificate(dns_names=("other.example.test",)),
    )
    sockets = [verified_socket, relaxed_socket]

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: sockets.pop(0),
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="not valid"):
        _cas_client().cas_get_encryption("CAM123")

    assert relaxed_socket.closed is True


def test_cas_device_session_infers_aes128_encrypt_type() -> None:
    response = {
        "Response": {
            "Session": {
                "@Key": "1234567890abcdef",
                "@OperationCode": "0123456",
                "@Algorithm": "AES128",
            },
        },
    }

    device_session = CasDeviceSession.from_response(response)

    assert device_session.encrypt_type == 1


def test_cas_device_session_rejects_non_session_response() -> None:
    response = {"Response": {"Result": "1052173", "Limit": "-9999"}}

    with pytest.raises(
        PyEzvizError,
        match=r"missing Session \(Result=1052173, Limit=-9999\)",
    ):
        CasDeviceSession.from_response(response)


def test_cas_get_encryption_rejects_empty_xml_body(monkeypatch) -> None:
    fake_socket = FakeSocket(_cas_response(b""))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="did not contain an XML body"):
        _cas_client().cas_get_encryption("CAM123")

    assert fake_socket.closed is True


def test_cas_get_encryption_rejects_malformed_xml_body(monkeypatch) -> None:
    fake_socket = FakeSocket(_cas_response(b"<Response>"))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="Could not parse CAS"):
        _cas_client().cas_get_encryption("CAM123")

    assert fake_socket.closed is True


def test_probe_local_operation_code_uses_plain_socket(monkeypatch) -> None:
    fake_socket = FakeSocket(LOCAL_RESPONSE)
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    def fail_ssl_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> FakeSSLContext:
        raise AssertionError("LAN probe must not create a TLS context")

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", fail_ssl_context)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token()).probe_local_operation_code(
        "CAM123",
        host="192.0.2.10",
        port=9010,
    )

    assert connect_calls == [("192.0.2.10", 9010)]
    assert result.host == "192.0.2.10"
    assert result.port == 9010
    assert result.used_tls is False
    assert result.response == LOCAL_RESPONSE
    assert DEV_SERIAL_XML in fake_socket.sent[0]
    header = CasFrameHeader.parse(fake_socket.sent[0])
    assert header.command == CAS_COMMAND_GET_OPERATION_CODE
    assert fake_socket.closed is True


def test_probe_local_operation_code_retries_partial_socket_writes(monkeypatch) -> None:
    class PartialSendSocket(FakeSocket):
        def send(self, payload: bytes) -> int:
            sent = min(7, len(payload))
            self.sent.append(payload[:sent])
            return sent

    fake_socket = PartialSendSocket(LOCAL_RESPONSE)

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token()).probe_local_operation_code(
        "CAM123",
        host="192.0.2.10",
        port=9010,
    )

    assert result.response == LOCAL_RESPONSE
    assert len(fake_socket.sent) > 1
    sent_payload = b"".join(fake_socket.sent)
    assert DEV_SERIAL_XML in sent_payload
    assert CasFrameHeader.parse(sent_payload).command == CAS_COMMAND_GET_OPERATION_CODE
    assert fake_socket.closed is True


def test_probe_local_operation_code_reports_connection_reset(monkeypatch) -> None:
    class ResetSocket(FakeSocket):
        def recv(self, size: int = 1024) -> bytes:
            raise ConnectionResetError("reset")

    fake_socket = ResetSocket()

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )

    with pytest.raises(PyEzvizError, match="connection was reset"):
        EzvizCAS(_token()).probe_local_operation_code(
            "CAM123",
            host="192.0.2.10",
            port=9010,
        )

    assert fake_socket.closed is True


def test_set_camera_defence_state_sends_encrypted_payload(monkeypatch) -> None:
    fake_socket = FakeSocket(_cas_response(b"ok", command=CAS_COMMAND_VERIFY))
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)
    monkeypatch.setattr(
        EzvizCAS,
        "cas_get_encryption",
        lambda self, serial: {
            "Response": {
                "Session": {
                    "@Key": "1234567890abcdef",
                    "@OperationCode": "0123456",
                }
            }
        },
    )

    assert _cas_client().set_camera_defence_state("CAM123456", enable=0) is True

    assert connect_calls == [("cas.example.test", 443)]
    assert len(fake_socket.sent) == 1
    assert CLIENT_SESSION_XML in fake_socket.sent[0]
    assert ANDROID_DEFENCE_CLIENT_TYPE_XML in fake_socket.sent[0]
    assert fake_socket.sent[0].endswith(f"{1:064x}"[:64].encode("latin1"))

    verify_header = CasFrameHeader.parse(fake_socket.sent[0])
    assert verify_header.sequence == 0x14
    assert verify_header.command == CAS_COMMAND_VERIFY
    assert verify_header.body_size_hint == 0x02D0
    assert verify_header.tail_size_hint == 0x01E0

    message_header_offset = fake_socket.sent[0].find(
        CAS_FRAME_MAGIC, CAS_FRAME_HEADER_SIZE
    )
    message_header = CasFrameHeader.parse(fake_socket.sent[0][message_header_offset:])
    assert message_header.sequence == 0x13
    assert message_header.command == CAS_COMMAND_DEVICE_MESSAGE
    assert message_header.flags == 0xFFFFFFFF
    assert message_header.body_size_hint == 0xB0

    encrypted_body = fake_socket.sent[0][
        message_header_offset + CAS_FRAME_HEADER_SIZE : -CAS_RANDOM_TRAILER_SIZE
    ]
    cipher = AES.new(
        b"1234567890abcdef",
        AES.MODE_CBC,
        b"CAM1234560123456",
    )
    decrypted_body = cipher.decrypt(encrypted_body)
    assert OPERATION_CODE_XML in decrypted_body
    assert fake_socket.closed is True


def test_cas_frame_header_rejects_invalid_payload() -> None:
    with pytest.raises(ValueError, match="shorter"):
        CasFrameHeader.parse(b"short")

    with pytest.raises(ValueError, match="magic"):
        CasFrameHeader.parse((b"x" * 4) + (b"\0" * 28))
