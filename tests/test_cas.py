from __future__ import annotations

import ssl
from typing import Any

from Crypto.Cipher import AES
import pytest

from pyezvizapi.cas import (
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
LOCAL_RESPONSE = b"local-response"
OPERATION_CODE_XML = b"<OperationCode>0123456</OperationCode>"


class FakeSocket:
    def __init__(self, response: bytes = b"") -> None:
        self.response = response
        self.sent: list[bytes] = []
        self.closed = False
        self.ssl_context: FakeSSLContext | None = None

    def send(self, payload: bytes) -> int:
        self.sent.append(payload)
        return len(payload)

    def recv(self, size: int = 1024) -> bytes:
        return self.response

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
        assert server_hostname == "cas.example.test"
        sock.ssl_context = self
        return sock


def _token() -> dict[str, Any]:
    sys_conf: list[Any] = [None] * 17
    sys_conf[15] = "cas.example.test"
    sys_conf[16] = 443
    return {"session_id": "session-id", "service_urls": {"sysConf": sys_conf}}


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
    fake_socket = FakeSocket((b"h" * 32) + body + (b"t" * 32))
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token()).cas_get_encryption("CAM123")

    assert connect_calls == [("cas.example.test", 443)]
    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert result["Response"]["Session"]["@OperationCode"] == "0123456789"
    device_session = CasDeviceSession.from_response(result)
    assert device_session.key == "1234567890abcdef"
    assert device_session.operation_code == "0123456789"
    assert device_session.encrypt_type == 2
    assert DEV_SERIAL_XML in fake_socket.sent[0]
    assert fake_socket.ssl_context is not None
    assert fake_socket.ssl_context.check_hostname is False
    assert fake_socket.ssl_context.verify_mode == ssl.CERT_NONE
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


def test_cas_get_encryption_can_require_tls_certificate_validation(
    monkeypatch,
) -> None:
    body = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" '
        b'EncryptType="2" /></Response>'
    )
    fake_socket = FakeSocket((b"h" * 32) + body + (b"t" * 32))

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
    fake_socket = FakeSocket((b"h" * 32) + (b"t" * 32))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="did not contain an XML body"):
        EzvizCAS(_token()).cas_get_encryption("CAM123")

    assert fake_socket.closed is True


def test_cas_get_encryption_rejects_malformed_xml_body(monkeypatch) -> None:
    fake_socket = FakeSocket((b"h" * 32) + b"<Response>" + (b"t" * 32))

    monkeypatch.setattr(
        "pyezvizapi.cas.socket.create_connection",
        lambda _address: fake_socket,
    )
    monkeypatch.setattr("pyezvizapi.cas.ssl.create_default_context", FakeSSLContext)

    with pytest.raises(PyEzvizError, match="Could not parse CAS"):
        EzvizCAS(_token()).cas_get_encryption("CAM123")

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
    fake_socket = FakeSocket(b"ok")
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

    assert EzvizCAS(_token()).set_camera_defence_state("CAM123456", enable=0) is True

    assert connect_calls == [("cas.example.test", 443)]
    assert len(fake_socket.sent) == 1
    assert CLIENT_SESSION_XML in fake_socket.sent[0]
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
