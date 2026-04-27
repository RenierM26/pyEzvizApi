from __future__ import annotations

from typing import Any

import pytest

from pyezvizapi.cas import EzvizCAS, xor_enc_dec
from pyezvizapi.exceptions import PyEzvizError

DEV_SERIAL_XML = b"<DevSerial>CAM123</DevSerial>"
CLIENT_SESSION_XML = b'ClientSession="session-id"'


class FakeSocket:
    def __init__(self, response: bytes = b"") -> None:
        self.response = response
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, payload: bytes) -> int:
        self.sent.append(payload)
        return len(payload)

    def recv(self, size: int = 1024) -> bytes:
        return self.response

    def close(self) -> None:
        self.closed = True


class FakeSSLContext:
    def __init__(self, protocol: Any) -> None:
        self.protocol = protocol
        self.ciphers: str | None = None

    def set_ciphers(self, ciphers: str) -> None:
        self.ciphers = ciphers

    def wrap_socket(self, sock: FakeSocket, *, server_hostname: str) -> FakeSocket:
        assert server_hostname == "cas.example.test"
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
        b'<Response><Session Key="1234567890abcdef" OperationCode="0123456789" /></Response>'
    )
    fake_socket = FakeSocket((b"h" * 32) + body + (b"t" * 32))
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.SSLContext", FakeSSLContext)
    monkeypatch.setattr("pyezvizapi.cas.random.randrange", lambda value: 1)

    result = EzvizCAS(_token()).cas_get_encryption("CAM123")

    assert connect_calls == [("cas.example.test", 443)]
    assert result["Response"]["Session"]["@Key"] == "1234567890abcdef"
    assert result["Response"]["Session"]["@OperationCode"] == "0123456789"
    assert DEV_SERIAL_XML in fake_socket.sent[0]
    assert fake_socket.closed is True


def test_set_camera_defence_state_sends_encrypted_payload(monkeypatch) -> None:
    fake_socket = FakeSocket(b"ok")
    connect_calls: list[tuple[str, int]] = []

    def fake_create_connection(address: tuple[str, int]) -> FakeSocket:
        connect_calls.append(address)
        return fake_socket

    monkeypatch.setattr("pyezvizapi.cas.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("pyezvizapi.cas.ssl.SSLContext", FakeSSLContext)
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
    assert fake_socket.closed is True
