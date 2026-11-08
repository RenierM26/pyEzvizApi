"""RTSP framing and ownership tests without a camera."""
import socket

import pytest

from pyezvizapi.exceptions import AuthTestResultFailed, InvalidHost
from pyezvizapi.streaming import rtsp_auth
from pyezvizapi.streaming.rtsp_auth import TestRTSPAuth as Implementation
from pyezvizapi.streaming.rtsp_compat import TestRTSPAuth

REPLY = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 4\r\n\r\ndata"


class Socket:
    def __init__(self, chunks, connect_error=None):
        self.chunks = list(chunks)
        self.connect_error = connect_error
        self.closed = False
        self.sent = []
        self.timeouts = []
    def settimeout(self, timeout):
        self.timeouts.append(timeout)
    def connect(self, _address):
        if self.connect_error:
            raise self.connect_error
    def send(self, data):
        raise AssertionError("the probe must use sendall")
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""
    def close(self):
        self.closed = True


@pytest.mark.parametrize("split", range(1, len(REPLY)))
def test_fragmented_response_and_deterministic_close(monkeypatch, split):
    session = Socket([REPLY[:split], REPLY[split:]])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    TestRTSPAuth("192.0.2.10", "user", "pass", "/h264").main()
    assert session.closed and session.timeouts and len(session.sent) == 1


@pytest.mark.parametrize("reply", [b"RTSP/1.0 404 Not Found\r\n\r\n200 OK", b"invalid 200 OK\r\n\r\n", b"RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"only\"\r\n\r\n", b"RTSP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nx"])
def test_invalid_or_incomplete_response_is_not_success(monkeypatch, reply):
    session = Socket([reply])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    with pytest.raises(AuthTestResultFailed):
        TestRTSPAuth("192.0.2.10", "user", "pass").main()
    assert session.closed


@pytest.mark.parametrize("error, category", [(TimeoutError(), AuthTestResultFailed), (socket.gaierror(), InvalidHost), (ConnectionRefusedError(), InvalidHost)])
def test_connection_failures_close_the_socket(monkeypatch, error, category):
    session = Socket([], error)
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    with pytest.raises(category):
        TestRTSPAuth("192.0.2.10").main()
    assert session.closed


@pytest.mark.parametrize("reply", [
    b"RTSP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n",
    b"RTSP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n",
    b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n",
    b"x" * 65536,
])
def test_response_size_and_sequence_boundaries(monkeypatch, reply):
    session = Socket([reply[i:i + 1024] for i in range(0, len(reply), 1024)])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    with pytest.raises(AuthTestResultFailed):
        TestRTSPAuth("192.0.2.10").main()
    assert session.closed


def test_deadline_is_shared_across_fragmented_reads(monkeypatch):
    clock = [0.0]
    class Dribble(Socket):
        def recv(self, _size):
            clock[0] += 0.04
            return b"R"
    session = Dribble([])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    monkeypatch.setattr(rtsp_auth.time, "monotonic", lambda: clock[0])
    with pytest.raises(AuthTestResultFailed, match="deadline"):
        TestRTSPAuth("192.0.2.10", timeout=0.1).main()
    assert session.closed and clock[0] == pytest.approx(0.12)
    assert session.timeouts[-1] < session.timeouts[0]


def test_legacy_rtsp_import_is_the_same_implementation():
    assert TestRTSPAuth is Implementation


def test_explicitly_empty_digest_realm_authenticates(monkeypatch):
    """An empty quoted realm is distinct from an absent realm directive."""
    session = Socket([
        b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm="", nonce="nonce-1"\r\n\r\n',
        b'RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n',
    ])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    probe = TestRTSPAuth("192.0.2.10", "user", "pass", "/h264")
    probe.main()
    assert session.closed and len(session.sent) == 2
    empty_realm = b'realm=""'
    assert empty_realm in session.sent[1]
    expected = probe.generate_auth_string(b"", "DESCRIBE", "/h264", b"nonce-1")
    assert f"Authorization: {expected}\r\n".encode() in session.sent[1]


def test_missing_digest_realm_is_still_rejected(monkeypatch):
    session = Socket([
        b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest nonce="nonce-1"\r\n\r\n',
    ])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    with pytest.raises(AuthTestResultFailed, match="challenge"):
        TestRTSPAuth("192.0.2.10", "user", "pass", "/h264").main()
    assert session.closed and len(session.sent) == 1


@pytest.mark.parametrize("indent", [b" ", b"\t"])
@pytest.mark.parametrize("realm", [b"camera", b""])
def test_folded_digest_challenge_authenticates(monkeypatch, indent, realm):
    challenge = (b'RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n'
                 b'WWW-Authenticate: Digest realm="' + realm + b'",\r\n'
                 + indent + b'nonce="nonce-1"\r\n\r\n')
    session = Socket([challenge[:70], challenge[70:], b'RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n'])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    probe = TestRTSPAuth("192.0.2.10", "user", "pass", "/h264")
    probe.main()
    expected = probe.generate_auth_string(realm, "DESCRIBE", "/h264", b"nonce-1")
    assert session.closed and len(session.sent) == 2
    assert f"Authorization: {expected}\r\n".encode() in session.sent[1]


def test_orphan_header_continuation_is_rejected(monkeypatch):
    session = Socket([b'RTSP/1.0 200 OK\r\n orphan\r\n\r\n'])
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: session)
    with pytest.raises(AuthTestResultFailed, match="header"):
        TestRTSPAuth("192.0.2.10").main()
    assert session.closed
@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), 10**1000])
def test_invalid_timeout_fails_before_socket_allocation(monkeypatch, timeout):
    def forbidden(*_args, **_kwargs):
        pytest.fail("must validate before opening socket")
    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(ValueError):
        TestRTSPAuth("unused.invalid", timeout=timeout)
