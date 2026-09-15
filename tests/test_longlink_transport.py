"""Socket-level framing and teardown checks, without a cloud service."""

# Synthetic wire bytes are explicit test expectations.
# ruff: noqa: PLR2004
import socket
from threading import Event, Thread

import pytest

from pyezvizapi._longlink_transport import LbsConnection


def test_preserves_next_frame() -> None:
    local, peer = socket.socketpair()
    with peer, LbsConnection(local) as connection:
        peer.sendall(b"\x20\x03abc\x50\x02de")
        assert connection.exchange(b"request") == (2, b"abc")
        assert connection.exchange(b"next") == (5, b"de")
        assert peer.recv(11) == b"requestnext"


@pytest.mark.parametrize("frame", [b"\x21\x00", b"\x20\x80\x00", b"\x20\x81\x80\x04"])
def test_rejects_malformed_or_oversized_frame(frame: bytes) -> None:
    local, peer = socket.socketpair()
    with peer, LbsConnection(local) as connection:
        peer.sendall(frame)
        with pytest.raises(ValueError):
            connection.exchange(b"request")


def test_truncated_frame() -> None:
    local, peer = socket.socketpair()
    with peer, LbsConnection(local) as connection:
        peer.sendall(b"\x20\x03a")
        peer.shutdown(socket.SHUT_WR)
        with pytest.raises(ConnectionError):
            connection.exchange(b"request")


def test_total_deadline_not_reset_by_partial_frame() -> None:
    local, peer = socket.socketpair()
    times = iter([0.0, 1.0, 2.0, 11.0])
    with peer, LbsConnection(local, timeout=10, clock=lambda: next(times)) as connection:
        peer.sendall(b"\x20\x01a")
        with pytest.raises(TimeoutError):
            connection.exchange(b"request")


def test_close_unblocks_pending_read() -> None:
    local, peer = socket.socketpair()
    connection = LbsConnection(local, timeout=30)
    finished = Event()

    def read() -> None:
        try:
            connection.exchange(b"request")
        except (OSError, ConnectionError):
            finished.set()

    worker = Thread(target=read, daemon=True)
    with peer:
        worker.start()
        assert peer.recv(7) == b"request"
        connection.close()
        assert finished.wait(2)
    worker.join(timeout=2)
    assert not worker.is_alive()
