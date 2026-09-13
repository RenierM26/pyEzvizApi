"""Handshake state transitions, including failures after server allocation."""

import hashlib
import json
from typing import Any

import pytest

from pyezvizapi import _longlink as wire
from pyezvizapi._longlink_auth import authenticate

SERIAL = b"MOBILE:ys7:synthetic-user:synthetic-phone"
TOKEN = "synthetic-token"
DEVICE = bytes(range(32))
SESSION = bytes(range(16))


class Peer:
    def __init__(self, *, redirect_fails: bool = False) -> None:
        self.commands: list[int] = []
        self.redirect_fails = redirect_fails
        self.shared = wire.share_key(hashlib.md5(TOKEN.encode()).hexdigest().encode(), SERIAL)
        self.n1 = 0

    def send(self, frame: bytes) -> None:
        self.commands.append(frame[0] >> 4)

    def exchange(self, frame: bytes) -> tuple[int, bytes]:
        command = frame[0] >> 4
        self.commands.append(command)
        if command == 1:
            self.n1 = frame[7 + len(SERIAL)]
            return 2, b"\x01\x00\x00\x00\x22" + wire.signature(
                SERIAL + bytes([self.n1, 0x22]), self.shared
            )
        if command in (3, 4):
            n3 = frame[5]
            master = wire.master_key(bytes([self.n1, 0x22, n3, 0x44]), self.shared)
            signed = wire.signature(SERIAL + bytes([n3, 0x44]), self.shared)
            if command == 3:
                assert frame[7:39] == DEVICE
                return 5, b"\x01\x00\x00\x00\x44\x20" + wire.encrypt(master, SESSION) + signed
            return 6, b"\x01\x00\x00\x00\x44\x30" + wire.encrypt(
                master, DEVICE
            ) + b"\x20" + wire.encrypt(master, SESSION) + signed
        if command == 10:
            if self.redirect_fails:
                raise ConnectionError("Synthetic redirect failure")
            body = {
                "Type": "DAS",
                "DasInfo": {
                    "Address": "192.0.2.10",
                    "Domain": "broker.example.invalid",
                    "Port": 8667,
                    "UdpPort": 0,
                    "ServerID": "synthetic",
                },
            }
            return 11, b"\x01\x00\x00\x00" + wire.encrypt(SESSION, json.dumps(body).encode())
        raise AssertionError(f"Unexpected command {command}")


def test_creation_persisted_before_redirect_failure() -> None:
    state: dict[str, Any] = {}
    saved: list[dict[str, Any]] = []
    peer = Peer(redirect_fails=True)
    with pytest.raises(ConnectionError):
        authenticate(peer, SERIAL, TOKEN, state, saved.append)
    assert saved[0]["phase"] == "creation_pending"
    assert saved[1]["device_id"] == DEVICE.hex()
    assert peer.commands == [1, 4, 10]


def test_existing_identity_retained_on_session_rotation() -> None:
    state: dict[str, Any] = {"device_id": DEVICE.hex(), "session_hash": "old"}
    saved: list[dict[str, Any]] = []
    peer = Peer()
    credentials = authenticate(peer, SERIAL, TOKEN, state, saved.append)
    assert credentials.device_id == DEVICE
    assert peer.commands == [1, 3, 10]
    assert len(saved) == 1
    assert saved[0]["session_hash"] == hashlib.sha256(TOKEN.encode()).hexdigest()


def test_failed_persistence_stops_before_redirect() -> None:
    state: dict[str, Any] = {"device_id": DEVICE.hex()}
    peer = Peer()

    def save(snapshot: dict[str, Any]) -> None:
        raise OSError("Synthetic storage failure")

    with pytest.raises(OSError):
        authenticate(peer, SERIAL, TOKEN, state, save)
    assert peer.commands == [1, 3]
    # Retry may not bypass failed persistence via the cached-key branch.
    with pytest.raises(OSError):
        authenticate(peer, SERIAL, TOKEN, state, save)
    assert peer.commands == [1, 3]


@pytest.mark.parametrize("state", [{"phase": "creation_pending"}, {"identity": "different"}])
def test_ambiguous_creation_or_wrong_account_stops_without_network(state: dict[str, Any]) -> None:
    peer = Peer()
    with pytest.raises(ValueError):
        authenticate(peer, SERIAL, TOKEN, state, lambda value: None)
    assert peer.commands == []


@pytest.mark.parametrize("status", [10, 5])
def test_only_invalid_master_key_selects_existing_device_reauthentication(status: int) -> None:
    state: dict[str, Any] = {
        "device_id": DEVICE.hex(),
        "master_key": SESSION.hex(),
        "session_hash": hashlib.sha256(TOKEN.encode()).hexdigest(),
    }
    saved: list[dict[str, Any]] = []

    class RejectedPeer(Peer):
        def exchange(self, frame: bytes) -> tuple[int, bytes]:
            self.commands.append(frame[0] >> 4)
            return 8, b"\x01\x00\x00" + bytes([status])

    rejected = RejectedPeer()
    with pytest.raises(wire.AuthenticationRejected):
        authenticate(rejected, SERIAL, TOKEN, state, saved.append)
    assert rejected.commands == [7]
    assert state["device_id"] == DEVICE.hex()
    if status == 10:
        assert "master_key" not in state
        assert saved[-1]["phase"] == "needs_reauthentication"
        retry = Peer()
        credentials = authenticate(retry, SERIAL, TOKEN, state, saved.append)
        assert credentials.device_id == DEVICE
        assert retry.commands == [1, 3, 10]
    else:
        assert state["master_key"] == SESSION.hex()
        assert len(saved) == 1
