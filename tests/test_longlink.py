"""Portable protocol tests: synthetic native vectors, no Android runtime/network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyezvizapi import _longlink as protocol

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "longlink_native.json").read_text())


def test_native_authentication_vector() -> None:
    serial = FIXTURE["serial"].encode()
    shared = protocol.share_key(FIXTURE["code"].encode(), serial)
    assert shared == FIXTURE["shared"].encode()
    assert (
        protocol.master_key(bytes.fromhex(FIXTURE["nonce_hex"]), shared)
        == FIXTURE["master"].encode()
    )
    assert protocol.authentication_i(serial, shared, 0x11) == bytes.fromhex(FIXTURE["auth_i_hex"])


def test_native_direct_ack_vector() -> None:
    ack = FIXTURE["ack"]
    topic, ciphertext = protocol.encode_application_ack(
        bytes.fromhex(ack["key_hex"]), 9000, 2, ack["sequence"], body=ack["body"].encode()
    )
    assert topic == ack["topic"]
    assert ciphertext == bytes.fromhex(ack["ciphertext_hex"])


@pytest.mark.parametrize(
    ("size", "expected"),
    [(0, "1000"), (127, "107f"), (128, "108001"), (16384, "10808001")],
)
def test_frame_boundaries(size: int, expected: str) -> None:
    assert protocol.header(1, size).hex() == expected


@pytest.mark.parametrize("size", [-1, 268435456])
def test_oversize_frame_rejected(size: int) -> None:
    with pytest.raises(ValueError):
        protocol.header(1, size)


@pytest.mark.parametrize("version", [b"\x01\x03\x00", b"\x01\x00\x00"])
def test_authentication_response_checks_signature(version: bytes) -> None:
    serial = FIXTURE["serial"].encode()
    shared = FIXTURE["shared"].encode()
    response = version + b"\x00\x22" + protocol.signature(serial + b"\x11\x22", shared)
    assert protocol.authentication_ii(response, serial, shared, 0x11) == 0x22
    with pytest.raises(ValueError, match="signature mismatch"):
        protocol.authentication_ii(response[:-1] + bytes([response[-1] ^ 1]), serial, shared, 0x11)


def test_server_lookup_rejection_is_not_a_version_error() -> None:
    with pytest.raises(protocol.AuthenticationRejected) as caught:
        protocol.authentication_ii(bytes.fromhex("01000005"), b"serial", b"key", 1)
    assert caught.value.status == 5


def test_cached_refresh_rejects_wrong_echoed_nonce() -> None:
    master = FIXTURE["master"].encode()
    session = bytes(range(16))
    response = b"\x01\x00\x00\x00" + protocol.encrypt(master, b"\x11\x22" + session)
    assert protocol.refresh_ii(response, master, 0x11) == (0x22, session)
    with pytest.raises(ValueError, match="challenge mismatch"):
        protocol.refresh_ii(response, master, 0x12)


def test_event_topic_identity_and_metadata_bounds() -> None:
    serial = b"MOBILE:ys7:synthetic-user:synthetic-phone"
    key = bytes(range(16))
    meta = b'{"CmdVer":"1.0","Seq":42}'
    body = b'{"alert":"synthetic event"}'
    ciphertext = protocol.encrypt(key, len(meta).to_bytes(2, "big") + meta + body)
    topic = f"/{serial.decode()}/9000/1"
    event = protocol.decode_event_envelope(topic, ciphertext, key, serial)
    assert event["body"] == body and event["sequence"] == 42
    with pytest.raises(ValueError, match="topic"):
        protocol.decode_event_envelope(topic, ciphertext, key, b"other-identity")
    with pytest.raises(ValueError, match="metadata length"):
        protocol.decode_event_envelope(topic, protocol.encrypt(key, b"\xff\xff{}"), key, serial)


@pytest.mark.parametrize("interval", [30, 60, 180])
def test_server_keepalive(interval: int) -> None:
    body = json.dumps({"KeepAlive": {"Interval": interval}}).encode()
    assert protocol.control_keepalive(body) == interval


@pytest.mark.parametrize("interval", [0, -1, 65536, True, "30"])
def test_invalid_keepalive(interval: object) -> None:
    with pytest.raises(ValueError):
        protocol.control_keepalive(json.dumps({"KeepAlive": {"Interval": interval}}).encode())


@pytest.mark.parametrize("version", [b"\x01\x01\x00", b"\x01\x00\x00"])
def test_existing_device_key_rotation(version: bytes) -> None:
    serial = FIXTURE["serial"].encode()
    shared = FIXTURE["shared"].encode()
    device = bytes(range(32))
    nonces = b"\x11\x22\x33\x44"
    master = protocol.master_key(nonces, shared)
    session = bytes(range(16))
    request = protocol.authentication_iii_existing(serial, shared, device, 0x22, 0x33)
    assert request[0] == 0x30  # Existing-device AUTH-III, not create command 4.
    assert request[7:39] == device
    response = (
        version
        + b"\x00\x44\x20"
        + protocol.encrypt(master, session)
        + protocol.signature(serial + b"\x33\x44", shared)
    )
    assert protocol.authentication_iv_existing(response, serial, shared, nonces[:3]) == (
        master,
        session,
    )
    with pytest.raises(ValueError, match="signature"):
        protocol.authentication_iv_existing(
            response[:-1] + bytes([response[-1] ^ 1]), serial, shared, nonces[:3]
        )
    with pytest.raises(ValueError, match="existing-device response"):
        protocol.authentication_iv_existing(response[:-1], serial, shared, nonces[:3])
