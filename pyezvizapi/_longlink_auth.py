"""Channel-99 handshake orchestration with caller-owned durable state.

Persistence is synchronous: the callback must save state before returning. No
files are written by the library and credential objects suppress their repr.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import secrets
from typing import Any, Protocol

from . import _longlink as wire


class Exchange(Protocol):
    def exchange(self, frame: bytes) -> tuple[int, bytes]: ...
    def send(self, frame: bytes) -> None: ...


@dataclass(repr=False)
class PushCredentials:
    device_id: bytes
    master_key: bytes
    session_key: bytes
    broker: dict[str, Any]


def authenticate(
    connection: Exchange,
    serial: bytes,
    session_token: str,
    state: dict[str, Any],
    save: Callable[[dict[str, Any]], None],
) -> PushCredentials:
    """Renew cached keys, or authenticate using the current HTTPS session.

    The state belongs to exactly one account/client identity. An interrupted
    device creation is never retried automatically: the server may already have
    allocated an identity. A failed persistence callback stops before DAS.
    """
    identity = hashlib.sha256(serial).hexdigest()
    if state.get("identity", identity) != identity:
        raise ValueError("Push state belongs to a different client identity")
    session_hash = hashlib.sha256(session_token.encode()).hexdigest()
    device_hex = state.get("device_id")
    if device_hex:
        device = bytes.fromhex(device_hex)
        if len(device) != 32:
            raise ValueError("Invalid saved push identity")
        if state.get("session_hash") == session_hash and state.get("master_key"):
            master = bytes.fromhex(state["master_key"])
            save(dict(state))
            try:
                return _cached(connection, serial, device, master)
            except wire.AuthenticationRejected as error:
                if error.status == 10:  # Native platform_masterkey_invalid (10010).
                    state.pop("master_key", None)
                    state.pop("session_hash", None)
                    state["phase"] = "needs_reauthentication"
                    save(dict(state))
                # Retry on a fresh connection, never on this failed socket.
                raise
    elif state.get("phase") == "creation_pending":
        raise ValueError("Previous push-device creation is incomplete; recovery required")
    else:
        device = None

    shared = wire.share_key(hashlib.md5(session_token.encode()).hexdigest().encode(), serial)
    n1, n3 = secrets.token_bytes(2)
    n2 = wire.authentication_ii(
        _response(connection, wire.authentication_i(serial, shared, n1), 2), serial, shared, n1
    )
    if device is None:
        state.update(identity=identity, phase="creation_pending")
        save(dict(state))
        payload = _response(connection, wire.authentication_iii_create(serial, shared, n2, n3), 6)
        device, master, session = wire.authentication_iv_create(
            payload, serial, shared, bytes([n1, n2, n3])
        )
    else:
        payload = _response(
            connection, wire.authentication_iii_existing(serial, shared, device, n2, n3), 5
        )
        master, session = wire.authentication_iv_existing(
            payload, serial, shared, bytes([n1, n2, n3])
        )
    state.update(
        identity=identity,
        device_id=device.hex(),
        master_key=master.hex(),
        session_hash=session_hash,
        phase="authenticated",
    )
    save(dict(state))
    return _redirect(connection, serial, device, master, session)


def _response(connection: Exchange, request: bytes, expected: int) -> bytes:
    command, payload = connection.exchange(request)
    if command != expected:
        raise ValueError("Unexpected long-link response command")
    return payload


def _redirect(
    connection: Exchange, serial: bytes, device: bytes, master: bytes, session: bytes
) -> PushCredentials:
    payload = _response(connection, wire.das_request(serial, session), 11)
    return PushCredentials(device, master, session, wire.das_response(payload, session))


def _cached(connection: Exchange, serial: bytes, device: bytes, master: bytes) -> PushCredentials:
    nonce = secrets.randbelow(256)
    payload = _response(connection, wire.refresh_i(serial, device, master, nonce), 8)
    n2, session = wire.refresh_ii(payload, master, nonce)
    connection.send(wire.refresh_iii(master, n2))
    return _redirect(connection, serial, device, master, session)
