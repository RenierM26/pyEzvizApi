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
from .exceptions import EzvizPushFatalError


class Exchange(Protocol):
    def exchange(self, frame: bytes) -> tuple[int, bytes]:
        """Send a frame and read one response."""
        raise NotImplementedError
    def send(self, frame: bytes) -> None:
        """Send a frame without waiting for a response."""
        raise NotImplementedError


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
        raise EzvizPushFatalError("Push state belongs to a different client identity; recovery required")
    session_hash = hashlib.sha256(session_token.encode()).hexdigest()
    if "device_id" in state:
        device = _saved_key(state["device_id"], 32, "device identity")
        if state.get("session_hash") == session_hash and "master_key" in state:
            master = _saved_key(state["master_key"], 16, "master key")
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
                raise EzvizPushFatalError(
                    f"Cached push credentials rejected (status {error.status}); recovery required"
                ) from error
    elif state:
        raise EzvizPushFatalError("Saved push state has no device identity; recovery required")
    else:
        device = None

    # EZVIZ protocol requires this MD5-derived input; it is not a storage hash.
    # Changing the digest breaks compatibility with the remote authentication peer.
    shared = wire.share_key(hashlib.md5(session_token.encode()).hexdigest().encode(), serial)
    n1, n3 = secrets.token_bytes(2)
    try:
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
    except wire.AuthenticationRejected as error:
        raise EzvizPushFatalError(
            f"Push authentication rejected (status {error.status}); reauthentication required"
        ) from error
    state.update(
        identity=identity,
        device_id=device.hex(),
        master_key=master.hex(),
        session_hash=session_hash,
        phase="authenticated",
    )
    save(dict(state))
    return _redirect(connection, serial, device, master, session)


def _saved_key(value: Any, size: int, label: str) -> bytes:
    """Validate local credentials before attempting any remote handshake."""
    if not isinstance(value, str):
        raise EzvizPushFatalError(f"Invalid saved push {label}; recovery required")
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise EzvizPushFatalError(f"Invalid saved push {label}; recovery required") from error
    if len(result) != size:
        raise EzvizPushFatalError(f"Invalid saved push {label}; recovery required")
    return result


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
