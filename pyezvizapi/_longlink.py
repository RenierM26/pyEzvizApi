"""Private codec for EZVIZ channel-99 long-link messages.

The mobile protocol uses fixed AES-CBC parameters and MD5-derived shared keys.
These are wire-compatibility requirements, not general-purpose crypto defaults.
No sockets, account registration or persistence are performed by this module.
"""

# Wire field widths and command numbers are intentionally literal here.
from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

IV = b"01234567" + bytes(8)


class AuthenticationRejected(ValueError):
    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"Long-link authentication rejected: {status}")


def header(command: int, length: int) -> bytes:
    if not 0 <= command <= 15 or not 0 <= length <= 268435455:
        raise ValueError("Invalid command or frame length")
    out = bytearray([command << 4])
    while True:
        digit = length & 127
        length >>= 7
        out.append(digit | (128 if length else 0))
        if not length:
            return bytes(out)


def share_key(verification_code: bytes, subserial: bytes, uppercase_first: bool = True) -> bytes:
    first = hashlib.md5(verification_code + subserial).hexdigest()
    if uppercase_first:
        first = first.upper()
    second = hashlib.md5(first.encode() + b"www.88075998.com").hexdigest().upper().encode()
    return hashlib.md5(second).hexdigest().upper().encode()


def master_key(random_bytes: bytes, shared: bytes) -> bytes:
    if len(random_bytes) != 4 or len(shared) != 32:
        raise ValueError("Invalid key input")
    return hashlib.sha384(random_bytes + shared).digest()[:8].hex().upper().encode()


def signature(data: bytes, key: bytes) -> bytes:
    return hmac.digest(key, hashlib.sha256(data).digest(), "sha256")


def encrypt(key: bytes, plain: bytes) -> bytes:
    padding = 16 - len(plain) % 16
    ctx = Cipher(algorithms.AES(key), modes.CBC(IV)).encryptor()
    return ctx.update(plain + bytes([padding]) * padding) + ctx.finalize()


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("Invalid ciphertext length")
    ctx = Cipher(algorithms.AES(key), modes.CBC(IV)).decryptor()
    plain = ctx.update(ciphertext) + ctx.finalize()
    pad = plain[-1]
    if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding")
    return plain[:-pad]


def authentication_i(subserial: bytes, shared: bytes, random_1: int, auth_mode: int = 2) -> bytes:
    if not 0 < len(subserial) <= 127 or not 0 <= random_1 <= 255 or not 0 <= auth_mode <= 255:
        raise ValueError("Invalid authentication fields")
    payload = bytes([1, 3, 0, auth_mode, len(subserial)]) + subserial + bytes([random_1])
    payload += signature(subserial + bytes([random_1]), shared)
    return header(1, len(payload)) + payload


def authentication_ii(payload: bytes, subserial: bytes, shared: bytes, random_1: int) -> int:
    """Validate the AUTH-II payload (outer command/header handled separately)."""
    if len(payload) < 4:
        raise ValueError("Truncated authentication response")
    if payload[:3] not in (b"\x01\x03\x00", b"\x01\x00\x00"):
        raise ValueError("Unexpected protocol version")
    if payload[3]:
        raise AuthenticationRejected(payload[3])
    if len(payload) != 37:
        raise ValueError("Invalid authentication response length")
    random_2 = payload[4]
    expected = signature(subserial + bytes([random_1, random_2]), shared)
    if not hmac.compare_digest(payload[5:], expected):
        raise ValueError("Authentication signature mismatch")
    return random_2


def authentication_iii_create(
    subserial: bytes, shared: bytes, random_2: int, random_3: int
) -> bytes:
    payload = (
        b"\x01\x01\x00"
        + bytes([random_3])
        + signature(subserial + bytes([random_2, random_3]), shared)
    )
    return header(4, len(payload)) + payload


def authentication_iv_create(
    payload: bytes, subserial: bytes, shared: bytes, random_123: bytes
) -> tuple[bytes, bytes, bytes]:
    if (
        len(random_123) != 3
        or len(payload) != 119
        or payload[:4] not in (b"\x01\x01\x00\x00", b"\x01\x00\x00\x00")
    ):
        raise ValueError("Invalid device-creation response")
    random_4 = payload[4]
    key = master_key(random_123 + bytes([random_4]), shared)
    if payload[5] != 48 or payload[54] != 32:
        raise ValueError("Invalid encrypted key lengths")
    device_id = decrypt(key, payload[6:54])
    session_key = decrypt(key, payload[55:87])
    if len(device_id) != 32 or len(session_key) != 16:
        raise ValueError("Invalid decrypted key lengths")
    signed = subserial + bytes([random_123[2], random_4])
    if not hmac.compare_digest(payload[87:], signature(signed, shared)):
        raise ValueError("Invalid key-response signature")
    return device_id, key, session_key


def das_request(subserial: bytes, session_key: bytes, mode: int = 4) -> bytes:
    payload = b"\x01\x01\x00" + encrypt(
        session_key,
        json.dumps(
            {"DevSerial": subserial.decode("ascii"), "Type": "DAS", "Mode": mode},
            separators=(",", ":"),
        ).encode(),
    )
    return header(10, len(payload)) + payload


def das_response(payload: bytes, session_key: bytes) -> dict[str, Any]:
    if len(payload) < 20 or payload[:4] not in (b"\x01\x01\x00\x00", b"\x01\x00\x00\x00"):
        raise ValueError("Invalid DAS response")
    obj = json.loads(decrypt(session_key, payload[4:]))
    if not isinstance(obj, dict) or obj.get("Type") != "DAS":
        raise ValueError("Wrong redirect type")
    info = obj.get("DasInfo")
    if not isinstance(info, dict):
        raise ValueError("Missing DAS information")
    for field, limit in [("Address", 63), ("Domain", 63), ("ServerID", 127)]:
        value = info.get(field)
        if not isinstance(value, str) or not value or len(value.encode()) > limit or "\0" in value:
            raise ValueError("Invalid DAS text field")
    for field in ["Port", "UdpPort"]:
        if type(info.get(field)) is not int or not 0 <= info[field] <= 65535:
            raise ValueError("Invalid DAS port")
    if info["Port"] == 0:
        raise ValueError("Invalid TCP port")
    return info


def refresh_i(subserial: bytes, device_id: bytes, master: bytes, random_1: int) -> bytes:
    if len(device_id) != 32 or not 0 < len(subserial) <= 127:
        raise ValueError("Invalid identity")
    payload = (
        b"\x01\x01\x00"
        + bytes([len(subserial)])
        + subserial
        + b"\x20"
        + device_id
        + encrypt(master, bytes([random_1]))
    )
    return header(7, len(payload)) + payload


def refresh_ii(payload: bytes, master: bytes, random_1: int) -> tuple[int, bytes]:
    if len(payload) >= 4 and payload[:3] in (b"\x01\x01\x00", b"\x01\x00\x00") and payload[3]:
        raise AuthenticationRejected(payload[3])
    if len(payload) != 36 or payload[:4] not in (b"\x01\x01\x00\x00", b"\x01\x00\x00\x00"):
        raise ValueError("Invalid refresh response")
    plain = decrypt(master, payload[4:])
    if len(plain) != 18 or plain[0] != random_1:
        raise ValueError("Refresh challenge mismatch")
    return plain[1], plain[2:]


def refresh_iii(master: bytes, random_2: int) -> bytes:
    payload = b"\x01\x01\x00" + encrypt(master, bytes([random_2]))
    return header(9, len(payload)) + payload


def decode_event_envelope(
    topic: str, ciphertext: bytes, session_key: bytes, subserial: bytes
) -> dict[str, Any]:
    match = re.fullmatch(r"/([^/]+)/([0-9]+)/([0-9]+)", topic)
    if not match or match[1] != subserial.decode("ascii"):
        raise ValueError("Unexpected MQTT topic")
    plain = decrypt(session_key, ciphertext)
    if len(plain) < 2:
        raise ValueError("Truncated envelope")
    size = int.from_bytes(plain[:2], "big")
    if size == 0 or size > len(plain) - 2:
        raise ValueError("Invalid metadata length")
    meta = json.loads(plain[2 : 2 + size].rstrip(b"\0"))
    if (
        not isinstance(meta, dict)
        or type(meta.get("Seq")) is not int
        or not isinstance(meta.get("CmdVer"), str)
    ):
        raise ValueError("Invalid metadata")
    return {
        "domain": int(match[2]),
        "command": int(match[3]),
        "sequence": meta["Seq"],
        "version": meta["CmdVer"],
        "body": plain[2 + size :],
    }


def decode_mobile_body(body: bytes) -> dict[str, Any]:
    """Mobile 0x6000..0x6fff body; unknown header words remain opaque.

    Native accepts trailing bytes. Preserve them instead of silently discarding.
    Does not assume either variable segment is JSON, text or an image.
    """
    if len(body) < 56:
        raise ValueError("Truncated mobile header")
    sequence, command, first_length, second_length = struct.unpack(">IIII", body[4:20])
    end = 56 + first_length + second_length
    if len(body) < end:
        raise ValueError("Truncated mobile segments")
    return {
        "sequence": sequence,
        "command": command,
        "id": body[20:52],
        "first": body[56 : 56 + first_length],
        "second": body[56 + first_length : end],
        "trailing": body[end:],
    }


def encode_application_ack(
    key: bytes,
    domain: int,
    command: int,
    sequence: int,
    *,
    version: str = "v2.4.0 build 20250310",
    body: bytes = b"{}",
) -> tuple[str, bytes]:
    """Return outgoing MQTT topic and ciphertext, not a MQTT PUBACK packet."""
    metadata = json.dumps(
        {"CmdVer": version, "Seq": sequence, "MsgType": 2}, separators=(",", ":")
    ).encode()
    return f"/{domain}/{command}", encrypt(key, len(metadata).to_bytes(2, "big") + metadata + body)


def control_keepalive(body: bytes) -> int | None:
    """Native domain1000/command1 KeepAlive.Interval, when present."""
    obj = json.loads(body.rstrip(b"\0"))
    if not isinstance(obj, dict):
        raise ValueError("Invalid control message")
    keepalive = obj.get("KeepAlive")
    if keepalive is None:
        return None
    if not isinstance(keepalive, dict):
        raise ValueError("Invalid keepalive settings")
    interval = keepalive.get("Interval")
    if type(interval) is not int or not 1 <= interval <= 65535:
        raise ValueError("Invalid keepalive interval")
    return interval


def authentication_iii_existing(
    subserial: bytes, shared: bytes, device_id: bytes, random_2: int, random_3: int
) -> bytes:
    """Authenticate a saved device identity without creating another registration."""
    if len(device_id) != 32:
        raise ValueError("Invalid device identity")
    payload = b"\x01\x01\x00" + bytes([random_3, 32]) + device_id
    payload += signature(subserial + bytes([random_2, random_3]), shared)
    return header(3, len(payload)) + payload


def authentication_iv_existing(
    payload: bytes, subserial: bytes, shared: bytes, random_123: bytes
) -> tuple[bytes, bytes]:
    """Verify the existing-device response and return rotated master/session keys."""
    if (
        len(random_123) != 3
        or len(payload) != 70
        or payload[:4] not in (b"\x01\x01\x00\x00", b"\x01\x00\x00\x00")
    ):
        raise ValueError("Invalid existing-device response")
    if payload[5] != 32:
        raise ValueError("Invalid encrypted session-key length")
    random_4 = payload[4]
    signed = subserial + bytes([random_123[2], random_4])
    if not hmac.compare_digest(payload[38:], signature(signed, shared)):
        raise ValueError("Invalid key-response signature")
    master = master_key(random_123 + bytes([random_4]), shared)
    session = decrypt(master, payload[6:38])
    if len(session) != 16:
        raise ValueError("Invalid session-key length")
    return master, session
