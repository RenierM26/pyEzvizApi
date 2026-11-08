"""wire crypto protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    _AES_RCON,
    _AES_SBOX,
    EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE,
    HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH,
    HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
    PyEzvizError,
    base64,
    binascii,
    ipaddress,
)


def _hcnetsdk_command_port_auth_mask(session_word: int, mask_seed: bytes) -> int:
    """Return the small native mask term mixed into command auth input."""
    return sum(
        mask_seed[index] & ((session_word >> (5 * index)) & 0xFF)
        for index in range(HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH)
    )


def _hcnetsdk_aes128_round_keys(key: bytes, *, rounds: int) -> tuple[bytes, ...]:
    """Return AES-128 round keys, truncated to the native command-auth rounds."""
    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    while len(words) < 4 * (rounds + 1):
        word = words[-1][:]
        if len(words) % 4 == 0:
            word = word[1:] + word[:1]
            word = [_AES_SBOX[item] for item in word]
            word[0] ^= _AES_RCON[(len(words) // 4) - 1]
        words.append([left ^ right for left, right in zip(words[-4], word, strict=True)])
    expanded = bytes(item for word in words for item in word)
    return tuple(expanded[index : index + 16] for index in range(0, 16 * (rounds + 1), 16))


def _hcnetsdk_aes_add_round_key(state: bytes, round_key: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(state, round_key, strict=True))


def _hcnetsdk_aes_sub_bytes(state: bytes) -> bytes:
    return bytes(_AES_SBOX[item] for item in state)


def _hcnetsdk_aes_shift_rows(state: bytes) -> bytes:
    return bytes(
        (
            state[0],
            state[5],
            state[10],
            state[15],
            state[4],
            state[9],
            state[14],
            state[3],
            state[8],
            state[13],
            state[2],
            state[7],
            state[12],
            state[1],
            state[6],
            state[11],
        )
    )


def _hcnetsdk_aes_xtime(value: int) -> int:
    shifted = value << 1
    if value & 0x80:
        shifted ^= 0x1B
    return shifted & 0xFF


def _hcnetsdk_aes_mix_columns(state: bytes) -> bytes:
    mixed = bytearray()
    for column_index in range(0, 16, 4):
        column = state[column_index : column_index + 4]
        doubled = [_hcnetsdk_aes_xtime(item) for item in column]
        mixed.extend(
            (
                doubled[0] ^ column[3] ^ column[2] ^ doubled[1] ^ column[1],
                doubled[1] ^ column[0] ^ column[3] ^ doubled[2] ^ column[2],
                doubled[2] ^ column[1] ^ column[0] ^ doubled[3] ^ column[3],
                doubled[3] ^ column[2] ^ column[1] ^ doubled[0] ^ column[0],
            )
        )
    return bytes(mixed)


def _hcnetsdk_command_port_four_round_aes(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block with the SDK's four-round AES-128 variant."""
    if len(block) != 16:
        raise PyEzvizError("HCNetSDK command-port auth block must be 16 bytes")
    if len(key) != HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth key must be 16 bytes")

    round_keys = _hcnetsdk_aes128_round_keys(key, rounds=4)
    state = _hcnetsdk_aes_add_round_key(block, round_keys[0])
    for round_index in range(1, 4):
        state = _hcnetsdk_aes_sub_bytes(state)
        state = _hcnetsdk_aes_shift_rows(state)
        state = _hcnetsdk_aes_mix_columns(state)
        state = _hcnetsdk_aes_add_round_key(state, round_keys[round_index])
    state = _hcnetsdk_aes_sub_bytes(state)
    state = _hcnetsdk_aes_shift_rows(state)
    return _hcnetsdk_aes_add_round_key(state, round_keys[4])


def hcnetsdk_command_port_auth_word(
    *,
    session_id: bytes,
    auth_seed: int,
    command_id: int,
    key: bytes,
    addend: int | None = None,
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
) -> int:
    """Return the native HCNetSDK port-8000 post-login command auth word.

    ``session_id`` is the network-order four-byte id returned in the login
    response and reused in command bodies. Native ``libHCCore.so`` reverses it
    into a host-order word before the auth routine, uses the first 16 challenge
    bytes as a four-round AES-128 key, folds the 16-byte result down to one
    little-endian word, then adds the session-derived time/addend word used in
    the command header.
    """
    if len(session_id) != 4:
        raise PyEzvizError("HCNetSDK command-port session id must be 4 bytes")
    if len(key) < HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth key must be at least 16 bytes")
    if len(mask_seed) < HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth mask seed must be 6 bytes")
    session_word = int.from_bytes(session_id, "big")
    input_word = (
        auth_seed + (command_id * 2) + _hcnetsdk_command_port_auth_mask(session_word, mask_seed)
    ) & 0xFFFFFFFF
    transformed = _hcnetsdk_command_port_four_round_aes(
        input_word.to_bytes(4, "little") + (b"\x00" * 12),
        key[:HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH],
    )
    folded = bytes(
        transformed[index]
        ^ transformed[index + 4]
        ^ transformed[index + 8]
        ^ transformed[index + 12]
        for index in range(4)
    )
    return (
        int.from_bytes(folded, "little") + (session_word if addend is None else addend)
    ) & 0xFFFFFFFF


def _hcnetsdk_command_port_local_ip_word(local_ip: str) -> bytes:
    try:
        return ipaddress.IPv4Address(local_ip).packed[::-1]
    except ipaddress.AddressValueError as err:
        raise PyEzvizError("HCNetSDK command-port local IP must be an IPv4 address") from err


def _local_sdk_aes_bytes(label: str, value: bytes | str) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else value
    if len(data) == EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        return data
    if isinstance(value, str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except binascii.Error:
            decoded = b""
        if len(decoded) == EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
            return decoded
    raise PyEzvizError(f"EZVIZ local SDK AES {label} must be 16 bytes")
