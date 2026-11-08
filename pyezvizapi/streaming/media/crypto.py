"""Native media AES key normalization and AAC block transform.

ECB is mandated by the camera format, not a general encryption API.
"""

from __future__ import annotations

from Crypto.Cipher import AES


def media_aes_key(media_key: str | bytes) -> bytes:
    key_bytes = media_key.encode() if isinstance(media_key, str) else media_key
    return key_bytes.ljust(16, b"\0")[:16]


def decrypt_aac_access_unit(access_unit: bytes, aes_key: bytes) -> bytes:
    decrypt_length = len(access_unit) - len(access_unit) % AES.block_size
    if decrypt_length == 0:
        return access_unit
    cipher = AES.new(aes_key, AES.MODE_ECB)  # codeql[py/weak-cryptographic-algorithm]
    decrypted_prefix = cipher.decrypt(
        access_unit[:decrypt_length]
    )  # codeql[py/weak-cryptographic-algorithm] lgtm[py/weak-cryptographic-algorithm]
    return decrypted_prefix + access_unit[decrypt_length:]
