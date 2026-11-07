"""Proprietary EZVIZ image envelope and CBC decryption."""

from __future__ import annotations

from hashlib import md5
import logging

from Crypto.Cipher import AES

from .constants import HIK_ENCRYPTION_HEADER
from .exceptions import PyEzvizError

_LOGGER = logging.getLogger("pyezvizapi.utils")


def decrypt_image(input_data: bytes, password: str) -> bytes:
    """Decrypts image data with provided password.

    Args:
        input_data (bytes): Encrypted image data
        password (string): Verification code

    Raises:
        PyEzvizError

    Returns:
        bytes: Decrypted image data

    """
    header_len = len(HIK_ENCRYPTION_HEADER)
    min_length = header_len + 32  # header + md5 hash

    if len(input_data) < min_length:
        raise PyEzvizError("Invalid image data")

    header_index = input_data.find(HIK_ENCRYPTION_HEADER)
    if header_index == -1:
        _LOGGER.debug("Image header doesn't contain %s", HIK_ENCRYPTION_HEADER)
        return input_data

    if header_index:
        _LOGGER.debug("Image header found at offset %s, trimming preamble", header_index)
        input_data = input_data[header_index:]
        if len(input_data) < min_length:
            raise PyEzvizError("Invalid image data after trimming preamble")

    hash_end = header_len + 32
    blocks = _split_encrypted_blocks(input_data, header_len, min_length)
    if not blocks:
        raise PyEzvizError("Invalid image data")

    decrypted_parts = [
        _decrypt_single_block(block, password, header_len, hash_end) for block in blocks
    ]
    if len(decrypted_parts) > 1:
        _LOGGER.debug("Decrypted %s concatenated image blocks", len(decrypted_parts))
    return b"".join(decrypted_parts)



def _split_encrypted_blocks(
    data: bytes, header_len: int, min_length: int
) -> list[bytes]:
    """Split concatenated hikencodepicture segments into individual blocks."""
    blocks: list[bytes] = []
    cursor = 0
    data_len = len(data)

    while cursor <= data_len - min_length:
        if data[cursor : cursor + header_len] != HIK_ENCRYPTION_HEADER:
            next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + 1)
            if next_header == -1:
                break
            cursor = next_header
            continue

        next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + header_len)
        block = data[cursor : next_header if next_header != -1 else data_len]
        if len(block) < min_length:
            break
        blocks.append(block)
        if next_header == -1:
            break
        cursor = next_header

    return blocks



def _decrypt_single_block(
    block: bytes, password: str, header_len: int, hash_end: int
) -> bytes:
    """Decrypt a single hikencodepicture block."""
    file_hash = block[header_len:hash_end]
    passwd_hash = md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()
    if file_hash != str.encode(passwd_hash):
        raise PyEzvizError("Invalid password")

    ciphertext = block[hash_end:]
    if not ciphertext:
        raise PyEzvizError("Missing ciphertext payload")

    remainder = len(ciphertext) % AES.block_size
    if remainder:
        _LOGGER.debug(
            "Ciphertext not aligned to 16 bytes; trimming %s trailing bytes", remainder
        )
        ciphertext = ciphertext[:-remainder]
    if not ciphertext:
        raise PyEzvizError("Ciphertext too short after alignment adjustment")

    key = str.encode(password.ljust(16, "\u0000")[:16])
    iv_code = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES.new(key, AES.MODE_CBC, iv_code)

    chunk_size = 1024 * AES.block_size
    output_data = bytearray()

    for start in range(0, len(ciphertext), chunk_size):
        block_chunk = cipher.decrypt(ciphertext[start : start + chunk_size])
        if start + chunk_size >= len(ciphertext):
            padding_length = block_chunk[-1]
            if not 1 <= padding_length <= AES.block_size or block_chunk[-padding_length:] != bytes([padding_length]) * padding_length:
                raise PyEzvizError("Invalid image padding")
            block_chunk = block_chunk[:-padding_length]
        output_data.extend(block_chunk)

    return bytes(output_data)



def return_password_hash(password: str) -> str:
    """Return the password hash."""
    return md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()

