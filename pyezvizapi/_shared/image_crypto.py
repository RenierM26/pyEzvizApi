"""Proprietary EZVIZ image envelope and CBC decryption."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from hashlib import md5
import logging

from Crypto.Cipher import AES

from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.exceptions import PyEzvizError

_LOGGER = logging.getLogger("pyezvizapi.utils")
_MULTI_IMAGE_MAGIC = b"mutichhikpic"
_MULTI_IMAGE_PREFIX_SIZE = 14
_MULTI_IMAGE_RECORD_SIZE = 12


class ImageKeyMode(StrEnum):
    """Explicit app credential representation; no automatic mode fallback."""

    TEXT = "text"
    HEX = "hex"


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

    # Length-delimited envelopes must retain their prefix until block splitting.
    # Searching/trimming at the first encryption magic loses record boundaries.
    if not input_data.startswith(_MULTI_IMAGE_MAGIC):
        if len(input_data) < min_length:
            raise PyEzvizError("Invalid image data")

        # Do not interpret encryption-like bytes inside a clear JPEG/PNG's
        # metadata as a legacy encrypted block. Keep the public decrypt hook.
        if input_data.startswith((b"\xff\xd8", b"\x89PNG\r\n\x1a\n")):
            return input_data

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


def _split_framed_images(data: bytes, header_len: int, min_length: int) -> list[bytes]:
    """Extract exact encrypted extents from a length-delimited multi-image envelope.

    The two outer suffix bytes, four record metadata bytes and length-bounded
    trailers are opaque. No frame-count, version or fixed trailer-size semantics
    are inferred from the observed format.
    """
    cursor = _MULTI_IMAGE_PREFIX_SIZE
    blocks: list[bytes] = []
    while cursor < len(data):
        if len(data) - cursor < _MULTI_IMAGE_RECORD_SIZE:
            raise PyEzvizError("Invalid multi-image framing: truncated record header")
        remaining = int.from_bytes(data[cursor + 4 : cursor + 8], "big")
        encrypted_len = int.from_bytes(data[cursor + 8 : cursor + 12], "big")
        block_start = cursor + _MULTI_IMAGE_RECORD_SIZE
        block_end = block_start + encrypted_len
        record_end = cursor + 8 + remaining
        if (
            encrypted_len < min_length + AES.block_size
            or (encrypted_len - min_length) % AES.block_size
        ):
            raise PyEzvizError("Invalid multi-image framing: encrypted block size")
        if record_end < block_end or record_end > len(data):
            raise PyEzvizError("Invalid multi-image framing: record bounds")
        if data[block_start : block_start + header_len] != HIK_ENCRYPTION_HEADER:
            raise PyEzvizError("Invalid multi-image framing: missing encryption header")
        blocks.append(data[block_start:block_end])
        cursor = record_end
    if not blocks:
        raise PyEzvizError("Invalid multi-image framing: missing records")
    return blocks


def _split_encrypted_blocks(data: bytes, header_len: int, min_length: int) -> list[bytes]:
    """Split length-delimited or legacy concatenated encryption blocks."""
    if data.startswith(_MULTI_IMAGE_MAGIC):
        return _split_framed_images(data, header_len, min_length)
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


def _decrypt_single_block(block: bytes, password: str, header_len: int, hash_end: int) -> bytes:
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
        _LOGGER.debug("Ciphertext not aligned to 16 bytes; trimming %s trailing bytes", remainder)
        ciphertext = ciphertext[:-remainder]
    if not ciphertext:
        raise PyEzvizError("Ciphertext too short after alignment adjustment")

    key = password.encode()[:16].ljust(16, b"\x00")
    return _decrypt_ciphertext(ciphertext, key)


def _decrypt_ciphertext(ciphertext: bytes, key: bytes) -> bytes:
    """CBC and strict PKCS7 common to text and explicit raw-key image modes."""
    iv_code = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES.new(key, AES.MODE_CBC, iv_code)

    chunk_size = 1024 * AES.block_size
    output_data = bytearray()

    for start in range(0, len(ciphertext), chunk_size):
        block_chunk = cipher.decrypt(ciphertext[start : start + chunk_size])
        if start + chunk_size >= len(ciphertext):
            padding_length = block_chunk[-1]
            if (
                not 1 <= padding_length <= AES.block_size
                or block_chunk[-padding_length:] != bytes([padding_length]) * padding_length
            ):
                raise PyEzvizError("Invalid image padding")
            block_chunk = block_chunk[:-padding_length]
        output_data.extend(block_chunk)

    return bytes(output_data)


def decrypt_image_block(
    block: bytes,
    password: str | None = None,
    *,
    key_mode: ImageKeyMode | str = ImageKeyMode.TEXT,
    key_candidates: Sequence[str] = (),
) -> bytes:
    """Decrypt an exact bounded record using explicit, caller-owned credentials."""
    if len(block) < 64 or (len(block) - 48) % AES.block_size:
        raise PyEzvizError("Invalid encrypted image block bounds")
    if isinstance(key_candidates, (str, bytes)):
        raise PyEzvizError("Image key candidates must be a sequence of keys")
    keys = ([password] if password is not None else []) + list(key_candidates)
    if any(not isinstance(key, str) or not key for key in keys):
        raise PyEzvizError("Image keys must be nonempty text")
    keys = list(dict.fromkeys(keys))
    try:
        mode = ImageKeyMode(key_mode)
    except ValueError as err:
        raise PyEzvizError("Unsupported image key mode") from err
    if mode is ImageKeyMode.HEX:
        if (
            len(keys) != 1
            or len(keys[0]) != 32
            or any(char not in "0123456789abcdefABCDEF" for char in keys[0])
        ):
            raise PyEzvizError("Hex image mode requires exactly one 16-byte hexadecimal key")
        return _decrypt_ciphertext(block[48:], bytes.fromhex(keys[0]))
    if not block.startswith(HIK_ENCRYPTION_HEADER):
        raise PyEzvizError("Invalid encrypted image header")
    for key in keys:
        if return_password_hash(key).encode() == block[16:48]:
            return _decrypt_ciphertext(block[48:], key.encode()[:16].ljust(16, b"\x00"))
    raise PyEzvizError("No supplied image key matches the image hash")


def return_password_hash(password: str) -> str:
    """Return the password hash."""
    return md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()
