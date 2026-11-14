"""Synthetic length-delimited image envelopes; no camera data or credentials."""

from io import BytesIO
from struct import pack

from Crypto.Cipher import AES
from PIL import Image
import pytest

from pyezvizapi._shared.image_crypto import decrypt_image
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.devices.images import process_image_bytes
from pyezvizapi.exceptions import PyEzvizError

PASSWORD = "TESTONLY"

# Public, precomputed test-only protocol vectors; no runtime password hashing.
HASH_HEADERS = {
    "TESTONLY": b"ac837ab144ae11d771426037bf46479e",
    "OTHER": b"bd661a48d4043d7c583bc1c3aee5f523",
}
PREFIX = b"mutichhikpic\x00\x01"


def jpeg(size):
    with BytesIO() as buf, Image.new("RGB", size, (20, 60, 90)) as image:
        image.save(buf, format="JPEG")
        return buf.getvalue()


def encrypt(plain, password=PASSWORD):
    password_hash = HASH_HEADERS[password]
    key = password.ljust(16, "\x00")[:16].encode()
    iv = b"01234567" + b"\x00" * 8
    padding = 16 - len(plain) % 16
    cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(plain + bytes([padding]) * padding)
    return HIK_ENCRYPTION_HEADER + password_hash + cipher


def record(block, trailer=b"\x00" * 6, metadata=b"\x00\x01\x00\x00"):
    return metadata + pack(">II", 4 + len(block) + len(trailer), len(block)) + block + trailer


@pytest.mark.parametrize("sizes", [[(16, 8)], [(16, 8), (12, 10)], [(8, 8), (10, 12), (6, 4)]])
@pytest.mark.parametrize("trailer", [b"", b"\x00" * 6, b"opaque" * 4])
def test_declared_extents_decrypt_all_frames_and_select_each_lens(sizes, trailer):
    plains = [jpeg(size) for size in sizes]
    records = [
        record(encrypt(plain), trailer, pack(">I", index + 1)) for index, plain in enumerate(plains)
    ]
    payload = PREFIX + b"".join(records)
    result = decrypt_image(payload, PASSWORD)
    assert result == b"".join(plains)
    for index, (plain, size) in enumerate(zip(plains, sizes, strict=True), 1):
        selected = process_image_bytes(payload, PASSWORD, index, len(plains))
        assert selected == plain
        with Image.open(BytesIO(selected)) as decoded:
            decoded.load()
            decoded_size = decoded.size
        assert decoded_size == size


def test_unknown_outer_suffix_and_record_metadata_are_not_frame_counts():
    blocks = [encrypt(b"first"), encrypt(b"second")]
    payload = (
        PREFIX[:12] + b"\x81\xfe" + b"".join(record(block, b"opaque", b"meta") for block in blocks)
    )
    expected = b"firstsecond"
    assert decrypt_image(payload, PASSWORD) == expected


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize(
    "field,value", [(4, 0), (4, 3), (4, 0xFFFFFFFF), (8, 0), (8, 49), (8, 0xFFFFFFFF)]
)
def test_bad_record_lengths_fail_without_partial_success(which, field, value):
    blocks = [encrypt(b"one"), encrypt(b"two")]
    records = [bytearray(record(block)) for block in blocks]
    records[which][field : field + 4] = pack(">I", value)
    with pytest.raises(PyEzvizError):
        decrypt_image(PREFIX + b"".join(records), PASSWORD)


@pytest.mark.parametrize("cut", [0, 1, 2, 8, 11, 12, 20, 60, 75, 76, 77, 81])
def test_recognized_envelope_never_falls_back_to_magic_scanning_when_truncated(cut):
    payload = PREFIX + record(encrypt(b"one"))
    with pytest.raises(PyEzvizError):
        decrypt_image(payload[: len(PREFIX) + cut], PASSWORD)


@pytest.mark.parametrize("mutation", ["magic", "alignment", "overlap", "padding", "tail"])
def test_structural_and_crypto_corruption_remains_fatal(mutation):
    block = bytearray(encrypt(b"private synthetic bytes"))
    if mutation == "magic":
        block[0] ^= 1
    if mutation == "alignment":
        block.append(0)
    if mutation == "padding":
        # Deterministically damage final padding through the previous CBC block.
        block[-17] ^= 1
    payload = bytearray(PREFIX + record(block))
    if mutation == "overlap":
        payload[18:22] = pack(">I", 4 + len(block) - 1)
    if mutation == "tail":
        payload.extend(b"unframed tail")
    with pytest.raises(PyEzvizError):
        decrypt_image(bytes(payload), PASSWORD)


def test_invalid_password_in_second_frame_is_not_ignored():
    payload = PREFIX + record(encrypt(b"one")) + record(encrypt(b"two", "OTHER"))
    with pytest.raises(PyEzvizError, match="Invalid password"):
        decrypt_image(payload, PASSWORD)


def test_legacy_raw_concatenation_and_arbitrary_preamble_are_unchanged():
    first, second = encrypt(b"one"), encrypt(b"two")
    expected = b"onetwo"
    assert decrypt_image(b"legacy preamble" + first + second, PASSWORD) == expected


def test_encryption_magic_inside_ciphertext_is_not_a_record_boundary():
    # Construct an AES block whose ciphertext is the magic itself. Everything
    # here uses the public synthetic test key; no captured image is involved.
    key = PASSWORD.ljust(16, "\x00").encode()
    first_cipher = HIK_ENCRYPTION_HEADER
    padding_plain = bytes([16]) * 16
    second_cipher = AES.new(key, AES.MODE_CBC, first_cipher).encrypt(padding_plain)
    first_plain = AES.new(key, AES.MODE_CBC, b"01234567" + b"\x00" * 8).decrypt(first_cipher)
    hash_header = encrypt(b"")[:48]
    framed = PREFIX + record(hash_header + first_cipher + second_cipher)
    assert decrypt_image(framed, PASSWORD) == first_plain


def test_encryption_magic_inside_opaque_trailer_is_not_decrypted():
    expected = b"one"
    trailer = HIK_ENCRYPTION_HEADER + b"0" * 32 + b"x" * 16
    assert decrypt_image(PREFIX + record(encrypt(expected), trailer), PASSWORD) == expected
