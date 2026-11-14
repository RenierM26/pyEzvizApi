"""App-backed image variants, using only public synthetic keys and images."""

from dataclasses import FrozenInstanceError
from io import BytesIO
from random import Random
from struct import pack
from types import SimpleNamespace

from Crypto.Cipher import AES
from PIL import Image
import pytest

from pyezvizapi._shared.image_crypto import ImageKeyMode, decrypt_image, decrypt_image_block
from pyezvizapi._shared.image_records import parse_image_envelope
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.devices import images
from pyezvizapi.devices.images import decode_image_records, process_image_bytes
from pyezvizapi.exceptions import PyEzvizError

PASSWORD = "TESTONLY"
HEX_KEY = "0123456789abcdef0123456789abcdef"
HASHES = {
    PASSWORD: b"ac837ab144ae11d771426037bf46479e",
    "OTHER": b"bd661a48d4043d7c583bc1c3aee5f523",
    "éTEST": b"8081f274b7aeb7c41896833659d622f9",
    "é" * 9: b"3eabe3c506a5ffd7a434d869aac0d19d",
    "123456789012345é": b"bd2373b13a2c35d6d5440650a55f3a6c",
    HEX_KEY: b"d9595af1b3f9f4cced7155ca07069801",
}
KINDS = ("mutichhikpic", "hikpic", "hiklittlepic", "mutichhiklit")


def jpeg(size=(12, 8)):
    with BytesIO() as output, Image.new("RGB", size, (20, 80, 100)) as image:
        image.save(output, format="JPEG")
        return output.getvalue()


@pytest.fixture(scope="module")
def png_with_jpeg_markers():
    # Fixed synthetic pixels, not cryptographic randomness or private imagery.
    pixels = Random(0).randbytes(256 * 256 * 3)
    with Image.frombytes("RGB", (256, 256), pixels) as image, BytesIO() as output:
        image.save(output, format="PNG")
        payload = output.getvalue()
    assert payload.find(b"\xff\xd8") > 0
    return payload


def encrypt(plain, key=PASSWORD, mode=ImageKeyMode.TEXT):
    raw_key = bytes.fromhex(key) if mode is ImageKeyMode.HEX else key.encode()[:16].ljust(16, b"\0")
    header = (
        b"opaque-raw-header"[:16] + b"x" * 32
        if mode is ImageKeyMode.HEX
        else HIK_ENCRYPTION_HEADER + HASHES[key]
    )
    padding = 16 - len(plain) % 16
    return header + AES.new(raw_key, AES.MODE_CBC, b"01234567" + b"\0" * 8).encrypt(
        plain + bytes([padding]) * padding
    )


def auxiliary(data=b"opaque auxiliary"):
    return pack(">HI", 0x8042, len(data)) + data


def envelope(kind, blocks, channels=None, *, version=None, trailer=b"opaque trailer"):
    channels = channels or list(range(1, len(blocks) + 1))
    if kind == "hikpic":
        assert len(blocks) == 1
        version = 2 if version is None else version
        return (
            b"hikpic"
            + pack(">HB I", version, 42, len(blocks[0]))
            + blocks[0]
            + (auxiliary(trailer) if version == 2 else b"")
        )
    if kind == "mutichhikpic":
        return b"mutichhikpic\x81\xfe" + b"".join(
            pack(">HHII", channel, 0xCAFE, 4 + len(block) + len(trailer), len(block))
            + block
            + trailer
            for channel, block in zip(channels, blocks, strict=True)
        )
    if kind == "hiklittlepic":
        version = 3 if version is None else version
        return (
            b"hiklittlepic"
            + pack(">H", version)
            + b"".join(
                pack(">IHI", 0xCAFE0000, channel, len(block))
                + block
                + (auxiliary(trailer) if version == 3 else b"")
                for channel, block in zip(channels, blocks, strict=True)
            )
        )
    assert kind == "mutichhiklit"
    return (
        b"mutichhiklitOPAQUE"
        + pack(">H", 7)
        + b"".join(
            pack(">HHII", 0xCAFE, channel, 0xFFFFFFFF, len(block)) + block + auxiliary(trailer)
            for channel, block in zip(channels, blocks, strict=True)
        )
    )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", [None, ImageKeyMode.TEXT, ImageKeyMode.HEX])
@pytest.mark.parametrize("trailer", [b"", b"\0" * 6, HIK_ENCRYPTION_HEADER + b"not ciphertext"])
def test_clear_text_and_explicit_hex_envelopes(kind, mode, trailer):
    plain = jpeg()
    key = HEX_KEY if mode is ImageKeyMode.HEX else PASSWORD
    block = encrypt(plain, key, mode) if mode else plain
    payload = envelope(kind, [block], trailer=trailer)
    options = {"key_mode": mode} if mode else {}
    records = decode_image_records(payload, key if mode else None, **options)
    assert len(records) == 1
    assert records[0].image_data == plain
    assert records[0].envelope == kind
    assert records[0].channel_id == (None if kind == "hikpic" else 1)
    assert records[0].trailer == (trailer if kind == "mutichhikpic" else auxiliary(trailer))
    assert process_image_bytes(payload, key if mode else None, 1, 1, **options) == plain


@pytest.mark.parametrize(
    "kind,version", [("hikpic", 1), ("hikpic", 9), ("hiklittlepic", 1), ("hiklittlepic", 9)]
)
def test_versions_without_auxiliary_data(kind, version):
    plain = jpeg()
    record = decode_image_records(envelope(kind, [plain], version=version))[0]
    assert record.image_data == plain
    assert not record.trailer
    assert record.version == version


@pytest.mark.parametrize("kind", KINDS)
def test_every_recognized_prefix_truncation_fails(kind):
    payload = envelope(kind, [encrypt(jpeg())])
    # Every strict prefix after complete magic must fail; never return partial images.
    for end in range(len(kind), len(payload)):
        with pytest.raises(PyEzvizError):
            decode_image_records(payload[:end], PASSWORD)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("size", [0, 0xFFFFFFFF])
def test_invalid_declared_block_length(kind, size):
    payload = bytearray(envelope(kind, [jpeg()]))
    offset = {"hikpic": 9, "mutichhikpic": 22, "hiklittlepic": 20, "mutichhiklit": 28}[kind]
    payload[offset : offset + 4] = pack(">I", size)
    with pytest.raises(PyEzvizError):
        decode_image_records(bytes(payload))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("damage", ["magic", "padding", "alignment", "tail"])
def test_damaged_encrypted_records_never_return_ciphertext(kind, damage):
    block = bytearray(encrypt(jpeg()))
    if damage == "magic":
        block[0] ^= 1
    elif damage == "padding":
        block[-17] ^= 1
    elif damage == "alignment":
        block.append(0)
    payload = envelope(kind, [bytes(block)]) + (b"unframed" if damage == "tail" else b"")
    with pytest.raises(PyEzvizError):
        decode_image_records(payload, PASSWORD)


@pytest.mark.parametrize("kind", ["mutichhikpic", "hiklittlepic", "mutichhiklit"])
def test_sparse_repeated_channels_retain_order_and_require_exact_selection(kind):
    plains = [jpeg((8, 8)), jpeg((10, 8)), jpeg((12, 8))]
    payload = envelope(kind, plains, [9, 2, 9])
    records = decode_image_records(payload)
    assert [record.channel_id for record in records] == [9, 2, 9]
    assert [record.image_data for record in records] == plains
    assert process_image_bytes(payload, None, 9, 2) == plains[0]
    assert process_image_bytes(payload, None, 9, 2, image_index=1) == plains[2]
    assert process_image_bytes(payload, None, 2, 2) == plains[1]
    for channel, occurrence in ((1, 0), (9, 2), (2, 1)):
        with pytest.raises(PyEzvizError, match="not present"):
            process_image_bytes(payload, None, channel, 2, image_index=occurrence)


def test_unknown_channel_zero_keeps_positional_compatibility():
    first, second = jpeg((8, 8)), jpeg((10, 8))
    payload = envelope("mutichhikpic", [first, second], [0, 0])
    assert process_image_bytes(payload, None, 2, 2) == second
    assert decode_image_records(payload)[0].version is None


def test_clear_concatenation_and_composite_need_no_key():
    first, second = jpeg((8, 8)), jpeg((10, 8))
    assert process_image_bytes(first + second, None, 2, 2) == second
    assert [record.image_data for record in decode_image_records(first + second)] == [first, second]
    with Image.open(BytesIO(process_image_bytes(jpeg((10, 16)), None, 2, 2))) as image:
        size = image.size
    assert size == (10, 8)


@pytest.mark.parametrize("key", [PASSWORD, "éTEST", "é" * 9, "123456789012345é"])
def test_text_keys_are_encoded_then_sized_to_sixteen_bytes(key):
    plain = jpeg()
    encrypted = encrypt(plain, key)
    assert decrypt_image(encrypted, key) == plain
    assert decrypt_image_block(encrypted, key) == plain
    assert decode_image_records(envelope("hikpic", [encrypted]), key)[0].image_data == plain


def test_explicit_candidates_match_each_frame_without_replacing_current_key():
    first, second = jpeg((8, 8)), jpeg((10, 8))
    payload = envelope("hiklittlepic", [encrypt(first), encrypt(second, "OTHER")])
    records = decode_image_records(
        payload, "wrong current key", key_candidates=[PASSWORD, "OTHER", PASSWORD]
    )
    assert [record.image_data for record in records] == [first, second]
    with pytest.raises(PyEzvizError, match="matches"):
        decode_image_records(payload, PASSWORD)


def test_raw_concatenated_candidates_are_matched_per_legacy_block():
    first, second = jpeg((8, 8)), jpeg((10, 8))
    payload = b"preamble" + encrypt(first) + encrypt(second, "OTHER")
    assert [
        record.image_data
        for record in decode_image_records(payload, key_candidates=[PASSWORD, "OTHER"])
    ] == [first, second]


@pytest.mark.parametrize("candidates", ["TESTONLY", b"TESTONLY", [None], [123], [""]])
def test_invalid_candidate_inputs_raise_sanitized_errors(candidates):
    with pytest.raises(PyEzvizError):
        decode_image_records(envelope("hikpic", [encrypt(jpeg())]), key_candidates=candidates)


@pytest.mark.parametrize("key", [None, "", "f" * 31, "f" * 33, "g" * 32, "aa " * 16])
def test_hex_requires_an_explicit_exact_raw_key(key):
    with pytest.raises(PyEzvizError, match=r"Hex image mode|nonempty"):
        decrypt_image_block(
            encrypt(jpeg(), HEX_KEY, ImageKeyMode.HEX), key, key_mode=ImageKeyMode.HEX
        )


def test_hex_does_not_silently_replace_text_derivation_or_try_candidates():
    plain = jpeg()
    encrypted = encrypt(plain, HEX_KEY)
    assert decrypt_image_block(encrypted, HEX_KEY) == plain
    with pytest.raises(PyEzvizError):
        decrypt_image_block(encrypted, HEX_KEY, key_mode=ImageKeyMode.HEX)
    with pytest.raises(PyEzvizError, match="exactly one"):
        decrypt_image_block(
            encrypted, HEX_KEY, key_mode=ImageKeyMode.HEX, key_candidates=[PASSWORD]
        )


def test_bounded_detection_footer_retained_but_not_in_display_image():
    plain, metadata = jpeg(), b"synthetic detection metadata"
    payload = plain + metadata + pack(">II", len(plain), len(metadata)) + b"$"
    for data in (payload, envelope("hikpic", [encrypt(payload)])):
        record = decode_image_records(data, PASSWORD)[0]
        assert record.image_data == plain
        assert record.detection_data == metadata
        assert metadata.decode() not in repr(record)
        assert plain.hex() not in repr(record)
        field_name = "channel_id"
        with pytest.raises(FrozenInstanceError):
            setattr(record, field_name, 9)
    assert process_image_bytes(envelope("hikpic", [encrypt(payload)]), PASSWORD, 1, 1) == plain


@pytest.mark.parametrize(
    "payload", [b"$", b"image" + pack(">II", 0, 5) + b"$", b"image" + pack(">II", 5, 100) + b"$"]
)
def test_bad_detection_footer_is_not_ignored(payload):
    with pytest.raises(PyEzvizError, match="footer"):
        decode_image_records(envelope("hikpic", [encrypt(payload)]), PASSWORD)


@pytest.mark.parametrize("data", [jpeg(), envelope("hikpic", [jpeg()])])
def test_occurrence_requires_channel_identity(data):
    with pytest.raises(PyEzvizError, match="channel-indexed"):
        process_image_bytes(data, None, 1, 1, image_index=1)


@pytest.mark.parametrize("indexes", [(0, 1, 0), (1, 0, 0), (1, 1, -1), (True, 1, 0), (1, 1, 0.5)])
def test_invalid_indexes_fail(indexes):
    with pytest.raises(PyEzvizError, match="integers"):
        process_image_bytes(jpeg(), None, indexes[0], indexes[1], image_index=indexes[2])


def client_with_image(monkeypatch, payload, *, lookup_allowed=False):
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    monkeypatch.setattr(client, "_http_request", lambda *a, **k: SimpleNamespace(content=payload))
    calls = []

    def key_lookup(*args, **kwargs):
        assert lookup_allowed, "must not fetch a key for clear data or caller-owned credentials"
        calls.append((args, kwargs))
        return PASSWORD

    monkeypatch.setattr(client, "get_cam_key", key_lookup)
    return client, calls


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("encrypted", [True, False])
def test_download_unpacks_envelopes_and_only_fetches_needed_keys(monkeypatch, kind, encrypted):
    plain = jpeg()
    payload = envelope(
        kind, [encrypt(plain) if encrypted else plain], trailer=HIK_ENCRYPTION_HEADER
    )
    client, calls = client_with_image(monkeypatch, payload, lookup_allowed=encrypted)
    assert client.download_alarm_image("https://image.example.test", "synthetic") == plain
    assert len(calls) == int(encrypted)
    assert client.download_alarm_image("https://image.example.test", decrypt=False) == payload


def test_download_candidates_and_hex_never_fetch_or_guess_keys(monkeypatch):
    plain = jpeg()
    client, calls = client_with_image(monkeypatch, envelope("hikpic", [encrypt(plain, "OTHER")]))
    assert (
        client.download_alarm_image(
            "https://image.example.test", key_candidates=(PASSWORD, "OTHER")
        )
        == plain
    )
    client, calls = client_with_image(
        monkeypatch, envelope("hikpic", [encrypt(plain, HEX_KEY, ImageKeyMode.HEX)])
    )
    assert (
        client.download_alarm_image(
            "https://image.example.test", encryption_key=HEX_KEY, key_mode=ImageKeyMode.HEX
        )
        == plain
    )
    with pytest.raises(PyEzvizError):
        client.download_alarm_image(
            "https://image.example.test", "synthetic", key_mode=ImageKeyMode.HEX
        )
    assert not calls


def test_unknown_formats_are_not_claimed_as_envelopes():
    assert parse_image_envelope(b"unrelated") is None


@pytest.mark.parametrize("kind", ["hiklittlepic", "mutichhiklit"])
def test_malformed_later_record_cannot_return_partial_success(kind):
    payload = envelope(kind, [encrypt(jpeg()), encrypt(jpeg(), "OTHER")])
    with pytest.raises(PyEzvizError):
        decode_image_records(payload, PASSWORD)
    with pytest.raises(PyEzvizError):
        decode_image_records(payload[:-1], PASSWORD, key_candidates=["OTHER"])


@pytest.mark.parametrize("kind", KINDS)
def test_valid_padding_on_nonimage_plaintext_does_not_make_it_an_image(kind):
    with pytest.raises(PyEzvizError, match="decoded image"):
        decode_image_records(envelope(kind, [encrypt(b"not an image")]), PASSWORD)


def test_clear_jpeg_metadata_magic_does_not_trigger_decryption_or_key_lookup(monkeypatch):
    plain = jpeg()
    metadata = HIK_ENCRYPTION_HEADER + b"0" * 64
    plain = plain[:2] + b"\xff\xe1" + pack(">H", len(metadata) + 2) + metadata + plain[2:]
    assert decode_image_records(plain)[0].image_data == plain
    assert process_image_bytes(plain, PASSWORD, 1, 1) == plain
    client, calls = client_with_image(monkeypatch, plain)
    assert client.download_alarm_image("https://image.example.test") == plain
    assert not calls


def test_legacy_processing_hook_still_observes_clear_images_with_a_key(monkeypatch):
    plain, calls = jpeg(), []
    original = images.decrypt_image

    def observed(data, key):
        calls.append(data)
        return original(data, key)

    monkeypatch.setattr(images, "decrypt_image", observed)
    assert process_image_bytes(plain, PASSWORD, 1, 1) == plain
    assert calls == [plain]


@pytest.mark.parametrize("kind", [*KINDS, "raw"])
def test_clear_images_bypass_configured_hex_mode_without_any_key(monkeypatch, kind):
    plain = jpeg()
    payload = plain if kind == "raw" else envelope(kind, [plain])
    assert decode_image_records(payload, key_mode=ImageKeyMode.HEX)[0].image_data == plain
    assert process_image_bytes(payload, None, 1, 1, key_mode=ImageKeyMode.HEX) == plain
    client, calls = client_with_image(monkeypatch, payload)
    assert (
        client.download_alarm_image("https://image.example.test", key_mode=ImageKeyMode.HEX)
        == plain
    )
    assert not calls


@pytest.mark.parametrize("kind", ["mutichhikpic", "hiklittlepic", "mutichhiklit"])
@pytest.mark.parametrize("mode,key", [(ImageKeyMode.TEXT, PASSWORD), (ImageKeyMode.HEX, HEX_KEY)])
def test_mixed_clear_and_encrypted_records_use_keys_only_where_needed(monkeypatch, kind, mode, key):
    first, second = jpeg((8, 8)), jpeg((10, 8))
    payload = envelope(kind, [first, encrypt(second, key, mode)])
    assert [record.image_data for record in decode_image_records(payload, key, key_mode=mode)] == [
        first,
        second,
    ]
    client, calls = client_with_image(monkeypatch, payload)
    assert (
        client.download_alarm_image("https://image.example.test", encryption_key=key, key_mode=mode)
        == first + second
    )
    assert not calls


@pytest.mark.parametrize("kind", [*KINDS, "raw"])
@pytest.mark.parametrize(
    "encrypted,key,mode",
    [
        (False, None, ImageKeyMode.TEXT),
        (False, PASSWORD, ImageKeyMode.TEXT),
        (False, None, ImageKeyMode.HEX),
        (True, PASSWORD, ImageKeyMode.TEXT),
        (True, HEX_KEY, ImageKeyMode.HEX),
    ],
)
def test_png_pixel_bytes_are_not_jpeg_frame_boundaries(
    monkeypatch, png_with_jpeg_markers, kind, encrypted, key, mode
):
    plain = png_with_jpeg_markers
    block = encrypt(plain, key, mode) if encrypted else plain
    payload = block if kind == "raw" else envelope(kind, [block])
    records = decode_image_records(payload, key, key_mode=mode)
    assert len(records) == 1
    assert records[0].image_data == plain
    selected = process_image_bytes(payload, key, 1, 1, key_mode=mode)
    assert selected == plain
    with Image.open(BytesIO(selected)) as image:
        image.load()
        size, image_format = image.size, image.format
    assert size == (256, 256)
    assert image_format == "PNG"
    client, _ = client_with_image(monkeypatch, payload)
    assert (
        client.download_alarm_image("https://image.example.test", encryption_key=key, key_mode=mode)
        == plain
    )


@pytest.mark.parametrize("kind", ["mutichhikpic", "hiklittlepic", "mutichhiklit"])
def test_png_and_jpeg_records_keep_formats_and_channel_identity(png_with_jpeg_markers, kind):
    plain, other = png_with_jpeg_markers, jpeg()
    payload = envelope(kind, [encrypt(plain), encrypt(other)], [9, 2])
    records = decode_image_records(payload, PASSWORD)
    assert [(record.channel_id, record.image_data) for record in records] == [
        (9, plain),
        (2, other),
    ]
    assert process_image_bytes(payload, PASSWORD, 9, 2) == plain
    assert process_image_bytes(payload, PASSWORD, 2, 2) == other


@pytest.mark.parametrize("image_mode", ["RGBA", "P"])
@pytest.mark.parametrize("kind", ["raw", "hikpic", "unindexed-multi"])
@pytest.mark.parametrize("password", [None, PASSWORD])
def test_nonjpeg_images_are_not_guessed_to_be_jpeg_composites(image_mode, kind, password):
    with Image.new(image_mode, (16, 16)) as image, BytesIO() as output:
        image.save(output, format="PNG")
        plain = output.getvalue()
    if kind == "raw":
        payload = plain
    elif kind == "hikpic":
        payload = envelope(kind, [plain])
    else:
        payload = envelope("mutichhikpic", [plain], [0])
    for lens in (1, 2):
        assert process_image_bytes(payload, password, lens, 2) == plain


def test_unsupported_key_mode_fails(monkeypatch):
    plain = jpeg()
    with pytest.raises(PyEzvizError, match="mode"):
        decode_image_records(plain, key_mode="unknown")
    with pytest.raises(PyEzvizError, match="mode"):
        process_image_bytes(plain, None, 1, 1, key_mode="unknown")
    client, _ = client_with_image(monkeypatch, plain)
    with pytest.raises(PyEzvizError, match="mode"):
        client.download_alarm_image("https://image.example.test", key_mode="unknown")
