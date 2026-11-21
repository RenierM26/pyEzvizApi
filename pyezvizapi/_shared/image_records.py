"""Bounded app image envelopes and caller-owned image credentials (no Pillow)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from pyezvizapi._shared.image_crypto import (
    ImageKeyMode,
    _split_encrypted_blocks,
    decrypt_image,
    decrypt_image_block,
)
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.exceptions import PyEzvizError


@dataclass(frozen=True, slots=True)
class ImageRecord:
    """One ordered image; repeated/sparse channel IDs and metadata are retained."""

    image_data: bytes = field(repr=False)
    channel_id: int | None = None
    envelope: str = "raw"
    version: int | None = None
    record_header: bytes = field(default=b"", repr=False)
    trailer: bytes = field(default=b"", repr=False)
    detection_data: bytes = field(default=b"", repr=False)


def is_clear_image(data: bytes) -> bool:
    """Recognize a top-level clear image without searching its opaque metadata."""
    return data.startswith((b"\xff\xd8", b"\x89PNG\r\n\x1a\n"))


def is_image_envelope(data: bytes) -> bool:
    """Recognize only app-backed envelope prefixes, not embedded magic searches."""
    return data.startswith((b"mutichhikpic", b"mutichhiklit", b"hiklittlepic", b"hikpic"))


def _u(data: bytes, offset: int, size: int) -> int:
    if offset < 0 or offset + size > len(data):
        raise PyEzvizError("Invalid image envelope: truncated field")
    return int.from_bytes(data[offset : offset + size], "big")


def _window(data: bytes, start: int, size: int) -> bytes:
    if size <= 0 or start < 0 or start + size > len(data):
        raise PyEzvizError("Invalid image envelope: payload bounds")
    return data[start : start + size]


def _aux_end(data: bytes, start: int) -> int:
    # App datatype(u16) + length(u32); datatype remains opaque to the decoder.
    size = _u(data, start + 2, 4)
    end = start + 6 + size
    if end > len(data):
        raise PyEzvizError("Invalid image envelope: auxiliary bounds")
    return end


def parse_image_envelope(
    data: bytes, *, preserve_zero_channel: bool = False
) -> tuple[ImageRecord, ...] | None:
    """Parse encoded records; unknown formats return None, recognized errors fail."""
    if not is_image_envelope(data):
        return None
    if data.startswith(b"hikpic"):
        single_version = _u(data, 6, 2)
        size = _u(data, 9, 4)
        block = _window(data, 13, size)
        end = _aux_end(data, 13 + size) if single_version == 2 else 13 + size
        if end != len(data):
            raise PyEzvizError("Invalid image envelope: trailing single-image data")
        return (
            ImageRecord(
                block,
                envelope="hikpic",
                version=single_version,
                record_header=data[:13],
                trailer=data[13 + size : end],
            ),
        )
    if data.startswith(b"mutichhikpic"):
        kind, start, header, channel_offset = "mutichhikpic", 14, 12, 0
    elif data.startswith(b"mutichhiklit"):
        # The app recognizes 12 bytes then consumes six opaque continuation bytes.
        kind, start, header, channel_offset = "mutichhiklit", 20, 12, 2
    else:
        kind, start, header, channel_offset = "hiklittlepic", 14, 10, 4
    suffix = _u(data, start - 2, 2)
    # The outer suffix on this family is not established as a version field.
    version = None if kind == "mutichhikpic" else suffix
    records: list[ImageRecord] = []
    cursor = start
    while cursor < len(data):
        size = _u(data, cursor + header - 4, 4)
        block_start = cursor + header
        block = _window(data, block_start, size)
        block_end = block_start + size
        if kind == "mutichhikpic":
            end = cursor + 8 + _u(data, cursor + 4, 4)
            if end < block_end or end > len(data):
                raise PyEzvizError("Invalid image envelope: record bounds")
        elif kind == "mutichhiklit" or version == 3:
            end = _aux_end(data, block_end)
        else:
            end = block_end
        channel = _u(data, cursor + channel_offset, 2)
        records.append(
            ImageRecord(
                block,
                channel if preserve_zero_channel else channel or None,
                kind,
                version,
                data[cursor:block_start],
                data[block_end:end],
            )
        )
        cursor = end
    if not records:
        raise PyEzvizError("Invalid image envelope: no records")
    return tuple(records)


def _detection_footer(data: bytes) -> tuple[bytes, bytes]:
    if not data.endswith(b"$"):
        return data, b""
    if len(data) < 9:
        raise PyEzvizError("Invalid image detection footer")
    image_size, detection_size = _u(data, len(data) - 9, 4), _u(data, len(data) - 5, 4)
    if image_size <= 0 or image_size + detection_size != len(data) - 9:
        raise PyEzvizError("Invalid image detection footer bounds")
    return data[:image_size], data[image_size:-9]


def decode_image_records(
    image_data: bytes,
    password: str | None = None,
    *,
    key_mode: ImageKeyMode | str = ImageKeyMode.TEXT,
    key_candidates: Sequence[str] = (),
    preserve_zero_channel: bool = False,
) -> tuple[ImageRecord, ...]:
    """Unpack clear/encrypted app images without guessing keys or storing secrets."""
    try:
        mode = ImageKeyMode(key_mode)
    except ValueError as err:
        raise PyEzvizError("Unsupported image key mode") from err
    records = parse_image_envelope(image_data, preserve_zero_channel=preserve_zero_channel)
    if records is None:
        if not is_clear_image(image_data) and HIK_ENCRYPTION_HEADER in image_data:
            start = image_data.find(HIK_ENCRYPTION_HEADER)
            blocks = _split_encrypted_blocks(image_data[start:], len(HIK_ENCRYPTION_HEADER), 48)
            if not blocks:
                raise PyEzvizError("Invalid encrypted image payload")
            records = tuple(ImageRecord(block, envelope="legacy") for block in blocks)
        elif mode is ImageKeyMode.HEX and not is_clear_image(image_data):
            records = (ImageRecord(image_data, envelope="legacy"),)
        else:
            data, detection = _detection_footer(image_data)
            return (ImageRecord(data, detection_data=detection),)
    decoded: list[ImageRecord] = []
    for record in records:
        plain = record.image_data
        if not is_clear_image(plain) and (
            plain.startswith(HIK_ENCRYPTION_HEADER) or mode is ImageKeyMode.HEX
        ):
            if (
                record.envelope == "legacy"
                and mode is ImageKeyMode.TEXT
                and not key_candidates
                and password is not None
            ):
                plain = decrypt_image(plain, password)
            else:
                plain = decrypt_image_block(
                    plain, password, key_mode=mode, key_candidates=key_candidates
                )
        elif not is_clear_image(plain):
            raise PyEzvizError("Unrecognized image record payload")
        data, detection = _detection_footer(plain)
        if record.envelope != "legacy" and not is_clear_image(data):
            raise PyEzvizError("Unrecognized decoded image record payload")
        decoded.append(
            ImageRecord(
                data,
                record.channel_id,
                record.envelope,
                record.version,
                record.record_header,
                record.trailer,
                detection,
            )
        )
    return tuple(decoded)
