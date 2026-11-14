"""EZVIZ concatenated JPEG and vertically stacked multi-lens image handling.

Requires the ``images`` extra. Call CPU-bound decoding from a worker in async apps.
"""

from collections.abc import Sequence
from contextlib import ExitStack, closing
from dataclasses import replace
from io import BytesIO
import logging

from PIL import Image as PilImage, UnidentifiedImageError

from pyezvizapi._shared.image_crypto import ImageKeyMode
from pyezvizapi._shared.image_records import (
    ImageRecord,
    decode_image_records as _decode_image_payload,
    is_clear_image,
    is_image_envelope,
)
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.utils import decrypt_image

_LOGGER = logging.getLogger(__name__)
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"


def decode_image_records(
    image_data: bytes,
    password: str | None = None,
    *,
    key_mode: ImageKeyMode | str = ImageKeyMode.TEXT,
    key_candidates: Sequence[str] = (),
) -> tuple[ImageRecord, ...]:
    """Return ordered, channel-aware decoded images and retained auxiliary data."""
    result: list[ImageRecord] = []
    for record in _decode_image_payload(
        image_data, password, key_mode=key_mode, key_candidates=key_candidates
    ):
        segments = extract_jpeg_segments(record.image_data)
        if segments:
            result.extend(replace(record, image_data=part) for part in segments)
        else:
            result.append(record)
    return tuple(result)


def process_image_bytes(
    image_data: bytes,
    password: str | None,
    lens_index: int,
    lens_total: int,
    *,
    key_mode: ImageKeyMode | str = ImageKeyMode.TEXT,
    key_candidates: Sequence[str] = (),
    image_index: int = 0,
) -> bytes:
    """Select an image without confusing channel identity with record position.

    Clear images are unpacked too. Existing unindexed raw JPEGs keep positional
    selection and composite cropping; indexed envelopes require the named channel.
    """
    if any(
        type(value) is not int or value < minimum
        for value, minimum in ((lens_index, 1), (lens_total, 1), (image_index, 0))
    ):
        raise PyEzvizError("Image indexes and lens count must be valid integers")
    try:
        mode = ImageKeyMode(key_mode)
    except ValueError as err:
        raise PyEzvizError("Unsupported image key mode") from err
    if is_image_envelope(image_data) or key_candidates or mode is ImageKeyMode.HEX:
        records = decode_image_records(
            image_data, password, key_mode=mode, key_candidates=key_candidates
        )
        if any(record.channel_id is not None for record in records):
            matches = [record for record in records if record.channel_id == lens_index]
            if image_index >= len(matches):
                raise PyEzvizError("Requested image channel or occurrence is not present")
            return matches[image_index].image_data
        if image_index:
            raise PyEzvizError("Image occurrence requires channel-indexed records")
        segments = [record.image_data for record in records]
    else:
        if image_index:
            raise PyEzvizError("Image occurrence requires channel-indexed records")
        # Keep this compatibility hook for callers instrumenting legacy decryption.
        decrypted = (
            decrypt_image(image_data, password)
            if password and not is_clear_image(image_data)
            else image_data
        )
        segments = extract_jpeg_segments(decrypted) or [decrypted]
    if len(segments) == 1 and lens_total > 1:
        segments = split_composite_image(segments[0], lens_total)
    return segments[min(lens_index - 1, len(segments) - 1)]


def _jpeg_frame_end(image_data: bytes, start: int) -> int:
    """Walk marker lengths, treating APP metadata and stuffed scan bytes as opaque."""
    cursor = start + 2
    size = len(image_data)
    while cursor < size:
        marker_start = image_data.find(b"\xff", cursor)
        if marker_start == -1:
            break
        cursor = marker_start + 1
        while cursor < size and image_data[cursor] == 0xFF:
            cursor += 1
        if cursor == size:
            break
        marker = image_data[cursor]
        cursor += 1
        if marker == 0xD9:
            return cursor
        if marker == 0xD8:
            # Tolerate a missing EOI before the next top-level frame.
            return marker_start
        if marker in (0x00, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if cursor + 2 > size:
            break
        length = int.from_bytes(image_data[cursor : cursor + 2], "big")
        if length < 2 or cursor + length > size:
            break
        # Includes SOS headers; subsequent scan data uses FF00 byte stuffing
        # and restart markers, handled above. Never search inside APP segments.
        cursor += length
    return size


def extract_jpeg_segments(image_data: bytes) -> list[bytes]:
    """Extract top-level JPEG frames without splitting embedded EXIF thumbnails."""
    segments: list[bytes] = []
    cursor = image_data.find(JPEG_SOI)
    while cursor != -1:
        end = _jpeg_frame_end(image_data, cursor)
        segments.append(image_data[cursor:end])
        cursor = image_data.find(JPEG_SOI, end)
    return segments


def split_composite_image(image_data: bytes, parts: int) -> list[bytes]:
    """Split a single JPEG containing multiple stacked views."""
    if parts <= 1:
        return [image_data]

    with ExitStack() as stack:
        try:
            img = stack.enter_context(closing(PilImage.open(BytesIO(image_data))))
            img.load()
        except (UnidentifiedImageError, OSError) as err:
            _LOGGER.debug("Unable to decode composite multi-lens snapshot: %s", err)
            return [image_data]

        width, height = img.size
        slice_height = max(1, height // parts)
        segments: list[bytes] = []

        for idx in range(parts):
            top = idx * slice_height
            bottom = height if idx == parts - 1 else (idx + 1) * slice_height
            with closing(img.crop((0, top, width, bottom))) as cropped, BytesIO() as buf:
                cropped.save(buf, format="JPEG", quality=90)
                segments.append(buf.getvalue())

        return segments or [image_data]
