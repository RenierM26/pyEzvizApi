"""EZVIZ concatenated JPEG and vertically stacked multi-lens image handling.

Requires the ``images`` extra. Call CPU-bound decoding from a worker in async apps.
"""

from io import BytesIO
import logging

from PIL import Image as PilImage, UnidentifiedImageError

from pyezvizapi.utils import decrypt_image

_LOGGER = logging.getLogger(__name__)
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"


def process_image_bytes(
    image_data: bytes, password: str | None, lens_index: int, lens_total: int
) -> bytes:
    """Pure worker-side decryption, JPEG scanning, decoding and lens cropping."""
    if not password:
        return image_data
    decrypted = decrypt_image(image_data, password)
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

    try:
        img = PilImage.open(BytesIO(image_data))
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
        cropped = img.crop((0, top, width, bottom))
        with BytesIO() as buf:
            cropped.save(buf, format="JPEG", quality=90)
            segments.append(buf.getvalue())

    return segments or [image_data]
