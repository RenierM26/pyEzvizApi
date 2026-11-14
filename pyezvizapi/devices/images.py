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


def extract_jpeg_segments(image_data: bytes) -> list[bytes]:
    """Extract individual JPEG segments from a concatenated payload."""
    segments: list[bytes] = []
    cursor = image_data.find(JPEG_SOI)

    while cursor != -1:
        next_soi = image_data.find(JPEG_SOI, cursor + 2)
        eoi = image_data.find(JPEG_EOI, cursor + 2)

        if eoi != -1 and (next_soi == -1 or eoi < next_soi):
            end = eoi + 2
        elif next_soi != -1:
            end = next_soi
        elif eoi != -1:
            end = eoi + 2
        else:
            end = len(image_data)

        segment = image_data[cursor:end]
        segments.append(segment)

        if next_soi == -1:
            break
        cursor = next_soi

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
