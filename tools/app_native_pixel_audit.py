"""Audit private native planar snapshots across the observed bottom-only crop.

No decode, colour-order inference, playback, camera access or capture mutation.
The JSONL map is caller-supplied provenance, not an authenticated trace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys
from typing import Any, BinaryIO

SOURCE = runpy.run_path(str(Path(__file__).with_name('app_aac_decode.py')))
HEADER_WORDS = 49
MAX_DIMENSION = 4096
MAX_PIXELS = 8_388_608
MAX_SAMPLES = 32
MAX_LINE = 8192
MAX_TOTAL_BYTES = 256 * 1024 * 1024
UINT32 = 2**32


def header(value: Any) -> list[int]:
    """Require the complete observed 0xc4-byte native descriptor."""
    if (not isinstance(value, list) or len(value) != HEADER_WORDS
            or any(type(word) is not int or not 0 <= word < UINT32 for word in value)):
        raise ValueError('requires 49 uint32 native header words')
    return value


def geometry(before: list[int], after: list[int]) -> tuple[int, int, int]:
    """Support only the measured two-track software planar, bottom-crop case."""
    width, height = before[37:39]
    bottom, left, right, top = before[39:43]
    visible = height - bottom
    if (before[0] != 3 or before[1] not in (224, 225) or before[33:36] != [133, 3, 2]
            or before[3:5] != [width, height] or any((left, right, top))
            or not 0 < width <= MAX_DIMENSION or not 0 < height <= MAX_DIMENSION
            or width % 2 or height % 2 or bottom % 2 or not 0 <= bottom < height
            or width * height > MAX_PIXELS):
        raise ValueError('unsupported native planar header or bottom-only crop geometry')
    expected = list(before)
    expected[4] = visible
    if after != expected:
        raise ValueError('render header must preserve every word except cropped height')
    return width, height, visible


def verify(row: dict[str, Any], source: bytes, rendered: bytes) -> dict[str, Any]:
    """Compare ordered planes without assigning U/V meaning to chroma bytes."""
    before, after = header(row.get('input_header')), header(row.get('render_header'))
    width, height, visible = geometry(before, after)
    if len(source) != width * height * 3 // 2 or len(rendered) != width * visible * 3 // 2:
        raise ValueError('native snapshot byte length does not match header geometry')
    for key, data in [('input_sha256', source), ('render_sha256', rendered)]:
        if row.get(key) != hashlib.sha256(data).hexdigest():
            raise ValueError(f'native snapshot digest mismatch: {key}')
    coded_y, visible_y = width * height, width * visible
    source_planes = (source[:visible_y], source[coded_y:coded_y + visible_y // 4],
                     source[coded_y * 5 // 4:coded_y * 5 // 4 + visible_y // 4])
    rendered_planes = (rendered[:visible_y], rendered[visible_y:visible_y * 5 // 4],
                       rendered[visible_y * 5 // 4:])
    if source_planes != rendered_planes:
        raise ValueError('native render bytes differ from ordered planar bottom crop')
    return dict(id=row['id'], lens=before[1] - 224, frame_index=before[10],
                raw_timestamp=before[7], media_ms=before[5], width=width,
                coded_height=height, visible_height=visible, bottom_rows=height - visible,
                input_sha256=row['input_sha256'], render_sha256=row['render_sha256'],
                ordered_plane_sha256=[hashlib.sha256(p).hexdigest() for p in rendered_planes])


def audit(source: BinaryIO, rendered: BinaryIO, manifest: BinaryIO) -> dict[str, Any]:
    """Require contiguous complete snapshot coverage; never select trace-named paths."""
    offsets = [0, 0]
    rows: list[dict[str, Any]] = []
    identities = set()
    for _ in range(MAX_SAMPLES + 1):
        line = manifest.readline(MAX_LINE + 1)
        if not line:
            break
        if len(line) > MAX_LINE or len(rows) >= MAX_SAMPLES:
            raise ValueError('native sample manifest limit exceeded')
        row = json.loads(line)
        if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                or not 0 < len(row['id']) <= 128 or row['id'] in identities):
            raise ValueError('requires unique bounded sample identity')
        before, after = header(row.get('input_header')), header(row.get('render_header'))
        width, height, visible = geometry(before, after)
        lengths = [width * height * 3 // 2, width * visible * 3 // 2]
        for index, key in enumerate(('input_offset', 'render_offset')):
            if type(row.get(key)) is not int or row[key] != offsets[index]:
                raise ValueError('snapshot offsets must provide contiguous complete coverage')
        if sum(offsets) + sum(lengths) > MAX_TOTAL_BYTES:
            raise ValueError('native snapshot total byte limit exceeded')
        rows.append(verify(row, source.read(lengths[0]), rendered.read(lengths[1])))
        identities.add(row['id'])
        offsets = [offset + length for offset, length in zip(offsets, lengths, strict=True)]
    if not rows or source.read(1) or rendered.read(1):
        raise ValueError('requires nonempty complete native snapshot coverage')
    return dict(mode='native-bottom-crop-audit', samples=rows, samples_verified=len(rows),
                input_bytes=offsets[0], render_bytes=offsets[1],
                exact_ordered_plane_crop_verified=True, chroma_order_verified=False,
                provenance='caller-manifest-not-authenticated',
                physical_display_verified=False, decoder_buffer_ownership_verified=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_snapshots', type=Path)
    parser.add_argument('render_snapshots', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    try:
        with (SOURCE['open_source'](args.input_snapshots) as source,
              SOURCE['open_source'](args.render_snapshots) as rendered,
              SOURCE['open_source'](args.manifest) as manifest):
            report = audit(source, rendered, manifest)
        print(json.dumps(report, sort_keys=True))
    except (OSError, ValueError, TypeError) as error:
        print(f'native pixel audit failed: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
