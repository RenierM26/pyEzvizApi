"""Explicit MPEG-PS PES identities resolved only against the active demuxer."""
from __future__ import annotations

from typing import Any


def validate_pes_ids(ids: tuple[int, int, int]) -> None:
    """Accept two distinct video PES bytes and one audio PES byte, never guesses."""
    if (type(ids) is not tuple or len(ids) != 3 or any(type(n) is not int for n in ids)
            or not 0xE0 <= ids[0] <= 0xEF or not 0xE0 <= ids[1] <= 0xEF
            or ids[0] == ids[1] or not 0xC0 <= ids[2] <= 0xDF):
        raise ValueError('select two distinct video PES IDs and one audio PES ID')


def resolve_pes_ids(container: Any, ids: tuple[int, int, int]) -> dict[str, Any]:
    """FFmpeg MPEG-PS AVStream.id is 0x100 | PES stream byte; match exactly."""
    validate_pes_ids(ids)
    rows = []
    for pes, kind in zip(ids, ('video', 'video', 'audio'), strict=True):
        matches = [stream for stream in container.streams if stream.id == 0x100 | pes]
        if len(matches) != 1 or matches[0].type != kind:
            raise ValueError('missing, duplicate or wrong-type selected MPEG-PS identity')
        stream = matches[0]
        if type(stream.index) is not int or stream.index < 0:
            raise ValueError('invalid resolved absolute stream index')
        rows.append(dict(pes_id=pes, demux_id=stream.id, index=stream.index, type=kind))
    if len({row['index'] for row in rows}) != 3:
        raise ValueError('resolved stream indices must be distinct')
    return dict(mode='explicit-mpeg-pes-ids', requested_pes_ids=list(ids), tracks=rows,
                video_indices=[rows[0]['index'], rows[1]['index']], audio_index=rows[2]['index'])
