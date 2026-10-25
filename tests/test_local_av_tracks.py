"""Same-container identities, strict ambiguity checks and unmodified source indices."""
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_tracks.py'))
IDS = (0xE0, 0xE1, 0xC0)


def stream(index, pes, kind):
    return SimpleNamespace(index=index, id=0x100 | pes, type=kind)


@pytest.mark.parametrize('order', [(0, 1, 2), (0, 2, 1), (2, 1, 0)])
def test_resolve_actual_container_order_not_previous_recording(order):
    rows = [stream(order[0], 0xE0, 'video'), stream(order[1], 0xE1, 'video'), stream(order[2], 0xC0, 'audio')]
    result = M['resolve_pes_ids'](SimpleNamespace(streams=rows), IDS)
    assert result['video_indices'] == list(order[:2]) and result['audio_index'] == order[2]
    assert [r['demux_id'] for r in result['tracks']] == [0x1E0, 0x1E1, 0x1C0]
    assert [r['index'] for r in result['tracks']] == list(order)


@pytest.mark.parametrize('ids', [(0xE0, 0xE0, 0xC0), (True, 0xE1, 0xC0), (0xE0, 0xE1, 0xE2),
    (0x1E0, 0xE1, 0xC0), (0xE0, 0xE1), [0xE0, 0xE1, 0xC0], ('224', 0xE1, 0xC0)])
def test_invalid_explicit_ids_are_not_coerced(ids):
    with pytest.raises(ValueError):
        M['validate_pes_ids'](ids)


@pytest.mark.parametrize('failure', ['missing', 'duplicate', 'wrong-type', 'duplicate-index', 'boolean-index', 'masked-alias'])
def test_resolution_rejects_missing_ambiguous_or_invalid_identity(failure):
    rows = [stream(0, 0xE0, 'video'), stream(1, 0xE1, 'video'), stream(2, 0xC0, 'audio')]
    if failure == 'missing':
        rows.pop()
    if failure == 'duplicate':
        rows.append(stream(3, 0xE0, 'video'))
    if failure == 'wrong-type':
        rows[1].type = 'audio'
    if failure == 'duplicate-index':
        rows[1].index = 0
    if failure == 'boolean-index':
        rows[1].index = True
    if failure == 'masked-alias':
        rows[0].id = 0x2E0
    with pytest.raises(ValueError):
        M['resolve_pes_ids'](SimpleNamespace(streams=rows), IDS)
