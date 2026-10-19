"""Native outcome joins must not invent acceptance, causes, output or timing."""
import json
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).parents[1]
M = runpy.run_path(str(ROOT / 'tools/app_compressed_reference_health.py'))
H = M['H']


def entry(call, sid=224, frame=0, width=2880, at=10):
    meta = [0] * 58
    meta[10], meta[12], meta[13], meta[16], meta[19] = sid, width, 1624, 100 + frame, frame
    return dict(event='encoded_video', id=call, meta_words=meta, device_mono_ns=at)


def returned(call, result=0):
    return dict(event='encoded_video_return', id=call, result=result)


def test_id_join_handles_retries_interleaving_geometry_and_pending_boundary():
    rows = [entry(1), entry(2, sid=225), returned(2), returned(1),
        entry(3, sid=225, width=1920), returned(3),
        entry(4, sid=225, frame=1), returned(4, -24),
        entry(5, sid=225, frame=1), returned(5, -10),
        entry(6, sid=225, frame=2),  # Never classify an unreturned call as failure.
        dict(event='render_callback', device_mono_ns=8)]
    r = H['summarize'](rows)
    primary, secondary = r['tracks']
    assert primary['accepted'] == 1 and primary['trailing_completed_rejections'] == 0
    assert (secondary['accepted'], secondary['rejected'], secondary['pending']) == (2, 2, 1)
    assert secondary['trailing_completed_rejections'] == 2
    assert secondary['first_trailing_rejection']['call'] == 4
    assert secondary['last_accepted']['call'] == 3
    assert secondary['result_counts'] == {'0': 2, '-24': 1, '-10': 1}
    assert [e['width'] for e in secondary['geometry_epochs']] == [2880, 1920, 2880]
    assert r['selection_to_input_tail_ns'] == 2  # Device clock only, not media/output latency.
    assert r['error_cause_identified'] is r['physical_output_verified'] is False


def test_acceptance_resets_completed_rejection_suffix_without_frame_counter_ordering():
    r = H['summarize']([entry(1, frame=99), returned(1, -10),
                        entry(2, frame=0), returned(2)])['tracks'][0]
    assert r['rejected'] == 1 and r['trailing_completed_rejections'] == 0
    assert r['first_trailing_rejection'] is None and r['last_accepted']['frame'] == 0


def test_missing_selection_does_not_invent_zero_gap():
    r = H['summarize']([entry(1), returned(1)])
    assert r['paired_selection_count'] == 0 and r['selection_to_input_tail_ns'] is None


@pytest.mark.parametrize('rows,message', [
    ([entry(1), entry(1)], 'duplicate'),
    ([entry(1), returned(1), returned(1)], 'duplicate'),
    ([returned(1)], 'without captured input'),
    ([dict(entry(1), id=True)], 'invalid native call'),
    ([entry(1, sid=226)], 'unsupported native lens'),
    ([dict(entry(1), meta_words=[0])], 'invalid native metadata'),
    ([entry(1), returned(1, True)], 'invalid native result'),
    ([dict(entry(1), device_mono_ns=-1)], 'invalid input device time'),
    ([{}] * 20001, 'observation limit'),
])
def test_invalid_or_ambiguous_metadata_fails(rows, message):
    with pytest.raises(ValueError, match=message):
        H['summarize'](rows)


def test_file_analysis_needs_no_media_files(tmp_path):
    events = tmp_path / 'events.jsonl'
    events.write_text('\n'.join(json.dumps(r) for r in [entry(1), returned(1)]) + '\n')
    assert M['analyze'](events)['tracks'][0]['accepted'] == 1
    assert list(tmp_path.iterdir()) == [events]


@pytest.mark.parametrize('content', [b' ' * 8193, b'{}\n' * 20001, b'[]\n'])
def test_file_bounds_and_object_contract(tmp_path, content):
    events = tmp_path / 'events.jsonl'
    events.write_bytes(content)
    with pytest.raises(ValueError):
        M['analyze'](events)
