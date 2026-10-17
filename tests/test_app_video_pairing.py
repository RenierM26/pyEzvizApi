"""Synthetic native staging oracles, lifecycle boundaries and strict metadata input."""

import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_video_pairing.py'
MODULE = runpy.run_path(str(SCRIPT))
Pairing = MODULE['Pairing']
ORACLE = json.loads((Path(__file__).parent / 'fixtures/app_pairing_native_oracle.json').read_text())
SIM = runpy.run_path(str(SCRIPT.with_name('app_playback_simulator.py')))


@pytest.mark.parametrize('case', ORACLE['cases'], ids=lambda row: row['name'])
def test_original_arm_paired_lifecycle(case):
    model = Pairing()
    for event in case['events']:
        model.step(event)
    result = model.result()
    assert result['summary'] == case['summary']
    for kind, field, expected in [
        ('lens_input_unaccepted', 'lens', 'unaccepted_ids'),
        ('lens_orphaned', 'lens', 'orphaned_ids'),
        ('render_queue_admitted', 'pair', 'admitted_pairs'),
        ('render_queue_taken', 'pair', 'taken_pairs'),
    ]:
        key = 'id' if field == 'lens' else 'pair_id'
        assert [a[field][key] for a in result['actions'] if a['kind'] == kind] == case[expected]
    assert not result['physical_lip_sync_measured']
    assert not result['decoder_buffer_ownership_verified']


def lens(identity, index=0, raw=0, media=0, frame=0, at=0):
    return dict(kind='lens_picture', at_ms=at, id=identity, lens=index,
                raw_time=raw, media_ms=media, frame_number=frame)


def test_assembled_event_feeds_merged_simulator_and_retains_both_headers():
    model = Pairing()
    model.step(lens('primary', raw=42, media=0, frame=10))
    model.step(lens('secondary', index=1, raw=42, media=999, frame=20))
    admitted = model.actions[-1]
    assert admitted['pair']['lenses'][1]['media_ms'] == 999
    assert admitted['pair']['lenses'][0]['frame_number'] == 10
    sim = SIM['PlaybackSimulator']()
    sim.step(admitted['simulator_event'])
    sim.step(dict(kind='video_tick', at_ms=0))
    sim.step(dict(kind='video_tick', at_ms=50))
    assert sim.result()['summary']['video_displayed'] == 1
    assert sim.actions[-1]['lenses'] == ['primary', 'secondary']
    assert sim.actions[-1]['media_ms'] == 0


def test_full_partial_stage_error_has_side_effect_but_no_automatic_retry():
    model = Pairing()
    for n in range(5):
        model.step(lens(f'offer:{n}', raw=n))
    summary = model.result()['summary']
    assert summary['lens_offered'] == 5
    assert summary['lens_unaccepted'] == summary['lens_orphaned'] == 1
    assert len(summary['staging_pending']) == 3
    assert [e['lens']['id'] for e in model.actions if e['kind'] == 'lens_orphaned'] == ['offer:0']
    failed = model.actions[-1]
    assert failed['kind'] == 'lens_input_unaccepted'
    assert failed['lens']['id'] == 'offer:4' and failed['native_result'] == 0x80000007
    model.step(lens('explicit-new-offer', raw=4))
    assert len(model.stage) == 4


def test_take_does_not_implicitly_push_and_eof_retains_partial_work():
    model = Pairing()
    for n in range(7):
        model.step(lens(f'm:{n}', raw=n))
        model.step(lens(f's:{n}', index=1, raw=n))
    assert len(model.render) == 6 and len(model.stage) == 1
    model.step(dict(kind='render_take', at_ms=0))
    assert len(model.render) == 5 and len(model.stage) == 1
    model.step(dict(kind='stage_push', at_ms=0))
    assert len(model.render) == 6 and not model.stage
    model.step(lens('unfinished', raw=100))
    assert model.result()['summary']['staging_pending'][0]['state'] == 1
    assert model.counts['lens_orphaned'] == 0


@pytest.mark.parametrize('bad', [
    None, [], {}, dict(kind='unknown', at_ms=0), dict(kind=[], at_ms=0),
    dict(kind='stage_push', at_ms=True), dict(kind='render_take', at_ms=-1),
    dict(kind='render_take', at_ms=3_600_001), dict(kind='stage_push', at_ms=0, id='extra'),
    dict(lens('x'), lens=2), dict(lens('x'), lens=True), dict(lens('x'), raw_time=-1),
    dict(lens('x'), raw_time=2**32), dict(lens('x'), media_ms=True),
    dict(lens('x'), frame_number=1.5), dict(lens('x'), id=''), dict(lens('x'), id='x' * 129),
    dict(kind='lens_picture', at_ms=0, id='missing'),
])
def test_invalid_metadata_rejected(bad):
    with pytest.raises(ValueError):
        Pairing().step(bad)


def test_time_identity_and_event_bounds():
    model = Pairing()
    model.step(lens('a', at=2))
    with pytest.raises(ValueError, match='observation-time'):
        model.step(lens('b', at=1))
    with pytest.raises(ValueError, match='uniquely'):
        model.step(lens('a', at=2))
    model.events = 10_000
    with pytest.raises(ValueError, match='event limit'):
        model.step(dict(kind='stage_push', at_ms=2))


def test_cli_stages_results_and_keeps_boundary_pending():
    good = json.dumps(lens('pending')).encode() + b'\n'
    p = subprocess.run([sys.executable, str(SCRIPT)], input=good, capture_output=True,
                       timeout=5, check=False)
    assert p.returncode == 0
    summary = json.loads(p.stdout)['summary']
    assert summary['staging_pending'][0]['lenses'][0]['id'] == 'pending'
    for bad in [b'{bad}\n', b' ' * 8193, good + b'{bad}\n']:
        p = subprocess.run([sys.executable, str(SCRIPT)], input=bad, capture_output=True,
                           timeout=5, check=False)
        assert p.returncode == 2 and not p.stdout
