"""Finite total video work is independent of unchanged resident output credit."""
import copy
import ctypes.util
import os
from pathlib import Path
import runpy
import time
from typing import Any

import pytest

CAP = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture_playback.py')))
M = CAP['M']
OUT = CAP['OUT']
C = OUT['CHANNEL']
POLICY = CAP['OLD']['POLICY']
rig = CAP['rig']
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed output')
native = pytest.mark.skipif(not ctypes.util.find_library('SDL2-2.0'), reason='SDL2 unavailable')


@pytest.mark.parametrize('limit,mode', [(True, 'source-sequence'), (0, 'source-sequence'),
    (-1, 'source-sequence'), (3001, 'source-sequence'), (301.0, 'source-sequence'),
    ('301', 'source-sequence'), (301, 'full-history')])
def test_bad_pair_budget_never_claims_capture(rig, limit, mode):
    owner, _run = CAP['play'](rig, {})
    with pytest.raises(ValueError, match='pair limit'):
        M['CapturePlayback'](owner, 'key', CAP['arguments'](), {},
            limits=CAP['CaptureLimits'](max_packets=1, max_bytes=1024, duration_seconds=1),
            pair_limit=limit, identity_mode=mode, diagnostic_tail=2)
    assert not owner.started and not owner.closed


def test_larger_output_budget_requires_bounded_diagnostics_before_source_claim(rig):
    owner, _run = CAP['play'](rig, {})
    with pytest.raises(ValueError, match='diagnostic tail'):
        M['CapturePlayback'](owner, 'key', CAP['arguments'](), {},
            limits=CAP['CaptureLimits'](max_packets=1, max_bytes=1024, duration_seconds=1),
            pair_limit=301, identity_mode='source-sequence')
    assert not owner.started and not owner.closed


@pytest.mark.parametrize('limit', [301, 3000])
def test_selected_policy_accepts_exact_explicit_quota_without_id_history_or_credit_growth(limit):
    online = M['PREPARE']['ONLINE']
    state = online['Policy']((0, 1), 2, 'reject', None, None,
        identity_mode='source-sequence', pair_limit=limit)
    state = online['selected_policy'](state, dict(mode='explicit-mpeg-pes-ids',
        video_indices=[0, 1], audio_index=2), {}, 'reject', None, None)
    assert state.pair_limit == limit and state.ids is None
    state.offer(*POLICY['sequence_audio']())
    state.offer(*POLICY['video']())
    state.map_pending()
    while state.queue:
        state.release()
    for index in range(1, limit):
        state.offer(*POLICY['video'](index, 1000 + index))
        state.map_pending()
        state.release()
    before = state.result()
    with pytest.raises(ValueError, match='excessive'):
        state.offer(*POLICY['video'](limit, 1000 + limit))
    assert state.result() == before and state.ids is None and not state.queue
    assert before['identity_audit']['accepted']['video_pair'] == limit
    assert before['peak_owned_bytes']['video_pair'] == 12
    assert before['owned_counts'] == dict(video_pair=0, audio_block=0)


def test_default_policy_still_rejects_pair_301():
    online = M['PREPARE']['ONLINE']
    state = online['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    for index in range(300):
        state.offer(*POLICY['video'](index, 1000 + index))
        state.release()
    with pytest.raises(ValueError, match='excessive'):
        state.offer(*POLICY['video'](300, 1300))
    assert 'pair_limit' not in state.result()


def test_larger_quota_does_not_relax_source_span_or_resident_credit():
    state = M['PREPARE']['ONLINE']['Policy']((0, 1), 2, 'reject', None, None,
        identity_mode='source-sequence', pair_limit=3000)
    state.offer(*POLICY['sequence_audio']())
    state.offer(*POLICY['video']())
    state.map_pending()
    while state.queue:
        state.release()
    for index in range(1, 5):
        state.offer(*POLICY['video'](index, 1000 + index))
    with pytest.raises(ValueError, match='capacity'):
        state.offer(*POLICY['video'](5, 1005))
    while state.queue:
        state.release()
    state.offer(*POLICY['video'](5, 61001))
    with pytest.raises(ValueError, match='60 seconds'):
        state.map_pending()


@native
@pytest.mark.parametrize('overshoot', [False, True])
def test_native_worker_accepts_pair_301_but_not_302_and_binds_budget(monkeypatch, overshoot):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 301, identity_mode='source-sequence')
    lease = C['Lease'](bytes(range(12)))
    try:
        for index in range(1, 302):
            ack = output.present(f'local-pair:{index}', lease, 5)
            assert ack['identity_audit'] == C['identity_audit'](index, 301)
        if overshoot:
            deadline = time.monotonic() + 2
            output.transfer(C['OUTPUT']['packet'](dict(kind='shared_frame', pair_id='local-pair:302',
                offset=0, bytes=12, pixel_sha256=lease.frame.sha256)), deadline)
            with pytest.raises(ValueError, match='frame limit'):
                output.receive(deadline)
            assert output.process.wait(timeout=2) == 2 and output.identity_receipt is None
        else:
            output.finish(5)
            assert output.identity_receipt == C['identity_audit'](301, 301)
    finally:
        output.abort()
        lease.close()


@pytest.mark.parametrize('field,value', [('pair_limit', 300), ('pair_limit', True),
    ('profile', 'strict-video-source-sequence-v1'), ('presented', 302)])
def test_bound_worker_receipt_rejects_changed_budget_or_count(field, value):
    audit = C['identity_audit'](301, 301)
    audit[field] = value
    with pytest.raises(ValueError, match='identity audit'):
        C['verify_identity_audit'](audit, 301, 301)


def test_capture_composition_binds_quota_and_rejects_missing_stage_bindings(rig):
    report: dict[str, Any] = {}
    owner, capture = CAP['session'](rig, report, pair_limit=601, diagnostic_tail=2,
        identity_mode='source-sequence', decoder_deadline_mode='consumer-excluding', pes_ids=(0xE0, 0xE1, 0xC0))
    capture.play()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    prep, output = report['preparation'], report['output']
    assert prep['pair_limit'] == prep['online']['policy']['pair_limit'] == output['pair_limit'] == 601
    assert output['video_identity_audit'] == C['identity_audit'](output['scheduler']['completed']['video_pair'], 601)
    for path in [('pair_limit',), ('online', 'policy', 'pair_limit')]:
        changed = copy.deepcopy(prep)
        target = changed
        for field in path[:-1]:
            target = target[field]
        del target[path[-1]]
        with pytest.raises(ValueError, match=r'pair limit|identity audit'):
            M['verify_output'](changed, output)
    changed_output = copy.deepcopy(output)
    changed_output.pop('pair_limit')
    with pytest.raises(ValueError, match='pair limit'):
        M['verify_output'](prep, changed_output)
    assert not report['source_pull']['worker_alive'] and not output['lookahead']['owned_ids']


def test_matching_worker_and_host_counts_cannot_exceed_the_bound_quota():
    with pytest.raises(ValueError, match='identity audit'):
        C['verify_identity_audit'](C['identity_audit'](302, 301), 302, 301)
