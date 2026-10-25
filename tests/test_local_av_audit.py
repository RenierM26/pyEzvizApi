"""Finalized tails bound diagnostic ownership independently of session length."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
from typing import Any

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_audit.py'))


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def test_many_records_keep_constant_tail_and_full_prefix_digest():
    log = M['Records'](3)
    digest = hashlib.sha256(b'bounded-finalized-json-v1\n')
    for index in range(10000):
        row = dict(index=index, timing=dict(ns=index * 1000))
        digest.update(canonical(row) + b'\n')
        log.append(row)
        assert log.result()['retained_records'] <= 3
    result = log.result()
    assert result['finalized_records'] == 10000 and result['evicted_records'] == 9997
    assert result['finalized_sha256'] == digest.hexdigest()
    assert [row['index'] for row in log] == [9997, 9998, 9999]
    assert result['peak_retained_bytes'] <= M['TAIL_BYTES']
    assert not result['complete_history_retained']


def test_byte_limit_evicts_before_count_limit_and_snapshots_do_not_alias():
    log = M['Records'](128)
    row = dict(parts=['x' * 4000] * 3)
    for _ in range(10):
        log.append(row)
    row['parts'][0] = 'changed'
    snapshot = list(log)
    assert snapshot[0]['parts'][0] != 'changed'
    snapshot[0]['parts'][0] = 'changed too'
    assert next(iter(log))['parts'][0] != 'changed too'
    r = log.result()
    assert r['retained_records'] < 10 and r['peak_retained_bytes'] <= M['TAIL_BYTES']
    assert r['retained_bytes'] == sum(len(canonical(row)) for row in log)


@pytest.mark.parametrize('limit', [None, True, 0, -1, 129, 1.5, '3'])
def test_invalid_required_tail_limit_rejected(limit):
    with pytest.raises(ValueError):
        M['Records'](limit)


@pytest.mark.parametrize('row', [dict(value=b'pixels'), dict(value=object()), dict(value=float('nan')),
    dict(value=float('inf')), dict(value='x' * 4097), dict(value=2**129), dict(value=[0] * 513),
    dict(value=[['x' * 4000] * 3] * 2), dict(value='\u0000' * 4000), {1: 'wrong key'}])
def test_invalid_metadata_cannot_change_audit_state(row):
    log = M['Records'](2)
    log.append(dict(valid=True))
    before = log.result(), list(log)
    with pytest.raises(ValueError):
        log.append(row)
    assert (log.result(), list(log)) == before


def test_cyclic_metadata_is_bounded_before_serialization():
    row: dict[str, Any] = {}
    row['cycle'] = row
    with pytest.raises(ValueError, match='structure bound'):
        M['Records'](2).append(row)


def submission(name, track='video_pair'):
    return dict(kind='output_call_submitted', track=track, id=name, target_monotonic_ns=100)


def outcome(name, track='video_pair', failed=False):
    return dict(kind='output_call_failed' if failed else 'output_call_completed', track=track,
                id=name, acknowledgement=dict(bytes=12))


def test_actions_seal_only_finished_worker_timing_and_follow_harvest_order():
    log = M['Actions'](2)
    video, audio = submission('v'), submission('a', 'audio_block')
    log.append(video)
    log.append(audio)
    assert log.result()['finalized_records'] == 0 and log.result()['pending_count'] == 2
    audio['started_monotonic_ns'] = 200
    log.append(outcome('a', 'audio_block'))
    video['started_monotonic_ns'] = 300
    log.append(outcome('v'))
    frozen = copy.deepcopy(log.tail())
    video['started_monotonic_ns'] = 999
    assert log.tail() == frozen
    pairs = [dict(submission=frozen[i], outcome=frozen[i+1]) for i in (0, 2)]
    digest = hashlib.sha256(b'bounded-finalized-json-v1\n' + b''.join(canonical(row) + b'\n' for row in pairs))
    assert log.result()['finalized_sha256'] == digest.hexdigest()
    assert log.result()['complete_finalization'] and log.result()['pending_count'] == 0
    assert [row['id'] for row in frozen] == ['a', 'a', 'v', 'v']


def test_failed_outcome_and_late_duplicate_are_not_successful_completions():
    log = M['Actions'](1)
    log.append(submission('v'))
    log.append(outcome('v', failed=True))
    before = log.result()
    with pytest.raises(ValueError, match='matching pending'):
        log.append(outcome('v'))
    assert log.result() == before
    assert before['failed'] == dict(video_pair=1, audio_block=0)
    assert before['completed'] == dict(video_pair=0, audio_block=0)


def test_pending_submission_is_reported_without_reading_mutable_worker_fields():
    log = M['Actions'](1)
    row = submission('v')
    log.append(row)
    row['started_monotonic_ns'] = object()  # A still-executing worker is not serialized.
    r = log.result()
    assert r['pending_submissions'] == [submission('v')]
    assert not r['complete_finalization'] and r['finalized_records'] == 0
    with pytest.raises(ValueError):
        log.append(submission('another'))
    assert log.result() == r


def test_action_tail_remains_bounded_over_many_completed_jobs():
    log = M['Actions'](3)
    for index in range(10000):
        name = str(index)
        log.append(submission(name))
        log.append(outcome(name))
    r = log.result()
    assert r['completed']['video_pair'] == 10000 and r['retained_records'] == 3
    assert r['pending_count'] == 0 and len(log.tail()) == 6
    assert r['peak_retained_bytes'] <= M['TAIL_BYTES']


def test_invalid_terminal_row_retains_pending_owner_and_unchanged_digest():
    log = M['Actions'](1)
    log.append(submission('v'))
    before = log.result()
    bad = outcome('v')
    bad['acknowledgement'] = object()
    with pytest.raises(ValueError):
        log.append(bad)
    after = log.result()
    assert after['pending_submissions'] == before['pending_submissions'] and after['pending_count'] == 1
    assert after['finalized_sha256'] == before['finalized_sha256'] and after['finalized_records'] == 0
    assert after['error_count'] == 1
    log.append(outcome('v'))
    assert log.result()['completed']['video_pair'] == 1
    assert not log.result()['complete_finalization']  # A later valid append cannot erase the earlier audit failure.
