"""Finalized tails bound diagnostic ownership independently of session length."""
import copy
from fractions import Fraction
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


def media_pair(index=0, track='video_pair', anchor=1000):
    name = f'{track}:{index}'
    size = 12 if track == 'video_pair' else 2048
    submit = dict(kind='output_call_submitted', track=track, id=name,
        source_at=dict(numerator=index, denominator=1000), target_monotonic_ns=anchor + index * 1000000,
        bytes=size, started_monotonic_ns=999, submission_late_ns=2)
    ack: dict[str, Any] = dict(bytes=size)
    if track == 'video_pair':
        ack.update(kind='presented', pair_id=name, pixel_sha256='a' * 64, present_returned_ns=12345)
    else:
        ack['pcm_sha256'] = 'b' * 64
    return submit, dict(kind='output_call_completed', track=track, id=name,
        acknowledgement=ack, completed_monotonic_ns=99999)


def expected_media_row(index, track, anchor=1000):
    stamp = Fraction(index, 1000)
    return dict(track=track, id=f'{track}:{index}',
        source_at=dict(numerator=stamp.numerator, denominator=stamp.denominator),
        target_monotonic_ns=anchor + index * 1000000,
        bytes=12 if track == 'video_pair' else 2048,
        payload_sha256=('a' if track == 'video_pair' else 'b') * 64)


def test_media_chains_reconstruct_from_source_rows_independent_of_harvest_and_host_observations():
    journals = [M['Actions'](1), M['Actions'](1)]
    for log in journals:
        log.set_media_anchor(1000)
    for index in range(4):
        pairs = [media_pair(index, track) for track in ('video_pair', 'audio_block')]
        for log in journals:
            for sub, _end in pairs:
                log.append(copy.deepcopy(sub))
        for _sub, end in pairs:
            journals[0].append(copy.deepcopy(end))
        for _sub, end in reversed(pairs):
            changed = copy.deepcopy(end)
            changed['completed_monotonic_ns'] += 1000
            journals[1].append(changed)
    a, b = [log.result() for log in journals]
    assert a['finalized_sha256'] != b['finalized_sha256']
    assert a['media_receipt'] == b['media_receipt']
    for track in ('video_pair', 'audio_block'):
        rows = [expected_media_row(i, track) for i in range(4)]
        digest = hashlib.sha256(b'bounded-output-media-v1\n' + track.encode() + b'\n'
            + b''.join(canonical(row) + b'\n' for row in rows))
        r = a['media_receipt']['tracks'][track]
        assert r == dict(completed=4, bytes=sum(row['bytes'] for row in rows), sha256=digest.hexdigest())
    assert not a['complete_history_retained'] and len(journals[0].tail()) == 2


@pytest.mark.parametrize('field,value', [('target_monotonic_ns', 1001), ('target_monotonic_ns', True),
    ('bytes', 13), ('bytes', True), ('source_at', {'numerator': 0, 'denominator': 0}),
    ('source_at', {'numerator': True, 'denominator': 1}), ('source_at', {'numerator': -1, 'denominator': 1}),
    ('source_at', {'numerator': 2**129, 'denominator': 1})])
def test_invalid_source_projection_cannot_advance_media_chain(field, value):
    log = M['MediaReceipt'](1000)
    sub, end = media_pair()
    sub[field] = value
    before = log.result()
    with pytest.raises(ValueError):
        log.append(sub, end)
    assert log.result() == before


@pytest.mark.parametrize('field,value', [('bytes', 13), ('bytes', True), ('pair_id', 'wrong'),
    ('kind', 'accepted-not-presented'), ('pixel_sha256', 'A' * 64), ('pixel_sha256', 'x' * 64),
    ('pixel_sha256', 'a' * 63), ('pixel_sha256', None)])
def test_invalid_acknowledgement_cannot_advance_media_chain(field, value):
    log = M['MediaReceipt'](1000)
    sub, end = media_pair()
    end['acknowledgement'][field] = value
    before = log.result()
    with pytest.raises(ValueError):
        log.append(sub, end)
    assert log.result() == before


def test_media_failure_and_pending_jobs_never_enter_completed_chain():
    log = M['Actions'](2)
    log.set_media_anchor(1000)
    sub, end = media_pair()
    log.append(sub)
    assert log.result()['media_receipt']['tracks']['video_pair']['completed'] == 0
    end.update(kind='output_call_failed', error='backend failed')
    log.append(end)
    assert log.result()['failed']['video_pair'] == 1
    assert log.result()['media_receipt']['tracks']['video_pair']['completed'] == 0


def test_duplicate_backward_source_and_anchor_reuse_reject_without_advancing():
    log = M['MediaReceipt'](1000)
    log.append(*media_pair(1))
    before = log.result()
    for index in (1, 0):
        with pytest.raises(ValueError, match='order'):
            log.append(*media_pair(index))
    assert log.result() == before
    actions = M['Actions'](1)
    actions.append(submission('already submitted'))
    with pytest.raises(ValueError, match='once before'):
        actions.set_media_anchor(1000)
    other = M['Actions'](1)
    other.set_media_anchor(1000)
    with pytest.raises(ValueError, match='once before'):
        other.set_media_anchor(1000)


def test_diagnostic_failure_cannot_partially_commit_media_or_erase_error(monkeypatch):
    log = M['Actions'](1)
    log.set_media_anchor(1000)
    sub, end = media_pair()
    log.append(sub)
    before = log.result()['media_receipt']
    def fail(_row):
        raise OSError('diagnostic storage failed')
    monkeypatch.setattr(log.records, 'append', fail)
    with pytest.raises(OSError):
        log.append(end)
    assert log.result()['media_receipt'] == before and log.result()['error_count'] == 1
    assert log.result()['pending_count'] == 1 and not log.result()['complete_finalization']


def test_many_media_completions_keep_only_per_track_state_and_do_not_retain_input():
    log = M['MediaReceipt'](1000)
    digest = hashlib.sha256(b'bounded-output-media-v1\nvideo_pair\n')
    for index in range(10000):
        sub, end = media_pair(index)
        log.append(sub, end)
        digest.update(canonical(expected_media_row(index, 'video_pair')) + b'\n')
        sub['id'] = 'changed'
        end['acknowledgement']['pixel_sha256'] = '0' * 64
    r = log.result()['tracks']['video_pair']
    assert r == dict(completed=10000, bytes=120000, sha256=digest.hexdigest())
    assert len(log.previous) == 1 and len(log.digests) == 2


@pytest.mark.parametrize('anchor', [-1, True, None, '1000', 2**128])
def test_invalid_media_anchor_rejected(anchor):
    with pytest.raises(ValueError, match='anchor'):
        M['MediaReceipt'](anchor)


def test_equivalent_exact_source_fractions_have_one_canonical_projection():
    a, b = M['MediaReceipt'](1000), M['MediaReceipt'](1000)
    sub, end = media_pair(1000)
    a.append(sub, end)
    sub['source_at'] = dict(numerator=2, denominator=2)
    b.append(sub, end)
    assert a.result() == b.result()


@pytest.mark.parametrize('change', ['hash', 'identity', 'target', 'extent', 'omitted'])
def test_media_receipt_detects_changes_outside_identical_retained_tail(change):
    original, altered = M['Actions'](1), M['Actions'](1)
    for log in (original, altered):
        log.set_media_anchor(1000)
    for index in range(3):
        sub, end = media_pair(index)
        original.append(copy.deepcopy(sub))
        original.append(copy.deepcopy(end))
        if index == 0:
            if change == 'omitted':
                continue
            if change == 'hash':
                end['acknowledgement']['pixel_sha256'] = 'c' * 64
            elif change == 'identity':
                sub['id'] = end['id'] = end['acknowledgement']['pair_id'] = 'changed-first-id'
            elif change == 'target':
                sub['source_at'] = dict(numerator=1, denominator=2000)
                sub['target_monotonic_ns'] = 501000
            else:
                sub['bytes'] = end['acknowledgement']['bytes'] = 13
        altered.append(sub)
        altered.append(end)
    assert original.tail() == altered.tail()
    a, b = original.result()['media_receipt'], altered.result()['media_receipt']
    assert a['tracks']['video_pair'] != b['tracks']['video_pair']
    assert a['tracks']['audio_block'] == b['tracks']['audio_block']
