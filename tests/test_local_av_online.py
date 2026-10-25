"""Online origin, whole-session audio phase and startup borrowed-byte ownership."""
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy
from typing import Any

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_online.py'))
P = M['PLAY']
T = M['TIMELINE']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_incremental.py')))


def video(index=0, pts=1000, width=2):
    payload = (bytes(width * 2 * 3 // 2), bytes([1]) * (width * 2 * 3 // 2))
    rows = [dict(decoded_id=f'v:{s}:{index}', stream_index=s, frame_index=index,
        source_pts=pts, time_base_num=1, time_base_den=1000, width=width, height=2,
        pixel_sha256=hashlib.sha256(data).hexdigest()) for s, data in enumerate(payload)]
    return dict(kind='video_pair', id=f'local-pair:{index + 1}',
                source_time=T['rational'](Fraction(pts, 1000)), lenses=rows), payload


def audio(index=0, pts=1000, gap=None):
    pcm = bytes(2048)
    row = dict(id=f'a:{index}', stream_index=2, source_pts=pts, time_base_num=1,
        time_base_den=1000, samples=1024, pcm_sha256=hashlib.sha256(pcm).hexdigest())
    return dict(kind='audio_block', source_time=T['rational'](Fraction(pts, 1000)),
        block=row, duration=T['rational'](Fraction(8, 125)),
        gap_before=None if gap is None else T['rational'](Fraction(gap, 1000))), (pcm,)


class Source:
    def __init__(self, events, close_error=False):
        self.iterator = iter(events)
        self.pulls = 0
        self.closed = False
        self.close_error = close_error
    def __iter__(self):
        return self
    def __next__(self):
        self.pulls += 1
        return next(self.iterator)
    def close(self):
        self.closed = True
        if self.close_error:
            raise RuntimeError('source cleanup failed')


def adapt(source, report, **kwargs):
    return M['iter_online'](source, (0, 1), 2, report, **kwargs)


def test_origin_matches_full_plan_without_global_sort_or_source_clock_changes():
    events = [audio(0, 1000), video(0, 1100), audio(1, 1064, 0), video(1, 1166)]
    original = copy.deepcopy(events)
    source = Source(events)
    report: dict[str, Any] = {}
    result = list(adapt(source, report))
    baseline = T['plan'](dict(primary_stream=0, secondary_stream=1,
        decoded_frames=[row for e, _ in events if e['kind'] == 'video_pair' for row in e['lenses']]),
        [e['block'] for e, _ in events if e['kind'] == 'audio_block'])
    by_id = {P['identity'](e): e for e in baseline['events']}
    assert [e for e, _ in result] == [by_id[P['identity'](e)] for e, _ in events]
    assert events == original and [data for _, data in result] == [data for _, data in events]
    assert report['policy']['origin'] == baseline['origin']
    assert report['policy']['audio_clock_contract'] == {k: v for k, v in P['audio_contract'](baseline).items() if k != 'blocks'}
    assert source.closed and not any(report['policy']['owned_bytes'].values())


def test_startup_validates_entire_prefix_before_first_yield_and_keeps_credit_through_yield():
    source = Source([audio(), audio(1, 1063, -1), video()])
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='overlapping'):
        next(adapt(source, report))
    assert report['policy_before_cleanup']['released_prepared_events'] == 0
    assert source.closed
    source = Source([audio(), video(), video(1, 1066)])
    iterator = adapt(source, {})
    next(iterator)
    assert source.pulls == 2  # No next source event pulled while startup rows are borrowed.
    next(iterator)
    assert source.pulls == 2
    iterator.close()
    assert source.closed


def test_cumulative_audio_phase_is_not_reset_after_startup_or_each_event():
    source = Source([video(), audio(), audio(1, 1063, -1), audio(2, 1126, -1)])
    report: dict[str, Any] = {}
    iterator = adapt(source, report, policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1)
    assert len([next(iterator) for _ in range(3)]) == 3
    with pytest.raises(ValueError, match='phase exceeds'):
        next(iterator)
    assert report['status'] == 'failed' and source.closed
    assert report['policy']['audio_blocks'] == 2
    assert report['policy']['audio_clock_contract']['calculated_max_abs_nominal_phase'] == T['rational'](Fraction(1, 1000))


@pytest.mark.parametrize('kind', ['video', 'audio'])
def test_missing_other_head_exhausts_original_startup_credit_without_discard(kind):
    count = M['BOUNDED']['VIDEO_SLOTS'] if kind == 'video' else M['BOUNDED']['AUDIO_SLOTS']
    events = [video(i, 1000 + i * 66) if kind == 'video' else audio(i, 1000 + i * 64, None if i == 0 else 0)
              for i in range(count + 1)]
    report: dict[str, Any] = {}
    source = Source(events)
    with pytest.raises(ValueError, match='capacity'):
        list(adapt(source, report))
    assert report['policy_before_cleanup']['owned_counts'][kind + ('_pair' if kind == 'video' else '_block')] == count
    assert source.closed and report['policy']['origin'] is None


@pytest.mark.parametrize('change', ['hash', 'extent', 'pts', 'track', 'samples', 'duration', 'duplicate', 'geometry', 'span'])
def test_invalid_later_event_stops_without_rebase_or_media_repair(change):
    bad = audio(1, 1064, 0)
    if change == 'hash':
        bad[0]['block']['pcm_sha256'] = '0' * 64
    elif change == 'extent':
        bad = (bad[0], (bytes(1),))
    elif change == 'pts':
        bad[0]['source_time'] = T['rational'](Fraction(2))
    elif change == 'track':
        bad[0]['block']['stream_index'] = 9
    elif change == 'samples':
        bad[0]['block']['samples'] = 512
    elif change == 'duration':
        bad[0]['duration'] = T['rational'](Fraction(1))
    elif change == 'duplicate':
        bad[0]['block']['id'] = 'a:0'
    elif change == 'geometry':
        bad = video(1, 1066, width=4)
    else:
        bad = video(1, 61001)
    source = Source([video(), audio(), bad])
    report: dict[str, Any] = {}
    iterator = adapt(source, report)
    next(iterator)
    next(iterator)
    with pytest.raises(ValueError):
        next(iterator)
    assert report['status'] == 'failed' and source.closed
    assert report['policy']['origin'] == T['rational'](Fraction(1))
    assert report['policy_before_cleanup']['released_prepared_events'] == 2


def test_early_close_and_cleanup_failure_preserve_ownership_and_primary_error():
    source = Source([video(), audio()])
    report: dict[str, Any] = {}
    iterator = adapt(source, report)
    next(iterator)
    iterator.close()
    assert report['status'] == 'closed-before-eof' and source.closed
    assert report['policy']['yielded_prepared_events'] == 1
    assert report['policy']['released_prepared_events'] == 0
    assert report['policy_before_cleanup']['owned_counts']['video_pair'] == 1
    assert not any(report['policy']['owned_bytes'].values())
    source = Source([video()], close_error=True)
    report = {}
    with pytest.raises(ValueError, match='before both'):
        list(adapt(source, report))
    assert 'before both' in report['error']
    assert report['cleanup_errors'] == ['source cleanup failed']


def test_real_online_policy_matches_snapshot_timeline_and_full_audio_rows(tmp_path):
    path = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    raw = path.read_bytes()
    expected = T['inspect'](path, 'mpeg', (0, 2), 1)
    report: dict[str, Any] = {}
    decode: dict[str, Any] = {}
    source = M['CHUNKED']['iter_chunks']((raw[i:i+7] for i in range(0, len(raw), 7)), 'mpeg', (0, 2), 1, decode, startup='bounded-mpeg')
    actual = list(M['iter_online'](source, (0, 2), 1, report, policy='bounded-serial-pcm', overlap_ms=1, phase_ms=1))
    wanted = {}
    for row in copy.deepcopy(expected['events']):
        if row['kind'] == 'audio_block':
            row['block'].pop('decoded_monotonic_ns')
            row['block'].pop('packet_index')
        wanted[P['identity'](row)] = row
    assert all(event == wanted[P['identity'](event)] for event, _ in actual)
    clock = P['audio_contract'](dict(events=list(wanted.values())), 'bounded-serial-pcm', 1, 1)
    digest = hashlib.sha256()
    for row in clock['blocks']:
        digest.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n')
    assert report['policy']['audio_clock_rows_sha256'] == digest.hexdigest()
    assert report['policy']['origin'] == expected['origin'] and decode['status'] == 'completed'


@pytest.mark.parametrize('kind', ['video', 'audio'])
def test_session_identity_limits_remain_after_startup_credit_is_released(monkeypatch, kind):
    if kind == 'video':
        events = [video(), audio(), video(1, 1066), video(2, 1132)]
    else:
        monkeypatch.setitem(T['AUDIO'], 'MAX_BLOCKS', 2)
        events = [video(), audio(), audio(1, 1064, 0), audio(2, 1128, 0)]
    report: dict[str, Any] = {}
    source = Source(events)
    with pytest.raises(ValueError, match='excessive'):
        list(adapt(source, report, **({'pair_limit': 2} if kind == 'video' else {})))
    assert report['status'] == 'failed' and source.closed
    assert report['policy']['released_prepared_events'] == 3


def test_cleanup_only_failure_raises_inside_unrelated_caller_except():
    source = Source([video(), audio()], close_error=True)
    report: dict[str, Any] = {}
    try:
        raise LookupError('ambient caller error')
    except LookupError:
        with pytest.raises(RuntimeError, match='cleanup failed'):
            list(adapt(source, report))
    assert report['status'] == 'failed' and report['cleanup_errors']


def sequence_audio(index=0, pts=1000, gap=None, stream=2):
    event, payload = audio(index, pts, gap)
    event['block'].update(id=f'aac:{stream}:{index}', stream_index=stream)
    return event, payload


def test_sequence_mode_keeps_two_counters_not_identity_history_at_session_limit():
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    def accept(pair):
        state.offer(*pair)
        if state.ready():
            state.map_pending()
            while state.queue:
                state.yielded += 1
                state.release()
        assert state.ids is None
        assert len(state.accepted) == 2
    accept(video())
    accept(sequence_audio())
    for index in range(1, P['MAX_PAIRS']):
        accept(sequence_audio(index, 1000 + index * 64, 0))
        accept(video(index, 1000 + index * 66))
    result = state.result()
    assert result['identity_audit'] == dict(profile='strict-source-sequence-v1',
        accepted=dict(video_pair=300, audio_block=300), retained_id_count=0, audio_stream_index=2)
    assert not state.queue and len(json.dumps(result)) < 3000
    assert result['validated_events'] == result['released_prepared_events'] == 600
    with pytest.raises(ValueError, match='excessive'):
        state.offer(*video(300, 20800))
    assert state.result() == result  # Rejection does not advance identity/accounting.


@pytest.mark.parametrize('kind', ['video_pair', 'audio_block'])
@pytest.mark.parametrize('name', ['', 'arbitrary', 'local-pair:0', 'local-pair:01', 'local-pair:+1',
    'local-pair:2', 'aac:2:1', 'aac:1:0', 'aac:2:00', 'aac:2:-1', 'aac:2:\u0660', 'x' * 10000])
def test_sequence_rejects_noncanonical_skipped_and_wrong_stream_names_before_reserving(kind, name):
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    event, payload = video() if kind == 'video_pair' else sequence_audio()
    if kind == 'video_pair':
        event['id'] = name
    else:
        event['block']['id'] = name
    before = state.result()
    with pytest.raises(ValueError, match=r'identity|identities'):
        state.offer(event, payload)
    assert state.result() == before and not state.queue and state.ids is None


@pytest.mark.parametrize('kind', ['video_pair', 'audio_block'])
def test_sequence_reuse_after_release_and_later_pts_still_fails(kind):
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    for event in (video(), sequence_audio()):
        state.offer(*event)
    state.map_pending()
    while state.queue:
        state.release()
    event, payload = video(1, 1066) if kind == 'video_pair' else sequence_audio(1, 1064, 0)
    if kind == 'video_pair':
        event['id'] = 'local-pair:1'
    else:
        event['block']['id'] = 'aac:2:0'
    before = state.result()
    with pytest.raises(ValueError, match='canonical source sequence'):
        state.offer(event, payload)
    assert state.result() == before


def test_sequence_legacy_metadata_and_policy_are_identical_for_canonical_source():
    events = [sequence_audio(), video(0, 1100), video(1, 1166), sequence_audio(1, 1064, 0)]
    legacy: dict[str, Any] = {}
    report: dict[str, Any] = {}
    expected = list(adapt(Source(events), legacy))
    assert list(adapt(Source(events), report, identity_mode='source-sequence')) == expected
    assert report['profile'] == 'standalone-online-sequence-av-policy-v1'
    audit = report['policy'].pop('identity_audit')
    report['policy_before_cleanup'].pop('identity_audit')
    report['profile'] = legacy['profile']
    assert report == legacy and audit['accepted'] == dict(video_pair=2, audio_block=2)


@pytest.mark.parametrize('mode', [None, False, 1, [], 'window', ''])
def test_unknown_identity_mode_does_not_claim_input(mode):
    source = Source([video(), sequence_audio()])
    with pytest.raises(ValueError, match='identity mode'):
        list(adapt(source, {}, identity_mode=mode))
    assert source.pulls == 0 and not source.closed


def test_sequence_selection_uses_resolved_audio_index_not_requested_placeholder():
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    selection = dict(mode='explicit-mpeg-pes-ids', video_indices=[0, 1], audio_index=7)
    report: dict[str, Any] = {}
    actual = M['selected_policy'](state, selection, report, 'reject', None, None)
    actual.offer(*sequence_audio(stream=7))
    assert actual.identity_mode == 'source-sequence' and actual.ids is None
    assert actual.result()['identity_audit']['audio_stream_index'] == 7
    with pytest.raises(ValueError, match='canonical source sequence'):
        event, payload = sequence_audio(1, 1064, 0, stream=7)
        event['block']['id'] = 'aac:2:1'
        actual.offer(event, payload)


@pytest.mark.parametrize('fault', ['hash', 'extent', 'pts', 'track'])
def test_sequence_payload_validation_failure_does_not_consume_the_next_name(fault):
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    bad = sequence_audio()
    if fault == 'hash':
        bad[0]['block']['pcm_sha256'] = '0' * 64
    elif fault == 'extent':
        bad = (bad[0], (bytes(1),))
    elif fault == 'pts':
        bad[0]['source_time'] = T['rational'](Fraction(2))
    else:
        bad[0]['block']['stream_index'] = 99
    before = state.result()
    with pytest.raises(ValueError):
        state.offer(*bad)
    assert state.result() == before
    state.offer(*sequence_audio())
    assert state.accepted == dict(video_pair=0, audio_block=1)


def test_sequence_capacity_failure_keeps_next_id_available_without_reserving_extra_credit():
    state = M['Policy']((0, 1), 2, 'reject', None, None, identity_mode='source-sequence')
    slots = M['BOUNDED']['AUDIO_SLOTS']
    for index in range(slots):
        state.offer(*sequence_audio(index, 1000 + index * 64, None if index == 0 else 0))
    before = state.result()
    with pytest.raises(ValueError, match='capacity'):
        state.offer(*sequence_audio(slots, 1000 + slots * 64, 0))
    assert state.result() == before
    state.offer(*video())
    state.map_pending()
    while state.queue:
        state.release()
    state.offer(*sequence_audio(slots, 1000 + slots * 64, 0))
    assert state.accepted['audio_block'] == slots + 1


def test_sequence_audio_work_limit_is_not_removed(monkeypatch):
    monkeypatch.setitem(T['AUDIO'], 'MAX_BLOCKS', 2)
    source = Source([video(), sequence_audio(), sequence_audio(1, 1064, 0), sequence_audio(2, 1128, 0)])
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='excessive'):
        list(adapt(source, report, identity_mode='source-sequence'))
    assert source.closed and report['status'] == 'failed'
    assert report['policy']['identity_audit']['accepted'] == dict(video_pair=1, audio_block=2)


def test_sequence_primary_error_survives_source_cleanup_failure():
    bad = sequence_audio(1, 1064, 0)
    bad[0]['block']['id'] = 'aac:2:0'
    source = Source([video(), sequence_audio(), bad], close_error=True)
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='canonical source sequence'):
        list(adapt(source, report, identity_mode='source-sequence'))
    assert source.closed and report['status'] == 'failed'
    assert report['cleanup_errors'] == ['source cleanup failed']
    assert report['policy']['released_prepared_events'] == 2
    assert report['policy']['owned_counts'] == dict(video_pair=0, audio_block=0)
