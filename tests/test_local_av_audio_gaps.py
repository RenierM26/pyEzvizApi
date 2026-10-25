"""A source-clock hole is a bounded padding plan, not silent live repair."""
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_audio_gaps.py'))
OLD = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_playback.py'))
D = Fraction(8, 125)
PCM = bytes([7, 11]) * 1024


def planner(**overrides):
    return M['GapPlanner'](**dict(dict(max_gap_blocks=1, max_total_gap_blocks=4,
        max_overlap_ms=1, max_phase_ms=1, max_blocks=3000, max_source_span_seconds=120), **overrides))


def prepared(index, stamp, previous=None, stream=2):
    stamp = Fraction(stamp)
    row = dict(id=f'aac:{stream}:{index}', stream_index=stream, source_pts=stamp.numerator,
        time_base_num=1, time_base_den=stamp.denominator, samples=1024,
        pcm_sha256=hashlib.sha256(PCM).hexdigest())
    event = dict(kind='audio_block', source_time=M['rational'](stamp), block=row,
        duration=M['rational'](D), gap_before=None if previous is None else M['rational'](stamp - previous - D))
    return event, (PCM,)


def test_observed_shape_after_long_prefix_plans_one_block_without_changing_source():
    state = planner()
    old = OLD['AudioClock']('bounded-serial-pcm', 1, 1)
    previous = None
    chain = hashlib.sha256((M['PROFILE'] + '\n').encode())
    for i in range(1785):
        stamp = i * D - (Fraction(1, 1000) if i == 1783 else 0) + (D if i == 1784 else 0)
        event, payload = prepared(i, stamp, previous)
        original = copy.deepcopy(event)
        decision = state.offer(event, payload)
        assert event == original and payload == (PCM,)
        chain.update(json.dumps(decision, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        legacy = dict(event, at=event['source_time'])
        if i < 1784:
            old.offer(legacy)
            assert decision['planned_padding'] is None
        else:
            with pytest.raises(ValueError, match='phase exceeds'):
                old.offer(legacy)
            pad = decision['planned_padding']
            assert pad['blocks'] == 1 and pad['samples'] == 1024 and pad['bytes'] == 2048
            assert pad['source_start'] == M['rational'](Fraction(14272, 125))
            assert pad['duration'] == M['rational'](D)
            assert pad['pcm_sha256'] == hashlib.sha256(bytes(2048)).hexdigest()
            assert decision['source_time'] == M['rational'](Fraction(2856, 25))
            assert decision['source_gap_before'] == M['rational'](Fraction(13, 200))
            assert decision['remaining_nominal_minus_source'] == M['rational'](Fraction(0))
        previous = stamp
    report = state.result()
    assert report['planned_padding_blocks'] == 1 and report['planned_gaps'] == 1
    assert report['decisions_sha256'] == chain.hexdigest()
    assert old.count == 1784 and report['source_blocks_verified'] == 1785
    assert report['retained_decisions'] == report['retained_pcm_bytes'] == 0
    assert report['plan_only'] and not report['padding_written'] and not report['output_devices_opened']
    assert not report['source_targets_changed'] and not report['source_pcm_changed']


def test_gap_budget_is_cumulative_and_failed_offer_is_transactional():
    state = planner(max_total_gap_blocks=2)
    previous = None
    for i, stamp in enumerate((Fraction(4), Fraction(4) + 2 * D, Fraction(4) + 4 * D)):
        state.offer(*prepared(i, stamp, previous))
        previous = stamp
    assert state.result()['planned_padding_blocks'] == 2
    before = state.result()
    with pytest.raises(ValueError, match='cumulative gap'):
        state.offer(*prepared(3, Fraction(4) + 6 * D, previous))
    assert state.result() == before
    # The rejected source identity and budget were not admitted.
    state.offer(*prepared(3, Fraction(4) + 5 * D, previous))
    assert state.result()['source_blocks_verified'] == 4


@pytest.mark.parametrize('extra,message', [
    (D * 2, 'single gap'), (Fraction(32, 1000), 'not whole blocks'),
    (Fraction(2, 1000), 'not whole blocks'), (Fraction(-2, 1000), 'overlap'),
])
def test_does_not_round_arbitrary_gaps_or_expand_overlap(extra, message):
    state = planner()
    state.offer(*prepared(0, 10))
    before = state.result()
    with pytest.raises(ValueError, match=message):
        state.offer(*prepared(1, 10 + D + extra, Fraction(10)))
    assert state.result() == before


def test_cumulative_jitter_is_not_reset_after_each_offer_or_gap():
    state = planner()
    stamps = (Fraction(10), Fraction(10) + 2 * D, Fraction(10) + 3 * D - Fraction(1, 1000))
    previous = None
    for i, stamp in enumerate(stamps):
        state.offer(*prepared(i, stamp, previous))
        previous = stamp
    before = state.result()
    with pytest.raises(ValueError, match='remaining cumulative'):
        state.offer(*prepared(3, Fraction(10) + 4 * D - Fraction(2, 1000), previous))
    assert state.result() == before


def test_multiple_block_gap_requires_explicit_single_and_total_budgets():
    state = planner(max_gap_blocks=3, max_total_gap_blocks=3)
    state.offer(*prepared(0, 0))
    row = state.offer(*prepared(1, 4 * D, Fraction(0)))
    assert row['planned_padding']['blocks'] == 3
    assert state.result()['planned_padding_bytes'] == 6144


def test_zero_padding_budget_keeps_the_gap_rejected():
    state = planner(max_gap_blocks=0, max_total_gap_blocks=0)
    state.offer(*prepared(0, 0))
    with pytest.raises(ValueError, match='single gap'):
        state.offer(*prepared(1, 2 * D, Fraction(0)))


@pytest.mark.parametrize('field,value', [
    ('max_gap_blocks', True), ('max_gap_blocks', 1.0), ('max_gap_blocks', 5),
    ('max_gap_blocks', -1), ('max_total_gap_blocks', 17), ('max_total_gap_blocks', 0),
    ('max_overlap_ms', 2), ('max_phase_ms', 2), ('max_phase_ms', False),
    ('max_blocks', 10001), ('max_blocks', 0), ('max_source_span_seconds', 121),
    ('max_source_span_seconds', 0), ('max_blocks', '3000'),
])
def test_limits_are_explicit_bounded_integers(field, value):
    with pytest.raises(ValueError, match='explicit finite'):
        planner(**{field: value})


@pytest.mark.parametrize('mutation', [
    lambda e: e['block'].update(id='aac:2:1'),
    lambda e: e['block'].update(source_pts=True),
    lambda e: e['block'].update(samples=True),
    lambda e: e['block'].update(time_base_den=0),
    lambda e: e['block'].update(stream_index=65536),
    lambda e: e['block'].update(pcm_sha256='0' * 64),
    lambda e: e.update(source_time=dict(numerator=1, denominator=2)),
    lambda e: e.update(duration=dict(numerator=16, denominator=250)),
    lambda e: e.update(source_time=dict(numerator=True, denominator=1)),
    lambda e: e.update(source_time=dict(numerator=0, denominator=1, extra=1)),
    lambda e: e.update(gap_before=dict(numerator=0, denominator=1)),
    lambda e: e.update(kind='video_pair'),
])
def test_invalid_input_is_rejected_before_any_state_admission(mutation):
    state = planner()
    event, payload = prepared(0, 0)
    before = state.result()
    mutation(event)
    with pytest.raises(ValueError):
        state.offer(event, payload)
    assert state.result() == before


@pytest.mark.parametrize('payload', [(), (PCM, PCM), [PCM], (bytearray(PCM),), (b'x',)])
def test_requires_one_exact_immutable_original_pcm_block(payload):
    with pytest.raises(ValueError, match='immutable'):
        planner().offer(prepared(0, 0)[0], payload)


@pytest.mark.parametrize('stamp,stream,message', [(0, 2, 'strictly'), (-D, 2, 'metadata'), (D, 3, 'same audio')])
def test_backward_equal_and_stream_switch_fail(stamp, stream, message):
    state = planner()
    state.offer(*prepared(0, 0))
    before = state.result()
    with pytest.raises(ValueError, match=message):
        state.offer(*prepared(1, stamp, Fraction(0), stream))
    assert state.result() == before


def test_source_count_and_span_budgets_are_independent_of_padding_budgets():
    state = planner(max_blocks=1)
    state.offer(*prepared(0, 0))
    with pytest.raises(ValueError, match='block budget'):
        state.offer(*prepared(1, D, Fraction(0)))
    state = planner(max_source_span_seconds=1)
    previous = None
    for i in range(16):
        stamp = i * D
        state.offer(*prepared(i, stamp, previous))
        previous = stamp
    with pytest.raises(ValueError, match='span budget'):
        state.offer(*prepared(16, 16 * D, previous))


def test_input_output_and_receipt_mutation_cannot_change_committed_decisions():
    state = planner()
    event, payload = prepared(0, 4)
    decision = state.offer(event, payload)
    expected = state.result()
    event['block']['source_pts'] = 99
    decision['source']['id'] = 'changed'
    report = state.result()
    report['limits']['max_gap_blocks'] = 4
    assert state.result() == expected
    state.offer(*prepared(1, 4 + D, Fraction(4)))


def test_bad_gap_metadata_and_small_positive_cumulative_drift_fail():
    state = planner()
    state.offer(*prepared(0, 0))
    event, payload = prepared(1, D, Fraction(0))
    event['gap_before'] = None
    with pytest.raises(ValueError, match='gap metadata'):
        state.offer(event, payload)
    state.offer(*prepared(1, D + Fraction(1, 1000), Fraction(0)))
    with pytest.raises(ValueError, match='not whole blocks'):
        state.offer(*prepared(2, 2 * D + Fraction(2, 1000), D + Fraction(1, 1000)))
