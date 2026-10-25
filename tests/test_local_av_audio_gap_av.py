"""Unknown-source reservations and original-target glue for explicit gap output."""
import copy
from fractions import Fraction
from pathlib import Path
import runpy
import time

import pytest

ROOT = Path(__file__).parents[1]
M = runpy.run_path(str(ROOT / 'tools/local_av_online_playback.py'))
G = M['GAP']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_online_playback.py')))
AUDIO = runpy.run_path(str(Path(__file__).with_name('test_local_av_audio_gap_output.py')))
LIMITS = dict(AUDIO['LIMITS'], max_source_span_seconds=60)


def rows(count=31):
    planner = G['GAPS']['GapPlanner'](**LIMITS)
    video = OLD['events'](1)[0]
    yield video
    previous = None
    for index in range(count):
        stamp = 1 + Fraction(8, 125) * (index + int(index >= 30))
        event, data = AUDIO['prepared'](index, stamp, previous)
        event[G['PLAN']] = planner.offer(event, data)
        event['at'] = G['GAPS']['rational'](stamp - 1)
        del event['source_time']
        yield event, data
        previous = stamp


def test_unknown_read_reserves_padding_inside_unchanged_64k_credit_cap():
    source = OLD['Source'](rows())
    pull = M['PULL']['PreparedPull'](source, interrupt=lambda: None)
    assets = M['Assets'](pull, pending_input=True, diagnostic_tail=2, gap_limits=LIMITS)
    deadline = time.monotonic() + 5
    try:
        while assets.offered['audio_block'] < 31:
            assert time.monotonic() < deadline
            assets.pump()
            if assets.reservation:
                assert assets.reservation['audio_block'] == 4096
                assert assets.bytes['audio_block'] + 4096 <= 65536
            time.sleep(.001)
        assert assets.counts['audio_block'] == 31
        assert assets.bytes['audio_block'] == 65536 and assets.padding_credit == 2048
        assert not assets.can_pull() and not assets.pump()
        assert not assets.reservation
        # One source event owns two block-equivalents until its combined job ack.
        assets.release('aac:2:30')
        assert assets.bytes['audio_block'] == 61440 and assets.padding_credit == 0
        assert assets.can_pull()
    finally:
        assets.close()
    assert source.closed and not pull.result()['worker_alive']
    assert assets.result()['owned_padding_credit_bytes'] == 0
    assert assets.result()['peak_credit_bytes']['audio_block'] <= 65536


@pytest.mark.parametrize('tamper', ['padding', 'source', 'bool'])
def test_prepared_plan_is_recomputed_from_original_source_and_pcm(tamper):
    event, data = list(rows(1))[1]
    bad = copy.deepcopy(event)
    if tamper == 'padding':
        bad[G['PLAN']]['planned_padding'] = {}
    elif tamper == 'source':
        bad['block']['pcm_sha256'] = '0' * 64
    else:
        bad[G['PLAN']]['source']['bytes'] = 2048.0
    with pytest.raises(ValueError):
        G['charge'](G['GAPS']['GapPlanner'](**LIMITS), bad, data)


def test_padding_dispatch_precedes_original_target_without_rebasing():
    event, _data = list(rows())[-1]
    before = copy.deepcopy(event)
    original = G['GAPS']['exact'](event['at'])
    assert G['relative_dispatch'](event) == original - Fraction(8, 125)
    assert G['origin'](event) == 1 and event == before


def gap_calls(blocks, jitter_ms=0):
    """Enter combined jobs at padding time, like the actual A/V scheduler."""
    clock = AUDIO['Clock']()
    backend = AUDIO['Backend'](clock)
    backend.progress = 8192  # A complete maximum-sized padding write is immediate.
    limits = dict(LIMITS, max_gap_blocks=blocks)
    adapter = G['Audio'](backend, limits, .1, 250)
    anchor = clock.ns
    adapter.bind(anchor, Fraction(10), clock, clock.pause)
    planner = G['GAPS']['GapPlanner'](**limits)
    def call(index, stamp, previous=None):
        event, data = AUDIO['prepared'](index, stamp, previous)
        event[G['PLAN']] = planner.offer(event, data)
        event['at'] = G['GAPS']['rational'](stamp - 10)
        del event['source_time']
        target = Fraction(stamp - 10) * 1000000000
        action = dict(target_monotonic_ns=anchor + target.numerator // target.denominator)
        return adapter.call(event, data[0], action), action
    call(0, Fraction(10))
    clock.ns = anchor + 64000000
    stamp = Fraction(10) + (blocks + 1) * Fraction(8, 125) + Fraction(jitter_ms, 1000)
    return adapter, backend, clock, lambda: call(1, stamp, Fraction(10)), anchor, stamp


@pytest.mark.parametrize('blocks', [1, 2, 3, 4])
@pytest.mark.parametrize('jitter_ms', [-1, 0, 1])
def test_combined_job_intentional_padding_wait_does_not_consume_write_deadline(blocks, jitter_ms):
    adapter, backend, clock, call, anchor, stamp = gap_calls(blocks, jitter_ms)
    ack, action = call()
    target = (stamp - 10) * 1000000000
    assert action['target_monotonic_ns'] == action['started_monotonic_ns'] == anchor + target.numerator // target.denominator
    assert action['submission_late_ns'] == 0 and ack['bytes'] == 2048
    assert backend.writes == [(anchor, AUDIO['PCM']), (anchor + 64000000, bytes(blocks * 2048)),
        (clock.ns, AUDIO['PCM'])]
    adapter.finish(.1)
    assert adapter.result()['completed'] == dict(source=2, padding=1)
    assert adapter.result()['outputs_finished'] and not adapter.result()['failed']
    assert adapter.result()['owned_source_bytes'] == adapter.result()['owned_padding_bytes'] == 0


def test_combined_job_stalled_source_still_has_original_100ms_write_deadline():
    adapter, backend, clock, call, _anchor, _stamp = gap_calls(4)
    original = backend.write
    def write(data):
        if len(backend.writes) == 2:
            raise BlockingIOError
        return original(data)
    backend.write = write
    with pytest.raises(TimeoutError, match='write deadline'):
        call()
    result = adapter.result()
    assert result['completed'] == dict(source=1, padding=1)
    assert result['failed_job']['kind'] == 'source' and result['failed_job']['partial_bytes'] == 0
    assert clock.ns - backend.writes[1][0] < 360000000
    assert result['failed'] and result['transport_closed']


def test_combined_job_cancellation_during_intentional_wait_is_prompt():
    adapter, backend, clock, call, anchor, _stamp = gap_calls(4)
    pause = clock.pause
    def cancel(seconds):
        pause(seconds)
        if clock.ns >= anchor + 114000000:
            adapter.abort()
    adapter.sink.pause = cancel
    with pytest.raises(InterruptedError):
        call()
    result = adapter.result()
    assert result['completed'] == dict(source=1, padding=1)
    assert result['cancelled'] and result['failed'] and backend.aborts == 1
    assert result['owned_source_bytes'] == result['owned_padding_bytes'] == 0
    assert clock.ns <= anchor + 119000000
