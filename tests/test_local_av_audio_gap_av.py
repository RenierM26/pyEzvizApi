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
