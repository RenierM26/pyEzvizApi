"""Explicit timer provenance, asynchronous display and strict replay failures."""

import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/app_playback_simulator.py'
MODULE = runpy.run_path(str(SCRIPT))
Replay = MODULE['ObservedClockReplay']
float32 = MODULE['float32']


def event(sim, kind, at=0, **fields):
    sim.step(dict(kind=kind, at_ms=at, **fields))


def picture(sim, n, at=0):
    event(sim, 'video_picture', at, id=f'v{n}', media_ms=n * 66,
          lenses=[f'main:{n}', f'second:{n}'])


def initialized():
    sim = Replay()
    picture(sim, 0)
    event(sim, 'video_epoch', epoch=0, origin_ms=0)
    return sim


def tick(sim, at=0, **overrides):
    fields = dict(epoch=0, id='v0', relative_ms=0, elapsed_ms=36,
                  depth=1, speed=1, bias_ms=50, interval_ms=66)
    fields.update(overrides)
    event(sim, 'video_observed_tick', at, **fields)


def test_timer_read_not_later_callback_decides_due_boundary():
    early = initialized()
    tick(early, at=999, elapsed_ms=35)
    due = initialized()
    tick(due, at=999, elapsed_ms=36)
    assert early.actions[-1]['display'] is False
    assert due.actions[-1]['kind'] == 'video_display_requested'
    assert early.video[0]['id'] == 'v0'
    assert due.result()['summary']['video_display_pending']['id'] == 'v0'
    assert due.result()['summary']['video_display_completed'] == 0


def test_native_sleep_order_not_callback_order():
    sim = initialized()
    tick(sim, elapsed_ms=0)  # Requests native elapsed >=5, not callback at_ms+5.
    tick(sim, at=0, elapsed_ms=5)
    with pytest.raises(ValueError, match='timer order'):
        tick(sim, at=100, elapsed_ms=9)
    tick(sim, at=100, elapsed_ms=10)


def test_post_display_admissions_control_speed_and_reset_epoch():
    sim = initialized()
    tick(sim)
    # Admissions while the display call is blocked affect POST-render speed.
    for n in (1, 2, 3):
        picture(sim, n)
    assert sim.clock.speed == 1
    event(sim, 'video_display_complete', id='v0', depth=3)
    assert sim.clock.speed == float32(1.1)
    # Unavailable-head read can precede staging admission. It is deliberately
    # independent of the queue's availability at the later staging-return event.
    event(sim, 'video_unavailable', staging_result=0)
    assert not sim.clock.rebase_pending
    event(sim, 'video_unavailable', staging_result=-2147483643)
    assert sim.clock.rebase_pending and sim.clock.speed == 1
    with pytest.raises(ValueError, match='established epoch'):
        tick(sim, id='v1', depth=3)
    event(sim, 'video_epoch', epoch=1, origin_ms=66)
    tick(sim, epoch=1, id='v1', depth=3, elapsed_ms=36)
    event(sim, 'video_display_complete', id='v1', depth=2)
    summary = sim.result()['summary']
    assert summary['video_epoch'] == 1 and summary['video_display_completed'] == 2
    assert summary['video_pending'] == ['v2', 'v3']
    assert not sim.result()['physical_lip_sync_measured']


def test_catchup_and_blocked_audio_are_independent():
    sim = initialized()
    for n in (1, 2, 3):
        picture(sim, n)
    event(sim, 'audio_enqueue', id='a0', media_ms=0)
    event(sim, 'audio_begin')
    event(sim, 'audio_release', id='a0')
    tick(sim, elapsed_ms=300, depth=4)
    assert [e['id'] for e in sim.actions if e['kind'] == 'video_drop_oldest'] == ['v0', 'v1', 'v2']
    event(sim, 'video_display_complete', id='v3', depth=0)
    assert sim.result()['summary']['audio_write_pending'] == 'a0'
    event(sim, 'audio_write_complete', id='a0', accepted_bytes=2048)
    assert sim.result()['summary']['audio_written'] == 1


@pytest.mark.parametrize(('field', 'value'), [
    ('epoch', 1), ('epoch', True), ('epoch', -1), ('id', 'wrong'),
    ('relative_ms', 1), ('relative_ms', True), ('elapsed_ms', True),
    ('elapsed_ms', -1), ('depth', 0), ('depth', 7), ('depth', True),
    ('speed', True), ('speed', float('nan')), ('speed', float('inf')),
    ('speed', 1.1), ('bias_ms', 0), ('bias_ms', True),
    ('interval_ms', 1), ('interval_ms', 67), ('interval_ms', True),
])
def test_mismatched_or_unsupported_snapshot_rejected(field, value):
    with pytest.raises(ValueError):
        tick(initialized(), **{field: value})


@pytest.mark.parametrize('field', ['epoch', 'id', 'relative_ms', 'elapsed_ms',
                                  'depth', 'speed', 'bias_ms', 'interval_ms'])
def test_missing_provenance_rejected(field):
    fields = dict(kind='video_observed_tick', at_ms=0, epoch=0, id='v0',
                  relative_ms=0, elapsed_ms=36, depth=1, speed=1, bias_ms=50, interval_ms=66)
    del fields[field]
    with pytest.raises(ValueError):
        initialized().step(fields)


@pytest.mark.parametrize('bad', [
    dict(kind='video_tick'),
    dict(kind='video_epoch', epoch=0, origin_ms=0),  # Repeating established epoch.
    dict(kind='video_epoch', epoch=1, origin_ms=0),  # No native reset prerequisite.
    dict(kind='video_unavailable', staging_result=True),
    dict(kind='video_unavailable', staging_result=2**31),
    dict(kind='video_unavailable'),
    dict(kind='video_display_complete', id='v0', depth=0),
])
def test_invalid_transitions(bad):
    with pytest.raises(ValueError):
        initialized().step(dict(at_ms=0, **bad))


def test_epoch_requires_available_matching_head_and_no_active_output():
    sim = Replay()
    with pytest.raises(ValueError, match='unconsumed head'):
        event(sim, 'video_epoch', epoch=0, origin_ms=0)
    picture(sim, 0)
    with pytest.raises(ValueError, match='unconsumed head'):
        event(sim, 'video_epoch', epoch=0, origin_ms=66)
    event(sim, 'video_epoch', epoch=0, origin_ms=0)
    tick(sim)
    for bad in [
        dict(kind='video_observed_tick', at_ms=0),
        dict(kind='video_unavailable', at_ms=0, staging_result=1),
        dict(kind='video_display_complete', at_ms=0, id='wrong', depth=0),
        dict(kind='video_display_complete', at_ms=0, id='v0', depth=1),
    ]:
        with pytest.raises(ValueError):
            sim.step(bad)
    assert sim.displaying['id'] == 'v0'
    event(sim, 'video_display_complete', id='v0', depth=0)
    with pytest.raises(ValueError, match='available head'):
        tick(sim)


def test_tick_before_epoch_and_elapsed_regression():
    sim = Replay()
    picture(sim, 0)
    with pytest.raises(ValueError, match='established epoch'):
        tick(sim)
    event(sim, 'video_epoch', epoch=0, origin_ms=0)
    tick(sim, elapsed_ms=35, interval_ms=0)
    with pytest.raises(ValueError, match='timer order'):
        tick(sim, elapsed_ms=34)
    tick(sim, elapsed_ms=36, interval_ms=0)  # Observed startup interval.


def test_cli_mode_is_explicit_and_failure_has_no_success_output():
    rows = [dict(kind='video_picture', at_ms=0, id='v0', media_ms=0, lenses=['m', 's']),
            dict(kind='video_epoch', at_ms=0, epoch=0, origin_ms=0)]
    raw = ''.join(json.dumps(e) + '\n' for e in rows).encode()
    for args, status in [([], 2), (['--observed-clock'], 0)]:
        result = subprocess.run([sys.executable, str(SCRIPT), *args], input=raw,
                                capture_output=True, check=False, timeout=10)
        assert result.returncode == status
        if status:
            assert not result.stdout
        else:
            output = json.loads(result.stdout)
            assert output['clock_source'] == 'explicit-native-timer-snapshots'
            assert output['summary']['video_pending'] == ['v0']
    result = subprocess.run([sys.executable, str(SCRIPT), '--observed-clock'],
                            input=raw + b'{"kind":"video_tick","at_ms":0}\n',
                            capture_output=True, check=False, timeout=10)
    assert result.returncode == 2 and not result.stdout


def test_frame_interval_cannot_return_to_startup_zero():
    sim = initialized()
    tick(sim, elapsed_ms=35)
    with pytest.raises(ValueError, match='profile state'):
        tick(sim, elapsed_ms=36, interval_ms=0)
    tick(sim, elapsed_ms=36)
    event(sim, 'video_display_complete', id='v0', depth=0)
    picture(sim, 1)
    with pytest.raises(ValueError, match='profile state'):
        tick(sim, id='v1', relative_ms=66, elapsed_ms=102, interval_ms=0)
