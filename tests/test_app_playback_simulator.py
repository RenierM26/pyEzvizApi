"""Synthetic native-oracle parity and combined queue/backpressure scenarios."""

import json
from pathlib import Path
import subprocess
import sys

import pytest
from tools.app_playback_simulator import Decision, PlaybackSimulator, VideoClock, float32

ORACLE = json.loads((Path(__file__).parent / 'fixtures/app_playback_native_oracle.json').read_text())
SCRIPT = Path(__file__).parents[1] / 'tools/app_playback_simulator.py'


@pytest.mark.parametrize('case', ORACLE['decisions'])
def test_executed_native_selection(case):
    clock = VideoClock(speed=float32(case['speed']))
    target = int(float32(float32(10050) / clock.speed))
    actual = clock.decision(10000, target - case['difference_ms'], case['depth'])
    expected = case['actions']
    assert actual == Decision(display='display' in expected,
                              drops=expected.count('drop'),
                              sleep_ms=next((v[1] // 1000 for v in expected if isinstance(v, list)), 0))


@pytest.mark.parametrize('case', ORACLE['speedups'])
def test_executed_native_speedup(case):
    clock = VideoClock(node_limit=case['limit'], bias_ms=case['bias'])
    clock.after_display(case['post_render_depth'])
    assert clock.speed == case['speed_after']


@pytest.mark.parametrize('case', ORACLE['resets'])
def test_executed_native_reset(case):
    clock = VideoClock(speed=float32(case['speed_before']), bias_ms=123, rebase_pending=False)
    clock.unavailable(case['staging_result'])
    assert (clock.speed, clock.bias_ms, clock.rebase_pending) == (
        case['speed_after'], case['bias_after'], bool(case['rebase_after']))


@pytest.mark.parametrize('case', ORACLE['rebases'])
def test_executed_native_rebase(case):
    clock = VideoClock()
    clock.rebase(case['picture'])
    assert clock.origin_ms == case['picture']
    assert clock.bias_ms == case['bias_after']
    assert not clock.rebase_pending


def event(sim, kind, at=0, **values):
    sim.step({'kind': kind, 'at_ms': at, **values})


def picture(sim, number, at=0):
    event(sim, 'video_picture', at, id=f'v{number}', media_ms=number * 66,
          lenses=[f'main:{number}', f'second:{number}'])


def test_combined_backpressure_and_video_catchup_keep_identities():
    sim = PlaybackSimulator()
    for n in range(25):
        event(sim, 'audio_enqueue', id=f'a{n}', media_ms=n * 64)
    # Keep the processing block in the ring until release, not begin.
    event(sim, 'audio_begin')
    event(sim, 'audio_enqueue', id='during-processing', media_ms=1600)
    event(sim, 'audio_release', id='a0')
    event(sim, 'audio_enqueue', id='after-release', media_ms=1664)
    with pytest.raises(ValueError, match='idle consumer'):
        event(sim, 'audio_begin')
    for n in range(4):
        picture(sim, n)
    event(sim, 'video_tick')  # Initial rebase leaves the head queued.
    event(sim, 'video_tick', 300)  # Late: drop first 3 pairs, display fourth.
    event(sim, 'audio_write_complete', 300, id='a0', accepted_bytes=2048)
    event(sim, 'audio_begin', 300)
    result = sim.result()
    summary = result['summary']
    assert (summary['audio_rejected'], summary['audio_written']) == (2, 1)
    assert summary['audio_processing'] == 'a1'
    assert summary['audio_ring_pending'][-1] == 'after-release'
    assert (summary['video_dropped'], summary['video_displayed']) == (3, 1)
    displayed = next(a for a in result['actions'] if a['kind'] == 'video_display_requested')
    assert displayed['id'] == 'v3' and displayed['lenses'] == ['main:3', 'second:3']
    assert displayed['media_ms'] == 198
    assert not result['physical_lip_sync_measured']


def test_autonomous_speed_and_unavailable_rebase_preserve_head():
    sim = PlaybackSimulator()
    for n in range(4):
        picture(sim, n)
    event(sim, 'video_tick')
    event(sim, 'video_tick', 50)  # Due, 3 nodes remain: speed up.
    assert sim.clock.speed == float32(1.1)
    for at in (110, 170, 230):
        event(sim, 'video_tick', at)
    assert not sim.video
    event(sim, 'video_tick', 240, staging_result=0)
    assert sim.clock.speed == float32(1.1)
    event(sim, 'video_tick', 250, staging_result=1)
    assert sim.clock.speed == 1 and sim.clock.rebase_pending
    picture(sim, 4, at=300)
    event(sim, 'video_tick', 300)
    assert sim.clock.origin_ms == 264 and len(sim.video) == 1
    event(sim, 'video_tick', 300)
    assert sim.result()['actions'][-1]['wake_ms'] == 305
    with pytest.raises(ValueError, match='wake time'):
        event(sim, 'video_tick', 301)


@pytest.mark.parametrize('bad', [
    {'kind': 'audio_enqueue', 'at_ms': True, 'id': 'a', 'media_ms': 0},
    {'kind': 'audio_enqueue', 'at_ms': 0, 'id': 'a'},
    {'kind': 'audio_begin', 'at_ms': 0},
    {'kind': 'video_tick', 'at_ms': 0},
    {'kind': 'unknown', 'at_ms': 0},
    {'kind': 'video_tick', 'at_ms': 0, 'staging_result': True},
    {'kind': 'video_picture', 'at_ms': 0, 'id': 'v', 'media_ms': 0, 'lenses': ['x', 'x']},
])
def test_invalid_or_unobserved_input_rejected(bad):
    with pytest.raises(ValueError):
        PlaybackSimulator().step(bad)


def test_bounds_duplicates_backward_time_and_partial_write():
    sim = PlaybackSimulator()
    for n in range(6):
        picture(sim, n)
    with pytest.raises(ValueError, match='overflow policy'):
        picture(sim, 6)
    event(sim, 'audio_enqueue', 10, id='a', media_ms=0)
    with pytest.raises(ValueError, match='duplicate'):
        event(sim, 'audio_enqueue', 10, id='a', media_ms=0)
    with pytest.raises(ValueError, match='nondecreasing'):
        event(sim, 'audio_begin', 9)
    event(sim, 'audio_begin', 10)
    event(sim, 'audio_release', 10, id='a')
    with pytest.raises(ValueError, match='partial/failed'):
        event(sim, 'audio_write_complete', 10, id='a', accepted_bytes=1024)
    assert sim.writing == 'a'


def test_cli_stages_output_and_limits_lines():
    for raw in (b'{bad}\n', b' ' * 8193, b'{"kind":"video_tick","at_ms":0}\n'):
        result = subprocess.run([sys.executable, str(SCRIPT)], input=raw,
                                capture_output=True, check=False, timeout=10)
        assert result.returncode == 2
        assert not result.stdout
    result = subprocess.run([sys.executable, str(SCRIPT)], input=b'',
                            capture_output=True, check=True, timeout=10)
    assert json.loads(result.stdout)['events'] == 0


def test_cli_event_bound_and_prefix_failure_are_atomic():
    valid = b'{"kind":"video_tick","at_ms":0,"staging_result":0}\n'
    result = subprocess.run([sys.executable, str(SCRIPT)], input=valid * 10001,
                            capture_output=True, check=False, timeout=10)
    assert result.returncode == 2 and not result.stdout
    for suffix in (b'not-json\n', b'[' * 1100 + b'0' + b']' * 1100):
        result = subprocess.run([sys.executable, str(SCRIPT)], input=valid + suffix,
                                capture_output=True, check=False, timeout=10)
        assert result.returncode == 2 and not result.stdout


def test_eof_retains_pending_work_and_backward_media_is_rejected():
    sim = PlaybackSimulator()
    picture(sim, 2)
    with pytest.raises(ValueError, match='continuity-repaired'):
        picture(sim, 1)
    event(sim, 'audio_enqueue', id='a', media_ms=500)
    event(sim, 'audio_begin')
    summary = sim.result()['summary']
    assert summary['video_pending'] == ['v2']
    assert summary['audio_ring_pending'] == ['a']
    assert summary['audio_processing'] == 'a'
    assert summary['audio_written'] == summary['video_displayed'] == 0
