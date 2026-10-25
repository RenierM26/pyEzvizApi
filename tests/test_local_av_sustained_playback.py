"""Sustained source-clock opt-in, native short-source composition and terminal guards."""
import copy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_sustained_playback.py'
M = runpy.run_path(str(SCRIPT))
POLICY = runpy.run_path(str(Path(__file__).with_name('test_local_av_online.py')))
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_online_playback.py')))


def sequence(seconds=120):
    rows = []
    for i in range(seconds + 1):
        event, data = POLICY['video'](i, i * 1000)
        rows.append((Fraction(i), event, data))
    for i in range(seconds * 125 // 8 + 1):
        event, data = POLICY['audio'](i, i * 64, None if i == 0 else 0)
        event['block']['id'] = f'aac:2:{i}'
        rows.append((Fraction(i * 8, 125), event, data))
    yield from ((event, data) for _time, event, data in sorted(rows, key=lambda r: r[0]))


def test_two_minute_policy_preserves_source_targets_and_constant_identity_ownership():
    report: dict[str, Any] = {}
    source = POLICY['Source'](sequence())
    iterator = M['ONLINE']['iter_online'](source, (0, 1), 2, report,
        identity_mode='source-sequence', pair_limit=3000, span_limit=120)
    counts = dict(video_pair=0, audio_block=0)
    for event, data in iterator:
        track = event['kind']
        i = counts[track]
        assert M['PLAY']['fraction'](event['at']) == (Fraction(i) if track == 'video_pair' else Fraction(i * 8, 125))
        counts[track] += 1
        assert sum(map(len, data)) <= 2048
    state = report['policy']
    assert counts == dict(video_pair=121, audio_block=1876)
    assert state['identity_audit']['retained_id_count'] == 0 and state['identity_audit']['accepted'] == counts
    assert state['source_span_limit_seconds'] == 120 and not any(state['owned_bytes'].values())
    assert state['peak_owned_bytes']['video_pair'] <= 48 and state['peak_owned_bytes']['audio_block'] <= 2048
    assert state['audio_clock_contract']['calculated_max_abs_nominal_phase'] == dict(numerator=0, denominator=1)
    assert source.closed and report['status'] == 'completed'


@pytest.mark.parametrize('limit,mode', [(True, 'source-sequence'), (120.0, 'source-sequence'),
    (0, 'source-sequence'), (121, 'source-sequence'), (120, 'full-history')])
def test_invalid_expanded_span_rejected_before_claiming_source(limit, mode):
    source = POLICY['Source'](sequence())
    with pytest.raises(ValueError, match='source span'):
        next(M['ONLINE']['iter_online'](source, (0, 1), 2, {}, identity_mode=mode, span_limit=limit))
    assert source.pulls == 0 and not source.closed


def test_legacy_sixty_second_limit_and_next_item_after_expanded_limit_still_fail():
    for options in ({}, dict(identity_mode='source-sequence', pair_limit=3000, span_limit=120)):
        source = POLICY['Source'](sequence(121))
        report: dict[str, Any] = {}
        with pytest.raises(ValueError, match='source span exceeds'):
            list(M['ONLINE']['iter_online'](source, (0, 1), 2, report, **options))
        assert source.closed and report['status'] == 'failed'
        assert not any(report['policy']['owned_bytes'].values())


def test_pes_resolution_keeps_explicit_span_and_default_receipt_unchanged():
    state = M['ONLINE']['Policy']((0, 1), 2, 'reject', None, None,
        identity_mode='source-sequence', pair_limit=3000, span_limit=120)
    resolved = M['ONLINE']['selected_policy'](state,
        dict(mode='explicit-mpeg-pes-ids', video_indices=[2, 0], audio_index=1), {}, 'reject', None, None)
    assert resolved.span_limit == 120 and resolved.streams == (2, 0)
    assert 'source_span_limit_seconds' not in M['ONLINE']['Policy']((0, 1), 2, 'reject', None, None).result()


@pytest.mark.parametrize('limit,target,success', [(60, 61, False), (120, 61, True), (120, 121, False)])
def test_scheduler_independent_wall_guard_preserves_legacy_and_explicit_bounds(limit, target, success):
    clock = OLD['OLD']['Clock']()
    rows = OLD['events'](2)
    rows[2][0]['at'] = dict(numerator=target, denominator=1)
    assets = M['OUTPUT']['Assets'](OLD['Source'](rows))
    video, audio = OLD['OLD']['Backend'](clock), OLD['OLD']['Backend'](clock)
    scheduler = M['OUTPUT']['Scheduler'](assets, .5, 250, span_limit=limit,
        clock=clock.read, pause=lambda _seconds: clock.sleep(.025))
    try:
        assets.prefill(5)
        if success:
            scheduler.run(assets, video, audio, OLD['OLD']['Executor'](clock))
            assert scheduler.finished and scheduler.completed == dict(video_pair=2, audio_block=2)
        else:
            with pytest.raises(ValueError, match='session deadline'):
                scheduler.run(assets, video, audio, OLD['OLD']['Executor'](clock))
    finally:
        M['OUTPUT']['cleanup'](assets, scheduler, None, (video, audio), {}, not success)
    assert not assets.owned


def command(source, receipt):
    return [sys.executable, str(SCRIPT), str(source), '--container', 'mpeg', '--primary-stream', '0',
        '--secondary-stream', '2', '--audio-stream', '1', '--play', '--pairing', 'exact-pts',
        '--timing', 'host-submission', '--layout', 'side-by-side', '--processor', 'passthrough',
        '--audio-overlap-policy', 'bounded-serial-pcm', '--max-audio-overlap-ms', '1', '--max-audio-phase-ms', '1',
        '--expected-source-sha256', hashlib.sha256(source.read_bytes()).hexdigest(), '--receipt', str(receipt)]


@pytest.fixture(scope='module')
def actual_receipt(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('sustained-recorded')
    if not OLD['ctypes'].util.find_library('SDL2-2.0') or not OLD['shutil'].which('ffplay') or not hasattr(os, 'memfd_create'):
        pytest.skip('optional Linux SDL/ffplay control')
    source = POLICY['OLD']['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    receipt = tmp_path / 'receipt.json'
    p = subprocess.run(command(source, receipt), capture_output=True, timeout=20,
        env=dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy'), check=False)
    assert p.returncode == 0, (p.stderr, receipt.read_text())
    return json.loads(receipt.read_text()), source


def test_actual_isolated_profile_has_bounded_histories_native_identity_and_sampled_resources(actual_receipt):
    report, source = actual_receipt
    playback = report['playback']
    assert report['status'] == playback['status'] == 'completed'
    assert playback['decode']['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert playback['output']['video_identity_audit']['retained_id_count'] == 0
    assert playback['output']['pair_limit'] == 3000
    assert len(playback['output']['scheduler']['actions']) <= 4
    assert report['resources']['windows']['0']['samples'] > 0
    assert report['resources']['windows']['0']['peak_rss_bytes'] > 0
    assert not report['network_acquisition']


@pytest.mark.parametrize('change', ['digest', 'source-eof', 'owned', 'worker', 'span', 'count', 'drain'])
def test_terminal_profile_rejects_partial_or_tampered_success(actual_receipt, change):
    report, source = actual_receipt
    r = copy.deepcopy(report['playback'])
    if change == 'digest':
        r['decode']['source_sha256'] = '0' * 64
    elif change == 'source-eof':
        r['decode']['input']['verified_source_end'] = False
    elif change == 'owned':
        r['output']['lookahead']['owned_bytes']['video_pair'] = 1
    elif change == 'worker':
        r['source_pull']['worker_alive'] = True
    elif change == 'span':
        r['policy']['policy']['source_span_limit_seconds'] = 60
    elif change == 'count':
        r['output']['scheduler']['completed']['video_pair'] += 1
    else:
        r['output']['scheduler']['outputs_finished'] = False
    with pytest.raises(ValueError, match='terminal accounting'):
        M['verify'](r, hashlib.sha256(source.read_bytes()).hexdigest())


def test_supervisor_does_not_accept_zero_exit_without_a_receipt(monkeypatch):
    monkeypatch.setitem(M['supervise'].__globals__, 'worker_command',
        lambda _args, _receipt: [sys.executable, '-I', '-c', 'pass'])
    report: dict[str, Any] = {}
    assert M['supervise'](SimpleNamespace(expected_source_sha256='0' * 64), report) == 2
    assert report['status'] == 'failed' and 'playback' not in report


def test_real_noncooperative_worker_is_killed_and_reaped_on_wall_guard(tmp_path, monkeypatch):
    if sys.platform != 'linux':
        pytest.skip('Linux process-group supervisor')
    ready = tmp_path / 'ready'
    real_popen = subprocess.Popen
    children, calls = [], []
    class Child:
        def __init__(self, _command, **kwargs):
            code = ("import signal,time;from pathlib import Path;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "Path(__import__('sys').argv[1]).write_text('ready');time.sleep(60)")
            self.process = real_popen([sys.executable, '-I', '-c', code, str(ready)], **kwargs)
            self.pid = self.process.pid
            children.append(self.process)
            until = time.monotonic() + 5
            while not ready.exists():
                assert time.monotonic() < until
                time.sleep(.01)
        def poll(self):
            return self.process.poll()
        def wait(self, timeout):
            calls.append(timeout)
            return self.process.wait(timeout=min(timeout, .1))
    monkeypatch.setattr(M['subprocess'], 'Popen', Child)
    monkeypatch.setitem(M['supervise'].__globals__, 'WALL', .15)
    monkeypatch.setitem(M['supervise'].__globals__, 'worker_command', lambda _args, _receipt: ['synthetic'])
    try:
        report: dict[str, Any] = {}
        assert M['supervise'](SimpleNamespace(expected_source_sha256='0' * 64), report) == 2
        assert report['status'] == 'failed' and report['error_type'] == 'TimeoutError'
        assert calls[-2:] == [10, 3] and children[0].returncode == -signal.SIGKILL
        with pytest.raises(ProcessLookupError):
            os.kill(children[0].pid, 0)
    finally:
        for process in children:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
