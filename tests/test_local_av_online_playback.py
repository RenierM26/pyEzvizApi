"""Single-pass host scheduling, unknown next kind and ack-bound lease ownership."""
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_online_playback.py'
M = runpy.run_path(str(SCRIPT))
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_playback.py')))
BackendBase: Any = OLD['Backend']
POLICY = runpy.run_path(str(Path(__file__).with_name('test_local_av_online.py')))
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed output')


class Source:
    def __init__(self, events, failure=None):
        self.events = iter(events)
        self.failure = failure
        self.pulls = 0
        self.closed = False
    def __iter__(self):
        return self
    def __next__(self):
        self.pulls += 1
        try:
            return next(self.events)
        except StopIteration:
            if self.failure:
                raise self.failure from None
            raise
    def close(self):
        self.closed = True


def events(count=12):
    rows = []
    for index in range(count):
        for event in (POLICY['video'](index, 1000 + index * 66), POLICY['audio'](index, 1000 + index * 64, None if index == 0 else 0)):
            row = dict(event[0])
            row['at'] = dict(numerator=index * (66 if row['kind'] == 'video_pair' else 64), denominator=1000)
            del row['source_time']
            rows.append((row, event[1]))
    return rows


@pytest.mark.parametrize('width,height', [(2, 2), (64, 48), (1920, 1080)])
def test_canonical_hash_matches_independent_composition_without_wide_owner_copy(width, height):
    size = width * height * 3 // 2
    left, right = bytes(i % 251 for i in range(size)), bytes((i + 17) % 251 for i in range(size))
    expected = M['PLAY']['PREVIEW']['compose'](left, right, width, height)
    assert M['pair_digest'](left, right, width, height) == hashlib.sha256(expected).hexdigest()


def test_held_credit_stops_unknown_kind_pull_until_ack_and_lease_close():
    source = Source(events())
    assets = M['Assets'](source)
    try:
        assets.prefill(5)
        assert assets.counts['video_pair'] == M['B']['VIDEO_SLOTS']
        pulls = source.pulls
        event = assets.head('video_pair')
        lease = assets.load(event)
        pumped = assets.pump()
        assert not pumped and source.pulls == pulls and not lease.store.closed
        assets.release(M['PLAY']['identity'](event))
        assert lease.store.closed
        pumped = assets.pump()
        assert pumped and source.pulls == pulls + 1
    finally:
        assets.close()
    assert source.closed


def test_startup_full_video_prefix_can_still_accept_other_head_without_extra_video_slot():
    rows = events(4)
    reordered = [row for row in rows if row[0]['kind'] == 'video_pair'] + [rows[1]]
    assets = M['Assets'](Source(reordered))
    try:
        assets.prefill(5)
        assert assets.counts == dict(video_pair=4, audio_block=1)
        assert assets.geometry == (2, 2)
    finally:
        assets.close()


def test_fixed_anchor_independent_targets_complete_all_calls_and_release_leases():
    clock = OLD['Clock']()
    assets = M['Assets'](Source(events()))
    assets.prefill(5)
    scheduler = M['Scheduler'](assets, .5, 250, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    try:
        scheduler.run(assets, video, audio, OLD['Executor'](clock, [100_000_000]))
        result = scheduler.result()
        assert scheduler.completed == dict(video_pair=12, audio_block=12)
        assert result['submitted'] == scheduler.completed
        assert assets.source_end and video.finished and audio.finished
        assert not assets.owned
        starts = [a for a in scheduler.actions if a['kind'] == 'output_call_submitted']
        for action in starts:
            relative = M['PLAY']['fraction'](action['source_at']) * 1_000_000_000
            assert action['target_monotonic_ns'] == scheduler.anchor + relative.numerator // relative.denominator
        audio_starts = [a['started_monotonic_ns'] for a in starts if a['track'] == 'audio_block']
        assert audio_starts[1] - scheduler.anchor < 100_000_000
    finally:
        assets.close()


@pytest.mark.parametrize('failure', ['late', 'source', 'drain', 'cancel'])
def test_failure_aborts_before_lease_close_and_never_reports_clean_output(failure):
    clock = OLD['Clock']()
    source = Source(events(4) if failure == 'source' else events(), BrokenPipeError('source interrupted') if failure == 'source' else None)
    assets = M['Assets'](source)
    assets.prefill(5)
    scheduler = M['Scheduler'](assets, .5, 20 if failure == 'late' else 250, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    if failure == 'drain':
        def fail(_timeout):
            raise ValueError('drain failed')
        audio.finish = fail
    if failure == 'cancel':
        scheduler.cancel.set()
    receipt: dict[str, Any] = {}
    with pytest.raises((ValueError, BrokenPipeError)):
        try:
            scheduler.run(assets, video, audio, OLD['Executor'](clock, [500_000_000] if failure == 'late' else []))
        finally:
            M['cleanup'](assets, scheduler, None, (video, audio), receipt, True)
    assert video.aborted and audio.aborted and source.closed
    assert not assets.owned and not scheduler.finished
    assert not any(receipt['lookahead']['owned_bytes'].values())
    if failure == 'source':
        assert sum(scheduler.completed.values()) > 0  # Valid prefix already output.


def test_failed_async_job_retains_lease_credit_until_explicit_abort_cleanup():
    clock = OLD['Clock']()
    assets = M['Assets'](Source(events(1)))
    assets.prefill(5)
    scheduler = M['Scheduler'](assets, .5, 250, clock=clock.read, pause=clock.sleep)
    scheduler.anchor = clock.read()
    class Broken(BackendBase):
        def present(self, *_args):
            raise BrokenPipeError('output failed')
    video, audio = Broken(clock), OLD['Backend'](clock)
    scheduler.dispatch(assets, dict(video_pair=video, audio_block=audio), OLD['Executor'](clock))
    lease = assets.owned['local-pair:1']['data']
    with pytest.raises(BrokenPipeError):
        scheduler.harvest()
    assert not lease.store.closed and assets.counts['video_pair'] == 1
    M['cleanup'](assets, scheduler, None, (video, audio), {}, True)
    assert lease.store.closed and not assets.owned


def test_real_single_pass_cli_output_matches_original_source_policy_and_hashes(tmp_path):
    if not ctypes.util.find_library('SDL2-2.0') or not shutil.which('ffplay'):
        pytest.skip('optional SDL/ffplay unavailable')
    path = POLICY['OLD']['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    receipt = tmp_path / 'online-output.json'
    command = [sys.executable, str(SCRIPT), str(path), '--container', 'mpeg',
        '--primary-stream', '0', '--secondary-stream', '2', '--audio-stream', '1', '--play',
        '--pairing', 'exact-pts', '--timing', 'host-submission', '--layout', 'side-by-side',
        '--processor', 'passthrough', '--audio-overlap-policy', 'bounded-serial-pcm',
        '--max-audio-overlap-ms', '1', '--max-audio-phase-ms', '1', '--receipt', str(receipt)]
    result = subprocess.run(command, env=dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy'),
        capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr
    r = json.loads(receipt.read_text())
    assert r['status'] == 'completed' and not r['cleanup_errors']
    assert r['input_decode']['status'] == r['online_policy']['status'] == 'completed'
    assert r['input_decode']['input']['verified_source_end'] and r['lookahead']['verified_prepared_source_end']
    assert r['scheduler']['outputs_finished'] and r['scheduler']['submitted'] == r['scheduler']['completed']
    assert r['scheduler']['completed']['video_pair'] > 0 and r['scheduler']['completed']['audio_block'] > 0
    assert not r['lookahead']['owned_ids'] and not r['physical_av_sync_measured']
    for action in r['scheduler']['actions']:
        if action['kind'] == 'output_call_submitted':
            offset = M['PLAY']['fraction'](action['source_at']) * 1_000_000_000
            assert action['target_monotonic_ns'] == r['scheduler']['host_anchor_monotonic_ns'] + offset.numerator // offset.denominator


def test_lease_preparation_failure_keeps_reserved_credit_until_cleanup(monkeypatch):
    def fail(*_args):
        raise OSError('lease preparation failed')
    monkeypatch.setitem(M['CHANNEL'], 'Lease', fail)
    source = Source(events(1))
    assets = M['Assets'](source)
    with pytest.raises(OSError, match='lease preparation'):
        assets.pump()
    assert assets.counts['video_pair'] == 1 and assets.owned['local-pair:1']['data'] is None
    assert assets.timings[-1]['status'] == 'failed'
    M['cleanup'](assets, None, None, (None, None), {}, True)
    assert source.closed and not assets.owned


def test_executor_cleanup_error_does_not_skip_source_or_lease_cleanup():
    class BrokenExecutor:
        def shutdown(self, **_kwargs):
            raise RuntimeError('executor cleanup failed')
    source = Source(events(1))
    assets = M['Assets'](source)
    assets.prefill(5)
    lease = assets.owned['local-pair:1']['data']
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='executor cleanup'):
        M['cleanup'](assets, None, BrokenExecutor(), (None, None), report, False)
    assert source.closed and lease.store.closed and not assets.owned
    assert report['cleanup_errors'] == ['executor cleanup failed']


def test_cancelled_main_restores_signal_handler_and_refuses_receipt_reuse(monkeypatch, tmp_path):
    path = tmp_path / 'cancelled.json'
    monkeypatch.setitem(M['PLAY'], 'arguments', lambda: SimpleNamespace(receipt=path))
    def cancel(*_args):
        raise KeyboardInterrupt
    monkeypatch.setitem(M['main'].__globals__, 'playback', cancel)
    previous = signal.getsignal(signal.SIGTERM)
    assert M['main']() == 130 and signal.getsignal(signal.SIGTERM) == previous
    original = path.read_bytes()
    assert json.loads(original)['status'] == 'cancelled'
    assert M['main']() == 2 and path.read_bytes() == original
