"""Opt-in source stalls must not hold output ownership/acknowledgement progress."""
from pathlib import Path
import runpy
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

BASE = runpy.run_path(str(Path(__file__).with_name('test_local_av_online_playback.py')))
M, OLD = BASE['M'], BASE['OLD']
pytestmark = BASE['pytestmark']
SourceBase: Any = BASE['Source']


class GatedSource(SourceBase):
    def __init__(self, rows, gate_at=0, failure=None):
        super().__init__(rows)
        self.gate_at, self.gate_failure = gate_at, failure
        self.entered, self.resume = threading.Event(), threading.Event()
        self.threads = []
        self.interrupts = 0

    def __next__(self):
        self.threads.append(threading.get_ident())
        if self.pulls == self.gate_at:
            self.entered.set()
            assert self.resume.wait(3), 'test source was not released'
            if self.gate_failure is not None:
                raise self.gate_failure
        return super().__next__()

    def interrupt(self):
        self.interrupts += 1
        self.resume.set()

    def close(self):
        self.threads.append(threading.get_ident())
        super().close()


def setup(source, timeout=.5):
    pull = M['PULL']['PreparedPull'](source, interrupt=source.interrupt)
    return M['Assets'](pull, pending_input=True, join_timeout=timeout), pull


def until(assets, predicate):
    deadline = time.monotonic() + 3
    while not predicate():
        assets.pump()
        if time.monotonic() > deadline:
            pytest.fail('pending source did not reach expected state')
        time.sleep(.001)


def test_single_pending_read_reserves_both_unknown_tracks_and_never_blocks_poll():
    source = GatedSource(BASE['events'](1))
    assets, pull = setup(source)
    try:
        assert not source.entered.is_set() and not assets.reservation
        assert assets.pump() and source.entered.wait(1)
        assert assets.reservation == dict(video_pair=M['B']['VIDEO_BYTES'], audio_block=M['PLAY']['PCM']['PCM_BYTES'])
        for _ in range(100):
            assert not assets.pump()
        assert pull.result()['requested'] == 1 and not assets.source_end
        assert not assets.owned and assets.peak_credit_counts == dict(video_pair=1, audio_block=1)
        source.resume.set()
        until(assets, lambda: bool(assets.owned))
        assert not assets.reservation and assets.counts == dict(video_pair=1, audio_block=0)
        assert source.pulls == 1  # No implicit request while accepting the borrow.
    finally:
        assets.close()
    assert source.closed and len(set(source.threads)) == 1
    assert source.threads[0] != threading.get_ident() and not pull.result()['worker_alive']


def test_pending_credit_includes_preparing_queued_and_inflight_until_exact_release():
    source = GatedSource(BASE['events']())
    source.resume.set()
    assets, pull = setup(source)
    executor = BASE['PreparationExecutor']()
    assets.start_preparation(executor)
    try:
        until(assets, lambda: assets.counts['video_pair'] == 4)
        assert not assets.can_pull() and not assets.reservation
        requested = pull.result()['requested']
        assert not assets.pump() and pull.result()['requested'] == requested
        executor.complete()
        assert assets.pump()
        event = assets.head('video_pair')
        lease = assets.load(event)
        assert not assets.pump() and not lease.store.closed
        assets.release(M['PLAY']['identity'](event))
        assert assets.pump() and assets.reservation
        assert assets.peak_credit_counts['video_pair'] == 4
        assert assets.peak_credit_bytes['video_pair'] <= M['B']['VIDEO_BYTES']
    finally:
        assets.close()
    assert not assets.owned and not pull.result()['worker_alive']


def test_pending_startup_does_not_bypass_unknown_track_capacity():
    rows = BASE['events'](4)
    source = GatedSource([r for r in rows if r[0]['kind'] == 'video_pair'] + [rows[1]])
    source.resume.set()
    assets, pull = setup(source)
    try:
        with pytest.raises(ValueError, match='initial track interleave'):
            assets.prefill(1)
        assert source.pulls == 4 and assets.counts['video_pair'] == 4
        assert pull.result()['requested'] == 4
    finally:
        assets.close()


@pytest.mark.parametrize('ending', ['resume', 'cancel', 'source-error', 'late'])
def test_stalled_source_does_not_prevent_queued_dispatch_or_inflight_harvest(ending):
    error = OSError('source read failed') if ending == 'source-error' else None
    source = GatedSource(BASE['events'](3), gate_at=4, failure=error)
    assets, pull = setup(source)
    clock = OLD['Clock']()
    scheduler: Any = None
    checked = False
    def pause(seconds):
        nonlocal checked
        time.sleep(.001)  # Yield to the source worker, not a fake busy wait.
        clock.sleep(seconds)
        if source.entered.is_set() and scheduler.completed == dict(video_pair=2, audio_block=2) and not checked:
            checked = True
            assert pull.result()['read_active'] and assets.reservation
            assert not assets.owned  # Both delayed in-flight calls were harvested.
            if ending == 'cancel':
                scheduler.cancel.set()
            else:
                if ending == 'late':
                    clock.sleep(1)  # Original targets must fail, never rebase/drop.
                source.resume.set()
    scheduler = M['Scheduler'](assets, .5, 250, clock=clock.read, pause=pause)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    receipt: dict[str, Any] = {}
    try:
        assets.prefill(1)
        executor = OLD['Executor'](clock, [100_000_000, 50_000_000])
        if ending == 'resume':
            scheduler.run(assets, video, audio, executor)
            assert scheduler.completed == dict(video_pair=3, audio_block=3) and scheduler.finished
        elif ending == 'source-error':
            with pytest.raises(OSError) as caught:
                scheduler.run(assets, video, audio, executor)
            assert caught.value is error
        else:
            with pytest.raises(ValueError, match='cancelled' if ending == 'cancel' else 'lateness limit'):
                scheduler.run(assets, video, audio, executor)
        assert checked and scheduler.anchor == 1_000_000_000
        for action in scheduler.actions:
            if action['kind'] == 'output_call_submitted':
                offset = M['PLAY']['fraction'](action['source_at']) * 1_000_000_000
                assert action['target_monotonic_ns'] == scheduler.anchor + offset.numerator // offset.denominator
    finally:
        M['cleanup'](assets, scheduler, None, (video, audio), receipt, True)
    assert not receipt['cleanup_errors'] and not assets.reservation and not assets.owned
    assert not pull.result()['worker_alive'] and source.closed
    assert source.interrupts == int(ending == 'cancel')


def test_timeout_retains_owner_and_reservation_without_concurrent_iterator_close():
    source = GatedSource(BASE['events'](1))
    pull = M['PULL']['PreparedPull'](source, interrupt=lambda: None)
    assets = M['Assets'](pull, pending_input=True, join_timeout=.01)
    try:
        assets.pump()
        assert source.entered.wait(1)
        with pytest.raises(ValueError, match='ownership retained'):
            assets.close()
        assert not source.closed and assets.reservation
        assert assets.result()['source_pull']['worker_alive']
    finally:
        source.resume.set()
        assets.close()
    assert source.closed and not assets.reservation and not pull.result()['worker_alive']


def test_pending_prefill_timeout_interrupts_source_without_opening_output_devices(monkeypatch):
    source = GatedSource(BASE['events'](1))
    pull = M['PULL']['PreparedPull'](source, interrupt=source.interrupt)
    def forbidden(*_args, **_kwargs):
        pytest.fail('output device was opened before prefill')
    monkeypatch.setitem(M['CHANNEL'], 'Output', forbidden)
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='prefill deadline'):
        M['play_prepared'](pull, SimpleNamespace(deadline=.05), report, pending_input=True)
    assert not report['output_devices_opened'] and not report['cleanup_errors']
    assert source.closed and source.interrupts == 1
    assert not report['lookahead']['source_pull']['worker_alive']


@pytest.mark.parametrize('failure', [OSError('source failure'), KeyboardInterrupt()])
def test_source_failure_identity_survives_output_cleanup(failure):
    source = GatedSource([], failure=failure)
    source.resume.set()
    pull = M['PULL']['PreparedPull'](source, interrupt=source.interrupt)
    report: dict[str, Any] = {}
    with pytest.raises(type(failure)) as caught:
        M['play_prepared'](pull, SimpleNamespace(deadline=.5), report, pending_input=True)
    assert caught.value is failure and not report['cleanup_errors']
    assert not report['lookahead']['source_pull']['worker_alive']


def test_oversized_returned_event_retains_reservation_until_explicit_abort():
    row, _ = BASE['events'](1)[1]
    source = GatedSource([(row, (b'x' * (M['PLAY']['PCM']['PCM_BYTES'] + 1),))])
    source.resume.set()
    assets, pull = setup(source)
    try:
        with pytest.raises(ValueError, match='exceeds reserved'):
            until(assets, lambda: bool(assets.owned))
        assert assets.reservation and not assets.owned and not assets.source_end
    finally:
        assets.close()
    assert not assets.reservation and not pull.result()['worker_alive']


def test_pending_play_prepared_runs_both_outputs_and_joins_borrow_owner(monkeypatch):
    source = GatedSource(BASE['events'](3))
    source.resume.set()
    pull = M['PULL']['PreparedPull'](source, interrupt=source.interrupt)
    clock = SimpleNamespace(read=time.monotonic_ns)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    monkeypatch.setitem(M['CHANNEL'], 'Output', lambda *_a, **_k: video)
    monkeypatch.setitem(M['PLAY']['PCM'], 'Ffplay', lambda **_k: audio)
    report: dict[str, Any] = {}
    M['play_prepared'](pull, SimpleNamespace(deadline=.5, max_late_ms=250, mono_option='ch-layout'),
        report, pending_input=True)
    assert report['scheduler']['completed'] == dict(video_pair=3, audio_block=3)
    assert report['scheduler']['outputs_finished'] and not report['cleanup_errors']
    assert report['lookahead']['verified_prepared_source_end']
    assert not report['lookahead']['input_reservation'] and not report['lookahead']['owned_ids']
    assert report['lookahead']['source_pull']['consumed'] == 6
    assert not pull.result()['worker_alive'] and source.closed


@pytest.mark.parametrize('invalid', ['type', 'timeout', 'requested', 'closed'])
def test_invalid_pending_owner_is_not_claimed_or_closed_by_playback(invalid):
    source = GatedSource(BASE['events'](1))
    assets, pull = setup(source)
    try:
        if invalid == 'requested':
            pull.request()
            assert source.entered.wait(1)
        if invalid == 'closed':
            pull.close(.5)
        report: dict[str, Any] = {}
        before = pull.result()
        with pytest.raises(ValueError):
            M['play_prepared'](source if invalid == 'type' else pull,
                SimpleNamespace(deadline=0 if invalid == 'timeout' else .5), report, pending_input=True)
        assert report == {} and pull.result() == before
        assert source.closed == (invalid == 'closed')
    finally:
        assets.close()


def test_backend_failure_aborts_and_interrupts_pending_input_without_masking_output_error():
    source = GatedSource(BASE['events'](1), gate_at=2)
    assets, pull = setup(source)
    clock = OLD['Clock']()
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    primary = BrokenPipeError('output failed')
    def fail(*_args):
        assert source.entered.wait(1)
        raise primary
    video.present = fail
    scheduler = M['Scheduler'](assets, .5, 250, clock=clock.read, pause=clock.sleep)
    receipt: dict[str, Any] = {}
    try:
        assets.prefill(1)
        with pytest.raises(BrokenPipeError) as caught:
            scheduler.run(assets, video, audio, OLD['Executor'](clock))
        assert caught.value is primary
        assert assets.owned and assets.reservation  # Failed output retains its lease until abort.
    finally:
        M['cleanup'](assets, scheduler, None, (video, audio), receipt, True)
    assert video.aborted and audio.aborted and not receipt['cleanup_errors']
    assert source.interrupts == 1 and source.closed and not pull.result()['worker_alive']
    assert not assets.owned and not assets.reservation


def test_source_close_failure_blocks_clean_eof_and_remains_visible_after_output_cleanup(monkeypatch):
    source = GatedSource([])
    source.resume.set()
    def fail_close():
        raise OSError('source finalizer failed')
    monkeypatch.setattr(source, 'close', fail_close)
    assets, pull = setup(source)
    try:
        with pytest.raises(M['PULL']['PullCleanupError'], match='source close failed'):
            until(assets, lambda: assets.source_end)
        assert not assets.source_end and assets.reservation
        report: dict[str, Any] = {}
        M['cleanup'](assets, None, None, (None, None), report, True)
        assert report['cleanup_errors'] and assets.reservation
        assert report['lookahead']['source_pull']['close_error_type'] == 'OSError'
        assert not pull.result()['worker_alive']
    finally:
        # A failed finalizer is intentionally not reported as recovered by close.
        with pytest.raises(ValueError, match='cleanup failed'):
            assets.close()
