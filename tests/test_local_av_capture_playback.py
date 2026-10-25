"""Guarded prefix output requires acquisition policy, output acks and clean drain."""
from concurrent.futures import Future
import copy
import os
from pathlib import Path
import runpy
from threading import Event, Thread, get_ident
import time
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi import stream_selection
from pyezvizapi.clip import AutoClipSource, CloudClipSource
from pyezvizapi.media import CaptureLimits

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_capture_playback.py'))
PREP = M['PREPARE']
OUT = M['OUTPUT']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_online_playback.py')))
OWNER = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture.py')))['Owner']
BackendBase: Any = OLD['BackendBase']
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed output')


def arguments(**changes):
    values = dict(primary_stream=0, secondary_stream=2, audio_stream=1,
        audio_overlap_policy='bounded-serial-pcm', max_audio_overlap_ms=1, max_audio_phase_ms=1,
        video_transport='sealed-store', container='mpeg', deadline=5, max_late_ms=250,
        mono_option='channels', play=True, pairing='exact-pts', timing='host-submission',
        layout='side-by-side', processor='passthrough')
    values.update(changes)
    return SimpleNamespace(**values)


class Executor:
    def __init__(self, **_kwargs):
        self.joined = False
    def submit(self, fn, *args):
        future: Future[Any] = Future()
        try:
            future.set_result(fn(*args))
        except Exception as error:
            future.set_exception(error)
        return future
    def shutdown(self, **_kwargs):
        self.joined = True


@pytest.fixture
def rig(tmp_path, monkeypatch):
    raw = OLD['POLICY']['OLD']['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True).read_bytes()
    monkeypatch.setattr(PREP['CAPTURE']['DECRYPT']['Decryptor'], 'decode', lambda _self, chunk: chunk)
    clock = OLD['OLD']['Clock']()
    video, audio = BackendBase(clock), BackendBase(clock)
    present = video.present
    def acknowledged(identity, data, timeout):
        present(identity, data, timeout)
        return dict(kind='presented', pair_id=identity, bytes=len(data), pixel_sha256=data.pair_sha256)
    video.present = acknowledged
    titles = []
    def output(*_args, **kwargs):
        titles.append(kwargs.get('title'))
        return video
    monkeypatch.setitem(OUT['CHANNEL'], 'Output', output)
    monkeypatch.setitem(OUT['PLAY']['PCM'], 'Ffplay', lambda **_kwargs: audio)
    namespace = OUT['play_prepared'].__globals__
    scheduler = OUT['Scheduler']
    def pause(seconds):
        clock.sleep(seconds)
        time.sleep(.001)  # Allow the actual source worker to run under the fake clock.
    monkeypatch.setitem(namespace, 'Scheduler', lambda *args: scheduler(*args, clock=clock.read, pause=pause))
    monkeypatch.setitem(namespace, 'ThreadPoolExecutor', Executor)
    return raw, video, audio, titles


def play(rig, report, *, args=None, **kwargs):
    raw = rig[0]
    owner = OWNER([raw[i:i+1024] for i in range(0, len(raw), 1024)])
    limits = CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60)
    options = dict(limits=limits, codec='hevc', completion='bounded-prefix')
    options.update(kwargs)
    return owner, lambda: M['capture_playback'](owner, 'camera-key', args or arguments(), report, **options)


def test_success_requires_same_origin_targets_all_calls_and_clean_drains(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    run()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    prepared, output = report['preparation'], report['output']
    assert prepared['status'] == 'prepared-prefix-ended'
    assert prepared['accepted_prefix_clear_sha256'] == report['accepted_prefix_clear_sha256']
    assert output['scheduler']['outputs_finished'] and output['scheduler']['completed'] == output['scheduler']['submitted']
    assert rig[1].finished and rig[2].finished and rig[1].aborted and rig[2].aborted
    assert rig[3] == ['Bounded capture prefix (host submissions; not device sync)']
    assert not report['whole_source_complete'] and not report['network_eof_verified']
    assert not report['physical_av_sync_measured']
    scheduler = output['scheduler']
    for action in scheduler['actions']:
        if action['kind'] == 'output_call_submitted':
            offset = OUT['PLAY']['fraction'](action['source_at']) * 1_000_000_000
            assert action['target_monotonic_ns'] == scheduler['host_anchor_monotonic_ns'] + offset.numerator // offset.denominator
    assert not output['lookahead']['owned_ids'] and not output['lookahead']['pending_preparation']


@pytest.mark.parametrize('changes', [dict(play=False), dict(video_transport='socket'), dict(container='auto'),
    dict(primary_stream=1), dict(audio_overlap_policy='guess'), dict(max_late_ms=251), dict(max_late_ms=True),
    dict(deadline=float('nan')), dict(deadline=31), dict(deadline=True), dict(mono_option='guess'),
    dict(pairing='guess'), dict(timing='guess'), dict(layout='guess'), dict(processor='guess')])
def test_invalid_output_options_do_not_claim_capture_or_open_backends(rig, changes):
    report: dict[str, Any] = {'status': 'prefix-output-completed', 'accepted_prefix_clear_sha256': 'stale'}
    owner, run = play(rig, report, args=arguments(**changes))
    with pytest.raises(ValueError):
        run()
    assert not owner.started and not owner.closed and not rig[3]
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['preparation'] and not report['output']


def test_already_started_capture_is_not_cancelled(rig):
    owner, run = play(rig, {})
    owner.started = True
    with pytest.raises(ValueError, match='pristine'):
        run()
    assert not owner.closed and not rig[3]


def test_output_constructor_failure_closes_active_capture_and_sealed_leases(rig, monkeypatch):
    def fail(**_kwargs):
        raise OSError('audio constructor failed')
    monkeypatch.setitem(OUT['PLAY']['PCM'], 'Ffplay', fail)
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    with pytest.raises(OSError, match='audio constructor'):
        run()
    assert owner.closed and rig[1].aborted
    assert report['status'] == 'failed' and report['accepted_prefix_clear_sha256'] is None
    assert not report['output']['lookahead']['owned_ids']


def test_unstarted_preparation_is_closed_if_output_setup_fails_before_pull(rig, monkeypatch):
    primary = BrokenPipeError('setup failure')
    def fail(*_args, **_kwargs):
        raise primary
    monkeypatch.setitem(OUT, 'play_prepared', fail)
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    owner.close_error = True
    with pytest.raises(BrokenPipeError) as caught:
        run()
    assert caught.value is primary and owner.closed and not owner.started
    assert report['cleanup_error_types'] == ['OSError']


@pytest.mark.parametrize('failure', ['capture-end', 'ambiguous-end', 'source', 'output', 'drain', 'cancel'])
def test_late_failures_abort_output_and_never_upgrade_prefix(rig, failure):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, completion='reject' if failure=='capture-end' else 'bounded-prefix')
    if failure == 'ambiguous-end':
        owner.reason = 'upstream_ended'
    if failure == 'source':
        owner.error = BrokenPipeError('source error')
    if failure in ('output', 'drain'):
        def fail(*_args):
            raise OSError('backend failed')
        if failure == 'output':
            rig[1].present = fail
        else:
            rig[2].finish = fail
    if failure == 'cancel':
        def cancel():
            raise KeyboardInterrupt
        rig[1].alive = cancel
    with pytest.raises((ValueError, OSError, KeyboardInterrupt)):
        run()
    assert owner.closed and report['status'] == ('cancelled' if failure=='cancel' else 'failed')
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['output']['lookahead']['owned_ids']
    assert not any(report['output']['lookahead']['owned_bytes'].values())
    if report['output']['output_devices_opened']:
        assert rig[1].aborted


def test_cleanup_only_error_not_hidden_inside_unrelated_caller_exception(rig):
    def fail():
        raise OSError('cleanup failed')
    rig[1].abort = fail
    report: dict[str, Any] = {}
    owner, run = play(rig, report)
    try:
        raise LookupError('ambient')
    except LookupError:
        with pytest.raises(ValueError, match='cleanup failed'):
            run()
    assert owner.closed and report['status'] == 'failed'
    assert report['accepted_prefix_clear_sha256'] is None and report['output']['cleanup_errors']


@pytest.mark.parametrize('path,value', [
    ('preparation.status', 'running'), ('output.scheduler.outputs_finished', False),
    ('output.scheduler.completed.video_pair', 0), ('output.scheduler.partial_audio_bytes', 1),
    ('output.scheduler.failed', {'video_pair': 'failed'}), ('output.cleanup_errors', ['failed']),
    ('output.lookahead.verified_prepared_source_end', False), ('output.lookahead.pending_preparation', ['pending']),
    ('output.lookahead.owned_bytes.video_pair', 1), ('output.lookahead.offered.audio_block', 0),
])
def test_partial_receipts_cannot_claim_output_completion(rig, path, value):
    report: dict[str, Any] = {}
    _owner, run = play(rig, report)
    run()
    changed = copy.deepcopy(report)
    parts = path.split('.')
    target = changed
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    with pytest.raises(ValueError, match='terminal checks'):
        M['verify_output'](changed['preparation'], changed['output'])


def test_explicit_pes_selection_reaches_output_without_changing_source_indices(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, args=arguments(secondary_stream=1, audio_stream=2),
                      pes_ids=(0xE0, 0xE1, 0xC0))
    run()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    selection = report['preparation']['decode']['track_selection']
    assert selection['video_indices'] == [0, 2] and selection['audio_index'] == 1
    assert report['preparation']['online']['track_selection'] == selection
    assert rig[1].finished and rig[2].finished


def test_missing_pes_identity_fails_before_output_opens(rig):
    report: dict[str, Any] = {}
    owner, run = play(rig, report, pes_ids=(0xE0, 0xEF, 0xC0))
    with pytest.raises(ValueError, match='identity'):
        run()
    assert owner.closed and not rig[3] and report['output']['output_devices_opened'] is False
    assert report['accepted_prefix_clear_sha256'] is None


def session(rig, report, **changes):
    owner, _run = play(rig, {})
    options = dict(limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216,
        duration_seconds=60), codec='hevc', completion='bounded-prefix')
    options.update(changes)
    return owner, M['CapturePlayback'](owner, 'camera-key', arguments(), report, **options)


def test_pending_capture_is_lazy_then_matches_synchronous_output(rig):
    baseline: dict[str, Any] = {}
    _owner, run = play(rig, baseline)
    run()
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, pes_ids=(0xE0, 0xE1, 0xC0))
    assert not owner.started and not owner.closed and report['status'] == 'ready'
    capture.play()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    state = report['source_pull']
    assert state['source_ended'] and state['iterator_closed'] and not state['worker_alive']
    assert not state['abandoned'] and not state['outstanding']
    assert report['output']['scheduler']['completed'] == baseline['output']['scheduler']['completed']
    assert report['accepted_prefix_clear_sha256'] == baseline['accepted_prefix_clear_sha256']
    assert report['preparation']['decode']['preparation'] == baseline['preparation']['decode']['preparation']
    assert not report['output']['lookahead']['input_reservation']
    with pytest.raises(ValueError, match='single-use'):
        capture.play()


def test_pending_unstarted_close_releases_owner_on_worker(rig):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report)
    threads = []
    original = owner.close
    def close():
        threads.append(get_ident())
        original()
    # The interrupt hook was bound at construction; no read means no interrupt.
    owner.close = close
    capture.close()
    assert owner.closed and not owner.started and owner.close_calls == 1
    assert threads == [capture.pull.worker.ident] and threads != [get_ident()]
    assert report['status'] == 'consumer-closed'
    assert not report['source_pull']['worker_alive']
    capture.close()
    assert owner.close_calls == 1


@pytest.mark.parametrize('kind', ['options', 'policy', 'limits', 'pes', 'used'])
def test_pending_invalid_construction_never_claims_owner(rig, kind):
    owner, _ = play(rig, {})
    opts: dict[str, Any] = dict(limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60))
    args = arguments()
    if kind == 'options':
        args.deadline = True
    elif kind == 'policy':
        args.audio_overlap_policy = 'guess'
    elif kind == 'limits':
        opts['limits'] = None
    elif kind == 'pes':
        opts['pes_ids'] = (0xE0, 0xE0, 0xC0)
    else:
        owner.started = True
    report = {'accepted_prefix_clear_sha256': 'stale'}
    with pytest.raises(ValueError):
        M['CapturePlayback'](owner, 'key', args, report, **opts)
    assert not owner.closed and not rig[3]
    assert report['accepted_prefix_clear_sha256'] is None
    assert report['error_type'] == 'ValueError'


def test_pending_thread_start_failure_releases_unstarted_owner(rig, monkeypatch):
    thread = OUT['PULL']['PreparedPull'].__init__.__globals__['Thread']
    def fail(_self):
        raise RuntimeError('thread start failed')
    monkeypatch.setattr(thread, 'start', fail)
    owner, _ = play(rig, {})
    report: dict[str, Any] = {}
    with pytest.raises(RuntimeError, match='thread start'):
        M['CapturePlayback'](owner, 'key', arguments(), report,
            limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60))
    assert owner.closed and not owner.started and owner.close_calls == 1


@pytest.mark.parametrize('failure', ['capture-end', 'source', 'output', 'drain', 'cancel'])
def test_pending_failures_join_worker_and_preserve_primary(rig, failure):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, completion='reject' if failure == 'capture-end' else 'bounded-prefix')
    if failure == 'source':
        owner.error = BrokenPipeError('source error')
    if failure in ('output', 'drain'):
        def fail(*_args):
            raise OSError('backend failed')
        if failure == 'output':
            rig[1].present = fail
        else:
            rig[2].finish = fail
    if failure == 'cancel':
        def cancel():
            raise KeyboardInterrupt
        rig[1].alive = cancel
    with pytest.raises((ValueError, OSError, KeyboardInterrupt)):
        capture.play()
    assert owner.closed and not report['source_pull']['worker_alive']
    assert report['accepted_prefix_clear_sha256'] is None
    assert report['status'] == ('cancelled' if failure == 'cancel' else 'failed')
    assert not report['output']['lookahead']['owned_ids']


def test_pending_stalled_transport_interrupts_then_worker_closes_pipeline(rig, monkeypatch):
    entered, release = Event(), Event()
    owner, _ = play(rig, {})
    close_threads = []
    original = owner.close
    def close():
        close_threads.append(get_ident())
        original()
        release.set()
    owner.close = close
    original_packets = owner.iter_media_packets
    def packets(**kwargs):
        entered.set()
        if not release.wait(2):
            raise TimeoutError('test transport was not interrupted')
        yield from original_packets(**kwargs)
    owner.iter_media_packets = packets
    report: dict[str, Any] = {}
    capture = M['CapturePlayback'](owner, 'key', arguments(), report,
        limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        codec='hevc', completion='bounded-prefix')
    capture.pull.request()
    try:
        assert entered.wait(2)
        capture.close()
        assert close_threads[0] == get_ident()
        assert close_threads[-1] == capture.pull.worker.ident
        assert report['source_pull']['interrupt_called']
        assert report['source_pull']['iterator_closed'] and not report['source_pull']['worker_alive']
        assert report['accepted_prefix_clear_sha256'] is None
    finally:
        release.set()
        capture.close()


def test_pending_join_timeout_retains_pipeline_for_recovery(rig, monkeypatch):
    entered, release = Event(), Event()
    owner, _ = play(rig, {})
    owner.close = lambda: None  # Explicitly model an ineffective transport interrupt.
    original_packets = owner.iter_media_packets
    def packets(**kwargs):
        entered.set()
        if not release.wait(3):
            raise TimeoutError('test release missing')
        yield from original_packets(**kwargs)
    owner.iter_media_packets = packets
    report: dict[str, Any] = {}
    capture = M['CapturePlayback'](owner, 'key', arguments(), report,
        limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        codec='hevc', completion='bounded-prefix')
    closed_on = []
    source = capture.pull.iterator
    close = source.close
    def tracked_close():
        closed_on.append(get_ident())
        close()
    monkeypatch.setattr(source, 'close', tracked_close)
    capture.pull.request()
    try:
        assert entered.wait(2)
        with pytest.raises(OUT['PULL']['PullCleanupError'], match='ownership retained'):
            capture.close(.001)
        assert capture.pull.iterator is source and not closed_on
        assert report['source_pull']['worker_alive'] and report['status'] == 'failed'
        assert report['accepted_prefix_clear_sha256'] is None
    finally:
        release.set()
        capture.close(2)
    assert closed_on == [capture.pull.worker.ident]
    assert not report['source_pull']['worker_alive'] and report['source_pull']['iterator_closed']
    assert report['status'] == 'failed'  # Recovery must not upgrade the verdict.


def test_pending_early_output_failure_preserves_primary_with_cleanup_error(rig, monkeypatch):
    primary = BrokenPipeError('before first pull')
    def fail(*_args, **_kwargs):
        raise primary
    monkeypatch.setitem(OUT, 'play_prepared', fail)
    report: dict[str, Any] = {}
    owner, capture = session(rig, report)
    owner.close_error = True
    with pytest.raises(BrokenPipeError) as caught:
        capture.play()
    assert caught.value is primary and owner.closed and not owner.started
    assert report['error_type'] == 'BrokenPipeError'
    assert report['cleanup_error_types'] == ['OSError', 'PullCleanupError']
    assert not report['source_pull']['worker_alive']
    assert report['source_pull']['close_error_type'] == 'OSError'
    assert report['accepted_prefix_clear_sha256'] is None


def test_pending_play_timeout_retains_live_session_without_consumer_close(rig, monkeypatch):
    entered, release = Event(), Event()
    owner, capture = session(rig, {})
    # Stall the preparation iterator itself, to assert consumer code never
    # attempts generator.close while next is executing on the source worker.
    source = capture.pull.iterator
    original = source.events
    def stalled():
        entered.set()
        if not release.wait(3):
            raise TimeoutError('test release missing')
        yield from original
    source.events = stalled()
    capture.pull.interrupt = lambda: None
    def fail(pull, *_args, **_kwargs):
        pull.request()
        assert entered.wait(2)
        pull.close(.001)
    monkeypatch.setitem(OUT, 'play_prepared', fail)
    try:
        with pytest.raises(OUT['PULL']['PullCleanupError'], match='ownership retained'):
            capture.play()
        assert capture.report['source_pull']['worker_alive']
        assert capture.pull.iterator is source and not owner.closed
        assert capture.report['status'] == 'failed'
    finally:
        release.set()
        capture.close(2)
    assert owner.closed and not capture.report['source_pull']['worker_alive']
    assert capture.report['accepted_prefix_clear_sha256'] is None


@pytest.mark.parametrize('phase', ['read', 'startup'])
def test_pending_real_capture_owner_quiesces_transport_after_interrupt(rig, monkeypatch, phase):
    entered, release = Event(), Event()
    class Transport:
        closes = 0
        def start(self, **_kwargs):
            if phase == 'startup':
                entered.set()
                if not release.wait(3):
                    raise TimeoutError('test startup not released')
        def close(self):
            self.closes += 1
            if phase == 'read':
                release.set()
    transport = Transport()
    def open_transport(*_args, **_kwargs):
        return transport
    class Adapter:
        def iter_media_packets(self, **_kwargs):
            entered.set()
            if not release.wait(3):
                raise TimeoutError('test IO not interrupted')
            raise BrokenPipeError('transport interrupted')
    monkeypatch.setattr(stream_selection, 'select_stream_source', lambda *_a, **_k: CloudClipSource())
    monkeypatch.setattr(stream_selection, 'open_cloud_stream', open_transport)
    monkeypatch.setattr(stream_selection, 'vtm_media_packet_source', lambda *_a, **_k: Adapter())
    owner = stream_selection.AutoMediaStream(object(), 'private-replay', AutoClipSource())
    report: dict[str, Any] = {}
    capture = M['CapturePlayback'](owner, 'key', arguments(), report,
        limits=CaptureLimits(max_packets=100, max_bytes=16777216, duration_seconds=60),
        completion='bounded-prefix', codec='hevc')
    capture.pull.request()
    try:
        assert entered.wait(2)
        if phase == 'startup':
            with pytest.raises(OUT['PULL']['PullCleanupError'], match='ownership retained'):
                capture.close(.001)
            assert owner.capture_result['startup_in_progress']
            assert not owner.capture_result['transport_closure_verified']
            assert transport.closes == 1 and report['source_pull']['worker_alive']
            release.set()
        capture.close(2)
        result = owner.capture_result
        assert result['owner_closed'] and not result['startup_in_progress']
        assert result['transport_closure_verified'] and result['transports_released'] == 1
        assert transport.closes == (2 if phase == 'startup' else 1)
        assert not report['source_pull']['worker_alive']
        assert report['source_pull']['iterator_closed'] and report['source_pull']['interrupt_called']
        assert report['accepted_prefix_clear_sha256'] is None
    finally:
        release.set()
        capture.close(2)


@pytest.mark.parametrize('identity_mode', ['full-history', 'source-sequence'])
def test_stop_before_play_is_idempotent_without_acquisition(rig, identity_mode):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, identity_mode=identity_mode)
    capture.request_stop()
    capture.request_stop()
    with pytest.raises(OUT['PlaybackStopped']):
        capture.play()
    assert owner.closed and not owner.started and not rig[3]
    assert report['status'] == 'cancelled' and report['stop_requested']
    assert not report['output']['output_devices_opened']
    assert report['source_pull']['iterator_closed'] and not report['source_pull']['worker_alive']
    assert report['accepted_prefix_clear_sha256'] is None


def test_external_stop_interrupts_stalled_prefill_on_playback_owner(rig):
    entered, release = Event(), Event()
    owner, _ = play(rig, {})
    close_threads, request_threads = [], []
    original_close = owner.close
    def close():
        close_threads.append(get_ident())
        original_close()
        release.set()
    owner.close = close
    original_packets = owner.iter_media_packets
    def packets(**kwargs):
        entered.set()
        if not release.wait(3):
            raise TimeoutError('test transport not interrupted')
        yield from original_packets(**kwargs)
    owner.iter_media_packets = packets
    report: dict[str, Any] = {}
    capture = M['CapturePlayback'](owner, 'key', arguments(), report,
        limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        codec='hevc', completion='bounded-prefix')
    def request():
        if entered.wait(2):
            request_threads.append(get_ident())
            capture.request_stop()
    requester = Thread(target=request)
    requester.start()
    try:
        with pytest.raises(OUT['PlaybackStopped']):
            capture.play()
    finally:
        release.set()
        requester.join(2)
        capture.close(2)
    assert request_threads and not requester.is_alive()
    assert close_threads[0] == get_ident() and close_threads[-1] == capture.pull.worker.ident
    assert request_threads[0] not in close_threads
    assert report['source_pull']['interrupt_called'] and report['source_pull']['iterator_closed']
    assert not report['source_pull']['worker_alive'] and report['status'] == 'cancelled'
    assert not report['output']['lookahead']['owned_ids']
    assert not report['output']['lookahead']['input_reservation']
    assert report['accepted_prefix_clear_sha256'] is None


def test_stop_during_video_constructor_skips_audio_and_aborts_owned_video(rig, monkeypatch):
    report: dict[str, Any] = {}
    _owner, capture = session(rig, report)
    def video(*_args, **_kwargs):
        capture.request_stop()
        return rig[1]
    def audio(**_kwargs):
        pytest.fail('audio must not open after stop')
    monkeypatch.setitem(OUT['CHANNEL'], 'Output', video)
    monkeypatch.setitem(OUT['PLAY']['PCM'], 'Ffplay', audio)
    with pytest.raises(OUT['PlaybackStopped']):
        capture.play()
    assert rig[1].aborted and report['status'] == 'cancelled'
    assert not report['source_pull']['worker_alive']
    assert not report['output']['lookahead']['owned_ids']


@pytest.mark.parametrize('stage', ['present', 'audio-drain', 'video-drain'])
@pytest.mark.parametrize('decoder_deadline_mode', ['wall', 'consumer-excluding'])
def test_stop_during_output_prevents_success_and_releases_every_lease(rig, stage, decoder_deadline_mode):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, decoder_deadline_mode=decoder_deadline_mode)
    backend, method = (rig[1], 'present') if stage == 'present' else (rig[2] if stage == 'audio-drain' else rig[1], 'finish')
    original = getattr(backend, method)
    def stop(*args):
        value = original(*args)
        capture.request_stop()
        return value
    setattr(backend, method, stop)
    with pytest.raises(OUT['PlaybackStopped']):
        capture.play()
    assert owner.closed and report['status'] == 'cancelled' and report['stop_requested']
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['source_pull']['worker_alive']
    assert not report['output']['lookahead']['owned_ids']
    assert not report['output']['scheduler']['outputs_finished']
    if stage == 'present':
        assert report['output']['scheduler']['submitted']['audio_block'] == 0
    if stage == 'audio-drain':
        assert not rig[1].finished

    if decoder_deadline_mode != 'wall':
        assert not report['preparation']['decode']['input']['processing_clock']['borrow_active']


def test_stop_after_success_does_not_mutate_completed_receipt(rig):
    report: dict[str, Any] = {}
    _owner, capture = session(rig, report)
    capture.play()
    before = copy.deepcopy(report)
    capture.request_stop()
    assert report == before and report['status'] == 'prefix-output-completed'


@pytest.mark.parametrize('identity_mode', ['full-history', 'source-sequence'])
def test_stop_does_not_replace_primary_source_failure(rig, monkeypatch, identity_mode):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, identity_mode=identity_mode)
    primary = BrokenPipeError('primary source failure')
    def fail(*_args, **_kwargs):
        capture.request_stop()
        raise primary
    monkeypatch.setitem(OUT, 'play_prepared', fail)
    with pytest.raises(BrokenPipeError) as caught:
        capture.play()
    assert caught.value is primary and owner.closed
    assert report['status'] == 'failed' and report['error_type'] == 'BrokenPipeError'
    assert report['accepted_prefix_clear_sha256'] is None and report['stop_requested']


def test_stop_with_ineffective_interrupt_retains_live_owner_for_rejoin(rig):
    entered, release = Event(), Event()
    owner, _ = play(rig, {})
    owner.close = lambda: None
    report: dict[str, Any] = {}
    capture = M['CapturePlayback'](owner, 'key', arguments(deadline=.1), report,
        limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
        codec='hevc', completion='bounded-prefix')
    source = capture.pull.iterator
    original = source.events
    def stall():
        entered.set()
        if not release.wait(3):
            raise TimeoutError('test source not released')
        yield from original
    source.events = stall()
    def request():
        if entered.wait(2):
            capture.request_stop()
    requester = Thread(target=request)
    requester.start()
    try:
        with pytest.raises(OUT['PlaybackStopped']):
            capture.play()
        assert report['status'] == 'cancelled' and report['source_pull']['worker_alive']
        assert capture.pull.iterator is source and not owner.closed
        assert report['output']['cleanup_errors'] and report['output']['lookahead']['input_reservation']
        assert report['accepted_prefix_clear_sha256'] is None
    finally:
        release.set()
        requester.join(2)
        capture.close(2)
    assert not report['source_pull']['worker_alive'] and report['status'] == 'cancelled'


@pytest.mark.parametrize('stage', ['cleanup', 'verification'])
def test_late_stop_cannot_upgrade_to_completed_prefix(rig, monkeypatch, stage):
    report: dict[str, Any] = {}
    _owner, capture = session(rig, report)
    if stage == 'cleanup':
        original = rig[1].abort
        def abort():
            original()
            capture.request_stop()
        rig[1].abort = abort
    else:
        namespace = capture.play.__globals__
        verify = namespace['verify_output']
        def checked(*args):
            verify(*args)
            capture.request_stop()
        monkeypatch.setitem(namespace, 'verify_output', checked)
    with pytest.raises(OUT['PlaybackStopped']):
        capture.play()
    assert report['status'] == 'cancelled' and report['stop_requested']
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['source_pull']['worker_alive']
    assert report['output']['scheduler']['outputs_finished']
    if stage == 'cleanup':
        assert report['output']['stop_requested']


def test_compact_capture_preserves_full_counts_and_limits_only_diagnostic_tail(rig):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, diagnostic_tail=2)
    capture.play()
    assert owner.closed and report['status'] == 'prefix-output-completed'
    assert report['profile'] == 'guarded-capture-pending-tail-host-submissions-v1'
    s, look = report['output']['scheduler'], report['output']['lookahead']
    audit = s['action_audit']
    assert audit['submitted'] == audit['completed'] == s['completed']
    assert audit['finalized_records'] == sum(s['completed'].values()) > 2
    assert audit['retained_records'] == 2 and len(s['actions']) == 4
    assert not audit['complete_history_retained'] and audit['complete_finalization']
    assert look['preparation_audit']['finalized_records'] == audit['finalized_records']
    assert len(look['preparation_timings']) == 2 and not look['owned_ids']
    assert not report['source_pull']['worker_alive']
    changed = copy.deepcopy(report)
    changed['output']['scheduler']['action_audit']['completed']['video_pair'] = 0
    with pytest.raises(ValueError, match='terminal counts'):
        M['verify_output'](changed['preparation'], changed['output'])


@pytest.mark.parametrize('limit', [True, 0, 129, -1, '2'])
def test_invalid_diagnostic_limit_leaves_capture_unclaimed(rig, limit):
    owner, _ = play(rig, {})
    with pytest.raises(ValueError, match='diagnostic tail'):
        M['CapturePlayback'](owner, 'key', arguments(), {},
            limits=CaptureLimits(max_packets=len(owner.bodies), max_bytes=16777216, duration_seconds=60),
            diagnostic_tail=limit)
    assert not owner.started and not owner.closed


def test_compact_stop_preserves_partial_counters_without_completion_claim(rig):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, diagnostic_tail=1)
    original = rig[1].present
    def stop(*args):
        result = original(*args)
        capture.request_stop()
        return result
    rig[1].present = stop
    with pytest.raises(OUT['PlaybackStopped']):
        capture.play()
    assert owner.closed and report['status'] == 'cancelled'
    assert report['accepted_prefix_clear_sha256'] is None
    assert not report['output']['lookahead']['owned_ids']
    audit = report['output']['scheduler']['action_audit']
    assert audit['submitted'] == report['output']['scheduler']['submitted']
    assert audit['completed'] == report['output']['scheduler']['completed']


def test_missing_compact_audit_cannot_claim_terminal_completion(rig):
    report: dict[str, Any] = {}
    _owner, capture = session(rig, report, diagnostic_tail=1)
    capture.play()
    for section, field in [('scheduler', 'action_audit'), ('lookahead', 'preparation_audit')]:
        changed = copy.deepcopy(report['output'])
        del changed[section][field]
        with pytest.raises(ValueError, match='terminal counts'):
            M['verify_output'](report['preparation'], changed)


def test_compact_diagnostic_failure_does_not_replace_primary_preparation_error(rig, monkeypatch):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, diagnostic_tail=2)
    primary = OSError('original preparation error')
    def fail(*_args):
        raise primary
    monkeypatch.setattr(OUT['Assets'], 'prepare', staticmethod(fail))
    records = OUT['AUDIT']['Records']
    append = records.append
    def record(self, row):
        if row.get('status') == 'failed':
            raise ValueError('diagnostic admission failed')
        append(self, row)
    monkeypatch.setattr(records, 'append', record)
    with pytest.raises(OSError) as caught:
        capture.play()
    assert caught.value is primary and owner.closed
    assert not report['output']['lookahead']['owned_ids']
    assert not report['source_pull']['worker_alive']
    assert report['output']['lookahead']['preparation_audit']['error_count'] > 0
    assert report['accepted_prefix_clear_sha256'] is None


def test_oversize_failure_diagnostic_preserves_backend_error_and_cleanup(rig):
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, diagnostic_tail=2)
    primary = OSError('x' * 5000)
    def fail(*_args):
        raise primary
    rig[1].present = fail
    with pytest.raises(OSError) as caught:
        capture.play()
    assert caught.value is primary and owner.closed
    audit = report['output']['scheduler']['action_audit']
    assert audit['error_count'] == 1 and not audit['complete_finalization']
    assert not report['output']['lookahead']['owned_ids']
    assert not report['source_pull']['worker_alive'] and report['accepted_prefix_clear_sha256'] is None


def test_compact_media_receipt_is_required_and_matches_all_completed_counts(rig):
    report: dict[str, Any] = {}
    _owner, capture = session(rig, report, diagnostic_tail=1)
    capture.play()
    media = report['output']['scheduler']['action_audit']['media_receipt']
    assert media['profile'] == 'bounded-output-media-v1'
    assert media['host_anchor_monotonic_ns'] == report['output']['scheduler']['host_anchor_monotonic_ns']
    assert {k:v['completed'] for k,v in media['tracks'].items()} == report['output']['scheduler']['completed']
    for failure in ('missing', 'anchor', 'count'):
        changed = copy.deepcopy(report['output'])
        audit = changed['scheduler']['action_audit']
        if failure == 'missing':
            del audit['media_receipt']
        elif failure == 'anchor':
            audit['media_receipt']['host_anchor_monotonic_ns'] += 1
        else:
            audit['media_receipt']['tracks']['video_pair']['completed'] -= 1
        with pytest.raises(ValueError, match='media receipt'):
            M['verify_output'](report['preparation'], changed)


def test_pending_sequence_identities_preserve_compact_media_and_all_cleanup(rig):
    legacy: dict[str, Any] = {}
    _owner, baseline = session(rig, legacy, pes_ids=(0xE0, 0xE1, 0xC0), diagnostic_tail=2)
    baseline.play()
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, pes_ids=(0xE0, 0xE1, 0xC0), diagnostic_tail=2,
        identity_mode='source-sequence')
    assert not owner.started and not owner.closed
    capture.play()
    assert report['status'] == 'prefix-output-completed' and owner.closed
    preparation = report['preparation']
    audit = preparation['online']['policy']['identity_audit']
    counts = report['output']['scheduler']['completed']
    assert audit['accepted'] == counts and audit['retained_id_count'] == 0
    assert audit['audio_stream_index'] == preparation['decode']['track_selection']['audio_index'] == 1
    for field in ('mapped_metadata_sha256', 'audio_clock_rows_sha256', 'origin', 'audio_clock_contract'):
        assert preparation['online']['policy'][field] == legacy['preparation']['online']['policy'][field]
    # Frozen anchors differ between runs; relative targets and media summaries remain identical.
    for track in ('video_pair', 'audio_block'):
        actual = report['output']['scheduler']['action_audit']['media_receipt']['tracks'][track]
        expected = legacy['output']['scheduler']['action_audit']['media_receipt']['tracks'][track]
        assert actual['completed'] == expected['completed'] and actual['bytes'] == expected['bytes']
    assert not report['source_pull']['worker_alive'] and report['source_pull']['iterator_closed']
    assert not report['output']['lookahead']['owned_ids'] and not report['output']['lookahead']['input_reservation']
    M['verify_output'](preparation, report['output'])
    for path, value in [('accepted', {}), ('retained_id_count', 1), ('profile', 'old'), ('audio_stream_index', 99)]:
        changed = copy.deepcopy(preparation)
        changed['online']['policy']['identity_audit'][path] = value
        with pytest.raises(ValueError, match='identity accounting'):
            M['verify_output'](changed, report['output'])


def test_pending_invalid_identity_mode_is_rejected_before_claiming_capture(rig):
    owner, _run = play(rig, {})
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='identity mode'):
        M['CapturePlayback'](owner, 'key', arguments(), report,
            limits=CaptureLimits(duration_seconds=8), codec='hevc', completion='bounded-prefix',
            identity_mode='not-a-profile')
    assert not owner.started and not owner.closed and report['source_pull'] is None


def test_pending_opt_in_decoder_clock_composes_with_sequence_ids_and_compact_media(rig):
    legacy: dict[str, Any] = {}
    _owner, baseline = session(rig, legacy, pes_ids=(0xE0, 0xE1, 0xC0), diagnostic_tail=2)
    baseline.play()
    report: dict[str, Any] = {}
    owner, capture = session(rig, report, pes_ids=(0xE0, 0xE1, 0xC0), diagnostic_tail=2,
        identity_mode='source-sequence', decoder_deadline_mode='consumer-excluding')
    assert not owner.started and not owner.closed
    capture.play()
    assert report['status'] == 'prefix-output-completed' and owner.closed
    prep = report['preparation']
    assert prep['decoder_deadline_mode'] == 'consumer-excluding'
    assert prep['decode']['profile'] == 'standalone-chunked-consumer-excluding-v1'
    count = sum(report['output']['scheduler']['completed'].values())
    assert prep['decode']['input']['processing_clock']['completed_borrows'] == count
    assert prep['online']['policy']['identity_audit']['retained_id_count'] == 0
    assert report['accepted_prefix_clear_sha256'] == legacy['accepted_prefix_clear_sha256']
    for field in ('origin', 'mapped_metadata_sha256', 'audio_clock_rows_sha256', 'audio_clock_contract'):
        assert prep['online']['policy'][field] == legacy['preparation']['online']['policy'][field]
    assert report['output']['scheduler']['completed'] == legacy['output']['scheduler']['completed']
    assert report['source_pull']['iterator_closed'] and not report['source_pull']['worker_alive']
    assert not report['output']['lookahead']['owned_ids'] and not report['output']['lookahead']['input_reservation']
    M['verify_output'](prep, report['output'])
    mutations = [('decoder_deadline_mode', 'wall'), ('decoder_deadline_mode', 'old'),
        ('decode.profile', 'standalone-chunked-preparation-v1'), ('decode.input.processing_clock', {}),
        ('decode.input.processing_clock.borrow_active', True),
        ('decode.input.processing_clock.completed_borrows', True),
        ('decode.input.processing_clock.completed_borrows', count - 1),
        ('decode.input.processing_clock.processing_seconds', -1),
        ('decode.input.processing_clock.processing_seconds', float('nan')),
        ('decode.input.processing_clock.processing_seconds', float('inf')),
        ('decode.input.processing_clock.processing_seconds', 61),
        ('decode.input.processing_clock.processing_seconds', True),
        ('decode.input.processing_clock.wall_seconds', -1),
        ('decode.input.processing_clock.excluded_consumer_seconds', '0'),
        ('decode.input.processing_seconds_limit', 60.0), ('decode.input.processing_seconds_limit', 61),
        ('decode.input.startup_active', True), ('decode.input.startup_ready_elapsed_seconds', 6),
        ('decode.input.startup_ready_elapsed_seconds', float('nan')),
        ('decode.input.startup_seconds_limit', 6), ('decode.input.startup_byte_limit', 999),
        ('decode.startup.mode', 'default'), ('decode.input_before_cleanup', {}),
        ('decode.input_before_cleanup.processing_clock.borrow_active', True),
        ('decode.input_before_cleanup.processing_clock.profile', 'old'),
        ('decode.input_before_cleanup.processing_clock.completed_borrows', -1)]
    for path, value in mutations:
        changed = copy.deepcopy(prep)
        parts = path.split('.')
        target = changed
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = value
        with pytest.raises(ValueError):
            M['verify_output'](changed, report['output'])
    changed = copy.deepcopy(prep)
    changed.pop('decoder_deadline_mode')
    with pytest.raises(ValueError, match='mode/profile'):
        M['verify_output'](changed, report['output'])
    # Both snapshots individually valid, but cleanup may not subtract more wait
    # or move the clock backwards after producer/decoder EOF.
    for after in (dict(wall_seconds=9, processing_seconds=4, excluded_consumer_seconds=5),
                  dict(wall_seconds=11, processing_seconds=5, excluded_consumer_seconds=6)):
        changed = copy.deepcopy(prep)
        changed['decode']['input_before_cleanup']['processing_clock'].update(
            wall_seconds=10, processing_seconds=5, excluded_consumer_seconds=5)
        changed['decode']['input']['processing_clock'].update(after)
        with pytest.raises(ValueError, match='cleanup clock'):
            M['verify_output'](changed, report['output'])


@pytest.mark.parametrize('mode', [None, False, [], 'active'])
def test_pending_invalid_decoder_clock_mode_does_not_claim_capture(rig, mode):
    owner, _run = play(rig, {})
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='deadline mode'):
        M['CapturePlayback'](owner, 'key', arguments(), report, limits=CaptureLimits(duration_seconds=8),
            codec='hevc', completion='bounded-prefix', decoder_deadline_mode=mode)
    assert not owner.started and not owner.closed and report['source_pull'] is None
