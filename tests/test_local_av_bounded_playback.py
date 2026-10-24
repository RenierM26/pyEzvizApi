"""Rolling preparation credit, common clock, sealed descriptor ownership and EOF."""

import array
import ctypes.util
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_bounded_playback.py'
M = runpy.run_path(str(SCRIPT))
G = M['playback'].__globals__
C = M['CHANNEL']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_playback.py')))
pytestmark = pytest.mark.skipif(not hasattr(os, 'memfd_create'), reason='Linux sealed descriptors')


def pair(index=0, at=0):
    payload = (bytes([1]) * 6, bytes([2]) * 6)
    return dict(kind='video_pair', id=f'p:{index}', source_time=dict(numerator=at, denominator=1),
                lenses=[dict(decoded_id=f'v:{lens}:{index}', width=2, height=2,
                             pixel_sha256=hashlib.sha256(data).hexdigest())
                        for lens, data in enumerate(payload)]), payload


def block(index=0, at=0):
    pcm = bytes(2048)
    return dict(kind='audio_block', source_time=dict(numerator=at, denominator=1),
                block=dict(id=f'a:{index}', pcm_sha256=hashlib.sha256(pcm).hexdigest())), (pcm,)


def lookahead(events):
    return M['Lookahead'](ClosableIterator(events), [event for event, _ in events])


def test_credit_includes_active_video_and_audio_and_is_returned_only_after_ack(monkeypatch):
    monkeypatch.setitem(G, 'VIDEO_SLOTS', 1)
    events = [pair(), pair(1)]
    assets = lookahead(events)
    try:
        pumped = assets.pump()
        assert pumped
        data = assets.load(events[0][0])
        pumped = assets.pump()
        assert not pumped  # Dequeued but output has not acknowledged it.
        assert assets.result()['owned_bytes']['video_pair'] == 12
        assert not data.store.closed
        assets.release('p:0')
        assert data.store.closed
        pumped = assets.pump()
        assert pumped
        assert assets.result()['peak_owned_counts']['video_pair'] == 1
    finally:
        assets.close()
    assert assets.result()['owned_ids'] == []


def test_byte_capacity_blocks_before_advancing_decoder(monkeypatch):
    monkeypatch.setitem(G, 'VIDEO_BYTES', 12)
    events = [pair(), pair(1)]
    assets = lookahead(events)
    try:
        pumped = assets.pump()
        assert pumped
        pumped = assets.pump()
        assert not pumped and assets.index == 1
    finally:
        assets.close()


@pytest.mark.parametrize('change', ['metadata', 'hash', 'count', 'tail', 'short'])
def test_second_decode_never_substitutes_changed_media_or_silent_tails(change):
    expected, payload = pair()
    actual = json.loads(json.dumps(expected))
    source = [(actual, payload)]
    if change == 'metadata':
        actual['source_time']['numerator'] = 1
    elif change == 'hash':
        source = [(actual, (bytes(6), payload[1]))]
    elif change == 'count':
        source = [(actual, payload[:1])]
    elif change == 'tail':
        source.append(pair(1))
    else:
        source = []
    assets = M['Lookahead'](ClosableIterator(source), [expected])
    try:
        if change == 'tail':
            pumped = assets.pump()
            assert pumped
        with pytest.raises(ValueError):
            assets.pump()
    finally:
        assets.close()
    assert not any(assets.bytes.values())


def test_bounded_initial_interleave_fails_without_starting_outputs(monkeypatch):
    monkeypatch.setitem(G, 'VIDEO_SLOTS', 1)
    events = [pair(), pair(1), block()]
    assets = lookahead(events)
    timeline = dict(events=[dict(event, at=event['source_time']) for event, _ in events])
    try:
        with pytest.raises(ValueError, match='initial track interleave'):
            assets.prefill(timeline, 1)
    finally:
        assets.close()


def test_many_pairs_use_constant_lease_credit_and_close_every_descriptor(monkeypatch):
    monkeypatch.setitem(G, 'VIDEO_SLOTS', 1)
    events = [pair(i) for i in range(1000)]
    assets = lookahead(events)
    for event, _ in events:
        pumped = assets.pump()
        assert pumped
        data = assets.load(event)
        assets.release(event['id'])
        assert data.store.closed and not assets.owned
    pumped = assets.pump()
    assert pumped and assets.source_end
    assert assets.peak_bytes['video_pair'] == 12
    assets.close()


class ClosableIterator:
    def __init__(self, events):
        self.events = iter(events)
        self.closed = False
    def __next__(self):
        return next(self.events)
    def close(self):
        self.closed = True


def test_close_unwinds_preparation_iterator_and_unacknowledged_leases():
    events = [pair(), block()]
    iterator = ClosableIterator(events)
    assets = M['Lookahead'](iterator, [e for e, _ in events])
    pumped = assets.pump()
    assert pumped
    data = assets.load(events[0][0])
    assets.close()
    assert iterator.closed and data.store.closed
    assert assets.abandoned == ['p:0']


def test_common_anchor_partial_audio_and_delayed_video_keep_original_targets():
    clock = OLD['Clock']()
    events = []
    timeline = OLD['timeline']()
    for kind in ('video_pair', 'audio_block'):
        for event in timeline['events']:
            if event['kind'] != kind:
                continue
            raw, payload = pair(int(event['id'].split(':')[1])) if kind == 'video_pair' else block(int(event['block']['id'].split(':')[1]))
            raw['source_time'] = event['at']
            events.append((raw, payload))
    assets = lookahead(events)
    assets.prefill(timeline, 1)
    scheduler = M['Scheduler'](timeline, .5, 100, assets, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    try:
        scheduler.run(assets, video, audio, OLD['Executor'](clock, (150_000_000,)))
        result = scheduler.result()
        assert result['completed'] == dict(video_pair=3, audio_block=3)
        assert result['outputs_finished'] and assets.source_end
        assert assets.result()['owned_ids'] == []
        for action in result['actions']:
            if action['kind'] == 'output_call_submitted':
                offset = Fraction(**action['source_at'])
                assert action['target_monotonic_ns'] == result['host_anchor_monotonic_ns'] + int(offset * 10**9)
        assert audio.chunks[0][0] - scheduler.anchor == 50_000_000
    finally:
        assets.close()


def test_slow_track_fails_without_rebase_and_cleans_inflight_lease():
    clock = OLD['Clock']()
    events = [pair(i) for i in range(3)] + [block(i) for i in range(3)]
    assets = lookahead(events)
    timeline = OLD['timeline']()
    assets.prefill(timeline, 1)
    scheduler = M['Scheduler'](timeline, .5, 20, assets, clock=clock.read, pause=clock.sleep)
    try:
        with pytest.raises(ValueError, match='lateness'):
            scheduler.run(assets, OLD['Backend'](clock), OLD['Backend'](clock), OLD['Executor'](clock, (500_000_000,)))
        assert scheduler.anchor == 1_000_000_000
        assert scheduler.result()['not_submitted']['video_pair'] == ['p:1', 'p:2']
        assert assets.counts['video_pair'] == 3
    finally:
        assets.close()
    assert assets.counts['video_pair'] == 0


@pytest.mark.parametrize('count,token', [(0, b'F'), (2, b'F'), (1, b'X')])
def test_descriptor_protocol_rejects_extra_missing_or_wrong_marker_without_leaks(count, token):
    before = len(list(Path('/proc/self/fd').iterdir()))
    left, right = socket.socketpair()
    try:
        with C['Lease'](bytes(12)).store as store:
            # The Lease object owns this same store; no separate descriptor is hidden.
            rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [store.fileno()] * count))] if count else []
            left.sendmsg([token], rights)
            right.settimeout(.02)
            with pytest.raises(ValueError, match='exactly one'):
                C['receive_fd'](right, lambda: None, time.monotonic() + 1)
    finally:
        left.close()
        right.close()
    assert len(list(Path('/proc/self/fd').iterdir())) == before


@pytest.mark.parametrize('bad', ['hash', 'unsealed', 'size'])
def test_received_file_rejects_mutability_wrong_hash_or_wrong_extent_and_closes_fd(bad):
    store = C['SHARED']['sealed_file']()
    store.write(bytes(12))
    store.flush()
    if bad != 'unsealed':
        C['SHARED']['seal'](store)
    fd = os.dup(store.fileno())
    surface = SimpleNamespace(present=lambda _: pytest.fail('invalid bytes reached SDL'))
    try:
        with pytest.raises(ValueError):
            C['present_fd'](fd, 24 if bad == 'size' else 12, '0' * 64, surface)
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        store.close()


@pytest.mark.skipif(not ctypes.util.find_library('SDL2-2.0'), reason='SDL2 unavailable')
def test_real_descriptor_output_reuses_worker_closes_each_mapping_and_never_sends_pixels(monkeypatch):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 3)
    pid = output.process.pid
    sent = []
    original = output.transfer
    def transfer(data, deadline):
        if isinstance(data, bytes):
            sent.append(data)
        return original(data, deadline)
    output.transfer = transfer
    try:
        for index in range(3):
            lease = C['Lease'](bytes([index]) * 12)
            try:
                result = output.present(f'p:{index}', lease, 5)
                assert result['pixel_sha256'] == lease.frame.sha256
                assert output.process.pid == pid
            finally:
                lease.close()
        assert all(len(data) < 256 for data in sent)
        output.finish(5)
    finally:
        output.abort()
    assert output.process.poll() is not None


def test_real_incremental_snapshot_iterator_closes_native_container_without_false_eof(tmp_path):
    source = OLD['SOURCE']['encode_three_track_ps'](tmp_path)
    snapshot = M['DECODE']['snapshot_source'](source)
    source.write_bytes(b'changed after snapshot')
    report: dict[str, Any] = {}
    iterator = M['DECODE']['iter_snapshot'](snapshot, 'mpeg', (0, 2), 1, report)
    next(iterator)
    iterator.close()
    assert report['status'] == 'closed-before-eof'
    assert report['source_sha256'] == hashlib.sha256(snapshot).hexdigest()


def test_real_rolling_cli_completes_original_plan_and_drains_owned_workers(tmp_path):
    if not ctypes.util.find_library('SDL2-2.0') or not shutil.which('ffplay'):
        pytest.skip('optional SDL/ffplay unavailable')
    source = OLD['SOURCE']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    receipt = tmp_path / 'output.json'
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'mpeg',
        '--primary-stream', '0', '--secondary-stream', '2', '--audio-stream', '1',
        '--play', '--pairing', 'exact-pts', '--timing', 'host-submission', '--layout', 'side-by-side',
        '--processor', 'passthrough', '--receipt', str(receipt),
        '--audio-overlap-policy', 'bounded-serial-pcm', '--max-audio-overlap-ms', '1', '--max-audio-phase-ms', '1']
    result = subprocess.run(command, env=dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy'),
                            capture_output=True, timeout=20, check=False)
    output = json.loads(receipt.read_text())
    assert result.returncode == 0, output['error']
    assert output['scheduler']['completed'] == dict(video_pair=9, audio_block=5)
    assert output['lookahead']['verified_source_end'] and not output['lookahead']['owned_ids']
    assert not output['cleanup_errors'] and output['scheduler']['outputs_finished']


def test_generator_close_failure_still_releases_all_leases(monkeypatch):
    iterator = ClosableIterator([pair(), pair(1)])
    def fail_close():
        raise OSError('decoder close failed')
    monkeypatch.setattr(iterator, 'close', fail_close)
    assets = M['Lookahead'](iterator, [pair()[0], pair(1)[0]])
    assets.pump()
    assets.pump()
    stores = [row['data'].store for row in assets.owned.values()]
    with pytest.raises(ValueError, match='decoder close failed'):
        assets.close()
    assert all(store.closed for store in stores) and not assets.owned


def test_audio_startup_failure_aborts_created_video_and_closes_prepared_media(monkeypatch):
    events = [pair(), block()]
    timeline = OLD['timeline']()
    iterator = ClosableIterator(events)
    monkeypatch.setitem(M['DECODE'], 'snapshot_source', lambda _: b'compressed')
    monkeypatch.setitem(G, 'preflight', lambda *_: ([e for e, _ in events], timeline, (2, 2)))
    monkeypatch.setitem(M['DECODE'], 'iter_snapshot', lambda *_: iterator)
    video = OLD['Backend'](OLD['Clock']())
    monkeypatch.setitem(C, 'Output', lambda *_: video)
    def fail_audio(**_kwargs):
        raise OSError('audio startup failed')
    monkeypatch.setitem(M['PLAY']['PCM'], 'Ffplay', fail_audio)
    args = SimpleNamespace(source=Path('unused'), container='mpeg', primary_stream=0,
        secondary_stream=1, audio_stream=2, deadline=1, max_late_ms=250, mono_option='ch-layout', video_transport='sealed-store')
    receipt: dict[str, Any] = {}
    with pytest.raises(OSError, match='audio startup failed'):
        M['playback'](args, receipt)
    assert video.aborted and iterator.closed
    assert receipt['lookahead']['owned_ids'] == [] and not receipt['cleanup_errors']
    assert receipt['scheduler']['host_anchor_monotonic_ns'] is None


def test_drain_failure_retains_all_successful_calls_without_completed_status():
    events = [pair(i) for i in range(3)] + [block(i) for i in range(3)]
    assets = lookahead(events)
    timeline = OLD['timeline']()
    assets.prefill(timeline, 1)
    clock = OLD['Clock']()
    scheduler = M['Scheduler'](timeline, .5, 250, assets, clock=clock.read, pause=clock.sleep)
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    def failed_drain(_timeout):
        raise TimeoutError('audio drain failed')
    audio.finish = failed_drain
    try:
        with pytest.raises(TimeoutError, match='drain failed'):
            scheduler.run(assets, video, audio, OLD['Executor'](clock))
        assert scheduler.completed == dict(video_pair=3, audio_block=3)
        assert not scheduler.finished and assets.source_end
        assert not assets.owned
    finally:
        assets.close()


@pytest.mark.parametrize('enabled', [False, True])
def test_explicit_raw_probe_changes_analysis_only_not_samples_or_pipe_profile(monkeypatch, enabled):
    commands = []
    pcm = M['PLAY']['PCM']
    class Process:
        def __init__(self):
            self.stdin = SimpleNamespace(fileno=lambda: 123, close=lambda: None)
        def poll(self):
            return 0
    def spawn(command, **_kwargs):
        commands.append(command)
        return Process()
    monkeypatch.setattr(pcm['subprocess'], 'Popen', spawn)
    monkeypatch.setattr(pcm['os'], 'set_blocking', lambda *_: None)
    backend = pcm['Ffplay'](immediate_raw_probe=enabled)
    try:
        command = commands[0]
        assert ('-probesize' in command) == enabled
        assert ('-analyzeduration' in command) == enabled
        assert command[-2:] == ['-i', 'pipe:0']
        assert command[command.index('-f') + 1] == 's16le'
        assert command[command.index('-ar') + 1] == '16000'
        assert command[command.index('-ch_layout') + 1] == 'mono'
        forbidden = {'-af', '-filter:a', '-framedrop', '-fflags', '-ss', '-itsoffset'}
        assert not forbidden.intersection(command)
    finally:
        backend.abort()


def test_truncated_ancillary_and_invalid_lease_do_not_leak_descriptors():
    before = len(list(Path('/proc/self/fd').iterdir()))
    left, right = socket.socketpair()
    lease = C['Lease'](bytes(12))
    try:
        left.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array.array('i', [lease.store.fileno()] * 32))])
        right.settimeout(.02)
        with pytest.raises(ValueError, match='exactly one'):
            C['receive_fd'](right, lambda: None, time.monotonic() + 1)
    finally:
        lease.close()
        left.close()
        right.close()
    with pytest.raises(ValueError):
        C['Lease'](b'')
    assert len(list(Path('/proc/self/fd').iterdir())) == before


@pytest.mark.skipif(not ctypes.util.find_library('SDL2-2.0'), reason='SDL2 unavailable')
@pytest.mark.parametrize('bad', ['hash', 'duplicate'])
def test_real_worker_rejects_invalid_frame_and_is_reaped(monkeypatch, bad):
    monkeypatch.setenv('SDL_VIDEODRIVER', 'dummy')
    output = C['Output'](4, 2, 5, 3)
    lease = C['Lease'](bytes(12))
    try:
        if bad == 'duplicate':
            output.present('p:0', lease, 5)
        else:
            lease.frame = C['SHARED']['Frame'](0, 12, '0' * 64)
        with pytest.raises(ValueError, match=r'duplicate|fingerprint'):
            output.present('p:0', lease, 5)
    finally:
        output.abort()
        lease.close()
    assert output.process.poll() is not None


def test_cross_track_ack_survives_video_failure_and_both_credits_are_released():
    events = [pair(), block()]
    timeline = dict(events=[dict(event, at=event['source_time']) for event, _ in events])
    assets = lookahead(events)
    assets.prefill(timeline, 1)
    clock = OLD['Clock']()
    scheduler = M['Scheduler'](timeline, .5, 250, assets, clock=clock.read, pause=clock.sleep)
    scheduler.anchor = clock.read()
    video, audio = OLD['Backend'](clock), OLD['Backend'](clock)
    def failed_present(*_args):
        raise BrokenPipeError('video failed')
    video.present = failed_present
    try:
        scheduler.dispatch(assets, dict(video_pair=video, audio_block=audio), OLD['Executor'](clock))
        with pytest.raises(BrokenPipeError, match='video failed'):
            scheduler.harvest()
        assert scheduler.completed['audio_block'] == 1
        assert scheduler.failed == dict(video_pair='p:0')
        assert not assets.owned and scheduler.cancel.is_set()
    finally:
        assets.close()


def test_cancelled_scheduler_does_not_drop_or_rebase_queued_events():
    events = [pair(), block()]
    timeline = dict(events=[dict(event, at=event['source_time']) for event, _ in events])
    assets = lookahead(events)
    assets.prefill(timeline, 1)
    clock = OLD['Clock']()
    scheduler = M['Scheduler'](timeline, .5, 250, assets, clock=clock.read, pause=clock.sleep)
    scheduler.cancel.set()
    try:
        with pytest.raises(ValueError, match='cancelled'):
            scheduler.run(assets, OLD['Backend'](clock), OLD['Backend'](clock), OLD['Executor'](clock))
        assert scheduler.anchor == clock.read()
        assert scheduler.result()['not_submitted'] == dict(video_pair=['p:0'], audio_block=['a:0'])
    finally:
        assets.close()


def test_real_whole_session_overlap_rejection_precedes_devices_and_exclusive_receipt(tmp_path):
    source = OLD['SOURCE']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    receipt = tmp_path / 'output.json'
    command = [sys.executable, str(SCRIPT), str(source), '--container', 'mpeg',
        '--primary-stream', '0', '--secondary-stream', '2', '--audio-stream', '1',
        '--play', '--pairing', 'exact-pts', '--timing', 'host-submission', '--layout', 'side-by-side',
        '--processor', 'passthrough', '--receipt', str(receipt)]
    result = subprocess.run(command, capture_output=True, timeout=15, check=False)
    original = receipt.read_bytes()
    output = json.loads(original)
    assert result.returncode == 2 and output['status'] == 'failed'
    assert 'overlapping audio' in output['error'] and 'video_driver' not in output
    assert output['output_decode'] == {} and not output['cleanup_errors']
    result = subprocess.run(command, capture_output=True, timeout=5, check=False)
    assert result.returncode == 2 and receipt.read_bytes() == original
