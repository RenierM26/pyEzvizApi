"""Absolute host targets, independent bounded output jobs and owned cleanup."""

import ctypes.util
from fractions import Fraction
import hashlib
import io
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

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_playback.py'
M = runpy.run_path(str(SCRIPT))
SOURCE = runpy.run_path(str(Path(__file__).with_name('test_local_av_timeline.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX SDL/PCM output')


def rational(value):
    return M['TIMELINE']['rational'](Fraction(value))


def timeline():
    return dict(events=[
        *[dict(kind='video_pair', id=f'p:{i}', at=rational(Fraction(i, 10)),
               lenses=[dict(decoded_id=f'v:{lens}:{i}', width=2, height=2) for lens in (0, 1)])
          for i in range(3)],
        *[dict(kind='audio_block', at=rational(Fraction(50 + i * 64, 1000)),
               gap_before=None if i == 0 else rational(0), block=dict(id=f'a:{i}'))
          for i in range(3)]], pending_unpaired=[])


class Clock:
    def __init__(self):
        self.now = 1_000_000_000
    def read(self):
        return self.now
    def sleep(self, seconds):
        self.now += int(seconds * 1_000_000_000)


class Backend:
    def __init__(self, clock):
        self.clock = clock
        self.driver = 'fake'
        self.calls = []
        self.chunks = []
        self.finished = self.aborted = False
    def alive(self):
        pass
    def present(self, identity, data, timeout):
        self.calls.append((identity, self.clock.read(), data))
        return dict(id=identity)
    def write(self, data):
        self.chunks.append((self.clock.read(), bytes(data[:512])))
        return min(512, len(data))
    def finish(self, timeout):
        self.finished = True
    def abort(self):
        self.aborted = True


class Future:
    def __init__(self, clock, ready, value, error):
        self.clock, self.ready, self.value, self.error = clock, ready, value, error
    def done(self):
        return self.clock.read() >= self.ready
    def result(self):
        if self.error:
            raise self.error
        return self.value


class Executor:
    def __init__(self, clock, video_delays=()):
        self.clock, self.video_delays = clock, list(video_delays)
    def submit(self, function, *args):
        delay = self.video_delays.pop(0) if args[0]['kind'] == 'video_pair' and self.video_delays else 0
        ready = self.clock.read() + delay
        value = error = None
        try:
            value = function(*args)
        except Exception as caught:
            error = caught
        return Future(self.clock, ready, value, error)


class Assets:
    def load(self, event):
        return b'v' * 12 if event['kind'] == 'video_pair' else b'a' * 2048


def setup(max_late=100, delays=()):
    clock = Clock()
    scheduler = M['Scheduler'](timeline(), 0.1, max_late, clock.read, clock.sleep)
    video, audio = Backend(clock), Backend(clock)
    executor = Executor(clock, delays)
    return scheduler, clock, video, audio, executor


def test_common_anchor_absolute_targets_and_partial_audio_writes_complete():
    s, _, video, audio, executor = setup()
    s.run(Assets(), video, audio, executor)
    r = s.result()
    assert r['completed'] == dict(video_pair=3, audio_block=3)
    assert r['outputs_finished'] and video.finished and audio.finished
    assert r['active'] == {} and r['not_submitted'] == dict(video_pair=[], audio_block=[])
    assert r['partial_audio_bytes'] == 0
    starts = [a for a in r['actions'] if a['kind'] == 'output_call_submitted']
    for action in starts:
        target = r['host_anchor_monotonic_ns'] + int(M['fraction'](action['source_at']) * 1_000_000_000)
        assert action['target_monotonic_ns'] == action['started_monotonic_ns'] == target
    assert b''.join(data for _, data in audio.chunks) == b'a' * (2048 * 3)
    assert audio.chunks[0][0] - video.calls[0][1] == 50_000_000


def test_slow_video_does_not_hold_audio_or_rebase_later_targets():
    s, _, video, audio, executor = setup(delays=(150_000_000,))
    s.run(Assets(), video, audio, executor)
    assert 150_000_000 <= video.calls[1][1] - s.anchor < 155_000_000
    assert video.calls[2][1] - s.anchor == 200_000_000
    assert audio.chunks[0][0] - s.anchor == 50_000_000
    assert s.completed == dict(video_pair=3, audio_block=3)


def test_stalled_track_exceeds_lateness_without_drop_or_clock_repair():
    s, _, video, audio, executor = setup(max_late=20, delays=(500_000_000,))
    with pytest.raises(ValueError, match='lateness limit'):
        s.run(Assets(), video, audio, executor)
    assert s.result()['not_submitted']['video_pair'] == ['p:1', 'p:2']
    assert s.result()['active']['video_pair'] == 'p:0'
    assert s.anchor == 1_000_000_000


@pytest.mark.parametrize('progress', [0, -1, 2049, True])
def test_invalid_audio_progress_fails_without_acknowledgement(progress):
    s, _, video, audio, executor = setup()
    audio.write = lambda data: progress
    with pytest.raises(ValueError, match='invalid audio'):
        s.run(Assets(), video, audio, executor)
    assert s.completed['audio_block'] == 0
    assert s.result()['failed']['audio_block'] == 'a:0'


def test_stalled_audio_deadline_and_partial_broken_pipe_are_retained():
    for partial in (False, True):
        s, _, video, audio, executor = setup(max_late=500)
        def write(data, partial=partial):
            if partial and len(data) == 2048:
                return 512
            if partial:
                raise BrokenPipeError('broken after prefix')
            raise BlockingIOError
        audio.write = write
        with pytest.raises((ValueError, BrokenPipeError)):
            s.run(Assets(), video, audio, executor)
        assert s.completed['audio_block'] == 0
        assert s.audio_partial == (512 if partial else 0)


def test_cancellation_keeps_completed_calls_and_remaining_work():
    s, clock, video, audio, executor = setup()
    def present(identity, data, timeout):
        s.cancel.set()
        return dict(id=identity)
    video.present = present
    with pytest.raises(ValueError, match='cancelled'):
        s.run(Assets(), video, audio, executor)
    assert s.completed['video_pair'] == 1
    assert s.result()['not_submitted']['video_pair'] == ['p:1', 'p:2']
    assert clock.now > s.anchor


def test_failed_drain_does_not_erase_completed_api_calls():
    s, _, video, audio, executor = setup()
    def fail(timeout):
        raise ValueError('drain failed')
    audio.finish = fail
    with pytest.raises(ValueError, match='drain failed'):
        s.run(Assets(), video, audio, executor)
    assert s.completed == dict(video_pair=3, audio_block=3)
    assert not s.finished and not video.finished


@pytest.mark.parametrize('change', ['pending', 'overlap', 'geometry', 'span', 'count'])
def test_unsupported_output_policy_rejected_before_backend_creation(change):
    t = timeline()
    assert M['validate'](t) == (2, 2)
    if change == 'pending':
        t['pending_unpaired'] = ['unmatched']
    elif change == 'overlap':
        t['events'][-1]['gap_before'] = rational(-1)
    elif change == 'geometry':
        t['events'][1]['lenses'][0]['width'] = 4
    elif change == 'span':
        t['events'][0]['at'] = rational(61)
    else:
        t['events'] = [t['events'][0]] * 301
    with pytest.raises(ValueError):
        M['validate'](t)


def test_payload_spool_hashes_and_exact_side_by_side_composition():
    pixels = io.BytesIO(b'a' * 6 + b'b' * 6)
    pcm = io.BytesIO()
    assets = M['Assets'](pixels, pcm)
    e = timeline()['events'][0]
    for lens, row in enumerate(e['lenses']):
        assets.video.records[row['decoded_id']] = dict(offset=lens * 6, size=6,
            pixel_sha256=hashlib.sha256((b'a' if lens == 0 else b'b') * 6).hexdigest())
    composed = b'aabbaabbabab'
    assert assets.load(e) == composed
    data = b'a' * 2048
    metadata = dict(id='a:0', pcm_sha256=hashlib.sha256(data).hexdigest())
    assets.capture_audio(metadata, data)
    event = dict(kind='audio_block', block=metadata)
    assert assets.load(event) == data
    with pytest.raises(ValueError):
        assets.capture_audio(metadata, data)
    pcm.seek(0)
    pcm.write(b'changed')
    with pytest.raises(ValueError, match='changed'):
        assets.load(event)
    pcm.truncate(5)
    with pytest.raises(ValueError, match='truncated'):
        assets.load(event)


def test_audio_observer_gets_verified_unchanged_pcm_and_copied_metadata():
    metadata = M['TIMELINE']['AudioMetadata']()
    record = dict(kind='decoded', id='a', media_ms=0,
                  pcm_sha256=hashlib.sha256(bytes(2048)).hexdigest())
    metadata.write(json.dumps(record))
    seen = []
    def observer(row, pcm):
        seen.append(pcm)
        row['id'] = 'changed'
    inspector = M['TIMELINE']['AudioInspector'](metadata, observer)
    inspector.write(dict(id='a', media_ms=0, pcm_s16le_b64='A' * 2731 + '='))
    assert metadata.frames[0]['id'] == 'a' and seen == [bytes(2048)]
    assert inspector.count == 1


def test_startup_failure_cleans_video_and_preserves_primary_error(monkeypatch, tmp_path):
    clock = Clock()
    backend = Backend(clock)
    temporary_files = []
    factory = M['tempfile'].TemporaryFile
    def temporary():
        stream = factory()
        temporary_files.append(stream)
        return stream
    monkeypatch.setattr(M['tempfile'], 'TemporaryFile', temporary)
    def abort():
        assert not any(stream.closed for stream in temporary_files)
        backend.aborted = True
        raise ValueError('cleanup diagnostic')
    monkeypatch.setattr(backend, 'abort', abort)
    monkeypatch.setitem(M['TIMELINE'], 'inspect', lambda *args: timeline())
    monkeypatch.setitem(M['OUTPUT'], 'Output', lambda *args, **kwargs: backend)
    def fail(**kwargs):
        raise OSError('audio startup failure')
    monkeypatch.setitem(M['PCM'], 'Ffplay', fail)
    args = SimpleNamespace(source=tmp_path / 'source', container='mpegts', primary_stream=0,
        secondary_stream=1, audio_stream=2, video_transport='socket', deadline=1, max_late_ms=50, mono_option='ch-layout')
    receipt: dict[str, Any] = {}
    with pytest.raises(OSError, match='audio startup failure'):
        M['playback'](args, receipt)
    assert backend.aborted and receipt['cleanup_errors'] == ['cleanup diagnostic']
    assert all(stream.closed for stream in temporary_files)
    assert not receipt['scheduler']['outputs_finished']


@pytest.mark.parametrize('title', ['', True, 'x' * 129])
def test_scoped_video_title_rejects_invalid_values_without_launch(title):
    with pytest.raises(ValueError, match='title'):
        M['OUTPUT']['Output'](2, 2, 1, title=title)


def command(source, receipt):
    return [sys.executable, str(SCRIPT), str(source), '--container', 'mpegts',
        '--primary-stream', '0', '--secondary-stream', '1', '--audio-stream', '2',
        '--play', '--pairing', 'exact-pts', '--timing', 'host-submission',
        '--layout', 'side-by-side', '--processor', 'passthrough', '--receipt', str(receipt)]


def test_cli_failure_receipt_and_existing_receipt_preserved(tmp_path):
    receipt = tmp_path / 'receipt.json'
    cmd = command(tmp_path / 'absent', receipt)
    p = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and json.loads(receipt.read_text())['status'] == 'failed'
    original = receipt.read_bytes()
    p = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and receipt.read_bytes() == original
    p = subprocess.run([*command(tmp_path / 'absent', tmp_path / 'invalid'), '--deadline', 'nan'],
                       capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and not (tmp_path / 'invalid').exists()


def test_optional_actual_sdl_ffplay_dummy_output(tmp_path):
    if not shutil.which('ffplay') or not ctypes.util.find_library('SDL2-2.0'):
        pytest.skip('optional SDL/ffplay output unavailable')
    source = SOURCE['encode_three_track'](tmp_path)
    receipt = tmp_path / 'output.json'
    env = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy')
    p = subprocess.run([*command(source, receipt), '--max-late-ms', '1000'],
                       env=env, capture_output=True, timeout=20, check=False)
    result = json.loads(receipt.read_text())
    assert p.returncode == 0, result.get('error') or p.stderr.decode()
    assert result['status'] == 'completed' and result['cleanup_errors'] == []
    s = result['scheduler']
    assert s['completed'] == dict(video_pair=result['timeline']['summary']['video_pairs'],
                                  audio_block=result['timeline']['summary']['audio_blocks'])
    assert s['outputs_finished'] and not s['active'] and s['partial_audio_bytes'] == 0
    assert result['video_driver'] == 'dummy' and not result['physical_av_sync_measured']
    for action in s['actions']:
        if action['kind'] == 'output_call_submitted':
            target = s['host_anchor_monotonic_ns'] + int(M['fraction'](action['source_at']) * 1_000_000_000)
            assert action['target_monotonic_ns'] == target
            assert target <= action['started_monotonic_ns'] <= target + 1_000_000_000



def test_sigterm_writes_cancelled_receipt_and_restores_handler(tmp_path, monkeypatch):
    path = tmp_path / 'cancelled.json'
    previous = signal.getsignal(signal.SIGTERM)
    monkeypatch.setitem(M['main'].__globals__, 'arguments', lambda: SimpleNamespace(receipt=path))
    def stop(args, receipt):
        signal.raise_signal(signal.SIGTERM)
    monkeypatch.setitem(M['main'].__globals__, 'playback', stop)
    assert M['main']() == 130
    assert json.loads(path.read_text())['status'] == 'cancelled'
    assert signal.getsignal(signal.SIGTERM) == previous


def test_worker_start_lateness_fails_before_backend_call():
    s, clock, video, audio, _ = setup(max_late=20)
    class LateExecutor(Executor):
        def submit(self, function, *args):
            self.clock.now += 500_000_000
            return super().submit(function, *args)
    with pytest.raises(ValueError, match='lateness limit'):
        s.run(Assets(), video, audio, LateExecutor(clock))
    assert not video.calls and not audio.chunks
    assert s.completed == dict(video_pair=0, audio_block=0)


def test_validation_failure_never_opens_output(monkeypatch, tmp_path):
    t = timeline()
    t['pending_unpaired'] = ['pending']
    monkeypatch.setitem(M['TIMELINE'], 'inspect', lambda *args: t)
    def forbidden(*args, **kwargs):
        pytest.fail('output opened before plan rejection')
    monkeypatch.setitem(M['OUTPUT'], 'Output', forbidden)
    args = SimpleNamespace(source=tmp_path / 'source', container='mpegts', primary_stream=0,
        secondary_stream=1, audio_stream=2, video_transport='socket', deadline=1, max_late_ms=50)
    receipt: dict[str, Any] = {}
    with pytest.raises(ValueError, match='unmatched'):
        M['playback'](args, receipt)
    assert receipt['cleanup_errors'] == []



def test_one_failed_track_does_not_hide_other_completed_acknowledgement():
    s, _, video, audio, executor = setup()
    s.tracks['audio_block'][0]['at'] = rational(0)
    def fail(*args):
        raise ValueError('video failed')
    video.present = fail
    with pytest.raises(ValueError, match='video failed'):
        s.run(Assets(), video, audio, executor)
    assert s.failed == dict(video_pair='p:0')
    assert s.completed == dict(video_pair=0, audio_block=1)
    assert s.result()['active'] == {} and s.audio_partial == 0
