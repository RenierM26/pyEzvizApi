"""Non-seekable compressed ownership, producer EOF and exact decoded provenance."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / 'tools/local_av_chunked.py'
M = runpy.run_path(str(SCRIPT))
D = M['DECODE']
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_incremental.py')))


class Producer:
    def __init__(self, chunks, *, failure=None, close_failure=False):
        self.chunks = iter(chunks)
        self.pulls = 0
        self.closed = 0
        self.failure = failure
        self.close_failure = close_failure
    def __iter__(self):
        return self
    def __next__(self):
        self.pulls += 1
        try:
            return next(self.chunks)
        except StopIteration:
            if self.failure:
                raise self.failure from None
            raise
    def close(self):
        self.closed += 1
        if self.close_failure:
            raise RuntimeError('producer cleanup failed')


def test_reader_never_prefetches_or_replays_and_eof_is_sticky():
    empty, ab, cdef, gh, last = b'', b'ab', b'cdef', b'gh', b'i'
    source = Producer([ab + cdef, gh + last])
    reader = M['ChunkReader'](source, 9)
    assert reader.read(0) == empty and source.pulls == 0
    assert reader.read(2) == ab and source.pulls == 1
    assert reader.result()['owned_chunk_bytes'] == 6
    assert reader.read(999999) == cdef and source.pulls == 1
    assert reader.read(2) == gh and source.pulls == 2
    assert reader.read(2) == last and reader.result()['owned_chunk_bytes'] == 0
    reader.verify_end()
    assert reader.eof and source.pulls == 3
    assert reader.read(100) == empty and source.pulls == 3
    assert reader.result()['prefix_sha256'] == hashlib.sha256(b'abcdefghi').hexdigest()
    assert not reader.seekable()
    with pytest.raises(OSError):
        reader.seek(0)
    reader.close()
    reader.close()
    assert source.closed == 1
    with pytest.raises(ValueError, match='closed'):
        reader.read(1)


def test_reader_caps_each_return_without_retaining_additional_chunks():
    data = b'x' * M['MAX_CHUNK_BYTES']
    source = Producer([data])
    reader = M['ChunkReader'](source, len(data))
    assert len(reader.read(99999999)) == M['MAX_READ_BYTES']
    assert source.pulls == 1 and reader.result()['peak_owned_chunk_bytes'] == len(data)
    reader.close()
    assert reader.result()['pending_bytes'] == 0


@pytest.mark.parametrize('chunk', [b'', bytearray(b'x'), memoryview(b'x'), 'x', b'x' * (1024 * 1024 + 1)])
def test_invalid_or_oversized_chunk_is_rejected_without_accepting_or_emitting(chunk):
    reader = M['ChunkReader'](Producer([chunk]), 2 * 1024 * 1024)
    with pytest.raises(ValueError, match='bounded chunks'):
        reader.read(1)
    assert reader.received == reader.delivered == reader.chunks == 0
    with pytest.raises(ValueError, match='previously failed'):
        reader.read(1)
    reader.close()


@pytest.mark.parametrize('limit', [0, -1, True, 256 * 1024 * 1024 + 1])
def test_invalid_limits_do_not_pull_producer(limit):
    source = Producer([b'x'])
    with pytest.raises(ValueError, match='limit'):
        M['ChunkReader'](source, limit)
    assert source.pulls == 0


def test_total_and_chunk_count_limits_and_unbounded_read_fail_closed(monkeypatch):
    abc, first = b'abc', b'a'
    reader = M['ChunkReader'](Producer([abc, b'd']), 3)
    assert reader.read(3) == abc
    with pytest.raises(ValueError, match='limit'):
        reader.read(1)
    assert reader.received == reader.delivered == 3
    reader.close()
    monkeypatch.setitem(M['ChunkReader'].read.__globals__, 'MAX_CHUNKS', 1)
    reader = M['ChunkReader'](Producer([b'a', b'b']), 2)
    assert reader.read(1) == first
    with pytest.raises(ValueError, match='limit'):
        reader.read(1)
    reader.close()
    reader = M['ChunkReader'](Producer([b'x']), 1)
    with pytest.raises(ValueError, match='unbounded'):
        reader.read()
    reader.close()


def test_early_demux_eof_and_partial_current_chunk_are_not_source_eof():
    for size in (1, 3):
        source = Producer([b'abc', b'tail'])
        reader = M['ChunkReader'](source, 7)
        reader.read(size)
        with pytest.raises(ValueError, match='unread tail'):
            reader.verify_end()
        assert not reader.eof
        reader.close()
        assert source.closed == 1


def test_cooperative_source_deadline_is_checked_after_slow_producer(monkeypatch):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def slow():
        clock[0] = D['VIDEO']['MAX_SECONDS'] + 1
        yield b'x'
    reader = M['ChunkReader'](slow(), 1)
    with pytest.raises(ValueError, match='deadline'):
        reader.read(1)
    assert reader.delivered == 0
    reader.close()


@pytest.mark.parametrize('chunk_size', [1, 7, 32768])
def test_real_fragmented_decode_matches_snapshot_every_event_and_payload(tmp_path, chunk_size):
    path = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    snapshot = path.read_bytes()
    baseline_report: dict[str, Any] = {}
    report: dict[str, Any] = {}
    expected = list(D['iter_snapshot'](snapshot, 'mpeg', (0, 2), 1, baseline_report))
    source = Producer([snapshot[i:i + chunk_size] for i in range(0, len(snapshot), chunk_size)])
    actual = list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report))
    assert actual == expected
    assert report['status'] == 'completed' and not report['cleanup_errors']
    assert report['source_sha256'] == baseline_report['source_sha256']
    assert report['preparation'] == baseline_report['preparation']
    assert report['input']['verified_source_end'] and not report['input']['owned_chunk_bytes']
    assert report['input']['peak_owned_chunk_bytes'] <= chunk_size
    assert 0 < report['first_event_input']['received_bytes'] <= len(snapshot)
    assert source.closed == 1


def test_real_early_consumer_close_closes_input_without_claiming_decode_completion(tmp_path):
    path = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path)
    source = Producer([path.read_bytes()])
    report: dict[str, Any] = {}
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report)
    next(iterator)
    iterator.close()
    assert source.closed == 1 and report['status'] == 'closed-before-eof'
    assert 'source_sha256' not in report
    assert not report['input']['owned_chunk_bytes']


def test_input_failure_and_cleanup_failure_preserve_primary_error(monkeypatch):
    source = Producer([b'x'], close_failure=True)
    def fail_open(reader, **_kwargs):
        reader.read(1)
        raise BrokenPipeError('primary failure')
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: type('AV', (), dict(
        __version__='test', library_versions={}, open=staticmethod(fail_open))))
    report: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError, match='primary failure'):
        next(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report))
    assert report['status'] == 'failed' and report['error'] == 'BrokenPipeError: primary failure'
    assert report['cleanup_errors'] == ['producer cleanup failed']
    assert not report['input']['owned_chunk_bytes'] and source.closed == 1


def test_cli_failure_is_exclusive_and_keeps_receipt(tmp_path):
    receipt = tmp_path / 'receipt.json'
    command = [sys.executable, str(SCRIPT), str(tmp_path / 'absent'), '--container', 'mpeg',
        '--primary-stream', '0', '--secondary-stream', '2', '--audio-stream', '1', '--receipt', str(receipt)]
    failed = subprocess.run(command, capture_output=True, timeout=10, check=False)
    assert failed.returncode == 2 and json.loads(receipt.read_text())['status'] == 'failed'
    original = receipt.read_bytes()
    repeated = subprocess.run(command, capture_output=True, timeout=10, check=False)
    message = b'receipt failed'
    assert repeated.returncode == 2 and message in repeated.stderr
    assert receipt.read_bytes() == original


def test_producer_failure_cannot_be_retried_as_clean_eof():
    source = Producer([b'ab'], failure=BrokenPipeError('transport interrupted'))
    reader = M['ChunkReader'](source, 2)
    reader.read(2)
    with pytest.raises(BrokenPipeError, match='transport interrupted'):
        reader.read(1)
    with pytest.raises(ValueError, match='previously failed'):
        reader.verify_end()
    assert not reader.eof
    reader.close()


@pytest.mark.parametrize('streams,audio', [((0, 0), 2), ((0, 1), 1), ((False, 1), 2)])
def test_invalid_tracks_do_not_pull_or_open_decoder(streams, audio, monkeypatch):
    source = Producer([b'x'])
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: pytest.fail('decoder opened'))
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='distinct'):
        next(M['iter_chunks'](source, 'mpeg', streams, audio, report))
    assert source.pulls == 0 and report['status'] == 'failed'


@pytest.mark.parametrize('close_failure', [False, True])
def test_native_demux_end_requires_producer_eof_and_cleanup_failure_changes_success(monkeypatch, close_failure):
    source = Producer([] if close_failure else [b'unread'], close_failure=close_failure)
    class Container:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: type('AV', (), dict(
        __version__='test', library_versions={}, open=staticmethod(lambda *_a, **_k: Container()))))
    monkeypatch.setitem(D, 'selected_tracks', lambda *_: [])
    monkeypatch.setitem(D['AUDIO'], 'FormatConverter', lambda _: None)
    monkeypatch.setitem(D['AUDIO'], 'FrameAdapter', lambda *_: None)
    monkeypatch.setitem(D, 'prepared_events', lambda *_: iter(()))
    report: dict[str, Any] = {}
    with pytest.raises((ValueError, RuntimeError), match='cleanup failed' if close_failure else 'unread tail'):
        list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report))
    assert source.closed == 1 and report['status'] == 'failed'
    assert not report['input']['owned_chunk_bytes']
    assert bool(report['cleanup_errors']) == close_failure


@pytest.mark.parametrize('finish', ['read', 'verify_end'])
def test_slow_producer_eof_is_not_accepted_after_deadline(monkeypatch, finish):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def slow_eof():
        yield b'x'
        clock[0] = D['VIDEO']['MAX_SECONDS'] + 1
    reader = M['ChunkReader'](slow_eof(), 1)
    reader.read(1)
    try:
        with pytest.raises(ValueError, match='deadline'):
            reader.read(1) if finish == 'read' else reader.verify_end()
        assert not reader.eof and reader.failure is not None
        with pytest.raises(ValueError, match='previously failed'):
            reader.verify_end()
    finally:
        reader.close()


def test_final_slow_eof_cannot_publish_completed_source_receipt(monkeypatch):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def slow_eof():
        clock[0] = D['VIDEO']['MAX_SECONDS'] + 1
        yield from ()
    source = Producer(slow_eof())
    class Container:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: type('AV', (), dict(
        __version__='test', library_versions={}, open=staticmethod(lambda *_a, **_k: Container()))))
    monkeypatch.setitem(D, 'selected_tracks', lambda *_: [])
    monkeypatch.setitem(D['AUDIO'], 'FormatConverter', lambda _: None)
    monkeypatch.setitem(D['AUDIO'], 'FrameAdapter', lambda *_: None)
    monkeypatch.setitem(D, 'prepared_events', lambda *_: iter(()))
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='deadline'):
        list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report))
    assert report['status'] == 'failed' and not report['cleanup_errors']
    assert not report['input']['verified_source_end']
    assert 'source_sha256' not in report and 'source_bytes' not in report
    assert source.closed == 1 and not report['input']['owned_chunk_bytes']


def test_cleanup_only_failure_raises_inside_unrelated_caller_except(tmp_path):
    path = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path)
    source = Producer([path.read_bytes()], close_failure=True)
    report: dict[str, Any] = {}
    try:
        raise LookupError('ambient caller error')
    except LookupError:
        with pytest.raises(RuntimeError, match='cleanup failed'):
            list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, startup='bounded-mpeg'))
    assert report['status'] == 'failed' and report['cleanup_errors']


def test_failed_pes_selection_clears_reused_session_diagnostics():
    report = dict(track_selection={'old': True}, preparation={'video_pairs_consumed': 999})
    with pytest.raises(ValueError, match='PES'):
        list(M['iter_chunks'](iter(()), 'mpeg', (0, 2), 1, report,
                             pes_ids=(0xE0, 0xE0, 0xC0), selection={}))
    assert report['status'] == 'failed' and report['preparation'] == {}
    assert 'track_selection' not in report


def test_consumer_clock_excludes_only_open_borrows_and_has_no_history(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    clock = M['ConsumerClock']()
    now[0] = 2
    clock.pause()
    now[0] = 102
    assert clock() == 2
    assert clock.result() == dict(profile='consumer-excluding-monotonic-v1', wall_seconds=102,
        processing_seconds=2, excluded_consumer_seconds=100, completed_borrows=0, borrow_active=True)
    with pytest.raises(ValueError, match='already paused'):
        clock.pause()
    clock.resume()
    now[0] = 105
    assert clock() == 5
    assert clock.result()['processing_seconds'] == 5
    with pytest.raises(ValueError, match='not paused'):
        clock.resume()
    for _ in range(1000):
        clock.pause()
        now[0] += 1
        clock.resume()
    assert clock.result()['completed_borrows'] == 1001
    assert clock.result()['excluded_consumer_seconds'] == 1100
    assert not any(isinstance(value, (list, dict, set)) for value in vars(clock).values())


@pytest.mark.parametrize('mode', ['wall', 'consumer-excluding'])
def test_real_consumer_hold_exceeds_wall_limit_only_in_legacy_mode(tmp_path, monkeypatch, mode):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path).read_bytes()
    expected: dict[str, Any] = {}
    baseline = list(M['iter_chunks'](Producer([raw]), 'mpeg', (0, 2), 1, expected))
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    report: dict[str, Any] = {}
    source = Producer([raw])
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, deadline_mode=mode)
    actual = [next(iterator)]
    now[0] += D['VIDEO']['MAX_SECONDS'] + 1
    if mode == 'wall':
        with pytest.raises(ValueError, match=r'limit|deadline'):
            list(iterator)
        assert report['status'] == 'failed' and 'source_sha256' not in report
    else:
        actual.extend(iterator)
        assert actual == baseline
        timing = report['input']['processing_clock']
        assert timing['processing_seconds'] == 0 and timing['excluded_consumer_seconds'] == 61
        assert not timing['borrow_active'] and timing['completed_borrows'] == len(actual)
        assert report['status'] == 'completed' and report['source_sha256'] == hashlib.sha256(raw).hexdigest()
    assert source.closed == 1 and not report['input']['owned_chunk_bytes']


@pytest.mark.parametrize('finish', ['close', 'throw'])
def test_real_borrow_resume_on_close_or_consumer_exception_preserves_primary(tmp_path, monkeypatch, finish):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path).read_bytes()
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    source = Producer([raw], close_failure=True)
    report: dict[str, Any] = {}
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, deadline_mode='consumer-excluding')
    next(iterator)
    now[0] = 100
    if finish == 'close':
        iterator.close()
    else:
        primary = LookupError('consumer failed')
        with pytest.raises(LookupError) as caught:
            iterator.throw(primary)
        assert caught.value is primary
    assert source.closed == 1 and report['cleanup_errors'] == ['producer cleanup failed']
    assert not report['input']['processing_clock']['borrow_active']
    assert report['input']['processing_clock']['excluded_consumer_seconds'] == 100
    assert report['status'] != 'completed' and 'source_sha256' not in report


@pytest.mark.parametrize('mode', [None, False, 1, [], '', 'active'])
def test_invalid_deadline_mode_does_not_claim_or_pull_input(monkeypatch, mode):
    source = Producer([b'x'])
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: pytest.fail('decoder opened'))
    with pytest.raises(ValueError, match='deadline mode'):
        next(M['iter_chunks'](source, 'mpeg', (0, 2), 1, {}, deadline_mode=mode))
    assert source.pulls == source.closed == 0


@pytest.mark.parametrize('phase', ['yield', 'eof', 'close'])
def test_excluding_consumer_does_not_exclude_slow_source_work(monkeypatch, phase):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    class Slow(Producer):
        def __next__(self):
            if phase == 'yield' or (phase == 'eof' and self.pulls):
                now[0] += 61
            return super().__next__()
        def close(self):
            if phase == 'close':
                now[0] += 61
            super().close()
    clock = M['ConsumerClock']()
    source = Slow([b'x'])
    reader = M['ChunkReader'](source, 1, work_clock=clock)
    if phase == 'close':
        reader.read(1)
        reader.close()
        assert reader.now() - reader.started == 61
    else:
        if phase == 'eof':
            reader.read(1)
            clock.pause()
            now[0] += 100
            clock.resume()
        with pytest.raises(ValueError, match='deadline'):
            reader.read(1)
        assert not reader.eof and reader.failure is not None
        reader.close()
    assert source.closed == 1


def test_consumer_exclusion_does_not_relax_wall_startup_deadline(tmp_path, monkeypatch):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path).read_bytes()
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    source = Producer([raw])
    report: dict[str, Any] = {}
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report,
        startup='bounded-mpeg', deadline_mode='consumer-excluding')
    next(iterator)
    now[0] += M['STARTUP_SECONDS'] + 1
    with pytest.raises(ValueError, match='startup deadline'):
        list(iterator)
    assert source.closed == 1 and report['status'] == 'failed'
    assert not report['input']['processing_clock']['borrow_active']
    assert 'source_sha256' not in report


def test_real_slow_producer_cleanup_cannot_publish_opt_in_success(tmp_path, monkeypatch):
    raw = OLD['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path).read_bytes()
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    class SlowClose(Producer):
        def close(self):
            now[0] += D['VIDEO']['MAX_SECONDS'] + 1
            super().close()
    source = SlowClose([raw])
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='deadline'):
        list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, deadline_mode='consumer-excluding'))
    assert source.closed == 1 and report['status'] == 'failed' and report['cleanup_errors']
    assert report['input']['verified_source_end'] and not report['input']['owned_chunk_bytes']
    assert 'source_sha256' not in report and 'source_bytes' not in report


@pytest.mark.parametrize('stage', ['demux', 'decode'])
def test_native_work_is_charged_after_excluded_borrow(monkeypatch, stage):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    clock = M['ConsumerClock']()
    clock.pause()
    now[0] += 100
    clock.resume()
    class Packet:
        is_corrupt = False
        size = 1
        stream = SimpleNamespace(index=0)
        def decode(self):
            if stage == 'decode':
                now[0] += 61
            return [object()]
    class Container:
        def demux(self, *_args):
            if stage == 'demux':
                now[0] += 61
            yield Packet()
    with pytest.raises(ValueError, match='limit'):
        list(D['decoded_frames'](Container(), [], SimpleNamespace(packets=0), 1, 0, clock=clock))
    assert clock.result()['processing_seconds'] == 61


def test_opt_in_payload_borrow_does_not_hide_late_final_eof_flush(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    clock = M['ConsumerClock']()
    clock.pause()
    now[0] += 100
    clock.resume()
    def resample(_frame):
        now[0] += 61
        return []
    monkeypatch.setitem(D['prepared_events'].__globals__, 'decoded_frames', lambda *_a, **_k: iter(()))
    adapter = SimpleNamespace(resampler=SimpleNamespace(resample=resample))
    session = SimpleNamespace(pairs=SimpleNamespace(consume=None, finish=lambda: None), audio_count=1)
    with pytest.raises(ValueError, match='session limit'):
        list(D['prepared_events'](None, [], adapter, session, 1, 0, clock=clock))
    assert clock.result()['processing_seconds'] == 61


def test_opt_in_read_cannot_hide_source_work_inside_an_open_consumer_borrow(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    clock = M['ConsumerClock']()
    source = Producer([b'x'])
    reader = M['ChunkReader'](source, 1, work_clock=clock)
    clock.pause()
    now[0] += 100
    with pytest.raises(ValueError, match='consumer borrow'):
        reader.read(1)
    clock.resume()
    assert source.pulls == 0 and reader.failure is not None
    reader.close()


@pytest.mark.parametrize('bound', ['bytes', 'chunks'])
def test_opt_in_consumer_clock_keeps_compressed_work_caps(monkeypatch, bound):
    clock = M['ConsumerClock']()
    if bound == 'chunks':
        monkeypatch.setitem(M['ChunkReader'].read.__globals__, 'MAX_CHUNKS', 1)
    first = b'x'
    reader = M['ChunkReader'](Producer([first, b'y']), 1 if bound == 'bytes' else 2, work_clock=clock)
    assert reader.read(1) == first
    with pytest.raises(ValueError, match='limit'):
        reader.read(1)
    assert reader.chunks == 1 and reader.received == reader.delivered == 1
    reader.close()


def test_slow_native_container_close_is_charged_before_success(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: now[0])
    class Container:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            now[0] += 61
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: SimpleNamespace(
        __version__='test', library_versions={}, open=lambda *_a, **_k: Container()))
    monkeypatch.setitem(D, 'selected_tracks', lambda *_: [])
    monkeypatch.setitem(D['AUDIO'], 'FormatConverter', lambda _: None)
    monkeypatch.setitem(D['AUDIO'], 'FrameAdapter', lambda *_: None)
    monkeypatch.setitem(D, 'prepared_events', lambda *_a, **_k: iter(()))
    source = Producer([])
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='deadline'):
        list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, deadline_mode='consumer-excluding'))
    assert source.closed == 1 and report['status'] == 'failed'
    assert not report['input']['owned_chunk_bytes'] and 'source_sha256' not in report
    assert report['input']['processing_clock']['processing_seconds'] == 61
