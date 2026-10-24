"""Opt-in discovery settings plus independently enforced startup budgets."""
from pathlib import Path
import runpy
from types import SimpleNamespace
from typing import Any

import pytest

OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_chunked.py')))
M = OLD['M']
D = M['DECODE']
Producer = OLD['Producer']


def fake_decoder(monkeypatch, make_events, *, opening=None):
    observed: dict[str, Any] = {}
    class Container:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            observed['closed'] = True
    def open_source(reader, **kwargs):
        observed.update(reader=reader, options=kwargs['options'])
        if opening:
            opening(reader)
        return Container()
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: SimpleNamespace(
        __version__='test', library_versions={}, open=open_source))
    monkeypatch.setitem(D, 'selected_tracks', lambda *_: [])
    monkeypatch.setitem(D['AUDIO'], 'FormatConverter', lambda _: None)
    monkeypatch.setitem(D['AUDIO'], 'FrameAdapter', lambda *_: None)
    monkeypatch.setitem(D, 'prepared_events', lambda *_: make_events(observed['reader']))
    return observed


@pytest.mark.parametrize('mode', ['default', 'bounded-mpeg'])
def test_profile_options_and_startup_credit_remain_until_both_track_heads(monkeypatch, mode):
    def events(reader):
        reader.read(1)
        yield dict(kind='audio_block'), (b'a',)
        yield dict(kind='video_pair'), (b'v',)
        while reader.read(1):
            pass
    observed = fake_decoder(monkeypatch, events)
    source = Producer([b'ab'])
    report: dict[str, Any] = {}
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, startup=mode)
    next(iterator)
    reader = observed['reader']
    assert reader.startup_active == (mode == 'bounded-mpeg')
    next(iterator)
    assert not reader.startup_active
    if mode == 'bounded-mpeg':
        assert report['startup_ready_input']['delivered_bytes'] == 1
        assert not report['startup_ready_input']['verified_source_end']
    else:
        assert 'startup_ready_input' not in report
    assert list(iterator) == []
    expected = dict(protocol_whitelist='file,pipe')
    if mode == 'bounded-mpeg':
        expected.update(probesize='262144', analyzeduration='100000')
    assert observed['options'] == expected
    assert report['status'] == 'completed' and source.closed == 1


def test_startup_byte_crossing_is_rejected_before_acceptance_and_not_retried(monkeypatch):
    monkeypatch.setitem(M['ChunkReader'].read.__globals__, 'STARTUP_BYTES', 4)
    reader = M['ChunkReader'](Producer([b'abc', b'de']), 10, bounded_startup=True)
    reader.read(3)
    try:
        with pytest.raises(ValueError, match='startup byte'):
            reader.read(2)
        assert reader.received == reader.delivered == 3 and reader.chunks == 1
        with pytest.raises(ValueError, match='previously failed'):
            reader.read(1)
    finally:
        reader.close()


def test_startup_completion_releases_only_startup_budget_not_session_or_total_limits(monkeypatch):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    monkeypatch.setitem(M['ChunkReader'].read.__globals__, 'STARTUP_BYTES', 1)
    reader = M['ChunkReader'](Producer([b'a', b'bb', b'c']), 3, bounded_startup=True)
    reader.read(1)
    reader.finish_startup()
    clock[0] = M['STARTUP_SECONDS'] + 1
    assert len(reader.read(2)) == 2
    with pytest.raises(ValueError, match='chunk/count/byte'):
        reader.read(1)
    reader.close()
    reader = M['ChunkReader'](Producer([]), 1, bounded_startup=True)
    reader.finish_startup()
    clock[0] += D['VIDEO']['MAX_SECONDS'] + 1
    with pytest.raises(ValueError, match='session deadline'):
        reader.verify_end()
    reader.close()


@pytest.mark.parametrize('finish', ['read', 'verify_end', 'finish_startup'])
def test_slow_startup_exit_cannot_accept_eof_or_release_credit(monkeypatch, finish):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def source():
        clock[0] = M['STARTUP_SECONDS'] + 1
        yield from ()
    reader = M['ChunkReader'](source(), 1, bounded_startup=True)
    try:
        if finish == 'finish_startup':
            clock[0] = M['STARTUP_SECONDS'] + 1
        with pytest.raises(ValueError, match='startup deadline'):
            reader.read(1) if finish == 'read' else getattr(reader, finish)()
        assert reader.startup_active and not reader.eof
        assert reader.failure is not None
    finally:
        reader.close()


def test_native_discovery_return_after_deadline_fails_before_any_decode(monkeypatch):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def opening(_reader):
        clock[0] = M['STARTUP_SECONDS'] + 1
    observed = fake_decoder(monkeypatch, lambda _: pytest.fail('decode began after startup deadline'), opening=opening)
    source = Producer([])
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='startup deadline'):
        list(M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, startup='bounded-mpeg'))
    assert observed['closed'] and source.closed == 1
    assert report['status'] == 'failed' and 'startup_ready_input' not in report


def test_only_audio_head_cannot_end_startup_or_hide_later_deadline(monkeypatch):
    clock = [0]
    monkeypatch.setattr(M['time'], 'monotonic', lambda: clock[0])
    def events(_reader):
        yield dict(kind='audio_block'), (b'a',)
        clock[0] = M['STARTUP_SECONDS'] + 1
        yield dict(kind='video_pair'), (b'v',)
    fake_decoder(monkeypatch, events)
    source = Producer([])
    report: dict[str, Any] = {}
    iterator = M['iter_chunks'](source, 'mpeg', (0, 2), 1, report, startup='bounded-mpeg')
    next(iterator)
    with pytest.raises(ValueError, match='startup deadline'):
        next(iterator)
    assert report['status'] == 'failed' and 'startup_ready_input' not in report
    assert source.closed == 1


@pytest.mark.parametrize('mode,container', [('unknown', 'mpeg'), ('bounded-mpeg', 'matroska')])
def test_unsupported_mode_or_container_is_rejected_before_producer_or_decoder(monkeypatch, mode, container):
    monkeypatch.setitem(D['AUDIO'], 'load_av', lambda: pytest.fail('decoder opened'))
    source = Producer([b'x'])
    with pytest.raises(ValueError, match='startup'):
        next(M['iter_chunks'](source, container, (0, 2), 1, {}, startup=mode))
    assert source.pulls == 0


def test_real_bounded_profile_preserves_all_events_and_payloads(tmp_path):
    path = OLD['OLD']['TIMELINE_TESTS']['encode_three_track_ps'](tmp_path, audio_jitter=True)
    raw = path.read_bytes()
    baseline: dict[str, Any] = {}
    report: dict[str, Any] = {}
    expected = list(D['iter_snapshot'](raw, 'mpeg', (0, 2), 1, baseline))
    chunks = (raw[i:i + 7] for i in range(0, len(raw), 7))
    actual = list(M['iter_chunks'](chunks, 'mpeg', (0, 2), 1, report, startup='bounded-mpeg'))
    assert actual == expected and report['preparation'] == baseline['preparation']
    assert report['status'] == 'completed' and not report['cleanup_errors']
    assert report['startup_ready_input']['received_bytes'] <= M['STARTUP_BYTES']
    assert not report['startup_ready_input']['startup_active']
    assert 0 <= report['startup_ready_input']['startup_ready_elapsed_seconds'] <= M['STARTUP_SECONDS']
