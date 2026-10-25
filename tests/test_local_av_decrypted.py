"""Cooperative encrypted input bounds, EOF, no-prefetch and owned cleanup."""
import hashlib
from pathlib import Path
import runpy
from typing import Any

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_decrypted.py'))
FIXTURE = runpy.run_path(str(Path(__file__).with_name('test_stream_media.py')))


class Source:
    def __init__(self, rows, error=None):
        self.rows = iter(rows)
        self.error = error
        self.pulls = 0
        self.closed = False
    def __iter__(self):
        return self
    def __next__(self):
        self.pulls += 1
        try:
            return next(self.rows)
        except StopIteration:
            if self.error:
                raise self.error from None
            raise
    def close(self):
        self.closed = True


def fixture():
    body = b'0123456789abcdef' * 2
    header = b'\0\0\1\xe0' + (3 + 6 + len(body)).to_bytes(2, 'big') + b'\x80\0\0'
    nal = b'\0\0\0\1\x42\x01'
    pack = bytes.fromhex('000001ba4400040004010001fff8')
    encrypted = FIXTURE['_encrypt_hikvision_fixture_blocks'](b'camera-key'.ljust(16, b'\0'), body)
    return header + nal + encrypted + pack, header + nal + body + pack


@pytest.mark.parametrize('size', [1, 7, 32, 65536])
def test_arbitrary_packet_splits_preserve_all_clear_bytes_and_verified_completion(size):
    encrypted, expected = fixture()
    source = Source(encrypted[i:i + size] for i in range(0, len(encrypted), size))
    report: dict[str, Any] = {}
    assert b''.join(M['iter_decrypted'](source, 'camera-key', report, codec='hevc')) == expected
    assert source.closed and report['status'] == 'completed' and report['verified_decryption_end']
    assert report['complete_clear_sha256'] == hashlib.sha256(expected).hexdigest()
    assert report['pending_bytes'] == 0 and not report['network_eof_verified']


@pytest.mark.parametrize('bad', [b'', bytearray(b'x'), 'x', b'x' * (1024 * 1024 + 1)])
def test_rejects_invalid_packet_without_hashing_or_prefetch(bad):
    source = Source([bad, b'next'])
    chunks = M['Chunks'](source, 'camera-key', codec='hevc')
    with pytest.raises(ValueError, match='immutable bounded'):
        next(chunks)
    assert source.pulls == 1 and chunks.received == 0
    with pytest.raises(ValueError, match='previously failed'):
        next(chunks)
    chunks.close()
    assert source.closed and chunks.result()['complete_clear_sha256'] is None


@pytest.mark.parametrize('codec', ['auto', 'hevc'])
def test_pending_bound_precedes_buffer_append_in_both_modes(codec):
    chunks = M['Chunks'](Source([b'x' * M['MAX_PENDING'], b'y']), 'camera-key', codec=codec)
    with pytest.raises(ValueError, match='before append'):
        next(chunks)
    assert len(chunks.transform.buffer) == M['MAX_PENDING']
    assert chunks.transform.peak == M['MAX_PENDING']
    chunks.close()
    assert chunks.result()['pending_bytes'] == 0 and not chunks.transform.key


@pytest.mark.parametrize('bound', ['MAX_TOTAL', 'MAX_PACKETS'])
def test_input_total_and_packet_limits_remain_failures(monkeypatch, bound):
    monkeypatch.setitem(M['Chunks'].__next__.__globals__, bound, 1)
    chunks = M['Chunks'](Source([b'x', b'y']), 'camera-key', codec='hevc')
    with pytest.raises(ValueError, match='packet/count/byte'):
        next(chunks)
    assert chunks.received == 1 and chunks.packets == 1
    chunks.close()


def test_no_prefetch_and_consumer_close_owns_source_without_flushing(monkeypatch):
    monkeypatch.setattr(M['Decryptor'], 'feed', lambda _self, data: data)
    encrypted, _ = fixture()
    source = Source([encrypted, encrypted])
    report: dict[str, Any] = {}
    iterator = M['iter_decrypted'](source, 'camera-key', report, codec='hevc')
    assert next(iterator) and source.pulls == 1
    iterator.close()
    assert source.closed and report['status'] == 'closed'
    assert not report['verified_decryption_end'] and report['complete_clear_sha256'] is None


@pytest.mark.parametrize('stage', ['producer', 'pull', 'eof', 'flush'])
def test_slow_producer_or_flush_never_verifies_timely_end(stage):
    now = [0.0]
    encrypted, _ = fixture()
    chunks = M['Chunks'](Source([encrypted]), 'camera-key', codec='hevc', clock=lambda: now[0])
    if stage == 'producer':
        class SlowPull(Source):
            def __next__(self):
                now[0] = 61
                return super().__next__()
        chunks.iterator = SlowPull([encrypted])
    elif stage == 'pull':
        original = chunks.transform.feed
        def slow(data):
            now[0] = 61
            return original(data)
        chunks.transform.feed = slow
    else:
        chunks.transform.feed = lambda data: data
        next(chunks)
        if stage == 'eof':
            class SlowEOF(Source):
                def __next__(self):
                    now[0] = 61
                    raise StopIteration
            chunks.iterator = SlowEOF([])
        else:
            original = chunks.transform.finish
            def slow_flush():
                now[0] = 61
                return original()
            chunks.transform.finish = slow_flush
    with pytest.raises(ValueError, match='deadline'):
        next(chunks)
    assert not chunks.producer_end and not chunks.completed
    chunks.close()


def test_auto_unresolved_tail_and_empty_input_fail_without_complete_hash():
    for rows in ([b'not a detected stream'], []):
        chunks = M['Chunks'](Source(rows), 'camera-key')
        with pytest.raises(ValueError):
            list(chunks)
        assert chunks.result()['complete_clear_sha256'] is None
        chunks.close()


def test_source_failure_preserved_even_when_owned_close_also_fails():
    class BrokenClose(Source):
        def close(self):
            super().close()
            raise OSError('close failure')
    source = BrokenClose([], BrokenPipeError('producer failure'))
    report: dict[str, Any] = {}
    with pytest.raises(BrokenPipeError, match='producer failure'):
        list(M['iter_decrypted'](source, 'camera-key', report, codec='hevc'))
    assert source.closed and report['cleanup_errors'] == ['close failure']
    assert report['status'] == 'failed'


def test_bad_constructor_codec_still_closes_owned_iterator():
    source = Source([])
    with pytest.raises(ValueError, match='auto or hevc'):
        M['Chunks'](source, 'camera-key', codec='h264')
    assert source.closed


def test_clear_output_limit_rejected_before_counting_or_hashing(monkeypatch):
    monkeypatch.setitem(M['Chunks'].__next__.__globals__, 'MAX_TOTAL', 3)
    chunks = M['Chunks'](Source([b'x', b'y']), 'camera-key', codec='hevc')
    expected = b'yy'
    chunks.transform.feed = lambda _data: expected
    assert next(chunks) == expected
    with pytest.raises(ValueError, match='decrypted chunk/byte'):
        next(chunks)
    assert chunks.yielded == 2 and chunks.chunks == 1
    assert chunks.clear_hash.hexdigest() == hashlib.sha256(b'yy').hexdigest()
    chunks.close()


def test_unrequested_tail_does_not_publish_complete_hash():
    encrypted, _ = fixture()
    now = [0.0]
    chunks = M['Chunks'](Source([encrypted]), 'camera-key', codec='hevc', clock=lambda: now[0])
    assert next(chunks) and chunks.producer_end and not chunks.completed
    now[0] = 61
    with pytest.raises(ValueError, match='deadline'):
        next(chunks)
    assert chunks.result()['complete_clear_sha256'] is None
    chunks.close()


def test_successful_bytes_do_not_hide_producer_cleanup_failure():
    class BrokenClose(Source):
        def close(self):
            super().close()
            raise OSError('close failure')
    encrypted, _ = fixture()
    report: dict[str, Any] = {}
    with pytest.raises(ValueError, match='cleanup'):
        list(M['iter_decrypted'](BrokenClose([encrypted]), 'camera-key', report, codec='hevc'))
    assert report['status'] == 'failed' and report['cleanup_errors'] == ['close failure']


def test_constructor_error_is_not_replaced_by_owned_close_failure():
    class BrokenClose(Source):
        def close(self):
            super().close()
            raise OSError('close failure')
    source = BrokenClose([])
    with pytest.raises(ValueError, match='auto or hevc'):
        M['Chunks'](source, 'camera-key', codec='h264')
    assert source.closed


def test_decryption_cleanup_inside_ambient_except_does_not_hide_failure():
    class BrokenClose(Source):
        def close(self):
            super().close()
            raise OSError('close failure')
    encrypted, _ = fixture()
    report: dict[str, Any] = {}
    try:
        raise LookupError('ambient caller')
    except LookupError:
        with pytest.raises(ValueError, match='cleanup'):
            list(M['iter_decrypted'](BrokenClose([encrypted]), 'camera-key', report, codec='hevc'))
    assert report['status'] == 'failed'
