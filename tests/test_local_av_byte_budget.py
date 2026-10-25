"""Finite compressed work quotas do not expand resident buffers or wall clocks."""
import copy
import hashlib
from pathlib import Path
import runpy
from typing import Any

import pytest

CAP = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture_playback.py')))
M = CAP['M']
PREP = M['PREPARE']
D = PREP['CAPTURE']['DECRYPT']
CRYPTO = runpy.run_path(str(Path(__file__).with_name('test_local_av_decrypted.py')))
Source = CRYPTO['Source']
rig = CAP['rig']
MIB = 1024 * 1024


@pytest.mark.parametrize('limit', [None, False, True, 0, -1, 1.5, '32', 256 * MIB + 1])
def test_invalid_byte_limit_does_not_claim_or_close_the_producer(limit):
    source = Source([b'x'])
    report = dict(status='completed', complete_clear_sha256='stale', verified_decryption_end=True)
    with pytest.raises(ValueError, match='byte limit'):
        next(D['iter_decrypted'](source, 'key', report, codec='hevc', byte_limit=limit))
    assert source.pulls == 0 and not source.closed
    assert report['status'] == 'failed' and report['complete_clear_sha256'] is None
    assert report['verified_decryption_end'] is False


@pytest.mark.parametrize('expanded', [False, True])
def test_streamed_input_crosses_default_only_under_explicit_quota(monkeypatch, expanded):
    monkeypatch.setattr(D['Decryptor'], 'feed', lambda _self, data: data)
    chunk = b'x' * 65536
    source = Source(chunk for _ in range(17 * MIB // len(chunk)))
    limit = 17 * MIB if expanded else 16 * MIB
    chunks = D['Chunks'](source, 'key', codec='hevc', byte_limit=limit)
    expected = hashlib.sha256()
    yielded = 0
    try:
        if not expanded:
            with pytest.raises(ValueError, match='packet/count/byte'):
                for value in chunks:
                    expected.update(value)
                    yielded += len(value)
        else:
            for value in chunks:
                expected.update(value)
                yielded += len(value)
        assert yielded == chunks.received == chunks.yielded == limit
        assert chunks.clear_hash.hexdigest() == expected.hexdigest()
        assert chunks.completed is expanded and chunks.result()['peak_pending_bytes'] == 0
        assert chunks.result()['total_byte_limit'] == limit
        assert chunks.result()['profile'].endswith('v2' if expanded else 'v1')
    finally:
        chunks.close()
    assert source.closed


def test_expanded_input_still_checks_pending_buffer_before_append():
    source = Source([b'x' * MIB, b'y'])
    chunks = D['Chunks'](source, 'key', codec='hevc', byte_limit=32 * MIB)
    with pytest.raises(ValueError, match='before append'):
        next(chunks)
    assert chunks.received == MIB + 1 and chunks.transform.peak == MIB
    chunks.close()
    assert chunks.result()['pending_bytes'] == 0 and source.closed


def test_expanded_input_still_checks_wall_clock_and_packet_work(monkeypatch):
    now = [0.0]
    chunks = D['Chunks'](Source([b'x']), 'key', codec='hevc', byte_limit=32 * MIB, clock=lambda: now[0])
    now[0] = 61
    with pytest.raises(ValueError, match='deadline'):
        next(chunks)
    assert chunks.received == 0
    chunks.close()
    monkeypatch.setitem(D['Chunks'].pull.__globals__, 'MAX_PACKETS', 1)
    source = Source([b'x', b'y'])
    chunks = D['Chunks'](source, 'key', codec='hevc', byte_limit=32 * MIB)
    with pytest.raises(ValueError, match='packet/count/byte'):
        next(chunks)
    assert chunks.packets == 1
    chunks.close()


def test_expanded_decoder_keeps_startup_and_chunk_size_limits():
    reader = PREP['CHUNKED']['ChunkReader'](Source([b'x' * (256 * 1024), b'y']), 32 * MIB, bounded_startup=True)
    try:
        for _ in range(4):
            assert len(reader.read(65536)) == 65536
        with pytest.raises(ValueError, match='startup byte'):
            reader.read(1)
        assert reader.received == 256 * 1024
        assert reader.result()['read_byte_limit'] == 65536 and reader.result()['chunk_byte_limit'] == MIB
    finally:
        reader.close()


@pytest.mark.parametrize('mode,tail', [('full-history', 2), ('source-sequence', None)])
def test_expanded_capture_output_requires_bounded_histories_before_claim(rig, mode, tail):
    owner, _run = CAP['play'](rig, {})
    with pytest.raises(ValueError, match='bounded diagnostics'):
        M['CapturePlayback'](owner, 'key', CAP['arguments'](), {},
            limits=CAP['CaptureLimits'](max_packets=1, max_bytes=32 * MIB, duration_seconds=60),
            byte_limit=32 * MIB, identity_mode=mode, diagnostic_tail=tail)
    assert not owner.started and not owner.closed


def test_capture_cannot_request_more_bytes_than_its_explicit_decryption_quota(rig):
    owner, _run = CAP['play'](rig, {})
    with pytest.raises(ValueError, match='within decryption caps'):
        M['CapturePlayback'](owner, 'key', CAP['arguments'](), {},
            limits=CAP['CaptureLimits'](max_packets=1, max_bytes=32 * MIB + 1, duration_seconds=60),
            byte_limit=32 * MIB, identity_mode='source-sequence', diagnostic_tail=2)
    assert not owner.started and not owner.closed


def test_composed_byte_quota_and_all_terminal_bindings(rig):
    report: dict[str, Any] = {}
    owner, session = CAP['session'](rig, report, byte_limit=32 * MIB, pair_limit=601,
        identity_mode='source-sequence', diagnostic_tail=2, decoder_deadline_mode='consumer-excluding')
    session.play()
    prep, output = report['preparation'], report['output']
    assert owner.closed and report['status'] == 'prefix-output-completed'
    assert prep['byte_limit'] == prep['capture']['byte_limit'] == 32 * MIB
    assert prep['capture']['decryption']['profile'] == 'bounded-decrypted-packet-chunks-v2'
    for field in ('input', 'input_before_cleanup'):
        assert prep['decode'][field]['total_byte_limit'] == 32 * MIB
    changes = [(('byte_limit',), None), (('byte_limit',), 16 * MIB),
        (('capture', 'byte_limit'), True), (('capture', 'decryption', 'total_byte_limit'), 16 * MIB),
        (('capture', 'decryption', 'profile'), 'bounded-decrypted-packet-chunks-v1'),
        (('capture', 'decryption', 'pending_byte_limit'), 2 * MIB),
        (('capture', 'limits', 'max_bytes'), 32 * MIB + 1),
        (('capture', 'decryption', 'encrypted_bytes'), 32 * MIB + 1),
        (('capture', 'decryption', 'encrypted_bytes'), '1'),
        (('decode', 'input_before_cleanup', 'received_bytes'), True),
        (('decode', 'input', 'total_byte_limit'), 16 * MIB),
        (('decode', 'input_before_cleanup', 'total_byte_limit'), 16 * MIB),
        (('decode', 'input_before_cleanup', 'delivered_bytes'), 1),
        (('decode', 'input', 'chunk_byte_limit'), 2 * MIB)]
    for path, value in changes:
        changed = copy.deepcopy(prep)
        target = changed
        for field in path[:-1]:
            target = target[field]
        if value is None:
            target.pop(path[-1])
        else:
            target[path[-1]] = value
        with pytest.raises(ValueError, match='byte budget'):
            M['verify_output'](changed, output)
    with pytest.raises(ValueError, match='byte budget'):
        PREP['verify_completion'](prep['capture'], prep['decode'], prep['online'],
            pair_limit=601, decoder_deadline_mode='consumer-excluding')
    assert not report['source_pull']['worker_alive'] and not output['lookahead']['owned_ids']
