"""Controlled replay uses identical verified bytes and preserves failed trials."""

import hashlib
import json
from pathlib import Path
import runpy

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/reference_stream/replay.py'))


def source(root, payloads):
    root.mkdir()
    rows, offset = [], 0
    with (root / 'pixels.bin').open('wb') as stream:
        for index, payload in enumerate(payloads):
            rows.append(dict(event='native_pixels' if index % 2 == 0 else 'native_render_pixels',
                             bytes=len(payload), offset=offset, file='pixels.bin',
                             sha256=hashlib.sha256(payload).hexdigest(),
                             encoding='zlib', transport_bytes=1, device_mono_ns=10))
            stream.write(payload)
            offset += len(payload)
    (root / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
    return rows


@pytest.mark.parametrize('codec', M['CODECS'])
def test_codec_roundtrip_uses_real_bounded_collector_decoder(codec):
    if codec == 'lz4' and not M['ctypes'].util.find_library('lz4'):
        pytest.skip('optional system liblz4 unavailable')
    for payload in (b'pixels' * 1000, bytes(range(256)), b'x'):
        wire, encoding = M['encode_payload'](payload, codec)
        decoded = M['REFERENCE']['unpack_payload'](
            dict(bytes=len(payload), encoding=encoding, transport_bytes=len(wire)), wire)
        assert decoded == payload
        assert len(wire) <= len(payload)


def test_same_corpus_all_trials_rotated_and_no_payload_artifacts(tmp_path):
    root = tmp_path / 'capture'
    source(root, [b'input' * 1000, b'render' * 1000])
    output = tmp_path / 'result'
    report = M['replay'](root, output, 3)
    # Optional LZ4 absence must be recorded as failure, never silently skipped.
    expected = 'ok' if M['ctypes'].util.find_library('lz4') else 'failed'
    assert report['status'] == expected
    assert [r['codec'] for r in report['trials']] == [
        'raw', 'zlib', 'lz4', 'zlib', 'lz4', 'raw', 'lz4', 'raw', 'zlib']
    for trial in report['trials']:
        if trial['status'] == 'ok':
            assert trial['payload_bytes'] == 11000
            assert trial['verified_snapshots'] == 2
            assert trial['collector_profile']['stages']['collector_payload_hash']['count'] == 2
    assert not report['android_measured'] and not report['playback_measured']
    assert list(output.iterdir()) == [output / 'replay.json']
    assert json.loads((output / 'replay.json').read_text()) == report
    assert (output.stat().st_mode & 0o777) == 0o700
    with pytest.raises(FileExistsError):
        M['replay'](root, output)


def test_bad_source_fails_before_any_trials_and_receipt_survives(tmp_path):
    root = tmp_path / 'capture'
    source(root, [b'first', b'second'])
    (root / 'pixels.bin').write_bytes(b'firstchanged')
    report = M['replay'](root, tmp_path / 'result')
    assert report['status'] == 'failed' and 'fingerprint' in report['error']
    assert not report['trials']
    assert (tmp_path / 'result/replay.json').exists()


def test_failed_codec_preserves_prefix_and_other_trials(tmp_path, monkeypatch):
    root = tmp_path / 'capture'
    source(root, [b'first', b'second'])
    original = M['encode_payload']
    second = b'second'

    def broken(payload, codec):
        if codec == 'zlib' and payload == second:
            return b'broken', 'zlib'
        return original(payload, codec)

    monkeypatch.setitem(M['trial'].__globals__, 'encode_payload', broken)
    report = M['replay'](root, tmp_path / 'result', 1)
    failed = next(t for t in report['trials'] if t['codec'] == 'zlib')
    assert report['status'] == 'failed'
    assert failed['status'] == 'failed' and failed['error']
    assert failed['verified_snapshots'] == 1 and failed['payload_bytes'] == 5
    assert next(t for t in report['trials'] if t['codec'] == 'raw')['status'] == 'ok'


@pytest.mark.parametrize('mutation, message', [
    (dict(file='../pixels.bin'), 'outside'),
    (dict(offset=-1), 'extent'),
    (dict(bytes=12 * 1024 * 1024 + 1), 'extent'),
    (dict(event='error'), 'native error'),
])
def test_invalid_source_never_reaches_codec(tmp_path, mutation, message):
    root = tmp_path / 'capture'
    rows = source(root, [b'first'])
    rows[0].update(mutation)
    (root / 'events.jsonl').write_text(json.dumps(rows[0]) + '\n')
    report = M['replay'](root, tmp_path / 'result', 1)
    assert message in report['error'] and not report['trials']


@pytest.mark.parametrize('limit, value', [('MAX_LINE', 5), ('MAX_PIXELS', 1), ('MAX_SNAPSHOTS', 0)])
def test_source_limits_fail_closed(tmp_path, monkeypatch, limit, value):
    root = tmp_path / 'capture'
    source(root, [b'first'])
    monkeypatch.setitem(M['snapshots'].__globals__, limit, value)
    report = M['replay'](root, tmp_path / 'result', 1)
    assert report['status'] == 'failed' and not report['trials']


@pytest.mark.parametrize('repeats', [0, 6, True])
def test_invalid_repeats_do_not_create_output(tmp_path, repeats):
    output = tmp_path / 'result'
    with pytest.raises(ValueError, match=r'1\.\.5'):
        M['replay'](tmp_path, output, repeats)
    assert not output.exists()
