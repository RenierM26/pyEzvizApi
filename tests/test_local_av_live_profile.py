"""Explicit longer-live budgets, unchanged defaults and strict cross-stage binding."""
import copy
from pathlib import Path
import runpy
import subprocess
from types import SimpleNamespace

import pytest

from pyezvizapi.media import CaptureLimits

BASE = Path(__file__).parents[1] / 'tools'
P = runpy.run_path(str(BASE / 'local_av_lan_profiles.py'))
D = runpy.run_path(str(BASE / 'local_av_decrypted.py'))
C = runpy.run_path(str(BASE / 'local_av_chunked.py'))
E = runpy.run_path(str(BASE / 'local_av_packet_evidence.py'))
V = runpy.run_path(str(BASE / 'local_av_lan_verify.py'))
OLD = runpy.run_path(str(Path(__file__).with_name('test_local_av_decrypted.py')))
CAPTURE = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture.py')))


def test_profile_tables_are_explicit_finite_and_return_unshared_values():
    old, new = P['get'](), P['get']('two-minute')
    assert old['limits'] == dict(duration_seconds=30, max_packets=15000, max_bytes=32 * 1024 * 1024)
    assert 'seconds_limit' not in old['options'] and 'span_limit' not in old['options']
    assert new['limits'] == dict(duration_seconds=120, max_packets=60000, max_bytes=128 * 1024 * 1024)
    assert new['options']['seconds_limit'] == 150 and new['options']['span_limit'] == 120
    assert new['worker_seconds'] == 210 and new['verify_seconds'] == 180
    assert new['evidence']['max_index'] == 12 * 1024 * 1024
    new['options'].clear()
    assert P['get']('two-minute')['options']


@pytest.mark.parametrize('name', [None, True, 120, '120', 'auto', 'TWO-MINUTE'])
def test_profile_is_never_inferred_or_coerced(name):
    with pytest.raises(ValueError, match='profile'):
        P['get'](name)


@pytest.mark.parametrize('value', [True, 150.0, 0, -1, 151])
def test_time_quota_rejected_before_source_claim(value):
    source = OLD['Source']([])
    with pytest.raises(ValueError, match='seconds limit'):
        D['Chunks'](source, 'camera-key', seconds_limit=value)
    assert not source.closed and source.pulls == 0


@pytest.mark.parametrize('limit,elapsed,success', [(60, 61, False), (150, 120, True), (150, 151, False)])
def test_decryption_wall_quota_includes_consumer_wait_and_slow_eof(limit, elapsed, success):
    raw, clear = OLD['fixture']()
    now = [0]
    source = OLD['Source']([raw])
    chunks = D['Chunks'](source, 'camera-key', codec='hevc', clock=lambda: now[0], seconds_limit=limit)
    first = next(chunks)
    now[0] = elapsed
    try:
        if success:
            assert first + b''.join(chunks) == clear
            assert chunks.result()['wall_seconds_limit'] == 150 and chunks.completed
        else:
            with pytest.raises(ValueError, match='deadline'):
                next(chunks)
            assert not chunks.completed and chunks.result()['complete_clear_sha256'] is None
    finally:
        chunks.close()
    assert source.closed


def test_capture_duration_cannot_exceed_its_explicit_crypto_wall_allowance():
    owner = CAPTURE['Owner']([b'a'])
    m = runpy.run_path(str(BASE / 'local_av_capture.py'))
    limits = CaptureLimits(max_packets=60000, max_bytes=128 * 1024 * 1024, duration_seconds=120)
    with pytest.raises(ValueError):
        m['validate_arguments'](owner, limits, 'bounded-prefix', 'hevc', byte_limit=128 * 1024 * 1024)
    m['validate_arguments'](owner, limits, 'bounded-prefix', 'hevc', byte_limit=128 * 1024 * 1024, seconds_limit=150)
    assert not owner.started and not owner.closed


@pytest.mark.parametrize('limit,elapsed,success', [(60, 61, False), (150, 120, True), (150, 151, False)])
def test_reader_and_persistent_decoder_enforce_the_same_explicit_processing_quota(monkeypatch, limit, elapsed, success):
    now = [0]
    monkeypatch.setattr(C['time'], 'monotonic', lambda: now[0])
    body = b'a'
    reader = C['ChunkReader'](iter([body]), 1, seconds_limit=limit)
    assert reader.read(1) == body
    now[0] = elapsed
    try:
        if success:
            reader.verify_end()
            assert reader.result()['processing_seconds_limit'] == 150
        else:
            with pytest.raises(ValueError, match='deadline'):
                reader.verify_end()
    finally:
        reader.close()
    packet = SimpleNamespace(stream=SimpleNamespace(index=2), is_corrupt=False, size=1,
        decode=lambda: iter([SimpleNamespace()]))
    container = SimpleNamespace(demux=lambda *_args: iter([packet]))
    session = SimpleNamespace(packets=0)
    decoded = C['DECODE']['decoded_frames'](container, [], session, 2, 0,
        clock=lambda: elapsed, seconds_limit=limit)
    if success:
        assert len(list(decoded)) == 1
    else:
        with pytest.raises(ValueError, match='limit'):
            next(decoded)


def test_long_evidence_exceeds_old_count_but_is_not_accepted_as_default_format(tmp_path):
    root = tmp_path / 'evidence'
    root.mkdir()
    writer = E['PacketEvidence'](root, capture_profile='two-minute')
    def packets():
        for _ in range(15001):
            yield SimpleNamespace(body=b'x')
    assert sum(1 for _ in writer.retain(packets())) == 15001
    summary = writer.finish(dict(package_sha256='a' * 64, config_sha256='b' * 64))
    assert summary['profile'] == 'encrypted-lan-packets-120s-v1'
    assert E['verify'](root, capture_profile='two-minute') == summary
    with pytest.raises(ValueError, match='index'):
        E['verify'](root)


def test_long_evidence_exceeds_old_byte_cap_with_fixed_size_input_chunks(tmp_path):
    root = tmp_path / 'evidence'
    root.mkdir()
    writer = E['PacketEvidence'](root, capture_profile='two-minute')
    body = bytes(65536)
    def packets():
        for _ in range(513):
            yield SimpleNamespace(body=body)
    for _ in writer.retain(packets()):
        pass
    summary = writer.finish(dict(package_sha256='a' * 64, config_sha256='b' * 64))
    assert summary['bytes'] > E['MAX_BYTES']
    assert E['verify'](root, capture_profile='two-minute') == summary


def test_verifier_source_chain_does_not_silently_increase_legacy_span_or_pair_caps():
    event_time = dict(numerator=119, denominator=1)
    with pytest.raises(ValueError, match='source target'):
        V['SourceChain'](1000).add('video_pair', 'local-pair:1', event_time, 12, 'a' * 64)
    chain = V['SourceChain'](1000, capture_profile='two-minute')
    chain.add('video_pair', 'local-pair:1', event_time, 12, 'a' * 64)
    assert chain.count['video_pair'] == 1


def test_profile_binding_rejects_a_downgrade_before_any_native_replay(monkeypatch):
    base = runpy.run_path(str(Path(__file__).with_name('test_local_av_lan_verify.py')))
    summary = dict(binding=base['BINDING'], packets=1, bytes=3, sha256='e' * 64)
    parent = base['parent_receipt'](summary)
    monkeypatch.setitem(V['LAN']['CAPTURE'], 'verify_output', lambda *_args: None)
    with pytest.raises(ValueError, match='profile binding'):
        V['receipt_binding'](parent, summary, 'c' * 64, 'a' * 64, capture_profile='two-minute')


@pytest.mark.parametrize('tamper', [None, 'crypto', 'reader', 'policy', 'output'])
def test_composed_long_budget_reaches_all_terminal_stages(tmp_path, monkeypatch, tamper):
    capture = runpy.run_path(str(Path(__file__).with_name('test_local_av_capture_playback.py')))
    if not hasattr(capture['os'], 'memfd_create'):
        pytest.skip('Linux sealed media control')
    rig = capture['rig'].__wrapped__(tmp_path, monkeypatch)
    options = P['get']('two-minute')['options']
    # A short public fixture exercises the longer profile without a camera or
    # a two-minute delay in CI; private controls cover real-time duration/AES.
    owner, prepared = capture['session'](rig, {}, pes_ids=(224, 225, 192), **options)
    prepared.play()
    report = copy.deepcopy(prepared.report)
    prep, output = report['preparation'], report['output']
    assert prep['seconds_limit'] == 150 and prep['span_limit'] == 120
    assert prep['capture']['decryption']['wall_seconds_limit'] == 150
    assert prep['decode']['input']['processing_seconds_limit'] == 150
    assert prep['online']['policy']['source_span_limit_seconds'] == 120
    assert output['source_span_limit_seconds'] == 120 and owner.closed
    if tamper == 'crypto':
        prep['capture']['decryption'].pop('wall_seconds_limit')
    elif tamper == 'reader':
        prep['decode']['input']['processing_seconds_limit'] = 60
    elif tamper == 'policy':
        prep['online']['policy'].pop('source_span_limit_seconds')
    elif tamper == 'output':
        output.pop('source_span_limit_seconds')
    if tamper is not None:
        with pytest.raises(ValueError, match='budget mismatch'):
            capture['M']['verify_output'](prep, output)
    else:
        capture['M']['verify_output'](prep, output)


@pytest.mark.parametrize('kind,timeout', [('capture', 210), ('verification', 180)])
def test_long_supervisors_forward_profile_and_keep_their_independent_waits(tmp_path, monkeypatch, kind, timeout):
    module = V['LAN'] if kind == 'capture' else V
    calls = []
    class Child:
        def __init__(self, command, **kwargs):
            assert command[command.index('--capture-profile') + 1] == 'two-minute'
            assert kwargs['start_new_session'] is True
        def wait(self, timeout):
            calls.append(timeout)
            raise subprocess.TimeoutExpired('synthetic worker', timeout)
        def poll(self):
            return 0
    monkeypatch.setattr(module['subprocess'], 'Popen', Child)
    monkeypatch.setitem(V['LAN'], 'reap', lambda _child: calls.append('reaped'))
    if kind == 'capture':
        monkeypatch.setitem(module['finish_child'].__globals__, 'reap', lambda _child: calls.append('reaped'))
    args = SimpleNamespace(capture_profile='two-minute', private_config=tmp_path / 'p',
        receipt=tmp_path / 'r', packet_evidence=tmp_path / 'e', expected_package_sha256='a' * 64,
        startup_pairing='strict', audio_overlap_policy='reject', max_audio_overlap_ms=None, max_audio_phase_ms=None)
    with pytest.raises(subprocess.TimeoutExpired):
        if kind == 'capture':
            module['supervise'](args, {}, 'b' * 64, 'channels')
        else:
            module['supervise'](args)
    assert calls == [timeout, 'reaped']
