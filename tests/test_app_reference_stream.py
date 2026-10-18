"""Build gating, native projection, binary evidence and honest benchmark accounting."""
import hashlib
import io
import json
from pathlib import Path
import runpy
import time
from typing import Any, ClassVar

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/app_reference_stream.py'))
P = M['PROJECT']
SOURCE = runpy.run_path(str(Path(__file__).with_name('test_app_live_native_av.py')))


def test_profile_checks_both_exact_elf_hashes_before_acceptance(monkeypatch):
    payloads = {name: b'\x7fELF' + name.encode() for name in M['HASHES']}
    monkeypatch.setitem(M['verify_profile'].__globals__, 'HASHES', {n: hashlib.sha256(b).hexdigest() for n, b in payloads.items()})
    profile: dict[str, Any] = dict(arch='arm', pointerSize=4, modules=[dict(name=n, path=n) for n in payloads])
    assert M['verify_profile'](profile, payloads.__getitem__)['arch'] == 'arm'
    with pytest.raises(ValueError, match='ELF'):
        M['verify_profile'](profile, lambda path: payloads[path] + b'changed')
    with pytest.raises(ValueError, match='ABI'):
        M['verify_profile'](dict(profile, arch='arm64'), payloads.__getitem__)
    with pytest.raises(ValueError, match='missing'):
        M['verify_profile'](dict(profile, modules=profile['modules'][:1]), payloads.__getitem__)


def test_capture_flushes_hashed_bytes_before_publishing_rows(tmp_path):
    capture = M['Capture'](tmp_path)
    data = b'original native buffer'
    row = dict(event='native_pixels', device_mono_ns=1, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
    try:
        capture.message(dict(type='send', payload=row), data)
        found = capture.snapshot()[0]
        assert P['blob'](tmp_path, found) == data
        assert json.loads((tmp_path / 'events.jsonl').read_text()) == found
        assert found['collector_received_ns'] <= time.monotonic_ns()
        capture.message(dict(type='error', description='hook failure'), None)
        with pytest.raises(ValueError, match='hook failure'):
            capture.snapshot()
    finally:
        capture.close()


def test_capture_rejects_budget_overflow_before_payload_write(tmp_path, monkeypatch):
    monkeypatch.setitem(M['Capture'].message.__globals__, 'MAX_CAPTURE_BYTES', 1)
    capture = M['Capture'](tmp_path)
    try:
        capture.message(dict(type='send', payload=dict(event='native_pixels', device_mono_ns=1)), b'xx')
        with pytest.raises(ValueError, match='binary limit'):
            capture.snapshot()
        assert not list(tmp_path.glob('*.bin'))
    finally:
        capture.close()


@pytest.mark.parametrize('name', ['../escape.bin', '/tmp/escape.bin'])
def test_blob_never_follows_outside_capture_paths(tmp_path, name):
    with pytest.raises(ValueError, match='outside'):
        P['blob'](tmp_path, dict(file=name))


def test_blob_rejects_changed_or_truncated_content(tmp_path):
    (tmp_path / 'data.bin').write_bytes(b'abc')
    row = dict(file='data.bin', bytes=4, offset=0, sha256=hashlib.sha256(b'abcd').hexdigest())
    with pytest.raises(ValueError, match='fingerprint'):
        P['blob'](tmp_path, row)
    row.update(bytes=3, sha256='0' * 64)
    with pytest.raises(ValueError, match='fingerprint'):
        P['blob'](tmp_path, row)


def native_rows():
    records, _ = SOURCE['samples']()
    rows = [dict(event='ready', device_mono_ns=0)]
    for i, (sample, _) in enumerate(records):
        h = sample['manifest']['input_header']
        rows.append(dict(event='decoded_picture', device_mono_ns=(i + 1) * 1000000,
            payload_is_null=False, payload_bytes=96, codec=133, tracks=2, sid=h[1],
            call=i, raw=h[7], media_ms=h[5], frame=h[10], header_words=h))
    h0 = records[0][0]['manifest']['input_header']
    h1 = records[1][0]['manifest']['input_header']
    node = dict(sid=224, raw=h1[7], frame=h1[10], secondary_sid=225, secondary_raw=h0[7], secondary_frame=h0[10], media_ms=0)
    rows.extend([
        dict(event='video_queue_admitted', device_mono_ns=3000000, copy=dict(node=node), queue='q', result=1),
        dict(event='schedule_enter', device_mono_ns=70000000, call=10, frame_speed=1,
            smooth=0, mode=0, sync=0, node_limit=6, pending_rebase=0, origin_ms=0,
            picture_ms=0, arg1=0, elapsed_ms=50, speed=1, bias=50, frame_interval=0),
        dict(event='node_count', device_mono_ns=70000001, schedule=10, data=1),
        dict(event='display_request', device_mono_ns=70000002, schedule=10),
        dict(event='node_peek', device_mono_ns=71000000, queue='q', node=node),
        dict(event='node_commit', device_mono_ns=71000001, queue='q'),
        dict(event='render_callback', device_mono_ns=72000000, schedule=10, node=node),
        dict(event='node_count', device_mono_ns=72000001, schedule=10, data=0),
    ])
    return rows


def test_projection_preserves_observed_boundaries_and_replays_without_inventing():
    rows = native_rows()
    events = P['project'](rows, rows[-1]['device_mono_ns'])
    replay = M['LIVE']['NATIVE']['NativeReplay'](dict(samples=[]), allow_metadata_only=True)
    for event in events:
        replay.step(event)
    assert [r['pair_id'] for r in replay.selected] == ['pair:0']
    assert [r['kind'] for r in events][-3:] == ['video_observed_tick', 'render_release', 'video_display_complete']
    assert events[-1]['at_ms'] == 72


@pytest.mark.parametrize('change', ['admission', 'profile', 'drop'])
def test_projection_fails_closed_on_unsupported_or_ambiguous_observations(change):
    rows = native_rows()
    if change == 'admission':
        rows.insert(4, rows[3].copy())
    elif change == 'profile':
        next(r for r in rows if r['event'] == 'schedule_enter')['sync'] = 1
    else:
        rows.append(dict(event='drop_request', device_mono_ns=72000001))
    with pytest.raises(ValueError):
        P['project'](rows, 72000001)


def test_metrics_separate_clocks_before_eof_and_retained_audio():
    class Host:
        writes: ClassVar[list] = [dict(kind='sample', completed_ns=4000000, started_ns=1000000, collector_received_ns=0)]
    receipt = dict(source_eof_monotonic_ns=1000000000, actions=[
        dict(kind='host_video_acknowledged', host_completed_ns=1000000),
        dict(kind='host_video_acknowledged', host_completed_ns=900000000),
        dict(kind='host_audio_pipe_written', host_completed_ns=500000000),
        dict(kind='host_audio_pipe_written', host_completed_ns=1001000000)],
        audio=dict(rejected=2, ring_pending=['retained'], partial_pipe_bytes=0, actions=[
            dict(kind='audio_admitted'), dict(kind='audio_admitted'), dict(kind='audio_pipe_write_completed')]))
    result = M['metrics']([], Host(), receipt, 20)
    assert result['video_before_eof'] == 2 and result['audio_before_eof'] == 1
    assert result['host_audio_peak_pending_including_active'] == 2
    assert result['host_audio_rejected'] == 2 and result['host_audio_retained'] == 1
    assert result['collector_callback_to_write_complete_ms'] == [4]
    assert result['cross_device_transport_delay_ms'] is None
    assert not result['requested_host_video_span_reached'] and not result['sustained_realtime_verified']


def test_audio_ambiguity_never_becomes_an_index_join(tmp_path):
    class Host:
        calls: ClassVar[list] = []
        def send(self, *args):
            self.calls.append(args)
    host = Host()
    producer = M['Producer'](tmp_path, host, 1)
    rows = [dict(event='audio_decoded', device_mono_ns=1, id=i, sha256='same') for i in (1, 2)]
    rows += [dict(event='audio_vqe_input', device_mono_ns=2, call=3, sha256='same'),
             dict(event='audio_vqe_output', device_mono_ns=3, call=3)]
    producer.audio(rows)
    assert not host.calls and not producer.processed


def test_host_dual_pipe_cleanup_and_metrics_from_real_dummy_io(tmp_path):
    prior = runpy.run_path(str(Path(__file__).with_name('test_app_live_native_av.py')))
    if not prior['ctypes'].util.find_library('SDL2-2.0') or not prior['shutil'].which('ffplay'):
        pytest.skip('optional SDL/ffplay unavailable')
    host = M['Host'](tmp_path)
    try:
        records, events = SOURCE['samples']()
        for row, data in records:
            host.send(row, data, time.monotonic_ns())
        for event in events:
            host.send(dict(kind='event', event=event))
        # Paced input spans multiple independent audio writes while stdin remains open.
        for index in range(20):
            row, data = SOURCE['audio'](f'block:{index}', index * 64)
            host.send(row, data, time.monotonic_ns())
            time.sleep(.02)
            host.drain()
        until = time.monotonic() + 5
        while len(host.progress) < 21:
            host.drain()
            assert time.monotonic() < until
            time.sleep(.005)
        host.finish()
        receipt = json.loads((tmp_path / 'live-receipt.json').read_text())
        result = M['metrics']([], host, receipt, 20)
        assert result['audio_before_eof'] == 20 and result['video_before_eof'] == 1
        assert result['host_audio_rejected'] == 0
        assert result['host_audio_write_cadence']['span_ms'] > 100
    finally:
        host.close()
    assert host.process.poll() is not None


def test_synthetic_raw_observations_project_audited_pixels_through_real_source_model(tmp_path):
    class Host:
        records: ClassVar[list] = []
        def send(self, row, data=b'', observed_ns=None):
            self.records.append((dict(row, payload_bytes=len(data)), data))
    rows = native_rows()
    samples, _ = SOURCE['samples']()
    for i, (record, data) in enumerate(samples):
        manifest = record['manifest']
        before, after = manifest['input_header'], manifest['render_header']
        sid, raw, frame = before[1], before[7], before[10]
        for event, header, content in [('native_pixels', before, data[:96]), ('native_render_pixels', after, data[96:])]:
            name = f'{event}-{sid}.bin'
            (tmp_path / name).write_bytes(content)
            rows.append(dict(event=event, sid=sid, raw=raw, frame=frame, header_words=header,
                file=name, offset=0, bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
                device_mono_ns=60000000))
        layout = manifest['renderer_layout']
        rows.append(dict(event='update', id=i, device_mono_ns=20000000 + i * 20000000, format=layout['renderer_format'],
            width=layout['width'], height=layout['height'], cNative=dict(payload_matches=True,
                header=dict(sid=sid, raw=raw, frame=frame))))
        rows.append(dict(event='update_return', id=i, device_mono_ns=30000000 + i * 20000000))
        for upload in layout['uploads']:
            rows.append(dict(upload, event='plane_upload', id=i, device_mono_ns=21000000 + i * 20000000))
        for sampler in layout['samplers']:
            rows.append(dict(event='sampler', device_mono_ns=22000000 + i * 20000000, name=sampler['name'],
                arg2=sampler['unit'], arg3=sampler['texture']))
    rows.sort(key=lambda r: r['device_mono_ns'])
    host = Host()
    producer = M['Producer'](tmp_path, host, 1)
    producer.pump(rows)
    assert len(producer.sampled) == 2
    spool = M['LIVE']['NATIVE']['NativeSpool'](io.BytesIO())
    live = M['LIVE']['Live'](spool, 1)
    try:
        for row, data in host.records:
            live.ingest(row, data)
        assert len(live.model.selected) == 1
        assert len(live.sample_reports) == 2
        assert live.model.selected[0]['pair_id'] == 'pair:0'
    finally:
        live.source_eof_ns = time.monotonic_ns()
        live.close(False)


def test_host_constructor_failure_closes_every_open_evidence_file(tmp_path, monkeypatch):
    opened = []
    original = Path.open
    def track(path, *args, **kwargs):
        handle = original(path, *args, **kwargs)
        opened.append(handle)
        return handle
    def fail(*args, **kwargs):
        raise OSError('subprocess startup failed')
    monkeypatch.setattr(Path, 'open', track)
    monkeypatch.setattr(M['Host'].__init__.__globals__['subprocess'], 'Popen', fail)
    with pytest.raises(OSError, match='startup failed'):
        M['Host'](tmp_path)
    assert opened and all(handle.closed for handle in opened)


def test_failed_host_receipt_still_produces_prefix_measurements(tmp_path):
    class Host:
        writes: ClassVar[list] = []
    class Producer:
        sent: ClassVar[list] = []
        sampled: ClassVar[set] = set()
        processed: ClassVar[set] = set()
    receipt = dict(status='failed', error='drain deadline', source_eof_monotonic_ns=2,
        actions=[dict(kind='host_audio_pipe_written', host_completed_ns=1)],
        audio=dict(actions=[], rejected=0, ring_pending=[], partial_pipe_bytes=0))
    result = M['observation_report']([], Host(), Producer(), receipt, 20, {})
    assert result['audio_before_eof'] == 1
    assert result['captured_pairs_not_forwarded'] is None
    assert not result['sustained_realtime_verified']


def test_observation_window_does_not_spend_media_budget_waiting_for_manual_start():
    window = M['Window'](20)
    base = window.ready_ns
    assert window.stop_reason([], base + 14 * 10**9) is None
    rows = [dict(event='decoded_picture', payload_is_null=False, collector_received_ns=base + 14 * 10**9)]
    assert window.stop_reason(rows, base + 30 * 10**9) is None
    assert window.stop_reason(rows, base + 34 * 10**9) == 'duration-limit'
    unused = M['Window'](20)
    assert unused.stop_reason([], unused.ready_ns + 15 * 10**9) == 'startup-timeout'


def test_cancelling_a_running_host_keeps_receipt_and_reaps_output_group(tmp_path):
    prior = runpy.run_path(str(Path(__file__).with_name('test_app_live_native_av.py')))
    if not prior['shutil'].which('ffplay'):
        pytest.skip('optional ffplay unavailable')
    host = M['Host'](tmp_path)
    try:
        row, data = SOURCE['audio']()
        host.send(row, data)
        until = time.monotonic() + 5
        while not host.progress:
            host.drain()
            assert time.monotonic() < until
            time.sleep(.005)
    finally:
        host.close()
    receipt = json.loads((tmp_path / 'live-receipt.json').read_text())
    assert receipt['status'] == 'cancelled' and receipt['audio']['pipe_written'] == 1
    with pytest.raises(ProcessLookupError):
        M['os'].killpg(host.process.pid, 0)
