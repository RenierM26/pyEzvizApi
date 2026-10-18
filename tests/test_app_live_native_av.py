"""Live prefix effects, source-policy coupling, native VQE fingerprints and EOF retention."""
import ctypes.util
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import select
import shutil
import struct
import subprocess
import sys
import threading
import time
from typing import ClassVar

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/app_live_native_av.py'))
SOURCE = runpy.run_path(str(Path(__file__).with_name('test_app_native_scheduled_video.py')))
pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX live output')


def samples():
    rows, inputs, renders = SOURCE['snapshots'](1)
    records = []
    for index, item in enumerate(rows):
        row = dict(item, input_offset=0, render_offset=0)
        payload = inputs[index * 96:(index + 1) * 96] + renders[index * 72:(index + 1) * 72]
        records.append((dict(kind='sample', manifest=row, payload_bytes=len(payload)), payload))
    _, report = SOURCE['load'](*SOURCE['snapshots'](1))
    events = SOURCE['sparse_events'](report)
    # Live source offers carry full descriptors; pixel bindings arrive separately.
    for event in events:
        if 'sample_id' in event:
            row = next(row for row in rows if row['id'] == event['sample_id'])
            event['native_header'] = row['input_header']
            del event['sample_id'], event['pixel_sha256']
    return records, events


def audio(identity='vqe:0', media=0):
    decoded, processed = bytes(range(256)) * 8, bytes(reversed(range(256))) * 8
    row = dict(kind='native_vqe', payload_bytes=6144, id=identity, input_media_ms=media, status=0, source_input_ns=1, source_output_ns=2,
        sample_rate=16000, channels=1, samples=1024, format='s16le',
        decoded_sha256=hashlib.sha256(decoded).hexdigest(), input_sha256=hashlib.sha256(decoded).hexdigest(),
        output_sha256=hashlib.sha256(processed).hexdigest())
    return row, decoded + decoded + processed


class Video:
    driver = 'test'
    calls: ClassVar[list] = []
    def __init__(self, width, height, timeout):
        self.geometry = (width, height)
    def present(self, identity, pixels, timeout):
        Video.calls.append((identity, pixels))
        return dict(pair_id=identity, pixel_sha256=hashlib.sha256(pixels).hexdigest())
    def finish(self, timeout):
        pass
    def abort(self):
        pass


class Audio:
    writes: ClassVar[list] = []
    def alive(self):
        pass
    def write(self, data):
        self.writes.append(bytes(data))
        return len(data)
    def finish(self, timeout):
        pass
    def abort(self):
        pass


@pytest.fixture
def live(monkeypatch):
    Video.calls.clear()
    Audio.writes.clear()
    monkeypatch.setitem(M['Live'].video_write.__globals__['VIDEO'], 'Output', Video)
    monkeypatch.setitem(M['Live'].audio_write.__globals__['PCM'], 'Ffplay', Audio)
    value = M['Live'](M['NATIVE']['NativeSpool'](io.BytesIO()), 1)
    yield value
    value.source_eof_ns = time.monotonic_ns()
    value.close(False)


def pump_until(live, condition):
    end = time.monotonic() + 2
    while not condition():
        live.pump()
        assert time.monotonic() < end
        time.sleep(0.001)


def test_live_video_and_actual_processed_audio_output_before_source_eof(live):
    records, events = samples()
    for row, payload in records:
        live.ingest(row, payload)
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
        live.pump()
    row, payload = audio()
    live.ingest(row, payload)
    pump_until(live, lambda: live.video_completed == 1 and live.audio.written == 1)
    assert live.source_eof_ns is None
    assert Video.calls[0][0] == 'pair:0' and b''.join(Audio.writes) == payload[-2048:]
    assert b''.join(Audio.writes) != payload[:2048]
    assert live.model.result()['queue_admissions_pending'] == []
    assert live.model.scheduler.result()['summary']['video_pending'] == ['pair:1']
    assert not any(a['kind'] == 'audio_passthrough' for a in live.audio.actions)


def test_completed_source_waits_for_exact_verified_samples_not_a_substitute(live):
    records, events = samples()
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.pump()
    assert len(live.waiting) == 1 and not Video.calls
    for row, payload in records:
        live.ingest(row, payload)
    pump_until(live, lambda: live.video_completed == 1)
    assert len(Video.calls) == 1


def test_eof_retains_queued_audio_and_video_without_drain(live):
    records, events = samples()
    for row, payload in records:
        live.ingest(row, payload)
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.ingest(*audio())
    live.source_eof_ns = time.monotonic_ns()
    live.pump()
    assert not Video.calls and not Audio.writes
    result = live.result()
    assert len(result['video_waiting']) == 1
    assert result['audio']['ring_pending'] == ['vqe:0']


def test_audio_host_ring_rejects_newest_and_preserves_source_gaps(live):
    for i in range(26):
        live.ingest(*audio(f'vqe:{i}', i * 64 + (64 if i > 10 else 0)))
    assert live.audio.offered == 26 and live.audio.rejected == 2
    assert len(live.audio.ring) == 24
    assert live.audio.ring[11].media_ms == 768
    assert live.actions[-1]['output_content_time_verified'] is False


@pytest.mark.parametrize('change', ['bad-status', 'bad-input', 'bad-output', 'wrong-size', 'duplicate', 'float-media'])
def test_audio_rejects_unverified_or_ambiguous_causal_pairs(live, change):
    row, payload = audio()
    if change == 'bad-status':
        row['status'] = 1
    elif change == 'bad-input':
        payload = b'x' + payload[1:]
    elif change == 'bad-output':
        row['output_sha256'] = '0' * 64
    elif change == 'wrong-size':
        payload = payload[:-1]
        row['payload_bytes'] = len(payload)
    elif change == 'duplicate':
        live.ingest(row, payload)
    else:
        row['input_media_ms'] = 0.0
    with pytest.raises(ValueError):
        live.ingest(row, payload)


def test_live_sample_checks_whole_record_before_binding(live):
    records, _ = samples()
    row, data = records[0]
    row['manifest']['renderer_layout']['renderer_format'] = 3
    with pytest.raises(ValueError):
        live.ingest(row, data)
    assert not live.samples and not Video.calls


def test_incremental_framing_and_valid_prefix_before_later_error():
    good = M['encode'](dict(kind='event', event=dict(kind='stage_push', at_ms=0)))
    reader = M['Input']()
    rows = []
    for byte in good:
        rows.extend(reader.feed(bytes([byte])))
    assert rows[0][0]['kind'] == 'event' and not rows[0][1]
    reader.eof()
    iterator = reader.feed(good + struct.pack('!I', 8193))
    assert next(iterator)[0]['kind'] == 'event'
    with pytest.raises(ValueError, match='header limit'):
        next(iterator)


@pytest.mark.parametrize('data', [b'x', struct.pack('!I', 2), struct.pack('!I', 2) + b'{}',
    M['encode'](dict(kind='sample'), b'payload')[:-1]])
def test_incomplete_or_invalid_stream_never_passes_eof(data):
    reader = M['Input']()
    with pytest.raises(ValueError):
        list(reader.feed(data))
        reader.eof()


def test_live_sample_identity_and_whole_header_cannot_be_relabelled(live):
    records, events = samples()
    for row, data in records:
        live.ingest(row, data)
    # Identical raw/frame but a changed non-alias word must not bind sampled pixels.
    events[0]['native_header'][20] += 1
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.pump()
    assert not Video.calls and len(live.waiting) == 1
    live.waiting[0]['host_wait_started'] = time.monotonic() - 2
    with pytest.raises(ValueError, match='lacks timely verified'):
        live.pump()


def start_cli(tmp_path):
    if not ctypes.util.find_library('SDL2-2.0') or not shutil.which('ffplay'):
        pytest.skip('optional system SDL2/ffplay unavailable')
    receipt = tmp_path / 'live.json'
    command = [sys.executable, str(Path(__file__).parents[1] / 'tools/app_live_native_av.py'),
        '--play', '--audio', 'observed-native-vqe', '--clock', 'reference-native-events',
        '--eof', 'retain', '--progress', '--receipt', str(receipt)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy'), bufsize=0)
    return process, receipt


def receive(process):
    assert select.select([process.stdout], [], [], 8)[0], 'live progress timed out'
    line = process.stdout.readline()
    assert line, process.stderr.read().decode()
    return json.loads(line)


@pytest.mark.parametrize('invalid_tail', [False, True])
def test_real_live_dual_output_is_acknowledged_before_source_eof_and_later_failure_keeps_prefix(tmp_path, invalid_tail):
    process, receipt = start_cli(tmp_path)
    try:
        records, events = samples()
        for row, payload in records:
            process.stdin.write(M['encode'](row, payload))
        for event in events:
            process.stdin.write(M['encode'](dict(kind='event', event=event)))
        process.stdin.write(M['encode'](*audio()))
        progress: list[dict] = []
        while {r['kind'] for r in progress} != {'host_video_acknowledged', 'host_audio_pipe_written'}:
            progress.append(receive(process))
        # Both outputs have acknowledged real I/O while this producer pipe is still open.
        assert process.poll() is None
        producer_end = time.monotonic_ns()
        if invalid_tail:
            process.stdin.write(struct.pack('!I', 8193))
        process.stdin.close()
        assert process.wait(timeout=10) == (2 if invalid_tail else 0), process.stderr.read().decode()
        result = json.loads(receipt.read_text())
        assert result['host_video_acknowledged'] == 1 and result['audio']['pipe_written'] == 1
        ack = next(r for r in result['actions'] if r['kind'] == 'host_video_acknowledged')
        assert ack['host_completed_ns'] < producer_end
        assert result['reference_app_required'] and not result['host_vqe_implemented']
        assert not result['physical_lip_sync_measured']
        assert result['native_source_replay']['scheduler']['summary']['video_pending'] == ['pair:1']
        if invalid_tail:
            assert result['status'] == 'failed' and 'header limit' in result['error']
        else:
            assert result['source_eof_monotonic_ns'] >= producer_end
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=12)
        process.stdout.close()
        process.stderr.close()


def test_video_backpressure_does_not_stop_audio_ingestion_or_other_output(live, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def blocked(pair, pixels, width, height):
        entered.set()
        assert release.wait(timeout=2)
        return dict(pair_id=pair['pair_id'])
    monkeypatch.setattr(live, 'video_write', blocked)
    records, events = samples()
    for row, payload in records:
        live.ingest(row, payload)
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.pump()
    assert entered.wait(timeout=1)
    try:
        live.ingest(*audio())
        pump_until(live, lambda: live.audio.written == 1)
        assert live.video_completed == 0
    finally:
        release.set()
    pump_until(live, lambda: live.video_completed == 1)


def test_host_video_backlog_fails_without_implicit_drop(live):
    records, events = samples()
    for row, payload in records:
        live.ingest(row, payload)
    for event in events[:-1]:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.waiting.extend(dict(pair_id=f'blocked:{i}') for i in range(6))
    with pytest.raises(ValueError, match='backlog limit'):
        live.ingest(dict(kind='event', payload_bytes=0, event=events[-1]), b'')
    assert len(live.waiting) == 6 and live.video_completed == 0


def test_native_vqe_source_observation_time_cannot_be_reversed(live):
    row, payload = audio()
    row.update(source_input_ns=2, source_output_ns=1)
    with pytest.raises(ValueError, match='source observation times'):
        live.ingest(row, payload)


def test_truncated_payload_after_admission_retains_old_effects(live):
    reader = M['Input']()
    row, data = audio()
    good = M['encode'](row, data)
    for header, payload in reader.feed(good + good[:-1]):
        live.ingest(header, payload)
    with pytest.raises(ValueError, match='truncated'):
        reader.eof()
    assert live.audio.offered == 1 and live.audio.ring[0].identity == 'vqe:0'


@pytest.mark.parametrize(('field', 'value'), [('sample_rate', 48000), ('channels', 2),
    ('samples', 512), ('format', 'f32le'), ('channels', True)])
def test_audio_format_is_explicit_and_exact(live, field, value):
    row, payload = audio()
    row[field] = value
    with pytest.raises(ValueError, match='PCM format'):
        live.ingest(row, payload)


def test_selected_pixel_budget_includes_repeated_source_samples(live):
    records, events = samples()
    for row, payload in records:
        live.ingest(row, payload)
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.video_pixels = M['NATIVE']['SCHEDULED']['MAX_EXPORT_PIXELS']
    with pytest.raises(ValueError, match='selected pixel limit'):
        live.pump()
    assert not Video.calls


def test_missing_pixel_deadline_is_enforced_even_while_other_video_job_is_busy(live):
    _, events = samples()
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    class Busy:
        def done(self):
            return False
    live.video_job = Busy()
    live.waiting[0]['host_wait_started'] = time.monotonic() - 2
    try:
        with pytest.raises(ValueError, match='lacks timely verified'):
            live.pump()
    finally:
        live.video_job = None


def test_late_sample_cannot_evade_wait_deadline_just_because_it_arrived_before_pump(live):
    records, events = samples()
    for event in events:
        live.ingest(dict(kind='event', payload_bytes=0, event=event), b'')
    live.waiting[0]['host_wait_started'] = time.monotonic() - 2
    for row, data in records:
        live.ingest(row, data)
    with pytest.raises(ValueError, match='verified after selection deadline'):
        live.pump()
    assert not Video.calls
