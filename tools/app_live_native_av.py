"""Bounded reference-assisted LIVE handoff of native selections and native VQE PCM.

The Android reference app remains the source/processor. This is not an independent
EZVIZ decoder or VQE port. Host acknowledgements are not physical presentation.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
import hashlib
import io
import json
import math
import os
from pathlib import Path
import runpy
import select
import struct
import sys
import tempfile
import threading
import time
from typing import Any

VIDEO = runpy.run_path(str(Path(__file__).with_name('app_native_video_preview.py')))
NATIVE = VIDEO['NATIVE']
PROFILE = runpy.run_path(str(Path(__file__).parent / 'reference_stream/profile.py'))
PCM = runpy.run_path(str(Path(__file__).with_name('app_pcm_playback.py')))
MAX_HEADER = 8192
MAX_PAYLOAD = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_SECONDS = 60
MIN_DEADLINE = 0.1


def encode(row: dict[str, Any], payload: bytes = b'') -> bytes:
    data = json.dumps(dict(row, payload_bytes=len(payload))).encode()
    if len(data) > MAX_HEADER or len(payload) > MAX_PAYLOAD:
        raise ValueError('live record size limit exceeded')
    return struct.pack('!I', len(data)) + data + payload


class Input:
    """Incremental binary records; valid prefix survives a later malformed record."""
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.header: dict[str, Any] | None = None
        self.size: int | None = None
        self.total = self.records = 0

    def feed(self, chunk: bytes) -> Any:
        self.buffer.extend(chunk)
        while True:
            if self.size is None:
                if len(self.buffer) < 4:
                    break
                self.size = struct.unpack('!I', self.buffer[:4])[0]
                del self.buffer[:4]
                if not 0 < self.size <= MAX_HEADER:
                    raise ValueError('live header limit exceeded')
            if self.header is None:
                if len(self.buffer) < self.size:
                    break
                row = json.loads(self.buffer[:self.size])
                del self.buffer[:self.size]
                if (not isinstance(row, dict) or type(row.get('payload_bytes')) is not int
                        or not 0 <= row['payload_bytes'] <= MAX_PAYLOAD):
                    raise ValueError('invalid live payload length')
                self.header = row
                self.size = row['payload_bytes']
                if self.total + self.size > MAX_TOTAL or self.records >= 10_000:
                    raise ValueError('live total/event limit exceeded')
            if len(self.buffer) < self.size:
                break
            payload = bytes(self.buffer[:self.size])
            del self.buffer[:self.size]
            self.total += self.size
            self.records += 1
            row = self.header
            self.header = self.size = None
            yield row, payload
        if len(self.buffer) > MAX_PAYLOAD + MAX_HEADER:
            raise ValueError('live input buffer limit exceeded')

    def eof(self) -> None:
        if self.buffer or self.header is not None or self.size is not None:
            raise ValueError('truncated live record at EOF')


PcmBase: Any = PCM['PcmQueue']


class ProcessedQueue(PcmBase):
    """Host sink ring for ALREADY processed native PCM; never calls it passthrough DSP."""
    writing: Any

    def begin(self, now: float) -> None:
        if self.writing is None and self.ring:
            self.writing = self.ring.popleft()
            self.offset, self.write_started = 0, now
            self.emit('observed_native_vqe_output_ready', self.writing, now)
            self.emit('audio_pipe_write_started', self.writing, now)


class Live:
    """One owner for source policy, two bounded in-flight host I/O operations."""
    def __init__(self, spool: Any, timeout: float, progress: Any = None) -> None:
        self.profile = PROFILE["Profile"]()
        self.spool, self.timeout = spool, timeout
        self.progress = progress
        self.model = NATIVE['NativeReplay'](dict(samples=[]), allow_metadata_only=True)
        self.audio = ProcessedQueue()
        self.samples: dict[tuple[int, ...], str] = {}
        self.sample_reports: list[dict[str, Any]] = []
        self.sample_times: dict[tuple[int, ...], float] = {}
        self.waiting: deque[dict[str, Any]] = deque()
        self.actions: list[dict[str, Any]] = []
        self.geometry: tuple[int, int] | None = None
        self.audio_ids: set[str] = set()
        self.total = 0
        self.source_eof_ns: int | None = None
        self.started = time.monotonic()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='live-native-output')
        self.cancel = threading.Event()
        self.video_backend: Any = None
        self.audio_backend: Any = None
        self.video_job: Future[Any] | None = None
        self.audio_job: Future[Any] | None = None
        self.video_active: dict[str, Any] | None = None
        self.audio_progress = 0
        self.video_completed = 0
        self.video_pixels = 0
        self.current_sample_ids: list[str] = []

    def ingest(self, row: dict[str, Any], payload: bytes) -> None:
        kind = row.get('kind')
        if type(row.get('payload_bytes')) is not int or row['payload_bytes'] != len(payload):
            raise ValueError('live payload length mismatch')
        self.total += len(payload)
        if self.total > MAX_TOTAL:
            raise ValueError('live payload budget exceeded')
        if kind == 'sample':
            if set(row) != {'kind', 'payload_bytes', 'manifest'} or len(self.sample_reports) >= 32:
                raise ValueError('invalid or excessive live sample')
            manifest = row['manifest']
            before, after = NATIVE['AUDIT']['header'](manifest.get('input_header')), NATIVE['AUDIT']['header'](manifest.get('render_header'))
            width, height, _ = NATIVE['AUDIT']['geometry'](before, after)
            split = width * height * 3 // 2
            if tuple(before) in self.samples or manifest.get('id') in self.spool.records:
                raise ValueError('duplicate or ambiguous live native sample')
            with self.profile.measure('native_sample_audit', bytes=len(payload)):
                report = NATIVE['AUDIT']['audit'](io.BytesIO(payload[:split]), io.BytesIO(payload[split:]),
                    io.BytesIO((json.dumps(manifest) + '\n').encode()), verify_renderer=True, observer=self.spool.capture)
            self.samples[tuple(before)] = report['samples'][0]['id']
            self.sample_times[tuple(before)] = time.monotonic()
            self.sample_reports.extend(report['samples'])
        elif kind == 'event':
            if set(row) != {'kind', 'payload_bytes', 'event'} or payload:
                raise ValueError('invalid live event record')
            previous = len(self.model.selected)
            self.model.step(row['event'])
            for pair in self.model.selected[previous:]:
                if len(self.waiting) >= 6:
                    raise ValueError('host video backlog limit exceeded; no implicit drop')
                self.waiting.append(dict(pair, host_wait_started=time.monotonic()))
        elif kind == 'native_vqe':
            self.ingest_audio(row, payload)
        else:
            raise ValueError('unknown live record kind')

    def ingest_audio(self, row: dict[str, Any], payload: bytes) -> None:
        fields = {'kind', 'payload_bytes', 'id', 'input_media_ms', 'status',
                  'decoded_sha256', 'input_sha256', 'output_sha256', 'source_input_ns', 'source_output_ns',
                  'sample_rate', 'channels', 'samples', 'format'}
        if set(row) != fields or len(payload) != 6144 or type(row['status']) is not int or row['status'] != 0:
            raise ValueError('requires successful paired native VQE 1024-sample mono16kHz records')
        expected_format = dict(sample_rate=16000, channels=1, samples=1024, format='s16le')
        if any(type(row[k]) is not type(v) or row[k] != v for k, v in expected_format.items()):
            raise ValueError('unsupported native VQE PCM format')
        if (any(type(row[k]) is not int for k in ('source_input_ns', 'source_output_ns'))
                or not 0 <= row['source_input_ns'] <= row['source_output_ns'] < 2**63):
            raise ValueError('invalid native VQE source observation times')
        identity = row['id']
        media = row['input_media_ms']
        if (not isinstance(identity, str) or not 1 <= len(identity) <= 128 or identity in self.audio_ids
                or type(media) is not int or not 0 <= media <= 0xffffffff):
            raise ValueError('invalid or duplicate live VQE identity/source time')
        parts = [payload[i:i + 2048] for i in (0, 2048, 4096)]
        if (parts[0] != parts[1] or any(hashlib.sha256(p).hexdigest() != row[k]
                for p, k in zip(parts, ('decoded_sha256', 'input_sha256', 'output_sha256'), strict=True))):
            raise ValueError('native VQE causal input/output fingerprint mismatch')
        self.audio_ids.add(identity)
        admitted = self.audio.offer(PCM['Block'](identity, media, parts[2]), time.monotonic() - self.started)
        self.actions.append(dict(kind='native_vqe_received', id=identity, input_media_ms=media,
            input_sha256=row['input_sha256'], output_sha256=row['output_sha256'], admitted=admitted,
            host_received_ns=time.monotonic_ns(), source_input_ns=row['source_input_ns'],
            source_output_ns=row['source_output_ns'], output_content_time_verified=False))

    def video_write(self, pair: dict[str, Any], pixels: bytes, width: int, height: int) -> dict[str, Any]:
        if self.video_backend is None:
            with self.profile.measure('video_output_startup'):
                self.video_backend = VIDEO['Output'](width * 2, height, self.timeout)
        if self.cancel.is_set():
            raise ValueError('live output cancelled')
        with self.profile.measure('video_output', bytes=len(pixels)):
            return self.video_backend.present(pair['pair_id'], pixels, self.timeout)

    def audio_write(self, data: bytes) -> int:
        if self.audio_backend is None:
            with self.profile.measure('audio_output_startup'):
                self.audio_backend = PCM['Ffplay']()
        deadline = time.monotonic() + self.timeout
        self.audio_progress = 0
        while self.audio_progress < len(data):
            if self.cancel.is_set() or time.monotonic() >= deadline:
                raise ValueError('live audio cancelled or write deadline exceeded')
            self.audio_backend.alive()
            try:
                count = self.audio_backend.write(data[self.audio_progress:])
            except BlockingIOError:
                time.sleep(0.005)
            else:
                if type(count) is not int or not 0 < count <= len(data) - self.audio_progress:
                    raise ValueError('invalid live audio write progress')
                self.audio_progress += count
        return self.audio_progress

    def harvest(self) -> None:
        if self.video_job is not None and self.video_job.done():
            ack = self.video_job.result()
            self.actions.append(dict(kind='host_video_acknowledged', selection=self.video_active,
                sample_ids=list(self.current_sample_ids), acknowledgement=ack, host_completed_ns=time.monotonic_ns()))
            if self.progress is not None:
                self.progress(self.actions[-1])
            self.video_completed += 1
            self.video_job = None
            self.video_active = None
        if self.audio_job is not None and self.audio_job.done():
            try:
                count = self.audio_job.result()
            except BaseException:
                self.audio.offset = self.audio_progress
                raise
            identity = self.audio.writing.identity
            digest = hashlib.sha256(self.audio.writing.pcm).hexdigest()
            self.audio.accept(count, time.monotonic() - self.started)
            self.actions.append(dict(kind='host_audio_pipe_written', id=identity, bytes=count,
                output_sha256=digest, host_completed_ns=time.monotonic_ns()))
            if self.progress is not None:
                self.progress(self.actions[-1])
            self.audio_job = None

    def check_waiting(self) -> None:
        for pair in self.waiting:
            headers = [tuple(self.model.metadata_only[o]['native_header']) for o in pair['offer_ids']]
            times = [self.sample_times.get(header) for header in headers]
            deadline = pair['host_wait_started'] + self.timeout
            if all(value is not None for value in times):
                if max(value for value in times if value is not None) > deadline:
                    raise ValueError('live pixels verified after selection deadline')
            elif time.monotonic() > deadline:
                raise ValueError('completed selection lacks timely verified live pixels')

    def pump(self) -> None:
        self.harvest()
        if self.source_eof_ns is not None:
            return  # no source-ring or completed-selection drain after EOF
        self.check_waiting()
        if self.video_job is None and self.waiting:
            pair = self.waiting[0]
            ids = [self.samples.get(tuple(self.model.metadata_only[o]['native_header'])) for o in pair['offer_ids']]
            if all(identity is not None for identity in ids):
                if self.video_completed >= 32:
                    raise ValueError('live video output frame limit exceeded')
                records = [self.spool.records[i] for i in ids]
                geometry = (records[0]['width'], records[0]['height'])
                if (geometry != (records[1]['width'], records[1]['height'])
                        or (self.geometry is not None and self.geometry != geometry)
                        or geometry[0] * 2 * geometry[1] > NATIVE['MAX_PAIR_PIXELS']):
                    raise ValueError('live video requires constant bounded equal lens geometry')
                pixels_this_pair = geometry[0] * 2 * geometry[1]
                if self.video_pixels + pixels_this_pair > NATIVE['SCHEDULED']['MAX_EXPORT_PIXELS']:
                    raise ValueError('live selected pixel limit exceeded')
                self.video_pixels += pixels_this_pair
                self.geometry = geometry
                with self.profile.measure('spool_read_compose'):
                    pixels = NATIVE['SCHEDULED']['PREVIEW']['compose'](*[self.spool.read(i) for i in ids], *geometry)
                self.waiting.popleft()
                self.video_active = pair
                self.current_sample_ids = [i for i in ids if i is not None]
                self.actions.append(dict(kind='host_video_requested', selection=pair, sample_ids=list(ids),
                    pixel_sha256=hashlib.sha256(pixels).hexdigest(), bytes=len(pixels), host_requested_ns=time.monotonic_ns()))
                self.video_job = self.executor.submit(self.video_write, pair, pixels, *geometry)
        if self.audio_job is None and self.audio.pending:
            self.audio.begin(time.monotonic() - self.started)
            self.audio_job = self.executor.submit(self.audio_write, self.audio.writing.pcm)

    def abort_outputs(self) -> list[str]:
        errors = []
        for backend in (self.video_backend, self.audio_backend):
            if backend is not None:
                try:
                    backend.abort()
                except Exception as error:
                    errors.append(str(error))
        return errors

    def close(self, successful: bool) -> None:
        if not successful:
            self.cancel.set()
            self.abort_outputs()
        try:
            if successful:
                until = time.monotonic() + 2 * self.timeout + 1
                while self.video_job is not None or self.audio_job is not None:
                    self.pump()
                    if time.monotonic() > until:
                        raise ValueError('live active operation shutdown deadline exceeded')
                    time.sleep(0.005)
                for backend in (self.video_backend, self.audio_backend):
                    if backend is not None:
                        with self.profile.measure('output_finish', backend=type(backend).__name__):
                            backend.finish(self.timeout)
        finally:
            self.cancel.set()
            errors = self.abort_outputs()
            try:
                self.executor.shutdown(wait=True, cancel_futures=True)
            finally:
                errors.extend(self.abort_outputs())
            if errors:
                raise ValueError('live output cleanup failed: ' + '; '.join(errors))

    def result(self) -> dict[str, Any]:
        return dict(stage_profile=self.profile.result(), native_source_replay=self.model.result(), native_samples=self.sample_reports,
            actions=self.actions, source_eof_monotonic_ns=self.source_eof_ns,
            host_video_acknowledged=self.video_completed, video_waiting=list(self.waiting),
            video_active=self.video_active, video_sample_bindings=self.samples_as_list(),
            audio=dict(actions=self.audio.actions, offered=self.audio.offered, rejected=self.audio.rejected,
                pipe_written=self.audio.written, ring_pending=[b.identity for b in self.audio.ring],
                write_pending=self.audio.writing.identity if self.audio.writing else None, partial_pipe_bytes=self.audio.offset),
            sdl_video_driver=self.video_backend.driver if self.video_backend else None)

    def samples_as_list(self) -> list[dict[str, Any]]:
        return [dict(native_header=list(header), sample_id=identity) for header, identity in self.samples.items()]


def run(live: Live, fd: int) -> None:
    source = Input()
    while True:
        live.pump()
        if time.monotonic() - live.started > MAX_SECONDS:
            raise ValueError('live session limit exceeded')
        if select.select([fd], [], [], 0.005)[0]:
            chunk = os.read(fd, 65536)
            if not chunk:
                source.eof()
                live.source_eof_ns = time.monotonic_ns()
                return
            for row, payload in source.feed(chunk):
                live.ingest(row, payload)
                live.pump()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--play', action='store_true', required=True)
    parser.add_argument('--audio', choices=['observed-native-vqe'], required=True)
    parser.add_argument('--clock', choices=['reference-native-events'], required=True)
    parser.add_argument('--eof', choices=['retain'], required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--deadline', type=float, default=5)
    parser.add_argument('--progress', action='store_true', help='metadata-only progress JSONL on stdout')
    args = parser.parse_args()
    if os.name != 'posix' or not math.isfinite(args.deadline) or not MIN_DEADLINE <= args.deadline <= 30:
        parser.error('requires POSIX and finite deadline 0.1..30 seconds')
    code, status, error = 0, 'source-ended-pending-retained', None
    try:
        with args.receipt.open('x') as receipt, tempfile.TemporaryFile() as temporary:
            progress = (lambda row: print(json.dumps(row), flush=True)) if args.progress else None
            live = Live(NATIVE['NativeSpool'](temporary), args.deadline, progress)
            try:
                run(live, sys.stdin.fileno())
                live.close(True)
            except (Exception, KeyboardInterrupt) as failure:
                code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                status, error = ('cancelled' if code == 130 else 'failed'), f'{type(failure).__name__}: {failure}'
                try:
                    live.close(False)
                except Exception as cleanup:
                    error += f'; cleanup: {cleanup}'
            json.dump(VIDEO['NATIVE']['receipt_names'](dict(profile='reference-assisted-live-native-av-v1',
                status=status, error=error, reference_app_required=True, host_vqe_implemented=False,
                processor='observed-native-ezviz-vqe-output-not-host-dsp',
                processor_provenance_authenticated=False, output_content_time_verified=False,
                physical_lip_sync_measured=False, host_ack_is_physical_output=False,
                eof_policy='retain-no-source-drain', **live.result())), receipt, sort_keys=True)
            receipt.write('\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'live native AV failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
