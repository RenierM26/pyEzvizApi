"""Opt-in incremental host HEVC preview of reference-selected pairs and native VQE.

Sampled native pixel parity is NOT per-frame native audit, scheduler replay,
independent camera access, host DSP or physical A/V synchronization.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import runpy
import select
import signal
import subprocess
import sys
import time
from typing import Any

BASE = Path(__file__).parent
LIVE = runpy.run_path(str(BASE / 'app_live_native_av.py'))
NATIVE = LIVE['NATIVE']
VIDEO = LIVE['VIDEO']
MAX_UNITS = 600
MAX_RECORDS = 4000
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_PIXELS = 192 * 1024 * 1024
MAX_WAITING = 6
MIN_DEADLINE = 0.1
HASHES = {
    'libPlayCtrl.so': 'a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc',
    'libezstreamclient.so': '184f8eb8ce29a2f4ce5c6a915dd9f5649907f55e410a92c6a3db8b414f665f6b',
}


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def words(value: Any, length: int) -> list[int]:
    require(isinstance(value, list) and len(value) == length
            and all(type(n) is int and 0 <= n < 2**32 for n in value), 'invalid native words')
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key(header: list[int]) -> tuple[int, int, int]:
    return header[1], header[7], header[10]


def audio_options() -> tuple[str, str]:
    result = subprocess.run(['ffplay', '-hide_banner', '-h', 'demuxer=s16le'],
                            capture_output=True, text=True, timeout=3, check=True)
    text = result.stdout + result.stderr
    require(len(text) <= 65536, 'ffplay capability response limit')
    if re.search(r'^\s+-ch_layout\s', text, re.MULTILINE):
        return '-ch_layout', 'mono'
    require(re.search(r'^\s+-channels\s', text, re.MULTILINE), 'ffplay lacks explicit mono PCM support')
    return '-channels', '1'


@dataclass(frozen=True)
class OutputBlock:
    identity: str
    pcm: bytes
    media_ms: None = None  # Native DSP output has no established source content PTS.


class Decoder:
    """Bounded copied pixel ownership; codec PTS are opaque identity tokens only."""
    def __init__(self) -> None:
        self.contexts: dict[int, Any] = {}
        self.tokens: dict[int, tuple[int, int, int]] = {}
        self.keys: set[tuple[int, int, int]] = set()
        self.ordinals: dict[tuple[int, int, int], int] = {}
        self.frames: dict[tuple[int, int, int], dict[str, Any]] = {}
        self.previous: dict[int, int] = {}
        self.bytes = self.compressed = self.count = 0
        self.peak_bytes = self.peak_frames = 0
        self.retired_unselected = 0

    def add(self, token: int, meta: list[int], payload: bytes) -> None:
        sid, raw, index = meta[10], meta[16], meta[19]
        identity = sid, raw, index
        require(sid in (224, 225) and identity not in self.keys and token == self.count + 1,
                'unknown or duplicate compressed picture identity')
        require(sid in self.previous or index == 0, 'requires fresh reference decoder startup')
        require(self.count < MAX_UNITS and self.compressed + len(payload) <= MAX_COMPRESSED,
                'compressed input budget')
        require(len(self.tokens) < 32, 'delayed decoder identity budget')
        require(0 < meta[12] <= 4096 and 0 < meta[13] <= 4096
                and meta[12] % 2 == meta[13] % 2 == 0
                and meta[12] * meta[13] <= 8_388_608, 'compressed source geometry budget')
        self.previous[sid] = index
        self.keys.add(identity)
        self.ordinals[identity] = token
        self.tokens[token] = identity
        self.count += 1
        self.compressed += len(payload)
        av = LIVE['VIDEO']['NATIVE']['AUDIT']['SOURCE']['load_av']()
        if sid not in self.contexts:
            context = av.CodecContext.create('hevc', 'r')
            context.thread_count = 1
            context.options = {'max_pixels': '8388608'}
            context.open()
            require(not context.options, 'decoder did not enforce configured pixel budget')
            self.contexts[sid] = context
        packet = av.Packet(payload)
        packet.pts = packet.dts = token
        packet.time_base = Fraction(1, 1000)  # Identity transport, never content timing.
        for frame in self.contexts[sid].decode(packet):
            require(not self.contexts[sid].has_b_frames, 'reordered HEVC profile is unsupported')
            require(type(frame.pts) is int and frame.pts in self.tokens and not frame.is_corrupt,
                    'missing, reused or corrupt decoded identity')
            target = self.tokens.pop(frame.pts)
            require(target[0] == sid and target not in self.frames, 'decoded track/token mismatch')
            require(frame.format.name == 'yuv420p' and 0 < frame.width <= 4096
                    and 0 < frame.height <= 4096 and frame.width % 2 == frame.height % 2 == 0
                    and frame.width * frame.height <= 8_388_608, 'unsupported decoded geometry')
            require(len(self.frames) < 32 and self.bytes + frame.width * frame.height * 3 // 2 <= MAX_PIXELS,
                    'owned decoded pixel budget')
            pixels = NATIVE['SCHEDULED']['PREVIEW']['pack'](frame)
            self.frames[target] = dict(pixels=pixels, sha256=digest(pixels),
                                       width=frame.width, height=frame.height)
            self.bytes += len(pixels)
            self.peak_bytes = max(self.peak_bytes, self.bytes)
            self.peak_frames = max(self.peak_frames, len(self.frames))

    def release(self, identities: Any) -> None:
        for identity in identities:
            frame = self.frames.pop(identity, None)
            if frame is not None:
                self.bytes -= len(frame['pixels'])

    def retire(self, ordinal: int, protected: set[tuple[int, int, int]]) -> None:
        old = [i for i in self.frames if self.ordinals[i] < ordinal and i not in protected]
        self.retired_unselected += len(old)
        self.release(old)


Parent: Any = LIVE['Live']


class Preview(Parent):
    """One input owner, at most one video job and one independent audio job."""
    audio_backend: Any
    video_backend: Any
    video_job: Any
    video_active: Any
    audio_job: Any

    def __init__(self, timeout: float, progress: Any = None, expected_session: str | None = None) -> None:
        super().__init__(None, timeout, progress)
        self.decoder = Decoder()
        self.headers: dict[tuple[int, int, int], list[int]] = {}
        self.checkpoints: dict[int, dict[str, Any]] = {}
        self.waiting: deque[dict[str, Any]] = deque()
        self.sequence = self.last_pair = self.last_audio = 0
        self.audio_output_ns = -1
        self.session: str | None = None
        self.pairs = 0
        self.options: tuple[str, str] | None = None
        self.end: dict[str, Any] | None = None
        self.expected_session = expected_session
        self.last_native_call = 0
        self.decoder_owner: str | None = None
        self.selected_ordinals: dict[int, int] = {}
        self.worker_geometry: tuple[int, int] | None = None
        self.geometry_epochs: list[dict[str, Any]] = []
        self.audio_progress = 0

    def ingest(self, row: dict[str, Any], payload: bytes) -> None:  # noqa: PLR0915 - strict per-kind contracts
        require(self.end is None, 'record after source end')
        require(type(row.get('seq')) is int and row['seq'] == self.sequence + 1
                and row['seq'] <= MAX_RECORDS, 'record sequence mismatch or limit')
        require(type(row.get('payload_bytes')) is int and row['payload_bytes'] == len(payload),
                'record payload extent mismatch')
        self.sequence += 1
        kind = row.get('kind')
        fields = set(row) - {'kind', 'seq', 'payload_bytes'}
        if kind == 'begin':
            require(self.sequence == 1 and fields == {'session', 'elf_sha256'} and not payload
                    and row['elf_sha256'] == HASHES and isinstance(row['session'], str)
                    and re.fullmatch(r'[a-f0-9]{32}', row['session'])
                    and (self.expected_session is None or row['session'] == self.expected_session),
                    'unsupported reference session/build')
            self.session = row['session']
            return
        require(self.session is not None, 'missing reference begin record')
        if kind == 'encoded':
            require(fields == {'token', 'native_call', 'decoder_owner', 'meta_words', 'sha256', 'decoder_result'}
                    and type(row['token']) is int and 0 < row['token'] <= MAX_UNITS
                    and type(row['native_call']) is int and self.last_native_call < row['native_call'] <= MAX_UNITS
                    and isinstance(row['decoder_owner'], str)
                    and re.fullmatch(r'0x[0-9a-f]{1,8}', row['decoder_owner'])
                    and (self.decoder_owner is None or self.decoder_owner == row['decoder_owner'])
                    and type(row['decoder_result']) is int and row['decoder_result'] == 0
                    and 0 < len(payload) <= 2 * 1024 * 1024 and digest(payload) == row['sha256'],
                    'invalid accepted compressed input')
            self.decoder.add(row['token'], words(row['meta_words'], 58), payload)
            self.last_native_call = row['native_call']
            self.decoder_owner = row['decoder_owner']
        elif kind == 'header':
            require(fields == {'native_header'} and not payload, 'invalid decoded header record')
            header = words(row['native_header'], 49)
            identity = key(header)
            require(identity in self.decoder.keys and identity not in self.headers,
                    'unknown or duplicate native decoded header')
            after = list(header)
            after[4] = header[38] - header[39]
            NATIVE['AUDIT']['geometry'](header, after)
            self.headers[identity] = header
        elif kind == 'checkpoint':
            require(fields == {'manifest'} and len(self.checkpoints) < 2, 'checkpoint count or fields')
            manifest = row['manifest']
            require(manifest.get('input_offset') == manifest.get('render_offset') == 0,
                    'checkpoint offsets must be zero')
            before = words(manifest.get('input_header'), 49)
            after = words(manifest.get('render_header'), 49)
            width, height, visible = NATIVE['AUDIT']['geometry'](before, after)
            split = width * height * 3 // 2
            audit = NATIVE['AUDIT']['audit'](io.BytesIO(payload[:split]), io.BytesIO(payload[split:]),
                io.BytesIO((json.dumps(manifest) + '\n').encode()), verify_renderer=True)
            actual = self.decoder.frames.get(key(before))
            require(before[1] not in self.checkpoints and actual is not None
                    and (actual['width'], actual['height']) == (width, visible)
                    and actual['sha256'] == audit['samples'][0]['canonical_pixel_sha256'],
                    'native checkpoint differs from bound host decode')
            self.checkpoints[before[1]] = audit['samples'][0]
        elif kind == 'pair':
            require(fields == {'render_headers', 'source_device_ns'} and not payload
                    and type(row['source_device_ns']) is int and 0 <= row['source_device_ns'] < 2**63
                    and isinstance(row['render_headers'], list) and len(row['render_headers']) == 2,
                    'invalid reference selection')
            headers = [words(h, 49) for h in row['render_headers']]
            require([h[1] for h in headers] == [224, 225]
                    and headers[0][7] == headers[1][7], 'mismatched reference lenses')
            identities = [key(h) for h in headers]
            require(all(k in self.decoder.ordinals and
                        self.decoder.ordinals[k] > self.selected_ordinals.get(k[0], 0) for k in identities),
                    'repeated or backwards accepted-picture selection')
            require(len(self.waiting) < MAX_WAITING and self.pairs < MAX_UNITS // 2,
                    'host selected-pair backlog/count limit; no implicit drop')
            self.last_pair = min(self.decoder.ordinals[k] for k in identities)
            self.selected_ordinals.update({k[0]: self.decoder.ordinals[k] for k in identities})
            self.pairs += 1
            self.waiting.append(dict(pair_id=f'pair:{self.pairs}', keys=identities,
                render_headers=headers, source_device_ns=row['source_device_ns'],
                host_wait_started=time.monotonic()))
            protected = {k for p in self.waiting for k in p['keys']}
            self.decoder.retire(self.last_pair, protected)
        elif kind == 'end':
            expected = {'encoded_units', 'pairs', 'vqe_outputs', 'rejected_native_attempts'}
            require(fields == expected and not payload
                    and all(type(row[k]) is int and 0 <= row[k] <= MAX_UNITS for k in expected)
                    and row['encoded_units'] == self.decoder.count and row['pairs'] == self.pairs
                    and row['vqe_outputs'] == self.audio.offered
                    and self.last_native_call <= row['encoded_units'] + row['rejected_native_attempts'] <= MAX_UNITS,
                    'source end count mismatch')
            self.end = {k: row[k] for k in expected}
            self.source_eof_ns = time.monotonic_ns()
        elif kind == 'vqe':
            expected = {'id', 'source_input_ns', 'source_output_ns', 'input_sha256', 'output_sha256',
                        'sample_rate', 'channels', 'samples', 'status'}
            require(fields == expected and len(payload) == 4096 and self.audio.offered < 512
                    and type(row['id']) is int and self.last_audio < row['id'] < 2**31
                    and all(type(row[k]) is int for k in ('source_input_ns', 'source_output_ns',
                                                         'sample_rate', 'channels', 'samples', 'status'))
                    and (row['sample_rate'], row['channels'], row['samples'], row['status']) == (16000, 1, 1024, 0)
                    and 0 <= row['source_input_ns'] <= row['source_output_ns'] < 2**63
                    and row['source_output_ns'] >= self.audio_output_ns
                    and digest(payload[:2048]) == row['input_sha256']
                    and digest(payload[2048:]) == row['output_sha256'], 'invalid native VQE input/output pair')
            self.last_audio, self.audio_output_ns = row['id'], row['source_output_ns']
            self.audio.offer(OutputBlock(f'vqe:{row["id"]}', payload[2048:]), time.monotonic() - self.started)
        else:
            raise ValueError('unknown compressed reference record')

    def audio_write(self, data: bytes) -> int:
        if self.audio_backend is None:
            self.options = audio_options()
            self.audio_backend = LIVE['PCM']['Ffplay'](channel_args=self.options)
        return super().audio_write(data)

    def video_write(self, pair: dict[str, Any], pixels: bytes, width: int, height: int) -> dict[str, Any]:
        if self.video_backend is not None and self.worker_geometry != (width, height):
            try:
                self.video_backend.finish(self.timeout)
            finally:
                self.video_backend.abort()
                self.video_backend = None
        if self.video_backend is None:
            self.video_backend = VIDEO['Output'](width * 2, height, self.timeout, frame_limit=MAX_UNITS // 2)
            self.worker_geometry = width, height
            self.geometry_epochs.append(dict(first_pair=pair['pair_id'], width=width, height=height,
                                             host_opened_ns=time.monotonic_ns()))
        require(not self.cancel.is_set(), 'compressed video output cancelled')
        return self.video_backend.present(pair['pair_id'], pixels, self.timeout)

    def harvest(self) -> None:
        if self.video_job is not None and self.video_job.done():
            ack = self.video_job.result()
            self.video_completed += 1
            self.actions.append(dict(kind='video_ack', pair_id=self.video_active['pair_id'],
                source_media_ms=self.video_active['render_headers'][0][5],
                source_device_ns=self.video_active['source_device_ns'],
                host_completed_ns=time.monotonic_ns(), acknowledgement=ack))
            self.video_job = self.video_active = None
            if self.progress:
                self.progress(self.actions[-1])
        if self.audio_job is not None and self.audio_job.done():
            try:
                count = self.audio_job.result()
            except BaseException:
                self.audio.offset = self.audio_progress
                raise
            identity = self.audio.writing.identity
            self.audio.accept(count, time.monotonic() - self.started)
            self.audio_job = None
            self.actions.append(dict(kind='audio_ack', id=identity, host_completed_ns=time.monotonic_ns(),
                                     output_content_pts=None))
            if self.progress:
                self.progress(self.actions[-1])

    def pump(self) -> None:
        self.harvest()
        if self.source_eof_ns is not None:
            return
        for pair in self.waiting:
            require(time.monotonic() - pair['host_wait_started'] <= self.timeout,
                    'reference selection exceeded host waiting deadline')
        if len(self.checkpoints) != 2:
            return  # Neither video nor audio output starts before sampled native parity.
        if self.video_job is None and self.waiting:
            pair = self.waiting[0]
            if all(k in self.decoder.frames and k in self.headers for k in pair['keys']):
                records = [self.decoder.frames[k] for k in pair['keys']]
                dimensions = []
                for identity, render, record in zip(pair['keys'], pair['render_headers'], records, strict=True):
                    width, _, visible = NATIVE['AUDIT']['geometry'](self.headers[identity], render)
                    require((width, visible) == (record['width'], record['height']), 'host/native geometry mismatch')
                    dimensions.append((width, visible))
                require(dimensions[0] == dimensions[1], 'unequal selected lens geometry')
                self.geometry = dimensions[0]
                pixels = NATIVE['SCHEDULED']['PREVIEW']['compose'](
                    records[0]['pixels'], records[1]['pixels'], *self.geometry)
                self.waiting.popleft()
                self.video_active = pair
                self.video_job = self.executor.submit(self.video_write, pair, pixels, *self.geometry)
                self.decoder.release(pair['keys'])
        if self.audio_job is None and self.audio.pending:
            self.audio.begin(time.monotonic() - self.started)
            self.audio_job = self.executor.submit(self.audio_write, self.audio.writing.pcm)

    def result(self) -> dict[str, Any]:
        return dict(session=self.session, records=self.sequence, source_selected_pairs=self.pairs,
            encoded_units=self.decoder.count, compressed_bytes=self.decoder.compressed,
            video_frames=self.video_completed, video_driver=self.video_backend.driver if self.video_backend else None,
            checkpoint_samples=list(self.checkpoints.values()), sampled_pixel_parity_only=True,
            native_scheduler_replayed=False, decoder_eof_flushed=False,
            owned_pixels=dict(bytes=self.decoder.bytes, peak_bytes=self.decoder.peak_bytes,
                frames=len(self.decoder.frames), peak_frames=self.decoder.peak_frames,
                delayed_tokens=len(self.decoder.tokens), retired_unselected=self.decoder.retired_unselected),
            video_waiting=[p['pair_id'] for p in self.waiting],
            audio=dict(offered=self.audio.offered, written=self.audio.written, rejected=self.audio.rejected,
                queued=len(self.audio.ring), active=self.audio.writing is not None,
                partial_bytes=self.audio.offset, channel_args=self.options, output_content_pts=None),
            source_eof_host_ns=self.source_eof_ns, source_end=self.end,
            geometry_epochs=self.geometry_epochs, actions=self.actions)


def run(preview: Preview, fd: int, startup: float = 120, stopped: Any = lambda: False) -> None:
    parser = LIVE['Input']()
    source_started: float | None = None
    while True:
        if stopped():
            raise KeyboardInterrupt('preview stop requested')
        preview.pump()
        now = time.monotonic()
        require(now - (source_started or preview.started) <= (40 if source_started else startup),
                'compressed reference startup/session deadline')
        if select.select([fd], [], [], 0.005)[0]:
            chunk = os.read(fd, 65536)
            if not chunk:
                parser.eof()
                require(preview.end is not None, 'source ended without completion record; retained prefix only')
                return
            source_started = source_started or now
            for row, payload in parser.feed(chunk):
                preview.ingest(row, payload)
                preview.pump()


def main() -> int:  # noqa: PLR0912, PLR0915 - owned output/receipt lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--play', action='store_true', required=True)
    parser.add_argument('--audio', choices=['observed-native-vqe-output'], required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--deadline', type=float, default=5)
    parser.add_argument('--progress', action='store_true')
    parser.add_argument('--expect-session', help='optional exact fresh handoff session identity')
    args = parser.parse_args()
    if os.name != 'posix' or not math.isfinite(args.deadline) or not MIN_DEADLINE <= args.deadline <= 10:
        parser.error('requires POSIX and finite output deadline 0.1..10 seconds')
    if args.expect_session and not re.fullmatch(r'[a-f0-9]{32}', args.expect_session):
        parser.error('expected session must be 32 lowercase hex characters')
    os.umask(0o077)
    os.environ['EZVIZ_SDL_WINDOW_TITLE'] = 'Compressed reference preview (experimental)'
    status, error, code = 'source-ended-pending-retained', None, 0
    progress = (lambda row: print(json.dumps(row), flush=True)) if args.progress else None
    preview = Preview(args.deadline, progress, args.expect_session)
    requested = [False]
    previous: dict[Any, Any] = {}
    def stop(_signum: int, _frame: Any) -> None:
        requested[0] = True
    try:
        with args.receipt.open('x') as receipt:
            try:
                for signum in (signal.SIGINT, signal.SIGTERM):
                    previous[signum] = signal.getsignal(signum)
                    signal.signal(signum, stop)
                if progress:
                    progress(dict(kind='consumer_ready', host_monotonic_ns=time.monotonic_ns()))
                run(preview, sys.stdin.fileno(), stopped=lambda: requested[0])
                preview.close(True)
                require(preview.session is not None and len(preview.checkpoints) == 2
                        and preview.video_completed > 0 and preview.audio.written > 0,
                        'no joint checkpoint-verified compressed preview output')
            except (Exception, KeyboardInterrupt) as failure:
                status, error, code = 'failed', f'{type(failure).__name__}: {failure}', 2
                if isinstance(failure, KeyboardInterrupt):
                    status, code = 'cancelled', 130
                try:
                    preview.close(False)
                except Exception as cleanup:
                    error += '; cleanup: ' + str(cleanup)
            finally:
                for signum, handler in previous.items():
                    signal.signal(signum, handler)
            if requested[0]:
                status, code = 'cancelled', 130
                error = error or 'stop requested'
            json.dump(dict(profile='compressed-reference-preview-v1', status=status, error=error,
                reference_app_required=True, host_hevc_decoder=True, native_vqe_ported=False,
                input_provenance_authenticated=False, codec_pts_are_identity_tokens_only=True,
                native_pixels_verified_every_frame=False, physical_av_sync_measured=False,
                eof_policy='retain-no-decoder-or-source-drain', **preview.result()), receipt)
            receipt.write('\n')
            if progress:
                progress(dict(kind='consumer_result', status=status, error=error,
                    video_frames=preview.video_completed, audio=preview.result()['audio'],
                    video_driver=preview.video_backend.driver if preview.video_backend else None,
                    geometry_epochs=preview.geometry_epochs, source_end=preview.end,
                    physical_av_sync_measured=False))
    except OSError as failure:
        preview.close(False)
        error, code = str(failure), 2
    if error:
        print('compressed reference preview failed: ' + error, file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
