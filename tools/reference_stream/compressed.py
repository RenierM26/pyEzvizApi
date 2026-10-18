"""Separate compressed reference preview adapter; not the native scheduler projector."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import time
from typing import Any

BASE = Path(__file__).parent
REFERENCE = runpy.run_path(str(BASE.parent / 'app_reference_stream.py'))
require = REFERENCE['require']


def build_source() -> str:
    source = (BASE / 'h9c-armv7.js').read_text()
    decoded = 'header_words:Array.from({length:49},(_,i)=>v.add(i*4).readU32())'
    render = "node:node(a[1]),caller:this.returnAddress.sub(p.base).toString()});}catch(e){error(kind,e);"
    require(source.count(decoded) == 1 and source.count(render) == 1, 'observer source layout changed')
    source = source.replace(render,
        "node:node(a[1]),render_headers:kind==='render_callback'?"
        "[0x28,0x124].map(base=>Array.from({length:49},(_,i)=>a[1].add(base+i*4).readU32())):null,"
        "caller:this.returnAddress.sub(p.base).toString()});}catch(e){error(kind,e);")
    prelude = 'const REFERENCE_CONFIG={verified:true,pairs:1,transport:"lz4",transport_acks:false};\n'
    for name in ('transport-ack.js', 'snapshot-codec.js'):
        prelude += (BASE / name).read_text() + '\n'
    return prelude + source + '\n' + (BASE / 'compressed-input.js').read_text()


CaptureBase: Any = REFERENCE['Capture']


class Capture(CaptureBase):
    """Retain accepted-call evidence, never concatenate rejected/retried stream input."""
    error: str | None

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.encoded_count = self.encoded_bytes = 0

    def message(self, message: dict[str, Any], data: bytes | None) -> None:
        row = message.get('payload', {})
        if message.get('type') != 'send' or not isinstance(row, dict) or row.get('event') != 'encoded_video':
            super().message(message, data)
            return
        with self.lock:
            if self.error:
                return
            try:
                require(isinstance(data, bytes) and len(data) == row['bytes']
                    and 0 < len(data) <= 2 * 1024 * 1024
                    and type(row['id']) is int and row['id'] == self.encoded_count + 1 <= 600
                    and self.encoded_bytes + len(data) <= 64 * 1024 * 1024
                    and isinstance(row.get('decoder_owner'), str)
                    and re.fullmatch(r'0x[0-9a-f]{1,8}', row['decoder_owner'])
                    and isinstance(row['meta_words'], list) and len(row['meta_words']) == 58
                    and all(type(n) is int and 0 <= n < 2**32 for n in row['meta_words'])
                    and hashlib.sha256(data).hexdigest() == row['sha256']
                    and len(self.rows) < 20_000 and self.bytes + len(data) <= 248 * 1024 * 1024,
                    'invalid encoded checkpoint record')
                assert isinstance(data, bytes)  # require() above also enforces this at runtime.
                if 'encoded_video.bin' not in self.files:
                    self.files['encoded_video.bin'] = (self.root / 'encoded_video.bin').open('xb')
                out = self.files['encoded_video.bin']
                row.update(file='encoded_video.bin', offset=out.tell(), collector_received_ns=time.monotonic_ns())
                require(out.write(data) == len(data), 'short compressed capture write')
                out.flush()
                self.bytes += len(data)
                self.encoded_count += 1
                self.encoded_bytes += len(data)
                self.transport_bytes += len(data)
                self.log.write(json.dumps(row) + '\n')
                self.log.flush()
                self.rows.append(row)
            except Exception as error:
                self.error = str(error)


class Writer:
    """Finite nonblocking stdout writes; mirror only bytes actually accepted by the pipe."""
    def __init__(self, root: Path, fd: int, stopped: Any = lambda: False) -> None:
        self.fd, self.sequence = fd, 0
        self.stopped = stopped
        self.original_blocking = os.get_blocking(fd)
        self.wire = (root / 'source.bin').open('xb')
        try:
            os.set_blocking(fd, False)
        except BaseException:
            self.wire.close()
            raise

    def send(self, row: dict[str, Any], payload: bytes = b'') -> None:
        if self.stopped():
            raise KeyboardInterrupt('source stop requested')
        self.sequence += 1
        wire = REFERENCE['LIVE']['encode'](dict(row, seq=self.sequence), payload)
        offset, until = 0, time.monotonic() + 10
        while offset < len(wire):
            if self.stopped():
                raise KeyboardInterrupt('source stop requested')
            require(time.monotonic() < until, 'compressed source pipe deadline')
            try:
                size = os.write(self.fd, memoryview(wire)[offset:])
            except BlockingIOError:
                select.select([], [self.fd], [], 0.01)
            else:
                require(0 < size <= len(wire) - offset, 'invalid source pipe progress')
                self.wire.write(memoryview(wire)[offset:offset + size])
                self.wire.flush()
                offset += size

    def close(self) -> None:
        self.wire.close()
        os.set_blocking(self.fd, self.original_blocking)


def selection_keys(rows: list[dict[str, Any]]) -> set[tuple[int, int, int]]:
    """Only explicit checkpoint/paired selections justify copied host pixels."""
    needed = {(r['sid'], r['raw'], r['frame']) for r in rows
              if r.get('event') == 'native_render_pixels'}
    for selection in (r for r in rows if r.get('event') == 'render_callback'):
        headers = selection.get('render_headers')
        require(isinstance(headers, list) and len(headers) == 2
                and all(isinstance(h, list) and len(h) == 49 for h in headers),
                'missing explicit reference-selected paired headers')
        assert isinstance(headers, list)
        needed.update((h[1], h[7], h[10]) for h in headers)
    return needed


class Emitter:
    """Explicit reference identities/selections; no native clock or per-frame audit invented."""
    def __init__(self, root: Path, send: Any) -> None:
        self.root, self.send = root, send
        self.next_token = 1
        self.next_attempt = 1
        self.accepted: dict[tuple[int, int, int], int] = {}
        self.rejected: list[dict[str, Any]] = []
        self.decoder_owner: str | None = None
        self.headers: set[int] = set()
        self.samples: set[tuple[int, int, int]] = set()
        self.pairs: set[tuple[int, int, int]] = set()
        self.audio: set[int] = set()

    def pump(self, rows: list[dict[str, Any]]) -> None:
        require(not any(r.get('event') in {'error', 'vqe_unverified_format', 'vqe_failure'} for r in rows),
                'unsupported native compressed/VQE source')
        encoded = {r['id']: r for r in rows if r.get('event') == 'encoded_video'}
        returned = {r['id']: r for r in rows if r.get('event') == 'encoded_video_return'}
        require(len(returned) == sum(r.get('event') == 'encoded_video_return' for r in rows),
                'duplicate native decoder return')
        # Keep the full compressed capture, but forward only the accepted prefix
        # needed for observed selections. Unselected future inputs stay source-side;
        # if a later selection needs them, every prerequisite is forwarded in order.
        needed = selection_keys(rows)
        last_needed = max((call for call, row in encoded.items()
            if call in returned and returned[call]['result'] == 0
            and tuple(row['meta_words'][i] for i in (10, 16, 19)) in needed), default=0)
        while (self.next_attempt <= last_needed
               and self.next_attempt in encoded and self.next_attempt in returned):
            row = encoded[self.next_attempt]
            result = returned[self.next_attempt]['result']
            require(type(result) is int, 'invalid native decoder status')
            meta = row['meta_words']
            identity = meta[10], meta[16], meta[19]
            if result == 0:
                require(self.decoder_owner is None or self.decoder_owner == row['decoder_owner'],
                        'reference decoder instance changed; separate source session required')
                self.decoder_owner = row['decoder_owner']
                require(identity not in self.accepted, 'ambiguous accepted native picture identity')
                self.send(dict(kind='encoded', token=self.next_token, native_call=self.next_attempt,
                    decoder_owner=self.decoder_owner, meta_words=meta, sha256=row['sha256'], decoder_result=0),
                    REFERENCE['PROJECT']['blob'](self.root, row))
                self.accepted[identity] = self.next_token
                self.next_token += 1
                self.emit_video(rows)
            else:
                # The app may retry the same bytes. We never decode a rejected attempt.
                self.rejected.append(dict(call=self.next_attempt, result=result, identity=identity,
                                          sha256=row['sha256']))
            self.next_attempt += 1
        self.emit_video(rows)
        if len(self.samples) != 2:
            return
        audio_inputs = {r['call']: r for r in rows if r.get('event') == 'audio_vqe_input'}
        for output in [r for r in rows if r.get('event') == 'audio_vqe_output']:
            call = output['call']
            if call in self.audio or call not in audio_inputs:
                continue
            before = audio_inputs[call]
            self.send(dict(kind='vqe', id=call, source_input_ns=before['device_mono_ns'],
                source_output_ns=output['device_mono_ns'], input_sha256=before['sha256'],
                output_sha256=output['sha256'], sample_rate=16000, channels=1, samples=1024,
                status=output['status']), REFERENCE['PROJECT']['blob'](self.root, before)
                + REFERENCE['PROJECT']['blob'](self.root, output))
            self.audio.add(call)

    def emit_video(self, rows: list[dict[str, Any]]) -> None:
        """Publish ready selections before decoding the rest of a collector batch."""
        decoded = [r for r in rows if r.get('event') == 'decoded_picture'
                   and not r['payload_is_null'] and r['payload_bytes'] > 0]
        # Decoder input can include an unselected single-track startup prefix.
        # Retain/decode it for HEVC dependencies, but never label it paired output.
        needed = selection_keys(rows)
        for row in decoded:
            if row['call'] in self.headers:
                continue
            identity = row['sid'], row['raw'], row['frame']
            if identity not in self.accepted or identity not in needed:
                continue
            header = row['header_words']
            require((header[1], header[7], header[10]) == identity,
                    'native input/output stream/raw/frame identity mismatch')
            self.send(dict(kind='header', native_header=row['header_words']))
            self.headers.add(row['call'])
        for render in [r for r in rows if r.get('event') == 'native_render_pixels']:
            identity = render['sid'], render['raw'], render['frame']
            if identity in self.samples:
                continue
            original = next((r for r in decoded if (r['sid'], r['raw'], r['frame']) == identity), None)
            if original is None or original['call'] not in self.headers:
                continue
            try:
                manifest, payload = REFERENCE['PROJECT']['manifest'](self.root, rows, render)
            except StopIteration:
                continue  # The bounded renderer observation prefix is not complete yet.
            self.send(dict(kind='checkpoint', manifest=manifest), payload)
            self.samples.add(identity)
        if len(self.samples) != 2:
            return
        # Source callback order is retained; no sample-skipping pseudo scheduler is used.
        for row in [r for r in rows if r.get('event') == 'render_callback']:
            n = row['node']
            identity = row['schedule'], n['raw'], n['frame']
            if identity in self.pairs:
                continue
            inputs = [next((r for r in decoded if r['sid'] == sid and r['raw'] == raw
                       and r['frame'] == frame), None) for sid, raw, frame in (
                       (n['sid'], n['raw'], n['frame']),
                       (n['secondary_sid'], n['secondary_raw'], n['secondary_frame']))]
            if any(r is None or r['call'] not in self.headers for r in inputs):
                break
            self.send(dict(kind='pair', render_headers=row['render_headers'],
                           source_device_ns=row['device_mono_ns']))
            self.pairs.add(identity)
