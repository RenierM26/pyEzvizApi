"""Explicit local side-by-side HEVC preview; NOT a native A/V playback backend.

Requires --play --layout side-by-side --fps and an exact decoded header map.
Only explicitly render-taken pairs are written. Pipe acceptance is not display.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import subprocess
import sys
import tempfile
import time
from typing import Any

DECODE = runpy.run_path(str(Path(__file__).with_name('app_video_decode.py')))
AUDIO = DECODE['AUDIO']
MAX_PAIR_PIXELS = 8_388_608
MAX_SECONDS = 3600
MIN_DEADLINE = 0.1
MAX_SPOOL_BYTES = DECODE['MAX_TOTAL_PIXELS'] * 3 // 2


def pack(frame: Any) -> bytes:
    """Copy a validated borrowed decoder frame into tightly packed Y/U/V bytes."""
    rows: list[bytes] = []
    for plane, width, height in zip(frame.planes,
            (frame.width, frame.width // 2, frame.width // 2),
            (frame.height, frame.height // 2, frame.height // 2), strict=True):
        data = bytes(plane)
        rows.extend(data[i * plane.line_size:i * plane.line_size + width] for i in range(height))
    return b''.join(rows)


class Spool:
    """One private temporary file owns copied pixels, never native decoder buffers."""

    def __init__(self, source: Any) -> None:
        self.source = source
        self.records: dict[str, dict[str, Any]] = {}
        self.size = 0

    def capture(self, row: dict[str, Any], frame: Any) -> None:
        data = pack(frame)
        if (len(data) != row['width'] * row['height'] * 3 // 2
                or hashlib.sha256(data).hexdigest() != row['pixel_sha256']):
            raise ValueError('decoded pixel copy does not match validated fingerprint')
        if self.size + len(data) > MAX_SPOOL_BYTES:
            raise ValueError('temporary decoded-pixel storage limit exceeded')
        if row['decoded_id'] in self.records:
            raise ValueError('duplicate decoded pixel identity')
        # Reads move the shared cursor; subsequent live captures must append.
        self.source.seek(0, os.SEEK_END)
        offset = self.source.tell()
        if self.source.write(data) != len(data):
            raise ValueError('short temporary pixel write')
        self.records[row['decoded_id']] = dict(row, offset=offset, size=len(data))
        self.size += len(data)

    def read(self, identity: str) -> bytes:
        row = self.records[identity]
        self.source.seek(row['offset'])
        data = self.source.read(row['size'])
        if len(data) != row['size'] or hashlib.sha256(data).hexdigest() != row['pixel_sha256']:
            raise ValueError('temporary decoded pixel data is truncated or changed')
        return data


def plan_pairs(mapped: dict[str, Any], spool: Spool) -> tuple[list[dict[str, Any]], int, int]:
    """Only explicit queue takes produce output work; do not drain pending pairs."""
    bindings = {b['offer_id']: b['decoded_id'] for b in mapped['offer_bindings']}
    plan = []
    geometry = None
    for action in mapped['pairing']['actions']:
        if action['kind'] != 'render_queue_taken':
            continue
        pair = action['pair']
        identities = [bindings[lens['id']] for lens in pair['lenses']]
        rows = [spool.records[identity] for identity in identities]
        current = (rows[0]['width'], rows[0]['height'])
        if ((rows[1]['width'], rows[1]['height']) != current
                or (geometry is not None and current != geometry)
                or current[0] * 2 * current[1] > MAX_PAIR_PIXELS):
            raise ValueError('preview requires constant equal lens geometry within paired pixel limit')
        geometry = current
        plan.append(dict(pair_id=pair['pair_id'], decoded_ids=identities,
                         offer_ids=[lens['id'] for lens in pair['lenses']],
                         primary_media_ms=pair['lenses'][0]['media_ms'],
                         observed_take_at_ms=action['at_ms']))
    if not plan or geometry is None:
        raise ValueError('header map must explicitly consume at least one pair; no EOF drain inferred')
    return plan, geometry[0], geometry[1]


def compose(left: bytes, right: bytes, width: int, height: int) -> bytes:
    """Explicit side-by-side YUV layout, not an inferred Android compositor."""
    expected = width * height * 3 // 2
    if len(left) != expected or len(right) != expected:
        raise ValueError('paired pixels have invalid lengths')
    output: list[bytes] = []
    offset = 0
    for w, h in ((width, height), (width // 2, height // 2), (width // 2, height // 2)):
        for y in range(h):
            pos = offset + y * w
            output.extend((left[pos:pos + w], right[pos:pos + w]))
        offset += w * h
    return b''.join(output)


class Ffplay:
    """Nonblocking rawvideo pipe with bounded finish/abort and no speaker output."""

    def __init__(self, width: int, height: int, fps: int) -> None:
        self.process = subprocess.Popen(
            ['ffplay', '-an', '-sn', '-autoexit', '-loglevel', 'error',
             '-f', 'rawvideo', '-pixel_format', 'yuv420p', '-video_size', f'{width}x{height}',
             '-framerate', str(fps), '-i', 'pipe:0'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=None,
        )
        assert self.process.stdin is not None
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
        except BaseException:
            self.abort()
            raise

    def alive(self) -> None:
        if self.process.poll() is not None:
            raise ValueError(f'ffplay exited before input completed (status {self.process.returncode})')

    def write(self, data: memoryview) -> int:
        assert self.process.stdin is not None
        return os.write(self.process.stdin.fileno(), data)

    def finish(self, timeout: float) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ValueError('video output did not exit within drain deadline') from error
        if code:
            raise ValueError(f'ffplay exited with status {code}')

    def abort(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=0.5)
        if self.process.stdin is not None:
            self.process.stdin.close()


class Preview:
    """One owned paired frame in flight; all writes stay on that pair until complete."""

    def __init__(self, plan: list[dict[str, Any]], fps: int) -> None:
        self.plan = plan
        self.fps = fps
        self.actions: list[dict[str, Any]] = []
        self.completed = 0
        self.pending: str | None = None
        self.offset = 0

    def run(self, spool: Spool, backend: Any, width: int, height: int, timeout: float) -> None:
        started = time.monotonic()
        for pair in self.plan:
            self.pending, self.offset = pair['pair_id'], 0
            pixels = [spool.read(identity) for identity in pair['decoded_ids']]
            output = compose(pixels[0], pixels[1], width, height)
            view = memoryview(output)
            self.actions.append(dict(kind='video_pipe_write_started', **pair,
                                     write_started_monotonic_ns=time.monotonic_ns()))
            deadline = time.monotonic() + timeout
            while self.offset < len(view):
                if time.monotonic() > deadline or time.monotonic() - started > MAX_SECONDS:
                    raise ValueError('video write/session deadline exceeded')
                backend.alive()
                try:
                    count = backend.write(view[self.offset:])
                except BlockingIOError:
                    select.select([], [], [], 0.02)
                else:
                    if type(count) is not int or not 0 < count <= len(view) - self.offset:
                        raise ValueError('invalid video pipe write progress')
                    self.offset += count
            self.actions.append(dict(kind='video_pipe_write_completed', **pair,
                                     composed_sha256=hashlib.sha256(output).hexdigest(), bytes=len(output),
                                     pipe_completed_monotonic_ns=time.monotonic_ns()))
            self.completed += 1
            self.pending, self.offset = None, 0
        backend.finish(timeout)

    def result(self, status: str, error: str | None) -> dict[str, Any]:
        return dict(profile='local-hevc-side-by-side-preview-v1', status=status, error=error,
                    layout='side-by-side-not-native-compositor', fps=self.fps,
                    timing='explicit-preview-cadence-not-source-or-native-schedule',
                    pipe_completion_is_display=False, physical_lip_sync_measured=False,
                    decoder_buffer_ownership_verified=False, native_header_provenance_verified=False,
                    plan=self.plan, actions=self.actions, summary=dict(selected_pairs=len(self.plan),
                    pipe_written=self.completed, write_pending=self.pending, partial_pipe_bytes=self.offset,
                    remaining_pairs=[p['pair_id'] for p in self.plan[self.completed:]]))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=AUDIO['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--header-map', required=True, type=Path)
    parser.add_argument('--play', required=True, action='store_true')
    parser.add_argument('--layout', required=True, choices=('side-by-side',))
    parser.add_argument('--fps', required=True, type=int, choices=range(1, 61))
    parser.add_argument('--receipt', required=True, type=Path, help='new JSON receipt, never overwrite')
    parser.add_argument('--deadline', type=float, default=5)
    args = parser.parse_args()
    if not MIN_DEADLINE <= args.deadline <= 30:
        parser.error('deadline must be 0.1..30 seconds')
    return args


def main() -> int:
    args = arguments()
    preview = Preview([], args.fps)
    backend = None
    code, status, error = 0, 'completed', None
    provenance: dict[str, Any] = {}
    try:
        with args.receipt.open('x') as receipt:
            try:
                with tempfile.TemporaryFile() as temporary:
                    spool = Spool(temporary)
                    with AUDIO['open_source'](args.source) as source:
                        report = DECODE['decode'](source, args.container,
                            (args.primary_stream, args.secondary_stream), spool.capture)
                    with AUDIO['open_source'](args.header_map) as headers:
                        mapped = DECODE['join_headers'](report, headers)
                    provenance = dict(decoder=dict(pyav_version=report['pyav_version'],
                                      library_versions=report['library_versions']),
                                      source_pairing=mapped['pairing'],
                                      offer_bindings=mapped['offer_bindings'],
                                      decoded_frames=report['decoded_frames'])
                    plan, width, height = plan_pairs(mapped, spool)
                    preview = Preview(plan, args.fps)
                    backend = Ffplay(width * 2, height, args.fps)
                    preview.run(spool, backend, width, height, args.deadline)
            except (Exception, KeyboardInterrupt) as failure:
                code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                status = 'cancelled' if code == 130 else 'failed'
                error = f'{type(failure).__name__}: {failure}'
            finally:
                if backend is not None:
                    try:
                        backend.abort()
                    except (Exception, KeyboardInterrupt) as failure:
                        if error is None:
                            code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                            status = 'cancelled' if code == 130 else 'failed'
                            error = f'cleanup failed: {type(failure).__name__}: {failure}'
            json.dump(dict(preview.result(status, error), **provenance), receipt, sort_keys=True)
            receipt.write('\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'video preview failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
