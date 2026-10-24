"""Development-only bounded PCM output; passthrough is NOT EZVIZ VQE.

POSIX only. JSONL stdin supplies id, media_ms and pcm_s16le_b64 (2048 bytes,
16-kHz mono s16le). Requires --play --processor passthrough. No camera I/O.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
import json
import math
import os
import select
import subprocess
import sys
import time
from typing import Any

PCM_BYTES = 2048
RING_BYTES = 51_200
MAX_BLOCKS = 10_000
MAX_LINE = 8192
MAX_SECONDS = 3600
POLL_SECONDS = 0.02
MIN_DEADLINE = 0.1
NEWLINE = b'\n'


@dataclass(frozen=True)
class Block:
    """Retain source identity/time; never relabel output after a rejection."""

    identity: str
    media_ms: int
    pcm: bytes


def parse_block(row: Any) -> Block:
    """Reject unsupported formats/fields before queue admission."""
    if not isinstance(row, dict) or set(row) != {'id', 'media_ms', 'pcm_s16le_b64'}:
        raise ValueError('block requires exactly id, media_ms and pcm_s16le_b64')
    identity = row['id']
    if not isinstance(identity, str) or not 1 <= len(identity) <= 128:
        raise ValueError('id must contain 1..128 characters')
    media = row['media_ms']
    if type(media) is not int or not 0 <= media <= 0xffffffff:
        raise ValueError('media_ms must be uint32')
    encoded = row['pcm_s16le_b64']
    if not isinstance(encoded, str) or len(encoded) != 2732:
        raise ValueError('PCM must encode exactly 2048 bytes')
    try:
        pcm = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('invalid PCM base64') from error
    if len(pcm) != PCM_BYTES:
        raise ValueError('PCM must contain exactly 2048 bytes')
    return Block(identity, media, pcm)


class PcmQueue:
    """Single-owner ring plus one in-flight pipe write; no DSP delay invented.

    Passthrough processing is immediate. A block leaves the ring when its write
    starts; the next block cannot start until that entire write is accepted.
    """

    def __init__(self) -> None:
        self.ring: deque[Block] = deque()
        self.writing: Block | None = None
        self.offset = 0
        self.write_started = 0.0
        self.seen: set[str] = set()
        self.actions: list[dict[str, Any]] = []
        self.offered = self.rejected = self.written = 0

    def emit(self, kind: str, block: Block, now: float, **fields: Any) -> None:
        self.actions.append(dict(kind=kind, id=block.identity, media_ms=block.media_ms,
                                 at_seconds=now, **fields))

    def offer(self, block: Block, now: float) -> bool:
        if self.offered >= MAX_BLOCKS:
            raise ValueError('block limit exceeded')
        if block.identity in self.seen:
            raise ValueError('duplicate block identity')
        self.seen.add(block.identity)
        self.offered += 1
        if (len(self.ring) + 1) * PCM_BYTES >= RING_BYTES:
            self.rejected += 1
            self.emit('audio_reject_newest', block, now)
            return False
        self.ring.append(block)
        self.emit('audio_admitted', block, now)
        return True

    def begin(self, now: float) -> None:
        """Immediate explicitly bypassed processing, then release the ring slot."""
        if self.writing is None and self.ring:
            self.writing = self.ring.popleft()
            self.offset = 0
            self.write_started = now
            self.emit('audio_passthrough', self.writing, now)
            self.emit('audio_pipe_write_started', self.writing, now)

    def accept(self, count: int, now: float) -> None:
        """A short OS pipe write is transport progress, not a completed block."""
        if (self.writing is None or type(count) is not int
                or not 0 < count <= PCM_BYTES - self.offset):
            raise ValueError('invalid pipe write progress')
        self.offset += count
        if self.offset == PCM_BYTES:
            self.written += 1
            self.emit('audio_pipe_write_completed', self.writing, now)
            self.writing = None
            self.offset = 0

    @property
    def pending(self) -> bool:
        return bool(self.ring) or self.writing is not None

    def result(self, status: str, error: str | None = None) -> dict[str, Any]:
        return dict(profile='h9c-pcm-passthrough-ffplay-v1', status=status, error=error,
                    processor='passthrough-not-vqe', physical_lip_sync_measured=False,
                    pipe_completion_is_audible_output=False, actions=self.actions,
                    summary=dict(offered=self.offered, rejected=self.rejected,
                                 pipe_written=self.written,
                                 ring_pending=[b.identity for b in self.ring],
                                 write_pending=self.writing.identity if self.writing else None,
                                 partial_pipe_bytes=self.offset))


class Ffplay:
    """Nonblocking pipe transport with bounded, kill-and-reap cleanup."""

    def __init__(self, *, channel_args: tuple[str, str] = ('-ch_layout', 'mono')) -> None:
        if type(channel_args) is not tuple or channel_args not in {('-ch_layout', 'mono'), ('-channels', '1')}:
            raise ValueError('requires an explicit supported mono channel option')
        self.process = subprocess.Popen(
            ['ffplay', '-nodisp', '-autoexit', '-loglevel', 'error',
             '-f', 's16le', '-ar', '16000', *channel_args, '-i', 'pipe:0'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=None,
        )
        assert self.process.stdin is not None
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
        except (OSError, KeyboardInterrupt):
            self.abort()
            raise

    def write(self, data: bytes) -> int:
        assert self.process.stdin is not None
        return os.write(self.process.stdin.fileno(), data)

    def alive(self) -> None:
        code = self.process.poll()
        if code is not None:
            raise ValueError(f'ffplay exited before input completed (status {code})')

    def finish(self, timeout: float) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ValueError('ffplay did not exit within drain deadline') from error
        if code != 0:
            raise ValueError(f'ffplay exited with status {code}')

    def abort(self) -> None:
        """Idempotent cleanup, including a child ignoring terminate."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=0.5)
        if self.process.stdin is not None:
            self.process.stdin.close()


class JsonlInput:
    """Bound fragmented input before decoding; no retained media beyond one line."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, chunk: bytes) -> Iterator[Block]:
        # Yield each valid prefix record before parsing the next one. A later
        # failure must not erase admissions merely because reads coalesced.
        self.buffer.extend(chunk)
        while NEWLINE in self.buffer:
            line, _, remainder = self.buffer.partition(NEWLINE)
            self.buffer = bytearray(remainder)
            if len(line) + 1 > MAX_LINE:
                raise ValueError('JSONL line limit exceeded')
            yield parse_block(json.loads(line))
        if len(self.buffer) > MAX_LINE:
            raise ValueError('JSONL line limit exceeded')
        if not chunk and self.buffer:
            yield parse_block(json.loads(self.buffer))
            self.buffer.clear()


def run(queue: PcmQueue, backend: Ffplay, input_fd: int, timeout: float) -> None:
    """Poll input/output fairly; blocked pipe writes never block input or cancel."""
    started = time.monotonic()
    eof = False
    source = JsonlInput()
    drain_started: float | None = None
    while not eof or queue.pending:
        now = time.monotonic() - started
        if now > MAX_SECONDS:
            raise ValueError('one-hour session limit exceeded')
        if drain_started is not None and now - drain_started > timeout:
            raise ValueError('pending queue exceeded EOF drain deadline')
        backend.alive()
        if not eof and select.select([input_fd], [], [], POLL_SECONDS)[0]:
            chunk = os.read(input_fd, 4096)
            now = time.monotonic() - started
            if not chunk:
                eof = True
                drain_started = now
            for block in source.feed(chunk):
                queue.offer(block, now)
        queue.begin(now)
        if queue.writing is not None:
            if now - queue.write_started > timeout:
                raise ValueError('pipe block write deadline exceeded')
            try:
                count = backend.write(queue.writing.pcm[queue.offset:])
            except BlockingIOError:
                # No producer wait at EOF; still avoid spinning on a full pipe.
                if eof:
                    select.select([], [], [], POLL_SECONDS)
            else:
                queue.accept(count, time.monotonic() - started)
    backend.finish(timeout)


def seconds(value: str) -> float:
    result = float(value)
    if not math.isfinite(result) or not MIN_DEADLINE <= result <= 30:
        raise argparse.ArgumentTypeError('deadline must be 0.1..30 seconds')
    return result


def main() -> int:
    """Playback is opt-in; final JSON reports partial work even after failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--play', action='store_true', required=True,
                        help='explicitly allow speaker output through ffplay')
    parser.add_argument('--processor', choices=['passthrough'], required=True,
                        help='explicitly bypass proprietary voice processing')
    parser.add_argument('--deadline', type=seconds, default=5.0,
                        help='seconds per blocked write / EOF drain / child exit (default 5)')
    args = parser.parse_args()
    queue = PcmQueue()
    backend = None
    status, error, code = 'completed', None, 0
    try:
        backend = Ffplay()
        run(queue, backend, sys.stdin.fileno(), args.deadline)
    except KeyboardInterrupt:
        status, error, code = 'cancelled', 'interrupted', 130
    except (OSError, ValueError, RecursionError) as failure:
        status, error, code = 'failed', str(failure), 2
    finally:
        if backend is not None:
            backend.abort()
    print(json.dumps(queue.result(status, error), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
