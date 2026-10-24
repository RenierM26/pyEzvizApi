"""Explicit paced host preview of audited native snapshots, NOT live camera playback.

Request-observation gaps anchor at the first selected request after validation.
SDL present-call return is neither a physical display observation nor lip-sync.
"""

from __future__ import annotations

import argparse
from contextlib import suppress
import ctypes
import ctypes.util
import hashlib
from itertools import pairwise
import json
import math
import os
from pathlib import Path
import runpy
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any

NATIVE = runpy.run_path(str(Path(__file__).with_name('app_native_scheduled_video.py')))
MAX_SPAN_MS = 60_000
MAX_MESSAGE = 8192
MIN_DEADLINE = 0.1


def packet(row: dict[str, Any]) -> bytes:
    data = json.dumps(row).encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError('output protocol message limit exceeded')
    return struct.pack('!I', len(data)) + data


def message(read: Any) -> dict[str, Any]:
    size = struct.unpack('!I', read(4))[0]
    if not 0 < size <= MAX_MESSAGE:
        raise ValueError('output protocol message limit exceeded')
    row = json.loads(read(size))
    if not isinstance(row, dict):
        raise ValueError('output protocol requires an object')
    return row


class SdlSurface:
    """Worker-only SDL2 software texture; video subsystem only, no audio API."""

    def __init__(self, width: int, height: int) -> None:
        self.window = self.renderer = self.texture = None
        self.lib = ctypes.CDLL(ctypes.util.find_library('SDL2-2.0') or 'libSDL2-2.0.so.0')
        signatures = {
            'SDL_InitSubSystem': (ctypes.c_int, [ctypes.c_uint32]),
            'SDL_QuitSubSystem': (None, [ctypes.c_uint32]),
            'SDL_GetError': (ctypes.c_char_p, []),
            'SDL_GetCurrentVideoDriver': (ctypes.c_char_p, []),
            'SDL_CreateWindow': (ctypes.c_void_p, [ctypes.c_char_p, *[ctypes.c_int] * 4, ctypes.c_uint32]),
            'SDL_CreateRenderer': (ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]),
            'SDL_CreateTexture': (ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_uint32, *[ctypes.c_int] * 3]),
            'SDL_UpdateYUVTexture': (ctypes.c_int, [ctypes.c_void_p] * 3 + [ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_int, ctypes.c_void_p, ctypes.c_int]),
            'SDL_RenderClear': (ctypes.c_int, [ctypes.c_void_p]),
            'SDL_RenderCopy': (ctypes.c_int, [ctypes.c_void_p] * 4),
            'SDL_RenderPresent': (None, [ctypes.c_void_p]),
            'SDL_PollEvent': (ctypes.c_int, [ctypes.c_void_p]),
            **{name: (None, [ctypes.c_void_p]) for name in
               ('SDL_DestroyTexture', 'SDL_DestroyRenderer', 'SDL_DestroyWindow')},
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, args
        self.width, self.height = width, height
        try:
            self.check(self.lib.SDL_InitSubSystem(0x20))  # SDL_INIT_VIDEO only
            shown_width = min(width, 1280)
            shown_height = max(1, height * shown_width // width)
            title = os.environ.get('EZVIZ_SDL_WINDOW_TITLE', 'Native snapshot replay (not live)')[:128].encode()
            self.window = self.lib.SDL_CreateWindow(title,
                0x1fff0000, 0x1fff0000, shown_width, shown_height, 0)
            if not self.window:
                raise ValueError(self.error())
            self.renderer = self.lib.SDL_CreateRenderer(self.window, -1, 1)  # software, no vsync claim
            if not self.renderer:
                raise ValueError(self.error())
            self.texture = self.lib.SDL_CreateTexture(self.renderer, 0x56555949, 1, width, height)  # IYUV
            if not self.texture:
                raise ValueError(self.error())
            self.driver = self.lib.SDL_GetCurrentVideoDriver().decode()
        except BaseException:
            self.close()
            raise

    def error(self) -> str:
        return self.lib.SDL_GetError().decode(errors='replace')

    def check(self, code: int) -> None:
        if code < 0:
            raise ValueError(self.error())

    def pump(self) -> None:
        event = ctypes.create_string_buffer(128)
        for _ in range(100):
            if not self.lib.SDL_PollEvent(event):
                break
            if ctypes.c_uint32.from_buffer(event).value == 0x100:
                raise ValueError('SDL window closed')
    def present(self, pixels: bytes) -> None:
        if len(pixels) != self.width * self.height * 3 // 2:
            raise ValueError('SDL pixel length mismatch')
        self.pump()
        data = ctypes.create_string_buffer(pixels)
        base, y = ctypes.addressof(data), self.width * self.height
        self.check(self.lib.SDL_UpdateYUVTexture(self.texture, None, base, self.width,
                   base + y, self.width // 2, base + y * 5 // 4, self.width // 2))
        self.check(self.lib.SDL_RenderClear(self.renderer))
        self.check(self.lib.SDL_RenderCopy(self.renderer, self.texture, None, None))
        self.lib.SDL_RenderPresent(self.renderer)

    def close(self) -> None:
        for key, function in (('texture', 'SDL_DestroyTexture'), ('renderer', 'SDL_DestroyRenderer'),
                              ('window', 'SDL_DestroyWindow')):
            value = getattr(self, key)
            if value:
                getattr(self.lib, function)(value)
                setattr(self, key, None)
        self.lib.SDL_QuitSubSystem(0x20)


def worker(fd: int, width: int, height: int, frame_limit: int = 32) -> int:
    """Inherited private socket only; errors/termination never escape the parent deadline."""
    if (type(frame_limit) is not int or not 1 <= frame_limit <= 300
            or fd < 3 or width % 2 or height % 2 or not 0 < width <= 8192
            or not 0 < height <= 4096 or width * height > NATIVE['MAX_PAIR_PIXELS']):
        raise ValueError('invalid SDL worker geometry or descriptor')
    surface = None
    with socket.socket(fileno=fd) as channel:
        channel.settimeout(0.02)
        def read(size: int) -> bytes:
            data = bytearray()
            deadline = time.monotonic() + 90
            while len(data) < size:
                if time.monotonic() >= deadline:
                    raise ValueError('worker protocol read deadline exceeded')
                try:
                    part = channel.recv(size - len(data))
                except TimeoutError:
                    if surface is not None:
                        surface.pump()
                    continue
                if not part:
                    raise ValueError('output protocol closed')
                data.extend(part)
            return bytes(data)
        try:
            surface = SdlSurface(width, height)
            channel.sendall(packet(dict(kind='ready', driver=surface.driver, width=width, height=height)))
            for index in range(frame_limit + 1):  # Default snapshot cap remains 32, including retries.
                row = message(read)
                if row == dict(kind='finish'):
                    surface.close()
                    surface = None
                    channel.sendall(packet(dict(kind='finished')))
                    return 0
                if index == frame_limit:
                    raise ValueError('output frame count limit exceeded')
                size = width * height * 3 // 2
                if (set(row) != {'kind', 'pair_id', 'bytes', 'pixel_sha256'} or row['kind'] != 'frame'
                        or type(row['bytes']) is not int or row['bytes'] != size
                        or not isinstance(row['pair_id'], str) or not 1 <= len(row['pair_id']) <= 128):
                    raise ValueError('invalid output frame command')
                pixels = read(size)
                digest = hashlib.sha256(pixels).hexdigest()
                if digest != row['pixel_sha256']:
                    raise ValueError('output pixel fingerprint mismatch')
                before = time.monotonic_ns()
                surface.present(pixels)
                channel.sendall(packet(dict(kind='presented', pair_id=row['pair_id'], bytes=size,
                    pixel_sha256=digest, present_started_ns=before, present_returned_ns=time.monotonic_ns())))
            raise ValueError('output frame count limit exceeded')
        except (Exception, KeyboardInterrupt) as error:
            with suppress(OSError):
                channel.sendall(packet(dict(kind='error', error=f'{type(error).__name__}: {error}'[:1000])))
            return 2
        finally:
            if surface is not None:
                surface.close()


class Output:
    """Nonblocking IPC, per-operation deadlines and terminate/kill/reap for SDL hangs."""

    def __init__(self, width: int, height: int, timeout: float, *, frame_limit: int = 32,
                 title: str | None = None) -> None:
        if type(frame_limit) is not int or not 1 <= frame_limit <= 300:
            raise ValueError('SDL frame limit must be 1..300')
        if title is not None and (not isinstance(title, str) or not 1 <= len(title) <= 128):
            raise ValueError('SDL title must contain 1..128 characters')
        self.channel, child = socket.socketpair()
        self.process: Any = None
        self.timeout = timeout
        try:
            self.channel.setblocking(False)
            command = [sys.executable, str(Path(__file__)), '--sdl-worker',
                       str(child.fileno()), str(width), str(height)]
            if frame_limit != 32:
                command.append(str(frame_limit))
            self.process = subprocess.Popen(command, pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=None if title is None else dict(os.environ, EZVIZ_SDL_WINDOW_TITLE=title))
            ready = self.receive(time.monotonic() + timeout)
            if (set(ready) != {'kind', 'driver', 'width', 'height'} or ready['kind'] != 'ready'
                    or not isinstance(ready['driver'], str) or ready['width'] != width or ready['height'] != height):
                raise ValueError('invalid SDL worker handshake')
            self.driver = ready['driver']
        except BaseException:
            self.abort()
            raise
        finally:
            child.close()

    def alive(self) -> None:
        if self.process is not None and self.process.poll() is not None:
            raise ValueError('SDL worker exited')

    def transfer(self, size_or_data: int | bytes | memoryview, deadline: float) -> bytes:
        reading = isinstance(size_or_data, int)
        remaining = size_or_data if isinstance(size_or_data, int) else len(size_or_data)
        view = memoryview(b'' if isinstance(size_or_data, int) else size_or_data)
        data = bytearray()
        offset = 0
        while offset < remaining:
            if time.monotonic() >= deadline:
                raise ValueError('SDL output deadline exceeded')
            try:
                if reading:
                    part = self.channel.recv(remaining - offset)
                    if not part:
                        raise ValueError('SDL output protocol closed')
                    data.extend(part)
                    offset += len(part)
                else:
                    count = self.channel.send(view[offset:])
                    if count <= 0:
                        raise ValueError('SDL output made no progress')
                    offset += count
            except BlockingIOError:
                self.alive()
                select.select([self.channel] if reading else [], [] if reading else [self.channel], [],
                              min(0.02, max(0, deadline - time.monotonic())))
        return bytes(data)

    def receive(self, deadline: float) -> dict[str, Any]:
        row = message(lambda size: self.transfer(size, deadline))
        if row.get('kind') == 'error':
            raise ValueError(f"SDL worker: {row.get('error')}")
        return row

    def present(self, pair_id: str, pixels: bytes, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        digest = hashlib.sha256(pixels).hexdigest()
        self.transfer(packet(dict(kind='frame', pair_id=pair_id, bytes=len(pixels), pixel_sha256=digest)), deadline)
        self.transfer(pixels, deadline)
        row = self.receive(deadline)
        if (row.get('kind') != 'presented' or row.get('pair_id') != pair_id
                or row.get('bytes') != len(pixels) or row.get('pixel_sha256') != digest
                or any(type(row.get(k)) is not int for k in ('present_started_ns', 'present_returned_ns'))
                or not 0 <= row['present_started_ns'] <= row['present_returned_ns']):
            raise ValueError('SDL acknowledgement identity/fingerprint mismatch')
        return row

    def finish(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        self.transfer(packet(dict(kind='finish')), deadline)
        if self.receive(deadline) != dict(kind='finished'):
            raise ValueError('invalid SDL finish acknowledgement')
        if self.process.wait(timeout=max(0.001, deadline - time.monotonic())):
            raise ValueError('SDL worker failed')

    def abort(self) -> None:
        self.channel.close()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=0.5)


def validate_plan(plan: list[dict[str, Any]]) -> None:
    if not plan or len(plan) > 32:
        raise ValueError('preview requires 1..32 completed requests')
    times = [p['request_at_ms'] for p in plan]
    if (any(type(t) is not int or t < 0 for t in times)
            or any(b <= a for a, b in pairwise(times)) or times[-1] - times[0] > MAX_SPAN_MS):
        raise ValueError('preview request gaps must increase within 60 seconds')


class PacedPreview:
    """Absolute first-request host anchor; no fixed FPS, implicit drop or timing repair."""

    def __init__(self, plan: list[dict[str, Any]]) -> None:
        validate_plan(plan)
        self.plan = plan
        self.actions: list[dict[str, Any]] = []
        self.completed = 0
        self.pending: str | None = None
        self.anchor_ns: int | None = None

    def run(self, spool: Any, output: Any, width: int, height: int,
            timeout: float, max_late_ms: int, final_hold_ms: int = 0) -> None:
        origin = self.plan[0]['request_at_ms']
        for pair in self.plan:
            self.pending = pair['pair_id']
            pixels = NATIVE['SCHEDULED']['PREVIEW']['compose'](
                *[spool.read(i) for i in pair['decoded_ids']], width, height)
            if self.anchor_ns is None:
                self.anchor_ns = time.monotonic_ns()
            target = self.anchor_ns + (pair['request_at_ms'] - origin) * 1_000_000
            action = dict(kind='host_present_requested', **pair, target_monotonic_ns=target,
                          composed_sha256=hashlib.sha256(pixels).hexdigest(), bytes=len(pixels))
            self.actions.append(action)
            while True:
                remaining = target - time.monotonic_ns()
                if remaining <= 0:
                    break
                output.alive()
                time.sleep(min(0.02, remaining / 1e9))
            now = time.monotonic_ns()
            action['submission_monotonic_ns'] = now
            action['submission_late_ns'] = now - target
            if now - target > max_late_ms * 1_000_000:
                raise ValueError('preview host submission lateness limit exceeded; no implicit drop')
            acknowledgement = output.present(pair['pair_id'], pixels, timeout)
            self.actions.append(dict(kind='host_present_returned', **pair, acknowledgement=acknowledgement))
            self.completed += 1
            self.pending = None
        end = time.monotonic_ns() + final_hold_ms * 1_000_000
        while True:
            remaining = end - time.monotonic_ns()
            if remaining <= 0:
                break
            output.alive()
            time.sleep(min(0.02, remaining / 1e9))
        output.finish(timeout)

    def result(self) -> dict[str, Any]:
        return dict(plan=self.plan, actions=self.actions, host_anchor_monotonic_ns=self.anchor_ns,
                    completed_host_calls=self.completed, host_call_pending=self.pending,
                    remaining_pairs=[p['pair_id'] for p in self.plan[self.completed:]])


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('input_snapshots', 'render_snapshots', 'manifest'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--event-map', required=True, type=Path)
    parser.add_argument('--play', required=True, action='store_true')
    parser.add_argument('--layout', required=True, choices=('side-by-side',))
    parser.add_argument('--timing', required=True, choices=('request-observation',))
    parser.add_argument('--anchor', required=True, choices=('first-request',))
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--allow-metadata-only', action='store_true')
    parser.add_argument('--deadline', type=float, default=5)
    parser.add_argument('--max-late-ms', type=int, default=250)
    parser.add_argument('--final-hold-ms', type=int, default=500)
    args = parser.parse_args()
    if os.name != 'posix' or not math.isfinite(args.deadline) or not MIN_DEADLINE <= args.deadline <= 30:
        parser.error('requires POSIX and a finite deadline of 0.1..30 seconds')
    if not 1 <= args.max_late_ms <= 30_000:
        parser.error('max-late-ms must be 1..30000')
    if not 0 <= args.final_hold_ms <= 30_000:
        parser.error('final-hold-ms must be 0..30000')
    return args


def main() -> int:
    args = arguments()
    backend = preview = None
    evidence: dict[str, Any] = {}
    code, status, error = 0, 'completed', None
    try:
        with args.receipt.open('x') as receipt:
            try:
                with tempfile.TemporaryFile() as temporary:
                    spool = NATIVE['NativeSpool'](temporary)
                    with (NATIVE['AUDIT']['SOURCE']['open_source'](args.input_snapshots) as source,
                          NATIVE['AUDIT']['SOURCE']['open_source'](args.render_snapshots) as rendered,
                          NATIVE['AUDIT']['SOURCE']['open_source'](args.manifest) as manifest):
                        evidence['native_audit'] = NATIVE['AUDIT']['audit'](
                            source, rendered, manifest, verify_renderer=True, observer=spool.capture)
                    with NATIVE['AUDIT']['SOURCE']['open_source'](args.event_map) as events:
                        evidence['replay'] = NATIVE['replay'](evidence['native_audit'], events,
                                                           allow_metadata_only=args.allow_metadata_only)
                    plan, width, height = NATIVE['plan_frames'](evidence['replay'], spool)
                    preview = PacedPreview(plan)
                    backend = Output(width * 2, height, args.deadline)
                    evidence['sdl_video_driver'] = backend.driver
                    evidence['output_geometry'] = dict(width=width * 2, height=height,
                        pixel_format='yuv420p', layout='side-by-side-not-native-compositor',
                        window_width=min(width * 2, 1280),
                        window_height=max(1, height * min(width * 2, 1280) // (width * 2)))
                    preview.run(spool, backend, width, height, args.deadline, args.max_late_ms, args.final_hold_ms)
            except (Exception, KeyboardInterrupt) as failure:
                code = 130 if isinstance(failure, KeyboardInterrupt) else 2
                status, error = ('cancelled' if code == 130 else 'failed'), f'{type(failure).__name__}: {failure}'
            finally:
                if backend is not None:
                    try:
                        backend.abort()
                    except (Exception, KeyboardInterrupt) as failure:
                        if error is None:
                            code, status, error = 2, 'failed', f'cleanup failed: {failure}'
            json.dump(NATIVE['receipt_names'](dict(profile='native-paced-host-preview-v1', status=status,
                error=error, timing='request-observation-gaps-first-request-host-anchor-not-live',
                initial_observation_delay_preserved=False, fixed_fps_used=False, audio_opened=False,
                host_present_return_is_physical_display=False, physical_lip_sync_measured=False,
                native_header_provenance_verified=False, decoder_buffer_ownership_verified=False,
                metadata_only_offers_allowed=args.allow_metadata_only, max_late_ms=args.max_late_ms,
                deadline_seconds=args.deadline, host_final_hold_ms=args.final_hold_ms,
                unacknowledged_call_may_have_presented=True, output=preview.result() if preview else None, **evidence)),
                receipt, sort_keys=True)
            receipt.write('\n')
    except OSError as failure:
        code, error = 2, str(failure)
    if error:
        print(f'native preview failed: {error}', file=sys.stderr)
    return code


if __name__ == '__main__':
    if len(sys.argv) in (5, 6) and sys.argv[1] == '--sdl-worker':
        raise SystemExit(worker(*map(int, sys.argv[2:])))
    raise SystemExit(main())
