"""Sealed bounded local paired pixels; metadata-only IPC, not a physical display clock."""
from __future__ import annotations

from contextlib import suppress
import ctypes
from dataclasses import dataclass
import fcntl
import hashlib
import mmap
import os
from pathlib import Path
import re
import runpy
import socket
import stat
import subprocess
import sys
import time
from typing import Any

OUTPUT = runpy.run_path(str(Path(__file__).with_name('app_native_video_preview.py')))
CAP = OUTPUT['NATIVE']['SCHEDULED']['PREVIEW']['MAX_SPOOL_BYTES']
SEALS = sum(getattr(fcntl, name, 0) for name in
            ('F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK', 'F_SEAL_SEAL'))


@dataclass(frozen=True)
class Frame:
    offset: int
    size: int
    sha256: str

    def __len__(self) -> int:
        return self.size


def sealed_file() -> Any:
    if not hasattr(os, 'memfd_create'):
        raise ValueError('sealed shared frames require Linux/WSL memfd support')
    return os.fdopen(os.memfd_create('standalone-paired-pixels', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING), 'w+b')


def seal(store: Any) -> None:
    store.flush()
    fcntl.fcntl(store.fileno(), fcntl.F_ADD_SEALS, SEALS)


def validate_store(fd: int) -> int:
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= CAP
            or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS != SEALS):
        raise ValueError('requires a bounded fully sealed frame store')
    return info.st_size


def frame_extent(row: dict[str, Any], size: int, total: int) -> tuple[int, str]:
    if (set(row) != {'kind', 'pair_id', 'offset', 'bytes', 'pixel_sha256'}
            or row['kind'] != 'shared_frame' or type(row['offset']) is not int
            or type(row['bytes']) is not int or row['bytes'] != size
            or not 0 <= row['offset'] <= total - size or row['offset'] % size
            or not isinstance(row['pair_id'], str) or not 1 <= len(row['pair_id']) <= 128
            or not isinstance(row['pixel_sha256'], str)
            or re.fullmatch('[0-9a-f]{64}', row['pixel_sha256']) is None):
        raise ValueError('invalid shared-frame identity or extent')
    return row['offset'], row['pixel_sha256']


SurfaceBase: Any = OUTPUT['SdlSurface']


class Surface(SurfaceBase):
    def present(self, pixels: Any) -> None:
        if len(pixels) != self.width * self.height * 3 // 2:
            raise ValueError('SDL shared pixel length mismatch')
        self.pump()
        # MAP_PRIVATE writable view permits ctypes buffer access without copying.
        # SDL_UpdateYUVTexture consumes it synchronously; no pointer is retained.
        data = (ctypes.c_ubyte * len(pixels)).from_buffer(pixels)
        base, y = ctypes.addressof(data), self.width * self.height
        self.check(self.lib.SDL_UpdateYUVTexture(self.texture, None, base, self.width,
                   base + y, self.width // 2, base + y * 5 // 4, self.width // 2))
        self.check(self.lib.SDL_RenderClear(self.renderer))
        self.check(self.lib.SDL_RenderCopy(self.renderer, self.texture, None, None))
        self.lib.SDL_RenderPresent(self.renderer)


def worker(channel_fd: int, store_fd: int, width: int, height: int, limit: int) -> int:
    if (channel_fd < 3 or store_fd < 3 or channel_fd == store_fd or not 1 <= limit <= 300
            or not 0 < width <= 8192 or not 0 < height <= 4096 or width % 2 or height % 2
            or width * height > OUTPUT['NATIVE']['MAX_PAIR_PIXELS']):
        raise ValueError('invalid shared output geometry or descriptors')
    surface = None
    total = validate_store(store_fd)
    with socket.socket(fileno=channel_fd) as channel, mmap.mmap(store_fd, 0, access=mmap.ACCESS_COPY) as mapping:
        channel.settimeout(0.02)
        def read(size: int) -> bytes:
            data = bytearray()
            deadline = time.monotonic() + 90
            while len(data) < size:
                if time.monotonic() >= deadline:
                    raise ValueError('shared output read deadline exceeded')
                try:
                    part = channel.recv(size - len(data))
                    if not part:
                        raise ValueError('shared output channel closed')
                    data.extend(part)
                except TimeoutError:
                    if surface is not None:
                        surface.pump()
            return bytes(data)
        try:
            surface = Surface(width, height)
            channel.sendall(OUTPUT['packet'](dict(kind='ready', driver=surface.driver,
                                                  width=width, height=height, store_bytes=total)))
            seen = set()
            for index in range(limit + 1):
                row = OUTPUT['message'](read)
                if row == dict(kind='finish'):
                    surface.close()
                    surface = None
                    channel.sendall(OUTPUT['packet'](dict(kind='finished')))
                    return 0
                if index == limit:
                    raise ValueError('shared output frame limit exceeded')
                size = width * height * 3 // 2
                offset, digest = frame_extent(row, size, total)
                if row['pair_id'] in seen:
                    raise ValueError('duplicate shared frame identity')
                seen.add(row['pair_id'])
                with memoryview(mapping)[offset:offset + size] as pixels:
                    if hashlib.sha256(pixels).hexdigest() != digest:
                        raise ValueError('sealed frame fingerprint mismatch')
                    before = time.monotonic_ns()
                    surface.present(pixels)
                    after = time.monotonic_ns()
                channel.sendall(OUTPUT['packet'](dict(kind='presented', pair_id=row['pair_id'],
                    bytes=size, pixel_sha256=digest, present_started_ns=before, present_returned_ns=after)))
        except (Exception, KeyboardInterrupt) as error:
            with suppress(OSError):
                channel.sendall(OUTPUT['packet'](dict(kind='error', error=f'{type(error).__name__}: {error}'[:1000])))
            return 2
        finally:
            if surface is not None:
                surface.close()
    return 2


Parent: Any = OUTPUT['Output']


class Output(Parent):
    """Reuse bounded handshake/ack/drain/abort, transmitting no frame payload bytes."""

    def __init__(self, width: int, height: int, timeout: float, store: Any, limit: int) -> None:
        total = validate_store(store.fileno())
        self.channel, child = socket.socketpair()
        self.process: Any = None
        self.timeout = timeout
        try:
            self.channel.setblocking(False)
            self.process = subprocess.Popen([sys.executable, str(Path(__file__)), '--worker',
                str(child.fileno()), str(store.fileno()), str(width), str(height), str(limit)],
                pass_fds=(child.fileno(), store.fileno()), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=dict(os.environ, EZVIZ_SDL_WINDOW_TITLE='Standalone sealed-frame replay (not live)'))
            row = self.receive(time.monotonic() + timeout)
            if (set(row) != {'kind', 'driver', 'width', 'height', 'store_bytes'}
                    or row['kind'] != 'ready' or not isinstance(row['driver'], str)
                    or (row['width'], row['height'], row['store_bytes']) != (width, height, total)):
                raise ValueError('invalid sealed output handshake')
            self.driver = row['driver']
        except BaseException:
            self.abort()
            raise
        finally:
            child.close()

    def present(self, pair_id: str, frame: Frame, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        self.transfer(OUTPUT['packet'](dict(kind='shared_frame', pair_id=pair_id,
            offset=frame.offset, bytes=frame.size, pixel_sha256=frame.sha256)), deadline)
        row = self.receive(deadline)
        if (row.get('kind') != 'presented' or row.get('pair_id') != pair_id
                or row.get('bytes') != frame.size or row.get('pixel_sha256') != frame.sha256
                or any(type(row.get(k)) is not int for k in ('present_started_ns', 'present_returned_ns'))
                or not 0 <= row['present_started_ns'] <= row['present_returned_ns']):
            raise ValueError('shared output acknowledgement mismatch')
        return row


if __name__ == '__main__':
    if len(sys.argv) != 7 or sys.argv[1] != '--worker':
        raise SystemExit('Private inherited-descriptor worker only')
    raise SystemExit(worker(*map(int, sys.argv[2:])))
