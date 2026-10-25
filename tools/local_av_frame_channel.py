"""One sealed pair per acknowledged lease; metadata and SCM_RIGHTS, not bulk pixels."""
from __future__ import annotations

import array
from contextlib import suppress
import ctypes
import hashlib
import mmap
import os
from pathlib import Path
import re
import runpy
import select
import socket
import subprocess
import sys
import time
from typing import Any

SHARED = runpy.run_path(str(Path(__file__).with_name('local_av_shared_frames.py')))
OUTPUT = SHARED['OUTPUT']
FD_TOKEN = b'F'


class Lease:
    """Owner closes its immutable memfd only after output completion or abort."""

    def __init__(self, pixels: bytes | tuple[bytes, bytes], pair_sha256: str | None = None) -> None:
        chunks: tuple[bytes, ...]
        if isinstance(pixels, tuple):
            split, chunks = True, pixels
        else:
            split, chunks = False, (pixels,)
        if (any(type(chunk) is not bytes for chunk in chunks)
                or (split and (len(chunks) != 2 or len(chunks[0]) != len(chunks[1])
                               or not isinstance(pair_sha256, str)
                               or re.fullmatch('[0-9a-f]{64}', pair_sha256) is None))
                or (not split and pair_sha256 is not None)):
            raise ValueError('invalid immutable paired lens layout or fingerprint')
        self.layout = 'lens-planar' if split else 'composed'
        self.pair_sha256 = pair_sha256
        self.store = SHARED['sealed_file']()
        try:
            digest = hashlib.sha256()
            size = 0
            for chunk in chunks:
                if self.store.write(chunk) != len(chunk):
                    raise ValueError('short sealed-pair write')
                digest.update(chunk)
                size += len(chunk)
            SHARED['seal'](self.store)
            if SHARED['validate_store'](self.store.fileno()) != size:
                raise ValueError('invalid sealed-pair extent')
            self.frame = SHARED['Frame'](0, size, digest.hexdigest())
        except BaseException:
            self.store.close()
            raise

    def __len__(self) -> int:
        return self.frame.size

    def close(self) -> None:
        self.store.close()


def receive_fd(channel: Any, pump: Any, deadline: float) -> int:
    """Reject ancillary truncation/extra descriptors, closing every received fd."""
    descriptors: list[int] = []
    try:
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('sealed-pair descriptor deadline exceeded')
            try:
                token, ancillary, flags, _ = channel.recvmsg(1, socket.CMSG_SPACE(8 * array.array('i').itemsize),
                                                             socket.MSG_CMSG_CLOEXEC)
                break
            except (TimeoutError, BlockingIOError):
                pump()
        unexpected = False
        for level, kind, data in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                values = array.array('i')
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                descriptors.extend(values)
            else:
                unexpected = True
        if (token != FD_TOKEN or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                or unexpected or len(descriptors) != 1):
            raise ValueError('requires exactly one sealed-pair descriptor')
        return descriptors.pop()
    finally:
        for fd in descriptors:
            os.close(fd)


class Rect(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int) for name in ('x', 'y', 'w', 'h')]


SurfaceBase: Any = SHARED['Surface']


class Surface(SurfaceBase):
    def present_lenses(self, pixels: Any) -> None:
        if self.width % 4 or len(pixels) != self.width * self.height * 3 // 2:
            raise ValueError('invalid split lens texture geometry or bytes')
        self.pump()
        data = (ctypes.c_ubyte * len(pixels)).from_buffer(pixels)
        base, width = ctypes.addressof(data), self.width // 2
        y = width * self.height
        for x, offset in ((0, 0), (width, y * 3 // 2)):
            rect = Rect(x, 0, width, self.height)
            self.check(self.lib.SDL_UpdateYUVTexture(self.texture, ctypes.byref(rect),
                base + offset, width, base + offset + y, width // 2,
                base + offset + y * 5 // 4, width // 2))
        self.check(self.lib.SDL_RenderClear(self.renderer))
        self.check(self.lib.SDL_RenderCopy(self.renderer, self.texture, None, None))
        self.lib.SDL_RenderPresent(self.renderer)


def paired_digest(pixels: Any, width: int, height: int) -> str:
    """Hash the canonical side-by-side rows without allocating a composed pair."""
    if width % 4 or len(pixels) != width * height * 3 // 2:
        raise ValueError('invalid split lens extent')
    lens_width = width // 2
    lens_size = lens_width * height * 3 // 2
    digest = hashlib.sha256()
    offset = 0
    for w, h in ((lens_width, height), (lens_width // 2, height // 2),
                 (lens_width // 2, height // 2)):
        for row in range(h):
            start = offset + row * w
            digest.update(pixels[start:start + w])
            digest.update(pixels[lens_size + start:lens_size + start + w])
        offset += w * h
    return digest.hexdigest()


def frame_layout(row: dict[str, Any], size: int) -> tuple[str, str, str]:
    layout = row.get('layout', 'composed')
    normalized = dict(row)
    storage = row.get('storage_sha256', row.get('pixel_sha256'))
    if not isinstance(storage, str) or re.fullmatch('[0-9a-f]{64}', storage) is None:
        raise ValueError('invalid storage fingerprint')
    if layout == 'lens-planar':
        if (set(row) != {'kind', 'pair_id', 'offset', 'bytes', 'pixel_sha256', 'layout', 'storage_sha256'}):
            raise ValueError('invalid split frame metadata')
        normalized.pop('layout')
        normalized.pop('storage_sha256')
    elif layout != 'composed':
        raise ValueError('unsupported frame layout')
    _, digest = SHARED['frame_extent'](normalized, size, size)
    return layout, digest, storage


def present_fd(fd: int, size: int, digest: str, surface: Any,
               storage_digest: str | None = None, layout: str = 'composed') -> tuple[int, int]:
    """Validate/map one sealed extent; close received ownership on every path."""
    try:
        if SHARED['validate_store'](fd) != size:
            raise ValueError('sealed-pair file size mismatch')
        with mmap.mmap(fd, 0, access=mmap.ACCESS_COPY) as mapping, memoryview(mapping) as pixels:
            if hashlib.sha256(pixels).hexdigest() != (storage_digest or digest):
                raise ValueError('sealed-pair fingerprint mismatch')
            if layout == 'lens-planar' and paired_digest(pixels, surface.width, surface.height) != digest:
                raise ValueError('canonical paired pixel fingerprint mismatch')
            before = time.monotonic_ns()
            if layout == 'lens-planar':
                surface.present_lenses(pixels)
            else:
                surface.present(pixels)
            after = time.monotonic_ns()
    finally:
        os.close(fd)
    return before, after


def worker(channel_fd: int, width: int, height: int, limit: int) -> int:
    if (channel_fd < 3 or not 1 <= limit <= 300 or not 0 < width <= 8192
            or not 0 < height <= 4096 or width % 2 or height % 2
            or width * height > OUTPUT['NATIVE']['MAX_PAIR_PIXELS']):
        raise ValueError('invalid rolling output geometry or limit')
    surface = None
    with socket.socket(fileno=channel_fd) as channel:
        channel.settimeout(0.02)
        def pump() -> None:
            if surface is not None:
                surface.pump()
        def read(size: int) -> bytes:
            data = bytearray()
            deadline = time.monotonic() + 90
            while len(data) < size:
                if time.monotonic() >= deadline:
                    raise ValueError('rolling output read deadline exceeded')
                try:
                    part = channel.recv(size - len(data))
                    if not part:
                        raise ValueError('rolling output channel closed')
                    data.extend(part)
                except TimeoutError:
                    pump()
            return bytes(data)
        try:
            surface = Surface(width, height)
            channel.sendall(OUTPUT['packet'](dict(kind='ready', driver=surface.driver,
                                                  width=width, height=height)))
            seen = set()
            for index in range(limit + 1):
                row = OUTPUT['message'](read)
                if row == dict(kind='finish'):
                    surface.close()
                    surface = None
                    channel.sendall(OUTPUT['packet'](dict(kind='finished')))
                    return 0
                if index == limit:
                    raise ValueError('rolling output frame limit exceeded')
                size = width * height * 3 // 2
                layout, digest, storage = frame_layout(row, size)
                if row['pair_id'] in seen:
                    raise ValueError('duplicate rolling frame identity')
                fd = receive_fd(channel, pump, time.monotonic() + 5)
                before, after = present_fd(fd, size, digest, surface, storage, layout)
                seen.add(row['pair_id'])
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
    """Persistent isolated SDL worker; at most one pending descriptor/ack exchange."""

    def __init__(self, width: int, height: int, timeout: float, limit: int, *,
                 title: str = 'Bounded standalone recording (not live)') -> None:
        self.channel, child = socket.socketpair()
        self.process: Any = None
        self.timeout = timeout
        try:
            self.channel.setblocking(False)
            self.process = subprocess.Popen([sys.executable, str(Path(__file__)), '--worker',
                str(child.fileno()), str(width), str(height), str(limit)], pass_fds=(child.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=dict(os.environ, EZVIZ_SDL_WINDOW_TITLE=title))
            ready = self.receive(time.monotonic() + timeout)
            if (set(ready) != {'kind', 'driver', 'width', 'height'} or ready['kind'] != 'ready'
                    or not isinstance(ready['driver'], str)
                    or (ready['width'], ready['height']) != (width, height)):
                raise ValueError('invalid rolling output handshake')
            self.driver = ready['driver']
        except BaseException:
            self.abort()
            raise
        finally:
            child.close()

    def present(self, pair_id: str, lease: Lease, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        frame = lease.frame
        digest = frame.sha256 if lease.layout == 'composed' else lease.pair_sha256
        metadata = dict(kind='shared_frame', pair_id=pair_id, offset=0, bytes=frame.size, pixel_sha256=digest)
        if lease.layout == 'lens-planar':
            metadata.update(layout=lease.layout, storage_sha256=frame.sha256)
        self.transfer(OUTPUT['packet'](metadata), deadline)
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('sealed-pair descriptor send deadline exceeded')
            try:
                count = self.channel.sendmsg([FD_TOKEN], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                      array.array('i', [lease.store.fileno()]))])
                if count != 1:
                    raise ValueError('invalid descriptor send progress')
                break
            except BlockingIOError:
                self.alive()
                select.select([], [self.channel], [], min(0.02, max(0, deadline - time.monotonic())))
        row = self.receive(deadline)
        if (row.get('kind') != 'presented' or row.get('pair_id') != pair_id
                or row.get('bytes') != frame.size or row.get('pixel_sha256') != digest
                or any(type(row.get(k)) is not int for k in ('present_started_ns', 'present_returned_ns'))
                or not 0 <= row['present_started_ns'] <= row['present_returned_ns']):
            raise ValueError('rolling output acknowledgement mismatch')
        return row


if __name__ == '__main__':
    if len(sys.argv) != 6 or sys.argv[1] != '--worker':
        raise SystemExit('Private inherited-socket worker only')
    raise SystemExit(worker(*map(int, sys.argv[2:])))
