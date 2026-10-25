"""Bounded encrypted MPEG-PS packet-body adapter; no socket/output ownership.

Producer exhaustion means only that the supplied iterator ended. A future live
adapter must distinguish transport termination from its capture limits and use
interruptible deadline-aware reads; this cooperative wrapper cannot do that.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from pyezvizapi.stream_media import (
    decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size,
    mpeg_ps_decryptable_prefix_length,
)

MAX_PENDING = 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_BYTE_LIMIT = 256 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_SECONDS = 60


def validate_byte_limit(limit: int) -> None:
    if type(limit) is not int or not 0 < limit <= MAX_BYTE_LIMIT:
        raise ValueError('invalid finite compressed byte limit')


class Decryptor:
    """Bound before append, preserve original bytes, never silently select at EOF."""

    def __init__(self, key: str | bytes, codec: str) -> None:
        if codec not in ('auto', 'hevc'):
            raise ValueError('bounded decryption requires auto or hevc')
        self.key = key
        self.header: int | None = 2 if codec == 'hevc' else None
        self.buffer = bytearray()
        self.peak = 0

    def decode(self, chunk: bytes) -> bytes:
        if self.header is None:
            self.header = detect_hikvision_ps_video_nalu_header_size(chunk, self.key, default=None)
            if self.header is None:
                raise ValueError('encryption mode unresolved at producer EOF')
        return decrypt_hikvision_ps_video(chunk, self.key, nalu_header_size=self.header)

    def feed(self, data: bytes) -> bytes:
        if len(self.buffer) + len(data) > MAX_PENDING:
            raise ValueError('encrypted pending byte limit exceeded before append')
        self.buffer.extend(data)
        self.peak = max(self.peak, len(self.buffer))
        end = mpeg_ps_decryptable_prefix_length(self.buffer)
        if end <= 0:
            return b''
        if self.header is None:
            self.header = detect_hikvision_ps_video_nalu_header_size(
                bytes(self.buffer[:end]), self.key, default=None)
            if self.header is None:
                return b''
        chunk = bytes(self.buffer[:end])
        result = self.decode(chunk)
        del self.buffer[:end]
        return result

    def finish(self) -> bytes:
        result = self.decode(bytes(self.buffer)) if self.buffer else b''
        self.buffer.clear()
        return result

    def close(self) -> None:
        self.buffer.clear()
        self.key = b''  # Drop this reference; not a secure-memory erasure claim.


class Chunks:
    """No prefetch or queue; caller owns each yielded immutable clear chunk."""

    def __init__(self, packets: Any, key: str | bytes, *, codec: str = 'auto',
            clock: Any = time.monotonic, byte_limit: int = MAX_TOTAL) -> None:
        validate_byte_limit(byte_limit)
        self.byte_limit = byte_limit
        self.iterator: Any = iter(())
        self.transform: Any = None
        self.closed = self.completed = self.producer_end = False
        self.failure: BaseException | None = None
        self.cleanup_errors: list[str] = []
        self.received = self.yielded = self.packets = self.chunks = 0
        self.encrypted_hash = hashlib.sha256()
        self.clear_hash = hashlib.sha256()
        self.clock = clock
        self.started = clock()
        try:
            self.iterator = iter(packets)
            self.transform = Decryptor(key, codec)
        except BaseException as error:
            self.failure = error
            self.close()
            raise

    def __iter__(self) -> Chunks:
        return self

    def check(self) -> None:
        if self.closed:
            raise ValueError('decrypted source is closed')
        if self.failure is not None:
            raise ValueError('decrypted source previously failed') from self.failure
        if self.clock() - self.started > MAX_SECONDS:
            raise ValueError('decrypted source cooperative deadline exceeded')

    def pull(self) -> bytes:
        try:
            packet = next(self.iterator)
        except StopIteration:
            self.check()  # Slow EOF is not timely verified completion.
            if not self.packets:
                raise ValueError('encrypted producer ended without media') from None
            clear = self.transform.finish()
            self.check()
            self.producer_end = True
        else:
            self.check()
            if type(packet) is not bytes or not 0 < len(packet) <= MAX_PENDING:
                raise ValueError('encrypted source requires immutable bounded nonempty bytes')
            if self.packets >= MAX_PACKETS or self.received + len(packet) > self.byte_limit:
                raise ValueError('encrypted packet/count/byte limit exceeded')
            self.received += len(packet)
            self.packets += 1
            self.encrypted_hash.update(packet)
            clear = self.transform.feed(packet)
            self.check()
        return clear

    def __next__(self) -> bytes:
        if self.completed:
            raise StopIteration
        try:
            self.check()
            if self.producer_end:
                self.completed = True
                raise StopIteration
            while True:
                clear = self.pull()
                if clear:
                    if type(clear) is not bytes or len(clear) > MAX_PENDING or self.yielded + len(clear) > self.byte_limit:
                        raise ValueError('decrypted chunk/byte limit exceeded')
                    self.yielded += len(clear)
                    self.chunks += 1
                    self.clear_hash.update(clear)
                    return clear
                if self.producer_end:
                    self.completed = True
                    raise StopIteration
        except StopIteration:
            raise
        except BaseException as error:
            self.failure = error
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            close = getattr(self.iterator, 'close', None)
            if close is not None:
                close()
        except Exception as error:
            self.cleanup_errors.append(str(error))
        finally:
            if self.transform is not None:
                self.transform.close()
        if self.cleanup_errors and self.failure is None:
            raise ValueError('decrypted source cleanup failed')

    def result(self) -> dict[str, Any]:
        return dict(profile='bounded-decrypted-packet-chunks-v1' if self.byte_limit == MAX_TOTAL
            else 'bounded-decrypted-packet-chunks-v2',
            status='failed' if self.failure is not None or self.cleanup_errors else 'completed' if self.completed else 'closed' if self.closed else 'open',
            error_type=type(self.failure).__name__ if self.failure is not None else None,
            producer_iterator_exhausted=self.producer_end,
            verified_decryption_end=self.completed, network_eof_verified=False,
            encrypted_bytes=self.received, clear_bytes_yielded=self.yielded,
            packets=self.packets, chunks=self.chunks,
            encrypted_prefix_sha256=self.encrypted_hash.hexdigest(), clear_prefix_sha256=self.clear_hash.hexdigest(),
            complete_clear_sha256=self.clear_hash.hexdigest() if self.completed else None,
            pending_bytes=len(self.transform.buffer) if self.transform else 0,
            peak_pending_bytes=self.transform.peak if self.transform else 0,
            pending_byte_limit=MAX_PENDING, total_byte_limit=self.byte_limit,
            cleanup_errors=list(self.cleanup_errors), output_devices_opened=False)


def iter_decrypted(packets: Any, key: str | bytes, report: dict[str, Any], *,
        codec: str = 'auto', byte_limit: int = MAX_TOTAL) -> Any:
    """Own the source iterator through downstream completion, close or failure."""
    report.update(status='failed', complete_clear_sha256=None, verified_decryption_end=False)
    chunks = Chunks(packets, key, codec=codec, byte_limit=byte_limit)
    primary = False
    try:
        yield from chunks
    except BaseException:
        primary = True
        raise
    finally:
        try:
            chunks.close()
        except Exception:
            if not primary:
                raise
        finally:
            report.update(chunks.result())
