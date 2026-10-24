"""Single-pass chunk-fed HEVC/AAC preparation; no network or output devices.

A non-seekable input boundary for future acquisition integration, not live
playback. Source iteration and native decode remain cooperatively bounded.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import time
from typing import Any

DECODE = runpy.run_path(str(Path(__file__).with_name('local_av_incremental.py')))
MAX_CHUNK_BYTES = 1024 * 1024
MAX_READ_BYTES = 64 * 1024
MAX_CHUNKS = 100_000


class ChunkReader(io.RawIOBase):
    """One immutable chunk owned at a time; no seek, replay, queue or read-all."""

    def __init__(self, chunks: Any, max_bytes: int) -> None:
        super().__init__()
        self.iterator: Any = iter(())
        self.pending = b''
        self.offset = 0
        if type(max_bytes) is not int or not 0 < max_bytes <= DECODE['AUDIO']['MAX_FILE_BYTES']:
            raise ValueError('invalid compressed byte limit')
        self.iterator = iter(chunks)
        self.limit = max_bytes
        self.pending = b''
        self.offset = 0
        self.received = self.delivered = self.chunks = self.peak = 0
        self.eof = False
        self.digest = hashlib.sha256()
        self.failure: BaseException | None = None
        self.started = time.monotonic()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def check(self) -> None:
        if self.closed:
            raise ValueError('chunk source is closed')
        if self.failure is not None:
            raise ValueError('chunk source previously failed') from self.failure
        if time.monotonic() - self.started > DECODE['VIDEO']['MAX_SECONDS']:
            raise ValueError('chunk source session deadline exceeded')

    def pull(self) -> bool:
        """Pull only after the preceding chunk is fully delivered."""
        self.check()
        if self.pending or self.eof:
            return bool(self.pending)
        try:
            chunk = next(self.iterator)
        except StopIteration:
            self.eof = True
            return False
        if type(chunk) is not bytes or not 0 < len(chunk) <= MAX_CHUNK_BYTES:
            raise ValueError('source requires nonempty immutable bounded chunks')
        if self.chunks >= MAX_CHUNKS or self.received + len(chunk) > self.limit:
            raise ValueError('compressed chunk/count/byte limit exceeded')
        self.pending = chunk
        self.offset = 0
        self.chunks += 1
        self.received += len(chunk)
        self.peak = max(self.peak, len(chunk))
        self.digest.update(chunk)
        self.check()  # A slow cooperative producer may have exceeded the deadline.
        return True

    def read(self, size: int = -1) -> bytes:
        try:
            self.check()
            if type(size) is not int or size < 0:
                raise ValueError('unbounded chunk reads are unsupported')
            if size == 0 or not self.pull():
                return b''
            end = min(len(self.pending), self.offset + min(size, MAX_READ_BYTES))
            data = self.pending[self.offset:end]
            self.offset = end
            self.delivered += len(data)
            if end == len(self.pending):
                self.pending = b''
                self.offset = 0
            return data
        except BaseException as error:
            self.failure = error
            raise

    def verify_end(self) -> None:
        """Demux EOF alone cannot establish producer EOF or accept unseen tails."""
        try:
            if self.pull():
                raise ValueError('decoder ended before chunk source EOF; unread tail')
        except BaseException as error:
            self.failure = error
            raise

    def result(self) -> dict[str, Any]:
        return dict(received_bytes=self.received, delivered_bytes=self.delivered,
            received_chunks=self.chunks, prefix_sha256=self.digest.hexdigest(),
            verified_source_end=self.eof, pending_bytes=len(self.pending) - self.offset,
            owned_chunk_bytes=len(self.pending), peak_owned_chunk_bytes=self.peak,
            chunk_byte_limit=MAX_CHUNK_BYTES, read_byte_limit=MAX_READ_BYTES,
            total_byte_limit=self.limit, chunk_count_limit=MAX_CHUNKS)

    def close(self) -> None:
        if self.closed:
            return
        try:
            close = getattr(self.iterator, 'close', None)
            if close is not None:
                close()
        finally:
            self.pending = b''
            self.offset = 0
            super().close()


def iter_chunks(chunks: Any, container_format: str, streams: tuple[int, int],
                audio_stream: int, report: dict[str, Any], *,
                max_bytes: int = 16 * 1024 * 1024) -> Any:
    """Own/close the producer iterator; preparation yields are not output acks."""
    reader = None
    session = DECODE['Session'](streams, audio_stream, DECODE['discard'])
    report.update(profile='standalone-chunked-preparation-v1', status='failed', error=None,
        output_devices_opened=False, source_kind='caller-supplied-clear-chunks', physical_av_sync_measured=False,
        delivery_order='demux-decode-order-not-global-presentation-order', cleanup_errors=[])
    try:
        if (container_format not in DECODE['AUDIO']['FORMATS'] or len(streams) != 2
                or len(set((*streams, audio_stream))) != 3
                or any(type(i) is not int or i < 0 for i in (*streams, audio_stream))):
            raise ValueError('select three distinct supported tracks and a supported container')
        reader = ChunkReader(chunks, max_bytes)
        av = DECODE['AUDIO']['load_av']()
        report.update(pyav_version=av.__version__, library_versions=av.library_versions)
        started = time.monotonic()
        with av.open(reader, format=container_format,
                     options={'protocol_whitelist': 'file,pipe'}) as container:
            selected = DECODE['selected_tracks'](container, streams, audio_stream)
            adapter = DECODE['AUDIO']['FrameAdapter'](audio_stream, DECODE['AUDIO']['FormatConverter'](av))
            events = DECODE['prepared_events'](container, selected, adapter, session, audio_stream, started)
            try:
                for event, payload in events:
                    if 'first_event_input' not in report:
                        report['first_event_input'] = reader.result()
                    yield event, payload
                    del event, payload
            finally:
                close_events = getattr(events, 'close', None)
                if close_events is not None:
                    close_events()
            reader.verify_end()
        report.update(status='completed', source_sha256=reader.digest.hexdigest(),
                      source_bytes=reader.received)
    except BaseException as error:
        report.update(status='closed-before-eof' if isinstance(error, GeneratorExit) else 'failed',
                      error=f'{type(error).__name__}: {error}')
        raise
    finally:
        primary = sys.exc_info()[0] is not None
        report['preparation'] = session.result()
        if reader is not None:
            report['input_before_cleanup'] = reader.result()
            try:
                reader.close()
            except Exception as error:
                report['cleanup_errors'].append(str(error))
                if not primary:
                    report.update(status='failed', error=f'{type(error).__name__}: {error}')
                    raise
            finally:
                report['input'] = reader.result()


def file_chunks(path: Path, chunk_bytes: int) -> Any:
    """Recorded input only; regular-file validation precedes the first pull."""
    if type(chunk_bytes) is not int or not 0 < chunk_bytes <= MAX_CHUNK_BYTES:
        raise ValueError('invalid recorded chunk size')
    with DECODE['AUDIO']['open_source'](path) as source:
        while chunk := source.read(chunk_bytes):
            yield chunk


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=DECODE['AUDIO']['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--audio-stream', required=True, type=int)
    parser.add_argument('--chunk-bytes', type=int, default=32768)
    parser.add_argument('--max-bytes', type=int, default=16 * 1024 * 1024)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    report: dict[str, Any] = {}
    try:
        with args.receipt.open('x', encoding='utf-8') as output:
            code = 0
            try:
                for _event, _payload in iter_chunks(file_chunks(args.source, args.chunk_bytes),
                        args.container, (args.primary_stream, args.secondary_stream), args.audio_stream,
                        report, max_bytes=args.max_bytes):
                    pass
            except (Exception, KeyboardInterrupt) as error:
                code = 130 if isinstance(error, KeyboardInterrupt) else 2
                print(f'chunked preparation failed: {type(error).__name__}: {error}', file=sys.stderr)
            json.dump(report, output, indent=2)
            output.write('\n')
        return code
    except OSError as error:
        print(f'receipt failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
