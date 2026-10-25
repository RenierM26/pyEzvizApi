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
TRACKS = runpy.run_path(str(Path(__file__).with_name('local_av_tracks.py')))
MAX_CHUNK_BYTES = 1024 * 1024
MAX_READ_BYTES = 64 * 1024
MAX_CHUNKS = 100_000
STARTUP_BYTES = 256 * 1024
STARTUP_SECONDS = 5
STARTUP_OPTIONS = dict(probesize=str(STARTUP_BYTES), analyzeduration='100000')


class ConsumerClock:
    """Monotonic processing clock excluding only explicitly borrowed yields.

    One decoder owner pauses/resumes it; producer reads, native calls and cleanup
    remain charged. This is cooperative accounting, not a blocking-IO interrupt.
    """

    def __init__(self) -> None:
        self.started = time.monotonic()
        self.excluded = 0.0
        self.borrowed_at: float | None = None
        self.borrows = 0

    def __call__(self) -> float:
        current = time.monotonic() if self.borrowed_at is None else self.borrowed_at
        return current - self.excluded

    def pause(self) -> None:
        if self.borrowed_at is not None:
            raise ValueError('consumer clock already paused')
        self.borrowed_at = time.monotonic()

    def resume(self) -> None:
        if self.borrowed_at is None:
            raise ValueError('consumer clock is not paused')
        self.excluded += time.monotonic() - self.borrowed_at
        self.borrowed_at = None
        self.borrows += 1

    def result(self) -> dict[str, Any]:
        now = time.monotonic()
        excluded = self.excluded + (0 if self.borrowed_at is None else now - self.borrowed_at)
        return dict(profile='consumer-excluding-monotonic-v1', wall_seconds=now - self.started,
            processing_seconds=now - self.started - excluded, excluded_consumer_seconds=excluded,
            completed_borrows=self.borrows, borrow_active=self.borrowed_at is not None)


def validate_deadline_mode(mode: str) -> None:
    if type(mode) is not str or mode not in ('wall', 'consumer-excluding'):
        raise ValueError('unknown chunk processing deadline mode')


def processing_clock(mode: str, report: dict[str, Any]) -> ConsumerClock | None:
    validate_deadline_mode(mode)
    if mode == 'consumer-excluding':
        for field in ('source_sha256', 'source_bytes', 'input', 'input_before_cleanup',
                'first_event_input', 'discovery_input', 'startup_ready_input', 'pyav_version', 'library_versions'):
            report.pop(field, None)
        return ConsumerClock()
    return None


class ChunkReader(io.RawIOBase):
    """One immutable chunk owned at a time; no seek, replay, queue or read-all."""

    def __init__(self, chunks: Any, max_bytes: int, *, bounded_startup: bool = False,
                 work_clock: ConsumerClock | None = None) -> None:
        super().__init__()
        self.iterator: Any = iter(())
        self.pending = b''
        self.offset = 0
        if type(bounded_startup) is not bool:
            raise ValueError('invalid startup mode')
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
        self.wall_started = time.monotonic()
        self.work_clock = work_clock
        self.started = self.now() if work_clock is None else work_clock.started
        self.bounded_startup = self.startup_active = bounded_startup
        self.startup_elapsed: float | None = None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def now(self) -> float:
        return time.monotonic() if self.work_clock is None else self.work_clock()

    def check(self) -> float:
        if self.closed:
            raise ValueError('chunk source is closed')
        if self.failure is not None:
            raise ValueError('chunk source previously failed') from self.failure
        if self.work_clock is not None and self.work_clock.borrowed_at is not None:
            raise ValueError('chunk source cannot advance while a consumer borrow is active')
        wall_elapsed = time.monotonic() - self.wall_started
        if self.startup_active and wall_elapsed > STARTUP_SECONDS:
            raise ValueError('chunk source startup deadline exceeded')
        self.check_processing()
        return wall_elapsed

    def check_processing(self) -> None:
        if self.now() - self.started > DECODE['VIDEO']['MAX_SECONDS']:
            raise ValueError('chunk source session deadline exceeded')

    def borrow(self, event: Any, payload: Any) -> Any:
        if self.work_clock is None:
            yield event, payload
        else:
            self.work_clock.pause()
            try:
                yield event, payload
            finally:
                self.work_clock.resume()

    def finish_processing(self) -> None:
        if self.work_clock is not None:
            self.check()  # Charge native container finalization before success.

    def close_processing(self) -> None:
        self.close()
        if self.work_clock is not None:
            self.check_processing()  # Producer finalization is not a consumer wait.

    def record_final_input(self, report: dict[str, Any]) -> None:
        report['input'] = self.result()
        if self.work_clock is not None and report['status'] != 'completed':
            report.pop('source_sha256', None)
            report.pop('source_bytes', None)

    def pull(self) -> bool:
        """Pull only after the preceding chunk is fully delivered."""
        self.check()
        if self.pending or self.eof:
            return bool(self.pending)
        try:
            chunk = next(self.iterator)
        except StopIteration:
            self.check()  # Exhaustion may arrive after a blocking producer pull.
            self.eof = True
            return False
        if type(chunk) is not bytes or not 0 < len(chunk) <= MAX_CHUNK_BYTES:
            raise ValueError('source requires nonempty immutable bounded chunks')
        if self.startup_active and self.received + len(chunk) > STARTUP_BYTES:
            raise ValueError('compressed startup byte limit exceeded')
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

    def finish_startup(self) -> None:
        """Both track heads must be prepared within the same startup budget."""
        try:
            self.startup_elapsed = self.check()
            self.startup_active = False
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
        timing = {} if self.work_clock is None else dict(processing_clock=self.work_clock.result(),
            processing_seconds_limit=DECODE['VIDEO']['MAX_SECONDS'])
        return dict(**timing, received_bytes=self.received, delivered_bytes=self.delivered,
            received_chunks=self.chunks, prefix_sha256=self.digest.hexdigest(),
            verified_source_end=self.eof, pending_bytes=len(self.pending) - self.offset,
            owned_chunk_bytes=len(self.pending), peak_owned_chunk_bytes=self.peak,
            chunk_byte_limit=MAX_CHUNK_BYTES, read_byte_limit=MAX_READ_BYTES,
            total_byte_limit=self.limit, chunk_count_limit=MAX_CHUNKS,
            startup_active=self.startup_active, startup_ready_elapsed_seconds=self.startup_elapsed,
            startup_byte_limit=STARTUP_BYTES if self.bounded_startup else None,
            startup_seconds_limit=STARTUP_SECONDS if self.bounded_startup else None)

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


def prepared_chunk_events(av: Any, reader: ChunkReader, container_format: str,
                          streams: tuple[int, int], audio_stream: int, session: Any,
                          report: dict[str, Any], *, pes_ids: tuple[int, int, int] | None = None,
                          selection: dict[str, Any] | None = None) -> Any:
    """One discovery and codec context; startup ends only at both prepared heads."""
    started = reader.now()
    options = {'protocol_whitelist': 'file,pipe'}
    if reader.bounded_startup:
        options.update(STARTUP_OPTIONS)
    with av.open(reader, format=container_format, options=options) as container:
        if reader.bounded_startup:
            reader.check()
        if pes_ids is not None:
            resolved = TRACKS['resolve_pes_ids'](container, pes_ids)
            streams = tuple(resolved['video_indices'])
            audio_stream = resolved['audio_index']
            session = DECODE['Session'](streams, audio_stream, DECODE['discard'])
            report['track_selection'] = resolved
            assert selection is not None
            selection.update(resolved)
        selected = DECODE['selected_tracks'](container, streams, audio_stream)
        report['discovery_input'] = reader.result()
        adapter = DECODE['AUDIO']['FrameAdapter'](audio_stream, DECODE['AUDIO']['FormatConverter'](av))
        events = DECODE['prepared_events'](container, selected, adapter, session, audio_stream, started,
            **({} if reader.work_clock is None else dict(clock=reader.work_clock)))
        ready_kinds: set[str] = set()
        try:
            for event, payload in events:
                if reader.bounded_startup and reader.startup_active:
                    reader.check()
                    ready_kinds.add(event['kind'])
                    if ready_kinds == {'video_pair', 'audio_block'}:
                        reader.finish_startup()
                        report['startup_ready_input'] = reader.result()
                if 'first_event_input' not in report:
                    report['first_event_input'] = reader.result()
                yield from reader.borrow(event, payload)
                del event, payload
        finally:
            if pes_ids is not None:
                report['preparation'] = session.result()
            close_events = getattr(events, 'close', None)
            if close_events is not None:
                close_events()
        if reader.bounded_startup and reader.startup_active:
            raise ValueError('startup ended without both track heads')
        reader.verify_end()


def iter_chunks(chunks: Any, container_format: str, streams: tuple[int, int],
                audio_stream: int, report: dict[str, Any], *,
                max_bytes: int = 16 * 1024 * 1024, startup: str = 'default',
                pes_ids: tuple[int, int, int] | None = None, selection: dict[str, Any] | None = None,
                deadline_mode: str = 'wall') -> Any:
    """Own/close the producer iterator; preparation yields are not output acks."""
    reader = None
    primary = False
    report.pop('track_selection', None)
    report.update({} if pes_ids is None else dict(preparation={}))
    session = DECODE['Session'](streams, audio_stream, DECODE['discard'])
    report.update(profile='standalone-chunked-consumer-excluding-v1' if deadline_mode == 'consumer-excluding'
        else 'standalone-chunked-preparation-v1', status='failed', error=None,
        output_devices_opened=False, source_kind='caller-supplied-clear-chunks', physical_av_sync_measured=False,
        delivery_order='demux-decode-order-not-global-presentation-order', cleanup_errors=[])
    try:
        work_clock = processing_clock(deadline_mode, report)
        if startup not in ('default', 'bounded-mpeg') or (startup == 'bounded-mpeg' and container_format != 'mpeg'):
            raise ValueError('bounded startup requires explicit MPEG-PS input')
        report['startup'] = dict(mode=startup, probe_options=dict(STARTUP_OPTIONS) if startup == 'bounded-mpeg' else {})
        if (container_format not in DECODE['AUDIO']['FORMATS'] or len(streams) != 2
                or len(set((*streams, audio_stream))) != 3
                or any(type(i) is not int or i < 0 for i in (*streams, audio_stream))):
            raise ValueError('select three distinct supported tracks and a supported container')
        if pes_ids is not None:
            TRACKS['validate_pes_ids'](pes_ids)
            if container_format != 'mpeg' or type(selection) is not dict or selection:
                raise ValueError('PES selection requires MPEG-PS and a fresh selection receipt')
        reader = ChunkReader(chunks, max_bytes, bounded_startup=startup == 'bounded-mpeg', work_clock=work_clock)
        av = DECODE['AUDIO']['load_av']()
        report.update(pyav_version=av.__version__, library_versions=av.library_versions)
        yield from prepared_chunk_events(av, reader, container_format, streams, audio_stream, session, report,
                                         pes_ids=pes_ids, selection=selection)
        reader.finish_processing()
        report.update(status='completed', source_sha256=reader.digest.hexdigest(),
                      source_bytes=reader.received)
    except BaseException as error:
        primary = True
        report.update(status='closed-before-eof' if isinstance(error, GeneratorExit) else 'failed',
                      error=f'{type(error).__name__}: {error}')
        raise
    finally:
        if pes_ids is None:
            report['preparation'] = session.result()
        else:
            report.setdefault('preparation', {})
        if reader is not None:
            report['input_before_cleanup'] = reader.result()
            try:
                reader.close_processing()
            except Exception as error:
                report['cleanup_errors'].append(str(error))
                if not primary:
                    report.update(status='failed', error=f'{type(error).__name__}: {error}')
                    raise
            finally:
                reader.record_final_input(report)


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
    parser.add_argument('--startup', choices=['default', 'bounded-mpeg'], default='default')
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
                        report, max_bytes=args.max_bytes, startup=args.startup):
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
