"""Bounded incremental local HEVC/AAC decode, NOT a live playback scheduler.

One demux pass, synchronous borrowed-byte callbacks, exact PTS lens pairing.
No devices, network access, native selections, VQE, dropping or clock repair.
"""

from __future__ import annotations

import argparse
from collections import deque
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import time
from typing import Any

BASE = Path(__file__).parent
TIMELINE = runpy.run_path(str(BASE / 'local_av_timeline.py'))
VIDEO = TIMELINE['VIDEO']
AUDIO = TIMELINE['AUDIO']
PREVIEW = runpy.run_path(str(BASE / 'app_video_preview.py'))
MAX_PENDING_FRAMES = 16
MAX_PENDING_BYTES = 64 * 1024 * 1024


def discard(_event: dict[str, Any], _payload: tuple[bytes, ...]) -> None:
    """Default sink inspects only; no pixel/PCM references retained."""


class PairBuffer:
    """Account before copying; keep unmatched pixels until acknowledged or failed."""

    def __init__(self, streams: tuple[int, int], consume: Any = discard) -> None:
        self.streams, self.consume = streams, consume
        self.pending: dict[int, Any] = {stream: deque() for stream in streams}
        self.previous: dict[int, Fraction] = {}
        self.bytes = self.peak_bytes = self.peak_frames = self.pairs = 0
        self.digest = hashlib.sha256()

    def offer(self, row: dict[str, Any], frame: Any) -> None:
        stream = row['stream_index']
        if stream not in self.pending:
            raise ValueError('unknown lens stream')
        stamp = TIMELINE['exact'](row)
        if stream in self.previous and stamp <= self.previous[stream]:
            raise ValueError('duplicate or backward lens PTS; exact pairing is ambiguous')
        size = row['width'] * row['height'] * 3 // 2
        count = sum(len(queue) for queue in self.pending.values())
        if count >= MAX_PENDING_FRAMES or self.bytes + size > MAX_PENDING_BYTES:
            raise ValueError('incremental pending pixel capacity exceeded; no discard')
        pixels = PREVIEW['pack'](frame)
        if len(pixels) != size or hashlib.sha256(pixels).hexdigest() != row['pixel_sha256']:
            raise ValueError('copied pixels disagree with decoded fingerprint')
        self.pending[stream].append((dict(row), pixels))
        self.previous[stream] = stamp
        self.bytes += size
        self.peak_bytes = max(self.peak_bytes, self.bytes)
        self.peak_frames = max(self.peak_frames, count + 1)
        self.take()

    def take(self) -> None:
        left, right = (self.pending[stream] for stream in self.streams)
        if not left or not right:
            return
        rows = [left[0][0], right[0][0]]
        stamp = TIMELINE['exact'](rows[0])
        if stamp != TIMELINE['exact'](rows[1]):
            raise ValueError('unmatched lens PTS; no nearest-time pairing or discard')
        if (rows[0]['width'], rows[0]['height']) != (rows[1]['width'], rows[1]['height']):
            raise ValueError('exact-time lens pair has unequal geometry')
        event = dict(kind='video_pair', id=f'local-pair:{self.pairs + 1}',
                     source_time=TIMELINE['rational'](stamp), lenses=[dict(row) for row in rows])
        encoded = json.dumps(event, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        # Synchronous backpressure: the next packet is not decoded until return.
        # A raised callback leaves the offered pair in the failure receipt.
        self.consume(event, (left[0][1], right[0][1]))
        self.digest.update(encoded)
        self.pairs += 1
        for queue in (left, right):
            self.bytes -= len(queue.popleft()[1])

    def finish(self) -> None:
        if any(self.pending.values()):
            raise ValueError('unmatched pictures at EOF; no implicit tail discard')
        if not self.pairs:
            raise ValueError('both selected lenses must produce an exact pair')

    def result(self) -> dict[str, Any]:
        return dict(video_pairs_consumed=self.pairs, pending_pixel_bytes=self.bytes,
                    peak_pending_pixel_bytes=self.peak_bytes, peak_pending_frames=self.peak_frames,
                    pending_unpaired=[dict(row) for queue in self.pending.values() for row, _ in queue],
                    consumed_video_metadata_sha256=self.digest.hexdigest())


class Session:
    """Bounded counters and per-track clocks, never a full decoded-media spool."""

    def __init__(self, streams: tuple[int, int], audio_stream: int, consume: Any) -> None:
        self.pairs = PairBuffer(streams, consume)
        self.audio_stream, self.consume = audio_stream, consume
        self.counts = dict.fromkeys(streams, 0)
        self.first: dict[int, Fraction] = {}
        self.minimum: Fraction | None = None
        self.maximum: Fraction | None = None
        self.audio_count = 0
        self.audio_pending: dict[str, Any] | None = None
        self.video_pending: dict[str, Any] | None = None
        self.previous_audio: Fraction | None = None
        self.audio_digest = hashlib.sha256()
        self.packets = 0

    def observe_time(self, row: dict[str, Any]) -> Fraction:
        stamp = TIMELINE['exact'](row)
        self.first.setdefault(row['stream_index'], stamp)
        self.minimum = stamp if self.minimum is None else min(self.minimum, stamp)
        self.maximum = stamp if self.maximum is None else max(self.maximum, stamp)
        if self.maximum - self.minimum > TIMELINE['MAX_SPAN']:
            raise ValueError('source timeline span exceeds one hour')
        return stamp

    def video(self, frame: Any, stream: int) -> None:
        if sum(self.counts.values()) >= VIDEO['MAX_FRAMES']:
            raise ValueError('decoded video frame limit exceeded')
        row = VIDEO['fingerprint'](frame, stream, self.counts[stream])
        self.observe_time(row)
        self.counts[stream] += 1
        self.video_pending = dict(row)
        self.pairs.offer(row, frame)
        self.video_pending = None

    def audio(self, frame: Any, adapter: Any) -> None:
        raw, row = adapter.convert(frame)
        stamp = self.observe_time(row)
        pcm = TIMELINE['PCM']['parse_block'](raw).pcm
        if hashlib.sha256(pcm).hexdigest() != row['pcm_sha256']:
            raise ValueError('converted PCM fingerprint mismatch')
        gap = (None if self.previous_audio is None else
               TIMELINE['rational'](stamp - self.previous_audio - Fraction(AUDIO['SAMPLES'], AUDIO['SAMPLE_RATE'])))
        # Host decode time is not source timing and must not enter stable audit hashes.
        row.pop('decoded_monotonic_ns')
        event = dict(kind='audio_block', source_time=TIMELINE['rational'](stamp),
                     duration=TIMELINE['rational'](Fraction(AUDIO['SAMPLES'], AUDIO['SAMPLE_RATE'])),
                     gap_before=gap, block=row)
        self.audio_pending = json.loads(json.dumps(event))
        encoded = json.dumps(event, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        self.consume(event, (pcm,))
        self.audio_digest.update(encoded)
        self.audio_count += 1
        self.audio_pending = None
        self.previous_audio = stamp

    def result(self) -> dict[str, Any]:
        return dict(self.pairs.result(), packets_decoded=self.packets,
                    video_frames_decoded=self.counts, audio_blocks_consumed=self.audio_count,
                    pending_audio=self.audio_pending, video_offer_in_progress=self.video_pending,
                    common_origin=(TIMELINE['rational'](min(self.first.values()))
                                   if len(self.first) == 3 else None),
                    consumed_audio_metadata_sha256=self.audio_digest.hexdigest())


def selected_tracks(container: Any, streams: tuple[int, int], audio_stream: int) -> list[Any]:
    selected = [s for s in container.streams if s.index in (*streams, audio_stream)]
    if len(selected) != 3:
        raise ValueError('select three existing absolute stream indices')
    for stream in selected:
        codec = stream.codec_context
        if stream.index == audio_stream:
            if (stream.type != 'audio' or codec.name != 'aac' or codec.profile != 'LC'
                    or codec.sample_rate != AUDIO['SAMPLE_RATE'] or codec.layout.name != 'mono'):
                raise ValueError('only AAC-LC, 16-kHz mono is supported')
        elif (stream.type != 'video' or codec.name != 'hevc' or not 0 < codec.width <= 4096
              or not 0 < codec.height <= 4096 or codec.width * codec.height > VIDEO['MAX_PIXELS']):
            raise ValueError('requires bounded HEVC tracks with declared dimensions')
        codec.thread_count = 1
    return selected


def decoded_frames(container: Any, selected: list[Any], session: Session,
                   audio_stream: int, started: float, *, clock: Any = None) -> Any:
    """Cooperatively bounded persistent demux/decode, including flush packets."""
    clock = time.monotonic if clock is None else clock
    for packet in container.demux(*selected):
        if session.packets >= VIDEO['MAX_PACKETS'] or clock() - started > VIDEO['MAX_SECONDS']:
            raise ValueError('incremental packet/session limit exceeded')
        limit = AUDIO['MAX_PACKET_BYTES'] if packet.stream.index == audio_stream else VIDEO['MAX_PACKET_BYTES']
        if packet.is_corrupt or not 0 <= packet.size <= limit:
            raise ValueError('corrupt or oversized encoded packet')
        session.packets += 1
        # Decode every selected packet, including codec prerequisite pictures
        # and the demuxer's EOF flush packets. Never recreate a codec per pair.
        for frame in packet.decode():
            if clock() - started > VIDEO['MAX_SECONDS']:
                raise ValueError('incremental session limit exceeded')
            yield packet.stream.index, frame


def consume_packets(container: Any, selected: list[Any], adapter: Any, session: Session,
                    audio_stream: int, started: float) -> None:
    """Preserve persistent codec contexts and demux flushes with cooperative bounds."""
    for stream, frame in decoded_frames(container, selected, session, audio_stream, started):
        if stream == audio_stream:
            session.audio(frame, adapter)
        else:
            session.video(frame, stream)
    if adapter.resampler.resample(None):
        raise ValueError('unexpected delayed format-conversion tail')
    if time.monotonic() - started > VIDEO['MAX_SECONDS']:
        raise ValueError('incremental session limit exceeded')

def inspect(path: Path, container_format: str, streams: tuple[int, int], audio_stream: int,
            consume: Any = discard, report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Incrementally consume one immutable local snapshot; report accepted prefixes on failure."""
    report = {} if report is None else report
    report.update(profile='standalone-incremental-local-av-decode-v1', status='failed', error=None,
                  delivery_order='demux-decode-order-not-global-presentation-order',
                  output_devices_opened=False, physical_av_sync_measured=False,
                  native_selections_used=False, native_vqe_used=False,
                  pending_frame_limit=MAX_PENDING_FRAMES, pending_pixel_byte_limit=MAX_PENDING_BYTES)
    session = Session(streams, audio_stream, consume)
    try:
        if (len(streams) != 2 or len(set((*streams, audio_stream))) != 3
                or any(type(i) is not int or i < 0 for i in (*streams, audio_stream))
                or container_format not in AUDIO['FORMATS']):
            raise ValueError('select three distinct absolute indices and a supported container')
        with AUDIO['open_source'](path) as source:
            snapshot = source.read()
            if len(snapshot) != source.size:
                raise ValueError('source truncated during snapshot')
        report.update(source_sha256=hashlib.sha256(snapshot).hexdigest(), source_bytes=len(snapshot),
                      container=container_format, primary_stream=streams[0],
                      secondary_stream=streams[1], audio_stream=audio_stream)
        av = AUDIO['load_av']()
        report.update(pyav_version=av.__version__, library_versions=av.library_versions)
        started = time.monotonic()
        with av.open(io.BytesIO(snapshot), format=container_format,
                     options={'protocol_whitelist': 'file,pipe'}) as container:
            selected = selected_tracks(container, streams, audio_stream)
            adapter = AUDIO['FrameAdapter'](audio_stream, AUDIO['FormatConverter'](av))
            consume_packets(container, selected, adapter, session, audio_stream, started)
            session.pairs.finish()
            if not session.audio_count:
                raise ValueError('source produced no supported audio frames')
        report['status'] = 'completed'
    except BaseException as error:
        report['status'] = 'cancelled' if isinstance(error, KeyboardInterrupt) else 'failed'
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        report.update(session.result())
    return report


def snapshot_source(path: Path) -> bytes:
    """Own one bounded immutable compressed snapshot for both preparation passes."""
    with AUDIO['open_source'](path) as source:
        snapshot = source.read()
        if len(snapshot) != source.size:
            raise ValueError('source truncated during snapshot')
    return snapshot


def prepared_events(container: Any, selected: list[Any], adapter: Any, session: Session,
                    audio_stream: int, started: float, *, clock: Any = None) -> Any:
    """Yield one event at a time from persistent codecs, retaining their EOF flush."""
    clock = time.monotonic if clock is None else clock
    events: Any = deque()
    session.consume = lambda event, payload: events.append((event, payload))
    session.pairs.consume = session.consume
    for stream, frame in decoded_frames(container, selected, session, audio_stream, started, clock=clock):
        if stream == audio_stream:
            session.audio(frame, adapter)
        else:
            session.video(frame, stream)
        while events:
            event, payload = events.popleft()
            yield event, payload
            # Do not retain emitted pixels across the next native decode.
            del event, payload
    if adapter.resampler.resample(None):
        raise ValueError('unexpected delayed format-conversion tail')
    session.pairs.finish()
    if not session.audio_count:
        raise ValueError('source produced no supported audio frames')
    if clock() - started > VIDEO['MAX_SECONDS']:
        raise ValueError('incremental session limit exceeded')


def iter_snapshot(snapshot: bytes, container_format: str, streams: tuple[int, int],
                  audio_stream: int, report: dict[str, Any]) -> Any:
    """Yield prepared media, NOT output acknowledgements; close to release the decoder."""
    session = Session(streams, audio_stream, discard)
    report.update(profile='standalone-incremental-preparation-v1', status='failed', error=None,
                  output_devices_opened=False, physical_av_sync_measured=False)
    try:
        if (type(snapshot) is not bytes or not 0 < len(snapshot) <= AUDIO['MAX_FILE_BYTES']
                or len(streams) != 2 or len(set((*streams, audio_stream))) != 3
                or any(type(i) is not int or i < 0 for i in (*streams, audio_stream))
                or container_format not in AUDIO['FORMATS']):
            raise ValueError('requires bounded immutable bytes and three distinct supported tracks')
        report.update(source_sha256=hashlib.sha256(snapshot).hexdigest(), source_bytes=len(snapshot))
        av = AUDIO['load_av']()
        report.update(pyav_version=av.__version__, library_versions=av.library_versions)
        started = time.monotonic()
        with av.open(io.BytesIO(snapshot), format=container_format,
                     options={'protocol_whitelist': 'file,pipe'}) as container:
            selected = selected_tracks(container, streams, audio_stream)
            adapter = AUDIO['FrameAdapter'](audio_stream, AUDIO['FormatConverter'](av))
            yield from prepared_events(container, selected, adapter, session, audio_stream, started)
        report['status'] = 'completed'
    except BaseException as error:
        report.update(status='closed-before-eof' if isinstance(error, GeneratorExit) else 'failed',
                      error=f'{type(error).__name__}: {error}')
        raise
    finally:
        report['preparation'] = session.result()  # Preparation counts are not downstream output acks.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=AUDIO['FORMATS'])
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--audio-stream', required=True, type=int)
    parser.add_argument('--pairing', required=True, choices=['exact-pts'])
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    receipt: dict[str, Any] = {}
    try:
        with args.receipt.open('x', encoding='utf-8') as output:
            code = 0
            try:
                inspect(args.source, args.container, (args.primary_stream, args.secondary_stream),
                        args.audio_stream, report=receipt)
            except (Exception, KeyboardInterrupt) as error:
                code = 130 if isinstance(error, KeyboardInterrupt) else 2
                print(f'incremental decode failed: {type(error).__name__}: {error}', file=sys.stderr)
            json.dump(receipt, output, indent=2)
            output.write('\n')
        return code
    except OSError as error:
        print(f'receipt failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
