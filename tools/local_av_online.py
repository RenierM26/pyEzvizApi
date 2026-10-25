"""Online relative-time policy preparation; no output devices or acquisition.

One immutable source origin after both track heads; later violations fail the
accepted prefix instead of promising whole-recording preflight guarantees.
"""
from __future__ import annotations

import argparse
from collections import deque
import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import runpy
import sys
from typing import Any

BASE = Path(__file__).parent
CHUNKED = runpy.run_path(str(BASE / 'local_av_chunked.py'))
BOUNDED = runpy.run_path(str(BASE / 'local_av_bounded_playback.py'))
PLAY = BOUNDED['PLAY']
TIMELINE = PLAY['TIMELINE']


class Policy:
    """Bound startup payload ownership and session metadata; never change media."""

    def __init__(self, streams: tuple[int, int], audio_stream: int, policy: str,
                 overlap_ms: int | None, phase_ms: int | None) -> None:
        if (len(streams) != 2 or len(set((*streams, audio_stream))) != 3
                or any(type(i) is not int or i < 0 for i in (*streams, audio_stream))):
            raise ValueError('requires three distinct absolute stream indices')
        self.audio = PLAY['AudioClock'](policy, overlap_ms, phase_ms)
        self.streams, self.audio_stream = streams, audio_stream
        self.queue: Any = deque()
        self.counts = dict(video_pair=0, audio_block=0)
        self.bytes = dict.fromkeys(self.counts, 0)
        self.peak = dict(self.bytes)
        self.previous: dict[str, Fraction] = {}
        self.first: dict[str, Fraction] = {}
        self.ids: dict[str, set[str]] = {kind: set() for kind in self.counts}
        self.origin: Fraction | None = None
        self.geometry: tuple[int, int] | None = None
        self.validated = self.yielded = self.released = 0
        self.digest = hashlib.sha256()
        self.audio_digest = hashlib.sha256()

    def validate(self, event: dict[str, Any], payload: tuple[bytes, ...]) -> tuple[str, Fraction, int]:
        kind = event['kind']
        if kind not in self.counts or type(payload) is not tuple or any(type(p) is not bytes for p in payload):
            raise ValueError('unsupported prepared event or mutable payload')
        rows = event['lenses'] if kind == 'video_pair' else [event['block']]
        expected = self.streams if kind == 'video_pair' else (self.audio_stream,)
        if tuple(row['stream_index'] for row in rows) != expected:
            raise ValueError('prepared event disagrees with selected tracks')
        stamp = PLAY['fraction'](event['source_time'])
        if any(TIMELINE['exact'](row) != stamp for row in rows):
            raise ValueError('prepared event disagrees with original source PTS')
        if kind in self.previous and stamp <= self.previous[kind]:
            raise ValueError('online source starts must strictly increase per track')
        name = PLAY['identity'](event)
        limit = PLAY['MAX_PAIRS'] if kind == 'video_pair' else TIMELINE['AUDIO']['MAX_BLOCKS']
        if not isinstance(name, str) or not name or name in self.ids[kind] or len(self.ids[kind]) >= limit:
            raise ValueError('duplicate or excessive online event identities')
        if kind == 'video_pair':
            geometry = (rows[0]['width'], rows[0]['height'])
            if (any(type(n) is not int or not 0 < n <= 4096 or n % 2 for n in geometry)
                    or rows[0]['width'] * rows[0]['height'] > TIMELINE['VIDEO']['MAX_PIXELS']
                    or (rows[1]['width'], rows[1]['height']) != geometry
                    or (self.geometry is not None and geometry != self.geometry)):
                raise ValueError('online profile requires constant equal bounded geometry')
            sizes = [geometry[0] * geometry[1] * 3 // 2] * 2
        else:
            if (type(rows[0]['samples']) is not int or rows[0]['samples'] != TIMELINE['AUDIO']['SAMPLES']
                    or PLAY['fraction'](event['duration']) != self.audio.duration):
                raise ValueError('unsupported online PCM duration or sample count')
            sizes = [PLAY['PCM']['PCM_BYTES']]
        if [len(p) for p in payload] != sizes:
            raise ValueError('prepared payload extent mismatch')
        BOUNDED['verify_payload'](event, payload)
        return kind, stamp, sum(sizes)

    def offer(self, event: dict[str, Any], payload: tuple[bytes, ...]) -> None:
        kind, stamp, size = self.validate(event, payload)
        slots = BOUNDED['VIDEO_SLOTS'] if kind == 'video_pair' else BOUNDED['AUDIO_SLOTS']
        byte_limit = BOUNDED['VIDEO_BYTES'] if kind == 'video_pair' else slots * PLAY['PCM']['PCM_BYTES']
        if self.counts[kind] >= slots or self.bytes[kind] + size > byte_limit:
            raise ValueError('online startup ownership capacity exceeded; no discard')
        # Reserve before retaining payload references; the decoder's current
        # borrowed event and its native/pending allocations are additional.
        self.counts[kind] += 1
        self.bytes[kind] += size
        self.peak[kind] = max(self.peak[kind], self.bytes[kind])
        self.queue.append((copy.deepcopy(event), payload, size))
        self.previous[kind] = stamp
        self.first.setdefault(kind, stamp)
        self.ids[kind].add(PLAY['identity'](event))
        if kind == 'video_pair':
            self.geometry = (event['lenses'][0]['width'], event['lenses'][0]['height'])
        if len(self.first) == 2 and self.origin is None:
            self.origin = min(self.first.values())

    def ready(self) -> bool:
        return self.origin is not None

    def map_pending(self) -> None:
        assert self.origin is not None
        mapped = []
        for event, payload, size in self.queue:
            at = PLAY['fraction'](event['source_time']) - self.origin
            if not 0 <= at <= PLAY['MAX_SPAN']:
                raise ValueError('online source span exceeds fixed-origin 60 seconds')
            row = dict(event)
            del row['source_time']
            row['at'] = TIMELINE['rational'](at)
            if row['kind'] == 'audio_block':
                audit = self.audio.offer(row)
                self.audio_digest.update(json.dumps(audit, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            self.digest.update(json.dumps(row, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            self.validated += 1
            mapped.append((row, payload, size))
        self.queue = deque(mapped)

    def release(self) -> None:
        event, _payload, size = self.queue.popleft()
        self.counts[event['kind']] -= 1
        self.bytes[event['kind']] -= size
        self.released += 1

    def result(self) -> dict[str, Any]:
        return dict(origin=None if self.origin is None else TIMELINE['rational'](self.origin),
            first_source_times={k: TIMELINE['rational'](v) for k, v in self.first.items()},
            geometry=self.geometry, owned_counts=dict(self.counts), owned_bytes=dict(self.bytes),
            peak_owned_bytes=dict(self.peak), validated_events=self.validated,
            yielded_prepared_events=self.yielded, released_prepared_events=self.released, mapped_metadata_sha256=self.digest.hexdigest(),
            audio_clock_contract=self.audio.result(), audio_blocks=self.audio.count,
            audio_clock_rows_sha256=self.audio_digest.hexdigest())


def selected_policy(state: Policy, selection: dict[str, Any] | None, report: dict[str, Any],
                    policy: str, overlap_ms: int | None, phase_ms: int | None) -> Policy:
    """Switch to same-container indices before the first offer, never renumber media."""
    if selection is not None and 'track_selection' not in report:
        if selection.get('mode') != 'explicit-mpeg-pes-ids':
            raise ValueError('PES selection must resolve before the first event')
        state = Policy(tuple(selection['video_indices']), selection['audio_index'], policy, overlap_ms, phase_ms)
        report['track_selection'] = copy.deepcopy(selection)
    return state


def iter_online(events: Any, streams: tuple[int, int], audio_stream: int, report: dict[str, Any], *,
                policy: str = 'reject', overlap_ms: int | None = None, phase_ms: int | None = None,
                selection: dict[str, Any] | None = None) -> Any:
    """Own input iterator; hold credit through each yield, not an output acknowledgement."""
    state = iterator = None
    primary = False
    report.pop('track_selection', None)
    report.update(profile='standalone-online-av-policy-v1', status='failed', error=None,
        output_devices_opened=False, whole_source_preflight=False, physical_av_sync_measured=False,
        delivery_order='demux-decode-order-not-global-presentation-order', cleanup_errors=[])
    try:
        state = Policy(streams, audio_stream, policy, overlap_ms, phase_ms)
        iterator = iter(events)
        for event, payload in iterator:
            state = selected_policy(state, selection, report, policy, overlap_ms, phase_ms)
            state.offer(event, payload)
            del event, payload
            if not state.ready():
                continue
            state.map_pending()  # Validate the entire startup prefix before its first yield.
            while state.queue:
                row, data, _size = state.queue[0]
                state.yielded += 1
                yield row, data
                state.release()
                del row, data
        if not state.ready():
            raise ValueError('online source ended before both track heads; no inferred origin')
        report['status'] = 'completed'
    except BaseException as error:
        primary = True
        report.update(status='closed-before-eof' if isinstance(error, GeneratorExit) else 'failed',
                      error=f'{type(error).__name__}: {error}')
        raise
    finally:
        if state is not None:
            report['policy_before_cleanup'] = state.result()
        try:
            close = getattr(iterator, 'close', None)
            if close is not None:
                close()
        except Exception as error:
            report['cleanup_errors'].append(str(error))
            report['status'] = 'failed'
            if not primary:
                report['error'] = f'{type(error).__name__}: {error}'
                raise
        finally:
            if state is not None:
                state.queue.clear()
                state.counts = dict.fromkeys(state.counts, 0)
                state.bytes = dict.fromkeys(state.bytes, 0)
                report['policy'] = state.result()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--primary-stream', required=True, type=int)
    parser.add_argument('--secondary-stream', required=True, type=int)
    parser.add_argument('--audio-stream', required=True, type=int)
    parser.add_argument('--audio-overlap-policy', choices=['reject', 'bounded-serial-pcm'], default='reject')
    parser.add_argument('--max-audio-overlap-ms', type=int)
    parser.add_argument('--max-audio-phase-ms', type=int)
    parser.add_argument('--receipt', required=True, type=Path)
    args = parser.parse_args()
    report: dict[str, Any] = {}
    decode: dict[str, Any] = {}
    try:
        with args.receipt.open('x', encoding='utf-8') as output:
            code = 0
            try:
                source = CHUNKED['iter_chunks'](CHUNKED['file_chunks'](args.source, 32768), 'mpeg',
                    (args.primary_stream, args.secondary_stream), args.audio_stream, decode, startup='bounded-mpeg')
                for _row, _payload in iter_online(source, (args.primary_stream, args.secondary_stream),
                        args.audio_stream, report, policy=args.audio_overlap_policy,
                        overlap_ms=args.max_audio_overlap_ms, phase_ms=args.max_audio_phase_ms):
                    pass
            except (Exception, KeyboardInterrupt) as error:
                code = 130 if isinstance(error, KeyboardInterrupt) else 2
                print(f'online policy failed: {type(error).__name__}: {error}', file=sys.stderr)
            report['input_decode'] = decode
            json.dump(report, output, indent=2)
            output.write('\n')
        return code
    except OSError as error:
        print(f'receipt failed: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
