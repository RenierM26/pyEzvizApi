"""Opt-in bounded standalone A/V host submissions, NOT device-clock synchronization.

Decode a local snapshot before output. Exact-PTS paired video and unchanged PCM
share one host anchor; SDL present returns/pipe writes do not measure lip sync.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import runpy
import signal
import sys
import tempfile
import threading
import time
from typing import Any

BASE = Path(__file__).parent
TIMELINE = runpy.run_path(str(BASE / 'local_av_timeline.py'))
PREVIEW = runpy.run_path(str(BASE / 'app_video_preview.py'))
OUTPUT = runpy.run_path(str(BASE / 'app_native_video_preview.py'))
SHARED = runpy.run_path(str(BASE / 'local_av_shared_frames.py'))
PCM = TIMELINE['PCM']
MAX_PAIRS = 300
MAX_SPAN = 60
POLL = 0.005
MIN_DEADLINE = 0.1


def fraction(value: dict[str, int]) -> Fraction:
    return Fraction(value['numerator'], value['denominator'])


def identity(event: dict[str, Any]) -> str:
    return event['id'] if event['kind'] == 'video_pair' else event['block']['id']


def audio_options(policy: str, overlap_ms: int | None, phase_ms: int | None) -> None:
    if policy not in ('reject', 'bounded-serial-pcm'):
        raise ValueError('unknown audio overlap policy')
    limits = (overlap_ms, phase_ms)
    if policy == 'reject':
        if any(value is not None for value in limits):
            raise ValueError('audio bounds require bounded-serial-pcm opt-in')
    elif any(type(value) is not int or not 0 <= value <= 64 for value in limits):
        raise ValueError('bounded-serial-pcm requires both explicit integer audio bounds, 0..64 ms')


def audio_contract(timeline: dict[str, Any], policy: str = 'reject',
                   overlap_ms: int | None = None, phase_ms: int | None = None) -> dict[str, Any]:
    """Audit nominal serial samples versus original targets; never an observed device clock."""
    audio_options(policy, overlap_ms, phase_ms)
    duration = Fraction(TIMELINE['AUDIO']['SAMPLES'], TIMELINE['AUDIO']['SAMPLE_RATE'])
    rows: list[dict[str, Any]] = []
    first: Fraction | None = None
    previous: Fraction | None = None
    worst_overlap = worst_phase = Fraction(0)
    for event in timeline['events']:
        if event['kind'] != 'audio_block':
            continue
        at = fraction(event['at'])
        if previous is not None and at <= previous:
            raise ValueError('audio output requires strictly increasing source starts')
        gap: Fraction | None = None if previous is None else at - previous - duration
        declared = event['gap_before']
        if (declared is None) != (gap is None) or (declared is not None and fraction(declared) != gap):
            raise ValueError('audio gap metadata disagrees with original targets')
        first = at if first is None else first
        serial_at = first + len(rows) * duration
        phase = serial_at - at
        overlap = max(Fraction(0), -gap) if gap is not None else Fraction(0)
        worst_overlap = max(worst_overlap, overlap)
        worst_phase = max(worst_phase, abs(phase))
        if policy == 'reject' and overlap:
            raise ValueError('overlapping audio is unsupported; no implicit drop or repair')
        if policy == 'bounded-serial-pcm':
            assert overlap_ms is not None and phase_ms is not None
            if overlap > Fraction(overlap_ms, 1000):
                raise ValueError('audio overlap exceeds explicit bound')
            if abs(phase) > Fraction(phase_ms, 1000):
                raise ValueError('nominal serial PCM/source phase exceeds explicit bound')
        rows.append(dict(id=event['block']['id'], source_at=event['at'],
            source_gap_before=declared, nominal_serial_pcm_at=TIMELINE['rational'](serial_at),
            nominal_serial_minus_source=TIMELINE['rational'](phase)))
        previous = at
    return dict(policy=policy, max_overlap_ms=overlap_ms, max_nominal_phase_ms=phase_ms,
        observed_max_source_overlap=TIMELINE['rational'](worst_overlap),
        calculated_max_abs_nominal_phase=TIMELINE['rational'](worst_phase),
        sample_clock_measured=False, source_targets_changed=False, pcm_samples_changed=False,
        nominal_sample_rate=TIMELINE['AUDIO']['SAMPLE_RATE'], blocks=rows)


def validate(timeline: dict[str, Any], policy: str = 'reject',
             overlap_ms: int | None = None, phase_ms: int | None = None,
             report: dict[str, Any] | None = None) -> tuple[int, int]:
    """Reject unsupported output policies before opening either backend."""
    if timeline['pending_unpaired']:
        raise ValueError('playback requires no unmatched pictures; no implicit discard')
    geometry = None
    pairs = 0
    for event in timeline['events']:
        if fraction(event['at']) > MAX_SPAN:
            raise ValueError('host submission span exceeds 60 seconds')
        if event['kind'] == 'video_pair':
            left, right = event['lenses']
            current = (left['width'], left['height'])
            if ((right['width'], right['height']) != current
                    or (geometry is not None and geometry != current)):
                raise ValueError('first standalone output profile requires constant equal geometry')
            geometry = current
            pairs += 1
    if geometry is None or not 1 <= pairs <= MAX_PAIRS:
        raise ValueError('output requires 1..300 paired pictures')
    contract = audio_contract(timeline, policy, overlap_ms, phase_ms)
    if report is not None:
        report['audio_clock_contract'] = contract
    return geometry


class Assets:
    """Private bounded temporary pixels/PCM; per-use hashes catch changed storage."""

    def __init__(self, video_file: Any, audio_file: Any) -> None:
        self.video = PREVIEW['Spool'](video_file)
        self.audio = audio_file
        self.records: dict[str, dict[str, Any]] = {}
        self.audio_bytes = 0
        self.frames: dict[str, Any] = {}

    def capture_audio(self, metadata: dict[str, Any], pcm: bytes) -> None:
        if (len(pcm) != PCM['PCM_BYTES'] or metadata['id'] in self.records
                or hashlib.sha256(pcm).hexdigest() != metadata['pcm_sha256']
                or self.audio_bytes + len(pcm) > TIMELINE['AUDIO']['MAX_BLOCKS'] * PCM['PCM_BYTES']):
            raise ValueError('invalid or excessive captured PCM')
        self.audio.seek(0, 2)
        offset = self.audio.tell()
        if self.audio.write(pcm) != len(pcm):
            raise ValueError('short temporary PCM write')
        self.records[metadata['id']] = dict(metadata, offset=offset)
        self.audio_bytes += len(pcm)

    def prepare_shared(self, timeline: dict[str, Any]) -> None:
        """Reorder/compose in place before the clock, without a second pixel spool."""
        started = time.monotonic()
        events = [e for e in timeline['events'] if e['kind'] == 'video_pair']
        order = [row['decoded_id'] for event in events for row in event['lenses']]
        records = self.video.records
        if len(order) != len(set(order)) or set(order) != set(records):
            raise ValueError('shared preparation must account for every lens exactly once')
        size = records[order[0]]['size']
        current = sorted(records, key=lambda name: records[name]['offset'])
        if any(records[name]['size'] != size or records[name]['offset'] != i * size
               for i, name in enumerate(current)):
            raise ValueError('shared preparation requires contiguous constant-size lens storage')
        positions = {name: i for i, name in enumerate(current)}
        for i, name in enumerate(order):
            if time.monotonic() - started > 60:
                raise ValueError('shared frame preparation deadline exceeded')
            j = positions[name]
            if i == j:
                continue
            other = current[i]
            desired, displaced = self.video.read(name), self.video.read(other)
            for index, data in ((i, desired), (j, displaced)):
                self.video.source.seek(index * size)
                if self.video.source.write(data) != size:
                    raise ValueError('short in-place lens reorder write')
            records[name]['offset'], records[other]['offset'] = i * size, j * size
            current[i], current[j] = name, other
            positions[name], positions[other] = i, j
        for i, event in enumerate(events):
            if time.monotonic() - started > 60:
                raise ValueError('shared frame preparation deadline exceeded')
            data = self.load(event)
            offset = i * size * 2
            self.video.source.seek(offset)
            if self.video.source.write(data) != len(data):
                raise ValueError('short in-place pair write')
            self.frames[event['id']] = SHARED['Frame'](offset, len(data), hashlib.sha256(data).hexdigest())
        SHARED['seal'](self.video.source)

    def load(self, event: dict[str, Any]) -> Any:
        if event['kind'] == 'video_pair':
            if event['id'] in self.frames:
                return self.frames[event['id']]
            left, right = event['lenses']
            return PREVIEW['compose'](self.video.read(left['decoded_id']),
                                      self.video.read(right['decoded_id']), left['width'], left['height'])
        row = event['block']
        record = self.records[row['id']]
        self.audio.seek(record['offset'])
        pcm = self.audio.read(PCM['PCM_BYTES'])
        if (len(pcm) != PCM['PCM_BYTES'] or hashlib.sha256(pcm).hexdigest() != row['pcm_sha256']
                or record['pcm_sha256'] != row['pcm_sha256']):
            raise ValueError('temporary PCM is truncated or changed')
        return pcm


class Scheduler:
    """Two independent single-job tracks, absolute targets and no drop/rebase policy."""

    def __init__(self, timeline: dict[str, Any], timeout: float, max_late_ms: int,
                 clock: Any = time.monotonic_ns, pause: Any = time.sleep) -> None:
        self.timeline, self.timeout, self.max_late_ns = timeline, timeout, max_late_ms * 1_000_000
        self.clock, self.pause = clock, pause
        self.tracks = {kind: [e for e in timeline['events'] if e['kind'] == kind]
                       for kind in ('video_pair', 'audio_block')}
        self.positions = dict.fromkeys(self.tracks, 0)
        self.completed = dict.fromkeys(self.tracks, 0)
        self.jobs: dict[str, Any] = {}
        self.active: dict[str, dict[str, Any]] = {}
        self.failed: dict[str, str] = {}
        self.actions: list[dict[str, Any]] = []
        self.cancel = threading.Event()
        self.anchor: int | None = None
        self.audio_partial = 0
        self.finished = False

    def target(self, event: dict[str, Any]) -> int:
        assert self.anchor is not None
        offset = fraction(event['at']) * 1_000_000_000
        return self.anchor + offset.numerator // offset.denominator

    def check_late(self, target: int) -> int:
        now = self.clock()
        if now - target > self.max_late_ns:
            raise ValueError('host submission lateness limit exceeded; no implicit drop or rebase')
        return now

    def call(self, event: dict[str, Any], data: Any, backend: Any,
             action: dict[str, Any]) -> Any:
        if self.cancel.is_set():
            raise ValueError('output cancelled')
        now = self.check_late(action['target_monotonic_ns'])
        action.update(started_monotonic_ns=now, submission_late_ns=now - action['target_monotonic_ns'])
        if event['kind'] == 'video_pair':
            return backend.present(identity(event), data, self.timeout)
        deadline = now + int(self.timeout * 1e9)
        self.audio_partial = 0
        while self.audio_partial < len(data):
            if self.cancel.is_set() or self.clock() >= deadline:
                raise ValueError('audio write cancelled or deadline exceeded')
            backend.alive()
            try:
                count = backend.write(data[self.audio_partial:])
            except BlockingIOError:
                self.pause(POLL)
            else:
                if type(count) is not int or not 0 < count <= len(data) - self.audio_partial:
                    raise ValueError('invalid audio write progress')
                self.audio_partial += count
        return dict(bytes=self.audio_partial, pcm_sha256=hashlib.sha256(data).hexdigest())

    def harvest(self) -> None:
        errors = []
        for kind, job in list(self.jobs.items()):
            if not job.done():
                continue
            event_id = identity(self.active[kind])
            try:
                acknowledgement = job.result()
            except Exception as error:
                self.failed[kind] = event_id
                self.actions.append(dict(kind='output_call_failed', track=kind, id=event_id,
                                         error=f'{type(error).__name__}: {error}'))
                errors.append(error)
            else:
                self.actions.append(dict(kind='output_call_completed', track=kind, id=event_id,
                                         completed_monotonic_ns=self.clock(),
                                         acknowledgement=acknowledgement))
                self.completed[kind] += 1
                if kind == 'audio_block':
                    self.audio_partial = 0
            del self.jobs[kind], self.active[kind]
        if errors:
            raise errors[0]

    def dispatch(self, assets: Assets, backends: dict[str, Any], executor: Any) -> None:
        for kind, events in self.tracks.items():
            index = self.positions[kind]
            if index == len(events):
                continue
            event = events[index]
            target = self.target(event)
            now = self.check_late(target)
            if now < target or kind in self.jobs:
                continue
            data = assets.load(event)
            self.check_late(target)  # Preparation/backpressure cannot silently move the anchor.
            action = dict(kind='output_call_submitted', track=kind, id=identity(event),
                          source_at=event['at'], target_monotonic_ns=target, bytes=len(data))
            self.actions.append(action)
            self.active[kind] = event
            self.jobs[kind] = executor.submit(self.call, event, data, backends[kind], action)
            self.positions[kind] += 1

    def run(self, assets: Assets, video: Any, audio: Any, executor: Any) -> None:
        self.anchor = self.clock()  # After validation and both output process constructors.
        backends = dict(video_pair=video, audio_block=audio)
        end = max(self.target(e) for e in self.timeline['events']) + int(self.timeout * 1e9)
        while self.jobs or any(self.positions[k] < len(v) for k, v in self.tracks.items()):
            self.harvest()
            if self.cancel.is_set() or self.clock() > end:
                raise ValueError('output cancelled or session deadline exceeded')
            for backend in backends.values():
                backend.alive()
            self.dispatch(assets, backends, executor)
            remaining = [self.target(v[self.positions[k]]) - self.clock()
                         for k, v in self.tracks.items() if self.positions[k] < len(v)]
            self.pause(min([POLL, *[n / 1e9 for n in remaining if n > 0]]))
        # Keep the final image until the explicit PCM pipe drain finishes.
        audio.finish(self.timeout)
        video.finish(self.timeout)
        self.finished = True

    def result(self) -> dict[str, Any]:
        return dict(host_anchor_monotonic_ns=self.anchor, actions=self.actions,
                    submitted=self.positions, completed=self.completed,
                    active={k: identity(v) for k, v in self.active.items()}, failed=self.failed,
                    not_submitted={k: [identity(e) for e in v[self.positions[k]:]]
                                   for k, v in self.tracks.items()},
                    partial_audio_bytes=self.audio_partial, outputs_finished=self.finished)


def playback(args: Any, receipt: dict[str, Any]) -> None:
    video = audio = scheduler = executor = None
    receipt['cleanup_errors'] = []
    shared = args.video_transport == 'sealed-store'
    with (SHARED['sealed_file']() if shared else tempfile.TemporaryFile()) as video_file, tempfile.TemporaryFile() as audio_file:
        try:
            assets = Assets(video_file, audio_file)
            timeline = TIMELINE['inspect'](args.source, args.container,
                (args.primary_stream, args.secondary_stream), args.audio_stream,
                assets.video.capture, assets.capture_audio)
            receipt['timeline'] = timeline
            receipt.update(audio_overlap_policy=args.audio_overlap_policy,
                max_audio_overlap_ms=args.max_audio_overlap_ms,
                max_audio_phase_ms=args.max_audio_phase_ms)
            width, height = validate(timeline, args.audio_overlap_policy,
                args.max_audio_overlap_ms, args.max_audio_phase_ms, receipt)
            if shared:
                assets.prepare_shared(timeline)
            receipt['video_transport'] = args.video_transport
            scheduler = Scheduler(timeline, args.deadline, args.max_late_ms)
            receipt['temporary_storage'] = dict(video_bytes=assets.video.size, audio_bytes=assets.audio_bytes)
            video = (SHARED['Output'](width * 2, height, args.deadline, video_file, MAX_PAIRS) if shared
                     else OUTPUT['Output'](width * 2, height, args.deadline, frame_limit=MAX_PAIRS,
                                          title='Standalone local A/V (host submissions; not live)'))
            receipt['video_driver'] = video.driver
            audio = PCM['Ffplay'](channel_args=('-ch_layout', 'mono') if args.mono_option == 'ch-layout'
                                  else ('-channels', '1'))
            executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='local-av-output')
            scheduler.run(assets, video, audio, executor)
        finally:
            primary_failure = sys.exc_info()[0] is not None
            if scheduler is not None:
                scheduler.cancel.set()
            errors = []
            for backend in (video, audio):
                if backend is not None:
                    try:
                        backend.abort()
                    except Exception as error:
                        errors.append(str(error))
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=True)
            if scheduler is not None:
                try:
                    scheduler.harvest()
                except Exception as error:
                    receipt['shutdown_output_error'] = f'{type(error).__name__}: {error}'
                    if not primary_failure:
                        errors.append(str(error))
                receipt['scheduler'] = scheduler.result()
            receipt['cleanup_errors'] = errors
            if errors and not primary_failure:
                raise ValueError('output cleanup failed: ' + '; '.join(errors))


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--container', required=True, choices=TIMELINE['AUDIO']['FORMATS'])
    for name in ('primary-stream', 'secondary-stream', 'audio-stream'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--play', required=True, action='store_true')
    parser.add_argument('--pairing', required=True, choices=['exact-pts'])
    parser.add_argument('--timing', required=True, choices=['host-submission'])
    parser.add_argument('--layout', required=True, choices=['side-by-side'])
    parser.add_argument('--processor', required=True, choices=['passthrough'])
    parser.add_argument('--mono-option', choices=['ch-layout', 'channels'], default='ch-layout')
    parser.add_argument('--video-transport', choices=['sealed-store', 'socket'], default='sealed-store')
    parser.add_argument('--audio-overlap-policy', choices=['reject', 'bounded-serial-pcm'], default='reject')
    parser.add_argument('--max-audio-overlap-ms', type=int)
    parser.add_argument('--max-audio-phase-ms', type=int)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--deadline', type=float, default=5)
    parser.add_argument('--max-late-ms', type=int, default=250)
    args = parser.parse_args()
    try:
        audio_options(args.audio_overlap_policy, args.max_audio_overlap_ms, args.max_audio_phase_ms)
    except ValueError as error:
        parser.error(str(error))
    if not math.isfinite(args.deadline) or not MIN_DEADLINE <= args.deadline <= 30:
        parser.error('deadline must be 0.1..30 seconds')
    if not 0 <= args.max_late_ms <= 5000:
        parser.error('max-late-ms must be 0..5000')
    return args


def main() -> int:
    args = arguments()
    receipt: dict[str, Any] = dict(profile='standalone-local-av-host-submissions-v1',
        status='failed', error=None, timing='common-host-submissions-not-device-clock-sync',
        audio_gap_policy='submit-at-source-target-no-silence-insertion',
        pipe_completion_is_audible=False, present_return_is_physical_display=False,
        native_selections_used=False, native_vqe_used=False, physical_av_sync_measured=False)
    try:
        output = args.receipt.open('x', encoding='utf-8')
    except OSError as error:
        print(f'receipt not created: {error}', file=sys.stderr)
        return 2
    previous = signal.getsignal(signal.SIGTERM)
    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    with output:
        try:
            playback(args, receipt)
            receipt['status'] = 'completed'
        except KeyboardInterrupt:
            receipt.update(status='cancelled', error='KeyboardInterrupt')
        except Exception as error:
            receipt['error'] = f'{type(error).__name__}: {error}'
        finally:
            signal.signal(signal.SIGTERM, previous)
        json.dump(receipt, output)
        output.write('\n')
    return 0 if receipt['status'] == 'completed' else 130 if receipt['status'] == 'cancelled' else 2


if __name__ == '__main__':
    raise SystemExit(main())
