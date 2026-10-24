"""Opt-in rolling local recording playback; host submissions, NOT device-clock sync.

Preflight metadata once, decode the same immutable snapshot again into bounded
lookahead. One persistent host anchor and isolated SDL worker; no live connector.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import runpy
import signal
import sys
import time
from typing import Any

BASE = Path(__file__).parent
PLAY = runpy.run_path(str(BASE / 'local_av_playback.py'))
DECODE = runpy.run_path(str(BASE / 'local_av_incremental.py'))
CHANNEL = runpy.run_path(str(BASE / 'local_av_frame_channel.py'))
VIDEO_SLOTS = 4
AUDIO_SLOTS = 32
VIDEO_BYTES = 64 * 1024 * 1024


def preflight(snapshot: bytes, args: Any, receipt: dict[str, Any]) -> tuple[list[Any], dict[str, Any], tuple[int, int]]:
    """Retain bounded metadata only; validate the entire clock/policy before devices."""
    delivery, pictures, audio = [], [], []
    report: dict[str, Any] = {}
    iterator = DECODE['iter_snapshot'](snapshot, args.container,
        (args.primary_stream, args.secondary_stream), args.audio_stream, report)
    try:
        for event, payload in iterator:
            delivery.append(event)
            if event['kind'] == 'video_pair':
                pictures.extend(event['lenses'])
            else:
                audio.append(event['block'])
            del payload
    finally:
        iterator.close()
        receipt['preflight_decode'] = report
    timeline = PLAY['TIMELINE']['plan'](dict(primary_stream=args.primary_stream,
        secondary_stream=args.secondary_stream, decoded_frames=pictures), audio)
    timeline.update(source_sha256=report['source_sha256'], source_bytes=len(snapshot),
        container=args.container, primary_stream=args.primary_stream,
        secondary_stream=args.secondary_stream, audio_stream=args.audio_stream)
    receipt['timeline'] = timeline
    geometry = PLAY['validate'](timeline, args.audio_overlap_policy,
        args.max_audio_overlap_ms, args.max_audio_phase_ms, receipt)
    return delivery, timeline, geometry


def event_id(event: dict[str, Any]) -> str:
    return PLAY['identity'](event)


def verify_payload(expected: dict[str, Any], payload: tuple[bytes, ...]) -> list[dict[str, Any]]:
    """Bind second-pass bytes to the preflight fingerprints before creating a lease."""
    kind = expected['kind']
    rows = expected['lenses'] if kind == 'video_pair' else [expected['block']]
    if len(payload) != len(rows):
        raise ValueError('second decode payload count mismatch')
    for row, data in zip(rows, payload, strict=True):
        digest = row['pixel_sha256'] if kind == 'video_pair' else row['pcm_sha256']
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('second decode payload fingerprint mismatch')
    return rows


class Lookahead:
    """Slot/byte credit includes preparation, queued and in-flight output ownership."""

    def __init__(self, iterator: Any, delivery: list[dict[str, Any]]) -> None:
        self.iterator, self.delivery = iterator, delivery
        self.index = 0
        self.source_end = False
        self.queues: dict[str, Any] = {kind: deque() for kind in ('video_pair', 'audio_block')}
        self.owned: dict[str, Any] = {}
        self.counts = dict.fromkeys(self.queues, 0)
        self.bytes = dict.fromkeys(self.queues, 0)
        self.peak_counts = dict.fromkeys(self.queues, 0)
        self.peak_bytes = dict.fromkeys(self.queues, 0)
        self.abandoned: list[str] = []
        self.preparing: str | None = None

    def capacity(self, event: dict[str, Any]) -> tuple[bool, int]:
        kind = event['kind']
        size = (sum(r['width'] * r['height'] * 3 // 2 for r in event['lenses'])
                if kind == 'video_pair' else PLAY['PCM']['PCM_BYTES'])
        slots, limit = (VIDEO_SLOTS, VIDEO_BYTES) if kind == 'video_pair' else (AUDIO_SLOTS, AUDIO_SLOTS * PLAY['PCM']['PCM_BYTES'])
        if size > limit:
            raise ValueError('one prepared event exceeds lookahead capacity')
        return self.counts[kind] < slots and self.bytes[kind] + size <= limit, size

    def pump(self) -> bool:
        if self.source_end:
            return False
        if self.index == len(self.delivery):
            try:
                next(self.iterator)
            except StopIteration:
                self.source_end = True
                return True
            raise ValueError('second decode produced unplanned tail media')
        expected = self.delivery[self.index]
        room, size = self.capacity(expected)
        if not room:
            return False
        kind, name = expected['kind'], event_id(expected)
        if name in self.owned:
            raise ValueError('duplicate lookahead reservation')
        self.preparing = name
        self.owned[name] = dict(kind=kind, size=size, data=None)
        self.counts[kind] += 1
        self.bytes[kind] += size
        self.peak_counts[kind] = max(self.peak_counts[kind], self.counts[kind])
        self.peak_bytes[kind] = max(self.peak_bytes[kind], self.bytes[kind])
        try:
            try:
                actual, payload = next(self.iterator)
            except StopIteration as error:
                raise ValueError(f'second decode ended before planned event {name}') from error
            if actual != expected:
                raise ValueError('second decode disagrees with preflight source metadata')
            rows = verify_payload(expected, payload)
            if kind == 'video_pair':
                left = rows[0]
                pixels = PLAY['PREVIEW']['compose'](*payload, left['width'], left['height'])
                prepared = CHANNEL['Lease'](pixels)
            else:
                prepared = payload[0]
            self.owned[name]['data'] = prepared
            if len(prepared) != size:
                raise ValueError('prepared output size mismatch')
            self.queues[kind].append(name)
            self.index += 1
            return True
        finally:
            self.preparing = None

    def ready(self, event: dict[str, Any]) -> bool:
        queue = self.queues[event['kind']]
        return bool(queue and queue[0] == event_id(event))

    def load(self, event: dict[str, Any]) -> Any:
        if not self.ready(event):
            raise ValueError('lookahead event is not ready in source track order')
        name = self.queues[event['kind']].popleft()
        return self.owned[name]['data']

    def release(self, name: str) -> None:
        row = self.owned.pop(name)
        try:
            if row['kind'] == 'video_pair' and row['data'] is not None:
                row['data'].close()
        finally:
            self.counts[row['kind']] -= 1
            self.bytes[row['kind']] -= row['size']

    def prefill(self, timeline: dict[str, Any], timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while self.pump():
            if time.monotonic() >= deadline:
                raise ValueError('lookahead preparation deadline exceeded')
        first = {kind: next(e for e in timeline['events'] if e['kind'] == kind) for kind in self.queues}
        if not all(self.ready(event) for event in first.values()):
            raise ValueError('initial track interleave exceeds bounded lookahead; no output started')

    def close(self) -> None:
        self.abandoned = list(self.owned)
        errors = []
        try:
            self.iterator.close()
        except Exception as error:
            errors.append(str(error))
        for name in list(self.owned):
            try:
                self.release(name)
            except Exception as error:
                errors.append(str(error))
        for queue in self.queues.values():
            queue.clear()
        if errors:
            raise ValueError('lookahead cleanup failed: ' + '; '.join(errors))

    def result(self) -> dict[str, Any]:
        return dict(prepared_events=self.index, verified_source_end=self.source_end,
            owned_counts=dict(self.counts), owned_bytes=dict(self.bytes),
            peak_owned_counts=dict(self.peak_counts), peak_owned_bytes=dict(self.peak_bytes),
            queued={kind: list(queue) for kind, queue in self.queues.items()},
            owned_ids=list(self.owned), preparing=self.preparing, abandoned=self.abandoned)


Parent: Any = PLAY['Scheduler']


class Scheduler(Parent):
    """One anchor; no queued executor backlog, frame drops, rebases or segment resets."""

    def __init__(self, timeline: dict[str, Any], timeout: float, max_late_ms: int,
                 assets: Lookahead, **kwargs: Any) -> None:
        super().__init__(timeline, timeout, max_late_ms, **kwargs)
        self.assets = assets
        self.lease_cleanup_errors: list[str] = []

    def harvest(self) -> None:
        before = {kind: event_id(event) for kind, event in self.active.items()}
        try:
            super().harvest()
        except BaseException:
            self.cancel.set()
            raise
        finally:
            primary_failure = sys.exc_info()[0] is not None
            errors = []
            for kind, name in before.items():
                if kind not in self.active and self.failed.get(kind) != name:
                    try:
                        self.assets.release(name)
                    except Exception as error:
                        errors.append(str(error))
                # Failed jobs retain credit until playback aborts/reaps the backend.
                # A timeout return is not proof that its worker released the mapping.
            self.lease_cleanup_errors.extend(errors)
            if errors:
                self.cancel.set()
                if not primary_failure:
                    raise ValueError('lease cleanup failed: ' + '; '.join(errors))

    def dispatch(self, assets: Lookahead, backends: dict[str, Any], executor: Any) -> None:
        for kind, events in self.tracks.items():
            index = self.positions[kind]
            if index == len(events):
                continue
            event = events[index]
            target = self.target(event)
            now = self.check_late(target)
            if now < target or kind in self.jobs or not assets.ready(event):
                continue
            data = assets.load(event)
            self.check_late(target)
            action = dict(kind='output_call_submitted', track=kind, id=event_id(event),
                          source_at=event['at'], target_monotonic_ns=target, bytes=len(data))
            self.actions.append(action)
            self.active[kind] = event
            self.jobs[kind] = executor.submit(self.call, event, data, backends[kind], action)
            self.positions[kind] += 1

    def run(self, assets: Lookahead, video: Any, audio: Any, executor: Any) -> None:
        self.anchor = self.clock()
        backends = dict(video_pair=video, audio_block=audio)
        end = max(self.target(e) for e in self.timeline['events']) + int(self.timeout * 1e9)
        while (not assets.source_end or self.jobs
               or any(self.positions[k] < len(v) for k, v in self.tracks.items())):
            self.harvest()
            if self.cancel.is_set() or self.clock() > end:
                raise ValueError('output cancelled or session deadline exceeded')
            for backend in backends.values():
                backend.alive()
            self.dispatch(assets, backends, executor)
            assets.pump()  # One prepared event at a time; native decode stays cooperatively bounded.
            self.dispatch(assets, backends, executor)
            self.pause(PLAY['POLL'])
        if self.clock() > end:
            raise ValueError('output session deadline exceeded')
        audio.finish(self.timeout)
        video.finish(self.timeout)
        self.finished = True


def validate_transport(args: Any) -> None:
    if args.video_transport != 'sealed-store':
        raise ValueError('bounded playback requires Linux/WSL sealed frame transport')

def playback(args: Any, receipt: dict[str, Any]) -> None:
    video = audio = scheduler = executor = assets = None
    decode_report: dict[str, Any] = {}
    receipt['cleanup_errors'] = []
    try:
        validate_transport(args)
        receipt['audio_input_probe'] = dict(probesize_bytes=32, analyzeduration_us=1,
                                             sample_format='s16le', sample_rate=16000, channels=1)
        snapshot = DECODE['snapshot_source'](args.source)
        delivery, timeline, (width, height) = preflight(snapshot, args, receipt)
        iterator = DECODE['iter_snapshot'](snapshot, args.container,
            (args.primary_stream, args.secondary_stream), args.audio_stream, decode_report)
        assets = Lookahead(iterator, delivery)
        assets.prefill(timeline, args.deadline)
        scheduler = Scheduler(timeline, args.deadline, args.max_late_ms, assets)
        video = CHANNEL['Output'](width * 2, height, args.deadline, PLAY['MAX_PAIRS'])
        receipt['video_driver'] = video.driver
        audio = PLAY['PCM']['Ffplay'](channel_args=('-ch_layout', 'mono') if args.mono_option == 'ch-layout'
                                      else ('-channels', '1'), immediate_raw_probe=True)
        executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='bounded-av-output')
        scheduler.run(assets, video, audio, executor)
    finally:
        primary_failure = sys.exc_info()[0] is not None
        errors = []
        if scheduler is not None:
            scheduler.cancel.set()
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
                receipt['shutdown_output_error'] = str(error)
                if not primary_failure:
                    errors.append(str(error))
            receipt['scheduler'] = scheduler.result()
            errors.extend(scheduler.lease_cleanup_errors)
        if assets is not None:
            receipt['lookahead_before_cleanup'] = assets.result()
            try:
                assets.close()
            except Exception as error:
                errors.append(str(error))
            receipt['lookahead'] = assets.result()
        receipt['output_decode'] = decode_report
        receipt['cleanup_errors'] = errors
        if errors and not primary_failure:
            raise ValueError('bounded output cleanup failed: ' + '; '.join(errors))


def main() -> int:
    args = PLAY['arguments']()
    receipt: dict[str, Any] = dict(profile='standalone-bounded-local-av-host-submissions-v1',
        status='failed', error=None, timing='common-host-submissions-not-device-clock-sync',
        audio_gap_policy='submit-at-source-target-no-silence-insertion',
        pipe_completion_is_audible=False, present_return_is_physical_display=False,
        native_selections_used=False, native_vqe_used=False, physical_av_sync_measured=False,
        audio_overlap_policy=args.audio_overlap_policy, max_audio_overlap_ms=args.max_audio_overlap_ms,
        max_audio_phase_ms=args.max_audio_phase_ms, video_transport='sealed-pair-descriptors')
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
