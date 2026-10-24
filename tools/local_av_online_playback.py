"""Single-pass online-policy recorded playback; no live network acquisition.

One fixed host anchor, bounded independent track queues and sealed split lens
uploads. Unknown future policy violations abort an already displayed prefix.
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

ONLINE = runpy.run_path(str(Path(__file__).with_name('local_av_online.py')))
B = ONLINE['BOUNDED']
PLAY = B['PLAY']
CHANNEL = B['CHANNEL']
HASH_SCRATCH_BYTES = 65536


def pair_digest(left: bytes, right: bytes, width: int, height: int) -> str:
    """Canonical wide Y/U/V hash directly from immutable lens planes; no wide copy."""
    if (any(type(n) is not int or n <= 0 or n % 2 for n in (width, height))
            or any(type(p) is not bytes or len(p) != width * height * 3 // 2 for p in (left, right))):
        raise ValueError('invalid immutable canonical pair extent')
    digest = hashlib.sha256()
    # Bound scratch independently of frame size; larger hashlib updates release
    # the GIL so the decode owner can progress while a preparation worker hashes.
    scratch = bytearray(HASH_SCRATCH_BYTES)
    used = 0
    with memoryview(left) as a, memoryview(right) as b, memoryview(scratch) as out:
        offset = 0
        for w, h in ((width, height), (width // 2, height // 2), (width // 2, height // 2)):
            for row in range(h):
                start = offset + row * w
                for lens in (a, b):
                    part = lens[start:start + w]
                    position = 0
                    while position < len(part):
                        size = min(len(part) - position, len(out) - used)
                        out[used:used + size] = part[position:position + size]
                        used += size
                        position += size
                        if used == len(out):
                            digest.update(out)
                            used = 0
            offset += w * h
        if used:
            digest.update(out[:used])
    return digest.hexdigest()


class Assets:
    """Credit includes preparing, queued and in-flight leases until ack/abort."""

    def __init__(self, iterator: Any) -> None:
        self.iterator = iter(iterator)
        self.queues: dict[str, Any] = {k: deque() for k in ('video_pair', 'audio_block')}
        self.owned: dict[str, Any] = {}
        self.counts = dict.fromkeys(self.queues, 0)
        self.bytes = dict(self.counts)
        self.peak_counts = dict(self.counts)
        self.peak_bytes = dict(self.counts)
        self.geometry: tuple[int, int] | None = None
        self.source_end = False
        self.preparing: str | None = None
        self.abandoned: list[str] = []
        self.offered = dict(self.counts)
        self.timings: list[dict[str, Any]] = []
        self.preparation_executor: Any = None
        self.pending: dict[str, Any] = {}

    def start_preparation(self, executor: Any = None) -> None:
        """One preparation worker; its backlog is charged to existing lease credit."""
        if self.preparation_executor is not None:
            raise ValueError('preparation worker already started')
        self.preparation_executor = executor if executor is not None else ThreadPoolExecutor(
            max_workers=1, thread_name_prefix='online-av-prepare')

    @staticmethod
    def prepare(payload: tuple[bytes, ...], geometry: tuple[int, int], timing: dict[str, Any]) -> Any:
        started = time.monotonic_ns()
        timing['preparation_started_ns'] = started
        digest = pair_digest(payload[0], payload[1], *geometry)
        hashed = time.monotonic_ns()
        lease = CHANNEL['Lease'](payload, digest)
        finished = time.monotonic_ns()
        timing.update(canonical_ns=hashed - started, store_ns=finished - hashed,
            preparation_finished_ns=finished)
        return lease

    def harvest_preparation(self) -> bool:
        progressed = False
        for name, (future, timing) in list(self.pending.items()):
            if not future.done():
                break  # Single worker preserves video source order.
            try:
                self.owned[name]['data'] = future.result()
                self.queues['video_pair'].append(name)
                self.offered['video_pair'] += 1
                progressed = True
            finally:
                timing['status'] = 'failed' if sys.exc_info()[0] is not None else 'prepared'
                self.timings.append(timing)
                del self.pending[name]
        return progressed

    def can_pull(self) -> bool:
        size = 0 if self.geometry is None else self.geometry[0] * self.geometry[1] * 3
        return (self.counts['video_pair'] < B['VIDEO_SLOTS']
            and self.bytes['video_pair'] + size <= B['VIDEO_BYTES']
            and self.counts['audio_block'] < B['AUDIO_SLOTS'])

    def pump(self, *, startup: bool = False) -> bool:
        if self.harvest_preparation():
            return True  # Dispatch newly ready heads before another decode pull.
        if self.source_end or (not startup and not self.can_pull()):
            return False
        started = time.monotonic_ns()
        try:
            event, payload = next(self.iterator)
        except StopIteration:
            self.source_end = True
            return True
        pulled = time.monotonic_ns()
        kind, name = event['kind'], PLAY['identity'](event)
        size = sum(len(part) for part in payload)
        slots = B['VIDEO_SLOTS'] if kind == 'video_pair' else B['AUDIO_SLOTS']
        limit = B['VIDEO_BYTES'] if kind == 'video_pair' else slots * PLAY['PCM']['PCM_BYTES']
        if name in self.owned or self.counts[kind] >= slots or self.bytes[kind] + size > limit:
            raise ValueError('online output ownership capacity exceeded; no discard')
        self.preparing = name
        self.owned[name] = dict(kind=kind, size=size, data=None, event=event)
        self.counts[kind] += 1
        self.bytes[kind] += size
        self.peak_counts[kind] = max(self.peak_counts[kind], self.counts[kind])
        self.peak_bytes[kind] = max(self.peak_bytes[kind], self.bytes[kind])
        timing = dict(id=name, kind=kind, pull_ns=pulled - started,
            pull_started_ns=started, pull_returned_ns=pulled)
        try:
            if kind == 'video_pair':
                self.geometry = (event['lenses'][0]['width'], event['lenses'][0]['height'])
                if self.preparation_executor is not None:
                    timing['preparation_submitted_ns'] = time.monotonic_ns()
                    future = self.preparation_executor.submit(self.prepare, payload, self.geometry, timing)
                    self.pending[name] = (future, timing)
                    return True
                self.owned[name]['data'] = self.prepare(payload, self.geometry, timing)
            else:
                self.owned[name]['data'] = payload[0]
            self.queues[kind].append(name)
            self.offered[kind] += 1
        finally:
            if name not in self.pending:
                timing.update(status='failed' if sys.exc_info()[0] is not None else 'prepared')
                self.timings.append(timing)
            self.preparing = None
        return True

    def prefill(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while not all(self.queues.values()):
            # Startup policy already bounds its entire prefix; accepting the
            # other head is allowed even when the first track's slots are full.
            if not self.pump(startup=True) or self.source_end:
                raise ValueError('source ended before both output heads')
            if time.monotonic() > deadline:
                raise ValueError('online output prefill deadline exceeded')
        while self.pump():
            if time.monotonic() > deadline:
                raise ValueError('online output prefill deadline exceeded')

    def head(self, kind: str) -> dict[str, Any] | None:
        queue = self.queues[kind]
        return self.owned[queue[0]]['event'] if queue else None

    def load(self, event: dict[str, Any]) -> Any:
        name = self.queues[event['kind']].popleft()
        if name != PLAY['identity'](event):
            raise ValueError('online output queue identity mismatch')
        return self.owned[name]['data']

    release = B['Lookahead'].release
    def close(self) -> None:
        errors = []
        # Never close an in-progress store. Join preparation before claiming or
        # releasing its result, even when source/output already failed.
        if self.preparation_executor is not None:
            try:
                self.preparation_executor.shutdown(wait=True)
            except Exception as error:
                errors.append(str(error))
                # result() below still waits for every outstanding store before
                # releasing it if executor shutdown itself failed.
        for name, (future, timing) in list(self.pending.items()):
            try:
                self.owned[name]['data'] = future.result()
                timing['status'] = 'prepared'
            except Exception as error:
                timing['status'] = 'failed'
                errors.append(str(error))
            finally:
                self.timings.append(timing)
                del self.pending[name]
        try:
            B['Lookahead'].close(self)
        except Exception as error:
            errors.append(str(error))
        if errors:
            raise ValueError('online preparation cleanup failed: ' + '; '.join(errors))

    def result(self) -> dict[str, Any]:
        return dict(verified_prepared_source_end=self.source_end, offered=dict(self.offered),
            owned_counts=dict(self.counts), owned_bytes=dict(self.bytes),
            peak_owned_counts=dict(self.peak_counts), peak_owned_bytes=dict(self.peak_bytes),
            queued={kind: list(q) for kind, q in self.queues.items()},
            owned_ids=list(self.owned), abandoned=list(self.abandoned), preparing=self.preparing,
            preparation_timings=list(self.timings), pending_preparation=list(self.pending),
            preparation_workers=1 if self.preparation_executor is not None else 0,
            canonical_scratch_byte_limit=HASH_SCRATCH_BYTES)


Parent: Any = B['Scheduler']


class Scheduler(Parent):
    """Reuse acknowledgement/abort lease handling, not the recorded timeline plan."""

    def __init__(self, assets: Assets, timeout: float, max_late_ms: int, **kwargs: Any) -> None:
        super().__init__(dict(events=[]), timeout, max_late_ms, assets, **kwargs)
        self.latest: int | None = None

    def dispatch(self, assets: Assets, backends: dict[str, Any], executor: Any) -> None:
        for kind in assets.queues:
            event = assets.head(kind)
            if event is None:
                continue
            target = self.target(event)
            now = self.check_late(target)
            if kind in self.jobs or now < target:
                continue
            data = assets.load(event)
            self.check_late(target)
            action = dict(kind='output_call_submitted', track=kind, id=PLAY['identity'](event),
                source_at=event['at'], target_monotonic_ns=target, bytes=len(data))
            self.actions.append(action)
            self.active[kind] = event
            self.jobs[kind] = executor.submit(self.call, event, data, backends[kind], action)
            self.positions[kind] += 1
            self.latest = target if self.latest is None else max(self.latest, target)

    def run(self, assets: Assets, video: Any, audio: Any, executor: Any) -> None:
        self.anchor = self.clock()
        backends = dict(video_pair=video, audio_block=audio)
        end = self.anchor + int((PLAY['MAX_SPAN'] + self.timeout) * 1e9)
        while not assets.source_end or assets.pending or self.jobs or any(assets.queues.values()):
            self.harvest()
            if self.cancel.is_set() or self.clock() > end:
                raise ValueError('online output cancelled or session deadline exceeded')
            for backend in backends.values():
                backend.alive()
            self.dispatch(assets, backends, executor)
            prepared = assets.pump()
            self.harvest()
            self.dispatch(assets, backends, executor)
            if assets.source_end and not assets.pending and not any(assets.queues.values()) and self.latest is not None:
                end = min(end, self.latest + int(self.timeout * 1e9))
            if not prepared:
                self.pause(PLAY['POLL'])
        if self.clock() > end:
            raise ValueError('online output session deadline exceeded')
        audio.finish(self.timeout)
        video.finish(self.timeout)
        self.finished = True

    def result(self) -> dict[str, Any]:
        report = super().result()
        report['not_submitted'] = {kind: list(q) for kind, q in self.assets.queues.items()}
        return report


def cleanup(assets: Any, scheduler: Any, executor: Any, backends: tuple[Any, Any],
            receipt: dict[str, Any], primary: bool) -> None:
    errors = []
    if scheduler is not None:
        scheduler.cancel.set()
    for backend in backends:
        if backend is not None:
            try:
                backend.abort()
            except Exception as error:
                errors.append(str(error))
    if executor is not None:
        try:
            executor.shutdown(wait=True, cancel_futures=True)
        except Exception as error:
            errors.append(str(error))
    if scheduler is not None:
        try:
            scheduler.harvest()
        except Exception as error:
            receipt['shutdown_output_error'] = str(error)
            if not primary:
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
    receipt['cleanup_errors'] = errors
    if errors and not primary:
        raise ValueError('online output cleanup failed: ' + '; '.join(errors))


def playback(args: Any, receipt: dict[str, Any]) -> None:
    assets = scheduler = executor = video = audio = None
    decode: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    try:
        B['validate_transport'](args)
        if args.container != 'mpeg':
            raise ValueError('online output profile requires clear MPEG-PS')
        source = ONLINE['CHUNKED']['iter_chunks'](ONLINE['CHUNKED']['file_chunks'](args.source, 32768),
            'mpeg', (args.primary_stream, args.secondary_stream), args.audio_stream, decode, startup='bounded-mpeg')
        events = ONLINE['iter_online'](source, (args.primary_stream, args.secondary_stream), args.audio_stream,
            policy, policy=args.audio_overlap_policy, overlap_ms=args.max_audio_overlap_ms, phase_ms=args.max_audio_phase_ms)
        assets = Assets(events)
        assets.prefill(args.deadline)
        assert assets.geometry is not None
        width, height = assets.geometry
        video = CHANNEL['Output'](width * 2, height, args.deadline, PLAY['MAX_PAIRS'])
        receipt['video_driver'] = video.driver
        audio = PLAY['PCM']['Ffplay'](channel_args=('-ch_layout', 'mono') if args.mono_option == 'ch-layout'
            else ('-channels', '1'), immediate_raw_probe=True)
        executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='online-av-output')
        assets.start_preparation()
        scheduler = Scheduler(assets, args.deadline, args.max_late_ms)
        scheduler.run(assets, video, audio, executor)
    finally:
        try:
            cleanup(assets, scheduler, executor, (video, audio), receipt, sys.exc_info()[0] is not None)
        finally:
            receipt.update(input_decode=decode, online_policy=policy)


def main() -> int:
    args = PLAY['arguments']()
    receipt: dict[str, Any] = dict(profile='standalone-online-local-av-host-submissions-v1',
        status='failed', error=None, whole_source_preflight=False, network_acquisition=False,
        timing='common-host-submissions-not-device-clock-sync',
        native_selections_used=False, native_vqe_used=False,
        video_transport='sealed-pair-descriptors', composition='split-upload',
        audio_input_probe=dict(probesize_bytes=32, analyzeduration_us=1,
            sample_format='s16le', sample_rate=16000, channels=1),
        pipe_completion_is_audible=False, present_return_is_physical_display=False,
        physical_av_sync_measured=False)
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
