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
from threading import Event
import time
from typing import Any

ONLINE = runpy.run_path(str(Path(__file__).with_name('local_av_online.py')))
B = ONLINE['BOUNDED']
PLAY = B['PLAY']
CHANNEL = B['CHANNEL']
PULL = runpy.run_path(str(Path(__file__).with_name('local_av_pull.py')))
AUDIT = runpy.run_path(str(Path(__file__).with_name('local_av_audit.py')))
HASH_SCRATCH_BYTES = 65536


class PlaybackStopped(ValueError):
    """Caller requested cooperative stop; this is not successful source EOF."""


def check_stop(stop: Event | None) -> None:
    if stop is not None and stop.is_set():
        raise PlaybackStopped('online playback stop requested')


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


def validate_pending_source(source: Any, timeout: float) -> None:
    PULL['validate_timeout'](timeout)
    if not isinstance(source, PULL['PreparedPull']):
        raise ValueError('pending input requires an explicitly owned PreparedPull')
    state = source.result()
    if state['requested'] or state['consumer_closed'] or not state['worker_alive']:
        raise ValueError('pending input requires a pristine, unrequested pull owner')


class Assets:
    """Credit includes preparing, queued and in-flight leases until ack/abort."""

    def __init__(self, iterator: Any, *, pending_input: bool = False, join_timeout: float = 5,
                 stop: Event | None = None, diagnostic_tail: int | None = None) -> None:
        # Opt-in callers retain the supplied pull owner, including after a failed
        # join. Never wrap/close its executing iterator on the consumer thread.
        if pending_input:
            validate_pending_source(iterator, join_timeout)
        self.pull: Any = iterator if pending_input else None
        self.iterator: Any = None if pending_input else iter(iterator)
        AUDIT['validate_tail'](diagnostic_tail)
        self.diagnostic_tail = diagnostic_tail
        self.stop = stop
        self.join_timeout = join_timeout
        self.reservation: dict[str, int] = {}
        self.pull_started_ns: int | None = None
        self.peak_credit_counts = dict(video_pair=0, audio_block=0)
        self.peak_credit_bytes = dict(self.peak_credit_counts)
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
        self.timings: Any = [] if diagnostic_tail is None else AUDIT['Records'](diagnostic_tail)
        self.diagnostic_errors = 0
        self.diagnostic_error_type: str | None = None
        self.preparation_executor: Any = None
        self.pending: dict[str, Any] = {}

    def record_timing(self, timing: dict[str, Any], *, primary: bool) -> None:
        try:
            self.timings.append(timing)
        except Exception as error:
            self.diagnostic_errors += 1
            self.diagnostic_error_type = type(error).__name__
            if not primary:
                raise

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
            timing['status'] = 'failed'
            try:
                self.owned[name]['data'] = future.result()
                self.queues['video_pair'].append(name)
                self.offered['video_pair'] += 1
                progressed = True
                timing['status'] = 'prepared'
            finally:
                try:
                    self.record_timing(timing, primary=timing['status'] == 'failed')
                finally:
                    del self.pending[name]
        return progressed

    def unknown_size(self) -> int:
        # Before geometry is known, conservatively reserve the entire video
        # budget. Policy already rejects geometry changes after the first pair.
        return B['VIDEO_BYTES'] if self.geometry is None else self.geometry[0] * self.geometry[1] * 3

    def can_pull(self) -> bool:
        size = self.unknown_size() if self.pull is not None else (
            0 if self.geometry is None else self.geometry[0] * self.geometry[1] * 3)
        return (self.counts['video_pair'] < B['VIDEO_SLOTS']
            and self.bytes['video_pair'] + size <= B['VIDEO_BYTES']
            and self.counts['audio_block'] < B['AUDIO_SLOTS']
            and self.bytes['audio_block'] + PLAY['PCM']['PCM_BYTES'] <= B['AUDIO_SLOTS'] * PLAY['PCM']['PCM_BYTES'])

    def record_credit(self) -> None:
        for kind in self.counts:
            self.peak_credit_counts[kind] = max(self.peak_credit_counts[kind],
                self.counts[kind] + int(kind in self.reservation))
            self.peak_credit_bytes[kind] = max(self.peak_credit_bytes[kind],
                self.bytes[kind] + self.reservation.get(kind, 0))

    def poll_input(self) -> tuple[bool, Any, int]:
        if not self.reservation:
            if not self.can_pull():
                return False, None, 0
            self.reservation = dict(video_pair=self.unknown_size(), audio_block=PLAY['PCM']['PCM_BYTES'])
            self.record_credit()
            self.pull_started_ns = time.monotonic_ns()
            self.pull.request()
            return True, None, 0
        started = self.pull_started_ns
        assert started is not None
        try:
            ready, value = self.pull.poll()
        except StopIteration:
            self.reservation.clear()
            self.source_end = True
            return True, None, 0
        if not ready:
            return False, None, 0  # Pending input is neither source EOF nor credit.
        event, payload = value
        size = sum(len(part) for part in payload)
        if event['kind'] not in self.reservation or size > self.reservation[event['kind']]:
            raise ValueError('prepared event exceeds reserved unknown-input credit')
        return True, value, started

    def pump(self, *, startup: bool = False) -> bool:
        if self.harvest_preparation():
            return True  # Dispatch newly ready heads before another decode pull.
        if self.source_end or (self.pull is None and not startup and not self.can_pull()):
            return False
        if self.pull is not None:
            progressed, value, started = self.poll_input()
            if value is None:
                return progressed
            event, payload = value
        else:
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
        self.reservation.clear()  # Conversion completed; failed acceptance retains the reservation.
        self.record_credit()
        timing = dict(id=name, kind=kind, pull_ns=pulled - started,
            pull_started_ns=started, pull_returned_ns=pulled)
        timing['status'] = 'failed'
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
            timing['status'] = 'prepared'
        finally:
            self.preparing = None
            if name not in self.pending:
                self.record_timing(timing, primary=timing['status'] == 'failed')
        return True

    def prefill(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while not all(self.queues.values()):
            check_stop(self.stop)
            # Legacy synchronous startup can inspect the other head at a full
            # first track. Pending unknown input must reserve both possibilities.
            progressed = self.pump(startup=True)
            check_stop(self.stop)
            if self.source_end:
                raise ValueError('source ended before both output heads')
            if not progressed:
                if self.pull is None or (not self.reservation and not self.can_pull()):
                    raise ValueError('initial track interleave exceeds bounded lookahead; no output started')
                time.sleep(PLAY['POLL'])
            if time.monotonic() > deadline:
                raise ValueError('online output prefill deadline exceeded')
        while True:
            check_stop(self.stop)
            if not self.pump():
                break
            check_stop(self.stop)
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
                self.record_timing(timing, primary=True)  # Finish cleanup even if diagnostic admission fails.
                del self.pending[name]
        try:
            if self.pull is not None:
                self.pull.close(self.join_timeout)
                self.reservation.clear()
            else:
                self.iterator.close()
        except Exception as error:
            errors.append(str(error))
        self.abandoned = list(self.owned)
        for name in list(self.owned):
            try:
                self.release(name)
            except Exception as error:
                errors.append(str(error))
        for queue in self.queues.values():
            queue.clear()
        if errors or self.diagnostic_errors:
            raise ValueError('online preparation cleanup failed: ' + '; '.join(errors)
                + f' (diagnostic failures: {self.diagnostic_errors})')

    def result(self) -> dict[str, Any]:
        report = dict(verified_prepared_source_end=self.source_end, offered=dict(self.offered),
            owned_counts=dict(self.counts), owned_bytes=dict(self.bytes),
            peak_owned_counts=dict(self.peak_counts), peak_owned_bytes=dict(self.peak_bytes),
            queued={kind: list(q) for kind, q in self.queues.items()},
            owned_ids=list(self.owned), abandoned=list(self.abandoned), preparing=self.preparing,
            preparation_timings=list(self.timings), pending_preparation=list(self.pending),
            preparation_workers=1 if self.preparation_executor is not None else 0,
            canonical_scratch_byte_limit=HASH_SCRATCH_BYTES,
            pending_input=self.pull is not None,
            input_reservation=dict(self.reservation),
            peak_credit_counts=dict(self.peak_credit_counts), peak_credit_bytes=dict(self.peak_credit_bytes),
            source_pull=None if self.pull is None else self.pull.result())
        if self.diagnostic_tail is not None:
            report['preparation_audit'] = dict(**self.timings.result(),
                error_count=self.diagnostic_errors, last_error_type=self.diagnostic_error_type)
        return report


Parent: Any = B['Scheduler']


class Scheduler(Parent):
    """Reuse acknowledgement/abort lease handling, not the recorded timeline plan."""

    def __init__(self, assets: Assets, timeout: float, max_late_ms: int, *, span_limit: int = 60, **kwargs: Any) -> None:
        ONLINE['validate_span_limit'](span_limit, 'source-sequence')
        self.span_limit = span_limit
        super().__init__(dict(events=[]), timeout, max_late_ms, assets, **kwargs)
        if assets.diagnostic_tail is not None:
            self.actions = AUDIT['Actions'](assets.diagnostic_tail)
        self.latest: int | None = None

    def dispatch(self, assets: Assets, backends: dict[str, Any], executor: Any) -> None:
        for kind in assets.queues:
            check_stop(assets.stop)
            event = assets.head(kind)
            if event is None:
                continue
            target = self.target(event)
            now = self.check_late(target)
            if kind in self.jobs or now < target:
                continue
            data = assets.load(event)
            self.check_late(target)
            check_stop(assets.stop)
            action = dict(kind='output_call_submitted', track=kind, id=PLAY['identity'](event),
                source_at=event['at'], target_monotonic_ns=target, bytes=len(data))
            self.actions.append(action)
            self.active[kind] = event
            self.jobs[kind] = executor.submit(self.call, event, data, backends[kind], action)
            self.positions[kind] += 1
            self.latest = target if self.latest is None else max(self.latest, target)

    def run(self, assets: Assets, video: Any, audio: Any, executor: Any) -> None:
        self.anchor = self.clock()
        if assets.diagnostic_tail is not None:
            self.actions.set_media_anchor(self.anchor)
        backends = dict(video_pair=video, audio_block=audio)
        end = self.anchor + int((self.span_limit + self.timeout) * 1e9)
        while not assets.source_end or assets.pending or self.jobs or any(assets.queues.values()):
            check_stop(assets.stop)
            self.harvest()
            if self.cancel.is_set() or self.clock() > end:
                raise ValueError('online output cancelled or session deadline exceeded')
            for backend in backends.values():
                backend.alive()
            self.dispatch(assets, backends, executor)
            prepared = assets.pump()
            check_stop(assets.stop)
            self.harvest()
            self.dispatch(assets, backends, executor)
            if assets.source_end and not assets.pending and not any(assets.queues.values()) and self.latest is not None:
                end = min(end, self.latest + int(self.timeout * 1e9))
            if not prepared:
                self.pause(PLAY['POLL'])
        if self.clock() > end:
            raise ValueError('online output session deadline exceeded')
        check_stop(assets.stop)
        audio.finish(self.timeout)
        check_stop(assets.stop)
        video.finish(self.timeout)
        check_stop(assets.stop)
        self.finished = True

    def result(self) -> dict[str, Any]:
        report = super().result()
        if self.assets.diagnostic_tail is not None:
            report['action_audit'] = self.actions.result()
            report['actions'] = self.actions.tail()
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


def validate_output(args: Any) -> None:
    B['validate_transport'](args)
    if args.container != 'mpeg':
        raise ValueError('online output profile requires MPEG-PS')


def validate_control(pending_input: bool, stop: Event | None, diagnostic_tail: int | None) -> None:
    AUDIT['validate_tail'](diagnostic_tail)
    if diagnostic_tail is not None and not pending_input:
        raise ValueError('bounded diagnostics requires opt-in pending input')
    if stop is not None and (not pending_input or not isinstance(stop, Event)):
        raise ValueError('stop requires an Event and opt-in pending input')


def save_video_identity(receipt: dict[str, Any], video: Any, presented: int, mode: str, pair_limit: int) -> None:
    if mode != 'source-sequence':
        return
    audit = video.identity_receipt
    CHANNEL['verify_identity_audit'](audit, presented, pair_limit)
    receipt['video_identity_audit'] = dict(audit)


def video_options(receipt: dict[str, Any], title: str | None, mode: str, pair_limit: int, diagnostic_tail: int | None) -> dict[str, str]:
    CHANNEL['validate_pair_limit'](pair_limit, mode)
    if pair_limit > PLAY['MAX_PAIRS'] and diagnostic_tail is None:
        raise ValueError('larger finite output budgets require a bounded diagnostic tail')
    receipt.pop('pair_limit', None)
    if pair_limit != PLAY['MAX_PAIRS']:
        receipt['pair_limit'] = pair_limit
    receipt.pop('video_identity_audit', None)
    receipt.pop('video_identity_mode', None)
    options = {} if title is None else dict(title=title)
    if mode == 'source-sequence':
        receipt['video_identity_mode'] = mode
        options['identity_mode'] = mode
    return options


def bind_span(receipt: dict[str, Any], limit: int, mode: str, pending: bool, tail: int | None) -> None:
    ONLINE['validate_span_limit'](limit, mode)
    if limit != PLAY['MAX_SPAN']:
        if tail is None or not pending:
            raise ValueError('expanded output span requires pending input and bounded diagnostics')
        receipt['source_span_limit_seconds'] = limit


def play_prepared(events: Any, args: Any, receipt: dict[str, Any], *, title: str | None = None,  # noqa: PLR0915
                  pending_input: bool = False, stop: Event | None = None, diagnostic_tail: int | None = None,
                  video_identity_mode: str = 'full-history', pair_limit: int = 300, span_limit: int = 60) -> None:
    """Own prepared input/output; opt-in events is a caller-retained pristine pull.

    The caller validates transport first. With pending_input, it must retain the
    pull owner and rejoin after a cleanup timeout, never close its nested source.
    """
    validate_control(pending_input, stop, diagnostic_tail)
    bind_span(receipt, span_limit, video_identity_mode, pending_input, diagnostic_tail)
    options = video_options(receipt, title, video_identity_mode, pair_limit, diagnostic_tail)
    if pending_input:
        validate_pending_source(events, args.deadline)  # Invalid owners remain unclaimed.
    assets = scheduler = executor = video = audio = None
    primary = False
    receipt.update(output_devices_opened=False, backend_initialization_started=False,
        **({} if diagnostic_tail is None else dict(profile='bounded-prepared-tail-host-submissions-v1')))
    try:
        check_stop(stop)
        assets = Assets(events, pending_input=True, join_timeout=args.deadline, stop=stop, diagnostic_tail=diagnostic_tail) if pending_input else Assets(events)
        assets.prefill(args.deadline)
        assert assets.geometry is not None
        check_stop(stop)
        receipt['backend_initialization_started'] = True
        video = CHANNEL['Output'](assets.geometry[0] * 2, assets.geometry[1], args.deadline, pair_limit, **options)
        receipt.update(video_driver=video.driver, output_devices_opened=True)
        check_stop(stop)
        audio = PLAY['PCM']['Ffplay'](channel_args=('-ch_layout', 'mono') if args.mono_option == 'ch-layout'
            else ('-channels', '1'), immediate_raw_probe=True)
        check_stop(stop)
        executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='online-av-output')
        assets.start_preparation()
        scheduler = Scheduler(assets, args.deadline, args.max_late_ms,
            **({} if span_limit == PLAY['MAX_SPAN'] else dict(span_limit=span_limit)))
        scheduler.run(assets, video, audio, executor)
        save_video_identity(receipt, video, scheduler.completed['video_pair'], video_identity_mode, pair_limit)
    except BaseException:
        primary = True
        raise
    finally:
        try:
            try:
                cleanup(assets, scheduler, executor, (video, audio), receipt, primary)
            finally:
                if assets is None:
                    try:
                        if pending_input:
                            events.close(args.deadline)
                        else:
                            close = getattr(events, 'close', None)
                            if close is not None:
                                close()
                    except Exception as error:
                        receipt.setdefault('cleanup_errors', []).append(str(error))
                        if not primary:
                            raise
        finally:
            receipt['stop_requested'] = stop is not None and stop.is_set()


def playback(args: Any, receipt: dict[str, Any]) -> None:
    validate_output(args)
    decode: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    source = ONLINE['CHUNKED']['iter_chunks'](ONLINE['CHUNKED']['file_chunks'](args.source, 32768),
        'mpeg', (args.primary_stream, args.secondary_stream), args.audio_stream, decode, startup='bounded-mpeg')
    events = ONLINE['iter_online'](source, (args.primary_stream, args.secondary_stream), args.audio_stream,
        policy, policy=args.audio_overlap_policy, overlap_ms=args.max_audio_overlap_ms, phase_ms=args.max_audio_phase_ms)
    try:
        play_prepared(events, args, receipt)
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
