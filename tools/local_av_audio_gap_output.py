"""Opt-in single-owner PCM gap output; not connected to live A/V playback.

A caller supplies the shared source origin/host anchor and an already opened,
nonblocking PCM backend. Padding has its own target and acknowledgement; it is
never prepended at the later original-block target. API writes are not acoustic
presentation. The caller must join its writing thread before declaring cleanup.
"""
from __future__ import annotations

import copy
import hashlib
import math
from pathlib import Path
import runpy
from threading import Event, Lock
import time
from typing import Any

GAPS = runpy.run_path(str(Path(__file__).with_name('local_av_audio_gaps.py')))
PROFILE = 'scheduled-whole-block-pcm-gap-output-v1'
POLL = 0.005
MIN_TIMEOUT = 0.1


class GapOutput:
    """Own one source block plus bounded padding through synchronous API writes."""

    def __init__(self, backend: Any, *, origin: dict[str, int], anchor_ns: int,
                 limits: dict[str, int], timeout: float, max_late_ms: int,
                 clock: Any = time.monotonic_ns, pause: Any = time.sleep) -> None:
        source_origin = GAPS['exact'](origin)
        if (source_origin < 0 or not GAPS['integer'](anchor_ns, 1, 2**63 - 1)
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not MIN_TIMEOUT <= timeout <= 5
                or not GAPS['integer'](max_late_ms, 0, 250) or type(limits) is not dict
                or any(not callable(getattr(backend, name, None)) for name in ('write', 'alive', 'finish', 'abort'))
                or not callable(clock) or not callable(pause)):
            raise ValueError('invalid explicit gap output contract')
        planner = GAPS['GapPlanner'](**limits)
        self.backend, self.planner = backend, planner
        self.origin, self.anchor = source_origin, anchor_ns
        self.timeout, self.max_late_ns = float(timeout), max_late_ms * 1000000
        self.clock, self.pause = clock, pause
        self.gate, self.abort_gate, self.stop = Lock(), Lock(), Event()
        self.finished = self.failed = self.aborted = self.transport_closed = self.writing = False
        self.owned_source = self.owned_padding = self.peak_owned = 0
        self.submitted = dict(source=0, padding=0)
        self.completed = dict(self.submitted)
        self.api_bytes = dict(self.submitted)
        self.chains = {k: hashlib.sha256((PROFILE + '\n' + k + '\n').encode('ascii')) for k in self.submitted}
        self.active: dict[str, Any] | None = None
        self.failed_job: dict[str, Any] | None = None
        self.last_error_type: str | None = None
        self.abort_error_type: str | None = None
        self.partial = self.peak_late_ns = self.abort_attempts = 0

    def check_stop(self) -> None:
        if self.stop.is_set():
            raise InterruptedError('PCM gap output cancelled')

    def target(self, stamp: Any) -> int:
        at = GAPS['exact'](stamp) - self.origin
        if at < 0:
            raise ValueError('source or padding precedes the shared source origin')
        offset = at * 1000000000
        return self.anchor + offset.numerator // offset.denominator

    def wait_target(self, target: int) -> int:
        end = self.clock() + int(self.timeout * 1000000000)
        while True:
            self.check_stop()
            now = self.clock()
            if now >= target:
                if now - target > self.max_late_ns:
                    raise ValueError('gap output lateness limit exceeded; no rebase')
                return now
            if now >= end:
                raise TimeoutError('PCM gap output target wait deadline exceeded')
            self.pause(min(POLL, (target - now) / 1000000000))

    def job(self, kind: str, row: dict[str, Any], data: bytes) -> dict[str, Any]:
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['payload_sha256']:
            raise ValueError('gap output payload fingerprint mismatch')
        target = row['target_monotonic_ns']
        started = self.wait_target(target)
        self.active = dict(row, kind=kind)
        self.partial = 0
        self.submitted[kind] += 1
        self.peak_late_ns = max(self.peak_late_ns, started - target)
        end = started + int(self.timeout * 1000000000)
        view = memoryview(data)
        while self.partial < len(data):
            self.check_stop()
            if self.clock() >= end:
                raise TimeoutError('PCM gap output write deadline exceeded')
            self.backend.alive()
            try:
                count = self.backend.write(view[self.partial:])
            except BlockingIOError:
                self.pause(POLL)
                continue
            if type(count) is not int or not 0 < count <= len(data) - self.partial:
                raise ValueError('invalid PCM gap output write progress')
            self.partial += count
        self.check_stop()
        if self.clock() >= end:
            raise TimeoutError('PCM gap output write deadline exceeded')
        self.chains[kind].update(GAPS['canonical'](row))
        self.completed[kind] += 1
        self.api_bytes[kind] += len(data)
        self.active = None
        self.partial = 0
        return dict(row, started_monotonic_ns=started, completed_monotonic_ns=self.clock())

    def _abort_transport_locked(self) -> None:
        """Caller holds abort_gate through transport ownership changes."""
        if self.transport_closed:
            return
        self.aborted = True
        self.abort_attempts += 1
        try:
            self.backend.abort()
            self.transport_closed = True
        except Exception as error:
            self.abort_error_type = type(error).__name__

    def abort_transport(self) -> None:
        with self.abort_gate:
            self._abort_transport_locked()

    def write(self, event: dict[str, Any], payload: tuple[bytes, ...]) -> dict[str, Any]:
        """Call before the earliest target; retain credit until both jobs return.

        There is no executor backlog. Concurrent offers/finish are rejected;
        abort may be called from another thread but does not release its payload.
        """
        if not self.gate.acquire(blocking=False):
            raise ValueError('one gap output operation is already active')
        if self.failed or self.finished or self.stop.is_set():
            self.gate.release()
            raise ValueError('gap output is terminal')
        try:
            self.writing = True
            # Validate the shared-origin relationship before planner admission.
            self.target(event.get('source_time'))
            decision = self.planner.offer(event, payload)
            self.owned_source = GAPS['PCM_BYTES']
            self.peak_owned = max(self.peak_owned, self.owned_source)
            padding_ack = None
            padding = decision['planned_padding']
            if padding is not None:
                self.owned_padding = padding['bytes']
                self.peak_owned = max(self.peak_owned, self.owned_source + self.owned_padding)
                data = bytes(self.owned_padding)
                row = dict(id=decision['source']['id'] + ':padding', source_time=padding['source_start'],
                    target_monotonic_ns=self.target(padding['source_start']), bytes=padding['bytes'],
                    payload_sha256=padding['pcm_sha256'], samples=padding['samples'], duration=padding['duration'])
                padding_ack = self.job('padding', row, data)
                del data
                self.owned_padding = 0
            row = dict(id=decision['source']['id'], source_time=decision['source_time'],
                target_monotonic_ns=self.target(decision['source_time']), bytes=decision['source']['bytes'],
                payload_sha256=decision['source']['pcm_sha256'], source=decision['source'])
            source_ack = self.job('source', row, payload[0])
            return dict(source=source_ack, padding=padding_ack)
        except BaseException as error:
            # This is the owned output boundary: cancellation/KeyboardInterrupt
            # must abort the backend too, while the original exception propagates.
            self.failed = True
            self.last_error_type = type(error).__name__
            if self.active is not None:
                self.failed_job = dict(self.active, partial_bytes=self.partial)
            self.abort_transport()
            raise
        finally:
            self.active = None
            self.owned_source = self.owned_padding = 0
            self.writing = False
            self.gate.release()

    def finish(self) -> None:
        if not self.gate.acquire(blocking=False):
            raise ValueError('one gap output operation is already active')
        if self.failed or self.finished or self.stop.is_set() or self.completed['source'] == 0:
            self.gate.release()
            raise ValueError('gap output cannot finish')
        try:
            self.backend.finish(self.timeout)
            # Linearize drain completion against abort: a backend can return
            # normally after abort discarded its pending bytes. Only a finish
            # that commits before cancellation may claim a completed drain.
            with self.abort_gate:
                self.check_stop()
                self.finished = self.transport_closed = True
        except BaseException as error:
            self.failed = True
            self.last_error_type = type(error).__name__
            self.abort_transport()
            raise
        finally:
            self.gate.release()

    def abort(self) -> None:
        with self.abort_gate:
            if self.finished:
                return
            self.stop.set()
            self._abort_transport_locked()
        # Only the returning writer can release its source/padding ownership.

    def result(self) -> dict[str, Any]:
        return dict(profile=PROFILE, shared_source_origin=GAPS['rational'](self.origin),
            host_anchor_monotonic_ns=self.anchor, timeout_seconds=self.timeout,
            max_late_ns=self.max_late_ns, source_gap_plan=self.planner.result(),
            submitted=dict(self.submitted), completed=dict(self.completed), api_bytes=dict(self.api_bytes),
            media_sha256={k: v.hexdigest() for k, v in self.chains.items()},
            write_active=self.writing, active_job=copy.deepcopy(self.active),
            failed_job=copy.deepcopy(self.failed_job),
            owned_source_bytes=self.owned_source, owned_padding_bytes=self.owned_padding,
            peak_owned_bytes=self.peak_owned, source_byte_limit=GAPS['PCM_BYTES'],
            padding_byte_limit=self.planner.limits['max_gap_blocks'] * GAPS['PCM_BYTES'],
            failed=self.failed, last_error_type=self.last_error_type, abort_error_type=self.abort_error_type,
            cancelled=self.stop.is_set(), backend_aborted=self.aborted, abort_attempts=self.abort_attempts,
            transport_closed=self.transport_closed,
            outputs_finished=self.finished, maximum_submission_lateness_ns=self.peak_late_ns,
            acknowledgements='complete-pipe-api-writes-not-acoustic-presentation',
            source_targets_changed=False, source_pcm_changed=False, live_policy_enabled=False,
            physical_av_sync_measured=False)
