"""Explicit gap-output glue for the bounded capture API, not a CLI default."""
from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import runpy
from typing import Any

OUTPUT = runpy.run_path(str(Path(__file__).with_name('local_av_audio_gap_output.py')))
GAPS = OUTPUT['GAPS']
PLAN = 'audio_gap_plan'


def validate(limits: Any, policy: str, overlap: Any, phase: Any, span: int, timeout: float | None = None) -> Any:
    if limits is None:
        return None
    if type(limits) is not dict:
        raise ValueError('gap output requires explicit planner limits')
    planner = GAPS['GapPlanner'](**limits)
    if (policy != 'bounded-serial-pcm' or overlap != limits['max_overlap_ms'] or phase != limits['max_phase_ms']
            or type(overlap) is not int or type(phase) is not int
            or type(span) is not int or span != limits['max_source_span_seconds']
            or (timeout is not None and (type(timeout) not in (int, float) or not OUTPUT['MIN_TIMEOUT'] <= timeout <= 5))):
        raise ValueError('gap limits must match the explicit source policy, span and output deadline')
    return dict(planner.limits)


def restore(event: dict[str, Any]) -> dict[str, Any]:
    block = event['block']
    stamp = Fraction(block['source_pts'] * block['time_base_num'], block['time_base_den'])
    return dict(event, source_time=GAPS['rational'](stamp))


def origin(event: dict[str, Any]) -> Fraction:
    row = event['block'] if event['kind'] == 'audio_block' else event['lenses'][0]
    return Fraction(row['source_pts'] * row['time_base_num'], row['time_base_den']) - GAPS['exact'](event['at'])


def charge(planner: Any, event: dict[str, Any], payload: tuple[bytes, ...]) -> int:
    """Recompute prepared padding before admitting its source/padding credit."""
    decision = planner.offer(restore(event), payload)
    if GAPS['canonical'](event.get(PLAN)) != GAPS['canonical'](decision):
        raise ValueError('prepared gap decision disagrees with original source/PCM')
    pad = decision['planned_padding']
    return GAPS['PCM_BYTES'] + (0 if pad is None else pad['bytes'])


def relative_dispatch(event: dict[str, Any]) -> Fraction:
    plan = event[PLAN]
    pad = plan['planned_padding']
    return GAPS['exact'](event['at']) if pad is None else GAPS['exact'](pad['source_start']) - origin(event)


class Audio:
    """One existing executor job owns both earlier padding and original PCM."""

    def __init__(self, backend: Any, limits: dict[str, int], timeout: float, max_late_ms: int) -> None:
        self.backend, self.limits = backend, dict(limits)
        self.timeout, self.max_late_ms = timeout, max_late_ms
        self.sink: Any = None
        self.unbound_closed = False

    def bind(self, anchor: int, source_origin: Fraction, clock: Any, pause: Any) -> None:
        if self.sink is not None:
            raise ValueError('gap audio anchor must bind once')
        self.sink = OUTPUT['GapOutput'](self.backend, origin=GAPS['rational'](source_origin), anchor_ns=anchor,
            limits=self.limits, timeout=self.timeout, max_late_ms=self.max_late_ms, clock=clock, pause=pause)

    def call(self, event: dict[str, Any], data: bytes, action: dict[str, Any]) -> dict[str, Any]:
        if self.sink is None or origin(event) != self.sink.origin:
            raise ValueError('gap audio shared-origin binding mismatch')
        ack = self.sink.write(restore(event), (data,), expected_plan=event[PLAN])
        source = ack['source']
        if source['target_monotonic_ns'] != action['target_monotonic_ns']:
            raise ValueError('gap output changed the original source target')
        action.update(started_monotonic_ns=source['started_monotonic_ns'],
            submission_late_ns=source['started_monotonic_ns'] - source['target_monotonic_ns'])
        return dict(bytes=source['bytes'], pcm_sha256=source['payload_sha256'])

    def alive(self) -> None:
        self.backend.alive()

    def finish(self, timeout: float) -> None:
        if self.sink is None or timeout != self.timeout:
            raise ValueError('gap audio drain binding mismatch')
        self.sink.finish()

    def abort(self) -> None:
        if self.sink is not None:
            self.sink.abort()
        elif not self.unbound_closed:
            self.backend.abort()
            self.unbound_closed = True

    def result(self) -> dict[str, Any]:
        return (dict(state='unbound', transport_closed=self.unbound_closed) if self.sink is None
            else self.sink.result())


def verify(preparation: dict[str, Any], output: dict[str, Any], limits: Any) -> None:
    gap = output.get('gap_audio')
    if limits is None:
        if gap is not None:
            raise ValueError('gap output requires an explicit capture opt-in')
        return
    GAPS['GapPlanner'](**limits)  # Revalidate terminal limits, including strict integer types.
    def same(a: Any, b: Any) -> bool:
        return GAPS['canonical'](a) == GAPS['canonical'](b)
    policy = preparation['online']['policy']['audio_clock_contract']
    scheduler = output['scheduler']
    credit = output.get('lookahead', {})
    expected = dict(source=policy['source_blocks_verified'], padding=policy['planned_gaps'])
    if (type(gap) is not dict or gap.get('profile') != OUTPUT['PROFILE']
            or not same(gap.get('source_gap_plan'), policy) or not same(policy.get('limits'), limits)
            or not same(gap.get('shared_source_origin'), preparation['online']['policy']['origin'])
            or not same(gap.get('host_anchor_monotonic_ns'), scheduler['host_anchor_monotonic_ns'])
            or not same(gap.get('completed'), expected) or not same(gap.get('submitted'), expected)
            or expected['source'] != scheduler['completed']['audio_block']
            or not same(gap.get('api_bytes'), dict(source=expected['source'] * GAPS['PCM_BYTES'],
                padding=policy['planned_padding_bytes']))
            or any(gap.get(key) is not False for key in ('failed', 'cancelled', 'write_active'))
            or gap.get('outputs_finished') is not True or gap.get('transport_closed') is not True
            or any(gap.get(key) is not None for key in ('active_job', 'failed_job', 'last_error_type', 'abort_error_type'))
            or any(type(gap.get(key)) is not int or gap[key] != 0 for key in ('owned_source_bytes', 'owned_padding_bytes'))
            or type(gap.get('peak_owned_bytes')) is not int
            or not GAPS['PCM_BYTES'] <= gap['peak_owned_bytes'] <= (1 + limits['max_gap_blocks']) * GAPS['PCM_BYTES']
            or not same(gap.get('source_byte_limit'), GAPS['PCM_BYTES'])
            or not same(gap.get('padding_byte_limit'), limits['max_gap_blocks'] * GAPS['PCM_BYTES'])
            or not same(credit.get('audio_gap_limits'), limits) or credit.get('input_reservation') != {}
            or not same(credit.get('audio_unknown_reservation_bytes'), (1 + limits['max_gap_blocks']) * GAPS['PCM_BYTES'])
            or not same(credit.get('owned_padding_credit_bytes'), 0)
            or type(credit.get('peak_credit_bytes', {}).get('audio_block')) is not int
            or not 0 < credit['peak_credit_bytes']['audio_block'] <= 65536):
        raise ValueError('gap source/padding output terminal binding failed')
