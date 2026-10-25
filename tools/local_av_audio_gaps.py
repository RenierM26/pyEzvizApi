"""Offline whole-block PCM gap planning, NOT an enabled playback policy.

A returned decision authorizes no IO. A future output adapter must schedule and
acknowledge separately declared padding before any live policy can use it.
Original source identities, timestamps and PCM fingerprints are never repaired.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from typing import Any

PROFILE = 'bounded-whole-block-audio-gap-plan-v1'
SAMPLES = 1024
RATE = 16000
PCM_BYTES = 2048
DURATION = Fraction(SAMPLES, RATE)
MAX_GAP_BLOCKS = 4
MAX_TOTAL_GAP_BLOCKS = 16


def integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def rational(value: Fraction) -> dict[str, int]:
    return dict(numerator=value.numerator, denominator=value.denominator)


def exact(row: Any) -> Fraction:
    if (type(row) is not dict or set(row) != {'numerator', 'denominator'}
            or not integer(row['numerator'], -(2**127), 2**127 - 1)
            or not integer(row['denominator'], 1, 2**127 - 1)):
        raise ValueError('requires a bounded canonical rational')
    stamp = Fraction(row['numerator'], row['denominator'])
    if rational(stamp) != row:
        raise ValueError('requires a canonical rational')
    return stamp


def canonical(row: Any) -> bytes:
    return json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'


class GapPlanner:
    """Transactional metadata decisions; constant retained state, no payload IO.

    All limits are explicit. Only whole 1024-sample positive gaps can be planned;
    overlap and the remaining cumulative phase must stay within 0..1 ms. A
    rejection consumes neither identity nor padding budget. This is not EOF,
    decoder/source completeness, missing-frame recovery or physical sync proof.
    """

    def __init__(self, *, max_gap_blocks: int, max_total_gap_blocks: int,
                 max_overlap_ms: int, max_phase_ms: int, max_blocks: int,
                 max_source_span_seconds: int) -> None:
        if (not integer(max_gap_blocks, 0, MAX_GAP_BLOCKS)
                or not integer(max_total_gap_blocks, max_gap_blocks, MAX_TOTAL_GAP_BLOCKS)
                or (max_gap_blocks == 0) != (max_total_gap_blocks == 0)
                or not integer(max_overlap_ms, 0, 1) or not integer(max_phase_ms, 0, 1)
                or not integer(max_blocks, 1, 10000)
                or not integer(max_source_span_seconds, 1, 120)):
            raise ValueError('requires explicit finite whole-block gap and jitter limits')
        self.limits = dict(max_gap_blocks=max_gap_blocks, max_total_gap_blocks=max_total_gap_blocks,
            max_overlap_ms=max_overlap_ms, max_phase_ms=max_phase_ms, max_blocks=max_blocks,
            max_source_span_seconds=max_source_span_seconds)
        self.count = self.padding_blocks = self.gaps = self.peak_gap = 0
        self.first: Fraction | None = None
        self.previous: Fraction | None = None
        self.stream: int | None = None
        self.worst_phase = self.worst_overlap = Fraction(0)
        self.digest = hashlib.sha256((PROFILE + '\n').encode('ascii'))

    def source(self, event: Any, payload: Any) -> tuple[dict[str, Any], Fraction, str]:
        if (type(event) is not dict or event.get('kind') != 'audio_block'
                or type(event.get('block')) is not dict or type(payload) is not tuple
                or len(payload) != 1 or type(payload[0]) is not bytes or len(payload[0]) != PCM_BYTES):
            raise ValueError('requires one immutable 2048-byte prepared audio block')
        row = event['block']
        if (not integer(row.get('stream_index'), 0, 65535)
                or not integer(row.get('source_pts'), 0, 2**63 - 1)
                or not integer(row.get('time_base_num'), 1, 2**31 - 1)
                or not integer(row.get('time_base_den'), 1, 2**31 - 1)
                or not integer(row.get('samples'), SAMPLES, SAMPLES)
                or exact(event.get('duration')) != DURATION):
            raise ValueError('unsupported source audio metadata')
        if (row.get('id') != f'aac:{row["stream_index"]}:{self.count}'
                or (self.stream is not None and row['stream_index'] != self.stream)):
            raise ValueError('requires the next canonical identity on the same audio stream')
        stamp = Fraction(row['source_pts'] * row['time_base_num'], row['time_base_den'])
        if exact(event.get('source_time')) != stamp:
            raise ValueError('source PTS and prepared timestamp disagree')
        digest = hashlib.sha256(payload[0]).hexdigest()
        if row.get('pcm_sha256') != digest:
            raise ValueError('original PCM fingerprint mismatch')
        return row, stamp, digest

    def offer(self, event: Any, payload: Any) -> dict[str, Any]:
        """Verify unchanged input, return one padding *plan*, then commit scalars."""
        row, stamp, pcm_digest = self.source(event, payload)
        if self.count >= self.limits['max_blocks']:
            raise ValueError('source block budget exceeded')
        if self.previous is not None and stamp <= self.previous:
            raise ValueError('source starts must strictly increase')
        first = stamp if self.first is None else self.first
        if stamp - first > self.limits['max_source_span_seconds']:
            raise ValueError('source span budget exceeded')
        gap = None if self.previous is None else stamp - self.previous - DURATION
        declared = event.get('gap_before')
        if ((gap is None) != (declared is None)
                or (declared is not None and exact(declared) != gap)):
            raise ValueError('source gap metadata disagrees with original PTS')
        overlap = max(Fraction(0), -gap) if gap is not None else Fraction(0)
        if overlap > Fraction(self.limits['max_overlap_ms'], 1000):
            raise ValueError('source overlap exceeds explicit jitter bound')
        serial = first + (self.count + self.padding_blocks) * DURATION
        phase = serial - stamp
        tolerance = Fraction(self.limits['max_phase_ms'], 1000)
        pad = 0
        if phase < -tolerance:
            # Nearest whole block in exact arithmetic. A tie remains far outside
            # the <=1 ms residual bound; do not round arbitrary gaps into repairs.
            deficit = -phase / DURATION
            pad = (2 * deficit.numerator + deficit.denominator) // (2 * deficit.denominator)
            if pad == 0 or abs(phase + pad * DURATION) > tolerance:
                raise ValueError('gap is not whole blocks within the explicit phase bound')
            if pad > self.limits['max_gap_blocks']:
                raise ValueError('single gap padding budget exceeded')
            if self.padding_blocks + pad > self.limits['max_total_gap_blocks']:
                raise ValueError('cumulative gap padding budget exceeded')
        residual = phase + pad * DURATION
        if abs(residual) > tolerance:
            raise ValueError('remaining cumulative source phase exceeds explicit bound')
        padding = None if pad == 0 else dict(blocks=pad, samples=pad * SAMPLES,
            bytes=pad * PCM_BYTES, source_start=rational(serial), duration=rational(pad * DURATION),
            format='s16le-mono-16000', fill='zero', pcm_sha256=hashlib.sha256(bytes(pad * PCM_BYTES)).hexdigest())
        decision = dict(profile=PROFILE, source=dict(id=row['id'], stream_index=row['stream_index'],
            source_pts=row['source_pts'], time_base_num=row['time_base_num'], time_base_den=row['time_base_den'],
            samples=SAMPLES, bytes=PCM_BYTES, pcm_sha256=pcm_digest), source_time=rational(stamp),
            source_gap_before=None if gap is None else rational(gap), planned_padding=padding,
            nominal_pcm_start_after_padding=rational(serial + pad * DURATION),
            remaining_nominal_minus_source=rational(residual))
        digest = self.digest.copy()
        digest.update(canonical(decision))
        # Everything above can reject without consuming any source or padding.
        self.first, self.previous, self.stream = first, stamp, row['stream_index']
        self.count += 1
        self.padding_blocks += pad
        self.gaps += int(pad > 0)
        self.peak_gap = max(self.peak_gap, pad)
        self.worst_phase = max(self.worst_phase, abs(residual))
        self.worst_overlap = max(self.worst_overlap, overlap)
        self.digest = digest
        return decision

    def result(self) -> dict[str, Any]:
        return dict(profile=PROFILE, limits=dict(self.limits), source_blocks_verified=self.count,
            source_pcm_bytes_verified=self.count * PCM_BYTES, audio_stream_index=self.stream,
            first_source_time=None if self.first is None else rational(self.first),
            last_source_time=None if self.previous is None else rational(self.previous),
            planned_gaps=self.gaps, planned_padding_blocks=self.padding_blocks,
            planned_padding_samples=self.padding_blocks * SAMPLES,
            planned_padding_bytes=self.padding_blocks * PCM_BYTES, peak_gap_blocks=self.peak_gap,
            maximum_remaining_absolute_phase=rational(self.worst_phase),
            maximum_source_overlap=rational(self.worst_overlap), decisions_sha256=self.digest.hexdigest(),
            retained_decisions=0, retained_pcm_bytes=0, padding_hash_scratch_byte_limit=MAX_GAP_BLOCKS * PCM_BYTES,
            plan_only=True, padding_written=False, source_targets_changed=False, source_pcm_changed=False,
            output_devices_opened=False, physical_av_sync_measured=False)
