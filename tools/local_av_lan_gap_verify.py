"""Offline independent API-media projection; no output or transport objects."""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from typing import Any

PROFILE = 'scheduled-whole-block-pcm-gap-output-v1'


def canonical(row: Any) -> bytes:
    return json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'


class GapChain:
    """Reconstruct source and synthetic-padding hashes/targets without a writer."""

    def __init__(self, anchor: int, origin: dict[str, int]) -> None:
        self.anchor = anchor
        self.origin = Fraction(origin['numerator'], origin['denominator'])
        self.count = dict(source=0, padding=0)
        self.bytes = dict(self.count)
        self.hashes = {k: hashlib.sha256((PROFILE + '\n' + k + '\n').encode()) for k in self.count}

    def target(self, at: dict[str, int]) -> int:
        offset = (Fraction(at['numerator'], at['denominator']) - self.origin) * 1000000000
        return self.anchor + offset.numerator // offset.denominator

    def add(self, kind: str, row: dict[str, Any]) -> None:
        self.hashes[kind].update(canonical(row))
        self.count[kind] += 1
        self.bytes[kind] += row['bytes']

    def offer(self, event: dict[str, Any], payload: tuple[bytes, ...]) -> None:
        # Events are independently decoded and admitted by the offline policy,
        # not taken from the live receipt or passed to any output implementation.
        meta = event['block']
        at = Fraction(meta['source_pts'] * meta['time_base_num'], meta['time_base_den'])
        source_time = dict(numerator=at.numerator, denominator=at.denominator)
        digest = hashlib.sha256(payload[0]).hexdigest()
        source = {key: meta[key] for key in ('id', 'stream_index', 'source_pts', 'time_base_num',
            'time_base_den', 'samples', 'pcm_sha256')}
        source['bytes'] = len(payload[0])
        if source['pcm_sha256'] != digest or self.origin + Fraction(event['at']['numerator'], event['at']['denominator']) != at:
            raise ValueError('offline gap source payload/origin mismatch')
        pad = event['audio_gap_plan']['planned_padding']
        if pad is not None:
            if type(pad['blocks']) is not int or not 1 <= pad['blocks'] <= 4:
                raise ValueError('offline padding block bound')
            size = pad['blocks'] * 2048
            zeros = bytes(size)
            if pad['bytes'] != size or hashlib.sha256(zeros).hexdigest() != pad['pcm_sha256']:
                raise ValueError('offline padding fingerprint mismatch')
            self.add('padding', dict(id=meta['id'] + ':padding', source_time=pad['source_start'],
                target_monotonic_ns=self.target(pad['source_start']), bytes=size,
                payload_sha256=hashlib.sha256(zeros).hexdigest(), samples=pad['blocks'] * 1024, duration=pad['duration']))
        self.add('source', dict(id=meta['id'], source_time=source_time,
            target_monotonic_ns=self.target(source_time), bytes=len(payload[0]), payload_sha256=digest, source=source))

    def verify(self, receipt: dict[str, Any]) -> None:
        for key, expected in [('completed', self.count), ('submitted', self.count), ('api_bytes', self.bytes),
                ('media_sha256', {k: v.hexdigest() for k, v in self.hashes.items()})]:
            if canonical(receipt.get(key)) != canonical(expected):
                raise ValueError('full source/padding API-media chain mismatch')
