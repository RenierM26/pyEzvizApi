"""Explicit finite LAN profiles; never infer larger limits from untrusted files."""
from __future__ import annotations

from typing import Any

DEFAULT = 'prefix-30s'
NAMES = (DEFAULT, 'two-minute')


def get(name: str = DEFAULT) -> dict[str, Any]:
    if type(name) is not str or name not in NAMES:
        raise ValueError('unknown finite LAN capture profile')
    extended = name == 'two-minute'
    return dict(name=name,
        limits=dict(duration_seconds=120 if extended else 30,
            max_packets=60000 if extended else 15000, max_bytes=(128 if extended else 32) * 1024 * 1024),
        options=dict(diagnostic_tail=2, identity_mode='source-sequence', decoder_deadline_mode='consumer-excluding',
            pair_limit=3000 if extended else 900, byte_limit=(128 if extended else 32) * 1024 * 1024,
            **(dict(seconds_limit=150, span_limit=120) if extended else {})),
        worker_seconds=210 if extended else 70,
        verify_seconds=180 if extended else 70,
        evidence=dict(max_packets=60000 if extended else 15000,
            max_bytes=(128 if extended else 32) * 1024 * 1024,
            max_index=(12 if extended else 3) * 1024 * 1024,
            profile='encrypted-lan-packets-120s-v1' if extended else 'encrypted-lan-packets-v1'))


def bind(report: dict[str, Any], name: str) -> None:
    get(name)
    report.pop('capture_profile', None)
    if name != DEFAULT:
        report['capture_profile'] = name
