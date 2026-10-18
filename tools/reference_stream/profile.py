"""Bounded same-clock stage timings; nested spans are not additive latency."""

from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
import math
import threading
import time
from typing import Any

LIMIT = 20_000


class Profile:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.omitted = 0
        self.lock = threading.Lock()

    @contextmanager
    def measure(self, stage: str, **fields: Any) -> Any:
        start = time.monotonic_ns()
        completed = False
        try:
            yield
            completed = True
        finally:
            row = dict(
                stage=stage,
                started_ns=start,
                completed_ns=time.monotonic_ns(),
                successful=completed,
                **fields,
            )
            with self.lock:
                if len(self.rows) < LIMIT:
                    self.rows.append(row)
                else:
                    self.omitted += 1

    def result(self) -> dict[str, Any]:
        with self.lock:
            rows, omitted = list(self.rows), self.omitted
        return dict(
            clock="host-monotonic",
            omitted=omitted,
            note="nested/overlapping spans are not additive; not cross-device latency",
            stages=summarize(rows),
            spans=rows,
        )


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["stage"]].append(row)
    result = {}
    for name, group in groups.items():
        durations = sorted((r["completed_ns"] - r["started_ns"]) / 1e6 for r in group)
        result[name] = dict(
            count=len(group),
            total_ms=sum(durations),
            max_ms=max(durations),
            p50_ms=durations[math.ceil(len(group) * 0.5) - 1],
            p95_ms=durations[math.ceil(len(group) * 0.95) - 1],
            bytes=sum(r.get("bytes", 0) for r in group),
            failed=sum(not r.get("successful", True) for r in group),
        )
    return result
