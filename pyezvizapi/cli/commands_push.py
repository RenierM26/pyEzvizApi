"""commands push implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
# ruff: noqa: SLF001 -- explicit legacy hook boundary.
from __future__ import annotations

import pyezvizapi.cli.main as _owner

def _start_cli_cloud_stream(stream: _owner.Any, *, timeout: float | None, duration_seconds: float | None, monotonic: _owner.Callable[[], float]=_owner.time.monotonic) -> float | None:
    """Start a CLI VTM stream with one bounded negotiation deadline."""
    if not isinstance(stream, _owner.VtmStreamClient):
        stream.start()
        return None
    startup_seconds = timeout
    if startup_seconds is None or startup_seconds <= 0:
        startup_seconds = duration_seconds
    deadline = None if startup_seconds is None else monotonic() + startup_seconds
    stream.start(deadline=deadline, monotonic=monotonic)
    return deadline
