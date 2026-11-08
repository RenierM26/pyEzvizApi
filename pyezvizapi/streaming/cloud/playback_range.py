"""Strict UTC bounds for finite, cloud-mediated camera SD playback."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import math
import re

from pyezvizapi.exceptions import PyEzvizError

MAX_PLAYBACK_RANGE_SECONDS = 86400


def playback_range(begin_time: str, end_time: str) -> tuple[datetime, datetime]:
    """Accept native UTC selectors only; never infer a process/camera timezone."""
    values = []
    for value in (begin_time, end_time):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", value):
            raise PyEzvizError("SD playback times must be UTC YYYYMMDDTHHMMSSZ")
        try:
            values.append(datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC))
        except ValueError as error:
            raise PyEzvizError("SD playback time is not a valid UTC date/time") from error
    begin, end = values
    if not 0 < (end - begin).total_seconds() <= MAX_PLAYBACK_RANGE_SECONDS:
        raise PyEzvizError("SD playback end must follow begin by at most 24 hours")
    return begin, end


DEFAULT_PLAYBACK_MAX_BYTES = 128 * 1024 * 1024
DEFAULT_PLAYBACK_TRANSFER_TIMEOUT = 60.0


def positive_timeout(value: object, label: str) -> float:
    """Validate playback time budgets consistently before network access."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise PyEzvizError(f"SD playback {label} must be positive and finite")
    return float(value)


def playback_integer(value: object, label: str, *, minimum: int = 1) -> int:
    """Validate integer selectors/budgets without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        kind = "positive" if minimum == 1 else "nonnegative"
        raise PyEzvizError(f"SD playback {label} must be a {kind} integer")
    return value


def selected_playback_range(
    begin_time: str, end_time: str, duration_seconds: float | None = None
) -> tuple[str, float]:
    """Resolve the selected UTC end and duration for all capture entry points."""
    begin, end = playback_range(begin_time, end_time)
    if duration_seconds is not None:
        duration = positive_timeout(duration_seconds, "duration_seconds")
        if duration < (end - begin).total_seconds():
            end = begin + timedelta(seconds=duration)
        if end.microsecond:
            raise PyEzvizError("SD playback duration must select whole UTC seconds")
    return end.strftime("%Y%m%dT%H%M%SZ"), (end - begin).total_seconds()
