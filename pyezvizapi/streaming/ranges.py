"""Strict UTC bounds for finite camera SD playback over either route."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
import math
import re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pyezvizapi.exceptions import PyEzvizError

MAX_PLAYBACK_RANGE_SECONDS = 86400


def playback_range(begin_time: str, end_time: str) -> tuple[datetime, datetime]:
    """Accept public UTC selections; never infer a process/camera timezone."""
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


def playback_timezone(name: str) -> tzinfo:
    """Resolve an explicit selector timezone without host-local fallbacks."""
    if not isinstance(name, str) or not name:
        raise PyEzvizError("SD playback timezone must be an explicit IANA timezone")
    if name == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise PyEzvizError("SD playback timezone is not a known IANA timezone") from error


def native_playback_range(begin_time: str, end_time: str, timezone: str = "UTC") -> tuple[str, str]:
    """Project UTC inputs into the native selector's wall clock.

    The app formats local time with a literal Z; that suffix is not a native
    UTC guarantee. Reject offset transitions and ambiguous wall times rather
    than silently selecting a different instant. The native URL carries no
    offset/fold discriminator.
    """
    begin, end = playback_range(begin_time, end_time)
    zone = playback_timezone(timezone)
    local_begin, local_end = begin.astimezone(zone), end.astimezone(zone)
    if local_begin.utcoffset() != local_end.utcoffset() or any(
        value.replace(fold=0).utcoffset() != value.replace(fold=1).utcoffset()
        for value in (local_begin, local_end)
    ):
        raise PyEzvizError("SD playback range crosses an offset change or ambiguous local time")
    return (local_begin.strftime("%Y%m%dT%H%M%SZ"), local_end.strftime("%Y%m%dT%H%M%SZ"))


def utc_stamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def record_time(value: Any, timezone: str) -> datetime:
    if not isinstance(value, str):
        raise PyEzvizError("SD catalog timestamp must be an ISO date/time string")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError as error:
        raise PyEzvizError("Invalid SD catalog date/time") from error
    if instant.microsecond:
        raise PyEzvizError("SD catalog requires whole-second timestamps")
    if instant.tzinfo is None:
        zone = playback_timezone(timezone)
        instant = instant.replace(tzinfo=zone)
        if instant.replace(fold=0).utcoffset() != instant.replace(fold=1).utcoffset():
            raise PyEzvizError("Ambiguous SD catalog local time")
        if instant.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != datetime.fromisoformat(
            value
        ):
            raise PyEzvizError("Nonexistent SD catalog local time")
    return instant.astimezone(UTC)
