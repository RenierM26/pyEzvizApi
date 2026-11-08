"""Strict UTC bounds for finite, cloud-mediated camera SD playback."""

from __future__ import annotations

from datetime import UTC, datetime
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
