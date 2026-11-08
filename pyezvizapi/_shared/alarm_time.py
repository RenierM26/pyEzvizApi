"""Camera alarm normalization and timezone parsing."""

from __future__ import annotations

import datetime
import re as _re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MILLISECONDS_THRESHOLD = 1e11


def normalize_alarm_time(
    last_alarm: dict[str, Any], tzinfo: datetime.tzinfo
) -> tuple[datetime.datetime | None, datetime.datetime | None, str | None]:
    """Normalize EZVIZ alarm timestamps.

    Returns a tuple of:
      - alarm_dt_local: datetime in the camera's timezone (for display)
      - alarm_dt_utc: datetime in UTC (for robust delta calculation)
      - alarm_time_str: formatted 'YYYY-MM-DD HH:MM:SS' string in camera tz

    Behavior:
      - Prefer epoch fields (alarmStartTime/alarmTime). Interpret as UTC by default.
      - Reinterpret a local-clock-encoded epoch only when the companion string
        agrees with that wall clock (within 120 seconds), not merely because
        the configured offset and localized string disagree (for example DST).
      - If no epoch, fall back to parsing the string time in the camera tz.
    """
    # Prefer epoch
    epoch = last_alarm.get("alarmStartTime")
    if epoch is None:
        epoch = last_alarm.get("alarmTime")
    raw_time_str = str(last_alarm.get("alarmStartTimeStr") or last_alarm.get("alarmTimeStr") or "")

    alarm_dt_local: datetime.datetime | None = None
    alarm_dt_utc: datetime.datetime | None = None
    alarm_str: str | None = None

    now_local = datetime.datetime.now(tz=tzinfo)

    if epoch is not None:
        try:
            ts = float(epoch if not isinstance(epoch, str) else float(epoch))
            if ts > MILLISECONDS_THRESHOLD:  # milliseconds
                ts /= 1000.0
            event_utc = datetime.datetime.fromtimestamp(ts, tz=datetime.UTC)
            alarm_dt_local = event_utc.astimezone(tzinfo)
            alarm_dt_utc = event_utc

            if raw_time_str:
                raw_norm = raw_time_str.replace("Today", str(now_local.date()))
                try:
                    dt_str_local = datetime.datetime.strptime(
                        raw_norm, "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=tzinfo)
                    diff = abs((event_utc - dt_str_local.astimezone(datetime.UTC)).total_seconds())
                    if diff > 120:
                        # Preserve the legacy local-clock epoch format only with
                        # corroborating wall-clock evidence. A DST-localized
                        # string can disagree with a fixed base offset while the
                        # UTC epoch remains correct; disagreement alone is not
                        # evidence that the epoch needs reinterpretation.
                        naive_utc = datetime.datetime.fromtimestamp(ts, tz=datetime.UTC).replace(
                            tzinfo=None
                        )
                        event_local_reint = naive_utc.replace(tzinfo=tzinfo)
                        wall_clock_diff = abs((event_local_reint - dt_str_local).total_seconds())
                        if wall_clock_diff <= 120:
                            alarm_dt_local = event_local_reint
                            alarm_dt_utc = event_local_reint.astimezone(datetime.UTC)
                except ValueError:
                    # Some firmware returns malformed timestamp strings; keep the
                    # epoch-derived value and allow the normal fallback path.
                    pass

            if alarm_dt_local is not None:
                alarm_str = alarm_dt_local.strftime("%Y-%m-%d %H:%M:%S")
                return alarm_dt_local, alarm_dt_utc, alarm_str
            # If conversion failed unexpectedly, fall through to string parsing
        except (TypeError, ValueError, OverflowError, OSError):
            alarm_dt_local = None

    # Fallback to string parsing
    if raw_time_str:
        raw = raw_time_str.replace("Today", str(now_local.date()))
        try:
            alarm_dt_local = datetime.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=tzinfo
            )
            alarm_dt_utc = alarm_dt_local.astimezone(datetime.UTC)
            alarm_str = alarm_dt_local.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Leave the default empty result when neither epoch nor string parsing
            # can interpret the camera-provided alarm timestamp.
            pass

    return alarm_dt_local, alarm_dt_utc, alarm_str


def compute_motion_from_alarm(
    last_alarm: dict[str, Any], tzinfo: datetime.tzinfo, window_seconds: float = 60.0
) -> tuple[bool, float, str | None]:
    """Compute motion state and seconds-since from an alarm payload.

    Returns (active, seconds_since, last_alarm_time_str).
    - Uses UTC for delta when epoch-derived UTC is available.
    - Falls back to camera local tz deltas when only string times are present.
    - Clamps negative deltas to 0.0 and deactivates motion.
    """
    alarm_dt_local, alarm_dt_utc, alarm_str = normalize_alarm_time(last_alarm, tzinfo)
    if alarm_dt_local is None:
        return False, 0.0, None

    now_local = datetime.datetime.now(tz=tzinfo).replace(microsecond=0)
    now_utc = datetime.datetime.now(tz=datetime.UTC).replace(microsecond=0)

    delta = now_utc - alarm_dt_utc if alarm_dt_utc is not None else now_local - alarm_dt_local

    seconds = float(delta.total_seconds())
    if seconds < 0:
        return False, 0.0, alarm_str

    return seconds < window_seconds, seconds, alarm_str


def parse_timezone_value(tz_val: Any) -> datetime.tzinfo:
    """Parse EZVIZ timeZone value into a tzinfo.

    Supports:
      - IANA names like 'Europe/Paris'
      - Offsets like 'UTC+02:00', 'GMT-5', '+0530', or integers (hours/minutes/seconds)
    Falls back to the local system timezone, or UTC if unavailable.
    """
    # IANA zone name
    if isinstance(tz_val, str) and "/" in tz_val:
        try:
            return ZoneInfo(tz_val)
        except (ZoneInfoNotFoundError, ValueError):
            pass

    # Numeric offsets
    offset_minutes: int | None = None
    if isinstance(tz_val, int) and not isinstance(tz_val, bool):
        if -14 <= tz_val <= 14:
            offset_minutes = tz_val * 60
        elif -24 * 60 <= tz_val <= 24 * 60:
            offset_minutes = tz_val
        elif -24 * 3600 <= tz_val <= 24 * 3600:
            offset_minutes = int(tz_val / 60)
    elif isinstance(tz_val, str):
        s = tz_val.strip().upper().replace("UTC", "").replace("GMT", "")
        m = _re.match(r"^([+-]?)(\d{1,2})(?::?(\d{2}))?$", s)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            hours = int(m.group(2))
            minutes = int(m.group(3)) if m.group(3) else 0
            if hours < 24 and minutes < 60:
                offset_minutes = sign * (hours * 60 + minutes)

    if offset_minutes is not None and -24 * 60 < offset_minutes < 24 * 60:
        return datetime.timezone(datetime.timedelta(minutes=offset_minutes))

    # Fallbacks
    return datetime.datetime.now().astimezone().tzinfo or datetime.UTC
