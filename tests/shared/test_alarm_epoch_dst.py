"""Localized strings must not shift a correct UTC epoch around DST."""

import datetime as dt
from zoneinfo import ZoneInfo

import pytest

from pyezvizapi._shared import alarm_time


@pytest.mark.parametrize(
    "epoch_key,string_key", [("alarmStartTime", "alarmStartTimeStr"), ("alarmTime", "alarmTimeStr")]
)
@pytest.mark.parametrize("milliseconds", [False, True])
@pytest.mark.parametrize("zone,base_offset", [("Europe/Rome", 1), ("America/New_York", -5)])
def test_correct_epoch_preserved_when_string_uses_dst_but_offset_does_not(
    epoch_key, string_key, milliseconds, zone, base_offset
):
    event = dt.datetime(2026, 7, 1, 7, 45, 39, tzinfo=dt.UTC)
    localized = event.astimezone(ZoneInfo(zone)).strftime("%Y-%m-%d %H:%M:%S")
    value = event.timestamp() * (1000 if milliseconds else 1)
    tz = dt.timezone(dt.timedelta(hours=base_offset))
    local, utc, display = alarm_time.normalize_alarm_time(
        {epoch_key: str(value), string_key: localized}, tz
    )
    assert utc == event
    assert local == event.astimezone(tz)
    assert display == event.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")


def test_motion_is_active_at_event_not_shifted_one_hour(monkeypatch):
    event = dt.datetime(2026, 7, 1, 7, 45, 39, tzinfo=dt.UTC)

    class Clock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            value = event + dt.timedelta(seconds=10)
            return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(alarm_time.datetime, "datetime", Clock)
    active, seconds, _ = alarm_time.compute_motion_from_alarm(
        {"alarmStartTime": event.timestamp(), "alarmStartTimeStr": "2026-07-01 09:45:39"},
        dt.timezone(dt.timedelta(hours=1)),
    )
    assert active is True
    assert seconds == 10


@pytest.mark.parametrize("offset", [2, -5])
def test_local_clock_encoded_epoch_still_requires_corroborating_string(offset):
    encoded = dt.datetime(2026, 7, 1, 10, 0, tzinfo=dt.UTC)
    tz = dt.timezone(dt.timedelta(hours=offset))
    _, utc, _ = alarm_time.normalize_alarm_time(
        {"alarmTime": encoded.timestamp(), "alarmTimeStr": "2026-07-01 10:00:00"}, tz
    )
    assert utc == dt.datetime(2026, 7, 1, 10, 0, tzinfo=tz).astimezone(dt.UTC)


def test_unrelated_stale_string_cannot_override_epoch():
    event = dt.datetime(2026, 7, 1, 7, 45, 39, tzinfo=dt.UTC)
    _, utc, _ = alarm_time.normalize_alarm_time(
        {"alarmTime": event.timestamp(), "alarmTimeStr": "2026-06-30 21:12:00"},
        dt.timezone(dt.timedelta(hours=2)),
    )
    assert utc == event


def test_string_only_fixed_offset_cannot_infer_a_dst_zone():
    # No epoch or IANA zone: preserve explicit offset semantics, never guess
    # geography/DST from the HA host or the current event age.
    _, utc, _ = alarm_time.normalize_alarm_time(
        {"alarmTimeStr": "2026-07-01 09:45:39"},
        dt.timezone(dt.timedelta(hours=1)),
    )
    assert utc == dt.datetime(2026, 7, 1, 8, 45, 39, tzinfo=dt.UTC)
