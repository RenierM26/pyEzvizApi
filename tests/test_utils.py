from __future__ import annotations

import datetime as dt
from hashlib import md5
from typing import Any
from zoneinfo import ZoneInfo

from Crypto.Cipher import AES
import pytest

from pyezvizapi import utils
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.utils import (
    coerce_int,
    compute_motion_from_alarm,
    convert_to_dict,
    decode_json,
    decrypt_image,
    deep_merge,
    fetch_nested_value,
    first_nested,
    iter_nested,
    normalize_alarm_time,
    parse_timezone_value,
    return_password_hash,
    string_to_list,
)


def test_coerce_int_handles_common_api_shapes() -> None:
    assert coerce_int(True) == 1
    assert coerce_int(False) == 0
    assert coerce_int("42") == 42
    assert coerce_int(12.9) == 12
    assert coerce_int("not-a-number") is None
    assert coerce_int(None) is None


def test_decode_json_returns_none_for_invalid_strings() -> None:
    assert decode_json('{"enabled": true}') == {"enabled": True}
    assert decode_json("not json") is None
    assert decode_json({"already": "decoded"}) == {"already": "decoded"}


def test_string_to_list_only_splits_strings_with_separator() -> None:
    assert string_to_list("a,b,c") == ["a", "b", "c"]
    assert string_to_list("abc") == "abc"
    assert string_to_list(["a", "b"]) == ["a", "b"]


def test_nested_helpers_support_dicts_lists_and_wildcards() -> None:
    payload = {
        "devices": [
            {"serial": "A", "status": {"online": True}},
            {"serial": "B", "status": {"online": False}},
        ]
    }

    assert list(iter_nested(payload, ["devices", "*", "serial"])) == ["A", "B"]
    assert first_nested(payload, ["devices", 1, "status", "online"]) is False
    assert fetch_nested_value(payload, ["devices", 0, "serial"]) == "A"
    assert fetch_nested_value(payload, ["missing"], default_value="fallback") == "fallback"


def test_deep_merge_merges_dicts_and_concatenates_lists() -> None:
    merged = deep_merge(
        {"a": {"x": 1}, "items": [1], "keep": True},
        {"a": {"y": 2}, "items": [2], "replace": "new"},
    )

    assert merged == {
        "a": {"x": 1, "y": 2},
        "items": [1, 2],
        "keep": True,
        "replace": "new",
    }


def test_return_password_hash_is_stable() -> None:
    assert return_password_hash("ABCDEF") == "aa37ad52a5a65df39791a95818fb3298"


def test_parse_timezone_value_supports_offsets() -> None:
    tz = parse_timezone_value("UTC+02:30")
    assert tz.utcoffset(None) == dt.timedelta(hours=2, minutes=30)

    tz = parse_timezone_value("GMT-5")
    assert tz.utcoffset(None) == -dt.timedelta(hours=5)

    tz = parse_timezone_value(120)
    assert tz.utcoffset(None) == dt.timedelta(hours=2)


def test_normalize_alarm_time_handles_epoch_milliseconds_and_string_fallback() -> None:
    tz = dt.timezone(dt.timedelta(hours=2))
    local_dt, utc_dt, alarm_str = normalize_alarm_time(
        {"alarmStartTime": 1714212000000},
        tz,
    )

    assert local_dt == dt.datetime(2024, 4, 27, 12, 0, tzinfo=tz)
    assert utc_dt == dt.datetime(2024, 4, 27, 10, 0, tzinfo=dt.UTC)
    assert alarm_str == "2024-04-27 12:00:00"

    local_dt, utc_dt, alarm_str = normalize_alarm_time(
        {"alarmStartTimeStr": "2024-04-27 13:30:00"},
        tz,
    )

    assert local_dt == dt.datetime(2024, 4, 27, 13, 30, tzinfo=tz)
    assert utc_dt == dt.datetime(2024, 4, 27, 11, 30, tzinfo=dt.UTC)
    assert alarm_str == "2024-04-27 13:30:00"


def test_normalize_alarm_time_reinterprets_local_clock_epoch_when_string_differs() -> None:
    tz = dt.timezone(dt.timedelta(hours=2))
    local_dt, utc_dt, alarm_str = normalize_alarm_time(
        {
            "alarmStartTime": 1714212000,
            "alarmStartTimeStr": "2024-04-27 10:00:00",
        },
        tz,
    )

    assert local_dt == dt.datetime(2024, 4, 27, 10, 0, tzinfo=tz)
    assert utc_dt == dt.datetime(2024, 4, 27, 8, 0, tzinfo=dt.UTC)
    assert alarm_str == "2024-04-27 10:00:00"


def test_compute_motion_from_alarm_handles_recent_old_and_future_events(monkeypatch) -> None:
    tz = dt.UTC

    class FixedDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> Any:
            base = dt.datetime(2024, 4, 27, 10, 0, tzinfo=dt.UTC)
            return base.astimezone(tz) if tz is not None else base.replace(tzinfo=None)

    monkeypatch.setattr(utils.datetime, "datetime", FixedDateTime)

    active, seconds, alarm_str = compute_motion_from_alarm(
        {"alarmStartTime": 1714211990},
        tz,
        window_seconds=60,
    )
    assert active is True
    assert seconds == float(10)
    assert alarm_str == "2024-04-27 09:59:50"

    active, seconds, alarm_str = compute_motion_from_alarm(
        {"alarmStartTime": 1714211900},
        tz,
        window_seconds=60,
    )
    assert active is False
    assert seconds == float(100)
    assert alarm_str == "2024-04-27 09:58:20"

    active, seconds, alarm_str = compute_motion_from_alarm(
        {"alarmStartTime": 1714212010},
        tz,
        window_seconds=60,
    )
    assert active is False
    assert seconds == 0.0
    assert alarm_str == "2024-04-27 10:00:10"


def test_parse_timezone_value_supports_iana_invalid_and_second_offsets() -> None:
    johannesburg = parse_timezone_value("Africa/Johannesburg")
    assert johannesburg.utcoffset(dt.datetime(2024, 4, 27)) == dt.timedelta(hours=2)
    assert parse_timezone_value("+0530").utcoffset(None) == dt.timedelta(hours=5, minutes=30)
    assert parse_timezone_value(7200).utcoffset(None) == dt.timedelta(hours=2)
    assert parse_timezone_value("Not/AZone").utcoffset(None) is not None


def _encrypted_image_block(password: str, plaintext: bytes) -> bytes:
    password_hash = md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()
    key = str.encode(password.ljust(16, "\u0000")[:16])
    iv_code = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])
    padding = AES.block_size - (len(plaintext) % AES.block_size)
    ciphertext = AES.new(key, AES.MODE_CBC, iv_code).encrypt(
        plaintext + bytes([padding]) * padding
    )
    return HIK_ENCRYPTION_HEADER + password_hash.encode() + ciphertext


def test_decrypt_image_returns_plain_data_without_encryption_header() -> None:
    image_data = b"plain-jpeg-bytes-that-are-long-enough" * 3

    assert decrypt_image(image_data, "ABCDEF") == image_data


def test_decrypt_image_handles_valid_preamble_and_concatenated_blocks() -> None:
    first = _encrypted_image_block("ABCDEF", b"first-image")
    second = _encrypted_image_block("ABCDEF", b"second-image")

    expected = b"first-imagesecond-image"

    assert decrypt_image(b"preamble" + first + second, "ABCDEF") == expected


def test_decrypt_image_rejects_invalid_password_and_malformed_payloads() -> None:
    encrypted = _encrypted_image_block("ABCDEF", b"secret-image")

    with pytest.raises(PyEzvizError, match="Invalid password"):
        decrypt_image(encrypted, "WRONG")

    with pytest.raises(PyEzvizError, match="Invalid image data"):
        decrypt_image(b"short", "ABCDEF")

    with pytest.raises(PyEzvizError, match="Invalid image data after trimming preamble"):
        decrypt_image((b"x" * 40) + encrypted[:20], "ABCDEF")


def test_convert_to_dict_decodes_json_string_values_in_place() -> None:
    payload = {"nested": '{"enabled": true}', "invalid": "not-json", "plain": 1}

    assert convert_to_dict(payload) is payload
    assert payload == {"nested": {"enabled": True}, "invalid": "not-json", "plain": 1}
    assert convert_to_dict(["not", "a", "dict"]) == ["not", "a", "dict"]


def test_parse_timezone_value_applies_dst_for_fixed_offset(monkeypatch) -> None:
    monkeypatch.delenv("TZ", raising=False)
    summer = dt.datetime(2026, 10, 13, 7, 6, 50)
    winter = dt.datetime(2026, 12, 1, 7, 6, 50)

    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)
    assert tz.utcoffset(summer) == dt.timedelta(hours=2)
    assert tz.utcoffset(winter) == dt.timedelta(hours=1)

    # Without the DST flag the fixed offset is kept (previous behaviour).
    tz = parse_timezone_value("UTC+01:00")
    assert tz.utcoffset(summer) == dt.timedelta(hours=1)
    tz = parse_timezone_value("UTC+01:00", dst_enabled=False)
    assert tz.utcoffset(summer) == dt.timedelta(hours=1)

    # Southern hemisphere: DST in January.
    tz = parse_timezone_value("UTC+10:00", dst_enabled=True)
    assert tz.utcoffset(dt.datetime(2026, 1, 15)) == dt.timedelta(hours=11)
    assert tz.utcoffset(dt.datetime(2026, 7, 15)) == dt.timedelta(hours=10)

    # Unknown DST rules for this offset: keep the fixed offset.
    tz = parse_timezone_value("UTC+05:30", dst_enabled=True)
    assert tz.utcoffset(summer) == dt.timedelta(hours=5, minutes=30)

    # IANA names already carry their own rules.
    tz = parse_timezone_value("Africa/Johannesburg", dst_enabled=True)
    assert tz.utcoffset(summer) == dt.timedelta(hours=2)


def test_parse_timezone_value_prefers_matching_host_dst_zone(monkeypatch) -> None:
    # Host zone with the same standard offset and DST wins over the default.
    monkeypatch.setenv("TZ", "Asia/Jerusalem")
    tz = parse_timezone_value("UTC+02:00", dst_enabled=True)
    assert tz == ZoneInfo("Asia/Jerusalem")

    # Host zone with another standard offset is ignored.
    monkeypatch.setenv("TZ", "America/New_York")
    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)
    assert tz == ZoneInfo("Europe/Paris")

    # Host zone without DST is ignored.
    monkeypatch.setenv("TZ", "Africa/Lagos")
    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)
    assert tz == ZoneInfo("Europe/Paris")

    # Invalid host values are ignored.
    monkeypatch.setenv("TZ", "Not/AZone")
    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)
    assert tz == ZoneInfo("Europe/Paris")


@pytest.mark.parametrize(
    ("alarm", "expected_utc"),
    [
        # Summer (CEST, UTC+2): string only, UTC epoch, local-clock epoch.
        (
            {"alarmStartTimeStr": "2026-10-13 07:06:50"},
            dt.datetime(2026, 10, 13, 5, 6, 50, tzinfo=dt.UTC),
        ),
        (
            {
                "alarmStartTime": 1791868010000,
                "alarmStartTimeStr": "2026-10-13 07:06:50",
            },
            dt.datetime(2026, 10, 13, 5, 6, 50, tzinfo=dt.UTC),
        ),
        (
            {
                "alarmStartTime": 1791875210000,
                "alarmStartTimeStr": "2026-10-13 07:06:50",
            },
            dt.datetime(2026, 10, 13, 5, 6, 50, tzinfo=dt.UTC),
        ),
        # Winter (CET, UTC+1): string only, UTC epoch, local-clock epoch.
        (
            {"alarmStartTimeStr": "2026-12-01 07:06:50"},
            dt.datetime(2026, 12, 1, 6, 6, 50, tzinfo=dt.UTC),
        ),
        (
            {
                "alarmStartTime": 1796105210000,
                "alarmStartTimeStr": "2026-12-01 07:06:50",
            },
            dt.datetime(2026, 12, 1, 6, 6, 50, tzinfo=dt.UTC),
        ),
        (
            {
                "alarmStartTime": 1796108810000,
                "alarmStartTimeStr": "2026-12-01 07:06:50",
            },
            dt.datetime(2026, 12, 1, 6, 6, 50, tzinfo=dt.UTC),
        ),
    ],
)
def test_normalize_alarm_time_with_dst_enabled_fixed_offset(
    monkeypatch, alarm: dict[str, Any], expected_utc: dt.datetime
) -> None:
    monkeypatch.delenv("TZ", raising=False)
    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)

    local_dt, utc_dt, alarm_str = normalize_alarm_time(alarm, tz)

    assert utc_dt == expected_utc
    assert local_dt is not None
    assert local_dt.utcoffset() == expected_utc.astimezone(tz).utcoffset()
    assert alarm_str == alarm["alarmStartTimeStr"]


def test_compute_motion_from_alarm_is_active_on_time_during_dst(monkeypatch) -> None:
    monkeypatch.delenv("TZ", raising=False)

    class FixedDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> Any:
            base = dt.datetime(2026, 10, 13, 5, 7, 0, tzinfo=dt.UTC)
            return base.astimezone(tz) if tz is not None else base.replace(tzinfo=None)

    alarm = {"alarmStartTimeStr": "2026-10-13 07:06:50"}
    dst_tz = parse_timezone_value("UTC+01:00", dst_enabled=True)
    fixed_tz = parse_timezone_value("UTC+01:00")
    monkeypatch.setattr(utils.datetime, "datetime", FixedDateTime)

    assert compute_motion_from_alarm(alarm, dst_tz) == (
        True,
        10.0,
        "2026-10-13 07:06:50",
    )
    # A fixed +01:00 offset places the event one hour in the future.
    assert compute_motion_from_alarm(alarm, fixed_tz) == (
        False,
        0.0,
        "2026-10-13 07:06:50",
    )


def test_parse_timezone_value_skips_ambiguous_hemisphere_offsets(monkeypatch) -> None:
    # UTC-04:00 is shared by Atlantic Canada and Chile with opposite seasons.
    monkeypatch.delenv("TZ", raising=False)
    tz = parse_timezone_value("UTC-04:00", dst_enabled=True)
    assert tz.utcoffset(dt.datetime(2026, 1, 15)) == -dt.timedelta(hours=4)
    assert tz.utcoffset(dt.datetime(2026, 7, 15)) == -dt.timedelta(hours=4)

    monkeypatch.setenv("TZ", "America/Santiago")
    tz = parse_timezone_value("UTC-04:00", dst_enabled=True)
    assert tz == ZoneInfo("America/Santiago")

    # UTC-06:00 is shared by the US Central zone and Easter Island.
    monkeypatch.delenv("TZ", raising=False)
    tz = parse_timezone_value("UTC-06:00", dst_enabled=True)
    assert tz.utcoffset(dt.datetime(2026, 1, 15)) == -dt.timedelta(hours=6)
    assert tz.utcoffset(dt.datetime(2026, 7, 15)) == -dt.timedelta(hours=6)

    monkeypatch.setenv("TZ", "America/Chicago")
    tz = parse_timezone_value("UTC-06:00", dst_enabled=True)
    assert tz == ZoneInfo("America/Chicago")


def test_parse_timezone_value_detects_short_host_dst_periods(monkeypatch) -> None:
    # Morocco is UTC+01:00 most of the year and UTC+00:00 around Ramadan.
    monkeypatch.setenv("TZ", "Africa/Casablanca")
    tz = parse_timezone_value("UTC+00:00", dst_enabled=True)
    assert tz == ZoneInfo("Africa/Casablanca")


@pytest.mark.parametrize(
    "expected_utc",
    [
        # First 02:30 (CEST) and repeated 02:30 (CET) on the fall-back day.
        dt.datetime(2026, 10, 25, 0, 30, tzinfo=dt.UTC),
        dt.datetime(2026, 10, 25, 1, 30, tzinfo=dt.UTC),
    ],
)
def test_normalize_alarm_time_handles_repeated_dst_hour(
    monkeypatch, expected_utc: dt.datetime
) -> None:
    monkeypatch.delenv("TZ", raising=False)
    tz = parse_timezone_value("UTC+01:00", dst_enabled=True)

    _, utc_dt, alarm_str = normalize_alarm_time(
        {
            "alarmStartTime": int(expected_utc.timestamp() * 1000),
            "alarmStartTimeStr": "2026-10-25 02:30:00",
        },
        tz,
    )

    assert utc_dt == expected_utc
    assert alarm_str == "2026-10-25 02:30:00"
