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
    resolve_camera_timezone,
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


def _freeze_utc_now(monkeypatch, now_utc: dt.datetime) -> None:
    class FixedDateTime(dt.datetime):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> Any:
            return now_utc.astimezone(tz) if tz is not None else now_utc.replace(tzinfo=None)

    monkeypatch.setattr(utils.datetime, "datetime", FixedDateTime)


def _utc(
    year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0
) -> dt.datetime:
    return dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.UTC)


UTC_PLUS_1 = dt.timezone(dt.timedelta(hours=1))
UTC_PLUS_2 = dt.timezone(dt.timedelta(hours=2))


@pytest.mark.parametrize(
    ("tzinfo", "alarm_str", "now_utc", "expected_utc"),
    [
        # Paris camera (UTC+01:00 + DST), summer: recent and 30 minutes old.
        (UTC_PLUS_1, "2026-10-13 07:06:50", _utc(2026, 10, 13, 5, 7), _utc(2026, 10, 13, 5, 6, 50)),
        (UTC_PLUS_1, "2026-10-13 07:06:50", _utc(2026, 10, 13, 5, 36, 50), _utc(2026, 10, 13, 5, 6, 50)),
        # Same camera in winter.
        (UTC_PLUS_1, "2026-12-01 07:06:50", _utc(2026, 12, 1, 6, 7), _utc(2026, 12, 1, 6, 6, 50)),
        (UTC_PLUS_1, "2026-12-01 07:06:50", _utc(2026, 12, 1, 6, 36, 50), _utc(2026, 12, 1, 6, 6, 50)),
        # Repeated 02:30 when DST ends in Paris: first and second occurrence.
        (UTC_PLUS_1, "2026-10-25 02:30:00", _utc(2026, 10, 25, 0, 30, 10), _utc(2026, 10, 25, 0, 30)),
        (UTC_PLUS_1, "2026-10-25 02:30:00", _utc(2026, 10, 25, 1, 30, 10), _utc(2026, 10, 25, 1, 30)),
        # UTC+02:00 + DST on 10 April 2026: Cairo is still UTC+2, Athens is UTC+3.
        (UTC_PLUS_2, "2026-04-10 12:00:00", _utc(2026, 4, 10, 10, 0, 10), _utc(2026, 4, 10, 10, 0)),
        (UTC_PLUS_2, "2026-04-10 13:00:00", _utc(2026, 4, 10, 10, 0, 10), _utc(2026, 4, 10, 10, 0)),
    ],
)
def test_normalize_alarm_time_resolves_dst_from_current_time(
    monkeypatch,
    tzinfo: dt.tzinfo,
    alarm_str: str,
    now_utc: dt.datetime,
    expected_utc: dt.datetime,
) -> None:
    _freeze_utc_now(monkeypatch, now_utc)

    # String only, and local-clock epoch (wall time encoded as if it were UTC).
    local_clock_epoch = dt.datetime.fromisoformat(alarm_str + "+00:00").timestamp()
    for alarm in (
        {"alarmStartTimeStr": alarm_str},
        {"alarmStartTime": int(local_clock_epoch * 1000), "alarmStartTimeStr": alarm_str},
        {"alarmStartTime": int(expected_utc.timestamp() * 1000), "alarmStartTimeStr": alarm_str},
    ):
        local_dt, utc_dt, result_str = normalize_alarm_time(alarm, tzinfo, dst_enabled=True)

        assert utc_dt == expected_utc
        # The local value keeps the camera wall time with the offset in force.
        assert local_dt == expected_utc
        assert local_dt is not None
        assert local_dt.strftime("%Y-%m-%d %H:%M:%S") == alarm_str
        assert result_str == alarm_str


def test_normalize_alarm_time_without_dst_flag_keeps_fixed_offset(monkeypatch) -> None:
    _freeze_utc_now(monkeypatch, _utc(2026, 10, 13, 5, 7))

    _, utc_dt, _ = normalize_alarm_time({"alarmStartTimeStr": "2026-10-13 07:06:50"}, UTC_PLUS_1)

    assert utc_dt == _utc(2026, 10, 13, 6, 6, 50)


def test_normalize_alarm_time_with_regional_zone_handles_repeated_hour(monkeypatch) -> None:
    paris = ZoneInfo("Europe/Paris")
    for now_utc, expected_utc in (
        (_utc(2026, 10, 25, 0, 30, 10), _utc(2026, 10, 25, 0, 30)),
        (_utc(2026, 10, 25, 1, 30, 10), _utc(2026, 10, 25, 1, 30)),
    ):
        _freeze_utc_now(monkeypatch, now_utc)
        for alarm in (
            {"alarmStartTimeStr": "2026-10-25 02:30:00"},
            {
                "alarmStartTime": int(expected_utc.timestamp() * 1000),
                "alarmStartTimeStr": "2026-10-25 02:30:00",
            },
        ):
            _, utc_dt, alarm_str = normalize_alarm_time(alarm, paris)
            assert utc_dt == expected_utc
            assert alarm_str == "2026-10-25 02:30:00"


def test_compute_motion_from_alarm_is_active_on_time_during_dst(monkeypatch) -> None:
    _freeze_utc_now(monkeypatch, _utc(2026, 10, 13, 5, 7))
    alarm = {"alarmStartTimeStr": "2026-10-13 07:06:50"}

    assert compute_motion_from_alarm(alarm, UTC_PLUS_1, dst_enabled=True) == (
        True,
        10.0,
        "2026-10-13 07:06:50",
    )
    # Without the camera DST flag the alarm looks one hour in the future.
    assert compute_motion_from_alarm(alarm, UTC_PLUS_1) == (
        False,
        0.0,
        "2026-10-13 07:06:50",
    )


@pytest.mark.parametrize(
    ("tz_val", "dst_enabled", "timezone", "expected_tz", "expected_dst"),
    [
        # No regional zone: fixed offset, DST resolved per alarm.
        ("UTC+01:00", True, None, UTC_PLUS_1, True),
        ("UTC+01:00", False, None, UTC_PLUS_1, False),
        # Matching regional zone is used.
        ("UTC+01:00", True, "Europe/Paris", ZoneInfo("Europe/Paris"), False),
        ("UTC+01:00", True, ZoneInfo("Europe/Paris"), ZoneInfo("Europe/Paris"), False),
        ("UTC+02:00", True, "Africa/Cairo", ZoneInfo("Africa/Cairo"), False),
        ("UTC+05:30", False, "Asia/Kolkata", ZoneInfo("Asia/Kolkata"), False),
        # Zones that disagree with the camera are ignored.
        ("UTC+01:00", True, "America/New_York", UTC_PLUS_1, True),
        ("UTC+01:00", False, "Europe/Paris", UTC_PLUS_1, False),
        ("UTC+01:00", True, "Not/AZone", UTC_PLUS_1, True),
        # A camera IANA zone always wins.
        ("Europe/Paris", True, "America/New_York", ZoneInfo("Europe/Paris"), False),
    ],
)
def test_resolve_camera_timezone(
    tz_val: Any,
    dst_enabled: bool,
    timezone: Any,
    expected_tz: dt.tzinfo,
    expected_dst: bool,
) -> None:
    assert resolve_camera_timezone(tz_val, dst_enabled, timezone) == (
        expected_tz,
        expected_dst,
    )


def test_resolve_camera_timezone_ignores_process_tz(monkeypatch) -> None:
    monkeypatch.setenv("TZ", "Europe/Paris")

    assert resolve_camera_timezone("UTC+01:00", True) == (UTC_PLUS_1, True)
