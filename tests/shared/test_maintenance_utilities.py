"""Negative utility contracts and compatibility, with synthetic payloads only."""
import datetime as dt

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import pytest

from pyezvizapi._shared import (
    alarm_time as _alarm_time,
    coercion as _coercion,
    image_crypto as _image_crypto,
    mapping as _mapping,
    utils,
)
from pyezvizapi._shared.utils import (
    coerce_int,
    decrypt_image,
    deep_merge,
    normalize_alarm_time,
    parse_timezone_value,
    return_password_hash,
)
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.media.remux import BoundedStderrTail


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_tolerant_integer_coercion_rejects_non_finite(value):
    assert coerce_int(value) is None


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), 10**1000])
def test_alarm_epoch_overflow_can_fall_back_to_string(value):
    result = normalize_alarm_time({"alarmStartTime": value, "alarmStartTimeStr": "2024-04-27 10:00:00"}, dt.UTC)
    assert result[1] == dt.datetime(2024, 4, 27, 10, tzinfo=dt.UTC)


def test_alarm_epoch_zero_is_not_treated_as_missing():
    assert normalize_alarm_time({"alarmStartTime": 0}, dt.UTC)[1] == dt.datetime(1970, 1, 1, tzinfo=dt.UTC)


@pytest.mark.parametrize("value", ["UTC+24:00", "UTC-24:00", "UTC+02:99", "UTC+99:00", 1440, -1440, True, False, "/absolute/invalid"])
def test_invalid_timezones_use_documented_local_fallback(value):
    fallback = parse_timezone_value(None)
    assert parse_timezone_value(value) == fallback


@pytest.mark.parametrize("ending", [b"\x00", b"\x11", b"\x01\x02", b"\x03\x02\x03"])
def test_image_decrypt_rejects_invalid_pkcs7_padding(ending):
    padded = b"x" * (16 - len(ending)) + ending
    encrypted = AES.new(b"ABCDEF" + b"\0" * 10, AES.MODE_CBC, b"01234567" + b"\0" * 8).encrypt(padded)
    payload = HIK_ENCRYPTION_HEADER + return_password_hash("ABCDEF").encode() + encrypted
    with pytest.raises(PyEzvizError, match="padding"):
        decrypt_image(payload, "ABCDEF")


@pytest.mark.parametrize("max_chars", [0, -1, -100])
def test_zero_or_negative_diagnostic_tail_is_empty(max_chars):
    tail = BoundedStderrTail(100)
    tail.append(b"secret diagnostic data")
    assert tail.text(max_chars=max_chars) == ""
    assert tail.text(max_chars=4) == "data"


def test_merge_keeps_existing_shallow_alias_contract():
    child = {"one": [1]}
    left = {"retained": child, "items": [1]}
    merged = deep_merge(left, {"items": [2], "new": False})
    assert merged == {"retained": child, "items": [1, 2], "new": False}
    assert merged is not left and merged["retained"] is child
    assert left["items"] == [1]


def test_utility_facade_preserves_function_identity():
    assert utils.coerce_int is _coercion.coerce_int
    assert utils.iter_nested is _mapping.iter_nested
    assert utils.decrypt_image is _image_crypto.decrypt_image
    assert utils.parse_timezone_value is _alarm_time.parse_timezone_value
    assert utils.datetime is _alarm_time.datetime


def test_iana_dst_and_explicit_fixed_offset_are_distinct():
    zone = parse_timezone_value("Europe/Paris")
    assert zone.utcoffset(dt.datetime(2024, 1, 1)) == dt.timedelta(hours=1)
    assert zone.utcoffset(dt.datetime(2024, 7, 1)) == dt.timedelta(hours=2)
    assert parse_timezone_value("UTC+01:00").utcoffset(dt.datetime(2024, 7, 1)) == dt.timedelta(hours=1)


@pytest.mark.parametrize("size", [*range(16), 16384, 16385])
def test_valid_image_padding_and_legacy_trailing_bytes_remain_supported(size):
    clear = b"x" * size
    encrypted = AES.new(b"ABCDEF" + b"\0" * 10, AES.MODE_CBC, b"01234567" + b"\0" * 8).encrypt(pad(clear, 16))
    payload = HIK_ENCRYPTION_HEADER + return_password_hash("ABCDEF").encode() + encrypted
    assert decrypt_image(payload, "ABCDEF") == clear
    assert decrypt_image(payload + b"end", "ABCDEF") == clear


def test_existing_config_channel_coercion_is_not_a_preview_normalizer():
    from pyezvizapi.devices.features import resolve_channel  # noqa: PLC0415
    assert resolve_channel({"channelNo": 0}) == 1
    assert resolve_channel({"channelNo": "0"}) == 0
