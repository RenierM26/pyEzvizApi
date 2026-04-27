from __future__ import annotations

import datetime as dt

from pyezvizapi.utils import (
    coerce_int,
    decode_json,
    deep_merge,
    fetch_nested_value,
    first_nested,
    iter_nested,
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
