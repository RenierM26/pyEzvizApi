"""Tolerant API scalar and JSON conversion helpers."""

from __future__ import annotations

import json
from typing import Any


def coerce_int(value: Any) -> int | None:
    """Best-effort coercion to int for mixed payloads."""

    if isinstance(value, bool):
        return int(value)

    try:
        if isinstance(value, (int, float)):
            return int(value)
        return int(str(value))
    except (TypeError, ValueError, OverflowError):
        return None



def decode_json(value: Any) -> Any:
    """Decode strings (invalid JSON becomes None); leave non-strings unchanged."""

    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None
    return value



def convert_to_dict(data: Any) -> Any:
    """Decode top-level string values of a dict in place; leave nested objects alone."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    # Attempt to convert the string back into a dictionary
                    data[key] = json.loads(value)

                except ValueError:
                    continue
            continue

    return data



def string_to_list(data: Any, separator: str = ",") -> Any:
    """Convert a string representation of a list to a list."""
    if isinstance(data, str) and separator in data:
        return data.split(separator)

    return data

