"""Nested mapping traversal and legacy shallow merge contracts."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

PathComponent = str | int
WILDCARD_STEP = "*"
_MISSING = object()


def iter_nested(data: Any, path: Iterable[PathComponent]) -> Iterator[Any]:
    """Yield values reachable by following a dotted path with optional wildcards."""

    current: list[Any] = [data]

    for step in path:
        next_level: list[Any] = []
        for candidate in current:
            if step == WILDCARD_STEP:
                if isinstance(candidate, dict):
                    next_level.extend(candidate.values())
                elif isinstance(candidate, (list, tuple)):
                    next_level.extend(candidate)
                continue

            if isinstance(candidate, dict) and step in candidate:
                next_level.append(candidate[step])
                continue

            if (
                isinstance(candidate, (list, tuple))
                and isinstance(step, int)
                and -len(candidate) <= step < len(candidate)
            ):
                next_level.append(candidate[step])

        current = next_level
        if not current:
            break

    yield from current



def first_nested(
    data: Any, path: Iterable[PathComponent], default: Any = None
) -> Any:
    """Return the first value produced by iter_nested or ``default``."""

    return next(iter_nested(data, path), default)



def fetch_nested_value(data: Any, keys: list, default_value: Any = None) -> Any:
    """Fetch the value corresponding to the given nested keys in a dictionary.

    If any of the keys in the path doesn't exist, the default value is returned.

    Args:
        data (dict): The nested dictionary to search for keys.
        keys (list): A list of keys representing the path to the desired value.
        default_value (optional): The value to return if any of the keys doesn't exist.

    Returns:
        The value corresponding to the nested keys or the default value.

    """
    value = first_nested(data, keys, _MISSING)
    return default_value if value is _MISSING else value



def deep_merge(dict1: Any, dict2: Any) -> Any:
    """Merge dicts recursively, concatenate lists, and otherwise prefer dict2.

    Inputs are not mutated. Unchanged subtrees and the non-None operand of a
    None merge are returned by reference; this is not a deep-copy operation.

    Args:
    dict1 (dict): The first dictionary.
    dict2 (dict): The second dictionary.

    Returns:
    dict: The merged dictionary.

    """
    # If one of the dictionaries is None, return the other one
    if dict1 is None:
        return dict2
    if dict2 is None:
        return dict1

    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        if isinstance(dict1, list) and isinstance(dict2, list):
            return dict1 + dict2
        return dict2

    # Create a new dictionary to store the merged result
    merged = {}

    # Merge keys from both dictionaries
    for key in set(dict1.keys()) | set(dict2.keys()):
        if key in dict1 and key in dict2:
            if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                merged[key] = deep_merge(dict1[key], dict2[key])
            elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                merged[key] = dict1[key] + dict2[key]
            else:
                # If both values are not dictionaries or lists, keep the value from dict2
                merged[key] = dict2[key]
        elif key in dict1:
            # If the key is only in dict1, keep its value
            merged[key] = dict1[key]
        else:
            # If the key is only in dict2, keep its value
            merged[key] = dict2[key]

    return merged
