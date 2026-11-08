"""Small shared device-payload helpers; device wrappers retain state ownership."""

from collections.abc import Mapping
from typing import Any


def switch_values(value: Any) -> dict[int, bool]:
    """Collapse valid switch rows, preserving zero/false and last-row wins."""
    result: dict[int, bool] = {}
    for item in value if isinstance(value, list) else ():
        if not isinstance(item, Mapping):
            continue
        kind, enabled = item.get("type"), item.get("enable")
        if isinstance(kind, int) and isinstance(enabled, (bool, int)):
            result[kind] = bool(enabled)
    return result


def local_ip_address(wifi: Any, connection: Any) -> str:
    """Prefer WIFI address then CONNECTION.localIp, ignoring 0.0.0.0."""
    for section, key in ((wifi, "address"), (connection, "localIp")):
        value = section.get(key) if isinstance(section, Mapping) else None
        if isinstance(value, str) and value != "0.0.0.0":
            return value
    return "0.0.0.0"
