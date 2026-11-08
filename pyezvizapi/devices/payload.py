"""Small shared device-payload helpers; device wrappers retain state ownership."""

from collections.abc import Mapping
from typing import Any

from pyezvizapi.devices.firmware import integer_code


def switch_rows(value: Any, *, channel_no: int = 0) -> dict[int, Mapping[str, Any]]:
    """Prefer the first explicit target-channel row; unscoped rows are fallback.

    Old payloads omit channelNo and retain their last-row-wins semantics. An
    explicit different/malformed channel must never overwrite the target.
    """
    scoped: dict[int, Mapping[str, Any]] = {}
    unscoped: dict[int, Mapping[str, Any]] = {}
    for item in value if isinstance(value, list) else ():
        if not isinstance(item, Mapping) or type(item.get("type")) is not int:
            continue
        kind = item["type"]
        if "channelNo" not in item:
            unscoped[kind] = item
        elif integer_code(item["channelNo"]) == channel_no:
            scoped.setdefault(kind, item)
    return unscoped | scoped


def switch_values(value: Any, *, channel_no: int | None = None) -> dict[int, bool]:
    """Collapse switch flags, optionally selecting one device/resource channel."""
    if channel_no is not None:
        value = list(switch_rows(value, channel_no=channel_no).values())
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
