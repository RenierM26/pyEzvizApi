"""Source-path observation for typed views, separate from legacy defaults."""

from collections.abc import Mapping
import json
from typing import Any

from pyezvizapi.constants import DeviceSwitchType

_COMMON = {
    "serial": ("deviceInfos", "deviceSerial"),
    "name": ("deviceInfos", "name"),
    "version": ("deviceInfos", "version"),
    "status": ("deviceInfos", "status"),
    "device_category": ("deviceInfos", "deviceCategory"),
    "device_sub_category": ("deviceInfos", "deviceSubCategory"),
    "mac_address": ("deviceInfos", "mac"),
    "supported_channels": ("deviceInfos", "channelNumber"),
    "supportExt": ("deviceInfos", "supportExt"),
    "switches": ("SWITCH",),
    "optionals": ("STATUS", "optionals"),
}
_CAMERA = {
    "battery_level": ("STATUS", "optionals", "powerRemaining"),
    "alarm_notify": ("STATUS", "globalStatus"),
    "encrypted": ("STATUS", "isEncrypt"),
    "alarm_sound_mod": ("STATUS", "alarmSoundMode"),
    "PIR_Status": ("STATUS", "pirStatus"),
    "push_notify_alarm": ("NODISTURB", "alarmEnable"),
    "push_notify_call": ("NODISTURB", "callingEnable"),
}
_MISSING = object()


def _present(raw: Mapping, path: tuple[str, ...]) -> bool:
    value: Any = raw
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return False
        value = value[key]
    return True


def plug_power(raw: Mapping) -> tuple[bool, Any]:
    """Retain the original last-row-wins power code, never legacy bool coercion."""
    value: Any = _MISSING
    rows = raw.get("SWITCH")
    for item in rows if isinstance(rows, list) else ():
        if isinstance(item, Mapping) and item.get("type") == DeviceSwitchType.PLUG.value:
            value = item.get("enable", _MISSING)
    return value is not _MISSING, None if value is _MISSING else value


def observed_fields(raw: Mapping, kind: str) -> frozenset[str]:
    """Conservative known property paths; absence is unknown, never unsupported."""
    paths = _COMMON | (_CAMERA if kind == "camera" else {})
    result = {key for key, path in paths.items() if _present(raw, path)}
    if kind == "plug" and plug_power(raw)[0]:
        result.add("is_on")
    elif kind == "light":
        feature = raw.get("FEATURE")
        encoded = feature.get("featureJson") if isinstance(feature, Mapping) else None
        try:
            decoded = json.loads(encoded) if isinstance(encoded, str) else {}
        except ValueError:
            return frozenset(result)
        if not isinstance(decoded, Mapping):
            return frozenset(result)
        if "productId" in decoded:
            result.add("productId")
        items = decoded.get("featureItemDtos")
        properties = {
            "light_switch": "is_on",
            "brightness": "brightness",
            "color_temperature": "color_temperature",
        }
        for item in items if isinstance(items, list) else ():
            if not isinstance(item, Mapping) or "dataValue" not in item:
                continue
            key = item.get("itemKey")
            name = properties.get(key) if isinstance(key, str) else None
            if name is not None:
                result.add(name)
        if "brightness" in result:
            result.add("alarm_light_luminance")
    return frozenset(result)
