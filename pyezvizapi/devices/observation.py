"""Source-path observation for typed views, separate from legacy defaults."""

from collections.abc import Mapping
import json
from typing import Any

from pyezvizapi.constants import DeviceSwitchType
from pyezvizapi.devices.payload import switch_rows

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
    "upgrade_available": ("UPGRADE", "isNeedUpgrade"),
    "upgrade_in_progress": ("STATUS", "upgradeStatus"),
    "upgrade_status": ("STATUS", "upgradeStatus"),
    "upgrade_phase": ("STATUS", "upgradeStatus"),
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


def _present(raw: Mapping, path: tuple[str, ...]) -> bool:
    value: Any = raw
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return False
        value = value[key]
    return True


def power_state(value: Any) -> bool | None:
    """Only native boolean or integer/string 0/1 is a known on/off state."""
    if type(value) not in (bool, int, str):
        return None
    return {True: True, False: False, "1": True, "0": False}.get(value)


def plug_power(raw: Mapping) -> tuple[bool, Any]:
    """Select the app's device-level plug channel before strict power validation."""
    row = switch_rows(raw.get("SWITCH"), channel_no=0).get(DeviceSwitchType.PLUG.value)
    if row is None or "enable" not in row:
        return False, None
    return True, row["enable"]


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
