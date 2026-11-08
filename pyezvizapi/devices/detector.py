"""Ezviz detector/sensor API.

Detector-specific helpers to read device status for Ezviz sensors
connected via a gateway (A3 hub). Covers door/window contact sensors
(T2C), water leak sensors (T10C), indoor sirens (T9C), and similar
Zigbee sub-devices.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyezvizapi._shared.mapping import fetch_nested_value
from pyezvizapi.models import EzvizDeviceRecord

# Field names introduced and hardware-reported by Simone Rescio in PR #99.
_FEATURE_FIELDS = {
    "door_status": ("DoorMagnetic", "DoorStatus"),
    "door_open_remind": ("DoorMagnetic", "OpenRemindSwitch"),
    "door_closed_remind": ("DoorMagnetic", "ClosedRemindSwitch"),
    "door_open_gateway_alarm": ("DoorMagnetic", "OpenGateWaySwitch"),
    "door_closed_gateway_alarm": ("DoorMagnetic", "ClosedGateWaySwitch"),
    "door_open_detection_time": ("DoorMagnetic", "OpenDetectionTime"),
    "water_leak_status": ("WaterOutSense", "WaterOutStatus"),
    "siren_work_state": ("SirenMgr", "SirenWorkState", "workState"),
    "siren_alarm_volume": ("SirenMgr", "SirenAlarmVolume", "alarmVolume"),
    "siren_alarm_duration": ("SirenMgr", "SirenAlarmDuration", "alarmDuration"),
    "siren_tamper_detection": ("SirenMgr", "SirenTamperCfg", "tamperDetection"),
    "siren_motion_detection": ("SirenMgr", "SirenMotionDetectCfg", "moveDetection"),
    "zigbee_signal": ("ZigbeeMgr", "ZigbeeSignal", "signal"),
    "power_mode": ("PowerMgr", "PowerMode", "mode"),
}


def _feature_value(value: Any, path: tuple[str, ...]) -> Any:
    """Read a product property without coercing unknown or malformed values."""
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


class EzvizDetector:
    """Representation of an Ezviz detector / sensor device.

    These are Zigbee sub-devices (door/window contacts, water leak
    sensors, sirens) paired to an Ezviz gateway (e.g. CS-A3).
    Status data comes primarily from the FEATURE_INFO section of the
    pagelist API response.
    """

    def __init__(
        self,
        client: Any,
        serial: str,
        device_obj: EzvizDeviceRecord | Mapping[str, Any] | None = None,
    ) -> None:
        self._client = client
        self._serial = serial
        if device_obj is None:
            payload = self._client.get_device_infos(self._serial)
        elif isinstance(device_obj, EzvizDeviceRecord):
            payload = device_obj.raw
        else:
            payload = device_obj
        self._device = dict(payload) if isinstance(payload, Mapping) else {}

    def fetch_key(self, keys: list[Any], default_value: Any = None) -> Any:
        """Fetch a nested key from the device payload."""
        return fetch_nested_value(self._device, keys, default_value)

    def _feature_global(self) -> Mapping[str, Any]:
        """Select native local-index zero without assuming every node is a map."""
        info = self.fetch_key(["FEATURE_INFO"])
        if not isinstance(info, Mapping):
            return {}
        channel = info.get("0")
        if not isinstance(channel, Mapping):
            channel = info.get(0)
        if not isinstance(channel, Mapping):
            return {}
        result = channel.get("global")
        return result if isinstance(result, Mapping) else {}

    def observed_fields(self) -> frozenset[str]:
        """Report actual property paths, including present-but-unknown values."""
        feat = self._feature_global()
        result = set()
        for name, path in _FEATURE_FIELDS.items():
            value = feat
            for key in path:
                if not isinstance(value, Mapping) or key not in value:
                    break
                value = value[key]
            else:
                result.add(name)
        if any(
            isinstance(feat.get(group), Mapping) and "SurplusPower" in feat[group]
            for group in ("BatteryInfo", "PowerMgr")
        ):
            result.add("battery_level")
        return frozenset(result)

    def status(self) -> dict[str, Any]:
        """Return a status dictionary for this detector.

        The output shape mirrors camera/light-bulb/smart-plug status
        for common keys, then adds detector-specific fields extracted
        from the FEATURE_INFO section.
        """
        feat = self._feature_global()
        battery_level = _feature_value(feat, ("BatteryInfo", "SurplusPower"))
        if battery_level is None:
            battery_level = _feature_value(feat, ("PowerMgr", "SurplusPower"))

        data: dict[str, Any] = {
            "serial": self._serial,
            "name": self.fetch_key(["deviceInfos", "name"]),
            "version": self.fetch_key(["deviceInfos", "version"]),
            "upgrade_available": bool(self.fetch_key(["UPGRADE", "isNeedUpgrade"]) == 3),
            "status": self.fetch_key(["deviceInfos", "status"]),
            "device_category": self.fetch_key(["deviceInfos", "deviceCategory"]),
            "device_sub_category": self.fetch_key(["deviceInfos", "deviceSubCategory"]),
            "upgrade_percent": self.fetch_key(["STATUS", "upgradeProcess"]),
            "upgrade_in_progress": bool(self.fetch_key(["STATUS", "upgradeStatus"]) == 0),
            "latest_firmware_info": self.fetch_key(["UPGRADE", "upgradePackageInfo"]),
            "supportExt": self.fetch_key(["deviceInfos", "supportExt"]),
            "switches": {},
            "optionals": self.fetch_key(["STATUS", "optionals"]),
            # Detector-specific fields
            "battery_level": battery_level,
        }
        # Values are intentionally raw. Product/firmware-specific state enums
        # must not be guessed into booleans or treated as safe when absent.
        for name, path in _FEATURE_FIELDS.items():
            data[name] = _feature_value(feat, path)

        return data
