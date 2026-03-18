"""Ezviz detector/sensor API.

Detector-specific helpers to read device status for Ezviz sensors
connected via a gateway (A3 hub). Covers door/window contact sensors
(T2C), water leak sensors (T10C), indoor sirens (T9C), and similar
Zigbee sub-devices.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .utils import fetch_nested_value

if TYPE_CHECKING:
    from .client import EzvizClient
from .models import EzvizDeviceRecord


class EzvizDetector:
    """Representation of an Ezviz detector / sensor device.

    These are Zigbee sub-devices (door/window contacts, water leak
    sensors, sirens) paired to an Ezviz gateway (e.g. CS-A3).
    Status data comes primarily from the FEATURE_INFO section of the
    pagelist API response.
    """

    def __init__(
        self,
        client: EzvizClient,
        serial: str,
        device_obj: EzvizDeviceRecord | dict | None = None,
    ) -> None:
        self._client = client
        self._serial = serial
        if device_obj is None:
            self._device = self._client.get_device_infos(self._serial)
        elif isinstance(device_obj, EzvizDeviceRecord):
            self._device = dict(device_obj.raw)
        else:
            self._device = device_obj

    def fetch_key(self, keys: list[Any], default_value: Any = None) -> Any:
        """Fetch a nested key from the device payload."""
        return fetch_nested_value(self._device, keys, default_value)

    def _feature_global(self) -> dict[str, Any]:
        """Return the FEATURE_INFO -> 0 -> global dict."""
        fi = self._device.get("FEATURE_INFO") or {}
        channel = fi.get("0") or fi.get(0) or {}
        return channel.get("global") or {}

    def status(self) -> dict[str, Any]:
        """Return a status dictionary for this detector.

        The output shape mirrors camera/light-bulb/smart-plug status
        for common keys, then adds detector-specific fields extracted
        from the FEATURE_INFO section.
        """
        feat = self._feature_global()
        door_mag = feat.get("DoorMagnetic") or {}
        water = feat.get("WaterOutSense") or {}
        siren = feat.get("SirenMgr") or {}
        battery_info = feat.get("BatteryInfo") or {}
        power_mgr = feat.get("PowerMgr") or {}
        zigbee = feat.get("ZigbeeMgr") or {}

        battery_level = battery_info.get(
            "SurplusPower", power_mgr.get("SurplusPower")
        )

        data: dict[str, Any] = {
            "serial": self._serial,
            "name": self.fetch_key(["deviceInfos", "name"]),
            "version": self.fetch_key(["deviceInfos", "version"]),
            "upgrade_available": bool(
                self.fetch_key(["UPGRADE", "isNeedUpgrade"]) == 3
            ),
            "status": self.fetch_key(["deviceInfos", "status"]),
            "device_category": self.fetch_key(["deviceInfos", "deviceCategory"]),
            "device_sub_category": self.fetch_key(
                ["deviceInfos", "deviceSubCategory"]
            ),
            "upgrade_percent": self.fetch_key(["STATUS", "upgradeProcess"]),
            "upgrade_in_progress": bool(
                self.fetch_key(["STATUS", "upgradeStatus"]) == 0
            ),
            "latest_firmware_info": self.fetch_key(
                ["UPGRADE", "upgradePackageInfo"]
            ),
            "supportExt": self.fetch_key(["deviceInfos", "supportExt"]),
            "switches": {},
            "optionals": self.fetch_key(["STATUS", "optionals"]),
            # Detector-specific fields
            "battery_level": battery_level,
            # Door/window magnetic contact (T2C)
            "door_status": door_mag.get("DoorStatus"),
            "door_open_remind": door_mag.get("OpenRemindSwitch"),
            "door_closed_remind": door_mag.get("ClosedRemindSwitch"),
            "door_open_gateway_alarm": door_mag.get("OpenGateWaySwitch"),
            "door_closed_gateway_alarm": door_mag.get("ClosedGateWaySwitch"),
            "door_open_detection_time": door_mag.get("OpenDetectionTime"),
            # Water leak sensor (T10C)
            "water_leak_status": water.get("WaterOutStatus"),
            # Siren (T9C)
            "siren_work_state": (
                siren.get("SirenWorkState", {}).get("workState")
            ),
            "siren_alarm_volume": (
                siren.get("SirenAlarmVolume", {}).get("alarmVolume")
            ),
            "siren_alarm_duration": (
                siren.get("SirenAlarmDuration", {}).get("alarmDuration")
            ),
            "siren_tamper_detection": (
                siren.get("SirenTamperCfg", {}).get("tamperDetection")
            ),
            "siren_motion_detection": (
                siren.get("SirenMotionDetectCfg", {}).get("moveDetection")
            ),
            # Zigbee signal strength
            "zigbee_signal": (
                zigbee.get("ZigbeeSignal", {}).get("signal")
            ),
            # Power mode (battery / wired)
            "power_mode": power_mgr.get("PowerMode", {}).get("mode"),
        }

        return data
