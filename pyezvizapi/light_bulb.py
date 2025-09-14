"""Ezviz light bulb API.

Light-bulb specific helpers to read device status and control
features exposed via the Ezviz cloud API (on/off, brightness,
color temperature, etc.).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .constants import DeviceSwitchType
from .exceptions import PyEzvizError
from .utils import fetch_nested_value

if TYPE_CHECKING:
    from .client import EzvizClient
from .models import EzvizDeviceRecord


class EzvizLightBulb:
    """Representation of an Ezviz light bulb.

    Provides a thin, typed wrapper over the pagelist/device payload
    for a light bulb, plus convenience methods to toggle and set
    brightness. This class mirrors the camera interface where
    possible to keep integration code simple.
    """

    def __init__(
        self,
        client: EzvizClient,
        serial: str,
        device_obj: EzvizDeviceRecord | dict | None = None,
    ) -> None:
        """Initialize the light bulb object.

        Raises:
            InvalidURL: If the API endpoint/connection is invalid when fetching device info.
            HTTPError: If the API returns a non-success HTTP status while fetching device info.
            PyEzvizError: On Ezviz API contract errors or decoding failures.
        """
        self._client = client
        self._serial = serial
        if device_obj is None:
            self._device = self._client.get_device_infos(self._serial)
        elif isinstance(device_obj, EzvizDeviceRecord):
            self._device = dict(device_obj.raw)
        else:
            self._device = device_obj
        self._feature_json = self.get_feature_json()
        switches = self._device.get("SWITCH") or []
        self._switch: dict[int, bool] = {}
        if isinstance(switches, list):
            for switch in switches:
                if not isinstance(switch, dict):
                    continue
                t = switch.get("type")
                en = switch.get("enable")
                if isinstance(t, int) and isinstance(en, (bool, int)):
                    self._switch[t] = bool(en)
        if DeviceSwitchType.ALARM_LIGHT.value not in self._switch:
            # trying to have same interface as the camera's light
            self._switch[DeviceSwitchType.ALARM_LIGHT.value] = self.get_feature_item(
                "light_switch"
            )["dataValue"]

    def fetch_key(self, keys: list[Any], default_value: Any = None) -> Any:
        """Fetch a nested key from the device payload.

        Uses the same semantics as the camera helper.
        """
        return fetch_nested_value(self._device, keys, default_value)

    def _local_ip(self) -> str:
        """Best-effort local IP address for devices that report 0.0.0.0."""
        wifi = self._device.get("WIFI") or {}
        addr = wifi.get("address")
        if isinstance(addr, str) and addr != "0.0.0.0":
            return addr

        # Seems to return none or 0.0.0.0 on some.
        conn = self._device.get("CONNECTION") or {}
        local_ip = conn.get("localIp")
        if isinstance(local_ip, str) and local_ip != "0.0.0.0":
            return local_ip

        return "0.0.0.0"

    def get_feature_json(self) -> Any:
        """Parse the FEATURE JSON string into a Python structure.

        Raises:
            PyEzvizError: If the FEATURE JSON cannot be decoded.
        """
        try:
            json_output = json.loads(self._device["FEATURE"]["featureJson"])

        except ValueError as err:
            raise PyEzvizError("Impossible to decode FEATURE: " + str(err)) from err

        return json_output

    def get_feature_item(self, key: str, default_value: Any = None) -> Any:
        """Return a feature item by key from the parsed FEATURE structure."""
        items = self._feature_json["featureItemDtos"]

        for item in items:
            if item["itemKey"] == key:
                return item

        return default_value if default_value else {"dataValue": ""}

    def get_product_id(self) -> Any:
        """Return the product ID from the FEATURE metadata."""
        return self._feature_json["productId"]

    def status(self) -> dict[Any, Any]:
        """Return a status dictionary mirroring the camera status shape where possible."""
        return {
            "serial": self._serial,
            "name": self.fetch_key(["deviceInfos", "name"]),
            "version": self.fetch_key(["deviceInfos", "version"]),
            "upgrade_available": bool(
                self.fetch_key(["UPGRADE", "isNeedUpgrade"]) == 3
            ),
            "status": self.fetch_key(["deviceInfos", "status"]),
            "device_category": self.fetch_key(["deviceInfos", "deviceCategory"]),
            "device_sub_category": self.fetch_key(["deviceInfos", "deviceSubCategory"]),
            "upgrade_percent": self.fetch_key(["STATUS", "upgradeProcess"]),
            "upgrade_in_progress": bool(
                self.fetch_key(["STATUS", "upgradeStatus"]) == 0
            ),
            "latest_firmware_info": self.fetch_key(["UPGRADE", "upgradePackageInfo"]),
            "local_ip": self._local_ip(),
            "wan_ip": self.fetch_key(["CONNECTION", "netIp"]),
            "mac_address": self.fetch_key(["deviceInfos", "mac"]),
            "supported_channels": self.fetch_key(["deviceInfos", "channelNumber"]),
            "wifiInfos": self._device["WIFI"],
            "switches": self._switch,
            "optionals": self.fetch_key(["STATUS", "optionals"]),
            "supportExt": self._device["deviceInfos"]["supportExt"],
            "ezDeviceCapability": self.fetch_key(["deviceInfos", "ezDeviceCapability"]),
            "featureItems": self._feature_json["featureItemDtos"],
            "productId": self._feature_json["productId"],
            "color_temperature": self.get_feature_item("color_temperature")[
                "dataValue"
            ],
            "is_on": self.get_feature_item("light_switch")["dataValue"],
            "brightness": self.get_feature_item("brightness")["dataValue"],
            # same as brightness... added in order to keep "same interface" between camera and light bulb objects
            "alarm_light_luminance": self.get_feature_item("brightness")["dataValue"],
        }

    def _write_state(self, state: bool | None = None) -> bool:
        """Set the light bulb state.

        If ``state`` is None, the current state will be toggled.
        Returns True on success.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        item = self.get_feature_item("light_switch")

        return self._client.set_device_feature_by_key(
            self._serial,
            self.get_product_id(),
            state if state else not bool(item["dataValue"]),
            item["itemKey"],
        )

    def set_brightness(self, value: int) -> bool:
        """Set the light bulb brightness.

        The value must be in range 1–100. Returns True on success.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        return self._client.set_device_feature_by_key(
            self._serial, self.get_product_id(), value, "brightness"
        )

    def toggle_switch(self) -> bool:
        """Toggle the light bulb on/off."""
        return self._write_state()

    def power_on(self) -> bool:
        """Power the light bulb on."""
        return self._write_state(True)

    def power_off(self) -> bool:
        """Power the light bulb off."""
        return self._write_state(False)
