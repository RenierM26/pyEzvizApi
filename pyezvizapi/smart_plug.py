"""Ezviz smart plug API.

Smart plug specific helpers to read device status and control
features exposed via the Ezviz cloud API.
"""

from __future__ import annotations

from typing import Any

from ._device_payload import local_ip_address, switch_values
from .constants import DeviceSwitchType
from .models import EzvizDeviceRecord
from .utils import fetch_nested_value


class EzvizSmartPlug:
    """Representation of an Ezviz smart plug.

    Provides a thin, typed wrapper over the pagelist/device payload
    for a smart plug. This class mirrors the camera interface where
    possible to keep integration code simple.
    """

    def __init__(
            self,
            client: Any,
            serial: str,
            device_obj: EzvizDeviceRecord | dict | None = None,
    ) -> None:
        """Initialize the smart plug object.

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
        self._switch = switch_values(self._device.get("SWITCH"))

    def fetch_key(self, keys: list[Any], default_value: Any = None) -> Any:
        """Fetch a nested key from the device payload.

        Uses the same semantics as the camera helper.
        """
        return fetch_nested_value(self._device, keys, default_value)

    def _local_ip(self) -> str:
        """Return the preferred reported local address without network access."""
        return local_ip_address(self._device.get("WIFI"), self._device.get("CONNECTION"))

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
            "is_on": self._switch[DeviceSwitchType.PLUG.value],
        }

    def _write_state(self, state: int) -> bool:
        """Set the socket state.

        If ``state`` is None, the current state will be toggled.
        Returns True on success.

        Raises:
            PyEzvizError: On API failures.
            InvalidURL: If the API endpoint/connection is invalid.
            HTTPError: If the API returns a non-success HTTP status.
        """
        self._client.set_switch(
            self._serial,
            DeviceSwitchType.PLUG.value,
            state
            )
        return True

    def power_on(self) -> bool:
        """Power the smart plug on."""
        return self._write_state(1)

    def power_off(self) -> bool:
        """Power the smart plug off."""
        return self._write_state(0)
