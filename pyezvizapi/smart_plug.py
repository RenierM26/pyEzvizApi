"""Ezviz smart plug API.

Smart plug specific helpers to read device status and control
features exposed via the Ezviz cloud API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .constants import DeviceSwitchType
from .utils import fetch_nested_value

if TYPE_CHECKING:
    from .client import EzvizClient
from .models import EzvizDeviceRecord


class EzvizSmartPlug:
    """Representation of an Ezviz smart plug.

    Provides a thin, typed wrapper over the pagelist/device payload
    for a smart plug. This class mirrors the camera interface where
    possible to keep integration code simple.
    """

    def __init__(
            self,
            client: EzvizClient,
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
