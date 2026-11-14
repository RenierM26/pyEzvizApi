"""EZVIZ ports helpers, independent of application lifecycle."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pyezvizapi.devices._port_payload import reported_port_security as _reported_port_security
from pyezvizapi.devices.features import (
    normalize_port_security,
    port_security_config,
    port_security_has_port,
    port_security_port_enabled,
)
from pyezvizapi.devices.metadata import coerce_int

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


def _load_port_security_payload(client: EzvizClient, serial: str) -> dict[str, Any]:
    """Fetch or synthesize a normalized port-security payload."""
    response = client.get_port_security(serial)
    value: dict[str, Any] = {}
    if isinstance(response, dict):
        value = _reported_port_security(response) or deepcopy(normalize_port_security(response))

    if not value:
        camera_state = getattr(client, "_cameras", {}).get(serial)
        if isinstance(camera_state, dict):
            value = _reported_port_security(camera_state) or deepcopy(
                port_security_config(camera_state)
            )

    if not value:
        value = {"portSecurityList": []}

    ports = value.get("portSecurityList")
    if not isinstance(ports, list):
        ports = []
    value["portSecurityList"] = ports

    if "enabled" not in value:
        value["enabled"] = True

    return value


def set_port_security_ports(
    client: EzvizClient, serial: str, ports: tuple[int, ...], enable: int
) -> None:
    """Toggle multiple secure ports in the cached payload and persist it."""
    value = _load_port_security_payload(client, serial)
    entries = value["portSecurityList"]
    if len(ports) == 1:
        for entry in entries:
            if isinstance(entry, dict) and coerce_int(entry.get("portNo")) == ports[0]:
                entry["enabled"] = bool(enable)
                break
        else:
            entries.append({"portNo": ports[0], "enabled": bool(enable)})
        client.set_port_security(serial, value)
        return

    port_map: dict[int, dict[str, Any]] = {}

    for entry in entries:
        if isinstance(entry, dict):
            port_no = coerce_int(entry.get("portNo"))
            if port_no is not None:
                port_map[port_no] = entry

    for port in ports:
        entry = port_map.get(port)
        if entry is None:
            entry = {"portNo": port}
            entries.append(entry)
            port_map[port] = entry
        entry["enabled"] = bool(enable)

    client.set_port_security(serial, value)


@dataclass(frozen=True)
class PortSecurityToggle:
    """Bundle availability/value/set operations for secure ports."""

    ports: tuple[int, ...]

    @classmethod
    def single(cls, port: int) -> PortSecurityToggle:
        """Create a toggle for a single port."""

        return cls((port,))

    def _present_ports(self, camera_data: dict[str, Any]) -> list[int]:
        return [port for port in self.ports if port_security_has_port(camera_data, port)]

    def is_supported(self, camera_data: dict[str, Any]) -> bool:
        """Return True if any of the toggle's ports exist on the device."""

        return bool(self._present_ports(camera_data))

    def current_value(self, camera_data: dict[str, Any]) -> bool:
        """Return True if the toggle should be considered enabled."""

        present = self._present_ports(camera_data)
        if not present:
            return False

        if len(self.ports) == 1:
            return bool(port_security_port_enabled(camera_data, self.ports[0]))

        return any(port_security_port_enabled(camera_data, port) for port in present)

    def apply(self, client: EzvizClient, serial: str, enable: int) -> None:
        """Persist the toggle state through the API."""

        set_port_security_ports(client, serial, self.ports, enable)
