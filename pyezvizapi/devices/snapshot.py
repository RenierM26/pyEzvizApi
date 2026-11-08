"""Copy-safe typed inventory snapshots, independent of Home Assistant."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
import math
from types import MappingProxyType
from typing import Any, Literal

from pyezvizapi.devices.observation import power_state
from pyezvizapi.exceptions import PyEzvizError

type DeviceKind = Literal["camera", "detector", "light", "plug"]


class _FrozenList(tuple):
    """Distinguish a frozen JSON list so dictionary adapters restore its type."""


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze(v) for v in value)
    if isinstance(value, tuple):
        return tuple(_freeze(v) for v in value)
    if value is None or isinstance(
        value, (str, bytes, int, float, bool, date, datetime, time, timedelta)
    ):
        return value
    raise PyEzvizError("Unsupported mutable inventory property type")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, _FrozenList):
        return [_thaw(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_thaw(v) for v in value)
    return value


@dataclass(frozen=True)
class DevicePollOptions:
    """One total polling budget, including lock waits, HTTP and alarm reads."""

    timeout: float = 20.0
    include_camera_alarms: bool = True
    max_devices: int = 10000

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise PyEzvizError("Inventory timeout must be positive and finite")
        if not isinstance(self.include_camera_alarms, bool):
            raise PyEzvizError("Inventory alarm selection must be a boolean")
        if (
            isinstance(self.max_devices, bool)
            or not isinstance(self.max_devices, int)
            or self.max_devices < 1
        ):
            raise PyEzvizError("Inventory device budget must be a positive integer")


@dataclass(frozen=True)
class DeviceCapabilities:
    """Observed properties, not guessed unsupported flags or actuator permissions."""

    observed: frozenset[str] = frozenset()
    verified_booleans: Mapping[str, bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if any(not isinstance(k, str) for k in self.observed):
            raise PyEzvizError("Observed property names must be strings")
        if not isinstance(self.verified_booleans, Mapping) or any(
            v is not None and not isinstance(v, bool) for v in self.verified_booleans.values()
        ):
            raise PyEzvizError("Verified binary states must be bool or None")
        object.__setattr__(self, "observed", frozenset(self.observed))
        object.__setattr__(self, "verified_booleans", _freeze(self.verified_booleans))

    def has(self, name: str) -> bool | None:
        """Absence means unknown, never proof of unsupported hardware."""
        return True if name in self.observed else None


@dataclass(frozen=True)
class DeviceState:
    serial: str
    kind: DeviceKind
    values: Mapping[str, Any] = field(repr=False)
    capabilities: DeviceCapabilities = field(default_factory=DeviceCapabilities)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", _freeze(self.values))

    @property
    def online(self) -> bool | None:
        value = self.values.get("status")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return None
        if value in (1, "1"):
            return True
        if value in (2, "2"):
            return False
        return None

    @property
    def battery_level(self) -> int | None:
        value = self.values.get("battery_level")
        if isinstance(value, str) and value.isdecimal():
            value = int(value)
        return value if type(value) is int and 0 <= value <= 100 else None

    def as_dict(self) -> dict[str, Any]:
        """Return a detached compatibility dictionary; old snapshots stay unchanged."""
        return _thaw(self.values)


@dataclass(frozen=True)
class CameraState(DeviceState):
    @property
    def motion(self) -> bool | None:
        value = self.values.get("Motion_Trigger")
        return value if isinstance(value, bool) else None


@dataclass(frozen=True)
class LightState(DeviceState):
    @property
    def is_on(self) -> bool | None:
        return power_state(self.values.get("is_on"))


@dataclass(frozen=True)
class PlugState(LightState):
    """An on/off socket, without inferred energy measurement capabilities."""


@dataclass(frozen=True)
class DetectorState(DeviceState):
    """Raw diagnostics remain available before a model's binary enum is qualified."""

    @property
    def door_open(self) -> bool | None:
        return self.capabilities.verified_booleans.get("door_open")

    @property
    def water_leak(self) -> bool | None:
        return self.capabilities.verified_booleans.get("water_leak")


@dataclass(frozen=True)
class DeviceHealth:
    present: bool
    current: bool
    last_success: datetime | None
    error_type: str | None = None


@dataclass(frozen=True)
class DeviceSnapshot:
    revision: int
    received_at: datetime
    devices: Mapping[str, DeviceState]
    health: Mapping[str, DeviceHealth]

    def __post_init__(self) -> None:
        object.__setattr__(self, "devices", MappingProxyType(dict(self.devices)))
        object.__setattr__(self, "health", MappingProxyType(dict(self.health)))

    def select(self, kind: DeviceKind | None = None) -> dict[str, DeviceState]:
        """A pure in-memory view; selectors never initiate another request."""
        return {k: v for k, v in self.devices.items() if kind is None or v.kind == kind}

    def as_dict(self, kind: DeviceKind | None = None) -> dict[str, dict[str, Any]]:
        return {k: v.as_dict() for k, v in self.select(kind).items()}
