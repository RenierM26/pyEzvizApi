"""Lightweight models for Ezviz API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from typing import Any

from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.devices.payload import switch_values


def _mapping(value: Any) -> Mapping[str, Any]:
    """Normalize an optional API object without probing scalar/list values."""
    return value if isinstance(value, Mapping) else {}


def _optional_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _optional_int(value: Any) -> int | None:
    """Return an int for API values that may arrive as ints or numeric strings."""
    result: int | None = None
    if isinstance(value, bool):
        result = int(value)
    elif isinstance(value, int):
        result = value
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped:
            try:
                result = int(stripped)
            except ValueError:
                result = None
    return result


def _optional_bool(value: Any) -> bool | None:
    """Return a bool for API enable flags that may be encoded as ints/strings."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        stripped = value.strip().lower()
        if stripped in {"1", "true", "yes", "on"}:
            return True
        if stripped in {"0", "false", "no", "off"}:
            return False
    return None


@dataclass(frozen=True)
class EzvizChimeMusic:
    """Typed view of the APK-backed ``STATUS.optionals.ChimeMusic`` payload."""

    doorbell: int | None = None
    pir: int | None = None
    volume: int | None = None
    doorbell_enabled: bool | None = None
    pir_enabled: bool | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, value: Any) -> EzvizChimeMusic | None:
        """Parse the cloud ChimeMusic optional JSON into typed fields."""
        if value is None or value == "":
            return None
        decoded: Any = value
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                return None
        if not isinstance(decoded, Mapping):
            return None

        return cls(
            doorbell=_optional_int(decoded.get("doorbell")),
            pir=_optional_int(decoded.get("pir")),
            volume=_optional_int(decoded.get("volume")),
            doorbell_enabled=_optional_bool(decoded.get("doorbell_enable")),
            pir_enabled=_optional_bool(decoded.get("pir_enable")),
            raw=dict(decoded),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return non-empty parsed fields using API-shaped keys."""
        values = {
            "doorbell": self.doorbell,
            "pir": self.pir,
            "volume": self.volume,
            "doorbell_enable": self.doorbell_enabled,
            "pir_enable": self.pir_enabled,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True)
class EzvizDeviceChimeInfo:
    """Typed view of the APK-backed device chime configuration response."""

    sound_type: int | None = None
    duration: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api(cls, value: Mapping[str, Any]) -> EzvizDeviceChimeInfo:
        """Parse ``/v3/alarms/device/chime`` response fields."""
        return cls(
            sound_type=_optional_int(value.get("type")),
            duration=_optional_int(value.get("duration")),
            raw=dict(value),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return non-empty parsed fields using API-shaped keys."""
        values = {"type": self.sound_type, "duration": self.duration}
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True)
class EzvizDeviceRecord:
    """A light, ergonomic view over Ezviz get_device_infos() output.

    Captures commonly used fields with a stable API while preserving
    the full raw mapping for advanced/one-off access.
    """

    serial: str
    name: str | None
    device_category: str | None
    device_sub_category: str | None
    version: str | None
    status: int | None

    # Popular sections (pass-through subsets)
    support_ext: Mapping[str, Any] | None = None
    connection: Mapping[str, Any] | None = None
    wifi: Mapping[str, Any] | None = None
    qos: Mapping[str, Any] | None = None
    vtm: Mapping[str, Any] | None = None
    cloud: Mapping[str, Any] | None = None
    p2p: Any | None = None
    time_plan: Any | None = None
    optionals: Mapping[str, Any] | None = None

    # Switches collapsed to a simple type->enabled map for convenience
    switches: Mapping[int, bool] = field(default_factory=dict)

    # Full unmodified mapping for anything not yet modeled
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def chime_music(self) -> EzvizChimeMusic | None:
        """Return parsed chime music metadata from status optionals, when present."""
        if not isinstance(self.optionals, Mapping):
            return None
        return EzvizChimeMusic.from_api(self.optionals.get("ChimeMusic"))

    @classmethod
    def from_api(cls, serial: str, data: Mapping[str, Any]) -> EzvizDeviceRecord:
        """Build EzvizDeviceRecord from raw pagelist mapping.

        Tolerates missing or partially shaped keys.
        """
        data = _mapping(data)
        device_infos = _mapping(data.get("deviceInfos"))
        status = _mapping(data.get("STATUS"))
        optionals = _optional_mapping(status.get("optionals"))
        device_status = device_infos.get("status")
        if device_status is None:
            device_status = status.get("globalStatus")

        category = device_infos.get("deviceCategory") or device_infos.get("device_category")
        switches = switch_values(
            data.get("SWITCH"),
            channel_no=0 if category == DeviceCatagories.SOCKET.value else None,
        )

        return cls(
            serial=serial,
            name=device_infos.get("name"),
            device_category=device_infos.get("deviceCategory")
            or device_infos.get("device_category"),
            device_sub_category=device_infos.get("deviceSubCategory")
            or device_infos.get("device_sub_category"),
            version=device_infos.get("version"),
            status=device_status,
            support_ext=_optional_mapping(device_infos.get("supportExt")),
            connection=_optional_mapping(data.get("CONNECTION")),
            wifi=_optional_mapping(data.get("WIFI")),
            qos=_optional_mapping(data.get("QOS")),
            vtm=_optional_mapping(next(iter(_mapping(data.get("VTM")).values()), None)),
            cloud=_optional_mapping(next(iter(_mapping(data.get("CLOUD")).values()), None)),
            p2p=data.get("P2P"),
            time_plan=data.get("TIME_PLAN"),
            optionals=optionals,
            switches=switches,
            raw=data,
        )


def build_device_records_map(devices: Mapping[str, Any]) -> dict[str, EzvizDeviceRecord]:
    """Convert get_device_infos() mapping → {serial: EzvizDeviceRecord}.

    Keeps behavior robust to partial/missing keys.
    """
    out: dict[str, EzvizDeviceRecord] = {}
    for serial, payload in _mapping(devices).items():
        out[serial] = EzvizDeviceRecord.from_api(serial, payload)
    return out
