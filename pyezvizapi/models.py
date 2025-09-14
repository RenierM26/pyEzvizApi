"""Lightweight models for Ezviz API payloads."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


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

    @classmethod
    def from_api(cls, serial: str, data: Mapping[str, Any]) -> EzvizDeviceRecord:
        """Build EzvizDeviceRecord from raw pagelist mapping.

        Tolerates missing or partially shaped keys.
        """
        device_infos = data.get("deviceInfos", {}) or {}
        status = (data.get("STATUS", {}) or {})
        optionals = status.get("optionals") if isinstance(status, dict) else None

        # Collapse SWITCH list[{type, enable}] to {type: enable}
        switches_list = data.get("SWITCH") or []
        switches: dict[int, bool] = {}
        for item in switches_list if isinstance(switches_list, list) else []:
            t = item.get("type")
            en = item.get("enable")
            if isinstance(t, int) and isinstance(en, (bool, int)):
                switches[t] = bool(en)

        return cls(
            serial=serial,
            name=device_infos.get("name"),
            device_category=device_infos.get("deviceCategory") or device_infos.get("device_category"),
            device_sub_category=device_infos.get("deviceSubCategory") or device_infos.get("device_sub_category"),
            version=device_infos.get("version"),
            status=device_infos.get("status") or status.get("globalStatus") if isinstance(status, dict) else None,
            support_ext=device_infos.get("supportExt"),
            connection=data.get("CONNECTION"),
            wifi=data.get("WIFI"),
            qos=data.get("QOS"),
            vtm=next(iter((data.get("VTM") or {}).values()), None),
            cloud=next(iter((data.get("CLOUD") or {}).values()), None),
            p2p=data.get("P2P"),
            time_plan=data.get("TIME_PLAN"),
            optionals=optionals if isinstance(optionals, dict) else None,
            switches=switches,
            raw=data,
        )


def build_device_records_map(devices: Mapping[str, Any]) -> dict[str, EzvizDeviceRecord]:
    """Convert get_device_infos() mapping → {serial: EzvizDeviceRecord}.

    Keeps behavior robust to partial/missing keys.
    """
    out: dict[str, EzvizDeviceRecord] = {}
    for serial, payload in (devices or {}).items():
        try:
            out[serial] = EzvizDeviceRecord.from_api(serial, payload)
        except (TypeError, KeyError, ValueError):
            # Do not crash on unexpected shapes; fall back to raw wrapper
            out[serial] = EzvizDeviceRecord(
                serial=serial,
                name=(payload.get("deviceInfos") or {}).get("name"),
                device_category=(payload.get("deviceInfos") or {}).get("deviceCategory"),
                device_sub_category=(payload.get("deviceInfos") or {}).get("deviceSubCategory"),
                version=(payload.get("deviceInfos") or {}).get("version"),
                status=(payload.get("deviceInfos") or {}).get("status"),
                raw=payload,
                switches={},
            )
    return out
