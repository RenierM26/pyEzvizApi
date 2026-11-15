"""Indoor-monitor rendering leaf; no actuator/client/stream dependencies."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from pyezvizapi.models import EzvizDeviceRecord


def monitor_status(serial: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Render a DBScreen without camera defaults, previews or alarm requests."""
    record = EzvizDeviceRecord.from_api(serial, raw)
    return {
        **deepcopy(raw),
        "serial": serial,
        "name": record.name or serial,
        "version": record.version,
        "status": record.status,
        "device_category": record.device_category,
        "device_sub_category": record.device_sub_category,
        "supportExt": dict(record.support_ext or {}),
        "optionals": deepcopy((raw.get("STATUS") or {}).get("optionals")),
    }
