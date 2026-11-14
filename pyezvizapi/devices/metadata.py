"""EZVIZ metadata helpers, independent of application lifecycle."""

from __future__ import annotations

from typing import Any

from pyezvizapi._shared.coercion import coerce_int as _shared_coerce_int


def coerce_int(value: Any) -> int | None:
    """Best-effort coercion to int for mixed API payloads."""
    # Preserve the extracted API's numeric exceptions (NaN/infinity). The shared
    # helper is deliberately more tolerant; do not silently change this contract.
    if isinstance(value, (int, float)):
        return int(value)
    return _shared_coerce_int(value)


def coerce_bool(value: Any) -> bool | None:
    """Best-effort coercion to bool for common EZVIZ payload styles."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 0:
            return False
        if value == 1:
            return True
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _wifi_section(camera_data: dict[str, Any]) -> dict[str, Any] | None:
    """Return the WIFI sub-mapping when present."""
    wifi_data = camera_data.get("WIFI")
    if isinstance(wifi_data, dict):
        return wifi_data
    return None


def wifi_ssid_value(camera_data: dict[str, Any]) -> str | None:
    """Return Wi-Fi SSID if provided."""
    wifi_data = _wifi_section(camera_data)
    if wifi_data is None:
        return None
    ssid = wifi_data.get("ssid")
    return ssid if isinstance(ssid, str) and ssid else None


def wifi_signal_value(camera_data: dict[str, Any]) -> int | None:
    """Return Wi-Fi signal strength percentage when an SSID is present."""
    wifi_data = _wifi_section(camera_data)
    if wifi_data is None:
        return None
    if not wifi_ssid_value(camera_data):
        return None
    return coerce_int(wifi_data.get("signal"))


def network_type_value(camera_data: dict[str, Any]) -> str | None:
    """Return network type (ethernet/wifi/other) if known."""
    wifi_data = _wifi_section(camera_data)
    if wifi_data is None:
        return None
    net_type = wifi_data.get("netType")
    if not isinstance(net_type, str) or not net_type:
        return None

    lowered = net_type.lower()
    if lowered == "wire":
        return "ethernet"
    if lowered == "wireless":
        return "wifi"
    return lowered


def sd_card_capacity_gb(camera_data: dict[str, Any]) -> float | None:
    """Return SD card capacity in gibibytes, if provided."""
    capacity = camera_data.get("diskCapacity")

    if isinstance(capacity, list):
        candidate = capacity[0] if capacity else None
    elif isinstance(capacity, str):
        candidate = capacity.split(",", 1)[0]
    else:
        candidate = capacity

    size_mb = coerce_int(candidate)
    if size_mb is None or size_mb <= 0:
        return None

    gb_value = size_mb / 1024
    return round(gb_value, 2)
