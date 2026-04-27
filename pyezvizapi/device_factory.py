"""Helpers for constructing Ezviz device wrapper status objects."""

from __future__ import annotations

from typing import Any, cast

from .camera import EzvizCamera
from .light_bulb import EzvizLightBulb
from .smart_plug import EzvizSmartPlug


def camera_status(
    client: Any,
    serial: str,
    device_obj: dict[str, Any],
    *,
    refresh: bool,
    latest_alarm: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a camera wrapper and return its status mapping."""

    return cast(
        dict[str, Any],
        EzvizCamera(client, serial, device_obj).status(
            refresh=refresh,
            latest_alarm=latest_alarm,
        ),
    )


def light_bulb_status(
    client: Any,
    serial: str,
    device_obj: dict[str, Any],
) -> dict[str, Any]:
    """Build a light bulb wrapper and return its status mapping."""

    return EzvizLightBulb(client, serial, device_obj).status()


def smart_plug_status(
    client: Any,
    serial: str,
    device_obj: dict[str, Any],
) -> dict[str, Any]:
    """Build a smart plug wrapper and return its status mapping."""

    return EzvizSmartPlug(client, serial, device_obj).status()
