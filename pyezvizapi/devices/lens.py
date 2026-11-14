"""EZVIZ lens helpers, independent of application lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pyezvizapi.devices.features import lens_defog_config

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


def has_lens_defog(camera_data: dict[str, Any]) -> bool:
    """Return True when this camera exposes a usable lens-defog configuration."""

    config = lens_defog_config(camera_data)
    mode = config.get("defogMode")
    return isinstance(mode, str) and bool(mode.strip())


def set_lens_defog_option(
    client: EzvizClient,
    serial: str,
    value: int,
    camera_data: dict[str, Any],
) -> None:
    """Persist lens-defog mode through the API and update cached data."""

    enabled, mode = client.set_lens_defog_mode(serial, value)

    config = lens_defog_config(camera_data)
    if isinstance(config, dict):
        config["enabled"] = enabled
        config["defogMode"] = mode
