"""EZVIZ lens helpers, independent of application lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pyezvizapi._shared.utils import first_nested
from pyezvizapi.devices.channels import CameraChannelError, camera_channels
from pyezvizapi.devices.features import lens_defog_config

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient
    from pyezvizapi.devices.channels import CameraChannel


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
    *,
    channel: CameraChannel | None = None,
) -> None:
    """Update defogging for an explicit reported Video route, or keep legacy behavior."""

    if channel is None:
        config = lens_defog_config(camera_data)
        enabled, mode = client.set_lens_defog_mode(serial, value)
    else:
        if channel.resource_identifier != "Video" or channel not in camera_channels(camera_data):
            raise CameraChannelError("unsupported")
        config = first_nested(
            camera_data, ("FEATURE_INFO", channel.local_index, "Video", "LensCleaning", "DefogCfg")
        )
        if not isinstance(config, dict):
            raise CameraChannelError("unsupported")
        reported_mode = config.get("defogMode")
        if not isinstance(reported_mode, str) or not reported_mode.strip():
            raise CameraChannelError("unsupported")
        enabled, mode = client.set_lens_defog_mode(serial, value, local_index=channel.local_index)

    config["enabled"] = enabled
    config["defogMode"] = mode
