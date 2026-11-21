"""EZVIZ lens helpers, independent of application lifecycle."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pyezvizapi._shared.utils import first_nested
from pyezvizapi.devices.channels import CameraChannelError, camera_channels
from pyezvizapi.devices.features import lens_defog_config

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient
    from pyezvizapi.devices.channels import CameraChannel


def _usable_defog_config(config: object) -> bool:
    if not isinstance(config, dict):
        return False
    mode = config.get("defogMode")
    return isinstance(mode, str) and bool(mode.strip())


def _scoped_defog_config(
    camera_data: dict[str, Any], channel: CameraChannel
) -> dict[str, Any] | None:
    if channel.resource_identifier != "Video" or channel not in camera_channels(camera_data):
        return None
    config = first_nested(
        camera_data, ("FEATURE_INFO", channel.local_index, "Video", "LensCleaning", "DefogCfg")
    )
    return config if _usable_defog_config(config) else None


def has_lens_defog(camera_data: dict[str, Any], *, channel: CameraChannel | None = None) -> bool:
    """Check for usable defog state; an explicit channel must have a supported route."""

    if channel is not None:
        return _scoped_defog_config(camera_data, channel) is not None
    return _usable_defog_config(lens_defog_config(camera_data))


def set_lens_defog_option(
    client: EzvizClient,
    serial: str,
    value: int,
    camera_data: dict[str, Any],
    *,
    channel: CameraChannel | None = None,
) -> None:
    """Update defogging for an explicit reported Video route, or keep legacy behavior."""

    config: dict[str, Any] | None
    if channel is None:
        config = lens_defog_config(camera_data)
        enabled, mode = client.set_lens_defog_mode(serial, value)
    else:
        config = _scoped_defog_config(camera_data, channel)
        if config is None:
            raise CameraChannelError("unsupported")
        enabled, mode = client.set_lens_defog_mode(serial, value, local_index=channel.local_index)

    config["enabled"] = enabled
    config["defogMode"] = mode
