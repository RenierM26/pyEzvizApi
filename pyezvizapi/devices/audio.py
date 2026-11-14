"""EZVIZ chime, voice and microphone volume capability and update rules."""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from typing import TYPE_CHECKING, Any

from pyezvizapi.constants import SupportExt
from pyezvizapi.devices.controls import SupportExtView
from pyezvizapi.devices.features import (
    custom_voice_volume_config,
    optionals_mapping,
    resolve_channel,
)
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


def volume_capability(camera_data: dict[str, Any], key: SupportExt) -> bool:
    """Require an enabled numeric flag, never mere presence or truthiness."""
    value = SupportExtView.from_camera_data(camera_data).get(str(key.value))
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return False
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    # Native voice-volume UI requires 203 == 1; RN chime UI uses enabled 185.
    return value == 1 if key is SupportExt.SupportChangeVolume else value > 0


def volume_config(camera_data: dict[str, Any], key: str) -> dict[str, Any] | None:
    """Decode a complete reported volume object, retaining unrecognized fields."""
    config = optionals_mapping(camera_data).get(key)
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            return None
    return dict(config) if isinstance(config, Mapping) else None


def alarm_volume_max(camera_data: dict[str, Any]) -> float:
    """The app's DBScreen ChimeMusic slider is 0-7, not a percentage."""
    category = camera_data.get("device_category")
    if category is None and isinstance(infos := camera_data.get("deviceInfos"), Mapping):
        category = infos.get("deviceCategory")
    return 7 if category == "DBScreen" else 100


def alarm_volume_config(camera_data: dict[str, Any]) -> dict[str, Any] | None:
    """Return the reported alarm chime object without changing its payload."""
    return volume_config(camera_data, "ChimeMusic")


def reported_volume(config: dict[str, Any] | None, maximum: float) -> float | None:
    """Keep missing/invalid readings unknown, including boolean enable flags."""
    value = config.get("volume") if config else None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return float(value)


def alarm_volume_getter(camera_data: dict[str, Any]) -> float | None:
    """Require app-backed support as well as a valid observed chime value."""
    if not volume_capability(camera_data, SupportExt.SupportDeviceRing):
        return None
    return reported_volume(alarm_volume_config(camera_data), alarm_volume_max(camera_data))


def set_alarm_volume(
    client: EzvizClient,
    serial: str,
    value: float,
    camera_data: dict[str, Any],
) -> Any:
    """Update alarm volume while preserving reported sibling fields."""
    config = alarm_volume_config(camera_data)
    if config is None or alarm_volume_getter(camera_data) is None:
        raise PyEzvizError("Camera does not report a supported alarm chime volume")
    if isinstance(value, bool) or not math.isfinite(value):
        raise PyEzvizError("Alarm chime volume must be a finite number")
    payload = {
        **config,
        "volume": max(0, min(int(alarm_volume_max(camera_data)), round(value))),
    }
    return client.set_dev_config_kv(serial, resolve_channel(camera_data), "ChimeMusic", payload)


def alarm_voice_volume_getter(camera_data: dict[str, Any]) -> float | None:
    """Report voice volume independently of ChimeMusic and microphone gain."""
    if not volume_capability(camera_data, SupportExt.SupportChangeVolume):
        return None
    value = reported_volume(volume_config(camera_data, "CustomVoice_Volume"), 100)
    return None if value is not None and 0 < value < 10 else value


def set_alarm_voice_volume(
    client: EzvizClient,
    serial: str,
    value: float,
    camera_data: dict[str, Any],
) -> Any:
    """Update alarm voice volume while preserving reported sibling fields."""
    config = volume_config(camera_data, "CustomVoice_Volume")
    if config is None or alarm_voice_volume_getter(camera_data) is None:
        raise PyEzvizError("Camera does not report a supported alarm voice volume")
    # App voice sliders select 10-100. A reported zero remains a valid muted
    # reading, but changing volume must not silently select a sound mode.
    if isinstance(value, bool) or not math.isfinite(value) or not 10 <= value <= 100:
        raise PyEzvizError("Alarm voice volume must be between 10 and 100")
    return client.set_dev_config_kv(
        serial,
        resolve_channel(camera_data),
        "CustomVoice_Volume",
        {**config, "volume": round(value)},
    )


def microphone_volume_getter(camera_data: dict[str, Any]) -> float | None:
    config = custom_voice_volume_config(camera_data)
    if not config:
        return None
    value = config.get("microphone_volume")
    return (
        float(value)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100
        else None
    )


def set_microphone_volume(
    client: EzvizClient,
    serial: str,
    value: float,
    camera_data: dict[str, Any],
) -> Any:
    """Update microphone volume while preserving reported sibling fields."""
    config = volume_config(camera_data, "CustomVoice_Volume")
    if config is None or microphone_volume_getter(camera_data) is None:
        raise PyEzvizError("Camera does not report a microphone volume")
    if isinstance(value, bool) or not math.isfinite(value):
        raise PyEzvizError("Microphone volume must be a finite number")
    payload = {**config, "microphone_volume": max(0, min(100, round(value)))}

    return client.set_dev_config_kv(
        serial,
        resolve_channel(camera_data),
        "CustomVoice_Volume",
        payload,
    )
