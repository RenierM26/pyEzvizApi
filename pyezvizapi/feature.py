"""Helpers for working with Ezviz feature metadata payloads."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any, cast

from .utils import coerce_int, decode_json


def _feature_video_section(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the nested Video feature section from feature info payload."""

    feature = camera_data.get("FEATURE_INFO")
    if not isinstance(feature, Mapping):
        return {}

    for group in feature.values():
        if isinstance(group, Mapping):
            video = group.get("Video")
            if isinstance(video, MutableMapping):
                return cast(dict[str, Any], video)

    return {}


def lens_defog_config(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the LensCleaning defog configuration if present."""

    video = _feature_video_section(camera_data)
    lens = video.get("LensCleaning") if isinstance(video, Mapping) else None
    if not isinstance(lens, MutableMapping):
        return {}

    config = lens.get("DefogCfg")
    if isinstance(config, MutableMapping):
        return cast(dict[str, Any], config)
    return {}


def lens_defog_value(camera_data: Mapping[str, Any]) -> int:
    """Return canonical defogging mode (0=auto,1=on,2=off)."""

    cfg = lens_defog_config(camera_data)
    if not cfg:
        return 0

    enabled = bool(cfg.get("enabled"))
    mode = str(cfg.get("defogMode") or "").lower()

    if not enabled:
        return 2

    if mode == "open":
        return 1

    return 0


def optionals_mapping(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return decoded optionals mapping from the camera payload."""

    status_info = camera_data.get("statusInfo")
    optionals: Any = None
    if isinstance(status_info, Mapping):
        optionals = status_info.get("optionals")

    optionals = decode_json(optionals)

    if not isinstance(optionals, Mapping):
        optionals = decode_json(camera_data.get("optionals"))

    if not isinstance(optionals, Mapping):
        status = camera_data.get("STATUS")
        if isinstance(status, Mapping):
            optionals = decode_json(status.get("optionals"))

    return dict(optionals) if isinstance(optionals, Mapping) else {}


def display_mode_value(camera_data: Mapping[str, Any]) -> int:
    """Return display mode value (1..3) from camera data."""

    optionals = optionals_mapping(camera_data)
    display_mode = optionals.get("display_mode")
    display_mode = decode_json(display_mode)

    if isinstance(display_mode, Mapping):
        mode = display_mode.get("mode")
    else:
        mode = display_mode

    if isinstance(mode, int) and mode in (1, 2, 3):
        return mode

    return 1


def device_icr_dss_config(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Decode and return the device_ICR_DSS configuration."""

    optionals = optionals_mapping(camera_data)
    icr = decode_json(optionals.get("device_ICR_DSS"))

    return dict(icr) if isinstance(icr, Mapping) else {}


def day_night_mode_value(camera_data: Mapping[str, Any]) -> int:
    """Return current day/night mode (0=auto,1=day,2=night)."""

    config = device_icr_dss_config(camera_data)
    mode = config.get("mode")
    if isinstance(mode, int) and mode in (0, 1, 2):
        return mode
    return 0


def day_night_sensitivity_value(camera_data: Mapping[str, Any]) -> int:
    """Return current day/night sensitivity value (1..3)."""

    config = device_icr_dss_config(camera_data)
    sensitivity = config.get("sensitivity")
    if isinstance(sensitivity, int) and sensitivity in (1, 2, 3):
        return sensitivity
    return 2


def resolve_channel(camera_data: Mapping[str, Any]) -> int:
    """Return the channel number to use for devconfig operations."""

    candidate = camera_data.get("channelNo") or camera_data.get("channel_no")
    if isinstance(candidate, int):
        return candidate
    if isinstance(candidate, str) and candidate.isdigit():
        return int(candidate)
    return 1


def night_vision_config(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return decoded NightVision_Model configuration mapping."""

    optionals = optionals_mapping(camera_data)
    config: Any = optionals.get("NightVision_Model")
    if config is None:
        config = camera_data.get("NightVision_Model")

    config = decode_json(config)

    return dict(config) if isinstance(config, Mapping) else {}


def night_vision_mode_value(camera_data: Mapping[str, Any]) -> int:
    """Return current night vision mode (0=BW,1=colour,2=smart,5=super)."""

    config = night_vision_config(camera_data)
    mode = coerce_int(config.get("graphicType"))
    if mode is None:
        return 0
    return mode if mode in (0, 1, 2, 5) else 0


def night_vision_luminance_value(camera_data: Mapping[str, Any]) -> int:
    """Return the configured night vision luminance (default 40)."""

    config = night_vision_config(camera_data)
    value = coerce_int(config.get("luminance"))
    if value is None:
        value = 40
    return max(0, value)


def night_vision_duration_value(camera_data: Mapping[str, Any]) -> int:
    """Return the configured smart night vision duration (default 60)."""

    config = night_vision_config(camera_data)
    value = coerce_int(config.get("duration"))
    return value if value is not None else 60


def night_vision_payload(
    camera_data: Mapping[str, Any],
    *,
    mode: int | None = None,
    luminance: int | None = None,
    duration: int | None = None,
) -> dict[str, Any]:
    """Return a sanitized NightVision_Model payload for updates."""

    config = dict(night_vision_config(camera_data))

    resolved_mode = (
        int(mode)
        if mode is not None
        else int(config.get("graphicType") or night_vision_mode_value(camera_data))
    )
    config["graphicType"] = resolved_mode

    if luminance is None:
        luminance_value = night_vision_luminance_value(camera_data)
    else:
        coerced_luminance = coerce_int(luminance)
        luminance_value = (
            coerced_luminance
            if coerced_luminance is not None
            else night_vision_luminance_value(camera_data)
        )
    if resolved_mode == 1:
        config["luminance"] = 0 if luminance_value <= 0 else max(20, luminance_value)
    elif resolved_mode == 2:
        config["luminance"] = max(
            20,
            luminance_value if luminance_value > 0 else 40,
        )
    else:
        config["luminance"] = max(0, luminance_value)

    if duration is None:
        duration_value = night_vision_duration_value(camera_data)
    else:
        coerced_duration = coerce_int(duration)
        duration_value = (
            coerced_duration
            if coerced_duration is not None
            else night_vision_duration_value(camera_data)
        )
    if resolved_mode == 2:
        config["duration"] = max(15, min(120, duration_value))
    else:
        config.pop("duration", None)

    return config


def has_osd_overlay(camera_data: Mapping[str, Any]) -> bool:
    """Return True when the camera has an active OSD label."""

    optionals = optionals_mapping(camera_data)
    osd_entries = optionals.get("OSD")

    if isinstance(osd_entries, Mapping):
        entries: list[Mapping[str, Any]] = [osd_entries]
    elif isinstance(osd_entries, list):
        entries = [entry for entry in osd_entries if isinstance(entry, Mapping)]
    else:
        return False

    for entry in entries:
        name = entry.get("name")
        if isinstance(name, str) and name.strip():
            return True
    return False
