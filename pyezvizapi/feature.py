"""Helpers for working with Ezviz feature metadata payloads."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from typing import Any, cast

from .utils import WILDCARD_STEP, coerce_int, decode_json, first_nested


def _feature_video_section(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the nested Video feature section from feature info payload."""

    video = first_nested(
        camera_data,
        ("FEATURE_INFO", WILDCARD_STEP, "Video"),
    )
    if isinstance(video, MutableMapping):
        return cast(dict[str, Any], video)
    return {}


def supplement_light_params(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return SupplementLightMgr parameters if present."""

    video = _feature_video_section(camera_data)
    if not video:
        return {}

    manager: Any = video.get("SupplementLightMgr")
    manager = decode_json(manager)
    if not isinstance(manager, Mapping):
        return {}

    params: Any = manager.get("ImageSupplementLightModeSwitchParams")
    params = decode_json(params)
    return dict(params) if isinstance(params, Mapping) else {}


def supplement_light_enabled(camera_data: Mapping[str, Any]) -> bool:
    """Return True when intelligent fill light is enabled."""

    params = supplement_light_params(camera_data)
    if not params:
        return False

    enabled = params.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, str):
        lowered = enabled.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    return bool(enabled)


def supplement_light_available(camera_data: Mapping[str, Any]) -> bool:
    """Return True when intelligent fill light parameters are present."""

    return bool(supplement_light_params(camera_data))


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


def optionals_dict(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return convenience wrapper for optionals mapping."""

    return optionals_mapping(camera_data)


def custom_voice_volume_config(camera_data: Mapping[str, Any]) -> dict[str, int] | None:
    """Return current CustomVoice volume configuration."""

    optionals = optionals_mapping(camera_data)
    config = optionals.get("CustomVoice_Volume")
    config = decode_json(config)
    if not isinstance(config, Mapping):
        return None

    volume = coerce_int(config.get("volume"))
    mic = coerce_int(config.get("microphone_volume"))
    result: dict[str, int] = {}
    if isinstance(volume, int):
        result["volume"] = volume
    if isinstance(mic, int):
        result["microphone_volume"] = mic
    return result or None


def iter_algorithm_entries(camera_data: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield entries from the AlgorithmInfo optionals list."""

    entries = optionals_dict(camera_data).get("AlgorithmInfo")
    if not isinstance(entries, Iterable):
        return
    for entry in entries:
        if isinstance(entry, Mapping):
            yield dict(entry)


def iter_channel_algorithm_entries(
    camera_data: Mapping[str, Any], channel: int
) -> Iterator[dict[str, Any]]:
    """Yield AlgorithmInfo entries filtered by channel."""

    for entry in iter_algorithm_entries(camera_data):
        entry_channel = coerce_int(entry.get("channel")) or 1
        if entry_channel == channel:
            yield entry


def get_algorithm_value(
    camera_data: Mapping[str, Any], subtype: str, channel: int
) -> int | None:
    """Return AlgorithmInfo value for provided subtype/channel."""

    for entry in iter_channel_algorithm_entries(camera_data, channel):
        if entry.get("SubType") != subtype:
            continue
        return coerce_int(entry.get("Value"))
    return None


def has_algorithm_subtype(
    camera_data: Mapping[str, Any], subtype: str, channel: int = 1
) -> bool:
    """Return True when AlgorithmInfo contains subtype for channel."""

    return get_algorithm_value(camera_data, subtype, channel) is not None


def support_ext_value(camera_data: Mapping[str, Any], ext_key: str) -> str | None:
    """Fetch a supportExt entry as a string when present."""

    raw = camera_data.get("supportExt")
    if not isinstance(raw, Mapping):
        device_infos = camera_data.get("deviceInfos")
        if isinstance(device_infos, Mapping):
            raw = device_infos.get("supportExt")

    if not isinstance(raw, Mapping):
        return None

    value = raw.get(ext_key)
    return str(value) if value is not None else None


def _normalize_port_list(value: Any) -> list[dict[str, Any]] | None:
    """Decode a list of port-security entries."""

    value = decode_json(value)
    if not isinstance(value, Iterable):
        return None

    normalized: list[dict[str, Any]] = []
    for raw_entry in value:
        entry = decode_json(raw_entry)
        if not isinstance(entry, Mapping):
            return None
        port = coerce_int(entry.get("portNo"))
        if port is None:
            continue
        normalized.append({"portNo": port, "enabled": bool(entry.get("enabled"))})

    return normalized


def normalize_port_security(payload: Any) -> dict[str, Any]:
    """Normalize IoT port-security payloads."""

    seen: set[int] = set()

    def _apply_hint(
        candidate: dict[str, Any] | None, hint_value: bool | None
    ) -> dict[str, Any] | None:
        if (
            candidate is not None
            and "enabled" not in candidate
            and isinstance(hint_value, bool)
        ):
            candidate["enabled"] = hint_value
        return candidate

    def _walk_mapping(obj: Mapping[str, Any], hint: bool | None) -> dict[str, Any] | None:
        obj_id = id(obj)
        if obj_id in seen:
            return None
        seen.add(obj_id)

        enabled_local = obj.get("enabled")
        if isinstance(enabled_local, bool):
            hint = enabled_local

        ports = _normalize_port_list(obj.get("portSecurityList"))
        if ports is not None:
            return {
                "portSecurityList": ports,
                "enabled": bool(enabled_local)
                if isinstance(enabled_local, bool)
                else bool(hint)
                if isinstance(hint, bool)
                else True,
            }

        for key in ("PortSecurity", "value", "data", "NetworkSecurityProtection"):
            if key in obj:
                candidate = _apply_hint(_walk(obj[key], hint), hint)
                if candidate:
                    return candidate

        for value in obj.values():
            candidate = _apply_hint(_walk(value, hint), hint)
            if candidate:
                return candidate

        return None

    def _walk_iterable(values: Iterable[Any], hint: bool | None) -> dict[str, Any] | None:
        for item in values:
            candidate = _walk(item, hint)
            if candidate:
                return candidate
        return None

    def _walk(obj: Any, hint: bool | None = None) -> dict[str, Any] | None:
        obj = decode_json(obj)
        if obj is None:
            return None

        if isinstance(obj, Mapping):
            return _walk_mapping(obj, hint)

        if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes, bytearray)):
            return _walk_iterable(obj, hint)

        return None

    normalized = _walk(payload)
    if isinstance(normalized, dict):
        normalized.setdefault("enabled", True)
        return normalized
    return {}


def port_security_config(camera_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the normalized port-security mapping for a camera payload."""

    direct = camera_data.get("NetworkSecurityProtection")
    normalized = normalize_port_security(direct)
    if normalized:
        return normalized

    feature = camera_data.get("FEATURE_INFO")
    if isinstance(feature, Mapping):
        normalized = normalize_port_security(feature)
        if normalized:
            return normalized

    return {}


def port_security_has_port(camera_data: Mapping[str, Any], port: int) -> bool:
    """Return True if the normalized config contains the port."""

    ports = port_security_config(camera_data).get("portSecurityList")
    if not isinstance(ports, Iterable):
        return False
    return any(
        isinstance(entry, Mapping) and coerce_int(entry.get("portNo")) == port
        for entry in ports
    )


def port_security_port_enabled(camera_data: Mapping[str, Any], port: int) -> bool:
    """Return True if the specific port is enabled."""

    ports = port_security_config(camera_data).get("portSecurityList")
    if not isinstance(ports, Iterable):
        return False
    for entry in ports:
        if isinstance(entry, Mapping) and coerce_int(entry.get("portNo")) == port:
            return bool(entry.get("enabled"))
    return False


def display_mode_value(camera_data: Mapping[str, Any]) -> int:
    """Return display mode value (1..3) from camera data."""

    optionals = optionals_mapping(camera_data)
    display_mode = optionals.get("display_mode")
    display_mode = decode_json(display_mode)

    mode = (
        display_mode.get("mode") if isinstance(display_mode, Mapping) else display_mode
    )

    if isinstance(mode, int) and mode in (1, 2, 3):
        return mode

    return 1


def blc_current_value(camera_data: Mapping[str, Any]) -> int:
    """Return BLC position (0..5) from camera data. 0 = Off."""
    optionals = optionals_mapping(camera_data)
    inverse_mode = optionals.get("inverse_mode")
    inverse_mode = decode_json(inverse_mode)

    # Expected: {"mode": int, "enable": 0|1, "position": 0..5}
    if isinstance(inverse_mode, Mapping):
        enable = inverse_mode.get("enable", 0)
        position = inverse_mode.get("position", 0)
        if (
            isinstance(enable, int)
            and enable == 1
            and isinstance(position, int)
            and position in (1, 2, 3, 4, 5)
        ):
            return position
        return 0

    # Fallbacks if backend ever returns a bare int (position) instead of the object
    if isinstance(inverse_mode, int) and inverse_mode in (0, 1, 2, 3, 4, 5):
        return inverse_mode

    # Default to Off
    return 0


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
