"""Vendor capability readers and feature controls, independent of Home Assistant."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from pyezvizapi.feature import (
    lens_defog_config,
    normalize_port_security,
    port_security_config,
    port_security_has_port,
    port_security_port_enabled,
)

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


from pyezvizapi.utils import WILDCARD_STEP, decode_json, first_nested, iter_nested


def coerce_int(value: Any) -> int | None:
    """Best-effort coercion to int for mixed API payloads."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


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


class SupportExtView:
    """Lightweight helper for inspecting supportExt capabilities."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any] | None = None) -> None:
        """Store a normalized copy of the provided supportExt mapping."""
        self._data: dict[str, Any] = dict(data) if isinstance(data, Mapping) else {}

    @classmethod
    def from_camera_data(cls, camera_data: Mapping[str, Any]) -> SupportExtView:
        """Build a view from raw camera payload."""

        support_ext = camera_data.get("supportExt")
        if not isinstance(support_ext, Mapping):
            device_infos = camera_data.get("deviceInfos")
            if isinstance(device_infos, Mapping):
                support_ext = device_infos.get("supportExt")
        return cls(support_ext if isinstance(support_ext, Mapping) else None)

    def as_dict(self) -> dict[str, Any]:
        """Return the underlying mapping."""

        return self._data

    def get(self, key: str, default: Any | None = None) -> Any | None:
        """Fetch a raw supportExt value."""

        return self._data.get(key, default)

    @staticmethod
    def _tokens(value: Any) -> set[str]:
        """Return comma-delimited tokens from a raw supportExt value."""
        if value is None:
            return set()
        return {token.strip() for token in str(value).split(",") if token.strip()}

    @staticmethod
    def normalize_values(values: Iterable[str] | None) -> tuple[str, ...]:
        """Normalize candidate values to a tuple of stripped strings."""
        if values is None:
            return ()
        return tuple(stripped for stripped in (str(raw).strip() for raw in values) if stripped)

    @classmethod
    def _values_match(cls, raw_value: Any, expected_values: tuple[str, ...]) -> bool:
        """Return True if ``raw_value`` satisfies normalized candidates."""

        if not expected_values:
            return True

        raw_str = str(raw_value).strip()
        if not raw_str:
            return False

        if raw_str in expected_values:
            return True

        raw_tokens = cls._tokens(raw_value)
        if not raw_tokens:
            raw_tokens = {raw_str}

        for candidate in expected_values:
            candidate_tokens = cls._tokens(candidate)
            if candidate_tokens and candidate_tokens <= raw_tokens:
                return True

        return False

    def match_any(self, keys: Iterable[str], normalized_values: tuple[str, ...]) -> bool:
        """Return True if any key exists (and matches optional values)."""

        for key in keys:
            raw_value = self._data.get(key)
            if raw_value is None:
                continue
            if not normalized_values:
                return True
            if self._values_match(raw_value, normalized_values):
                return True
        return False

    def has(self, key: str, expected_values: Iterable[str] | None = None) -> bool:
        """Check if the given key (and optional values) exist."""

        if not expected_values:
            normalized: tuple[str, ...] = ()
        else:
            normalized = self.normalize_values(expected_values)
            if not normalized:
                return False
        return self.match_any((key,), normalized)


def support_ext_dict(camera_data: dict[str, Any]) -> dict[str, Any]:
    """Return supportExt mapping if present."""

    return SupportExtView.from_camera_data(camera_data).as_dict()


def support_ext_has(
    camera_data: dict[str, Any], key: str, expected_values: list[str] | None = None
) -> bool:
    """Check if supportExt contains the key (and optional values)."""
    view = SupportExtView.from_camera_data(camera_data)
    return view.has(key, expected_values)


def ptz_master_slave_trace(camera_data: dict[str, Any]) -> dict[str, Any]:
    """Return the PTZ master/slave trace section if present."""

    for trace in iter_nested(
        camera_data,
        ("FEATURE_INFO", WILDCARD_STEP, "Video", "PTZMasterSlaveTrace"),
    ):
        if isinstance(trace, dict):
            return trace
    return {}


def ensure_ptz_master_slave_trace(camera_data: dict[str, Any]) -> dict[str, Any]:
    """Ensure PTZ master/slave trace section exists and return it."""

    feature_info = camera_data.setdefault("FEATURE_INFO", {})
    video_section = next(
        (
            video
            for video in iter_nested(camera_data, ("FEATURE_INFO", WILDCARD_STEP, "Video"))
            if isinstance(video, dict)
        ),
        None,
    )

    if video_section is None:
        group = feature_info.setdefault("1", {})
        if not isinstance(group, dict):
            feature_info["1"] = {}
            group = feature_info["1"]
        video_section = group.setdefault("Video", {})
        if not isinstance(video_section, dict):
            group["Video"] = {}
            video_section = group["Video"]

    trace = video_section.setdefault("PTZMasterSlaveTrace", {})
    if not isinstance(trace, dict):
        video_section["PTZMasterSlaveTrace"] = {}
        trace = video_section["PTZMasterSlaveTrace"]

    return cast(dict[str, Any], trace)


def linked_tracking_takeover_enabled(camera_data: dict[str, Any]) -> bool:
    """Return True if linked tracking takeover is enabled."""

    trace = ptz_master_slave_trace(camera_data)
    cfg = trace.get("LinkedTrackingAdvancedCfg")
    if not isinstance(cfg, dict):
        return False
    value = coerce_bool(cfg.get("trackingTakeoverEnabled"))
    return bool(value) if value is not None else False


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


def set_linked_tracking_takeover(
    client: EzvizClient,
    serial: str,
    enabled: bool,
    camera_data: dict[str, Any],
) -> None:
    """Persist linked-tracking takeover preference."""

    payload = {"value": {"trackingTakeoverEnabled": bool(enabled)}}
    client.set_iot_feature(
        serial,
        "Video",
        "1",
        "PTZMasterSlaveTrace",
        "LinkedTrackingAdvancedCfg",
        payload,
    )


def _reported_port_security(payload: Any) -> dict[str, Any]:
    """Find a reported port object without dropping vendor extension fields."""
    seen: set[int] = set()

    def visit(value: Any, enabled_hint: bool | None = None) -> dict[str, Any]:
        value = decode_json(value)
        if not isinstance(value, (dict, list)) or id(value) in seen:
            return {}
        seen.add(id(value))
        children: Iterable[Any]
        if isinstance(value, dict):
            if isinstance(value.get("enabled"), bool):
                enabled_hint = value["enabled"]
            ports = decode_json(value.get("portSecurityList"))
            if isinstance(ports, list):
                decoded = [decode_json(entry) for entry in ports]
                if all(isinstance(entry, dict) for entry in decoded):
                    result = {**deepcopy(value), "portSecurityList": deepcopy(decoded)}
                    if "enabled" not in result and enabled_hint is not None:
                        result["enabled"] = enabled_hint
                    return result
                return {}
            children = value.values()
        else:
            children = value
        for child in children:
            if result := visit(child, enabled_hint):
                return result
        return {}

    return visit(payload)


def _load_port_security_payload(client: EzvizClient, serial: str) -> dict[str, Any]:
    """Fetch or synthesize a normalized port-security payload."""
    response = client.get_port_security(serial)
    value: dict[str, Any] = {}
    if isinstance(response, dict):
        value = _reported_port_security(response) or deepcopy(normalize_port_security(response))

    if not value:
        camera_state = getattr(client, "_cameras", {}).get(serial)
        if isinstance(camera_state, dict):
            value = _reported_port_security(camera_state) or deepcopy(
                port_security_config(camera_state)
            )

    if not value:
        value = {"portSecurityList": []}

    ports = value.get("portSecurityList")
    if not isinstance(ports, list):
        ports = []
    value["portSecurityList"] = ports

    if "enabled" not in value:
        value["enabled"] = True

    return value


def set_port_security_ports(
    client: EzvizClient, serial: str, ports: tuple[int, ...], enable: int
) -> None:
    """Toggle multiple secure ports in the cached payload and persist it."""
    value = _load_port_security_payload(client, serial)
    entries = value["portSecurityList"]
    if len(ports) == 1:
        for entry in entries:
            if isinstance(entry, dict) and coerce_int(entry.get("portNo")) == ports[0]:
                entry["enabled"] = bool(enable)
                break
        else:
            entries.append({"portNo": ports[0], "enabled": bool(enable)})
        client.set_port_security(serial, value)
        return

    port_map: dict[int, dict[str, Any]] = {}

    for entry in entries:
        if isinstance(entry, dict):
            port_no = coerce_int(entry.get("portNo"))
            if port_no is not None:
                port_map[port_no] = entry

    for port in ports:
        entry = port_map.get(port)
        if entry is None:
            entry = {"portNo": port}
            entries.append(entry)
            port_map[port] = entry
        entry["enabled"] = bool(enable)

    client.set_port_security(serial, value)


@dataclass(frozen=True)
class PortSecurityToggle:
    """Bundle availability/value/set operations for secure ports."""

    ports: tuple[int, ...]

    @classmethod
    def single(cls, port: int) -> PortSecurityToggle:
        """Create a toggle for a single port."""

        return cls((port,))

    def _present_ports(self, camera_data: dict[str, Any]) -> list[int]:
        return [port for port in self.ports if port_security_has_port(camera_data, port)]

    def is_supported(self, camera_data: dict[str, Any]) -> bool:
        """Return True if any of the toggle's ports exist on the device."""

        return bool(self._present_ports(camera_data))

    def current_value(self, camera_data: dict[str, Any]) -> bool:
        """Return True if the toggle should be considered enabled."""

        present = self._present_ports(camera_data)
        if not present:
            return False

        if len(self.ports) == 1:
            return bool(port_security_port_enabled(camera_data, self.ports[0]))

        return any(port_security_port_enabled(camera_data, port) for port in present)

    def apply(self, client: EzvizClient, serial: str, enable: int) -> None:
        """Persist the toggle state through the API."""

        set_port_security_ports(client, serial, self.ports, enable)


def intelligent_app_value_fn(app_name: str) -> Callable[[dict[str, Any]], bool]:
    """Return a value extractor for an intelligent app."""

    def _value(camera_data: dict[str, Any]) -> bool:
        return intelligent_app_enabled(camera_data, app_name)

    return _value


def intelligent_app_method(app_name: str) -> Callable[[EzvizClient, str, int], bool]:
    """Return a setter callable for an intelligent app."""

    def _method(client: EzvizClient, serial: str, enable: int) -> bool:
        return bool(client.set_intelligent_app_state(serial, app_name, bool(enable)))

    return _method


def _decode_mapping(value: Any) -> dict[str, Any] | None:
    """Return a dict after best-effort JSON decoding."""

    decoded = decode_json(value)
    candidate = decoded if decoded is not None else value
    return candidate if isinstance(candidate, dict) else None


def _decode_list(value: Any) -> list[Any] | None:
    """Return a list after best-effort JSON decoding."""

    decoded = decode_json(value)
    candidate = decoded if decoded is not None else value
    return candidate if isinstance(candidate, list) else None


def iter_intelligent_apps(camera_data: dict[str, Any]) -> Iterator[tuple[str, bool]]:
    """Yield (app_name, enabled) pairs for intelligent apps."""

    intelligent_app = first_nested(
        camera_data, ("FEATURE_INFO", WILDCARD_STEP, "Video", "IntelligentAPP")
    )
    if intelligent_app is None:
        intelligent_app = first_nested(
            camera_data, ("FEATURE_INFO", WILDCARD_STEP, "IntelligentAPP")
        )
    intelligent_app = _decode_mapping(intelligent_app)
    if intelligent_app is None:
        return

    downloaded = _decode_mapping(intelligent_app.get("DownloadedAPP"))
    if downloaded is None:
        return

    apps = _decode_list(downloaded.get("APP", []))
    if apps is None:
        return

    for app in apps:
        if not isinstance(app, dict):
            continue
        raw_app_id = app.get("APPID")
        if not isinstance(raw_app_id, str):
            continue
        base = raw_app_id.split("$:$", 1)[0]
        yield base, bool(app.get("enabled"))


def intelligent_app_enabled(camera_data: dict[str, Any], app_name: str) -> bool:
    """Return True if the given intelligent app is enabled."""

    for name, enabled in iter_intelligent_apps(camera_data) or []:
        if name == app_name:
            return enabled
    return False


def intelligent_app_available(camera_data: dict[str, Any], app_name: str) -> bool:
    """Return True if the intelligent app is present in the payload."""

    return any(name == app_name for name, _enabled in iter_intelligent_apps(camera_data) or [])
