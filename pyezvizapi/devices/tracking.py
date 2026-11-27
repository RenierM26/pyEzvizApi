"""EZVIZ tracking helpers, independent of application lifecycle."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any, cast

from pyezvizapi._shared.utils import WILDCARD_STEP, decode_json, first_nested, iter_nested
from pyezvizapi.devices.metadata import coerce_bool
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient


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


def set_intelligent_app_config(
    client: EzvizClient,
    serial: str,
    app_id: str,
    *,
    resource_identifier: str,
    local_index: str,
    path: str,
    payload: str,
) -> None:
    """Write one app property using the reported resource, full app ID and encoded value."""
    if not all(
        isinstance(value, str) and value.strip()
        for value in (app_id, resource_identifier, local_index)
    ):
        raise PyEzvizError("App config requires a reported app ID and resource route")
    if not isinstance(path, str) or not path.startswith("/") or not path.strip("/").strip():
        raise PyEzvizError("App config requires an absolute property path")
    if not isinstance(payload, str):
        raise PyEzvizError("App config requires a device-encoded string payload")
    client.set_iot_action(
        serial,
        resource_identifier,
        local_index,
        "IntelligentAPP",
        "ModifyAppFunctionCfgs",
        {"value": {"configLists": [{"appId": app_id, "path": path, "payload": payload}]}},
    )


def set_app_auto_tracking(
    client: EzvizClient,
    serial: str,
    app_id: str,
    enabled: bool,
    *,
    resource_identifier: str = "Video",
    local_index: str = "1",
) -> None:
    """Set tracking for an app the caller verified is enabled and supports tracking."""
    if not isinstance(enabled, bool):
        raise PyEzvizError("App tracking state must be boolean")
    set_intelligent_app_config(
        client,
        serial,
        app_id,
        resource_identifier=resource_identifier,
        local_index=local_index,
        path="/PTZTrace/AutoTraceSwitch/prop",
        payload="true" if enabled else "false",
    )
