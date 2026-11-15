"""Capability-qualified intercom controls, independent of Home Assistant.

Cloud device IDs are opaque: a composite ID is not a monitor relationship.
Only advertised local relays and observed settings are exposed. No streaming,
credential enrolment, linked-lock commands or inferred physical lock state.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pyezvizapi.constants import SupportExt
from pyezvizapi.devices.audio import alarm_volume_max, volume_config
from pyezvizapi.devices.capabilities import SupportExtView
from pyezvizapi.devices.features import resolve_channel
from pyezvizapi.devices.metadata import coerce_bool
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient

type ChimeField = Literal["doorbell_enable", "pir_enable", "volume", "doorbell", "pir"]
_BOOL_FIELDS = {"doorbell_enable", "pir_enable"}
_TONE_FIELDS = {"doorbell", "pir"}


def device_category(data: Mapping[str, Any]) -> str | None:
    """Read normalized or raw category without parsing model names."""
    info = data.get("deviceInfos")
    value = data.get("device_category")
    if value is None and isinstance(info, Mapping):
        value = info.get("deviceCategory")
    return value if isinstance(value, str) else None


def _supports_local_relays(data: Mapping[str, Any]) -> bool:
    support = SupportExtView.from_camera_data(dict(data)).get(
        str(SupportExt.SupportLocalLockGate.value)
    )
    return (
        device_category(data) == "BDoorBell" and type(support) in (int, str) and support in (1, "1")
    )


def is_intercom(data: Mapping[str, Any]) -> bool:
    """Identify monitors or local-relay intercoms, not every battery doorbell."""
    return device_category(data) == "DBScreen" or _supports_local_relays(data)


@dataclass(frozen=True)
class IntercomRelay:
    """A momentary local relay, not proof of an unlocked/open door."""

    name: Literal["door", "gate"]
    lock_no: int
    resource_identifier: str
    local_index: str


def _video_resource(data: Mapping[str, Any]) -> Mapping[str, Any] | None:
    resources = data.get("resourceInfos")
    if isinstance(resources, Mapping):
        resources = list(resources.values())
    if not isinstance(resources, list | tuple):
        return None
    matches = [
        row
        for row in resources
        if isinstance(row, Mapping) and row.get("resourceIdentifier") == "Video"
    ]
    if len(matches) != 1:
        return None
    index = matches[0].get("localIndex")
    if isinstance(index, bool) or not isinstance(index, int | str):
        return None
    if not str(index).isdecimal():
        return None
    return matches[0]


def intercom_relays(data: dict[str, Any]) -> tuple[IntercomRelay, ...]:
    """Use app capability 662, not linked-lock flags or DoorLockMgr presence."""
    if not _supports_local_relays(data):
        return ()
    resource = _video_resource(data)
    if resource is None:
        return ()
    index = str(resource["localIndex"])
    return (IntercomRelay("door", 2, "Video", index), IntercomRelay("gate", 1, "Video", index))


def unlock_intercom(
    client: EzvizClient, serial: str, relay: Literal["door", "gate"], data: dict[str, Any]
) -> bool:
    """Send one advertised relay command; never try a different physical relay."""
    target = next((item for item in intercom_relays(data) if item.name == relay), None)
    if target is None:
        raise PyEzvizError("Intercom does not advertise an unambiguous local relay")
    resource = _video_resource(data)
    assert resource is not None
    return client.remote_unlock(
        serial,
        str(client.export_token().get("username") or ""),
        target.lock_no,
        resource_id=target.resource_identifier,
        local_index=target.local_index,
        stream_token=resource.get("streamToken"),
        lock_type=resource.get("type") if isinstance(resource.get("type"), str) else None,
    )


def chime_value(data: dict[str, Any], field: ChimeField) -> bool | int | None:
    """Missing/invalid fields stay unknown; do not invent a complete ChimeMusic."""
    if not is_intercom(data) or not (config := volume_config(data, "ChimeMusic")):
        return None
    value = config.get(field)
    if field in _BOOL_FIELDS:
        return coerce_bool(value)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    if field == "volume" and value > alarm_volume_max(data):
        return None
    return value


def set_intercom_chime(
    client: EzvizClient,
    serial: str,
    field: ChimeField,
    value: bool | int,
    data: dict[str, Any],
) -> bool:
    """Patch a reported field in a detached complete config, preserving siblings.

    Tone IDs have no evidenced universal upper bound. Callers may set an ID
    supplied by their device/app; this API does not invent a catalogue.
    """
    if field not in _BOOL_FIELDS | _TONE_FIELDS | {"volume"} or chime_value(data, field) is None:
        raise PyEzvizError("Intercom does not report the requested chime setting")
    if field in _BOOL_FIELDS:
        if not isinstance(value, bool):
            raise PyEzvizError("Chime enable settings require a boolean")
        encoded: bool | int = int(value)
    else:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PyEzvizError("Chime setting requires a non-negative integer")
        if field == "volume" and value > alarm_volume_max(data):
            raise PyEzvizError(
                f"Intercom chime volume must be between 0 and {int(alarm_volume_max(data))}"
            )
        encoded = value
    config = deepcopy(volume_config(data, "ChimeMusic"))
    assert config is not None
    config[field] = encoded
    client.set_dev_config_kv(serial, resolve_channel(data), "ChimeMusic", config)
    return True


def _night_light(data: dict[str, Any]) -> bool | None:
    resource = _video_resource(data)
    feature = data.get("FEATURE_INFO")
    if resource is None or not isinstance(feature, Mapping):
        return None
    channel = feature.get(str(resource["localIndex"]))
    if not isinstance(channel, Mapping):
        return None
    video = channel.get("Video", channel)
    light = video.get("LightCtrl") if isinstance(video, Mapping) else None
    return coerce_bool(light.get("NightLightEnable")) if isinstance(light, Mapping) else None


def label_light_value(data: dict[str, Any]) -> bool | None:
    """Prefer the routed HPD7 property over the inert legacy 611 switch."""
    if device_category(data) != "BDoorBell":
        return None
    if (value := _night_light(data)) is not None:
        return value
    rows = data.get("SWITCH")
    if isinstance(rows, Mapping):
        rows = rows.get("switchStatusInfos")
    if not isinstance(rows, list | tuple):
        return None
    values = [
        coerce_bool(row.get("enable"))
        for row in rows
        if isinstance(row, Mapping) and row.get("type") in (611, "611")
    ]
    return values[0] if len(values) == 1 else None


def set_label_light(client: EzvizClient, serial: str, enable: bool, data: dict[str, Any]) -> bool:
    """Choose one observed light route; rejection is not a reason to try another."""
    if not isinstance(enable, bool) or label_light_value(data) is None:
        raise PyEzvizError("Intercom does not report a writable label light")
    if _night_light(data) is not None:
        resource = _video_resource(data)
        assert resource is not None
        client.set_iot_feature(
            serial,
            resource_identifier="Video",
            local_index=str(resource["localIndex"]),
            domain_id="LightCtrl",
            action_id="NightLightEnable",
            value={"value": enable},
        )
        return True
    return client.switch_status(serial, 611, enable)
