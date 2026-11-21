"""Reported camera channels and command routing, with no application lifecycle.

Cloud resources, RTSP paths and image records are distinct namespaces. Never
derive an RTSP path or a physical fixed/moving lens from a cloud resource name.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from typing import Any, Literal

from pyezvizapi.devices.capabilities import SupportExtView
from pyezvizapi.exceptions import PyEzvizError

_VIDEO = re.compile(r"Video(?:_[0-9]+)?")
_INDEX = re.compile(r"0|[1-9][0-9]{0,5}")
DIRECT_POINT_ROUTE = ("Video_1", "1")


class CameraChannelError(PyEzvizError):
    """An unproven route must not be replaced with a different camera channel."""

    def __init__(
        self,
        reason: Literal["unsupported", "selection_required", "unavailable", "invalid", "ambiguous"],
    ) -> None:
        self.reason = reason
        super().__init__(f"Camera channel routing failed: {reason}")


@dataclass(frozen=True, slots=True)
class CameraChannel:
    """Stable reported video route, not a positional lens or stream-quality ID."""

    resource_identifier: str
    local_index: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.resource_identifier, str)
            or not isinstance(self.local_index, str)
            or not _VIDEO.fullmatch(self.resource_identifier)
            or not _INDEX.fullmatch(self.local_index)
        ):
            raise CameraChannelError("invalid")

    @property
    def key(self) -> str:
        """Keep resource identity when a channel disappears or metadata reorders."""
        return f"{self.resource_identifier}:{self.local_index}"

    @property
    def channel_no(self) -> int:
        """The app resolves play/devconfig channels through this local index."""
        return int(self.local_index)


def _local_index(value: object) -> str | None:
    if type(value) is int and 0 <= value <= 999_999:
        return str(value)
    if isinstance(value, str) and _INDEX.fullmatch(value):
        return value
    return None


def _channels(data: Mapping[str, Any]) -> tuple[CameraChannel, ...]:
    rows = data.get("resourceInfos", ())
    if not isinstance(rows, (list, tuple)):
        raise CameraChannelError("invalid")
    found: dict[str, CameraChannel] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        resource = row.get("resourceIdentifier")
        if not isinstance(resource, str) or not _VIDEO.fullmatch(resource):
            continue
        index = _local_index(row.get("localIndex"))
        if index is None:
            raise CameraChannelError("invalid")
        channel = CameraChannel(resource, index)
        if index in found and found[index] != channel:
            raise CameraChannelError("ambiguous")
        found[index] = channel
    return tuple(sorted(found.values(), key=lambda item: (item.channel_no, item.key)))


def camera_channels(data: Mapping[str, Any]) -> tuple[CameraChannel, ...]:
    """Discover only unambiguous routes; malformed metadata adds no child entity."""
    try:
        return _channels(data)
    except CameraChannelError:
        return ()


def reported_video_channel_numbers(data: Mapping[str, Any]) -> tuple[int, ...]:
    """Return reported video indexes without inventing command resource names."""
    rows = data.get("resourceInfos", ())
    if not isinstance(rows, (list, tuple)):
        return ()
    numbers: set[int] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        resource = row.get("resourceIdentifier")
        resource_type = row.get("resourceType")
        named_video = isinstance(resource, str) and _VIDEO.fullmatch(resource)
        anonymous_video = (
            resource in (None, "") and type(resource_type) is int and resource_type == 50
        )
        if named_video or anonymous_video:
            index = _local_index(row.get("localIndex"))
            if index is None:
                return ()
            numbers.add(int(index))
    return tuple(sorted(numbers))


def resolve_camera_channel(data: Mapping[str, Any], key: str) -> CameraChannel:
    """Re-resolve a stable identity against current metadata before any command."""
    for channel in _channels(data):
        if channel.key == key:
            return channel
    raise CameraChannelError("unavailable")


def capture_channel_number(data: Mapping[str, Any], channel_key: str | None = None) -> int:
    """Preserve the device capture default, or use the exact reported channel."""
    return 1 if channel_key is None else resolve_camera_channel(data, channel_key).channel_no


def _enabled(capabilities: SupportExtView, flag: str) -> bool:
    value = capabilities.get(flag)
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return False
    return type(value) is int and value == 1


def point_ptz_route(
    data: Mapping[str, Any], lens: str = "auto", *, channel_key: str | None = None
) -> tuple[str, str]:
    """Apply app-backed direct586/selected724 rules independently of HA."""
    capabilities = SupportExtView.from_camera_data(data)
    direct, locate = _enabled(capabilities, "586"), _enabled(capabilities, "724")
    if not direct and not locate:
        raise CameraChannelError("unsupported")
    if channel_key is not None:
        selected = resolve_camera_channel(data, channel_key)
        if lens not in ("auto", selected.local_index):
            raise CameraChannelError("unavailable")
        route = (selected.resource_identifier, selected.local_index)
        if locate or (direct and route == DIRECT_POINT_ROUTE):
            return route
        raise CameraChannelError("unsupported")
    if direct and (lens == "auto" or (not locate and lens == "1")):
        return DIRECT_POINT_ROUTE
    if not locate:
        raise CameraChannelError("unavailable")
    try:
        channels = _channels(data)
    except CameraChannelError as error:
        if error.reason == "ambiguous" and lens != "auto":
            raise CameraChannelError("unavailable") from error
        raise
    if lens != "auto":
        for channel in channels:
            if channel.local_index == lens:
                return channel.resource_identifier, channel.local_index
        raise CameraChannelError("unavailable")
    if len(channels) == 1:
        return channels[0].resource_identifier, channels[0].local_index
    raise CameraChannelError("selection_required" if channels else "invalid")


def notification_camera_channel(
    data: Mapping[str, Any], notification: Mapping[str, Any]
) -> CameraChannel | None:
    """Resolve the notification's explicit channel; absent/foreign IDs stay unknown."""
    ext = notification.get("ext")
    if (
        not isinstance(ext, Mapping)
        or type(ext.get("channel_type")) not in (int, str)
        or ext.get("channel_type") not in (1, "1")
    ):
        return None
    index = _local_index(ext.get("channel_no"))
    if index is None:
        return None
    return next((c for c in camera_channels(data) if c.local_index == index), None)


def alarm_camera_channel(data: Mapping[str, Any], alarm: Mapping[str, Any]) -> CameraChannel | None:
    """Resolve the explicit channel of a normalized alarm, never its list position."""
    index = _local_index(alarm.get("channel"))
    if index is None:
        return None
    return next((c for c in camera_channels(data) if c.local_index == index), None)


@dataclass(frozen=True, slots=True)
class CameraChannelNotification:
    """A received notification, not inferred persistent motion/recording state."""

    channel: CameraChannel
    event_id: str | None
    image_url: str | None = field(repr=False)
    code: str | int | None
    source_time: str | int | None


def camera_channel_notification(
    data: Mapping[str, Any], notification: Mapping[str, Any]
) -> CameraChannelNotification | None:
    """Normalize only explicit alarm-channel metadata; unknown channels stay unknown."""
    channel = notification_camera_channel(data, notification)
    ext = notification.get("ext")
    if channel is None or not isinstance(ext, Mapping):
        return None
    event_id, image_url = ext.get("msgId"), ext.get("image")
    code, source_time = ext.get("alert_type_code"), ext.get("time")
    return CameraChannelNotification(
        channel,
        event_id if isinstance(event_id, str) and event_id else None,
        image_url if isinstance(image_url, str) and image_url else None,
        code if type(code) in (str, int) else None,
        source_time if type(source_time) in (str, int) else None,
    )


def validate_channel_rtsp_path(value: object) -> str:
    """Accept an explicitly configured path, never credentials/host overrides."""
    if not isinstance(value, str) or (
        value
        and (
            not value.startswith("/")
            or value.startswith("//")
            or len(value) > 1024
            or any(char.isspace() or ord(char) < 32 for char in value)
        )
    ):
        raise PyEzvizError("Use an RTSP path beginning with /, not a complete URL")
    return value
