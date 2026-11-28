"""App-traced cloud controls for saved viewpoints and panorama capture."""

# ruff: noqa: SLF001
# Share the SDK's authenticated transport and request deadline.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import quote

from requests import Request

from pyezvizapi.cloud.deadline import request_budget_lock
from pyezvizapi.cloud.endpoints import (
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
)
from pyezvizapi.cloud.responses import object_section
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient
    from pyezvizapi.devices.channels import CameraChannel

_PRESET_PATH = "/api/device/preset"
_LEGACY_IDENTITY = (
    "sessionId",
    "featureCode",
    "clientType",
    "clientVersion",
    "osVersion",
    "netType",
    "clientNo",
)


_MultipartFields = dict[str, tuple[None, str] | tuple[str, bytes, str]]


def _post_multipart(client: EzvizClient, path: str, parts: _MultipartFields) -> dict[str, Any]:
    request = Request("POST", client._url(path), files=parts)
    prepared = client._session.prepare_request(request)
    return client._parse_json(client._send_prepared(prepared, retry_401=False))


def _preset_route(serial: str, channel: int) -> dict[str, str | int]:
    if not serial.strip():
        raise ValueError("Expected a preset device serial")
    if isinstance(channel, bool) or not isinstance(channel, int) or channel < 0:
        raise ValueError("Preset channel must be a non-negative integer")
    return {"subSerial": serial, "channelNo": channel}


def _preset_index(index: int) -> int:
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ValueError("Preset index must be a non-negative integer")
    return index


def _request_preset(
    client: EzvizClient,
    operation: Literal["list", "config", "set", "update"],
    fields: dict[str, str | int],
    *,
    thumbnail: bytes | None = None,
) -> dict[str, Any]:
    # Legacy Android forms include session metadata in the body as well as headers.
    # Prepare and send within the same session lock; never replay a stale form.
    with request_budget_lock(client._token_lock):
        headers = client._session.headers
        form = {key: headers[key] for key in _LEGACY_IDENTITY if key in headers}
        data = {**form, **fields}
        if operation in ("set", "update"):
            parts: _MultipartFields = {key: (None, str(value)) for key, value in data.items()}
            if thumbnail is not None:
                parts["Filedata"] = ("preset.jpg", thumbnail, "application/octet-stream")
            response = _post_multipart(client, f"{_PRESET_PATH}/{operation}", parts)
        else:
            response = client._request_json(
                "POST", f"{_PRESET_PATH}/{operation}", data=data, retry_401=False
            )
    code = response.get("resultCode")
    if (type(code) is not int or code != 0) and code != "0":
        raise PyEzvizError(
            f"Could not {operation} PTZ preset: {client._response_summary(response)}"
        )
    return response


def list_ptz_presets(client: EzvizClient, serial: str, *, channel: int) -> list[dict[str, Any]]:
    """List saved viewpoints for the specified playback channel."""
    response = _request_preset(client, "list", _preset_route(serial, channel))
    rows = response.get("data")
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise PyEzvizError("Missing or invalid PTZ preset list")
    return cast("list[dict[str, Any]]", rows)


def goto_ptz_preset(client: EzvizClient, serial: str, index: int, *, channel: int) -> None:
    """Move to a saved viewpoint using the route and index from its list row."""
    _request_preset(
        client,
        "config",
        {
            **_preset_route(serial, channel),
            "index": _preset_index(index),
            "configPreset": "GOTO_PRESET",
        },
    )


def delete_ptz_preset(client: EzvizClient, serial: str, index: int, *, channel: int) -> None:
    """Delete a saved viewpoint using the route and index from its list row."""
    _request_preset(
        client,
        "config",
        {
            **_preset_route(serial, channel),
            "index": _preset_index(index),
            "configPreset": "CLE_PRESET",
        },
    )


def _preset_result(response: dict[str, Any]) -> dict[str, Any]:
    preset = response.get("Preset")
    if not isinstance(preset, dict):
        raise PyEzvizError("Missing or invalid PTZ preset")
    return preset


def create_ptz_preset(
    client: EzvizClient, serial: str, name: str, *, channel: int, thumbnail: bytes
) -> dict[str, Any]:
    """Save the current viewpoint with a caller-supplied JPEG thumbnail."""
    if not isinstance(thumbnail, bytes) or not thumbnail:
        raise ValueError("Expected non-empty JPEG thumbnail bytes")
    return _preset_result(
        _request_preset(
            client,
            "set",
            {**_preset_route(serial, channel), "index": 0, "name": name},
            thumbnail=thumbnail,
        )
    )


def rename_ptz_preset(
    client: EzvizClient,
    serial: str,
    index: int,
    name: str,
    *,
    channel: int,
    pic_url: str,
) -> dict[str, Any]:
    """Rename a saved viewpoint, preserving its reported thumbnail URL."""
    return _preset_result(
        _request_preset(
            client,
            "update",
            {
                **_preset_route(serial, channel),
                "index": _preset_index(index),
                "name": name,
                "picUrl": pic_url,
            },
        )
    )


def save_patrol_point(client: EzvizClient, serial: str, name: int, *, thumbnail: bytes) -> int:
    """Capture the current patrol point using the app's device-wide channel-0 route.

    Pass the app's positive numeric point name and a JPEG of the current view.
    The returned index is a patrol point ID, not a user-saved viewpoint index.
    """
    if isinstance(name, bool) or not isinstance(name, int) or name < 1:
        raise ValueError("Patrol point name must be a positive integer")
    if not isinstance(thumbnail, bytes) or not thumbnail:
        raise ValueError("Expected non-empty JPEG thumbnail bytes")
    response = _post_multipart(
        client,
        f"/v3/devconfig/{quote(serial, safe='')}/0/preset/set",
        {
            "configPreset": (None, "SET_CRUISE_POINT"),
            "name": (None, str(name)),
            "filedata": (f"{name}.jpg", thumbnail, "image/jpg"),
        },
    )
    client._ensure_ok(response, "Could not save patrol point")
    index = response.get("index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise PyEzvizError("Missing or invalid patrol point index")
    return index


def _panorama_serial(serial: str) -> str:
    if not serial.strip():
        raise ValueError("Expected a panorama device serial")
    return serial.upper()


def start_panorama_capture(client: EzvizClient, serial: str, *, channel: CameraChannel) -> None:
    """Start a resource-scoped panorama capture (can move the camera)."""
    response = client._request_json(
        "POST",
        f"/v3/panoramicDevices/action/pics/collect/{quote(_panorama_serial(serial), safe='')}/{channel.local_index}",
        json_body={
            "resourceId": channel.resource_identifier,
            "domainId": "Panorama",
            "propId": "PanoramicCompPictureInfo",
            "actionId": "TriggerPanoramicCapture",
        },
        retry_401=False,
    )
    client._ensure_ok(response, "Could not start panorama capture")


def get_panorama_info(
    client: EzvizClient, serial: str, *, channel: CameraChannel
) -> dict[str, Any]:
    """Read raw panorama progress and picture metadata without fetching media."""
    response = client._iot_request(
        "PUT",
        API_ENDPOINT_IOT_ACTION,
        quote(_panorama_serial(serial), safe=""),
        channel.resource_identifier,
        channel.local_index,
        "Panorama",
        "QueryPanoramicPicInfo",
        payload={},
        error_message="Could not read panorama info",
    )
    return object_section(response, "data", required=True)


def _panorama_point(x: float, y: float) -> None:
    if any(
        isinstance(axis, bool) or not isinstance(axis, (int, float)) or not 0 <= axis <= 1
        for axis in (x, y)
    ):
        raise ValueError("Panorama coordinates must be numbers between 0 and 1")


def move_to_panorama_point(
    client: EzvizClient,
    serial: str,
    x: float,
    y: float,
    *,
    channel: CameraChannel | None = None,
) -> None:
    """Move to a normalized point on the panorama, not on the live view.

    Pass an explicit resource channel for RotateFixpoint, or omit it for the
    legacy device-wide app route. A failed command never tries the other route.
    """
    _panorama_point(x, y)
    device = _panorama_serial(serial)
    if channel is not None:
        client.set_iot_action(
            quote(device, safe=""),
            channel.resource_identifier,
            channel.local_index,
            "Panorama",
            "RotateFixpoint",
            {"x": round(x, 3), "y": round(y, 3)},
        )
        return

    response = client._request_json(
        "POST",
        API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
        data={
            "deviceSerial": device,
            "x": f"{x + 0.0:.6f}".rstrip("0").rstrip("."),
            "y": f"{y + 0.0:.6f}".rstrip("0").rstrip("."),
        },
        retry_401=False,
    )
    client._ensure_ok(response, "Could not move to panorama point")


def reset_panorama_mark(client: EzvizClient, serial: str) -> None:
    """Send the app's device-wide panorama coordinate reset (mark type 3)."""
    response = client._request_json(
        "PUT",
        "/v3/panoramicDevices/ptz/coordinate/mark",
        data={
            "deviceSerial": _panorama_serial(serial),
            "detectorSubSerial": "",
            "x": "",
            "y": "",
            "markType": 3,
        },
        retry_401=False,
    )
    client._ensure_ok(response, "Could not reset panorama coordinate mark")
