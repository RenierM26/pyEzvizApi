"""Cloud controls for saved viewpoints and patrol points.

Panorama helpers are implemented in devices.panorama and re-exported here
for compatibility.
"""

# ruff: noqa: SLF001
# Share the SDK's authenticated transport and request deadline.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import quote

from requests import Request

from pyezvizapi.cloud.deadline import request_budget_lock
from pyezvizapi.devices.panorama import (
    download_saved_panorama,
    get_panorama_info,
    get_stored_panorama,
    move_to_panorama_point,
    reset_panorama_mark,
    resolve_panorama_capture_route,
    start_device_panorama_capture,
    start_panorama_capture,
)
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient

__all__ = [
    "create_ptz_preset",
    "delete_ptz_preset",
    "download_saved_panorama",
    "get_panorama_info",
    "get_stored_panorama",
    "goto_ptz_preset",
    "list_ptz_presets",
    "move_to_panorama_point",
    "rename_ptz_preset",
    "reset_panorama_mark",
    "resolve_panorama_capture_route",
    "save_patrol_point",
    "start_device_panorama_capture",
    "start_panorama_capture",
]

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
    if (
        operation == "config"
        and fields.get("configPreset") == "GOTO_PRESET"
        and str(code) == "1310724"
    ):
        raise PyEzvizError(
            "PTZ preset recall was rejected (code 1310724); "
            "the camera may already be at the saved viewpoint"
        )
    if (type(code) is not int or code != 0) and code != "0":
        raise PyEzvizError(
            f"Could not {operation} PTZ preset: {client._response_summary(response)}"
        )
    return response


def list_ptz_presets(client: EzvizClient, serial: str, *, channel: int) -> list[dict[str, Any]]:
    """List saved viewpoints for a device serial and playback channel.

    Return the raw cloud rows, or an empty list if a successful response has
    no data. Use each row's subSerial, channelNo, and index for follow-up
    operations instead of assuming it belongs to the requested route.
    Raise PyEzvizError on cloud rejection or malformed non-null list data.
    """
    response = _request_preset(client, "list", _preset_route(serial, channel))
    rows = response.get("data")
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise PyEzvizError("Missing or invalid PTZ preset list")
    return cast("list[dict[str, Any]]", rows)


def goto_ptz_preset(client: EzvizClient, serial: str, index: int, *, channel: int) -> None:
    """Recall a saved viewpoint using its list row's subSerial, channelNo, and index.

    This can physically move the camera. Return after the cloud acknowledges
    the command, not after movement completes. Cloud rejection raises PyEzvizError.
    """
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
    """Delete a saved viewpoint using its list row's subSerial, channelNo, and index.

    This removes a viewpoint, not a patrol point or path. Return None on
    cloud acknowledgment; raise PyEzvizError if the cloud rejects the deletion.
    """
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
    """Save the current viewpoint on the specified playback channel.

    Supply non-empty JPEG bytes for the current view; this helper neither
    captures nor decodes the image. Return the raw Preset object. Empty or
    non-bytes thumbnails raise ValueError, while cloud rejection or a missing
    or malformed Preset object raises PyEzvizError.
    """
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
    """Rename a saved viewpoint and return the raw Preset object.

    Use the list row's subSerial, channelNo, and index, and pass its picUrl
    unchanged to retain the thumbnail. No image is uploaded. Cloud rejection
    or a missing or malformed Preset object raises PyEzvizError.
    """
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
    Reference it in an ordered patrol sequence as {"type": 1, "presetID": index}.
    This helper does not create or enable a path. Cloud rejection or a missing
    or invalid index raises PyEzvizError.
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
    if not client._meta_ok(response):
        raise PyEzvizError(f"Could not save patrol point: {client._response_summary(response)}")
    index = response.get("index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise PyEzvizError("Missing or invalid patrol point index")
    return index
