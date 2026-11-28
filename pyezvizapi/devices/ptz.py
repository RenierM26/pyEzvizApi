"""Cloud controls for saved viewpoints, patrol points, and panoramas.

Use the playback channel number for saved viewpoints and a reported
CameraChannel for resource-scoped panorama actions. Resolve the capture scope
from pagelist metadata before sending a command. No helper switches lenses
or falls back to LAN controls.
"""

# ruff: noqa: SLF001
# Share the SDK's authenticated transport and request deadline.

from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
from time import monotonic
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import quote, urlsplit

from requests import Request, RequestException, Session

from pyezvizapi.cloud.budget import (
    MAX_BUDGETED_BODY_BYTES,
    BudgetedBodyLimitError,
    budgeted_http_call,
)
from pyezvizapi.cloud.deadline import request_budget_lock, request_deadline
from pyezvizapi.cloud.endpoints import (
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_PANORAMIC_DEVICES_OPERATION,
)
from pyezvizapi.cloud.responses import object_section
from pyezvizapi.devices.channels import resolve_camera_channel
from pyezvizapi.exceptions import PyEzvizError

if TYPE_CHECKING:
    from pyezvizapi.client import EzvizClient
    from pyezvizapi.devices.channels import CameraChannel

_PANORAMA_DOWNLOAD_LIMIT = MAX_BUDGETED_BODY_BYTES
_PANORAMA_DOWNLOAD_TIMEOUT = 15
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
    _require_v3_success(client, response, "Could not save patrol point")
    index = response.get("index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise PyEzvizError("Missing or invalid patrol point index")
    return index


def _require_v3_success(client: EzvizClient, response: dict[str, Any], context: str) -> None:
    if not client._meta_ok(response):
        raise PyEzvizError(f"{context}: {client._response_summary(response)}")


def _panorama_serial(serial: str) -> str:
    if not serial.strip():
        raise ValueError("Expected a panorama device serial")
    return serial.upper()


def _panorama_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as error:
            raise PyEzvizError(f"Invalid panorama routing metadata: {field}") from error
    if not isinstance(value, Mapping):
        raise PyEzvizError(f"Missing or invalid panorama routing metadata: {field}")
    return value


def _panorama_rows(value: Any, field: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, Mapping) for row in value):
        raise PyEzvizError(f"Missing or invalid panorama routing metadata: {field}")
    return value


def _panorama_flag(support: Mapping[str, Any], key: str) -> bool:
    value = support.get(key, 0)
    if type(value) is int:
        return value == 1
    if isinstance(value, str):
        try:
            return int(value) == 1
        except ValueError as error:
            raise PyEzvizError(f"Invalid panorama supportExt flag {key}") from error
    raise PyEzvizError(f"Invalid panorama supportExt flag {key}")


def _profile_has_panorama_capture(profile: Mapping[str, Any], channel: CameraChannel) -> bool:
    for resource in _panorama_rows(profile.get("resources"), "profile.resources"):
        if resource.get("identifier") != channel.resource_identifier:
            continue
        indexes = resource.get("localIndex")
        if not isinstance(indexes, list):
            raise PyEzvizError("Missing or invalid panorama routing metadata: profile.localIndex")
        if not any(
            type(index) in (int, str) and str(index) == channel.local_index for index in indexes
        ):
            continue
        for domain in _panorama_rows(resource.get("domains"), "profile.domains"):
            if domain.get("identifier") != "Panorama":
                continue
            # Android's haveFeatureDef checks all three definition caches.
            for section in ("actions", "props", "events"):
                definitions = _panorama_rows(domain.get(section, []), f"Panorama.{section}")
                if any(item.get("identifier") == "TriggerPanoramicCapture" for item in definitions):
                    return True
    return False


def resolve_panorama_capture_route(
    page_list: Mapping[str, Any], serial: str, *, channel: CameraChannel
) -> Literal["device", "resource", "relay"]:
    """Resolve the app's capture scope from a full get_page_list() snapshot.

    Pass the selected, reported playback resource and local index. Relay
    (supportExt 913) takes precedence. Otherwise an exact product/firmware
    profile definition for Panorama.TriggerPanoramicCapture selects resource
    capture; without that definition, supportExt 81 enables device capture.

    This function sends no requests. Relay is a distinct workflow, not a cloud
    capture option. Raise PyEzvizError for missing or malformed capability
    metadata, an unavailable channel, or no supported cloud route. In
    particular, a missing profile is not proof that a resource lacks the action.
    """
    serial = _panorama_serial(serial)
    devices = [
        row
        for row in _panorama_rows(page_list.get("deviceInfos"), "deviceInfos")
        if row.get("deviceSerial") == serial
    ]
    if len(devices) != 1:
        raise PyEzvizError("Missing or ambiguous panorama device in the pagelist")
    device = devices[0]
    resources = _panorama_rows(page_list.get("resourceInfos"), "resourceInfos")
    resolve_camera_channel(
        {"resourceInfos": [row for row in resources if row.get("deviceSerial") == serial]},
        channel.key,
    )

    support = _panorama_mapping(device.get("supportExt"), "supportExt")
    if _panorama_flag(support, "913"):
        return "relay"

    model, version = device.get("deviceType"), device.get("version")
    if not (isinstance(model, str) and model and isinstance(version, str) and version):
        raise PyEzvizError("Missing panorama device type or firmware version")
    products = _panorama_mapping(page_list.get("PRODUCTS_INFO"), "PRODUCTS_INFO")
    product = _panorama_mapping(
        products.get(f"PV(productId={model}, version={version})"), "product"
    )
    profile = _panorama_mapping(product.get("profile"), "product.profile")
    if _profile_has_panorama_capture(profile, channel):
        return "resource"
    if _panorama_flag(support, "81"):
        return "device"
    raise PyEzvizError("Panorama capture is not advertised for the selected camera channel")


def start_panorama_capture(client: EzvizClient, serial: str, *, channel: CameraChannel) -> None:
    """Start panorama capture on an explicitly selected camera resource.

    Capture can physically move the camera. Return None on acknowledgment
    without waiting for completion; poll get_panorama_info separately using
    the same device and channel. Cloud rejection raises PyEzvizError.
    """
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
    _require_v3_success(client, response, "Could not start panorama capture")


def get_panorama_info(
    client: EzvizClient, serial: str, *, channel: CameraChannel
) -> dict[str, Any]:
    """Return the panorama data object for the specified device and resource.

    The object may contain percent and picInfoList. This call does not start a
    capture, wait for completion, or download or stitch the images. Cloud
    rejection or a missing or malformed data object raises PyEzvizError.
    """
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


def start_device_panorama_capture(client: EzvizClient, serial: str) -> None:
    """Start the Android device-wide cloud capture, which may move the camera.

    Use this for the app's device-wide workflow instead of a resource action.
    Return on V3 acknowledgment, not completion. Read get_stored_panorama
    separately. This helper never retries using a different route.
    """
    response = client._request_json(
        "POST",
        "/v3/panoramicDevices/pics/collect",
        data={"deviceSerial": _panorama_serial(serial)},
        retry_401=False,
    )
    _require_v3_success(client, response, "Could not start device panorama capture")


def get_stored_panorama(client: EzvizClient, serial: str) -> dict[str, Any]:
    """Return the Android device-wide panorama record without downloading images.

    The returned picInfo object can contain progress and levelPicInfoList.
    An empty list means no images were returned. This is a separate read route,
    not a fallback for resource-scoped capture or progress. Use
    download_saved_panorama for the finished JPEG uploaded by the app.
    """
    response = client._request_json(
        "GET",
        "/v3/panoramicDevices/pics",
        params={"deviceSerial": _panorama_serial(serial)},
        retry_401=False,
    )
    _require_v3_success(client, response, "Could not read stored panorama")
    return object_section(response, "picInfo", required=True)


def _validate_panorama_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        valid = (
            parsed.scheme == "https"
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443, 8444)
            and host.endswith(".ezvizlife.com")
            and host.isascii()
            and all(c.isalnum() or c in ".-" for c in host)
            and not any(c.isspace() or ord(c) < 32 or c == "\\" for c in url)
        )
    except ValueError:
        valid = False
    if not valid:
        raise PyEzvizError("Unsupported saved panorama URL; expected an EZVIZ HTTPS host")


class _PanoramaSession(Session):
    def resolve_redirects(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        # Requests can drain a redirect body even with allow_redirects=False
        # while building Response.next. No redirect processing is needed here.
        return iter(())


def _fetch_panorama_jpeg(url: str) -> bytes:
    _validate_panorama_url(url)
    try:
        with (
            _PanoramaSession() as media,
            request_deadline(monotonic() + _PANORAMA_DOWNLOAD_TIMEOUT),
        ):
            media.trust_env = False
            with budgeted_http_call(
                media,
                "get",
                url=url,
                allow_redirects=False,
                timeout=(5, 5),
                max_body_bytes=_PANORAMA_DOWNLOAD_LIMIT,
                body_status=200,
            ) as response:
                if response.status_code != 200:
                    raise PyEzvizError(
                        f"Saved panorama download returned HTTP {response.status_code}"
                    )
                data = response.content
    except TimeoutError:
        raise PyEzvizError("Saved panorama download exceeded its time limit") from None
    except BudgetedBodyLimitError:
        raise PyEzvizError("Saved panorama download exceeded its size limit") from None
    except RequestException:
        # Request exception messages can contain the signed URL.
        raise PyEzvizError("Could not download saved panorama") from None
    if not data.startswith(b"\xff\xd8\xff") or not data.endswith(b"\xff\xd9"):
        raise PyEzvizError("Saved panorama did not return JPEG data")
    return data


def download_saved_panorama(client: EzvizClient, serial: str) -> bytes | None:
    """Download the finished device-wide panorama JPEG without moving the camera.

    Read fresh inventory and use the selected serial's STATUS.levelPicUrl.
    Return None when no saved image is advertised for that serial. Android
    stitches and uploads the image; capture progress alone does not make one
    available. This helper does not capture, stitch, or upload anything.

    The bounded media download uses HTTPS without account headers, cookies, or
    redirects. Raise PyEzvizError for malformed status, an unsupported URL, or
    a failed or non-JPEG download. The returned JPEG bytes are not decoded.
    """
    serial = _panorama_serial(serial)
    status = client.get_page_list().get("STATUS")
    if status is None:
        return None
    row = _panorama_mapping(status, "STATUS").get(serial)
    if row is None:
        return None
    url = _panorama_mapping(row, "STATUS row").get("levelPicUrl")
    if url is None or url == "":
        return None
    if not isinstance(url, str):
        raise PyEzvizError("Malformed saved panorama URL")
    return _fetch_panorama_jpeg(url)


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
    legacy device-wide app route. The x and y fractions must be in [0, 1];
    invalid coordinates raise ValueError before any request. The camera may
    physically move. Return on cloud acknowledgment, not movement completion.
    A failed command never tries the other route.
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
    _require_v3_success(client, response, "Could not move to panorama point")


def reset_panorama_mark(client: EzvizClient, serial: str) -> None:
    """Reset the device-wide panorama coordinate mark (Android mark type 3).

    This sends only the mark reset command, not a panorama capture request
    or a live-view PTZ command. Return None on acknowledgment; cloud rejection
    raises PyEzvizError.
    """
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
    _require_v3_success(client, response, "Could not reset panorama coordinate mark")
