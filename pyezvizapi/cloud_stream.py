"""Client-oriented helpers for EZVIZ cloud stream bootstrap metadata."""

from __future__ import annotations

import base64
import json
from typing import Any, TypedDict, cast
from urllib.parse import urlparse

from .api_endpoints import API_ENDPOINT_VTDU_TOKEN_V2
from .constants import MAX_RETRIES
from .exceptions import HTTPError, PyEzvizError
from .stream import build_vtm_url

JsonDict = dict[str, Any]


class VtduTokenResponse(TypedDict, total=False):
    """Response from the VTDU token endpoint."""

    msg: str
    tokens: list[str]
    retcode: int


def get_vtdu_token_v2(client: Any, max_retries: int = 0) -> VtduTokenResponse:
    """Fetch VTDU stream tokens from the auth service for an EzvizClient."""

    if max_retries > MAX_RETRIES:
        raise PyEzvizError("Could not get VTDU token. Max retries exceeded.")

    token = getattr(client, "_token", {})
    session_id = token.get("session_id") if isinstance(token, dict) else None
    sign = _session_sign(session_id)
    try:
        json_output = client._parse_json(
            client._http_request(
                "GET",
                f"{_auth_base_url(client)}{API_ENDPOINT_VTDU_TOKEN_V2}",
                params={"ssid": session_id, "sign": sign},
                retry_401=False,
            )
        )
    except HTTPError as err:
        if _http_status_code(err) != 401:
            raise
        client.login()
        return get_vtdu_token_v2(client, max_retries=max_retries + 1)

    if not _success_retcode(json_output.get("retcode")):
        raise PyEzvizError(f"Could not get VTDU token: Got {json_output})")
    tokens = json_output.get("tokens")
    if not isinstance(tokens, list) or not tokens:
        raise PyEzvizError(f"Could not get VTDU token: Got {json_output})")
    return cast(VtduTokenResponse, json_output)


def get_vtm_page_list(client: Any) -> JsonDict:
    """Return pagelist payload filtered to VTM cloud stream metadata."""

    return cast(JsonDict, client._api_get_pagelist(page_filter="VTM", limit=50))


def get_cloud_stream_info(
    client: Any,
    serial: str,
    *,
    channel: int | None = None,
    client_type: int = 9,
    token_index: int = 0,
) -> JsonDict:
    """Build VTM stream bootstrap metadata for a camera.

    This does not open the TCP VTM/VTDU stream. It gathers the resource, VTM
    server, VTDU token, and ysproto URL needed by an experimental stream client.
    """

    pagelist = get_vtm_page_list(client)
    resources = pagelist.get("resourceInfos") or []
    vtms = pagelist.get("VTM") or {}
    if not isinstance(resources, list) or not isinstance(vtms, dict):
        raise PyEzvizError("VTM pagelist response is missing resource metadata")

    resource = _find_vtm_resource(resources, serial, channel=channel)
    if not isinstance(resource, dict):
        channel_text = f" channel {channel}" if channel is not None else ""
        raise PyEzvizError(f"Could not find VTM resource for serial {serial}{channel_text}")

    resource_id = resource.get("resourceId")
    vtm = vtms.get(resource_id)
    if not isinstance(vtm, dict):
        raise PyEzvizError(f"Could not find VTM server for resource {resource_id}")

    tokens = get_vtdu_token_v2(client).get("tokens", [])
    try:
        vtdu_token = tokens[token_index]
    except IndexError as err:
        raise PyEzvizError(f"VTDU token index out of range: {token_index}") from err
    if not isinstance(vtdu_token, str):
        raise PyEzvizError(f"Invalid VTDU token at index {token_index}")

    stream_channel = channel
    if stream_channel is None:
        local_index = resource.get("localIndex")
        local_index_text = str(local_index)
        stream_channel = int(local_index_text) if local_index_text.isdigit() else 1

    host = vtm.get("externalIp") or vtm.get("domain") or vtm.get("internalIp")
    if not isinstance(host, str) or not host.strip():
        raise PyEzvizError(f"Could not find VTM endpoint for resource {resource_id}")
    port_value = vtm.get("port")
    if not isinstance(port_value, (int, str)) or not str(port_value).isdigit():
        raise PyEzvizError(f"Could not find VTM port for resource {resource_id}")
    port = int(port_value)
    if port < 1 or port > 65535:
        raise PyEzvizError(f"Could not find VTM port for resource {resource_id}")

    stream_url = build_vtm_url(
        host.strip(),
        port,
        serial,
        str(resource.get("streamBizUrl") or ""),
        vtdu_token,
        channel=stream_channel,
        client_type=client_type,
    )
    return {
        "resource": resource,
        "vtm": vtm,
        "vtdu_token": vtdu_token,
        "stream_url": stream_url,
    }


def _find_vtm_resource(
    resources: list[Any],
    serial: str,
    *,
    channel: int | None,
) -> JsonDict | None:
    serial_resources = [
        item
        for item in resources
        if isinstance(item, dict) and item.get("deviceSerial") == serial
    ]
    if channel is None:
        return cast(JsonDict, serial_resources[0]) if serial_resources else None

    channel_text = str(channel)
    return next(
        (
            cast(JsonDict, item)
            for item in serial_resources
            if str(item.get("localIndex")) == channel_text
        ),
        None,
    )


def _http_status_code(err: HTTPError) -> int | None:
    cause = err.__cause__
    response = getattr(cause, "response", None)
    status_code = getattr(response, "status_code", None)
    return status_code if isinstance(status_code, int) else None


def _success_retcode(retcode: Any) -> bool:
    return retcode in {0, "0"}


def _session_sign(session_id: Any) -> str:
    if not session_id:
        raise PyEzvizError("No Login token present!")
    parts = str(session_id).split(".")
    if len(parts) < 2:
        raise PyEzvizError("Current session token is not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode())
        claims = json.loads(decoded.decode())
    except (ValueError, UnicodeDecodeError) as err:
        raise PyEzvizError("Could not decode current session token claims") from err
    if not isinstance(claims, dict):
        raise PyEzvizError("Session token claims are not an object")
    sign = claims.get("s")
    if not isinstance(sign, str) or not sign:
        raise PyEzvizError("Current session token does not contain VTDU sign claim")
    return sign


def _auth_base_url(client: Any) -> str:
    token = getattr(client, "_token", {})
    service_urls = token.get("service_urls") if isinstance(token, dict) else None
    if not isinstance(service_urls, dict) or _missing_auth_addr(service_urls.get("authAddr")):
        service_urls = client.get_service_urls()
        if isinstance(token, dict):
            token["service_urls"] = service_urls

    auth_addr = str(service_urls.get("authAddr", "")).strip()
    if _missing_auth_addr(auth_addr):
        raise PyEzvizError("Missing authAddr in service URLs")
    if not auth_addr.startswith(("http://", "https://")):
        auth_addr = f"https://{auth_addr}"
    parsed = urlparse(auth_addr)
    if not parsed.netloc:
        raise PyEzvizError(f"Invalid authAddr: {auth_addr}")
    return auth_addr.rstrip("/")


def _missing_auth_addr(value: Any) -> bool:
    auth_addr = str(value or "").strip()
    if not auth_addr or auth_addr.lower() in {"none", "null"}:
        return True
    candidate = auth_addr
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    return (parsed.hostname or "").lower() in {"", "none", "null"}
