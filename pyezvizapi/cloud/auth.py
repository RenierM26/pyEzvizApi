"""Shared HTTP credential refresh and isolated borrowed request transport.

Callers own the token lock and transport lifetime. A successful rotation is
persisted before discovery; storage failures must propagate to the caller.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import requests

from pyezvizapi.cloud import transport as _http_transport
from pyezvizapi.cloud.responses import meta_code, object_section, parse_json, response_summary
from pyezvizapi.cloud.budget import budgeted_http_call
from pyezvizapi.push.longlink.profile import profile_for_token, synchronize_http_headers
from pyezvizapi.cloud.token import validate_feature_code
from pyezvizapi.cloud.endpoints import API_ENDPOINT_REFRESH_SESSION_ID, API_ENDPOINT_SERVER_INFO
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.exceptions import EzvizAuthTokenExpired, HTTPError, PyEzvizError

# Older callers and MQTT retain this helper import as the same object.
isolated_session = _http_transport.isolated_session


def discover_services(session: requests.Session, token: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Discover endpoints using the just-refreshed isolated HTTP session."""
    response = session.get(
        f"https://{token['api_url']}{API_ENDPOINT_SERVER_INFO}", timeout=timeout,
        allow_redirects=False,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as error:
        raise HTTPError from error
    result = parse_json(response)
    if meta_code(result) != 200:
        raise PyEzvizError("Error getting service URLs")
    urls = object_section(result, "systemConfigInfo")
    urls["sysConf"] = str(urls.get("sysConf", "")).split("|")
    return urls


def refresh_credentials(
    session: requests.Session,
    token: dict[str, Any],
    timeout: int,
    notify: Callable[[], None],
    discover: Callable[[], Any],
) -> None:
    """Rotate an existing login; account/password fallback belongs to the caller."""
    validate_feature_code(token)
    try:
        response = budgeted_http_call(session, "put",
            url=f"https://{token['api_url']}{API_ENDPOINT_REFRESH_SESSION_ID}",
            data={"refreshSessionId": token["rf_session_id"], "featureCode": FEATURE_CODE,
                  **profile_for_token(token).registration},
            allow_redirects=False, timeout=timeout,
        )
        response.raise_for_status()
    except requests.HTTPError as error:
        raise HTTPError from error
    try:
        result = parse_json(response)
    except PyEzvizError as error:
        raise PyEzvizError("Impossible to decode refresh response") from error
    code = meta_code(result)
    if code in (401, 403):
        raise EzvizAuthTokenExpired("Token expired; login with username and password required")
    if code != 200:
        raise PyEzvizError(f"Error renewing login token: {response_summary(result)}")
    info = object_section(result, "sessionInfo", required=True)
    session_id, refresh_id = info.get("sessionId"), info.get("refreshSessionId")
    if not isinstance(session_id, str) or not session_id or not isinstance(refresh_id, str) or not refresh_id:
        raise PyEzvizError("Invalid refresh credential fields")
    token.update(session_id=session_id, rf_session_id=refresh_id)
    token["feature_code"] = FEATURE_CODE
    synchronize_http_headers(
        session.headers, profile_for_token(token), token["session_id"], scope="session"
    )
    notify()
    if not token.get("service_urls"):
        token["service_urls"] = discover()
        notify()
