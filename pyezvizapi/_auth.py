"""Shared HTTP credential refresh and isolated borrowed request transport.

Callers own the token lock and transport lifetime. A successful rotation is
persisted before discovery; storage failures must propagate to the caller.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from copy import copy, deepcopy
from typing import Any

import requests
from requests.structures import CaseInsensitiveDict

from ._longlink_profile import PROFILE, REGISTER
from ._token import validate_feature_code
from .api_endpoints import API_ENDPOINT_REFRESH_SESSION_ID, API_ENDPOINT_SERVER_INFO
from .constants import FEATURE_CODE
from .exceptions import EzvizAuthTokenExpired, HTTPError, PyEzvizError


def isolated_session(source: requests.Session) -> requests.Session:
    """Copy request state, borrowing transport adapters owned by the caller.

    No transport pools are created here. Do not close this copy: adapter/pool
    lifetime remains with the supplied session, including custom TLS adapters.
    """
    session = copy(source)
    session.headers = CaseInsensitiveDict(source.headers)
    session.cookies = source.cookies.copy()
    session.params = deepcopy(source.params)
    session.proxies = dict(source.proxies)
    session.hooks = {name: list(hooks) for name, hooks in source.hooks.items()}
    session.adapters = OrderedDict(source.adapters)
    return session


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
    result = response.json()
    if result.get("meta", {}).get("code") != 200:
        raise PyEzvizError("Error getting service URLs")
    urls: dict[str, Any] = result.get("systemConfigInfo", {})
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
        response = session.put(
            url=f"https://{token['api_url']}{API_ENDPOINT_REFRESH_SESSION_ID}",
            data={"refreshSessionId": token["rf_session_id"], "featureCode": FEATURE_CODE,
                  **(REGISTER if token.get("push_profile") == PROFILE else {})},
            allow_redirects=False, timeout=timeout,
        )
        response.raise_for_status()
    except requests.HTTPError as error:
        raise HTTPError from error
    try:
        result = response.json()
    except ValueError as error:
        raise PyEzvizError("Impossible to decode refresh response") from error
    code = result["meta"]["code"]
    if code in (401, 403):
        raise EzvizAuthTokenExpired("Token expired; login with username and password required")
    if code != 200:
        raise PyEzvizError(f"Error renewing login token: {result['meta']}")
    token["session_id"] = str(result["sessionInfo"]["sessionId"])
    token["rf_session_id"] = str(result["sessionInfo"]["refreshSessionId"])
    token["feature_code"] = FEATURE_CODE
    session.headers["sessionId"] = token["session_id"]
    notify()
    if not token.get("service_urls"):
        token["service_urls"] = discover()
        notify()
