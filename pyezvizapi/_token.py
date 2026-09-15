"""Shared persisted token schema and channel-99 boundary validation.

Tokens are partial during login. Validate the fields required by each operation
at its boundary; a TypedDict alone is not runtime validation.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, NotRequired, TypedDict

from ._longlink_profile import PROFILE
from .constants import FEATURE_CODE
from .exceptions import EzvizAuthTokenExpired, PyEzvizError


class ServiceUrls(TypedDict):
    """Service URLs present in the EZVIZ auth token.

    Attributes:
        pushAddr: Legacy hostname retained for token compatibility.
        pushDasDomain: Channel-99 LBS hostname.
        pushDasPort: Channel-99 LBS port.
    """

    pushAddr: NotRequired[str]
    pushDasDomain: NotRequired[str]
    pushDasPort: NotRequired[int | str]


class ClientToken(TypedDict):
    """Typed shape for the Ezviz client token."""

    session_id: NotRequired[str | None]
    rf_session_id: NotRequired[str | None]
    username: NotRequired[str | None]
    api_url: str
    feature_code: NotRequired[str]
    hardware_code: NotRequired[str]
    push_profile: NotRequired[str]
    push_state: NotRequired[dict[str, Any]]
    user_id: NotRequired[str]
    service_urls: NotRequired[dict[str, Any]]


def _hostname(value: Any) -> str:
    """Validate saved DNS names/IP literals without attempting network access."""
    if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise PyEzvizError("Invalid channel-99 hostname")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        encoded = value.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise PyEzvizError("Invalid channel-99 hostname") from error
    labels = encoded.removesuffix(".").split(".")
    if len(encoded.removesuffix(".")) > 253 or any(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None
        for label in labels
    ):
        raise PyEzvizError("Invalid channel-99 hostname")
    return encoded


def _push_endpoint(urls: Any) -> tuple[str, int]:
    """Reject malformed saved discovery before starting a background worker."""
    if not isinstance(urls, dict):
        raise PyEzvizError("Invalid channel-99 service discovery")
    host = _hostname(urls.get("pushDasDomain"))
    value = urls.get("pushDasPort", 8666)
    if type(value) not in (int, str):
        raise PyEzvizError("Invalid channel-99 service port")
    try:
        port = int(value)
    except ValueError as error:
        raise PyEzvizError("Invalid channel-99 service port") from error
    if not 1 <= port <= 65535:
        raise PyEzvizError("Invalid channel-99 service port")
    return host, port


def _push_serial(user_id: Any) -> bytes:
    """Validate the account component and native subserial length bound."""
    if not isinstance(user_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", user_id) is None:
        raise PyEzvizError("Invalid channel-99 user ID")
    serial = f"MOBILE:ys7:{user_id}:{FEATURE_CODE}".encode("ascii")
    if len(serial) > 127:
        raise PyEzvizError("Channel-99 user ID exceeds protocol limit")
    return serial


def validate_feature_code(token: dict[str, Any]) -> None:
    """Reject saved channel-99 credentials belonging to a different host identity."""
    if token.get("push_profile") == PROFILE and token.get("feature_code") != FEATURE_CODE:
        raise EzvizAuthTokenExpired(
            "Channel-99 host feature code changed or is missing; "
            "create a fresh login without the old token or push state"
        )


def validate_push_token(token: dict[str, Any]) -> None:
    """Validate persisted login/discovery before starting the push worker."""
    validate_feature_code(token)
    if not all(token.get(key) for key in ("user_id", "feature_code", "session_id", "api_url")):
        raise PyEzvizError("Channel-99 login metadata is incomplete; migrate the login first")
    _push_endpoint(token.get("service_urls", {}))
    _push_serial(token["user_id"])
    if ":" in _hostname(token["api_url"]):
        raise PyEzvizError("IPv6 API hosts are not supported")
    if not isinstance(token["session_id"], str) or re.fullmatch(r"[!-~]+", token["session_id"]) is None:
        raise PyEzvizError("Invalid channel-99 session ID")
    if not isinstance(token.get("push_state", {}), dict):
        raise PyEzvizError("Invalid saved push state")
