"""Immutable HTTP identities used by legacy and channel-99 sessions."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Literal

from .constants import REQUEST_HEADER


@dataclass(frozen=True, slots=True)
class HttpProfile:
    """One server-bound HTTP client identity."""

    name: str
    headers: Mapping[str, str]
    registration: Mapping[str, str]


def _immutable(values: Mapping[str, str]) -> Mapping[str, str]:
    """Return a detached read-only mapping."""

    return MappingProxyType(dict(values))


_ANDROID_OVERRIDES: Final = {
    "clientNo": "google",
    "clientVersion": "7.4.1.0421",
    "osVersion": "13",
}
_ANDROID_REGISTRATION: Final = {
    "pushRegisterJson": '[{"channel":99}]',
    "pushExtJson": '{"language":"","protoVer":"2"}',
}

WEB_PROFILE: Final = HttpProfile(
    name="web",
    headers=_immutable(REQUEST_HEADER),
    registration=_immutable({}),
)
ANDROID_PROFILE: Final = HttpProfile(
    name="android-channel99",
    headers=_immutable({**REQUEST_HEADER, **_ANDROID_OVERRIDES}),
    registration=_immutable(_ANDROID_REGISTRATION),
)

# Historical internal names retained while callers migrate to the profile object.
PROFILE: Final = ANDROID_PROFILE.name
HEADERS: Final = _immutable(_ANDROID_OVERRIDES)
REGISTER: Final = ANDROID_PROFILE.registration

_PROFILE_HEADER_NAMES: Final = tuple(
    dict.fromkeys((*WEB_PROFILE.headers, *ANDROID_PROFILE.headers))
)
_IDENTITY_HEADER_NAMES: Final = (
    "sessionId",
    "featureCode",
    *_ANDROID_OVERRIDES,
)
_DEFAULT_SESSION: Final = object()


def profile_for_token(token: Mapping[str, Any]) -> HttpProfile:
    """Select the HTTP identity bound to a persisted token."""

    if token.get("push_profile") == ANDROID_PROFILE.name:
        return ANDROID_PROFILE
    return WEB_PROFILE


def session_header_for_token(token: Mapping[str, Any]) -> object | str | None:
    """Return the exact session-header state represented by a token.

    Legacy sessions retain the historical empty default. An Android profile with
    no credential is a migration in progress and must omit ``sessionId`` so an
    old web credential cannot be sent under the new identity.
    """

    if session_id := token.get("session_id"):
        return str(session_id)
    if profile_for_token(token) is ANDROID_PROFILE:
        return None
    return _DEFAULT_SESSION


def recreated_session_header_for_token(
    token: Mapping[str, Any],
) -> object | str | None:
    """Return the historical session state used after transport recreation."""

    if profile_for_token(token) is ANDROID_PROFILE:
        return session_header_for_token(token)
    return WEB_PROFILE.headers["sessionId"]


def current_session_header(headers: Mapping[str, Any]) -> str | bytes | None:
    """Return a live header value, preserving absence as ``None``."""

    if "sessionId" not in headers:
        return None
    return headers["sessionId"]


def synchronize_http_headers(
    headers: MutableMapping[str, Any],
    profile: HttpProfile,
    session_id: object | str | bytes | None = _DEFAULT_SESSION,
    *,
    scope: Literal["profile", "identity", "session"],
) -> None:
    """Synchronize profile-owned headers without touching endpoint headers.

    The ``profile`` scope installs the complete identity on a new or repurposed
    session. ``identity`` updates fields that may differ after profile migration
    while preserving endpoint-specific request headers. ``session`` changes only
    the rotating credential on an already-owned or externally supplied session.

    ``session_id`` has three states: the private default keeps the profile's
    historical empty value, ``None`` removes the header for a fresh migration,
    and a string installs the current credential.
    """

    managed = {
        "profile": _PROFILE_HEADER_NAMES,
        "identity": _IDENTITY_HEADER_NAMES,
        "session": ("sessionId",),
    }[scope]
    for name in managed:
        if name in profile.headers:
            headers[name] = profile.headers[name]
        else:
            headers.pop(name, None)
    if session_id is None:
        headers.pop("sessionId", None)
    elif session_id is not _DEFAULT_SESSION:
        headers["sessionId"] = (
            session_id if isinstance(session_id, (str, bytes)) else str(session_id)
        )
