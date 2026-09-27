"""HTTP profile and session-header ownership tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
import requests

from pyezvizapi._longlink_profile import (
    profile_for_token,
    session_header_for_token,
    synchronize_http_headers,
)
from pyezvizapi.constants import (
    ANDROID_PROFILE,
    HEADERS,
    REQUEST_HEADER,
    WEB_PROFILE,
    HttpProfile,
)


def _profile_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    return {name: str(headers[name]) for name in REQUEST_HEADER}


def test_profiles_are_immutable_detached_snapshots() -> None:
    with pytest.raises(TypeError):
        ANDROID_PROFILE.headers["clientNo"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        ANDROID_PROFILE.registration["pushRegisterJson"] = "changed"  # type: ignore[index]

    assert WEB_PROFILE.headers == REQUEST_HEADER
    assert ANDROID_PROFILE.headers == {**REQUEST_HEADER, **HEADERS}


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ({}, WEB_PROFILE),
        ({"push_profile": "other"}, WEB_PROFILE),
        ({"push_profile": "android-channel99"}, ANDROID_PROFILE),
    ],
)
def test_profile_selection(token: dict[str, Any], expected: object) -> None:
    assert profile_for_token(token) is expected


def test_rebuild_replaces_stale_profile_identity_and_preserves_unowned_headers() -> None:
    session = requests.Session()
    session.headers["Endpoint-Specific"] = "preserved"
    synchronize_http_headers(session.headers, ANDROID_PROFILE, "android-session", scope="profile")

    assert _profile_headers(session.headers) == {
        **REQUEST_HEADER,
        **HEADERS,
        "sessionId": "android-session",
    }
    synchronize_http_headers(session.headers, WEB_PROFILE, "web-session", scope="profile")
    assert _profile_headers(session.headers) == {
        **REQUEST_HEADER,
        "sessionId": "web-session",
    }
    assert session.headers["Endpoint-Specific"] == "preserved"


@pytest.mark.parametrize("profile", [WEB_PROFILE, ANDROID_PROFILE])
def test_rebuild_matches_historical_ordered_session_update(
    profile: HttpProfile,
) -> None:
    expected = requests.Session()
    expected.headers.update(REQUEST_HEADER)
    if profile is ANDROID_PROFILE:
        expected.headers.update(HEADERS)
    actual = requests.Session()

    synchronize_http_headers(
        actual.headers,
        profile,
        "current-session",
        scope="profile",
    )
    expected.headers["sessionId"] = "current-session"

    assert list(actual.headers.items()) == list(expected.headers.items())


def test_session_header_state_distinguishes_default_migration_and_credential() -> None:
    legacy: dict[str, Any] = {}
    migrating = {"push_profile": "android-channel99", "session_id": None}
    authenticated = {"push_profile": "android-channel99", "session_id": 123}
    session = requests.Session()

    synchronize_http_headers(
        session.headers,
        profile_for_token(legacy),
        session_header_for_token(legacy),
        scope="profile",
    )
    assert session.headers["sessionId"] == ""

    synchronize_http_headers(
        session.headers,
        profile_for_token(migrating),
        session_header_for_token(migrating),
        scope="profile",
    )
    assert "sessionId" not in session.headers

    synchronize_http_headers(
        session.headers,
        profile_for_token(authenticated),
        session_header_for_token(authenticated),
        scope="profile",
    )
    assert session.headers["sessionId"] == "123"


def test_narrow_sync_preserves_prepared_endpoint_headers() -> None:
    session = requests.Session()
    prepared = session.prepare_request(
        requests.Request(
            "POST",
            "https://example.invalid/path",
            headers={"Content-Type": "application/custom", "areaId": "specific"},
        )
    )

    synchronize_http_headers(prepared.headers, ANDROID_PROFILE, "current", scope="identity")

    assert prepared.headers["Content-Type"] == "application/custom"
    assert prepared.headers["areaId"] == "specific"
    assert prepared.headers["sessionId"] == "current"
    assert all(prepared.headers[name] == value for name, value in HEADERS.items())
