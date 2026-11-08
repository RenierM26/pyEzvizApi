"""Native app wall-clock selectors must not be mistaken for UTC instants."""

from io import BytesIO
from urllib.parse import parse_qs, urlparse

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.capture import ClipOptions, CloudPlaybackClipSource
from pyezvizapi.streaming.cloud import playback
from pyezvizapi.streaming.cloud.playback_range import native_playback_range
from pyezvizapi.streaming.media.models import CaptureLimits
from tests.streaming.test_cloud_playback import media, transport

BEGIN = "20261108T081522Z"
END = "20261108T081542Z"


@pytest.mark.parametrize(
    "zone,begin,end",
    [
        ("UTC", BEGIN, END),
        ("Africa/Johannesburg", "20261108T101522Z", "20261108T101542Z"),
        ("Asia/Kolkata", "20261108T134522Z", "20261108T134542Z"),
        ("America/New_York", "20261108T031522Z", "20261108T031542Z"),
    ],
)
def test_explicit_zone_projects_public_utc_without_host_timezone(zone, begin, end):
    assert native_playback_range(BEGIN, END, zone) == (begin, end)
    url = playback.build_vtm_playback_url(
        "example.test", 8554, "CAM123", "", "token", BEGIN, END, timezone=zone, timestamp_ms=1
    )
    query = parse_qs(urlparse(url).query)
    assert query["begin"] == [begin] and query["end"] == [end]


def test_local_midnight_rollover_keeps_absolute_requested_span():
    assert native_playback_range("20261108T215950Z", "20261108T220010Z", "Africa/Johannesburg") == (
        "20261108T235950Z",
        "20261109T000010Z",
    )


@pytest.mark.parametrize("zone", ["", "Not/AZone", "../UTC", None, True])
def test_invalid_zone_fails_at_typed_and_direct_boundaries_before_account(zone):
    with pytest.raises(PyEzvizError, match="timezone"):
        CloudPlaybackClipSource(BEGIN, END, timezone=zone)
    with pytest.raises(PyEzvizError, match="timezone"):
        playback.copy_cloud_playback_to_mpegps(
            object(), "CAM123", BytesIO(), BEGIN, END, timezone=zone
        )


@pytest.mark.parametrize(
    "begin,end",
    [
        ("20260308T065950Z", "20260308T070010Z"),  # Spring-forward across offset change.
        ("20261101T055950Z", "20261101T060010Z"),  # Fall-back across offset change.
        ("20261101T061000Z", "20261101T061020Z"),  # Repeated local hour, fold1.
        ("20261101T051000Z", "20261101T051020Z"),  # Repeated local hour, fold0.
    ],
)
def test_native_selector_cannot_encode_ambiguous_or_transitioning_wall_time(begin, end):
    with pytest.raises(PyEzvizError, match="offset change or ambiguous"):
        native_playback_range(begin, end, "America/New_York")


def test_effective_duration_is_applied_in_utc_before_zone_projection(monkeypatch):
    sock, seen, _ = transport(monkeypatch, body=media(10))
    result = playback.copy_cloud_playback_to_mpegps(
        object(),
        "CAM123",
        BytesIO(),
        BEGIN,
        END,
        timezone="Africa/Johannesburg",
        duration_seconds=10,
    )
    # Public bootstrap receives UTC plus the explicit zone, not pre-shifted input.
    assert seen[0][0][2:4] == (BEGIN, "20261108T081532Z")
    assert seen[0][1]["timezone"] == "Africa/Johannesburg"
    assert result["begin_time"] == BEGIN and result["end_time"] == "20261108T081532Z"
    assert result["native_begin_time"] == "20261108T101522Z"
    assert result["native_end_time"] == "20261108T101532Z" and sock.closed


def test_typed_range_checks_only_effective_duration_before_transition():
    source = CloudPlaybackClipSource(
        "20260308T065950Z", "20260308T070010Z", timezone="America/New_York"
    )
    with pytest.raises(PyEzvizError, match="offset change"):
        ClipOptions(source=source)
    ClipOptions(source=source, capture=CaptureLimits(duration_seconds=5))


def test_convenience_dispatch_keeps_explicit_timezone(monkeypatch):
    calls = []

    def copy(client, serial, output, begin, end, **kwargs):
        calls.append(kwargs)
        output.write(b"PS")
        return {"bytes": 2}

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", copy)
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    try:
        client.save_clip(
            "CAM123",
            BytesIO(),
            source="cloud-playback",
            cloud_playback_begin_time=BEGIN,
            cloud_playback_end_time=END,
            cloud_playback_timezone="Africa/Johannesburg",
        )
    finally:
        client.close_session()
    assert calls[0]["timezone"] == "Africa/Johannesburg"
