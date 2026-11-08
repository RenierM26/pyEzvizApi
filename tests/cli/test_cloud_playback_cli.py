"""CLI playback selectors validate before account login, without camera I/O."""

from io import BytesIO

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.cli.arguments import build_parser
from pyezvizapi.client import EzvizClient
from pyezvizapi.streaming.cloud import playback

BASE = ["save", "clip", "--source", "cloud-playback", "--serial", "CAM123", "--output", "clip.ps"]
TIMES = ["--begin-time", "20261108T000000Z", "--end-time", "20261108T000020Z"]


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--format", "mpegts"],
        ["--playback-max-bytes", "0"],
        ["--playback-transfer-timeout", "nan"],
        ["--duration", "nan"],
        ["--duration", "0.5s"],
    ],
)
def test_invalid_playback_fails_before_constructing_a_client(monkeypatch, extra):
    def forbidden(*a, **kw):
        pytest.fail("Invalid playback arguments reached account construction")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    args = BASE + (TIMES if extra else []) + extra
    assert cli.main(args) == 1


@pytest.mark.parametrize("audio", [False, True])
def test_default_playback_range_and_container_reach_real_public_dispatch(monkeypatch, audio):
    calls = []

    def copy(client, serial, output, begin, end, **kwargs):
        calls.append((begin, end, kwargs))
        output.write(b"PS")
        return {"bytes": 2}

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", copy)
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    # Drive the command handler without login or creating an actual path.
    original = client.save_clip

    def capture(serial, path, **kwargs):
        return original(serial, BytesIO(), **kwargs)

    monkeypatch.setattr(client, "save_clip", capture)
    args = build_parser().parse_args(BASE + TIMES + (["--decrypt-audio"] if audio else []))
    assert cli._handle_save_clip(args, client) == 0  # noqa: SLF001
    assert calls[0][2]["duration_seconds"] is None
    assert calls[0][2]["client_type"] == 3
    assert calls[0][2]["decrypt_audio"] is audio
    client.close_session()


@pytest.mark.parametrize(
    "extra",
    [
        ["--playback-timezone", "Not/AZone"],
        [
            "--playback-timezone",
            "America/New_York",
            "--begin-time",
            "20261101T061000Z",
            "--end-time",
            "20261101T061020Z",
        ],
    ],
)
def test_timezone_failure_precedes_account_access(monkeypatch, extra):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid timezone reached account construction")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    assert cli.main(BASE + TIMES + extra) == 1


def test_cli_routes_explicit_timezone_to_capture(monkeypatch):
    calls = []

    def copy(client, serial, output, begin, end, **kwargs):
        calls.append(kwargs)
        output.write(b"PS")
        return {"bytes": 2}

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", copy)
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    original = client.save_clip
    monkeypatch.setattr(
        client, "save_clip", lambda serial, path, **kwargs: original(serial, BytesIO(), **kwargs)
    )
    args = build_parser().parse_args(BASE + TIMES + ["--playback-timezone", "Africa/Johannesburg"])
    try:
        assert cli._handle_save_clip(args, client) == 0  # noqa: SLF001 -- command dispatch
    finally:
        client.close_session()
    assert calls[0]["timezone"] == "Africa/Johannesburg"
