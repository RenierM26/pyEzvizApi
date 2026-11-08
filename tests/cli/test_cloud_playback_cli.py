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
    ],
)
def test_invalid_playback_fails_before_constructing_a_client(monkeypatch, extra):
    def forbidden(*a, **kw):
        pytest.fail("Invalid playback arguments reached account construction")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    args = BASE + (TIMES if extra else []) + extra
    assert cli.main(args) == 1


def test_default_playback_range_and_container_reach_real_public_dispatch(monkeypatch):
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
    args = build_parser().parse_args(BASE + TIMES)
    assert cli._handle_save_clip(args, client) == 0  # noqa: SLF001
    assert calls[0][2]["duration_seconds"] is None
    assert calls[0][2]["client_type"] == 3
    client.close_session()
