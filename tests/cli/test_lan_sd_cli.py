"""The LAN SD CLI must never authenticate an EZVIZ account."""

import json

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.client import EzvizClient
from pyezvizapi.streaming.local import playback

SECRET = b"device-secret"

BASE = [
    "--json",
    "save",
    "clip",
    "--source",
    "local-playback",
    "--serial",
    "C12345678",
    "--host",
    "192.0.2.10",
    "--begin-time",
    "20261108T081522Z",
    "--end-time",
    "20261108T081542Z",
    "--playback-timezone",
    "Africa/Johannesburg",
]


def test_cli_without_cloud_credentials_uses_device_password_file(monkeypatch, tmp_path, capsys):
    password = tmp_path / "password"
    password.write_bytes(SECRET + b"\n")
    calls = []

    def forbidden(*args, **kwargs):
        pytest.fail("LAN SD attempted account authentication or HTTP")

    def download(endpoint, secret, output, begin, end, **kwargs):
        calls.append((endpoint, secret, output, begin, end, kwargs))
        return {"ok": True, "bytes": 42, "output": str(output), "source": "local-playback"}

    monkeypatch.setattr(EzvizClient, "login", forbidden)
    monkeypatch.setattr(EzvizClient, "_request_json", forbidden)
    monkeypatch.setattr(playback, "download_lan_sd_recording", download)
    assert (
        cli.main(
            [*BASE, "--lan-password-file", str(password), "--output", str(tmp_path / "clip.ps")]
        )
        == 0
    )
    assert len(calls) == 1
    assert calls[0][1] == SECRET
    assert calls[0][-1]["duration_seconds"] is None
    assert calls[0][-1]["channel"] == 1
    assert calls[0][-1]["timezone"] == "Africa/Johannesburg"
    output = capsys.readouterr()
    assert json.loads(output.out)["bytes"] == 42
    assert "device-secret" not in output.out + output.err


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--format", "mpegts"],
        ["--max-packets", "5"],
        ["--decrypt-video"],
        ["--decrypt-audio"],
        ["--channel", "0"],
        ["--timeout", "nan"],
        ["--playback-transfer-timeout", "0"],
        ["--host", "camera.example.test"],
        ["--native-shared-clock"],
    ],
)
def test_invalid_lan_cli_rejected_before_client(monkeypatch, tmp_path, extra):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid LAN arguments reached client construction")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    # No password supplied in the first case; otherwise provide a synthetic one.
    credentials = ["--hcnetsdk-command-password", "synthetic"] if extra else []
    assert cli.main(BASE + credentials + ["--output", str(tmp_path / "clip.ps")] + extra) == 1
