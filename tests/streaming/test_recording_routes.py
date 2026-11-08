"""Route configurations preserve legacy adaptation and need no LAN account client."""

import json
from types import SimpleNamespace

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.recording_routes import (
    CloudRecordingRoute,
    LanRecordingRoute,
    RecordingBatchLimits,
)
from pyezvizapi.streaming.recordings import RecordingCatalog, StoredRecording, download_recordings
from tests.streaming.local import test_lan_recordings as search, test_lan_sd_playback as native
from tests.streaming.test_recordings import Saver, catalog

PRIVATE_KEY = b"SYNTHETIC_PRIVATE"


def forbidden(*args, **kwargs):
    pytest.fail("Account or token access during an account-free operation")


def test_accountless_batch_uses_complete_native_range_and_cross_entrypoint_resume(
    monkeypatch, tmp_path
):
    clients = native.transport(monkeypatch)
    selected = RecordingCatalog(
        native.SERIAL,
        1,
        "Africa/Johannesburg",
        (StoredRecording(native.BEGIN, native.END),),
        discovery="lan-hcnetsdk",
    )
    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    report = download_recordings(
        None,
        selected,
        tmp_path,
        source="local-playback",
        host=native.ENDPOINT.host,
        password="synthetic",
    )
    assert report["downloaded"] == 1 and report["failed"] == 0
    assert next(tmp_path.glob("*.ps")).read_bytes() == native.HEADER + native.media()
    assert len(clients) == 3 and all(c.closed for c in clients)
    report = download_recordings(
        SimpleNamespace(save_clip=forbidden),
        selected,
        tmp_path,
        source="local-playback",
        host=native.ENDPOINT.host,
        password="synthetic",
    )
    assert report["skipped"] == 1 and report["downloaded"] == 0
    assert len(clients) == 3


def test_lan_discovery_cli_never_constructs_account_or_reads_token(monkeypatch, tmp_path, capsys):
    clients = search.transport(monkeypatch, search.wire(search.record()))
    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    monkeypatch.setattr(cli, "_load_token_file", forbidden)
    password = tmp_path / "password"
    password.write_text("synthetic")
    result = cli.main(
        [
            "--token-file",
            str(tmp_path / "unused-token"),
            "recordings",
            "list",
            "--source",
            "lan-hcnetsdk",
            "--serial",
            native.SERIAL,
            "--host",
            native.ENDPOINT.host,
            "--lan-password-file",
            str(password),
            "--begin-time",
            native.BEGIN,
            "--end-time",
            native.END,
            "--timezone",
            "Africa/Johannesburg",
            "--catalog",
            str(tmp_path / "catalog"),
        ]
    )
    assert result == 0 and len(clients) == 3
    assert json.loads(capsys.readouterr().out)["discovery"] == "lan-hcnetsdk"


def test_cloud_decryption_profile_and_budgets_remain_explicit(tmp_path):
    client = Saver()
    report = download_recordings(
        client,
        catalog(),
        tmp_path,
        source="cloud-playback",
        channel=2,
        decrypt=False,
        media_key=PRIVATE_KEY,
        max_bytes=12345,
        transfer_timeout=25,
    )
    assert report["downloaded"] == 1
    options = client.calls[0][2]
    assert options["channel"] == 2
    assert options["decrypt_video"] is False and options["cloud_playback_decrypt_audio"] is False
    assert options["media_key"] == PRIVATE_KEY
    assert options["cloud_playback_max_bytes"] == 12345
    assert options["cloud_playback_transfer_timeout"] == 25
    assert "SYNTHETIC_PRIVATE" not in next(tmp_path.glob("*manifest.json")).read_text()


def test_route_representations_do_not_expose_credentials():
    assert "SYNTHETIC_PRIVATE" not in repr(LanRecordingRoute(1, "192.0.2.1", "SYNTHETIC_PRIVATE"))
    assert "SYNTHETIC_PRIVATE" not in repr(CloudRecordingRoute(0, media_key="SYNTHETIC_PRIVATE"))


@pytest.mark.parametrize(
    "kwargs", [{"max_bytes": False}, {"max_clips": 0}, {"transfer_timeout": float("inf")}]
)
def test_invalid_typed_limits(kwargs):

    with pytest.raises(PyEzvizError):
        RecordingBatchLimits(**kwargs)
