"""Native file-search framing, completeness, clocks and cleanup controls."""

from datetime import UTC, datetime
import struct
import time

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local import recordings as lan
from pyezvizapi.streaming.local.recordings import _receive_search
from pyezvizapi.streaming.recordings import RecordingCatalog, StoredRecording, _batch_channel
from tests.streaming.local import test_lan_sd_playback as shared

BEGIN, END = shared.BEGIN, shared.END


def record(left="2026-11-08T10:15:20", right="2026-11-08T10:17:02"):
    stamps = [int(datetime.fromisoformat(v).replace(tzinfo=UTC).timestamp()) for v in (left, right)]
    return b"synthetic-file".ljust(32, b"\0") + struct.pack(">II", *stamps) + bytes(40)


def wire(*records):
    body = shared.block(27, struct.pack(">I", len(records)) + b"".join(records)) if records else b""
    return shared.block(25) + body + shared.block(26)


def receive(data, **kwargs):
    begin, end = lan.playback_range(BEGIN, END)
    return _receive_search(
        shared.Socket(data),
        deadline=time.monotonic() + 2,
        timeout=1,
        max_bytes=4096,
        max_records=10,
        begin=begin,
        end=end,
        timezone=kwargs.pop("timezone", "Africa/Johannesburg"),
        **kwargs,
    )


def test_selector_matches_native_trace():
    body = lan.lan_recording_search_body(1, BEGIN, END, "Africa/Johannesburg")
    assert len(body) == 148
    assert struct.unpack(">9I", body[:36]) == (1, 255, 255, 0, 0, 0, 0, 0, 0)
    assert struct.unpack(">12I", body[36:84]) == (2026, 11, 8, 10, 15, 22, 2026, 11, 8, 10, 15, 42)
    assert body[84:] == bytes(64)


def test_fragmented_records_clipped_deduplicated_and_empty():
    assert receive(wire(record(), record())) == (StoredRecording(BEGIN, END),)
    assert receive(wire()) == ()
    assert receive(wire(record("2026-11-08T09:00:00", "2026-11-08T09:01:00"))) == ()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        shared.block(25),
        shared.block(26),
        wire(record())[:-1],
        shared.block(25) * 2,
        shared.block(99),
        shared.block(25, b"bad"),
        shared.block(25) + shared.block(26, b"bad"),
        shared.block(25) + shared.block(27),
        shared.block(25) + shared.block(27, struct.pack(">I", 1) + bytes(79)),
        shared.block(25) + shared.block(27, struct.pack(">I", 0)),
        shared.block(25) + shared.block(27, struct.pack(">I", 100000)),
        wire(record("2026-11-08T10:16:00", "2026-11-08T10:15:00")),
        struct.pack(">II", 7, 25),
    ],
)
def test_invalid_or_partial_is_not_complete(data):
    with pytest.raises(PyEzvizError):
        receive(data)


def transport(monkeypatch, data, **kwargs):
    clients = shared.transport(monkeypatch, data, **kwargs)
    monkeypatch.setattr(lan, "HcNetSdkCommandPortClient", shared.playback.HcNetSdkCommandPortClient)
    monkeypatch.setattr(lan, "hcnetsdk_command_port_rsa_key", object)
    return clients


def query(**kwargs):
    return lan.query_lan_recordings(
        shared.ENDPOINT,
        "synthetic",
        BEGIN,
        END,
        timezone=kwargs.pop("timezone", "Africa/Johannesburg"),
        **kwargs,
    )


def test_session_closed_and_catalog_route_roundtrip(monkeypatch):
    clients = transport(monkeypatch, wire(record()))
    result = query()
    assert result.recordings == (StoredRecording(BEGIN, END),)
    assert result.discovery == "lan-hcnetsdk"
    assert RecordingCatalog.from_dict(result.to_dict()) == result
    assert [int.from_bytes(f[12:16], "big") for c in clients for f in c.sent] == [0x111040, 0x10100]
    assert len(clients) == 3 and all(c.closed for c in clients)


@pytest.mark.parametrize("kwargs", [{"max_bytes": 10}, {"max_records": 1}])
def test_budgets_never_return_partial_catalog(monkeypatch, kwargs):
    clients = transport(monkeypatch, wire(record(), record()))
    with pytest.raises(PyEzvizError):
        query(**kwargs)
    assert len(clients) == 3 and all(c.closed for c in clients)


def test_refusal_and_logout_failure(monkeypatch):
    clients = transport(monkeypatch, wire(), selection_status=7)
    with pytest.raises(lan.LanPlaybackError) as error:
        query()
    assert error.value.result_code == 7
    assert all(c.closed for c in clients)
    transport(monkeypatch, wire(), logout_error=OSError("closed"))
    with pytest.raises(OSError):
        query()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"channel": False},
        {"channel": 0},
        {"channel": 2**32},
        {"max_bytes": -1},
        {"max_records": True},
        {"transfer_timeout": float("nan")},
        {"timeout": 0},
        {"timezone": "Invalid/Zone"},
    ],
)
def test_invalid_input_before_network(monkeypatch, kwargs):
    clients = transport(monkeypatch, wire())
    with pytest.raises(PyEzvizError):
        query(**kwargs)
    assert not clients


def test_cli_lan_discovery_without_account(monkeypatch, tmp_path, capsys):
    clients = transport(monkeypatch, wire(record()))
    monkeypatch.setattr(cli.EzvizClient, "login", lambda *a, **k: pytest.fail("account login"))
    password = tmp_path / "password"
    password.write_text("synthetic")
    output = tmp_path / "catalog.json"
    assert (
        cli.main(
            [
                "recordings",
                "list",
                "--source",
                "lan-hcnetsdk",
                "--host",
                shared.ENDPOINT.host,
                "--serial",
                shared.SERIAL,
                "--lan-password-file",
                str(password),
                "--begin-time",
                BEGIN,
                "--end-time",
                END,
                "--timezone",
                "Africa/Johannesburg",
                "--catalog",
                str(output),
            ]
        )
        == 0
    )
    assert '"discovery": "lan-hcnetsdk"' in output.read_text()
    assert len(clients) == 3


def test_route_channel_namespaces():
    catalog = RecordingCatalog(shared.SERIAL, 2, "UTC", (), discovery="lan-hcnetsdk")
    assert _batch_channel(catalog, "local-playback", None) == 2
    with pytest.raises(PyEzvizError, match="explicit cloud channel"):
        _batch_channel(catalog, "cloud-playback", None)
    assert _batch_channel(catalog, "cloud-playback", 0) == 0


def test_ambiguous_record_timestamp_rejected():
    begin, end = lan.playback_range("20261025T000000Z", "20261025T030000Z")
    with pytest.raises(PyEzvizError, match="Ambiguous"):
        _receive_search(
            shared.Socket(wire(record("2026-10-25T01:10:00", "2026-10-25T01:20:00"))),
            deadline=time.monotonic() + 2,
            timeout=1,
            max_bytes=4096,
            max_records=10,
            begin=begin,
            end=end,
            timezone="Europe/London",
        )


def test_absolute_deadline_is_not_empty_success():
    begin, end = lan.playback_range(BEGIN, END)
    with pytest.raises(PyEzvizError, match="deadline"):
        _receive_search(
            shared.Socket(wire()),
            deadline=time.monotonic() - 1,
            timeout=1,
            max_bytes=4096,
            max_records=10,
            begin=begin,
            end=end,
            timezone="UTC",
        )


def test_cleanup_preserves_source_failure(monkeypatch):
    transport(monkeypatch, b"", logout_error=OSError("logout failed"))
    with pytest.raises(PyEzvizError) as error:
        query()
    assert "logout unacknowledged" in error.value.__notes__[0]
