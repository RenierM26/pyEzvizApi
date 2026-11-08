"""Catalog completeness, explicit clocks, batch preservation and resume controls."""
import base64
from datetime import datetime
import json
from pathlib import Path
import zlib

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.recordings import (
    RecordingCatalog,
    StoredRecording,
    download_recordings,
    query_recordings,
)

BEGIN = "20261108T060000Z"
END = "20261108T060020Z"
RECORD = {"B": "2026-11-08T08:00:00", "E": "2026-11-08T08:00:20"}


def catalog():
    return RecordingCatalog("SYNTHETIC", 0, "Africa/Johannesburg", (StoredRecording(BEGIN, END),))


class Index:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def search_records_v2(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.payload(*args, **kwargs) if callable(self.payload) else self.payload


def test_catalog_normalizes_explicit_wall_clock_and_deduplicates():
    index = Index({"records": [RECORD, RECORD]})
    result = query_recordings(index, "SYNTHETIC", BEGIN, END, timezone="Africa/Johannesburg")
    assert result == catalog()
    args, kwargs = index.calls[0]
    assert args[2:] == ("2026-11-08T08:00:00", "2026-11-08T08:00:20")
    assert kwargs["max_retries"] == 0
    assert RecordingCatalog.from_dict(result.to_dict()) == result


def test_compressed_catalog_and_clipping():
    value = base64.b64encode(zlib.compress(json.dumps([RECORD]).encode())).decode()
    result = query_recordings(Index({"data": {"records": value}}), "SYNTHETIC",
                              "20261108T060005Z", "20261108T060015Z", timezone="Africa/Johannesburg")
    assert result.recordings == (StoredRecording("20261108T060005Z", "20261108T060015Z"),)


@pytest.mark.parametrize("payload", [{}, {"records": "bad"}, {"records": None},
    {"records": [{}]}, {"records": [False]}, {"records": [{"B": RECORD["E"], "E": RECORD["B"]}]}])
def test_malformed_index_is_not_empty_success(payload):
    with pytest.raises(PyEzvizError):
        query_recordings(Index(payload), "SYNTHETIC", BEGIN, END)


def test_empty_index_is_valid():
    assert query_recordings(Index({"records": []}), "SYNTHETIC", BEGIN, END).recordings == ()


def test_saturation_subdivides_and_keeps_all_records():
    def payload(*args, **kwargs):
        left, right = (datetime.fromisoformat(value) for value in args[2:])
        if (right - left).total_seconds() > 10:
            return {"records": [RECORD, RECORD]}
        return {"records": [{"B": left.isoformat(), "E": right.isoformat()}]}
    index = Index(payload)
    result = query_recordings(index, "SYNTHETIC", BEGIN, END, page_size=2)
    assert len(index.calls) == 3
    assert len(result.recordings) == 2


@pytest.mark.parametrize("kwargs", [{"max_queries": 1}, {"max_records": 1}])
def test_exhausted_budget_fails_without_partial_catalog(kwargs):
    index = Index({"records": [{"B": "2026-11-08T06:00:00", "E": "2026-11-08T06:00:20"}, {"B": "2026-11-08T06:00:01", "E": "2026-11-08T06:00:03"}]})
    with pytest.raises(PyEzvizError):
        query_recordings(index, "SYNTHETIC", BEGIN, END,
                         page_size=2 if "max_queries" in kwargs else 100,
                         max_queries=kwargs.get("max_queries", 256), max_records=kwargs.get("max_records", 10000))


def test_one_second_saturation_fails():
    with pytest.raises(PyEzvizError, match="saturated"):
        query_recordings(Index({"records": [RECORD]}), "SYNTHETIC", BEGIN, "20261108T060001Z", page_size=1)


def test_multi_day_search_is_bounded():
    index = Index({"records": []})
    query_recordings(index, "SYNTHETIC", BEGIN, "20261110T060000Z")
    assert len(index.calls) == 2


@pytest.mark.parametrize("begin,end,zone", [
    ("20261108T060000", END, "UTC"), (END, BEGIN, "UTC"),
    (BEGIN, END, "Bad/Zone"), ("20261025T003000Z", "20261025T023000Z", "Europe/London"),
])
def test_invalid_selection_does_not_call_network(begin, end, zone):
    index = Index({"records": []})
    with pytest.raises(PyEzvizError):
        query_recordings(index, "SYNTHETIC", begin, end, timezone=zone)
    assert not index.calls


@pytest.mark.parametrize("stamp", ["2026-10-25T01:30:00", "2026-03-29T01:30:00"])
def test_ambiguous_and_nonexistent_index_times_rejected(stamp):
    index = Index({"records": [{"B": stamp, "E": "2026-10-25T04:00:00"}]})
    with pytest.raises(PyEzvizError):
        query_recordings(index, "SYNTHETIC", "20261025T000000Z", "20261025T003000Z", timezone="Europe/London")


class Saver:
    def __init__(self):
        self.calls = []
        self.fail = False

    def close_session(self):
        pass

    def save_clip(self, serial, path, **kwargs):
        self.calls.append((serial, path, kwargs))
        if self.fail:
            raise PyEzvizError("PRIVATE KEY SHOULD NOT BE PERSISTED")
        Path(path).write_bytes(b"validated-media")
        return {"ok": True}


@pytest.mark.parametrize("source,channel", [("local-playback", 1), ("cloud-playback", 0)])
def test_batch_route_parameters_and_verified_resume(tmp_path, source, channel):
    client = Saver()
    kwargs = dict(source=source, host="192.0.2.1", password="PRIVATE")
    result = download_recordings(client, catalog(), tmp_path, **kwargs)
    assert result["downloaded"] == 1
    route = client.calls[0][2]
    assert route["source"] == source and route["channel"] == channel
    assert route["duration_seconds"] is None
    assert route[("local" if channel else "cloud") + "_playback_begin_time"] == BEGIN
    result = download_recordings(client, catalog(), tmp_path, **kwargs)
    assert result["skipped"] == 1 and len(client.calls) == 1
    assert "PRIVATE" not in next(tmp_path.glob("*manifest.json")).read_text()


def test_changed_file_not_overwritten(tmp_path):
    client = Saver()
    download_recordings(client, catalog(), tmp_path, source="cloud-playback")
    path = next(tmp_path.glob("*.ps"))
    changed = b"changed"
    path.write_bytes(changed)
    result = download_recordings(client, catalog(), tmp_path, source="cloud-playback")
    assert result["failed"] == 1 and len(client.calls) == 1
    assert path.read_bytes() == changed


def test_missing_receipt_preserves_existing_file(tmp_path):
    client = Saver()
    download_recordings(client, catalog(), tmp_path, source="cloud-playback")
    next(tmp_path.glob("*manifest.json")).unlink()
    result = download_recordings(client, catalog(), tmp_path, source="cloud-playback")
    assert result["failed"] == 1 and len(client.calls) == 1


def test_failures_continue_and_are_retried_on_resume(tmp_path):
    client = Saver()
    client.fail = True
    selected = RecordingCatalog("SYNTHETIC", 0, "UTC", (*catalog().recordings,
        StoredRecording("20261108T070000Z", "20261108T070020Z"),))
    result = download_recordings(client, selected, tmp_path, source="cloud-playback")
    assert result["failed"] == 2 and len(client.calls) == 2
    assert "PRIVATE" not in next(tmp_path.glob("*manifest.json")).read_text()
    client.fail = False
    result = download_recordings(client, selected, tmp_path, source="cloud-playback")
    assert result["downloaded"] == 2


@pytest.mark.parametrize("kwargs", [{"source": "auto"}, {"source": "local-playback"},
    {"source": "cloud-playback", "max_clips": 0},
    {"source": "cloud-playback", "max_bytes": 0},
    {"source": "cloud-playback", "transfer_timeout": float("nan")}])
def test_invalid_batch_does_not_acquire(tmp_path, kwargs):
    client = Saver()
    with pytest.raises(PyEzvizError):
        download_recordings(client, catalog(), tmp_path, **kwargs)
    assert not client.calls


def test_cli_local_saved_catalog_never_logs_in(tmp_path, monkeypatch, capsys):
    client = Saver()
    monkeypatch.setattr(cli, "EzvizClient", lambda *a, **k: client)
    selected = tmp_path / "catalog.json"
    selected.write_text(json.dumps(catalog().to_dict()))
    password = tmp_path / "password"
    password.write_text("PRIVATE")
    result = cli.main(["--token-file", str(tmp_path / "missing"), "recordings", "download",
        "--catalog", str(selected), "--output", str(tmp_path / "out"),
        "--source", "local-playback", "--host", "192.0.2.1", "--lan-password-file", str(password)])
    assert result == 0 and len(client.calls) == 1
    assert json.loads(capsys.readouterr().out)["local-playback"]["downloaded"] == 1


def test_app_zero_padded_compression():
    compressed = zlib.compress(json.dumps([RECORD]).encode())
    payload = base64.b64encode(compressed + bytes(31)).decode()
    result = query_recordings(Index({"records": payload, "isFinished": 1}), "SYNTHETIC",
                              BEGIN, END, timezone="Africa/Johannesburg")
    assert result == catalog()


def test_explicit_unfinished_index_is_not_complete():
    with pytest.raises(PyEzvizError, match="budget"):
        query_recordings(Index({"records": [], "isFinished": 0}), "SYNTHETIC",
                         BEGIN, END, max_queries=1)


def test_compressed_trailing_junk_is_rejected():
    compressed = zlib.compress(b"[]") + b"junk"
    with pytest.raises(PyEzvizError):
        query_recordings(Index({"records": base64.b64encode(compressed).decode()}),
                         "SYNTHETIC", BEGIN, END)
