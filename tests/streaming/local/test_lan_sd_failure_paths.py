"""Publication and deadline ownership for LAN SD failures."""

from io import BytesIO

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local import playback
from tests.streaming.local.test_lan_sd_playback import download, transport

ORIGINAL = b"original"

def test_deadline_does_not_reset_for_each_partial_read(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(playback.time, "monotonic", lambda: now[0])

    class DribblingSocket:
        def settimeout(self, timeout):
            assert timeout <= 1

        def recv(self, size):
            now[0] += 0.4
            return b"a"

    with pytest.raises(PyEzvizError, match="deadline"):
        playback._read_exact(DribblingSocket(), 10, 101, 5)  # noqa: SLF001 -- deadline boundary probe
    assert now[0] < 102


def test_valid_transfer_but_final_flush_failure_is_visible(monkeypatch):
    transport(monkeypatch)

    class BrokenFlush(BytesIO):
        def flush(self):
            raise OSError("synthetic flush failure")

    with pytest.raises(OSError, match="flush failure"):
        download(BrokenFlush())


def test_atomic_replace_failure_preserves_destination_and_removes_temporary(monkeypatch, tmp_path):
    transport(monkeypatch)
    target = tmp_path / "keep.ps"
    target.write_bytes(ORIGINAL)

    def broken(*args):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(playback.os, "replace", broken)
    with pytest.raises(OSError, match="replace failure"):
        download(target)
    assert target.read_bytes() == ORIGINAL
    assert list(tmp_path.iterdir()) == [target]


def test_shutdown_retains_original_process_control_exception(monkeypatch):
    clients = transport(monkeypatch)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(playback, "_receive", interrupt)
    with pytest.raises(KeyboardInterrupt):
        download(BytesIO())
    assert len(clients) == 3 and all(c.closed for c in clients)


def test_short_writes_preserve_all_validated_bytes(monkeypatch):
    transport(monkeypatch)

    class ShortWrites(BytesIO):
        def write(self, data):
            return super().write(data[:3])

    out = ShortWrites()
    result = download(out)
    assert result["bytes"] == len(out.getvalue())


def test_socket_idle_timeout_cannot_be_reported_as_completion(monkeypatch):
    clients = transport(monkeypatch)
    original = clients

    def interrupted(stream, *args, **kwargs):
        def timeout(size):
            raise TimeoutError

        stream.sock.recv = timeout
        return receive(stream, *args, **kwargs)

    receive = playback._receive  # noqa: SLF001 -- failure injection at transport boundary
    monkeypatch.setattr(playback, "_receive", interrupted)
    with pytest.raises(PyEzvizError, match="timed out"):
        download(BytesIO())
    assert all(c.closed for c in original)
