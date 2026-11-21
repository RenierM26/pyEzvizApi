"""Offline tests for the live MPEG-TS ownership boundary."""

# ruff: noqa: PLR2004

from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from threading import Event
from unittest.mock import Mock

import pytest

from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming import live
from pyezvizapi.streaming.media.models import MediaPacket, MediaPacketMetadata


def _process(monkeypatch: pytest.MonkeyPatch, script: str) -> None:
    def launch(_path: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    monkeypatch.setattr(live, "open_mpegts_remux_process", launch)


def _packets(items: Iterable[MediaPacket]) -> Generator[MediaPacket, None, None]:
    yield from items


def test_reads_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = Mock()
    source.iter_media_packets.return_value = _packets(
        [MediaPacket(b"abc", MediaPacketMetadata(source="cloud_vtm"))]
    )
    with live.LiveMpegtsStream(source, "ffmpeg") as stream:
        assert stream.read(2) == b"ab"
        assert stream.read() == b"c"
        assert stream.read() == b""
    source.close.assert_called_once()


def test_encrypted_input_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    source = Mock()
    source.iter_media_packets.return_value = _packets(
        [MediaPacket(b"encrypted", MediaPacketMetadata(source="cloud_vtm", encrypted=True))]
    )
    with (
        live.LiveMpegtsStream(source, "ffmpeg") as stream,
        pytest.raises(EzvizUnsupportedMediaError),
    ):
        stream.read()


def test_ffmpeg_stderr_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stderr.write('bad media'); sys.exit(2)")
    source = Mock()
    source.iter_media_packets.return_value = _packets([])
    with (
        live.LiveMpegtsStream(source, "ffmpeg") as stream,
        pytest.raises(PyEzvizError, match="bad media"),
    ):
        stream.read()


def test_close_interrupts_reader_and_input(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    entered = Event()
    stopped = Event()

    def packets() -> Generator[MediaPacket, None, None]:
        entered.set()
        if not stopped.wait(5):
            raise TimeoutError("Source was not cancelled")
        yield from ()

    source = Mock()
    source.iter_media_packets.side_effect = packets
    source.close.side_effect = stopped.set
    with live.LiveMpegtsStream(source, "ffmpeg") as stream, ThreadPoolExecutor(1) as executor:
        reader = executor.submit(stream.read)
        assert entered.wait(2)
        stream.close()
        assert reader.result(timeout=2) == b""
    assert stopped.is_set()
