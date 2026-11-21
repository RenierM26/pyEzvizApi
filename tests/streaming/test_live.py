"""Offline tests for the live MPEG-TS ownership boundary."""

# ruff: noqa: PLR2004, SLF001

from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
import json
from shutil import which
import socket
import subprocess
import sys
from threading import Event
import time
from typing import Any
from unittest.mock import Mock

import pytest

from pyezvizapi.exceptions import EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming import live, selection
from pyezvizapi.streaming.capture import AutoClipSource
from pyezvizapi.streaming.cloud.protocol import VtmStreamClient
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


def _source() -> Mock:
    return Mock(capture_result={"transport_closure_verified": True})


def test_reads_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = _source()
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
    source = _source()
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
    source = _source()
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

    def packets(**_kwargs: Any) -> Generator[MediaPacket, None, None]:
        entered.set()
        if not stopped.wait(5):
            raise TimeoutError("Source was not cancelled")
        yield from ()

    source = _source()
    source.iter_media_packets.side_effect = packets
    source.close.side_effect = stopped.set
    with live.LiveMpegtsStream(source, "ffmpeg") as stream, ThreadPoolExecutor(1) as executor:
        reader = executor.submit(stream.read)
        assert entered.wait(2)
        stream.close()
        assert reader.result(timeout=2) == b""
    assert stopped.is_set()


def test_close_during_cloud_bootstrap_retains_owner_until_it_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    entered = Event()
    release = Event()
    client = Mock()
    transport = Mock()

    def open_cloud(_client: Any, serial: str, **kwargs: Any) -> Mock:
        assert serial == "CAMERA"
        assert kwargs["channel"] == 0
        assert 0 < kwargs["capture_deadline"] - time.monotonic() <= 10
        entered.set()
        assert release.wait(5)
        return transport

    monkeypatch.setattr(selection, "open_cloud_stream", open_cloud)
    stream = live.open_live_mpegts_stream(
        client, "CAMERA", channel=0, source=AutoClipSource(mode="cloud"), close_timeout=0.1
    )
    try:
        assert entered.wait(2)
        with pytest.raises(live.LiveStreamShutdownTimeout, match="owner retained"):
            stream.close()
        assert stream._writer.is_alive()
        assert stream.read() == b""
        client.get_device_infos.assert_not_called()
        client.close_session.assert_not_called()
    finally:
        release.set()
        stream._writer.join(3)
        stream.close()
    transport.start.assert_not_called()
    transport.close.assert_called_once()
    assert stream._process.poll() is not None
    assert not stream._writer.is_alive()


def test_close_interrupts_a_real_vtm_socket_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    entered = Event()
    relay, peer = socket.socketpair()
    with relay, peer:
        peer.settimeout(2)
        transport = VtmStreamClient("ysproto://127.0.0.1:8554/live")
        monkeypatch.setattr(transport, "_socket_factory", lambda *_args: relay)
        monkeypatch.setattr(transport, "start", transport.connect)
        read_packet = transport.read_packet

        def read(**kwargs: Any) -> Any:
            entered.set()
            return read_packet(**kwargs)

        monkeypatch.setattr(transport, "read_packet", read)
        monkeypatch.setattr(selection, "open_cloud_stream", lambda *_args, **_kwargs: transport)
        with live.open_live_mpegts_stream(
            Mock(), "CAMERA", source=AutoClipSource(mode="cloud")
        ) as stream:
            assert entered.wait(2)
            stream.close()
            assert peer.recv(1) == b""
            assert relay.fileno() == -1
            assert not stream._writer.is_alive()


def test_close_releases_backpressure_from_a_full_child_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(monkeypatch, "import time; time.sleep(30)")
    entered = Event()

    def packets(**_kwargs: Any) -> Generator[MediaPacket, None, None]:
        entered.set()
        yield MediaPacket(b"x" * (8 * 1024 * 1024), MediaPacketMetadata(source="cloud_vtm"))

    source = _source()
    source.iter_media_packets.side_effect = packets
    with live.LiveMpegtsStream(source, "ffmpeg") as stream:
        assert entered.wait(2)
        stream.close()
        assert not stream._writer.is_alive()
        assert stream._process.poll() is not None


def test_close_does_not_report_unverified_transport_cleanup_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    source = _source()
    source.iter_media_packets.return_value = _packets([])
    source.capture_result["transport_closure_verified"] = False
    stream = live.LiveMpegtsStream(source, "ffmpeg")
    with pytest.raises(PyEzvizError, match="cleanup could not be verified"):
        stream.close()
    assert stream._process.poll() is not None
    assert not stream._writer.is_alive()


def test_real_ffmpeg_remux_preserves_video_and_audio() -> None:
    ffmpeg = which("ffmpeg")
    ffprobe = which("ffprobe")
    if not ffmpeg or not ffprobe:
        pytest.skip("FFmpeg and ffprobe are required for the media smoke test")
    program_stream = subprocess.run(
        [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=64x64:rate=10",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440",
            "-t",
            "1",
            "-c:v",
            "mpeg2video",
            "-c:a",
            "mp2",
            "-f",
            "mpeg",
            "pipe:1",
        ],
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout
    source = _source()
    source.iter_media_packets.return_value = _packets(
        [MediaPacket(program_stream, MediaPacketMetadata(source="cloud_vtm"))]
    )
    with live.LiveMpegtsStream(source, ffmpeg) as stream:
        transport_stream = b"".join(iter(stream.read, b""))
    probe = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name,codec_type",
            "-of",
            "json",
            "-f",
            "mpegts",
            "pipe:0",
        ],
        input=transport_stream,
        check=True,
        capture_output=True,
        timeout=10,
    )
    assert {
        entry["codec_type"]: entry["codec_name"] for entry in json.loads(probe.stdout)["streams"]
    } == {"video": "mpeg2video", "audio": "mp2"}
