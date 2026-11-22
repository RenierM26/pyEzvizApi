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
from typing import Any, TypedDict
from unittest.mock import Mock

import pytest

from pyezvizapi.exceptions import EzvizNoMediaError, EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming import live, selection
from pyezvizapi.streaming.capture import AutoClipSource
from pyezvizapi.streaming.cloud.protocol import StreamInfoResponse, VtmStreamClient
from pyezvizapi.streaming.media.models import MediaPacket, MediaPacketMetadata
from pyezvizapi.streaming.media.rtp_timing import _pack_header
from tests.streaming.media.test_ps_stream_isolation import pes


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
        [MediaPacket(b"abc", MediaPacketMetadata(source="local_sdk"))]
    )
    with live.LiveMpegtsStream(source, "ffmpeg") as stream:
        assert stream.read(2) == b"ab"
        assert stream.read() == b"c"
        assert stream.read() == b""
    source.close.assert_called()


def test_reads_short_ffmpeg_output_before_source_ends(monkeypatch: pytest.MonkeyPatch) -> None:
    stopped = Event()
    source = _source()
    source.close.side_effect = stopped.set

    def packets(**_kwargs: Any) -> Generator[MediaPacket, None, None]:
        yield MediaPacket(b"abc", MediaPacketMetadata(source="local_sdk"))
        assert stopped.wait(5)

    source.iter_media_packets.side_effect = packets
    _process(
        monkeypatch,
        "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read(3)); "
        "sys.stdout.buffer.flush(); sys.stdin.buffer.read()",
    )
    with live.LiveMpegtsStream(source, "ffmpeg", startup_timeout=1) as stream:
        assert stream.read() == b"abc"
        assert not stopped.is_set()
    assert stopped.is_set()


@pytest.mark.parametrize(("header_size", "nal_header"), [(1, b"\x65"), (2, b"\x26\x01")])
def test_decrypts_inner_ps_video_with_clear_vtm_flag(
    monkeypatch: pytest.MonkeyPatch, header_size: int, nal_header: bytes
) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = _source()
    clear = b"0123456789abcdef"
    cipher = bytes.fromhex("34a1119c1a165ddeb3ad0fffba9282ec")
    start = b"\x00\x00\x00\x01" + nal_header
    audio = pes(0xC0, b"unchanged audio", 0)
    encrypted = _pack_header(0) + pes(0xE0, start + cipher, 0, aligned=True) + audio
    expected = _pack_header(0) + pes(0xE0, start + clear, 0, aligned=True) + audio
    source.iter_media_packets.return_value = _packets(
        MediaPacket(encrypted[index : index + 7], MediaPacketMetadata(source="cloud_vtm"))
        for index in range(0, len(encrypted), 7)
    )
    with live.LiveMpegtsStream(
        source, "ffmpeg", media_key="camera-key", nalu_header_size=header_size
    ) as stream:
        assert b"".join(iter(stream.read, b"")) == expected
    assert isinstance(stream._transform, live.NativePsTransform)
    assert stream._transform.pending_bytes == 0


def test_cloud_live_recovers_short_video_pes_at_next_pack(monkeypatch: pytest.MonkeyPatch) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = _source()
    key = b"test-camera-key!"
    clear = b"0123456789abcdef" * 2
    # Fixed ciphertext for the camera protocol fixture above.
    cipher = bytes.fromhex("423a0e8b042bbbceded349b7e544820b423a0e8b042bbbceded349b7e544820b")
    prefix = _pack_header(0) + pes(0xE0, b"\x00\x00\x00\x01\x42\x01" + cipher[:16], 0)
    next_pack = _pack_header(3600)
    audio = pes(0xC0, b"unchanged audio", 3600)
    wire = prefix + cipher[16:] + next_pack + audio
    expected = prefix[:-16] + clear + next_pack + audio
    source.iter_media_packets.return_value = _packets(
        MediaPacket(wire[index : index + 7], MediaPacketMetadata(source="cloud_vtm"))
        for index in range(0, len(wire), 7)
    )
    with live.LiveMpegtsStream(source, "ffmpeg", media_key=key) as stream:
        assert b"".join(iter(stream.read, b"")) == expected


def test_legacy_ps_waits_for_pes_run_and_leaves_audio_intact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = _source()
    key = b"test-camera-key!"
    clear = b"\x67" + b"0123456789abcde"
    # Fixed ciphertext for the camera protocol fixture above.
    encrypted = bytes.fromhex("7bbf37a75901cc1819fcf84396208a2f")
    start = b"\x00\x00\x00\x01"
    pack = _pack_header(0)
    audio = pes(0xC0, b"audio", 0)
    chunks = [
        pack + pes(0xE0, start + encrypted[:8], 0, aligned=True),
        pes(0xE0, encrypted[8:]),
        audio,
    ]
    source.iter_media_packets.return_value = _packets(
        MediaPacket(chunk, MediaPacketMetadata(source="cloud_vtm")) for chunk in chunks
    )
    with live.LiveMpegtsStream(source, "ffmpeg", media_key=key, nalu_header_size=0) as stream:
        assert b"".join(iter(stream.read, b"")) == (
            pack + pes(0xE0, start + clear[:8], 0, aligned=True) + pes(0xE0, clear[8:]) + audio
        )


def test_cloud_live_detects_legacy_header_and_replays_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(monkeypatch, "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())")
    source = _source()
    key = b"test-camera-key!"
    start = b"\x00\x00\x00\x01"
    clear = b"\x67" + b"0123456789abcde"
    cipher = bytes.fromhex("7bbf37a75901cc1819fcf84396208a2f")
    pack = _pack_header(0)
    audio = pes(0xC0, b"unchanged audio", 0)
    padding = pes(0xBE, bytes(4096))
    wire = pack + pes(0xE0, start + cipher, 0, aligned=True) + audio + padding
    source.iter_media_packets.return_value = _packets(
        MediaPacket(wire[index : index + 7], MediaPacketMetadata(source="cloud_vtm"))
        for index in range(0, len(wire), 7)
    )
    with live.LiveMpegtsStream(source, "ffmpeg", media_key=key) as stream:
        assert b"".join(iter(stream.read, b"")) == (
            pack + pes(0xE0, start + clear, 0, aligned=True) + audio + padding
        )
        assert isinstance(stream._transform, live.LegacyPsVideoTransform)
    source.iter_media_packets.assert_called_once()


def test_legacy_ps_releases_video_without_audio_at_aligned_nal() -> None:
    transform = live.LegacyPsVideoTransform(b"test-camera-key!")
    start = b"\x00\x00\x00\x01"
    encrypted = bytes.fromhex("7bbf37a75901cc1819fcf84396208a2f")
    clear = b"\x67" + b"0123456789abcde"
    first = pes(0xE0, start + encrypted[:8], 0, aligned=True)
    continuation = pes(0xE0, encrypted[8:])
    pack = _pack_header(3600)
    next_picture = pes(0xE0, start + encrypted, 3600, aligned=True)

    assert transform.feed(first + pack + continuation) == b""
    assert transform.feed(pack + next_picture[:-1]) == b""
    assert transform.feed(next_picture[-1:]) == (
        pes(0xE0, start + clear[:8], 0, aligned=True) + pack + pes(0xE0, clear[8:]) + pack
    )


def test_rtp_output_can_be_read_and_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    entered = Event()
    release = Event()
    source = _source()
    source.close.side_effect = release.set
    body = bytes.fromhex("806000010000000155667788") + b"payload"
    source.iter_media_packets.return_value = _packets(
        [
            MediaPacket(b"nonmedia prelude", MediaPacketMetadata(source="cloud_vtm")),
            MediaPacket(body, MediaPacketMetadata(source="cloud_vtm")),
        ]
    )

    def copy_rtp(packets: Iterable[Any], output: Any, **kwargs: Any) -> None:
        assert next(iter(packets)).body == body
        assert kwargs["audio_key"] == b"test-key"
        output.write(b"transport stream")
        output.flush()
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(live, "_copy_cloud_rtp_packets_to_mpegts", copy_rtp)
    with live.LiveMpegtsStream(source, "ffmpeg", media_key=b"test-key") as stream:
        assert entered.wait(2)
        assert stream.read() == b"transport stream"
        stream.close()
        assert not stream._writer.is_alive()


def test_input_without_mpegts_output_times_out_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received_input = Event()
    stopped = Event()
    source = _source()
    source.close.side_effect = stopped.set

    def packets(**_kwargs: Any) -> Generator[MediaPacket, None, None]:
        yield MediaPacket(b"not a complete frame", MediaPacketMetadata(source="local_sdk"))
        received_input.set()
        assert stopped.wait(5)

    source.iter_media_packets.side_effect = packets
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    with live.LiveMpegtsStream(source, "ffmpeg", startup_timeout=0.3) as stream:
        with pytest.raises(EzvizNoMediaError, match="no MPEG-TS output"):
            stream.read()
        assert received_input.is_set()
        assert stopped.is_set()
        assert not stream._writer.is_alive()


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
    source.iter_media_packets.return_value = _packets(
        [MediaPacket(b"bad input", MediaPacketMetadata(source="local_sdk"))]
    )
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


class QualityOptions(TypedDict, total=False):
    cloud_stream_index: int


@pytest.mark.parametrize("cloud_stream_index", [None, 2])
def test_close_during_cloud_bootstrap_retains_owner_until_it_exits(
    monkeypatch: pytest.MonkeyPatch,
    cloud_stream_index: int | None,
) -> None:
    _process(monkeypatch, "import sys; sys.stdin.buffer.read()")
    entered = Event()
    release = Event()
    client = Mock()
    transport = Mock()

    def open_cloud(_client: Any, serial: str, **kwargs: Any) -> Mock:
        assert serial == "CAMERA"
        assert kwargs["channel"] == 0
        assert kwargs["stream_index"] == (cloud_stream_index or 1)
        assert 0 < kwargs["capture_deadline"] - time.monotonic() <= 10
        entered.set()
        assert release.wait(5)
        return transport

    monkeypatch.setattr(selection, "open_cloud_stream", open_cloud)
    quality: QualityOptions = {}
    if cloud_stream_index is not None:
        quality["cloud_stream_index"] = cloud_stream_index
    stream = live.open_live_mpegts_stream(
        client,
        "CAMERA",
        channel=0,
        source=AutoClipSource(mode="cloud"),
        close_timeout=0.1,
        **quality,
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
    assert stream._process is None
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
        yield MediaPacket(b"x" * (8 * 1024 * 1024), MediaPacketMetadata(source="local_sdk"))

    source = _source()
    source.iter_media_packets.side_effect = packets
    with live.LiveMpegtsStream(source, "ffmpeg") as stream:
        assert entered.wait(2)
        stream.close()
        assert not stream._writer.is_alive()
        assert stream._process is not None
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
    assert stream._process is None
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


@pytest.mark.parametrize("result", [0, 5405])
def test_vtm_first_media_wait_and_rejection(monkeypatch: pytest.MonkeyPatch, result: int) -> None:
    transport = VtmStreamClient("ysproto://127.0.0.1:8554/live")
    iterator = Mock(return_value=iter(()))

    def start(**_kwargs: Any) -> None:
        transport.stream_info = StreamInfoResponse(result=result)

    monkeypatch.setattr(transport, "start", start)
    monkeypatch.setattr(transport, "iter_packets", iterator)
    monkeypatch.setattr(selection, "open_cloud_stream", lambda *_args, **_kwargs: transport)
    expected = "result 5405" if result else "did not contain media"
    with (
        live.open_live_mpegts_stream(
            Mock(), "CAMERA", source=AutoClipSource(mode="cloud")
        ) as stream,
        pytest.raises(EzvizNoMediaError, match=expected),
    ):
        stream.read()
    if result:
        iterator.assert_not_called()
    else:
        assert 0 < iterator.call_args.kwargs["first_packet_deadline"] - time.monotonic() <= 10
    assert not stream._writer.is_alive()
