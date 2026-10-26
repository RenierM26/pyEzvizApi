"""Continuous ownership, source-clock copy, backpressure and cancellation."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import io
import shutil
import subprocess
import threading
import time
from typing import cast

import pytest
from test_local_av_decrypted import fixture as crypto_fixture
from test_local_av_timeline import encode_three_track_ps
from test_stream_sample import annexb_oracle, packet_oracle
from test_stream_selection import CAMERA, credentials

from pyezvizapi import native_stream
from pyezvizapi.client import EzvizClient
from pyezvizapi.clip import AutoClipSource
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.media import MediaPacket, MediaPacketMetadata
from pyezvizapi.native_ps import MAX_PENDING_PS_BYTES, NativePsTransform
from pyezvizapi.native_stream import (
    OUTPUT_QUEUE_CHUNKS,
    NativeMpegTsStream,
    NativeStreamClosed,
    NativeStreamOptions,
    NativeTrackSelection,
    native_mpegts_stream_from_client,
)
from pyezvizapi.rtp_timing import _mpeg_crc32, _pack_header, _pes


class Source:
    def __init__(
        self, data=b"", *, bodies=None, block=False, error=None, close_error=False, cooperate=True
    ):
        self.data = data
        self.bodies = bodies
        self.block = block
        self.error = error
        self.close_error = close_error
        self.cooperate = cooperate
        self.entered = threading.Event()
        self.release = threading.Event()
        self.iterator_closed = threading.Event()
        self.closed = False
        self.close_calls = self.pulls = 0
        self.iterator_thread = self.close_iterator_thread = None

    def iter_media_packets(self):
        self.iterator_thread = threading.get_ident()
        try:
            bodies = (
                self.bodies
                if self.bodies is not None
                else (
                    self.data[offset : offset + 1024] for offset in range(0, len(self.data), 1024)
                )
            )
            for body in bodies:
                self.pulls += 1
                yield MediaPacket(body, MediaPacketMetadata("local_sdk", 0, False))
            self.entered.set()
            if self.block:
                self.release.wait(10)
            if self.error:
                raise self.error
        finally:
            self.close_iterator_thread = threading.get_ident()
            self.iterator_closed.set()

    def close(self):
        self.close_calls += 1
        if self.cooperate:
            self.release.set()
        if self.close_error:
            raise OSError("private cleanup details")
        self.closed = True


def options(**changes):
    return replace(
        NativeStreamOptions(NativeTrackSelection(481, 448), "hevc", finite_source=True), **changes
    )


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    return encode_three_track_ps(
        tmp_path_factory.mktemp("native-ps"), audio_jitter=True
    ).read_bytes()


@pytest.mark.parametrize("size", [1, 7, 32, 65536])
def test_incremental_decryption_exact_across_arbitrary_packet_splits(size):
    cipher, expected = crypto_fixture()
    transform = NativePsTransform("camera-key")
    clear = (
        b"".join(transform.feed(cipher[i : i + size]) for i in range(0, len(cipher), size))
        + transform.finish()
    )
    assert clear == expected
    assert transform.pending_bytes == 0
    transform.close()
    with pytest.raises(PyEzvizError, match="closed"):
        transform.feed(b"x")


def test_ps_bounds_and_partial_tail_are_explicit():
    transform = NativePsTransform("camera-key")
    cipher, _expected = crypto_fixture()
    assert not transform.feed(cipher[:2])
    with pytest.raises(PyEzvizError, match="before append"):
        transform.feed(b"x" * MAX_PENDING_PS_BYTES)
    assert transform.pending_bytes == 2
    with pytest.raises(PyEzvizError, match="partial"):
        transform.finish()
    transform.close()
    with pytest.raises(PyEzvizError, match="MPEG-PS"):
        NativePsTransform().feed(b"IDMX")


def test_continuous_boundary_copies_selected_id_audio_and_original_clock(sample):
    source = Source(sample)
    stream = NativeMpegTsStream(lambda: source, options())
    with stream:
        output = b"".join(stream)
    original = packet_oracle(sample)
    actual = packet_oracle(output)
    assert actual[1] == original[1]  # Full AAC bodies and exact PTS/DTS/duration.
    assert [packet[1:] for packet in actual[0]] == [packet[1:] for packet in original[2]]

    def without_aud(units):
        return [unit for unit in units if (unit[0] >> 1) & 63 != 35]

    # The selected lens is ID 481, absolute index 2; not lens ordinal 1.
    elementary = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            "pipe:0",
            "-map",
            "0:2",
            "-c",
            "copy",
            "-f",
            "hevc",
            "pipe:1",
        ],
        input=sample,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    assert without_aud(annexb_oracle(output, "hevc")) == without_aud(
        annexb_oracle(elementary, "hevc")
    )
    receipt = stream.receipt
    assert receipt["status"] == "completed" and receipt["finite_source_end"]
    assert receipt["clear_sha256"] == hashlib.sha256(sample).hexdigest()
    assert receipt["selected_tracks"] == [
        {"id": 481, "index": 2, "kind": "video", "codec": "hevc"},
        {"id": 448, "index": 1, "kind": "audio", "codec": "aac"},
    ]
    assert receipt["worker_joined"] and receipt["cancel_joined"] and receipt["source_closed"]
    assert receipt["queued_chunks"] == receipt["owned_output_chunks"] == 0
    assert source.iterator_thread == source.close_iterator_thread


@pytest.mark.parametrize(
    "selection,codec",
    [
        (NativeTrackSelection(999, 448), "hevc"),
        (NativeTrackSelection(448), "hevc"),
        (NativeTrackSelection(481, 480), "hevc"),
        (NativeTrackSelection(481, 448), "h264"),
    ],
)
def test_missing_id_wrong_kind_and_codec_change_fail_before_output(sample, selection, codec):
    source = Source(sample)
    stream = NativeMpegTsStream(lambda: source, options(selection=selection, video_codec=codec))
    with pytest.raises(PyEzvizError, match="worker failed"), stream:
        stream.read()
    assert stream.receipt["output_bytes"] == 0
    assert source.closed and stream.receipt["worker_joined"]


def test_live_eof_is_error_not_verified_recording_end(sample):
    source = Source(sample)
    stream = NativeMpegTsStream(lambda: source, options(finite_source=False))
    with pytest.raises(PyEzvizError), stream:
        list(stream)
    assert not stream.receipt["finite_source_end"]
    assert stream.receipt["status"] == "failed" and source.closed


def test_queue_credit_bounds_paused_consumer_and_close_releases_all(sample):
    source = Source(sample)
    stream = NativeMpegTsStream(lambda: source, options()).start()
    deadline = time.monotonic() + 3
    while (
        stream.receipt["owned_output_chunks"] < OUTPUT_QUEUE_CHUNKS and time.monotonic() < deadline
    ):
        time.sleep(0.005)
    assert stream.receipt["owned_output_chunks"] == OUTPUT_QUEUE_CHUNKS
    stream.close()
    assert stream.receipt["peak_owned_output_chunks"] == OUTPUT_QUEUE_CHUNKS
    assert stream.receipt["owned_output_chunks"] == 0
    assert stream.receipt["discarded_output_bytes"] > 0
    assert stream.receipt["output_bytes"] == stream.receipt["discarded_output_bytes"]
    assert stream.receipt["read_output_bytes"] == 0
    assert stream.receipt["worker_joined"] and source.closed


def test_close_interrupts_pending_source_read_without_closing_executing_generator():
    source = Source(block=True)
    stream = NativeMpegTsStream(lambda: source, options(finite_source=False)).start()
    assert source.entered.wait(2)
    stream.close()
    assert source.iterator_closed.is_set() and source.closed
    assert source.iterator_thread == source.close_iterator_thread
    with pytest.raises(NativeStreamClosed):
        stream.read()


def test_startup_timeout_is_failure_and_releases_transport():
    source = Source(block=True)
    stream = NativeMpegTsStream(lambda: source, options(startup_timeout=0.1, finite_source=False))
    with pytest.raises(TimeoutError):
        stream.read()
    assert source.closed and stream.receipt["worker_joined"]
    assert stream.receipt["status"] == "failed"


def test_noncooperative_source_preserves_handle_until_recovery():
    source = Source(block=True, cooperate=False)
    stream = NativeMpegTsStream(
        lambda: source, options(close_timeout=0.05, finite_source=False)
    ).start()
    assert source.entered.wait(2)
    try:
        with pytest.raises(PyEzvizError, match="owner retained"):
            stream.close()
        assert not stream.receipt["worker_joined"]
    finally:
        source.release.set()
        stream.close()
    assert stream.receipt["worker_joined"] and source.iterator_closed.is_set()


def test_primary_source_failure_and_cleanup_failure_are_both_retained():
    source = Source(error=ValueError("private source details"), close_error=True)
    stream = NativeMpegTsStream(lambda: source, options())
    with pytest.raises(PyEzvizError, match="worker failed") as error:
        stream.read()
    assert isinstance(error.value.__cause__, ValueError)
    assert stream.receipt["cleanup_error_types"]
    assert not stream.receipt["source_closed"]
    source.close_error = False
    # Retry can recover ownership, but the recorded cleanup error is not erased.
    with pytest.raises(PyEzvizError, match="cleanup failed"):
        stream.close()
    assert stream.receipt["source_closed"]


def test_close_before_start_is_lazy_and_missing_runtime_does_not_acquire(monkeypatch):
    calls = []

    def factory():
        calls.append(1)
        return Source()

    stream = NativeMpegTsStream(factory, options())
    stream.close()
    assert calls == [] and stream.receipt["worker_joined"]

    def missing(_name):
        raise ModuleNotFoundError("av")

    monkeypatch.setattr(native_stream, "import_module", missing)
    with pytest.raises(PyEzvizError) as error:
        NativeMpegTsStream(factory, options()).read()
    assert isinstance(error.value.__cause__, ModuleNotFoundError)
    assert calls == []


def test_async_pending_read_cancellation_joins_source_and_executor_read():
    async def run():
        source = Source(block=True)
        stream = NativeMpegTsStream(lambda: source, options(finite_source=False))

        async def consume():
            async with stream:
                async for _chunk in stream.async_chunks():
                    pytest.fail("unexpected output")

        task = asyncio.create_task(consume())
        assert await asyncio.to_thread(source.entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.receipt["worker_joined"] and stream.receipt["cancel_joined"]
        assert source.closed and source.iterator_closed.is_set()

    asyncio.run(run())


def test_repeated_async_cancellation_waits_for_owned_shutdown():
    async def run():
        close_entered, release_close = threading.Event(), threading.Event()

        class SlowClose(Source):
            def close(self):
                close_entered.set()
                release_close.wait(2)
                super().close()

        source = SlowClose(block=True)
        stream = NativeMpegTsStream(lambda: source, options(finite_source=False))

        async def consume():
            async with stream:
                async for _chunk in stream.async_chunks():
                    pytest.fail("unexpected output")

        task = asyncio.create_task(consume())
        assert await asyncio.to_thread(source.entered.wait, 2)
        task.cancel()
        assert await asyncio.to_thread(close_entered.wait, 2)
        task.cancel()
        release_close.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert stream.receipt["worker_joined"] and stream.receipt["cancel_joined"]

    asyncio.run(run())


def test_async_cleanup_does_not_starve_behind_a_saturated_read_executor():
    async def run():
        asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
        source = Source(block=True)
        stream = NativeMpegTsStream(lambda: source, options(finite_source=False))

        async def consume():
            async with stream:
                async for _chunk in stream.async_chunks():
                    pytest.fail("unexpected output")

        task = asyncio.create_task(consume())
        deadline = time.monotonic() + 2
        while not source.entered.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.005)
        assert source.entered.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 1)
        assert source.closed and stream.receipt["worker_joined"]

    asyncio.run(run())


def test_async_exit_does_not_repeat_a_failed_shutdown_budget(monkeypatch):
    async def run():
        source = Source(block=True, cooperate=False)
        stream = NativeMpegTsStream(
            lambda: source, options(finite_source=False, close_timeout=0.05)
        )
        original_close, attempts = stream.close, []

        def counted_close():
            attempts.append(1)
            original_close()

        monkeypatch.setattr(stream, "close", counted_close)

        async def consume():
            async with stream:
                async for _chunk in stream.async_chunks():
                    pytest.fail("unexpected output")

        task = asyncio.create_task(consume())
        assert await asyncio.to_thread(source.entered.wait, 2)
        try:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert len(attempts) == 1
            assert stream.receipt["shutdown_timed_out"]
        finally:
            source.release.set()
            original_close()
        assert stream.receipt["worker_joined"]

    asyncio.run(run())


def test_partial_source_construction_and_iterator_cleanup_keep_primary_error():
    class BrokenIterator:
        def __iter__(self):
            return self

        def __next__(self):
            raise ValueError("source failure")

        def close(self):
            raise RuntimeError("iterator cleanup failure")

    class BrokenSource(Source):
        def iter_media_packets(self):
            return BrokenIterator()

    source = BrokenSource()
    stream = NativeMpegTsStream(lambda: source, options())
    with pytest.raises(PyEzvizError) as error:
        stream.read()
    assert isinstance(error.value.__cause__, ValueError)
    assert stream.receipt["cleanup_error_types"] == ["RuntimeError"]
    assert source.closed and stream.receipt["worker_joined"]


def test_source_factory_finishing_after_cancel_never_starts_acquisition():
    entered, release = threading.Event(), threading.Event()
    source = Source()

    def factory():
        entered.set()
        release.wait(2)
        return source

    stream = NativeMpegTsStream(factory, options(close_timeout=0.05)).start()
    assert entered.wait(2)
    try:
        with pytest.raises(PyEzvizError, match="owner retained"):
            stream.close()
        assert stream.receipt["shutdown_timed_out"]
    finally:
        release.set()
        stream.close()
    assert source.closed and not source.entered.is_set()
    assert stream.receipt["worker_joined"]


def test_track_id_resolution_does_not_reuse_recorded_absolute_indices(tmp_path):
    changed = encode_three_track_ps(tmp_path, discovery_order=(1, 2, 0)).read_bytes()
    with NativeMpegTsStream(lambda: Source(changed), options()) as stream:
        output = b"".join(stream)
    assert output
    assert stream.receipt["selected_tracks"][0] == {
        "id": 481,
        "index": 0,
        "kind": "video",
        "codec": "hevc",
    }


def repeated_ps_packets(data: bytes, cycles: int, codec="hevc"):
    """Independent test framing; a tiny encoded fixture, not whole-stream storage."""
    av = pytest.importorskip("av")
    with av.open(io.BytesIO(data)) as container:
        packets = [(p.stream.id, p.pts, p.dts, bytes(p)) for p in container.demux() if p.size]
    video_type = 0x24 if codec == "hevc" else 0x1B
    entries = bytes((video_type, 0xE0, 0, 0, 0x0F, 0xC0, 0, 0, video_type, 0xE1, 0, 0))
    body = b"\xe0\xff\x00\x00" + len(entries).to_bytes(2, "big") + entries
    mapping = b"\x00\x00\x01\xbc" + (len(body) + 4).to_bytes(2, "big") + body
    mapping += _mpeg_crc32(mapping)
    scr = 0
    for cycle in range(cycles):
        for source_id, source_pts, source_dts, payload in packets:
            sid = {256: 480, 257: 481, 258: 448}.get(source_id, source_id)
            pts, dts = source_pts + cycle * 90000, source_dts + cycle * 90000
            row = _pes(pts, sid & 255, payload)
            if pts != dts:
                stamp = bytes([row[9] | 0x10]) + row[10:14]
                decode = _pes(dts, sid & 255, b"")
                decode = bytes([decode[9] & ~0x20]) + decode[10:14]
                row = (
                    row[:4]
                    + (len(payload) + 13).to_bytes(2, "big")
                    + b"\x80\xc0\x0a"
                    + stamp
                    + decode
                    + payload
                )
            scr = max(scr, dts)
            yield _pack_header(scr) + mapping + row


def test_virtual_three_minute_source_has_no_total_capture_or_history_limit(sample):
    source = Source(bodies=repeated_ps_packets(sample, 180))
    with NativeMpegTsStream(lambda: source, options()) as stream:
        output = b"".join(stream)
    packets = packet_oracle(output)
    assert packets[0][-1][1] - packets[0][0][1] > 120 * 90000
    original = packet_oracle(sample)
    assert len(packets[0]) == len(original[2]) * 180
    assert len(packets[1]) == len(original[1]) * 180
    receipt = stream.receipt
    assert receipt["peak_pending_ps_bytes"] <= MAX_PENDING_PS_BYTES
    assert receipt["peak_read_bytes"] <= MAX_PENDING_PS_BYTES
    assert receipt["peak_owned_output_chunks"] <= OUTPUT_QUEUE_CHUNKS
    assert receipt["pending_ps_bytes"] == receipt["pending_read_bytes"] == 0
    assert receipt["owned_output_chunks"] == 0 and receipt["worker_joined"]


def test_source_failure_after_streaming_is_not_downgraded_by_native_io(sample):
    source = Source(
        bodies=repeated_ps_packets(sample, 20), error=ConnectionResetError("private endpoint")
    )
    stream = NativeMpegTsStream(lambda: source, options())
    with pytest.raises(PyEzvizError) as error, stream:
        for _chunk in stream:
            pass
    assert isinstance(error.value.__cause__, ConnectionResetError)
    assert stream.receipt["read_output_bytes"] > 0
    assert source.closed and stream.receipt["worker_joined"]


def test_decode_timestamp_reset_fails_instead_of_repair_or_rebase(sample):
    stream = NativeMpegTsStream(lambda: Source(sample + sample), options())
    with pytest.raises(PyEzvizError) as error, stream:
        list(stream)
    assert "timestamp" in str(error.value.__cause__)
    assert stream.receipt["worker_joined"] and not stream.receipt["owned_output_chunks"]


def test_real_h264_aac_stream_copy_retains_packets_and_clocks():
    if not shutil.which("ffmpeg"):
        pytest.skip("FFmpeg fixture encoder unavailable")
    generated = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=64x48:rate=10",
            "-f",
            "lavfi",
            "-i",
            "color=red:size=64x48:rate=10",
            "-f",
            "lavfi",
            "-i",
            "sine=sample_rate=16000",
            "-t",
            "0.6",
            "-map",
            "0:v",
            "-map",
            "1:v",
            "-map",
            "2:a",
            "-c:v",
            "libx264",
            "-threads:v",
            "1",
            "-bf",
            "0",
            "-c:a",
            "aac",
            "-f",
            "mpegts",
            "pipe:1",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    ).stdout
    ps = b"".join(repeated_ps_packets(generated, 1, codec="h264"))
    with NativeMpegTsStream(lambda: Source(ps), options(video_codec="h264")) as stream:
        copied = b"".join(stream)
    original, output = packet_oracle(ps), packet_oracle(copied)
    av = pytest.importorskip("av")
    with av.open(io.BytesIO(ps), format="mpeg") as incoming:
        indices = {stream.id: stream.index for stream in incoming.streams}
    assert original[indices[481]] == output[0]
    assert original[indices[448]] == output[1]


def test_async_recorded_bridge_exact_output_and_explicit_consumer_disconnect(sample):
    async def run():
        source = Source(sample)
        stream = NativeMpegTsStream(lambda: source, options())
        async with stream:
            chunks = [chunk async for chunk in stream.async_chunks()]
        assert len(b"".join(chunks)) == stream.receipt["output_bytes"]
        assert stream.receipt["status"] == "completed"
        second = NativeMpegTsStream(lambda: Source(sample), options())
        async with second:
            iterator = second.async_chunks()
            assert await anext(iterator)
            await iterator.aclose()
        assert second.receipt["worker_joined"] and second.receipt["source_closed"]
        assert second.receipt["owned_output_chunks"] == 0

    asyncio.run(run())


def test_client_composition_is_offline_lazy_and_uses_supplied_media_key(monkeypatch):
    calls = []
    owner = Source(block=True)

    def open_stream(serial, **kwargs):
        calls.append((serial, kwargs))
        return owner

    client = cast(EzvizClient, type("Client", (), {"open_stream": staticmethod(open_stream)})())
    source = AutoClipSource(mode="offline", credentials=credentials(), allow_cloud_fallback=False)
    stream = native_mpegts_stream_from_client(
        client, CAMERA, source=source, options=options(finite_source=False), channel=0
    )
    assert calls == []
    stream.start()
    assert owner.entered.wait(2)
    stream.close()
    assert calls == [(CAMERA, {"source": source, "channel": 0})]


@pytest.mark.parametrize(
    "changes", [{"mode": "auto"}, {"credentials": None}, {"allow_cloud_fallback": True}]
)
def test_client_policy_rejects_before_open(changes):
    client = cast(EzvizClient, None)
    with pytest.raises((ValueError, PyEzvizError)):
        source = replace(
            AutoClipSource(mode="offline", credentials=credentials(), allow_cloud_fallback=False),
            **changes,
        )
        native_mpegts_stream_from_client(
            client, CAMERA, source=source, options=options(finite_source=False), channel=0
        )
