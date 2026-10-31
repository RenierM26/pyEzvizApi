"""Fixed two-lens single-source session controls; no HA or actual cameras."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import io
import time

import pytest
from test_local_av_timeline import encode_three_track_ps
from test_native_stream import Source, options
from test_stream_sample import packet_oracle

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.native_stream import NativeTrackSelection


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    return encode_three_track_ps(tmp_path_factory.mktemp("native-session")).read_bytes()


def counted_source(calls, source):
    def factory():
        calls.append(1)
        return source
    return factory


def choices():
    return (options(selection=NativeTrackSelection(480, 448)), options())


def collect(output):
    with output:
        return b"".join(output)


def test_two_lenses_one_factory_and_one_demux_preserve_packet_clocks(sample, monkeypatch):
    av = pytest.importorskip("av")
    counts = {"factory": 0, "demux": 0}
    source = Source(sample)
    original_open = av.open

    def observed_open(*args, **kwargs):
        if kwargs.get("format") == "mpeg":
            counts["demux"] += 1
        return original_open(*args, **kwargs)

    def factory():
        counts["factory"] += 1
        return source

    monkeypatch.setattr(av, "open", observed_open)
    session = NativeMpegTsSession(factory, choices())
    assert counts == {"factory": 0, "demux": 0}
    with session, ThreadPoolExecutor(2) as executor:
        pending = [executor.submit(collect, output) for output in session.outputs]
        bodies = [future.result(timeout=10) for future in pending]
    assert counts == {"factory": 1, "demux": 1}
    original = packet_oracle(sample)
    for body, index in zip(bodies, (0, 2), strict=True):
        actual = packet_oracle(body)
        assert actual[1] == original[1]  # Same AAC, not split between readers.
        assert [row[1:] for row in actual[0]] == [row[1:] for row in original[index]]
    assert session.outputs[0].source_clock is session.outputs[1].source_clock
    assert session.receipt["all_outputs_completed"]
    assert session.receipt["worker_joined"] and source.closed
    assert all(row["owned_output_chunks"] == 0 and row["peak_owned_output_chunks"] <= 4
               for row in session.receipt["outputs"])


def test_unread_lens_fails_without_losing_healthy_lens(sample):
    source = Source(sample)
    session = NativeMpegTsSession(lambda: source, choices(), output_timeout=0.025)
    with session:
        data = collect(session.outputs[1])
    assert packet_oracle(data)[1] == packet_oracle(sample)[1]
    assert session.receipt["outputs"][0]["error_type"] == "TimeoutError"
    assert session.receipt["outputs"][1]["status"] == "completed"
    assert not session.receipt["all_outputs_completed"]
    assert session.receipt["worker_joined"] and source.closed


def test_closing_unused_lens_leaves_sibling_and_never_calls_factory_twice(sample):
    calls: list[int] = []
    source = Source(sample)
    session = NativeMpegTsSession(counted_source(calls, source), choices())
    session.outputs[0].close()
    assert calls == []
    with session:
        assert packet_oracle(collect(session.outputs[1]))[1] == packet_oracle(sample)[1]
    assert calls == [1] and source.closed
    assert session.receipt["outputs"][0]["status"] == "closed"
    assert session.receipt["outputs"][1]["status"] == "completed"
    assert session.receipt["status"] == "partial"
    assert not session.receipt["all_outputs_completed"]


def test_all_outputs_close_interrupts_blocked_source_without_clean_eof():
    source = Source(block=True)
    session = NativeMpegTsSession(
        lambda: source, tuple(replace(o, finite_source=False) for o in choices())
    )
    session.start()
    assert source.entered.wait(2)
    session.outputs[0].close()
    assert not source.closed
    session.outputs[1].close()
    assert source.closed and session.receipt["worker_joined"]
    assert not session.receipt["finite_source_end"]


@pytest.mark.parametrize("outputs", [(), list(choices()), (options(), options())])
def test_invalid_membership_does_not_acquire(outputs):
    with pytest.raises(ValueError):
        NativeMpegTsSession(lambda: pytest.fail("no source during validation"), outputs)


def test_incompatible_source_policy_does_not_share():
    changed = replace(options(), finite_source=False)
    with pytest.raises(ValueError, match="common codec"):
        NativeMpegTsSession(lambda: pytest.fail("not acquired"), (choices()[0], changed))


def test_source_failure_is_delivered_to_both_outputs():
    source = Source(error=ConnectionResetError("private source detail"))
    session = NativeMpegTsSession(lambda: source, choices())
    for output in session.outputs:
        with pytest.raises(PyEzvizError):
            collect(output)
    session.close()
    assert source.closed and session.receipt["worker_joined"]
    assert all(row["status"] == "failed" for row in session.receipt["outputs"])


def test_failed_join_retains_physical_owner_until_explicit_recovery():
    source = Source(block=True, cooperate=False)
    opts = tuple(replace(o, finite_source=False, close_timeout=0.05) for o in choices())
    session = NativeMpegTsSession(lambda: source, opts)
    session.start()
    assert source.entered.wait(2)
    session.outputs[0].close()
    with pytest.raises(PyEzvizError, match="shutdown timed out"):
        session.outputs[1].close()
    assert not session.receipt["worker_joined"]
    assert not session.outputs[0].receipt["physical_source"]["worker_joined"]
    source.release.set()
    session.close()
    assert session.receipt["worker_joined"]


def test_session_output_keeps_keyframe_flags(sample):
    av = pytest.importorskip("av")
    session = NativeMpegTsSession(lambda: Source(sample), (options(),))
    with session:
        data = collect(session.outputs[0])
    with av.open(io.BytesIO(data)) as incoming:
        assert any(packet.is_keyframe for packet in incoming.demux(video=0) if packet.size)


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), 2, "0.1"])
def test_invalid_output_grace_never_acquires(value):
    with pytest.raises(ValueError, match="grace"):
        NativeMpegTsSession(lambda: pytest.fail("not acquired"), choices(), output_timeout=value)


def test_both_unread_outputs_stop_the_single_acquisition(sample):
    calls: list[int] = []
    source = Source(sample)
    session = NativeMpegTsSession(counted_source(calls, source), choices(), output_timeout=0.025)
    session.start()
    deadline = time.monotonic() + 2
    while not session.receipt["worker_joined"] and time.monotonic() < deadline:
        time.sleep(0.01)
    session.close()
    assert calls == [1] and source.closed
    assert not session.receipt["all_outputs_completed"]
    assert all(row["error_type"] == "TimeoutError" for row in session.receipt["outputs"])


def test_async_cancel_pending_outputs_with_single_slot_executor():
    async def exercise():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(1))
        source = Source(block=True)
        session = NativeMpegTsSession(
            lambda: source, tuple(replace(o, finite_source=False) for o in choices())
        )

        async def consume(output):
            async with output:
                async for _chunk in output.async_chunks():
                    pass

        tasks = [asyncio.create_task(consume(output)) for output in session.outputs]
        while not source.entered.is_set():
            await asyncio.sleep(0.01)
        for task in tasks:
            task.cancel()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 2)
        await session.aclose()
        assert session.receipt["worker_joined"] and source.closed
        assert all(row["owned_output_chunks"] == 0 for row in session.receipt["outputs"])

    asyncio.run(exercise())



def test_session_declares_video_pes_extent_for_demux_startup(sample):
    session = NativeMpegTsSession(lambda: Source(sample), (options(),))
    with session:
        data = collect(session.outputs[0])
    video_pes_lengths = []
    video_start_code = b"\x00\x00\x01\xe0"
    for offset in range(0, len(data), 188):
        packet = data[offset:offset + 188]
        assert packet[0] == 0x47
        if not packet[1] & 0x40:
            continue
        start = 4 + (1 + packet[4] if packet[3] & 0x20 else 0)
        payload = packet[start:]
        if payload[:4] == video_start_code:
            video_pes_lengths.append(int.from_bytes(payload[4:6], "big"))
    # Small complete AUs must not require the next unbounded PES before a
    # demuxer can surface the initial keyframe ahead of following AAC.
    assert len(video_pes_lengths) > 1 and all(video_pes_lengths)



def test_completed_mux_with_unread_tail_is_not_completed_delivery():
    session = NativeMpegTsSession(lambda: pytest.fail("no acquisition"), (options(),))
    output = session.outputs[0]
    output.publish(b"unconsumed tail")
    output.source_finished(completed=True, failure=None, cleanup_errors=[])
    assert output.receipt["status"] == "draining"
    output.close()
    assert output.receipt["status"] == "partial"
    assert output.receipt["discarded_output_bytes"] == len(b"unconsumed tail")
    assert not session.receipt["all_outputs_completed"]
