"""One acquisition, staged original-IDR subscriptions, no cached media replay."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
import io
import subprocess
from threading import Event
from types import SimpleNamespace

import pytest
from test_native_session import choices, collect, sample as sample  # noqa: PLC0414
from test_native_stream import Source, repeated_ps_packets

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_access import _units
from pyezvizapi.native_session import NativeMpegTsSession, _Binding


@pytest.fixture(params=["h264", "hevc"])
def short_encoded(request):
    command = ["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
               "testsrc2=size=64x48:rate=10", "-f", "lavfi", "-i",
               "color=red:size=64x48:rate=10", "-f", "lavfi", "-i",
               "sine=sample_rate=16000", "-t", "0.6", "-map", "0:v", "-map", "1:v",
               "-map", "2:a", "-c:v", "libx264" if request.param == "h264" else "libx265",
               "-threads:v", "1"]
    if request.param == "hevc":
        command += ["-x265-params", "pools=none:frame-threads=1:log-level=error"]
    command += ["-c:a", "aac", "-f", "mpegts", "pipe:1"]
    return subprocess.run(command, capture_output=True, timeout=15, check=True).stdout


def oracle(data, codec="hevc"):
    av = pytest.importorskip("av")
    result: dict[int, list[tuple[bytes | tuple[bytes, ...], Fraction, Fraction]]] = {}
    with av.open(io.BytesIO(data)) as container:
        for packet in container.demux():
            if not packet.size:
                continue
            kind = packet.stream.type
            raw_payload = bytes(packet)
            payload: bytes | tuple[bytes, ...] = raw_payload
            if kind == "video":
                payload = tuple(bytes(n) for n in _units(raw_payload) if ((n[0] >> 1) & 63 != 35 if codec == "hevc" else n[0] & 31 != 9))
            result.setdefault(packet.stream.id, []).append((
                payload, Fraction(packet.pts) * packet.time_base,
                Fraction(packet.dts) * packet.time_base,
            ))
    return result


def gated_session(sample, monkeypatch, codec="hevc", **kwargs):
    payload = b"".join(repeated_ps_packets(sample, 20, codec=codec))
    source = Source(payload)
    counts = {"factory": 0, "primary_video": 0}
    ready, release = Event(), Event()

    def factory():
        counts["factory"] += 1
        return source

    session = NativeMpegTsSession(factory, tuple(replace(o, video_codec=codec) for o in choices()),
                                 late_join=True, **kwargs)
    original = session._deliver_packet  # noqa: SLF001

    def observed(av, stack, binding, packet):
        original(av, stack, binding, packet)
        if binding.output is session.outputs[0] and packet.stream.id == 480:
            counts["primary_video"] += 1
            if counts["primary_video"] == 40:
                ready.set()
                assert release.wait(3)

    monkeypatch.setattr(session, "_deliver_packet", observed)
    return session, source, counts, ready, release, payload


def test_late_idr_has_original_dependency_payloads_clock_and_complete_primary(sample, monkeypatch):
    session, source, counts, ready, release, payload = gated_session(sample, monkeypatch)
    with session, ThreadPoolExecutor(2) as executor:
        first = executor.submit(collect, session.outputs[0])
        assert ready.wait(3)
        assert session.outputs[1].receipt["status"] == "unused"
        assert session.outputs[1].receipt["output_bytes"] == 0
        session.outputs[1].start()
        second = executor.submit(collect, session.outputs[1])
        release.set()
        primary, late = first.result(timeout=5), second.result(timeout=5)
    original = oracle(payload)
    actual_primary, actual_late = oracle(primary), oracle(late)
    assert actual_primary[256] == original[480]
    assert actual_primary[257] == original[448]
    for actual, original_id in ((actual_late[256], 481), (actual_late[257], 448)):
        start = original[original_id].index(actual[0])
        assert start > 0
        assert actual == original[original_id][start:]
    assert session.outputs[1].join_pts == actual_late[256][0][1]
    assert session.outputs[1].source_clock.origin_90k == session.outputs[1].join_pts * 90000
    assert session.outputs[1].source_clock != session.outputs[0].source_clock
    assert counts["factory"] == 1 and source.closed
    assert session.receipt["all_outputs_completed"]
    assert session.receipt["worker_joined"] and session.receipt["cancel_joined"]


def test_only_requested_output_counts_and_unused_lens_never_buffers(sample):
    source = Source(sample)
    session = NativeMpegTsSession(lambda: source, choices(), late_join=True)
    with session:
        assert collect(session.outputs[0])
    assert session.receipt["status"] == "completed"
    assert session.receipt["all_requested_outputs_completed"]
    assert not session.receipt["all_outputs_completed"]
    assert session.outputs[1].receipt["status"] == "unused"
    assert session.outputs[1].receipt["peak_owned_output_bytes"] == 0
    assert session.receipt["worker_joined"] and source.closed


def test_cancel_pending_late_lens_does_not_cancel_primary(sample, monkeypatch):
    session, source, counts, ready, release, payload = gated_session(sample, monkeypatch)
    with session, ThreadPoolExecutor(1) as executor:
        first = executor.submit(collect, session.outputs[0])
        assert ready.wait(3)
        session.outputs[1].start()
        session.outputs[1].close()
        assert not source.closed
        release.set()
        primary = first.result(timeout=5)
    assert oracle(primary)[256] == oracle(payload)[480]
    assert session.outputs[1].receipt["status"] == "closed"
    assert counts["factory"] == 1 and session.receipt["worker_joined"]


def test_missing_late_idr_fails_only_that_subscriber(sample, monkeypatch):
    session, source, counts, ready, release, payload = gated_session(sample, monkeypatch)
    admit = session._admit_idr  # noqa: SLF001
    monkeypatch.setattr(session, "_admit_idr", lambda out, p: (
        False if out is session.outputs[1] else admit(out, p)
    ))
    with session, ThreadPoolExecutor(2) as executor:
        first = executor.submit(collect, session.outputs[0])
        assert ready.wait(3)
        session.outputs[1].start()
        second = executor.submit(collect, session.outputs[1])
        release.set()
        primary = first.result(timeout=5)
        with pytest.raises(PyEzvizError):
            second.result(timeout=5)
    assert oracle(primary)[256] == oracle(payload)[480]
    assert counts["factory"] == 1 and source.closed
    assert session.outputs[1].receipt["status"] == "failed"
    assert session.receipt["worker_joined"]


def test_cannot_attach_after_eof_or_restart_unused_lens(sample):
    calls = []

    def factory():
        calls.append(1)
        return Source(sample)

    session = NativeMpegTsSession(factory, choices(), late_join=True)
    assert collect(session.outputs[0])
    with pytest.raises(PyEzvizError):
        session.outputs[1].start()
    session.close()
    assert calls == [1]


def test_last_requested_output_stops_source_despite_unused_lenses():
    source = Source(block=True)
    session = NativeMpegTsSession(lambda: source, tuple(
        replace(o, finite_source=False) for o in choices()
    ), late_join=True)
    session.outputs[0].start()
    assert source.entered.wait(2)
    session.outputs[0].close()
    assert source.closed and session.receipt["worker_joined"]
    assert session.outputs[1].receipt["peak_owned_output_bytes"] == 0


@pytest.mark.parametrize("value", [1, None, "yes"])
def test_late_join_mode_is_explicit_and_lazy(value):
    with pytest.raises(ValueError):
        NativeMpegTsSession(lambda: pytest.fail("not acquired"), choices(), late_join=value)



def test_real_encoded_h264_and_hevc_late_suffix(short_encoded, monkeypatch):
    av = pytest.importorskip("av")
    with av.open(io.BytesIO(short_encoded)) as incoming:
        codec = incoming.streams.video[0].codec_context.name
    session, source, counts, ready, release, payload = gated_session(
        short_encoded, monkeypatch, codec=codec,
    )
    with session, ThreadPoolExecutor(2) as executor:
        first = executor.submit(collect, session.outputs[0])
        assert ready.wait(3)
        session.outputs[1].start()
        second = executor.submit(collect, session.outputs[1])
        release.set()
        primary, late = first.result(timeout=5), second.result(timeout=5)
    baseline = oracle(payload, codec)
    assert oracle(primary, codec)[256] == baseline[480]
    assert oracle(primary, codec)[257] == baseline[448]
    actual = oracle(late, codec)
    for track, source_id in ((256, 481), (257, 448)):
        start = baseline[source_id].index(actual[track][0])
        assert start > 0 and actual[track] == baseline[source_id][start:]
    assert counts["factory"] == 1 and source.closed and session.receipt["worker_joined"]


class Candidate:
    is_keyframe = True
    is_corrupt = False
    stream = SimpleNamespace(id=481)

    def __init__(self, pts, time_base):
        self.pts, self.time_base = pts, time_base

    def __bytes__(self):
        from test_native_access import chain  # noqa: PLC0415
        return chain("hevc")


@pytest.mark.parametrize("pts,base,accepted", [
    (-1, Fraction(1, 90000), True), ((1 << 33) - 1, Fraction(1, 90000), True),
    (1 << 33, Fraction(1, 90000), False), (1, Fraction(1, 7), False),
])
def test_join_clock_is_current_source_reference_without_rounding(pts, base, accepted):
    session = NativeMpegTsSession(lambda: pytest.fail("not acquired"), choices(), late_join=True)
    output = session.outputs[1]
    assert session._admit_idr(output, Candidate(pts, base)) == accepted  # noqa: SLF001
    if accepted:
        clock = output.source_clock
        assert clock is not None
        assert clock.origin_90k == pts * base * 90000
    else:
        assert output.receipt["error_type"] == "ValueError"
    session.close()


def test_corrupt_or_unflagged_idr_cannot_admit_even_with_parameter_sets():
    session = NativeMpegTsSession(lambda: pytest.fail("not acquired"), choices(), late_join=True)
    packet = Candidate(90000, Fraction(1, 90000))
    packet.is_corrupt = True
    assert not session._admit_idr(session.outputs[1], packet)  # noqa: SLF001
    packet.is_corrupt, packet.is_keyframe = False, False
    assert not session._admit_idr(session.outputs[1], packet)  # noqa: SLF001
    session.close()


def test_pending_idr_startup_timeout_is_local_to_subscriber(sample, monkeypatch):
    session, source, counts, ready, release, payload = gated_session(sample, monkeypatch)
    session.outputs[1].options = replace(session.outputs[1].options, startup_timeout=0.03)
    with session, ThreadPoolExecutor(2) as executor:
        first = executor.submit(collect, session.outputs[0])
        assert ready.wait(3)
        second = executor.submit(collect, session.outputs[1])
        with pytest.raises(TimeoutError):
            second.result(timeout=2)
        assert not source.closed
        release.set()
        primary = first.result(timeout=5)
    assert oracle(primary)[256] == oracle(payload)[480]
    assert counts["factory"] == 1 and session.receipt["worker_joined"]



def test_leading_picture_after_idr_fails_subscription_instead_of_silently_dropping():
    from unittest.mock import MagicMock  # noqa: PLC0415

    session = NativeMpegTsSession(lambda: pytest.fail("not acquired"), choices(), late_join=True)
    output = session.outputs[1]
    output._requested.set()  # noqa: SLF001
    output.join_pts = Fraction(2)
    packet = SimpleNamespace(stream=SimpleNamespace(id=481, index=0, type="video"),
                             pts=1, time_base=Fraction(1))
    binding = _Binding(output=output, muxer=MagicMock(), mapping={0: object()}, tracks=[])
    session._deliver_packet(None, None, binding, packet)  # noqa: SLF001
    assert output.receipt["error_type"] == "PyEzvizError"
    binding.muxer.mux.assert_not_called()
    session.close()



def test_late_mode_context_is_lazy_until_a_subscription_is_requested():
    calls = []
    source = Source(block=True)

    def factory():
        calls.append(1)
        return source

    session = NativeMpegTsSession(factory, choices(), late_join=True)
    with session:
        assert calls == [] and not source.entered.is_set()
        session.outputs[0].start()
        assert source.entered.wait(2) and calls == [1]
    assert session.receipt["worker_joined"] and source.closed
