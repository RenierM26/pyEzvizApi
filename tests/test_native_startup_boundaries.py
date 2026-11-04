"""Generated source boundaries, without live acquisition or IDR substitutions."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
import hashlib
import io
import os
import subprocess
from threading import Event

import pytest
from test_native_late_join import oracle
from test_native_resubscribe import interrupted
from test_native_session import choices, collect
from test_native_stream import Source

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_access import self_contained_idr
from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.rtp_timing import _mpeg_crc32, _pack_header, _pes


@pytest.fixture(scope="module")
def encoded_boundaries():
    """Real encoder controls: closed IDR, open CRA, long GOP and new geometry."""
    result = {}
    env = {k: v for k, v in os.environ.items() if k not in {"LD_PRELOAD", "LD_LIBRARY_PATH"}}
    for codec in ("h264", "hevc"):
        for mode, size in (("closed", "64x48"), ("open", "64x48"), ("radl", "64x48"),
                           ("long", "64x48"), ("changed", "96x64")):
            if codec == "h264" and mode in {"open", "radl"}:
                continue
            command = ["ffmpeg", "-v", "error", "-f", "lavfi", "-i",
                       f"testsrc2=size={size}:rate=10", "-f", "lavfi", "-i",
                       f"color=red:size={size}:rate=10", "-f", "lavfi", "-i",
                       "sine=sample_rate=16000", "-t", "2", "-map", "0:v", "-map", "1:v",
                       "-map", "2:a", "-c:v", "libx264" if codec == "h264" else "libx265",
                       "-threads:v", "1"]
            keyint = 1000 if mode == "long" else 9 if mode in {"open", "radl"} else 10
            params = f"keyint={keyint}:min-keyint={keyint}:scenecut=0:repeat-headers=1:bframes=2:b-adapt=0:open-gop={int(mode == 'open')}"
            if codec == "hevc":
                params += ":pools=none:frame-threads=1:log-level=error"
                if mode == "radl":
                    params += ":radl=2"
            command += ["-x264-params" if codec == "h264" else "-x265-params", params,
                        "-c:a", "aac", "-f", "mpegts", "pipe:1"]
            result[codec, mode] = subprocess.run(
                command, capture_output=True, timeout=20, check=True, env=env,
            ).stdout
    return result


def source_ps(segments, codec, offset=0):
    """Frame original generated AUs with declared PES IDs and exact source times."""
    av = pytest.importorskip("av")
    kind = 0x24 if codec == "hevc" else 0x1B
    entries = bytes((kind, 0xE0, 0, 0, kind, 0xE1, 0, 0, 0x0F, 0xC0, 0, 0))
    body = b"\xe0\xff\x00\x00" + len(entries).to_bytes(2, "big") + entries
    mapping = b"\x00\x00\x01\xbc" + (len(body) + 4).to_bytes(2, "big") + body
    mapping += _mpeg_crc32(mapping)
    result = bytearray()
    for segment, data in enumerate(segments):
        with av.open(io.BytesIO(data)) as incoming:
            for packet in incoming.demux():
                if not packet.size:
                    continue
                # Explicit forward gap also separates each encoder's AAC priming/tail.
                pts = Fraction(packet.pts) * packet.time_base * 90000 + offset + segment * 270000
                dts = Fraction(packet.dts) * packet.time_base * 90000 + offset + segment * 270000
                assert pts.denominator == dts.denominator == 1
                sid = (0xE0, 0xE1, 0xC0)[packet.stream.index]
                payload = bytes(packet)
                row = _pes(int(pts), sid, payload)
                if pts != dts:
                    decode = _pes(int(dts), sid, b"")
                    row = (row[:4] + (len(payload) + 13).to_bytes(2, "big") + b"\x80\xc0\x0a"
                           + bytes([row[9] | 0x10]) + row[10:14]
                           + bytes([decode[9] & ~0x20]) + decode[10:14] + payload)
                result.extend(_pack_header(int(dts) % (1 << 33)) + mapping + row)
    return bytes(result)


def decoded_video(data, video_id):
    av = pytest.importorskip("av")
    with av.open(io.BytesIO(data)) as incoming:
        stream = next(s for s in incoming.streams if s.id == video_id)
        return [(Fraction(frame.pts) * frame.time_base, frame.width, frame.height,
                 pixel_hash(frame))
                for frame in incoming.decode(stream)]


def pixel_hash(frame):
    """Hash visible YUV bytes, excluding decoder-specific allocation padding."""
    digest = hashlib.sha256()
    assert frame.format.name == "yuv420p"
    for plane in frame.planes:
        raw = bytes(plane)
        for row in range(plane.height):
            digest.update(raw[row * plane.line_size:row * plane.line_size + plane.width])
    return digest.hexdigest()


def controlled_session(payload, codec, monkeypatch, gates=(4,)):
    source, calls = Source(payload), []
    def factory():
        calls.append(1)
        return source

    session = NativeMpegTsSession(factory, tuple(
        replace(o, video_codec=codec) for o in choices()
    ), late_join=True)
    events = {n: (Event(), Event()) for n in gates}
    original, count = session._deliver_packet, 0  # noqa: SLF001

    def deliver(av, stack, binding, packet):
        nonlocal count
        original(av, stack, binding, packet)
        if binding.output is session.outputs[0] and packet.stream.id == 480:
            count += 1
            if count in events:
                ready, release = events[count]
                ready.set()
                assert release.wait(5)

    monkeypatch.setattr(session, "_deliver_packet", deliver)
    return session, source, calls, events


@pytest.mark.parametrize("codec,mode", [("hevc", "open"), ("hevc", "long"), ("h264", "long")])
def test_real_cra_or_no_later_idr_cannot_claim_late_completion(encoded_boundaries, monkeypatch, codec, mode):
    payload = source_ps([encoded_boundaries[codec, mode]], codec)
    baseline = oracle(payload, codec)
    video = baseline[481]
    assert self_contained_idr(b"".join(b"\0\0\1" + n for n in video[0][0]), codec)
    assert not any(self_contained_idr(b"".join(b"\0\0\1" + n for n in p[0]), codec) for p in video[1:])
    if mode == "open":
        kinds = [set((n[0] >> 1) & 63 for n in p[0]) for p in video]
        assert any(21 in row for row in kinds)  # Actual CRA, not a mocked keyframe flag.
        assert any(row & {8, 9} for row in kinds)  # Actual RASL leading pictures.
    session, source, calls, events = controlled_session(payload, codec, monkeypatch)
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert events[4][0].wait(5)
            secondary = executor.submit(collect, session.outputs[1].start())
            events[4][1].set()
            body = primary.result(timeout=5)
            with pytest.raises(PyEzvizError):
                secondary.result(timeout=5)
        finally:
            events[4][1].set()
    assert oracle(body, codec)[256] == baseline[480]
    assert oracle(body, codec)[257] == baseline[448]
    assert decoded_video(body, 256) == decoded_video(payload, 480)
    assert session.outputs[0].completion is not None
    assert session.outputs[1].completion is None
    assert session.outputs[1].join_pts is None
    assert session.outputs[1].receipt["output_bytes"] == 0
    assert calls == [1] and source.closed and session.receipt["worker_joined"]


@pytest.mark.parametrize("codec", ["h264", "hevc"])
@pytest.mark.parametrize("offset", [0, (1 << 33) - 200000])
def test_fresh_idr_after_parameter_change_and_wrap_preserves_original_suffix(encoded_boundaries, monkeypatch, codec, offset):
    payload = source_ps([encoded_boundaries[codec, "closed"], encoded_boundaries[codec, "changed"]], codec, offset)
    baseline = oracle(payload, codec)
    session, source, calls, events = controlled_session(payload, codec, monkeypatch, gates=(24,))
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert events[24][0].wait(5)
            secondary = executor.submit(collect, session.outputs[1].start())
            events[24][1].set()
            first, second = primary.result(timeout=5), secondary.result(timeout=5)
        finally:
            events[24][1].set()
    assert oracle(first, codec)[256] == baseline[480]
    assert oracle(first, codec)[257] == baseline[448]
    late = oracle(second, codec)
    start = baseline[481].index(late[256][0])
    assert start == 30
    assert late[256] == baseline[481][start:]
    audio_start = baseline[448].index(late[257][0])
    assert late[257] == baseline[448][audio_start:]
    assert late[257][0][1] >= session.outputs[1].join_pts == late[256][0][1]
    original_pixels = decoded_video(payload, 481)
    assert {(row[1], row[2]) for row in original_pixels} == {(64, 48), (96, 64)}
    assert decoded_video(first, 256) == decoded_video(payload, 480)
    assert decoded_video(second, 256) == original_pixels[start:]
    assert session.outputs[1].source_clock.origin_90k == late[256][0][1] * 90000
    assert session.outputs[0].completion is not None and session.outputs[1].completion is not None
    assert calls == [1] and source.closed and session.receipt["worker_joined"]


def test_real_idr_radl_leading_pictures_fail_only_the_late_subscription(encoded_boundaries, monkeypatch):
    payload = source_ps([encoded_boundaries["hevc", "radl"]], "hevc")
    baseline = oracle(payload)
    kinds = [set((n[0] >> 1) & 63 for n in p[0]) for p in baseline[481]]
    assert any(19 in row for row in kinds) and any(row & {6, 7} for row in kinds)
    session, source, calls, events = controlled_session(payload, "hevc", monkeypatch)
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert events[4][0].wait(5)
            secondary = executor.submit(collect, session.outputs[1].start())
            events[4][1].set()
            body = primary.result(timeout=5)
            with pytest.raises(PyEzvizError):
                secondary.result(timeout=5)
        finally:
            events[4][1].set()
    assert session.outputs[1].join_pts is not None  # Admitted IDR, then refused leading AU.
    assert "leading picture" in str(session.outputs[1]._failure)  # noqa: SLF001
    assert session.outputs[1].completion is None
    assert oracle(body)[256] == baseline[480] and oracle(body)[257] == baseline[448]
    assert decoded_video(body, 256) == decoded_video(payload, 480)
    assert session.outputs[0].completion is not None
    assert calls == [1] and source.closed and session.receipt["worker_joined"]


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_real_long_gop_timeout_then_explicit_fresh_parameter_generation(encoded_boundaries, monkeypatch, codec):
    payload = source_ps([encoded_boundaries[codec, "long"], encoded_boundaries[codec, "changed"]], codec)
    baseline = oracle(payload, codec)
    session, source, calls, events = controlled_session(payload, codec, monkeypatch, gates=(4, 14, 24))
    previous = session.outputs[1]
    previous.options = replace(previous.options, startup_timeout=0.2)
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert events[4][0].wait(5)
            secondary = executor.submit(collect, previous.start())
            events[4][1].set()
            assert events[14][0].wait(5)
            with pytest.raises(TimeoutError):
                secondary.result(timeout=3)
            assert previous.receipt["output_bytes"] == 0 and previous.completion is None
            assert not source.closed and calls == [1]
            with pytest.raises(PyEzvizError):
                previous.start()  # A failed handle cannot automatically retry.
            events[14][1].set()
            assert events[24][0].wait(5)
            fresh = session.replace_output(previous)
            assert fresh.source_clock is None and fresh.generation == 1
            replacement = executor.submit(collect, fresh.start())
            events[24][1].set()
            first, second = primary.result(timeout=5), replacement.result(timeout=5)
        finally:
            for _, release in events.values():
                release.set()
    assert oracle(first, codec)[256] == baseline[480]
    assert oracle(first, codec)[257] == baseline[448]
    late = oracle(second, codec)
    start = baseline[481].index(late[256][0])
    assert start == 30 and late[256] == baseline[481][start:]
    audio_start = baseline[448].index(late[257][0])
    assert late[257] == baseline[448][audio_start:]
    assert decoded_video(second, 256) == decoded_video(payload, 481)[start:]
    assert fresh.completion is not None and previous.completion is None
    assert session.receipt["retired_failed_subscriptions"] == 1
    assert session.receipt["output_totals"]["owned_output_chunks"] == 0
    assert calls == [1] and source.closed and session.receipt["worker_joined"]


@pytest.mark.parametrize("codec", ["h264", "hevc"])
def test_active_lens_replacement_does_not_reuse_old_parameters_across_wrap(encoded_boundaries, monkeypatch, codec):
    payload = source_ps([encoded_boundaries[codec, "closed"], encoded_boundaries[codec, "changed"]],
                        codec, (1 << 33) - 400000)
    baseline = oracle(payload, codec)
    session, source, calls, events = controlled_session(payload, codec, monkeypatch, gates=(4, 19, 24))
    previous = session.outputs[1]
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert events[4][0].wait(5)
            secondary = executor.submit(interrupted, previous.start())
            events[4][1].set()
            assert events[19][0].wait(5)
            previous.close()
            old_body = secondary.result(timeout=5)
            assert old_body and previous.completion is None
            events[19][1].set()
            assert events[24][0].wait(5)
            fresh = session.replace_output(previous)
            assert fresh.source_clock is None and fresh.generation == 1
            replacement = executor.submit(collect, fresh.start())
            events[24][1].set()
            first, second = primary.result(timeout=5), replacement.result(timeout=5)
        finally:
            for _, release in events.values():
                release.set()
    assert oracle(first, codec)[256] == baseline[480]
    assert oracle(first, codec)[257] == baseline[448]
    old = oracle(old_body, codec)[256]
    assert old == baseline[481][10:10 + len(old)]
    assert previous.source_clock.origin_90k == old[0][1] * 90000 < 0
    late = oracle(second, codec)
    assert late[256] == baseline[481][30:]
    audio_start = baseline[448].index(late[257][0])
    assert late[257] == baseline[448][audio_start:]
    fresh_clock = fresh.source_clock
    assert fresh_clock is not None
    assert fresh_clock.origin_90k == late[256][0][1] * 90000 > 0
    pixels = decoded_video(second, 256)
    assert pixels == decoded_video(payload, 481)[30:]
    assert {(row[1], row[2]) for row in pixels} == {(96, 64)}
    assert fresh.completion is not None
    assert fresh.completion.subscription_generation == 1
    assert session.receipt["retired_partial_subscriptions"] == 1
    assert session.receipt["output_totals"]["owned_output_chunks"] == 0
    assert calls == [1] and source.closed and session.receipt["worker_joined"]
