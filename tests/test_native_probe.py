"""Finite discovery must publish before a held tail, without consuming its prefix."""
from concurrent.futures import ThreadPoolExecutor
import io
import threading

import pytest
from test_local_av_timeline import encode_three_track_ps
from test_native_stream import Source, options
from test_stream_sample import packet_oracle

from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.native_stream import NativeMpegTsStream, NativeTrackSelection


@pytest.fixture(scope="module", params=[(0, 2, 1), (2, 1, 0)])
def held_sample(request, tmp_path_factory):
    return encode_three_track_ps(tmp_path_factory.mktemp("held-probe"),
                                 discovery_order=request.param).read_bytes()


def collect_tail(output: NativeMpegTsStream) -> bytes:
    return b"".join(output)


@pytest.mark.parametrize("grouped", [False, True])
def test_finite_probe_does_not_wait_for_tail_or_frame_rate_estimate(held_sample, grouped):
    av = pytest.importorskip("av")
    start = b"\x00\x00\x01\xba"
    packs = [start + p for p in held_sample.split(start)[1:]]
    assert len(packs) > 20
    release = threading.Event()

    def bodies():
        yield from packs[:20]
        if not release.wait(5):
            raise TimeoutError("Test must release finite source tail")
        yield from packs[20:]

    source = Source(bodies=bodies())
    choices = (options(selection=NativeTrackSelection(480, 448)), options())
    owner = (NativeMpegTsSession(lambda: source, choices) if grouped
             else NativeMpegTsStream(lambda: source, choices[1]))
    outputs = owner.outputs if isinstance(owner, NativeMpegTsSession) else (owner,)
    with owner, ThreadPoolExecutor(len(outputs)) as executor:
        first = [executor.submit(output.read) for output in outputs]
        try:
            prefix = [future.result(timeout=2) for future in first]
            assert all(prefix)
            assert not release.is_set()
        finally:
            release.set()
        rest = [executor.submit(collect_tail, output) for output in outputs]
        delivered = [head + future.result(timeout=5)
                     for head, future in zip(prefix, rest, strict=True)]
    original = packet_oracle(held_sample)
    with av.open(io.BytesIO(held_sample), format="mpeg") as container:
        expected = {s.id: original[s.index] for s in container.streams}
    selected = choices if grouped else (choices[1],)
    for body, selection in zip(delivered, selected, strict=True):
        actual = packet_oracle(body)
        for index, track_id in enumerate((selection.selection.video_id, 448)):
            # TS may add video AUD headers; AAC identity and all original clocks remain exact.
            if index == 1:
                assert actual[index] == expected[track_id]
            else:
                assert [row[1:] for row in actual[index]] == [row[1:] for row in expected[track_id]]
    assert owner.receipt["worker_joined"] and source.closed
