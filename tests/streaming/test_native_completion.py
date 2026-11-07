"""Completion metadata is owner-derived, immutable and never inferred from EOF."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.native_stream import NativeMpegTsStream, NativeTrackSelection
from tests.streaming.test_native_session import choices, collect, sample as sample  # noqa: PLC0414 -- retained cross-test fixture re-export
from tests.streaming.test_native_stream import Source, options
from tests.streaming.test_stream_sample import packet_oracle


def test_single_output_counts_match_independent_packet_oracle(sample):
    calls = []
    def factory():
        calls.append(1)
        return Source(sample)

    owner = NativeMpegTsStream(factory, options())
    generation = owner.source_generation
    assert owner.completion is None and calls == []
    with owner:
        body = b"".join(owner)
    result = owner.completion
    assert result is not None and result is owner.completion
    actual = packet_oracle(body)
    assert (result.video_units, result.audio_units) == (len(actual[0]), len(actual[1]))
    assert result.source_generation == generation and result.subscription_generation == 0
    assert {t.track_id for t in result.tracks} == {481, 448}
    assert calls == [1]
    with pytest.raises(FrozenInstanceError):
        result.source_generation = "changed"
    with pytest.raises(FrozenInstanceError):
        result.tracks[0].access_units = 0
    with pytest.raises(AttributeError):
        owner.source_generation = "changed"


def test_receipt_mutation_cannot_change_completion_track_identity(sample):
    owner = NativeMpegTsStream(lambda: Source(sample), options())
    with owner:
        b"".join(owner)
    receipt = owner.receipt
    receipt["selected_tracks"][0]["id"] = 123
    receipt["accepted_access_units"][0]["access_units"] = 0
    completion = owner.completion
    assert completion is not None
    assert completion.tracks[0].track_id != 123
    assert all(t.access_units > 0 for t in completion.tracks)


def test_physical_identity_shared_but_new_sources_never_reuse_it(sample):
    source = Source(sample)
    session = NativeMpegTsSession(lambda: source, choices())
    other = NativeMpegTsSession(lambda: Source(sample), choices())
    assert session.source_generation != other.source_generation
    assert all(o.source_generation == session.source_generation for o in session.outputs)
    assert session.completion is None and all(o.completion is None for o in session.outputs)
    with session, ThreadPoolExecutor(2) as executor:
        bodies = list(executor.map(collect, session.outputs))
    assert session.completion is None  # Physical aggregate is not a consumed selection.
    for output, body in zip(session.outputs, bodies, strict=True):
        complete = output.completion
        oracle = packet_oracle(body)
        assert complete is not None and complete.source_generation == session.source_generation
        assert (complete.video_units, complete.audio_units) == (len(oracle[0]), len(oracle[1]))
        assert {t.track_id for t in complete.tracks} == {
            output.options.selection.video_id,
            output.options.selection.audio_id,
        }


def test_cancelled_sibling_never_inherits_healthy_completion(sample):
    owner = NativeMpegTsSession(lambda: Source(sample), choices())
    abandoned, healthy = owner.outputs
    abandoned.close()
    with owner:
        collect(healthy)
    assert abandoned.completion is None and healthy.completion is not None
    assert owner.receipt["status"] == "partial"


def test_stalled_sibling_has_no_completion_metadata(sample):
    owner = NativeMpegTsSession(lambda: Source(sample), choices(), output_timeout=0.025)
    with owner:
        collect(owner.outputs[1])
    assert owner.outputs[0].completion is None and owner.outputs[1].completion is not None


@pytest.mark.parametrize("close_error", [False, True])
def test_source_or_cleanup_error_never_publishes_completion(sample, close_error):
    source = Source(
        sample, error=None if close_error else RuntimeError("source"), close_error=close_error
    )
    owner = NativeMpegTsStream(lambda: source, options())
    with pytest.raises(PyEzvizError), owner:
        b"".join(owner)
    assert owner.completion is None


def test_draining_or_abandoned_tail_is_not_complete(sample):
    baseline = NativeMpegTsStream(lambda: Source(sample), options())
    with baseline:
        chunks = list(baseline)
    owner = NativeMpegTsStream(lambda: Source(sample), options())
    with owner:
        for _ in chunks[:-1]:
            assert owner.read()
        assert owner._finished.wait(5)  # noqa: SLF001
        assert owner.receipt["owned_output_bytes"] > 0 and owner.completion is None
    assert owner.receipt["discarded_output_bytes"] > 0 and owner.completion is None


def test_video_only_has_no_implied_audio_track(sample):
    owner = NativeMpegTsStream(lambda: Source(sample), options(selection=NativeTrackSelection(481)))
    with owner:
        body = b"".join(owner)
    complete = owner.completion
    assert complete is not None and complete.audio_units == 0
    assert complete.video_units == len(packet_oracle(body)[0])
    assert len(complete.tracks) == 1


def test_failed_mux_does_not_count_rejected_access_unit(sample, monkeypatch):
    av = pytest.importorskip("av")
    original = av.open

    class Failed:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def add_stream_from_template(self, stream):
            return stream

        def mux(self, _):
            raise RuntimeError("rejected mux")

    def opened(*args, **kwargs):
        return Failed() if kwargs.get("mode") == "w" else original(*args, **kwargs)

    monkeypatch.setattr(av, "open", opened)
    owner = NativeMpegTsStream(lambda: Source(sample), options())
    with pytest.raises(PyEzvizError), owner:
        b"".join(owner)
    assert owner.completion is None
    assert all(t["access_units"] == 0 for t in owner.receipt["accepted_access_units"])
