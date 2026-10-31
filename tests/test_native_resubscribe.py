"""Explicit replacement handles never replay or restart the physical owner."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, get_ident

import pytest
from test_native_late_join import oracle
from test_native_session import choices, collect, sample as sample  # noqa: PLC0414
from test_native_stream import Source, repeated_ps_packets

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.native_session import NativeMpegTsSession


def interrupted(output):
    chunks = []
    try:
        with output:
            chunks.extend(output)
    except PyEzvizError:
        pass
    return b"".join(chunks)


def test_repeated_lens_suffixes_retire_muxes_on_worker_and_leave_primary_exact(sample, monkeypatch):  # noqa: PLR0915
    payload = b"".join(repeated_ps_packets(sample, 30))
    source, calls = Source(payload), []
    session = NativeMpegTsSession(lambda: (calls.append(1), source)[1], choices(), late_join=True)
    gates = {n: (Event(), Event()) for n in (40, 80, 120, 160, 200)}
    original, count = session._deliver_packet, [0]  # noqa: SLF001
    contexts, threads = [], []
    opened = session._open_output  # noqa: SLF001

    def observed(av, stack, binding, packet):
        original(av, stack, binding, packet)
        if binding.output is session.outputs[0] and packet.stream.id == 480:
            count[0] += 1
            if count[0] in gates:
                ready, release = gates[count[0]]
                ready.set()
                assert release.wait(5)

    def output_open(av, stack, output, tracks):
        contexts.append(stack)
        threads.append(get_ident())
        return opened(av, stack, output, tracks)

    monkeypatch.setattr(session, "_deliver_packet", observed)
    monkeypatch.setattr(session, "_open_output", output_open)
    retired = []
    with session, ThreadPoolExecutor(2) as executor:
        primary = executor.submit(collect, session.outputs[0])
        try:
            assert gates[40][0].wait(5)
            for begin, end in ((40, 80), (120, 160)):
                output = session.outputs[1]
                secondary = executor.submit(interrupted, output)
                gates[begin][1].set()
                assert gates[end][0].wait(5)
                output.close()
                body = secondary.result(timeout=5)
                assert body and output.receipt["owned_output_chunks"] == 0
                retired.append((output, body))
                gates[end][1].set()
                assert gates[end + 40][0].wait(5)
                fresh = session.replace_output(output)
                assert session.outputs[1] is fresh and fresh is not output
                assert fresh.receipt["subscription_generation"] == len(retired)
                assert fresh.receipt["status"] == "unused"
                assert fresh.source_clock is None and not source.closed
                with pytest.raises(PyEzvizError):
                    session.replace_output(output)  # Stale ownership cannot replace a newer lens.
                output.close()  # Nor can a stale close cancel it.
            final = executor.submit(collect, fresh)
            gates[200][1].set()
            primary_body, final_body = primary.result(timeout=10), final.result(timeout=10)
        finally:
            for _, release in gates.values():
                release.set()
    baseline = oracle(payload)
    assert oracle(primary_body)[256] == baseline[480]
    assert oracle(primary_body)[257] == baseline[448]
    starts = []
    for output, body in [*retired, (fresh, final_body)]:
        actual = oracle(body)
        start = baseline[481].index(actual[256][0])
        starts.append(start)
        assert start > 0
        assert actual[256] == baseline[481][start:start + len(actual[256])]
        assert output.source_clock.origin_90k == actual[256][0][1] * 90000
        audio_start = baseline[448].index(actual[257][0])
        assert actual[257] == baseline[448][audio_start:audio_start + len(actual[257])]
        assert actual[257][0][1] >= actual[256][0][1]
    assert starts == sorted(set(starts))
    assert oracle(final_body)[256] == baseline[481][starts[-1]:]
    assert len(contexts) == 4 and len({id(context) for context in contexts}) == 2
    assert len(set(threads)) == 1 and threads[0] != get_ident()
    receipt = session.receipt
    assert calls == [1] and source.closed and receipt["worker_joined"]
    assert receipt["retired_subscriptions"] == receipt["retired_partial_subscriptions"] == 2
    assert receipt["retired_output_totals"]["output_bytes"] == sum(
        out.receipt["output_bytes"] for out, _ in retired
    )
    assert receipt["output_totals"]["owned_output_chunks"] == 0
    assert receipt["output_queue_capacity_bytes"] == 2 * 4 * 65536
    assert receipt["status"] == "partial"  # Renewal never hides aborted historical delivery.


def test_replacement_requires_late_mode_closed_handle_and_live_sibling(sample):
    for late in (False, True):
        source = Source(block=True)
        session = NativeMpegTsSession(lambda source=source: source, choices(), late_join=late)
        with pytest.raises(PyEzvizError):
            session.replace_output(session.outputs[1])
        session.outputs[0].start()
        assert source.entered.wait(2)
        with pytest.raises(PyEzvizError):
            session.replace_output(session.outputs[1])
        session.close()
        with pytest.raises(PyEzvizError):
            session.replace_output(session.outputs[1])
    finite = NativeMpegTsSession(lambda: Source(sample), choices(), late_join=True)
    assert collect(finite.outputs[0])
    with pytest.raises(PyEzvizError):
        finite.replace_output(finite.outputs[0])
    finite.close()


def test_mux_retirement_timeout_retains_handle_without_restart():
    source = Source(block=True)
    session = NativeMpegTsSession(lambda: source, tuple(
        replace(o, close_timeout=0.02) for o in choices()
    ), late_join=True)
    session.outputs[0].start()
    assert source.entered.wait(2)
    previous = session.outputs[1]
    previous.close()
    with pytest.raises(PyEzvizError, match="retirement timed out"):
        session.replace_output(previous)
    assert session.outputs[1] is previous and not source.closed
    assert session.receipt["retired_subscriptions"] == 0
    session.close()
