"""Bursty source transport must not silently enlarge or overflow output queues."""

import json
from pathlib import Path
import runpy
import struct
import threading

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / "tools/reference_stream/credit.py"))


def offer(c, kind, **fields):
    c.offer(dict(kind=kind, **fields), lambda: False, lambda: True, timeout=0.5)


def test_video_credit_blocks_burst_until_exact_acknowledgement():
    c = M["Credit"]()
    offer(c, "pair")
    entered = threading.Event()
    completed = threading.Event()
    errors = []

    def second():
        entered.set()
        try:
            offer(c, "pair")
            completed.set()
        except BaseException as e:
            errors.append(e)

    t = threading.Thread(target=second)
    t.start()
    assert entered.wait(1)
    try:
        assert not completed.wait(0.03)
        c.progress(dict(kind="video_ack", pair_id="pair:1"))
        assert completed.wait(1)
        assert c.result()["peak"]["pair"] == 1
        assert c.result()["pending"]["pair"] == ["pair:2"]
    finally:
        c.close()
        t.join(timeout=1)
    assert not errors


def test_video_and_audio_credits_are_independent():
    c = M["Credit"]()
    offer(c, "pair")
    for i in range(4):
        offer(c, "vqe", id=i + 1)
    c.progress(dict(kind="audio_ack", id="vqe:1"))
    offer(c, "vqe", id=5)
    assert c.result()["pending"]["pair"] == ["pair:1"]
    assert c.result()["peak"] == dict(pair=1, vqe=4)


def test_end_does_not_wait_for_or_drain_pending_output():
    c = M["Credit"]()
    offer(c, "pair")
    offer(c, "vqe", id=1)
    before = c.result()["pending"]
    offer(c, "end")
    assert c.result()["pending"] == before


@pytest.mark.parametrize(
    "ack", [dict(kind="video_ack", pair_id="pair:2"), dict(kind="audio_ack", id="vqe:99")]
)
def test_unknown_ack_cannot_return_credit(ack):
    c = M["Credit"]()
    offer(c, "pair")
    offer(c, "vqe", id=1)
    with pytest.raises(ValueError, match="unknown or duplicate"):
        c.progress(ack)
    assert c.result()["acknowledged"] == dict(pair=0, vqe=0)


def test_replayed_ack_and_reused_native_audio_identity_fail():
    c = M["Credit"]()
    offer(c, "vqe", id=1)
    c.progress(dict(kind="audio_ack", id="vqe:1"))
    with pytest.raises(ValueError, match="unknown or duplicate"):
        c.progress(dict(kind="audio_ack", id="vqe:1"))
    with pytest.raises(ValueError, match="identity/count"):
        offer(c, "vqe", id=1)


def test_missing_ack_has_deadline_and_never_increases_window():
    c = M["Credit"]()
    offer(c, "pair")
    with pytest.raises(TimeoutError, match="credit deadline"):
        c.offer(dict(kind="pair"), lambda: False, lambda: True, timeout=0.01)
    assert c.result()["offered"]["pair"] == c.result()["peak"]["pair"] == 1


def test_cancel_or_failed_consumer_unblocks_credit_without_new_offer():
    c = M["Credit"]()
    offer(c, "pair")
    with pytest.raises(KeyboardInterrupt):
        c.offer(dict(kind="pair"), lambda: True, lambda: True)
    c.progress(dict(kind="consumer_result", error="output failed"))
    with pytest.raises(ValueError, match="output failed"):
        offer(c, "pair")
    assert c.result()["offered"]["pair"] == 1


def test_original_wire_bytes_survive_arbitrary_chunk_boundaries():
    parser = M["WireRecords"]()
    header = b'{ "kind":"encoded", "payload_bytes":256 }'
    raw = struct.pack("!I", len(header)) + header + bytes(range(256))
    rows = []
    for i in range(0, len(raw), 7):
        rows.extend(parser.feed(raw[i : i + 7]))
    parser.eof()
    assert rows == [(json.loads(header), raw)]
    assert parser.records == 1


def test_truncated_and_excessive_record_extents_fail():
    parser = M["WireRecords"]()
    with pytest.raises(ValueError, match="header extent"):
        list(parser.feed(struct.pack("!I", 8193)))
    parser = M["WireRecords"]()
    list(parser.feed(b"\x00"))
    with pytest.raises(ValueError, match="truncated"):
        parser.eof()
