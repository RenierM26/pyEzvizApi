"""Native retries/asynchronous callbacks must not change accepted identity binding."""

import hashlib
import os
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).parents[1]
M = runpy.run_path(str(ROOT / "tools/reference_stream/compressed.py"))


def attempt(identity, frame=0, result=0):
    meta = [0] * 58
    meta[10], meta[16], meta[19] = 224, 100 + frame, frame
    return [
        dict(
            event="encoded_video",
            id=identity,
            decoder_owner="0x1234",
            meta_words=meta,
            sha256=hashlib.sha256(b"payload").hexdigest(),
        ),
        dict(event="encoded_video_return", id=identity, result=result),
    ]


def decoded(call, frame=0):
    h = [0] * 49
    h[1], h[7], h[10] = 224, 100 + frame, frame
    # The callback call/thread context deliberately does not equal the owning native call.
    return dict(
        event="decoded_picture",
        call=call,
        payload_is_null=False,
        payload_bytes=1,
        sid=224,
        raw=100 + frame,
        frame=frame,
        header_words=h,
    )


def selection(row):
    primary = list(row["header_words"])
    secondary = list(primary)
    secondary[1] = 225
    return dict(event="render_callback", render_headers=[primary, secondary])


@pytest.fixture
def emitter(tmp_path, monkeypatch):
    rows = []
    monkeypatch.setitem(M["REFERENCE"]["PROJECT"], "blob", lambda *args: b"payload")
    return M["Emitter"](tmp_path, lambda row, payload=b"": rows.append((row, payload))), rows


def test_native_rejected_retry_is_diagnostic_not_a_second_decode(emitter):
    e, out = emitter
    rows = attempt(1, result=-2147483624) + attempt(2) + attempt(3, frame=1)
    rows += [
        decoded(99),
        decoded(100, frame=1),
        selection(decoded(99)),
        selection(decoded(100, frame=1)),
    ]
    e.pump(rows)
    e.pump(rows)
    encoded = [r for r, p in out if r["kind"] == "encoded"]
    assert [(r["token"], r["native_call"]) for r in encoded] == [(1, 2), (2, 3)]
    assert len(e.rejected) == 1 and e.rejected[0]["call"] == 1
    assert len([r for r, p in out if r["kind"] == "header"]) == 2


def test_async_header_waits_for_own_accepted_tuple_not_active_callback(emitter):
    e, out = emitter
    first = attempt(1)
    rows = [*first[:1], decoded(98), selection(decoded(98))]
    e.pump(rows)
    assert not out
    e.pump(rows + first[1:])
    assert [r["kind"] for r, p in out] == ["encoded", "header"]


def test_ambiguous_accepted_identity_fails_with_original_prefix_retained(emitter):
    e, out = emitter
    with pytest.raises(ValueError, match="ambiguous accepted"):
        e.pump(attempt(1) + attempt(2))
    assert len(out) == 1 and e.next_token == 2


def test_changed_decoder_owner_fails(emitter):
    e, out = emitter
    rows = attempt(1) + attempt(2, frame=1)
    rows[2]["decoder_owner"] = "0x5678"
    with pytest.raises(ValueError, match="instance changed"):
        e.pump(rows)
    assert len(out) == 1


def test_duplicate_native_return_rejected(emitter):
    e, out = emitter
    rows = attempt(1)
    with pytest.raises(ValueError, match="duplicate native decoder return"):
        e.pump([*rows, rows[1]])
    assert not out


@pytest.mark.skipif(os.name != "posix", reason="POSIX bounded source writer")
def test_cancelled_partial_write_mirrors_exact_accepted_wire_prefix(tmp_path, monkeypatch):
    r, w = os.pipe()
    stopped = [False]
    writer = M["Writer"](tmp_path, w, lambda: stopped[0])
    original = os.write

    def partial(fd, data):
        size = original(fd, data[:7])
        stopped[0] = True
        return size

    monkeypatch.setattr(os, "write", partial)
    try:
        with pytest.raises(KeyboardInterrupt, match="stop requested"):
            writer.send(dict(kind="example"), b"payload")
        writer.close()
        assert os.get_blocking(w)
        assert (tmp_path / "source.bin").read_bytes() == os.read(r, 7)
        assert (tmp_path / "source.bin").stat().st_size == 7
    finally:
        os.close(w)
        os.close(r)


def test_unselected_single_track_preroll_keeps_encoded_dependency_but_no_paired_header(emitter):
    e, out = emitter
    startup = decoded(10)
    startup["header_words"][33:36] = [133, 0, 1]
    rows = [*attempt(1), startup]
    e.pump(rows)
    assert [r["kind"] for r, p in out] == ["encoded"]
    assert len(e.accepted) == 1 and not e.headers
    later = decoded(20, frame=1)
    later["header_words"][33:36] = [133, 3, 2]
    rows += [*attempt(2, frame=1), later, selection(later)]
    e.pump(rows)
    assert [r["kind"] for r, p in out] == ["encoded", "encoded", "header"]
    assert out[-1][0]["native_header"][10] == 1
    assert e.headers == {20} and len(e.accepted) == 2


def test_selected_unsupported_header_is_not_silently_omitted(emitter):
    e, out = emitter
    bad = decoded(10)
    bad["header_words"][33:36] = [133, 0, 1]
    e.pump([*attempt(1), bad, selection(bad)])
    header = next(r["native_header"] for r, p in out if r["kind"] == "header")
    assert header[33:36] == [133, 0, 1]  # Downstream strict geometry audit must reject it.


def test_missing_paired_reference_headers_fail_closed(emitter):
    e, _out = emitter
    with pytest.raises(ValueError, match="missing explicit"):
        e.pump([*attempt(1), dict(event="render_callback")])
