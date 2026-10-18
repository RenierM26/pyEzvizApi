"""Compressed preview has explicit identities, bounded ownership and no invented native clock."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import select
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import ClassVar

import pytest

ROOT = Path(__file__).parents[1]
M = runpy.run_path(str(ROOT / "tools/app_compressed_reference_av.py"))
SOURCE = runpy.run_path(str(Path(__file__).with_name("test_app_native_scheduled_video.py")))
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX output transport")


class Packet:
    def __init__(self, data):
        self.data = data


class Context:
    options: dict[str, str] | None = None
    has_b_frames = False

    def open(self):
        self.options = {}

    def decode(self, packet):
        return [
            SimpleNamespace(
                pts=packet.pts,
                width=8,
                height=6,
                pixels=packet.data,
                format=SimpleNamespace(name="yuv420p"),
                is_corrupt=False,
            )
        ]


class Video:
    driver = "test"
    calls: ClassVar[list] = []

    def __init__(self, *args, **kwargs):
        pass

    def present(self, identity, pixels, timeout):
        self.calls.append(identity)
        return dict(pixel_sha256=hashlib.sha256(pixels).hexdigest())

    def finish(self, timeout):
        pass

    def abort(self):
        pass


class Audio:
    def __init__(self, **kwargs):
        pass

    def alive(self):
        pass

    def write(self, data):
        return len(data)

    def finish(self, timeout):
        pass

    def abort(self):
        pass


@pytest.fixture
def preview(monkeypatch):
    g = M["Decoder"].add.__globals__
    source = g["LIVE"]["VIDEO"]["NATIVE"]["AUDIT"]["SOURCE"]
    monkeypatch.setitem(
        source,
        "load_av",
        lambda: SimpleNamespace(
            Packet=Packet, CodecContext=SimpleNamespace(create=lambda *args: Context())
        ),
    )
    monkeypatch.setitem(g["NATIVE"]["SCHEDULED"]["PREVIEW"], "pack", lambda frame: frame.pixels)
    monkeypatch.setitem(M["Preview"].video_write.__globals__["VIDEO"], "Output", Video)
    monkeypatch.setitem(M["Preview"].audio_write.__globals__["LIVE"]["PCM"], "Ffplay", Audio)
    monkeypatch.setitem(
        M["Preview"].audio_write.__globals__, "audio_options", lambda: ("-channels", "1")
    )
    Video.calls = []
    p = M["Preview"](1)
    yield p
    p.source_eof_ns = time.monotonic_ns()
    p.close(False)


class Feed:
    def __init__(self, preview):
        self.preview = preview
        self.seq = self.token = 0
        self.send("begin", session="a" * 32, elf_sha256=M["HASHES"])

    def send(self, kind, payload=b"", **fields):
        self.seq += 1
        self.preview.ingest(
            dict(kind=kind, seq=self.seq, payload_bytes=len(payload), **fields), payload
        )

    def pair(self, index, checkpoints=False, select_pair=True):
        rows, inputs, renders = SOURCE["snapshots"](index + 1)
        selected = rows[-2:]
        for at, row in enumerate(selected):
            raw = renders[-144 + at * 72 :][:72]
            pixels = raw[:48] + raw[60:] + raw[48:60]
            h = row["input_header"]
            meta = [0] * 58
            meta[10], meta[16], meta[19] = h[1], h[7], h[10]
            meta[12:14] = [8, 6]
            self.token += 1
            self.send(
                "encoded",
                pixels,
                token=self.token,
                native_call=self.token,
                decoder_owner="0x1234",
                meta_words=meta,
                sha256=hashlib.sha256(pixels).hexdigest(),
                decoder_result=0,
            )
            self.send("header", native_header=h)
            if checkpoints:
                checkpoint = dict(row, input_offset=0, render_offset=0)
                src = inputs[-192 + at * 96 :][:96]
                self.send("checkpoint", src + raw, manifest=checkpoint)
        if select_pair:
            self.select(selected)
        return selected

    def select(self, rows):
        self.send(
            "pair",
            render_headers=[
                r["render_header"] for r in sorted(rows, key=lambda r: r["input_header"][1])
            ],
            source_device_ns=self.seq,
        )

    def audio(self, identity=1, **changes):
        before = bytes(range(256)) * 8
        after = b"\x09" * 2048
        fields = dict(
            id=identity,
            source_input_ns=identity,
            source_output_ns=identity + 1,
            input_sha256=hashlib.sha256(before).hexdigest(),
            output_sha256=hashlib.sha256(after).hexdigest(),
            sample_rate=16000,
            channels=1,
            samples=1024,
            status=0,
        )
        fields.update(changes)
        self.send("vqe", before + after, **fields)


def until(p, condition):
    end = time.monotonic() + 2
    while not condition():
        p.pump()
        assert time.monotonic() < end
        time.sleep(0.001)


def test_multiple_selected_pairs_and_native_audio_before_eof_with_constant_pixel_storage(preview):
    f = Feed(preview)
    for index in range(40):
        f.pair(index, checkpoints=index == 0)
        f.audio(index + 1)
        until(
            preview,
            lambda index=index: (
                preview.video_completed == index + 1 and preview.audio.written == index + 1
            ),
        )
        assert preview.decoder.bytes == 0 and not preview.decoder.frames
    assert preview.source_eof_ns is None
    assert preview.decoder.peak_frames == 2 and preview.decoder.peak_bytes == 144
    assert preview.result()["audio"]["output_content_pts"] is None


def test_outputs_wait_for_both_native_parity_checkpoints(preview):
    f = Feed(preview)
    rows = f.pair(0, select_pair=False)
    f.select(rows)
    f.audio()
    preview.pump()
    assert preview.video_job is preview.audio_job is None
    assert preview.audio.offered == 1 and not Video.calls


def test_changed_checkpoint_fails_without_output(preview):
    f = Feed(preview)
    f.pair(0, select_pair=False)
    rows, _inputs, renders = SOURCE["snapshots"](1)
    row = dict(rows[0], input_offset=0, render_offset=0)
    with pytest.raises(ValueError, match="digest mismatch"):
        f.send("checkpoint", bytes(96) + renders[:72], manifest=row)
    assert not Video.calls and preview.audio_job is None


def test_reference_advancement_retires_only_unselected_prefix_and_rejects_repeat(preview):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    until(preview, lambda: preview.video_completed == 1)
    f.pair(1, select_pair=False)
    rows = f.pair(2)
    until(preview, lambda: preview.video_completed == 2)
    assert preview.decoder.retired_unselected == 2 and not preview.decoder.frames
    with pytest.raises(ValueError, match="repeated or backwards"):
        f.select(rows)


def test_eof_retains_unstarted_selection_and_native_processed_audio(preview):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    f.audio()
    preview.source_eof_ns = time.monotonic_ns()
    preview.pump()
    assert preview.video_completed == preview.audio.written == 0
    assert len(preview.waiting) == len(preview.audio.ring) == 1
    assert preview.video_job is preview.audio_job is None


def test_blocked_video_does_not_stop_native_audio(preview, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def blocked(*args):
        entered.set()
        assert release.wait(timeout=2)
        return dict(pixel_sha256="test")

    monkeypatch.setattr(preview, "video_write", blocked)
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    preview.pump()
    assert entered.wait(timeout=1)
    try:
        f.audio()
        until(preview, lambda: preview.audio.written == 1)
        assert preview.video_completed == 0
    finally:
        release.set()
    until(preview, lambda: preview.video_completed == 1)


@pytest.mark.parametrize(
    "change",
    [
        dict(channels=2),
        dict(samples=512),
        dict(status=True),
        dict(source_input_ns=3, source_output_ns=2),
        dict(output_sha256="0" * 64),
        dict(sample_rate=48000),
    ],
)
def test_wrong_native_dsp_format_or_hash_is_never_forwarded(preview, change):
    f = Feed(preview)
    with pytest.raises(ValueError, match="native VQE"):
        f.audio(**change)
    assert preview.audio.offered == 0


@pytest.mark.parametrize(
    "change",
    [dict(token=2), dict(decoder_result=1), dict(sha256="0" * 64), dict(meta_words=[0] * 57)],
)
def test_bad_encoded_record_rejected_before_decode(preview, change):
    f = Feed(preview)
    meta = [0] * 58
    meta[10] = 224
    meta[12:14] = [8, 6]
    row = dict(
        token=1,
        native_call=1,
        decoder_owner="0x1234",
        decoder_result=0,
        sha256=hashlib.sha256(b"x").hexdigest(),
        meta_words=meta,
    )
    row.update(change)
    with pytest.raises(ValueError):
        f.send("encoded", b"x", **row)
    assert preview.decoder.count == 0


def test_explicit_decoded_pixel_budget_and_selected_pair_backlog(preview, monkeypatch):
    f = Feed(preview)
    monkeypatch.setitem(M["Decoder"].add.__globals__, "MAX_PIXELS", 1)
    with pytest.raises(ValueError, match="pixel budget"):
        f.pair(0)
    assert not preview.decoder.frames


def test_sequence_and_build_cannot_be_reused_or_guessed(preview):
    with pytest.raises(ValueError, match="sequence"):
        preview.ingest(
            dict(kind="begin", seq=2, payload_bytes=0, session="a" * 32, elf_sha256=M["HASHES"]),
            b"",
        )
    with pytest.raises(ValueError, match="session/build"):
        preview.ingest(
            dict(kind="begin", seq=1, payload_bytes=0, session="a" * 32, elf_sha256={}), b""
        )


@pytest.mark.parametrize(
    "flag,expected", [("-ch_layout", ("-ch_layout", "mono")), ("-channels", ("-channels", "1"))]
)
def test_ffplay_mono_capability_choice(monkeypatch, flag, expected):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="", stderr=f"  {flag} <value>\n")
    )
    assert M["audio_options"]() == expected


def test_unknown_ffplay_flags_have_no_guessed_fallback(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="", stderr="unknown")
    )
    with pytest.raises(ValueError, match="explicit mono"):
        M["audio_options"]()


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_cli_records_cancellation_while_waiting_for_source(tmp_path, signum):
    receipt = tmp_path / "receipt.json"
    p = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "tools/app_compressed_reference_av.py"),
            "--play",
            "--audio",
            "observed-native-vqe-output",
            "--receipt",
            str(receipt),
            "--progress",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert p.stdin is not None and p.stdout is not None and p.stderr is not None
    try:
        assert select.select([p.stdout], [], [], 5)[0]
        assert json.loads(p.stdout.readline())["kind"] == "consumer_ready"
        p.send_signal(signum)
        assert p.wait(timeout=5) == 130, p.stderr.read().decode()
        result = json.loads(receipt.read_text())
        assert result["status"] == "cancelled" and result["video_frames"] == 0
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        for handle in (p.stdin, p.stdout, p.stderr):
            if handle is not None:
                handle.close()


def test_native_frame_counter_jumps_do_not_reorder_accepted_picture_identity(preview, monkeypatch):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    until(preview, lambda: preview.video_completed == 1)
    original = f.send

    def rewrite(kind, payload=b"", **fields):
        if kind == "encoded":
            fields["meta_words"][19] = 2**32 - 400
        elif kind == "header":
            fields["native_header"][10] = 2**32 - 400
        elif kind == "pair":
            for h in fields["render_headers"]:
                h[10] = 2**32 - 400
        original(kind, payload, **fields)

    monkeypatch.setattr(f, "send", rewrite)
    f.pair(1)
    until(preview, lambda: preview.video_completed == 2)
    monkeypatch.setattr(f, "send", original)
    f.pair(2)
    until(preview, lambda: preview.video_completed == 3)
    assert preview.decoder.bytes == 0


def test_decoder_owner_change_is_rejected_before_mixing_sources(preview, monkeypatch):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    original = f.send

    def rewrite(kind, payload=b"", **fields):
        if kind == "encoded":
            fields["decoder_owner"] = "0x5678"
        original(kind, payload, **fields)

    monkeypatch.setattr(f, "send", rewrite)
    with pytest.raises(ValueError, match="accepted compressed"):
        f.pair(1)
    assert preview.decoder.count == 2


def test_completion_is_exact_and_freezes_unstarted_outputs(preview):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    f.audio()
    f.send("end", encoded_units=2, pairs=1, vqe_outputs=1, rejected_native_attempts=0)
    preview.pump()
    assert preview.end is not None and preview.source_eof_ns is not None
    assert preview.video_completed == preview.audio.written == 0
    assert len(preview.waiting) == len(preview.audio.ring) == 1
    with pytest.raises(ValueError, match="record after source end"):
        f.audio(2)


def test_incorrect_completion_counters_fail(preview):
    f = Feed(preview)
    f.pair(0, checkpoints=True)
    with pytest.raises(ValueError, match="count mismatch"):
        f.send("end", encoded_units=3, pairs=1, vqe_outputs=0, rejected_native_attempts=0)
    assert preview.end is None


def test_transport_eof_without_completion_is_not_success(preview, tmp_path):
    path = tmp_path / "prefix.bin"
    path.write_bytes(
        M["LIVE"]["encode"](dict(kind="begin", seq=1, session="a" * 32, elf_sha256=M["HASHES"]))
    )
    with path.open("rb") as source, pytest.raises(ValueError, match="without completion"):
        M["run"](preview, source.fileno())


def test_real_sdl_worker_explicit_continuous_limit_leaves_snapshot_default_unchanged(monkeypatch):
    monkeypatch.setenv("SDL_VIDEODRIVER", "dummy")
    output = M["VIDEO"]["Output"](16, 6, 2, frame_limit=33)
    try:
        for i in range(33):
            ack = output.present(f"pair:{i}", bytes(144), 2)
            assert ack["pair_id"] == f"pair:{i}"
        output.finish(2)
    finally:
        output.abort()
    assert M["VIDEO"]["Output"].__init__.__kwdefaults__ == {"frame_limit": 32}


def test_audio_mono_argument_allowlist_precedes_process_creation(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("must not start ffplay for unsupported options")

    monkeypatch.setattr(subprocess, "Popen", unexpected)
    with pytest.raises(ValueError, match="explicit supported mono"):
        M["LIVE"]["PCM"]["Ffplay"](channel_args=("-channels", "2"))
