"""Independent chain projection, full-prefix tampering and offline boundaries."""

import copy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
M = runpy.run_path(str(ROOT / "tools/local_av_lan_verify.py"))
G = M["verify"].__globals__
AUDIT = runpy.run_path(str(ROOT / "tools/local_av_audit.py"))
BINDING = dict(config_sha256="c" * 64, package_sha256="a" * 64)


def rational(n, d=1):
    stamp = Fraction(n, d)
    return dict(numerator=stamp.numerator, denominator=stamp.denominator)


def sample_events():
    for index, track in enumerate(
        ("video_pair", "audio_block", "video_pair", "audio_block", "video_pair")
    ):
        event: dict[str, Any] = dict(
            kind=track,
            at=rational(index, 10) if index not in (0, 2, 4) else rational(index // 2, 5),
        )
        data: tuple[bytes, ...]
        if track == "video_pair":
            event.update(id=f"local-pair:{index // 2 + 1}", lenses=[dict(width=2, height=2)] * 2)
            data = (bytes(range(index, index + 6)), bytes(range(index + 6, index + 12)))
        else:
            event["block"] = dict(id=f"aac:2:{index // 2}")
            data = (bytes([index]) * 2048,)
        yield event, data


@pytest.fixture
def replay():
    events = list(sample_events())
    media = AUDIT["MediaReceipt"](1000000000)
    actions = []
    for event, data in events:
        track, at = event["kind"], event["at"]
        identity = event["id"] if track == "video_pair" else event["block"]["id"]
        # This independent small fixture explicitly composes visible 2x2 Y/U/V.
        pixels = (
            (
                data[0][:2]
                + data[1][:2]
                + data[0][2:4]
                + data[1][2:4]
                + data[0][4:5]
                + data[1][4:5]
                + data[0][5:6]
                + data[1][5:6]
            )
            if track == "video_pair"
            else data[0]
        )
        stamp = at["numerator"] * 1000000000 // at["denominator"]
        submitted = dict(
            kind="output_call_submitted",
            track=track,
            id=identity,
            source_at=at,
            target_monotonic_ns=1000000000 + stamp,
            bytes=len(pixels),
            submission_late_ns=0,
        )
        ack: dict[str, Any] = dict(bytes=len(pixels))
        ack["pixel_sha256" if track == "video_pair" else "pcm_sha256"] = hashlib.sha256(
            pixels
        ).hexdigest()
        if track == "video_pair":
            ack.update(kind="presented", pair_id=identity)
        completed = dict(
            kind="output_call_completed", track=track, id=identity, acknowledgement=ack
        )
        media.append(submitted, completed)
        actions.extend([submitted, completed])
    decode = dict(
        status="completed",
        track_selection=dict(indices=[0, 1, 2]),
        preparation=dict(
            startup_alignment={"excluded_frames": 0},
            consumed_video_metadata_sha256="v",
            consumed_audio_metadata_sha256="a",
        ),
    )
    policy = dict(
        status="completed",
        policy=dict(
            origin=rational(0),
            audio_clock_contract={"policy": "reject"},
            audio_clock_rows_sha256="audio",
            mapped_metadata_sha256="mapped",
        ),
    )
    scheduler = dict(
        host_anchor_monotonic_ns=1000000000,
        completed=dict(video_pair=3, audio_block=2),
        actions=actions[-4:],
        action_audit=dict(media_receipt=media.result()),
    )
    pb = dict(
        output=dict(scheduler=scheduler),
        preparation=dict(decode=copy.deepcopy(decode), online=copy.deepcopy(policy)),
    )
    return pb, events, decode, policy


class iterator:
    def __init__(self, rows, closed):
        self.rows, self.closed = iter(rows), closed

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.rows)

    def close(self):
        self.closed.append(True)


def test_reconstructs_canonical_pair_not_concatenated_lenses_and_original_targets(replay):
    pb, rows, decode, policy = replay
    closed: list[bool] = []
    result = M["compare_events"](pb, iterator(rows, closed), decode, policy)
    assert closed and result == pb["output"]["scheduler"]["action_audit"]["media_receipt"]
    assert result["tracks"]["video_pair"]["completed"] == 3
    assert result["tracks"]["audio_block"]["bytes"] == 4096
    expected = bytes([0, 1, 6, 7, 2, 3, 8, 9, 4, 10, 5, 11])
    size, digest = M["fingerprint"](*rows[0])
    assert size == 12 and digest == hashlib.sha256(expected).hexdigest()
    assert digest != hashlib.sha256(b"".join(rows[0][1])).hexdigest()


@pytest.mark.parametrize(
    "case",
    [
        "old-pixel",
        "old-pcm",
        "old-target",
        "omitted-old",
        "chain",
        "anchor",
        "tail-target",
        "tail-ack",
        "tail-id",
        "metadata",
        "startup",
        "selection",
        "origin",
        "audio-policy",
        "mapped",
        "decode-end",
        "policy-end",
    ],
)
def test_source_changes_outside_identical_tail_and_receipt_tampering_fail_closed(replay, case):  # noqa: PLR0912
    pb, rows, decode, policy = replay
    scheduler = pb["output"]["scheduler"]
    original_tail = copy.deepcopy(scheduler["actions"])
    if case == "old-pixel":
        rows[0] = rows[0][0], (b"xxxxxx", rows[0][1][1])
    elif case == "old-pcm":
        rows[1] = rows[1][0], (b"x" * 2048,)
    elif case == "old-target":
        rows[0][0]["at"] = rational(1, 100)
    elif case == "omitted-old":
        rows.pop(0)
    elif case == "chain":
        scheduler["action_audit"]["media_receipt"]["tracks"]["video_pair"]["sha256"] = "0" * 64
    elif case == "anchor":
        scheduler["host_anchor_monotonic_ns"] += 1
    elif case == "tail-target":
        scheduler["actions"][0]["target_monotonic_ns"] += 1
    elif case == "tail-ack":
        scheduler["actions"][1]["acknowledgement"]["pcm_sha256"] = "0" * 64
    elif case == "tail-id":
        scheduler["actions"][1]["id"] = "unknown"
    elif case in ("metadata", "startup"):
        decode["preparation"][
            "consumed_video_metadata_sha256" if case == "metadata" else "startup_alignment"
        ] = "changed"
    elif case == "selection":
        decode["track_selection"] = {}
    elif case in ("origin", "audio-policy", "mapped"):
        policy["policy"][
            {
                "origin": "origin",
                "audio-policy": "audio_clock_contract",
                "mapped": "mapped_metadata_sha256",
            }[case]
        ] = "changed"
    else:
        (decode if case == "decode-end" else policy)["status"] = "failed"
    closed: list[bool] = []
    with pytest.raises(ValueError):
        M["compare_events"](pb, iterator(rows, closed), decode, policy)
    assert closed
    if case.startswith("old-") or case == "omitted-old":
        assert scheduler["actions"] == original_tail


@pytest.mark.parametrize(
    "at",
    [
        dict(numerator=True, denominator=1),
        dict(numerator=1, denominator=0),
        rational(-1),
        dict(numerator=2, denominator=4),
        rational(2**129),
        dict(numerator=0, denominator=1, extra=0),
    ],
)
def test_invalid_exact_targets_are_not_normalized_into_success(at):
    with pytest.raises(ValueError):
        M["SourceChain"](1).add("video_pair", "id", at, 12, "a" * 64)


def parent_receipt(summary):
    pb = dict(
        accepted_prefix_clear_sha256="d" * 64,
        status="prefix-output-completed",
        stage="finished",
        package_sha256="a" * 64,
        config_sha256="c" * 64,
        source_worker_retained=False,
        caller_cleanup_error_types=[],
        cleanup_error_types=[],
        requested_options=dict(M["LAN"]["OPTIONS"], startup_pairing="strict"),
        capture_limits=M["LAN"]["LIMITS"],
        preparation=dict(
            accepted_prefix_clear_sha256="d" * 64,
            capture=dict(
                limits=M["LAN"]["LIMITS"],
                capture=dict(packets_yielded=summary["packets"]),
                accepted_prefix_clear_sha256="d" * 64,
                decryption=dict(
                    encrypted_bytes=summary["bytes"],
                    encrypted_prefix_sha256=summary["sha256"],
                    complete_clear_sha256="d" * 64,
                ),
            ),
        ),
        output={},
        packet_evidence=dict(status="finalized", summary=summary),
        final_owner=dict(
            packets_yielded=summary["packets"],
            bytes_yielded=summary["bytes"],
            owner_closed=True,
            transport_owned=False,
            transport_closure_verified=True,
        ),
        source_pull=dict(
            worker_alive=False,
            outstanding=False,
            read_active=False,
            result_ready=False,
            source_ended=True,
            iterator_closed=True,
            consumer_closed=True,
            source_error_type=None,
            close_error_type=None,
            interrupt_error_type=None,
        ),
    )
    return dict(
        profile="attended-direct-lan-prefix-v1",
        status="completed",
        stage="finished",
        worker_reaped=True,
        config_sha256="c" * 64,
        playback=pb,
        packet_evidence=dict(status="integrity-verified", summary=summary),
    )


@pytest.mark.parametrize(
    "case",
    [
        "good",
        "parent-failed",
        "unreaped",
        "worker-failed",
        "config",
        "package",
        "evidence",
        "limits",
        "options",
        "counter",
        "bool-counter",
        "live-worker",
        "cleanup",
        "owner",
        "source-error",
        "inner-cipher",
        "inner-clear",
    ],
)
def test_receipt_binding_rejects_failed_unbound_or_unfinished_attempts(monkeypatch, case):  # noqa: PLR0912
    summary = dict(binding=BINDING, packets=1, bytes=3, sha256="e" * 64)
    parent = parent_receipt(summary)
    pb = parent["playback"]
    if case == "parent-failed":
        parent["status"] = "failed"
    elif case == "unreaped":
        parent["worker_reaped"] = False
    elif case == "worker-failed":
        pb["status"] = "failed"
    elif case == "config":
        parent["config_sha256"] = "0" * 64
    elif case == "package":
        pb["package_sha256"] = "0" * 64
    elif case == "evidence":
        pb["packet_evidence"] = {}
    elif case == "limits":
        pb["capture_limits"] = {}
    elif case == "options":
        pb["requested_options"] = dict(startup_pairing="strict")
    elif case == "counter":
        pb["final_owner"]["bytes_yielded"] += 1
    elif case == "bool-counter":
        pb["final_owner"]["packets_yielded"] = True
    elif case == "live-worker":
        pb["source_pull"]["worker_alive"] = True
    elif case == "cleanup":
        pb["caller_cleanup_error_types"] = ["OSError"]
    elif case == "owner":
        pb["final_owner"]["transport_owned"] = True
    elif case == "inner-cipher":
        pb["preparation"]["capture"]["decryption"]["encrypted_prefix_sha256"] = "0" * 64
    elif case == "inner-clear":
        pb["preparation"]["accepted_prefix_clear_sha256"] = "0" * 64
    elif case == "source-error":
        pb["source_pull"]["source_error_type"] = "TimeoutError"
    verified = []
    monkeypatch.setitem(M["LAN"]["CAPTURE"], "verify_output", lambda *_a: verified.append(True))
    if case == "good":
        assert M["receipt_binding"](parent, summary, "c" * 64, "a" * 64) is pb and verified
    else:
        with pytest.raises((ValueError, KeyError)):
            M["receipt_binding"](parent, summary, "c" * 64, "a" * 64)
        assert not verified


@pytest.mark.parametrize("case", ["good", "changed-snapshot", "bound"])
def test_offline_file_binding_and_immutable_snapshot_before_decode(tmp_path, monkeypatch, case):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    writer = M["EVIDENCE"]["PacketEvidence"](evidence)

    def packets():
        yield SimpleNamespace(body=b"ciphertext")

    list(writer.retain(packets()))
    summary = writer.finish(BINDING)
    parent = parent_receipt(summary)
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(parent))
    calls = []
    monkeypatch.setitem(M["LAN"]["CAPTURE"], "verify_output", lambda *_a: None)
    monkeypatch.setitem(
        M["LAN"],
        "private_config",
        lambda _p: (SimpleNamespace(media_key="private-key"), {}, "c" * 64),
    )
    monkeypatch.setitem(M["LAN"]["RUNTIME"], "package_fingerprint", lambda _p: "a" * 64)

    def reconstructed(pb, raw, key):
        calls.append((raw, key))
        return {}

    monkeypatch.setitem(G, "reconstruct", reconstructed)
    if case == "changed-snapshot":
        real_verify = M["EVIDENCE"]["verify"]

        def changed(path):
            result = real_verify(path)
            (path / "packet-bodies.bin").write_bytes(b"changed!!!")
            return result

        monkeypatch.setitem(M["EVIDENCE"], "verify", changed)
    elif case == "bound":
        receipt.write_bytes(b" " * (M["LAN"]["MAX_RECEIPT"] + 1))
    args = SimpleNamespace(
        packet_evidence=evidence, receipt=receipt, private_config=tmp_path / "private.json"
    )
    if case == "good":
        result = M["verify"](args)
        assert result["status"] == "source-media-verified" and calls == [
            (b"ciphertext", "private-key")
        ]
        assert result["camera_opened"] is False and result["output_devices_opened"] is False
    else:
        with pytest.raises(ValueError):
            M["verify"](args)
        assert not calls


@pytest.mark.parametrize("case", ["failed", "cancelled", "existing"])
def test_cli_never_echoes_private_exception_text_and_preserves_existing_result(
    tmp_path, monkeypatch, capsys, case
):
    result = tmp_path / "result.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify",
            "--receipt",
            str(tmp_path / "r"),
            "--packet-evidence",
            str(tmp_path / "e"),
            "--private-config",
            str(tmp_path / "p"),
            "--result",
            str(result),
        ],
    )
    calls = []

    def fail(_args):
        calls.append(True)
        if case == "cancelled":
            raise KeyboardInterrupt
        raise ValueError("PRIVATE-KEY-DO-NOT-ECHO")

    monkeypatch.setitem(G, "verify", fail)
    if case == "existing":
        result.write_text("keep")
    assert M["main"]() == (130 if case == "cancelled" else 2)
    if case == "existing":
        assert result.read_text() == "keep" and not calls
    else:
        assert result.stat().st_mode & 0o777 == 0o600
        assert json.loads(result.read_text()) == dict(
            status="cancelled" if case == "cancelled" else "verification-failed"
        )
    assert "PRIVATE-KEY" not in repr(capsys.readouterr())


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux sealed-store fixture")
@pytest.mark.parametrize("case", ["good", "clear-hash", "selection", "crypto-finalizer"])
def test_synthetic_native_source_replay_against_real_playback_receipt(tmp_path, monkeypatch, case):
    """Real public MPEG/PyAV/PCM; mock crypto and output, never camera IO."""
    capture = runpy.run_path(str(Path(__file__).with_name("test_local_av_capture_playback.py")))
    rig = capture["rig"].__wrapped__(tmp_path, monkeypatch)
    pb: dict[str, Any] = {}
    owner, session = capture["session"](
        rig,
        pb,
        pes_ids=(224, 225, 192),
        diagnostic_tail=2,
        identity_mode="source-sequence",
        decoder_deadline_mode="consumer-excluding",
        pair_limit=900,
        byte_limit=32 * 1024 * 1024,
    )
    session.play()
    assert owner.closed
    pb["requested_options"] = dict(startup_pairing="strict")
    monkeypatch.setattr(M["DECRYPT"]["Decryptor"], "decode", lambda _self, chunk: chunk)
    if case == "clear-hash":
        pb["accepted_prefix_clear_sha256"] = "0" * 64
    elif case == "selection":
        pb["preparation"]["decode"]["track_selection"]["audio_index"] = 99
    elif case == "crypto-finalizer":

        def fail(_self):
            raise ValueError("crypto finalizer failed")

        monkeypatch.setattr(M["DECRYPT"]["Decryptor"], "finish", fail)
    if case == "good":
        media = M["reconstruct"](pb, rig[0], "public-test-key")
        assert media == pb["output"]["scheduler"]["action_audit"]["media_receipt"]
        assert media["tracks"]["video_pair"]["completed"] > 1
        assert media["tracks"]["audio_block"]["completed"] > 1
    else:
        with pytest.raises(ValueError):
            M["reconstruct"](pb, rig[0], "public-test-key")
