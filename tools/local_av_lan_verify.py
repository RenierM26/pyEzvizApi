"""Offline saved-LAN source/media verification; no camera or output devices.

Rebuild media chains without the output receipt builder. Decoder/policy code is
shared with playback; this is not a separate decoder implementation, an
authenticity signature, or a physical display/audio-clock measurement.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import logging
import os
from pathlib import Path
import runpy
from typing import Any

import pyezvizapi

BASE = Path(__file__).parent
LAN = runpy.run_path(str(BASE / "local_av_lan_playback.py"))
EVIDENCE = LAN["EVIDENCE"]
ONLINE = LAN["CAPTURE"]["PREPARE"]["ONLINE"]
DECRYPT = LAN["CAPTURE"]["PREPARE"]["CAPTURE"]["DECRYPT"]
TRACKS = ("video_pair", "audio_block")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(row: Any) -> bytes:
    return json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def rational(row: Any) -> Fraction:
    require(type(row) is dict and set(row) == {"numerator", "denominator"}, "invalid rational")
    n, d = row["numerator"], row["denominator"]
    require(
        type(n) is int and type(d) is int and 0 <= n < 2**128 and 0 < d < 2**128,
        "invalid rational extent",
    )
    stamp = Fraction(n, d)
    require(stamp.numerator == n and stamp.denominator == d, "noncanonical rational")
    return stamp


class SourceChain:
    """Independent canonical projection; do not import the media receipt builder."""

    def __init__(self, anchor: int):
        require(type(anchor) is int and 0 < anchor < 2**128, "invalid host anchor")
        self.anchor = anchor
        self.count = dict.fromkeys(TRACKS, 0)
        self.bytes = dict(self.count)
        self.previous: dict[str, Fraction] = {}
        self.hashes = {
            t: hashlib.sha256(b"bounded-output-media-v1\n" + t.encode() + b"\n") for t in TRACKS
        }

    def add(self, track: str, identity: str, at: Any, size: int, digest: str) -> dict[str, Any]:
        require(track in TRACKS, "unknown track")
        stamp = rational(at)
        require(
            stamp <= 60 and stamp > self.previous.get(track, Fraction(-1)),
            "nonincreasing or excessive source target",
        )
        limit = 900 if track == "video_pair" else 10000
        require(
            self.count[track] < limit
            and type(identity) is str
            and bool(identity)
            and type(size) is int
            and 0 < size <= 64 * 1024 * 1024,
            "media extent bound",
        )
        require(track != "audio_block" or size == 2048, "unsupported PCM extent")
        row = dict(
            track=track,
            id=identity,
            source_at=at,
            target_monotonic_ns=self.anchor + stamp.numerator * 1000000000 // stamp.denominator,
            bytes=size,
            payload_sha256=digest,
        )
        self.hashes[track].update(canonical(row) + b"\n")
        self.count[track] += 1
        self.bytes[track] += size
        self.previous[track] = stamp
        return row

    def result(self) -> dict[str, Any]:
        return dict(
            profile="bounded-output-media-v1",
            host_anchor_monotonic_ns=self.anchor,
            order="strict-source-order-per-track",
            tracks={
                t: dict(
                    completed=self.count[t],
                    bytes=self.bytes[t],
                    sha256=self.hashes[t].hexdigest(),
                )
                for t in TRACKS
            },
        )


def fingerprint(event: dict[str, Any], payload: tuple[bytes, ...]) -> tuple[int, str]:
    """Canonical side-by-side Y/U/V rows, independently of transport layout."""
    require(type(payload) is tuple and all(type(p) is bytes for p in payload), "mutable payload")
    if event["kind"] == "audio_block":
        require(len(payload) == 1 and len(payload[0]) == 2048, "unsupported PCM extent")
        return len(payload[0]), hashlib.sha256(payload[0]).hexdigest()
    require(event["kind"] == "video_pair" and len(payload) == 2, "unsupported video payload")
    lenses = event["lenses"]
    require(type(lenses) is list and len(lenses) == 2, "invalid lenses")
    width, height = lenses[0]["width"], lenses[0]["height"]
    require(
        all(type(n) is int and 0 < n <= 4096 and n % 2 == 0 for n in (width, height))
        and lenses[1]["width"] == width
        and lenses[1]["height"] == height,
        "invalid video geometry",
    )
    require(all(len(p) == width * height * 3 // 2 for p in payload), "invalid video extent")
    digest, offset = hashlib.sha256(), 0
    for w, h in ((width, height), (width // 2, height // 2), (width // 2, height // 2)):
        for index in range(h):
            start = offset + index * w
            digest.update(payload[0][start : start + w])
            digest.update(payload[1][start : start + w])
        offset += w * h
    return sum(len(p) for p in payload), digest.hexdigest()


def receipt_binding(
    parent: dict[str, Any], summary: dict[str, Any], digest: str, package: str
) -> dict[str, Any]:
    require(
        parent.get("profile") == "attended-direct-lan-prefix-v1"
        and parent.get("status") == "completed"
        and parent.get("worker_reaped") is True
        and parent.get("stage") == "finished",
        "requires successful attended receipt",
    )
    pb = parent["playback"]
    require(
        summary["binding"] == dict(config_sha256=digest, package_sha256=package)
        and parent.get("config_sha256") == digest
        and pb.get("config_sha256") == digest
        and pb.get("package_sha256") == package,
        "package/configuration binding failed",
    )
    require(
        parent.get("packet_evidence") == dict(status="integrity-verified", summary=summary)
        and pb.get("packet_evidence") == dict(status="finalized", summary=summary),
        "evidence receipt binding failed",
    )
    startup = pb["requested_options"]["startup_pairing"]
    require(
        startup in ("strict", "common-keyframe")
        and pb["requested_options"] == dict(LAN["OPTIONS"], startup_pairing=startup)
        and pb.get("capture_limits") == LAN["LIMITS"],
        "unsupported receipt profile",
    )
    require(
        pb.get("status") == "prefix-output-completed"
        and pb.get("stage") == "finished"
        and pb.get("source_worker_retained") is False
        and pb.get("caller_cleanup_error_types") == []
        and pb.get("cleanup_error_types") == [],
        "failed playback or cleanup",
    )
    owner = pb["final_owner"]
    require(
        all(
            type(owner.get(field)) is int and owner[field] == summary[key]
            for field, key in (("packets_yielded", "packets"), ("bytes_yielded", "bytes"))
        )
        and owner.get("owner_closed") is True
        and owner.get("transport_owned") is False
        and owner.get("transport_closure_verified") is True,
        "source counters/cleanup mismatch",
    )
    pull = pb["source_pull"]
    require(
        all(
            pull.get(k) is False
            for k in ("worker_alive", "outstanding", "read_active", "result_ready")
        )
        and all(pull.get(k) is True for k in ("source_ended", "iterator_closed", "consumer_closed"))
        and all(
            pull.get(k) is None
            for k in ("source_error_type", "close_error_type", "interrupt_error_type")
        ),
        "unfinished source pull",
    )
    prepared = pb["preparation"]
    capture = prepared["capture"]
    crypto = capture["decryption"]
    require(
        capture["limits"] == LAN["LIMITS"]
        and capture["capture"]["packets_yielded"] == summary["packets"]
        and crypto["encrypted_bytes"] == summary["bytes"]
        and crypto["encrypted_prefix_sha256"] == summary["sha256"]
        and pb["accepted_prefix_clear_sha256"]
        == prepared["accepted_prefix_clear_sha256"]
        == capture["accepted_prefix_clear_sha256"]
        == crypto["complete_clear_sha256"],
        "nested source evidence mismatch",
    )
    LAN["CAPTURE"]["verify_output"](prepared, pb["output"])
    return pb


def tails(scheduler: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    actions = scheduler["actions"]
    require(
        type(actions) is list and len(actions) in (2, 4), "requires compact finalized action tail"
    )
    pairs = {}
    for index in range(0, len(actions), 2):
        a, b = actions[index : index + 2]
        require(
            a["kind"] == "output_call_submitted"
            and b["kind"] == "output_call_completed"
            and a["track"] == b["track"]
            and a["id"] == b["id"]
            and a["id"] not in pairs,
            "invalid action pair",
        )
        require(
            type(a["submission_late_ns"]) is int and 0 <= a["submission_late_ns"] <= 250000000,
            "invalid tail lateness",
        )
        pairs[a["id"]] = (a, b["acknowledgement"])
    return pairs


def compare_events(
    pb: dict[str, Any], events: Any, decode: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    scheduler = pb["output"]["scheduler"]
    try:
        chain = SourceChain(scheduler["host_anchor_monotonic_ns"])
        pending = tails(scheduler)
        for event, payload in events:
            track = event["kind"]
            identity = event["id"] if track == "video_pair" else event["block"]["id"]
            size, digest = fingerprint(event, payload)
            row = chain.add(track, identity, event["at"], size, digest)
            if identity in pending:
                a, ack = pending.pop(identity)
                require(
                    a["track"] == track
                    and a["source_at"] == event["at"]
                    and a["target_monotonic_ns"] == row["target_monotonic_ns"]
                    and a["bytes"] == size
                    and ack["bytes"] == size
                    and ack["pixel_sha256" if track == "video_pair" else "pcm_sha256"] == digest,
                    "retained acknowledgement mismatch",
                )
                if track == "video_pair":
                    require(
                        ack["kind"] == "presented" and ack["pair_id"] == identity,
                        "retained video identity mismatch",
                    )
    finally:
        events.close()
    require(
        not pending and decode["status"] == policy["status"] == "completed",
        "incomplete source replay",
    )
    require(
        chain.result() == scheduler["action_audit"]["media_receipt"]
        and chain.count == scheduler["completed"],
        "full media/target chain mismatch",
    )
    original = pb["preparation"]["decode"]
    require(
        decode["track_selection"] == original["track_selection"],
        "same-container track selection mismatch",
    )
    require(
        decode["preparation"].get("startup_alignment")
        == original["preparation"].get("startup_alignment"),
        "startup provenance mismatch",
    )
    for field in (
        "consumed_video_metadata_sha256",
        "consumed_audio_metadata_sha256",
    ):
        require(
            decode["preparation"][field] == original["preparation"][field],
            "decoded provenance mismatch",
        )
    for field in (
        "origin",
        "audio_clock_contract",
        "audio_clock_rows_sha256",
        "mapped_metadata_sha256",
    ):
        require(
            policy["policy"][field] == pb["preparation"]["online"]["policy"][field],
            "source timeline/audio policy mismatch",
        )
    return chain.result()


def reconstruct(pb: dict[str, Any], raw: bytes, key: str) -> dict[str, Any]:
    crypto: dict[str, Any] = {}
    decode: dict[str, Any] = {}
    policy: dict[str, Any] = {}
    selection: dict[str, Any] = {}
    contract = pb["preparation"]["online"]["policy"]["audio_clock_contract"]
    # Validate declared audio policy before any native decode work.
    ONLINE["Policy"](
        (0, 1),
        2,
        contract["policy"],
        contract["max_overlap_ms"],
        contract["max_nominal_phase_ms"],
        identity_mode="source-sequence",
        pair_limit=900,
    )
    clear = DECRYPT["iter_decrypted"](
        (raw[i : i + 32768] for i in range(0, len(raw), 32768)),
        key,
        crypto,
        codec="hevc",
        byte_limit=EVIDENCE["MAX_BYTES"],
    )
    chunks = ONLINE["CHUNKED"]["iter_chunks"](
        clear,
        "mpeg",
        (0, 1),
        2,
        decode,
        startup="bounded-mpeg",
        pes_ids=(224, 225, 192),
        selection=selection,
        startup_pairing=pb["requested_options"]["startup_pairing"],
        max_bytes=EVIDENCE["MAX_BYTES"],
    )
    events = ONLINE["iter_online"](
        chunks,
        (0, 1),
        2,
        policy,
        selection=selection,
        policy=contract["policy"],
        overlap_ms=contract["max_overlap_ms"],
        phase_ms=contract["max_nominal_phase_ms"],
        identity_mode="source-sequence",
        pair_limit=900,
    )
    media = compare_events(pb, events, decode, policy)
    require(
        crypto["verified_decryption_end"] is True
        and not crypto["cleanup_errors"]
        and crypto["encrypted_bytes"] == len(raw)
        and crypto["encrypted_prefix_sha256"] == hashlib.sha256(raw).hexdigest()
        and crypto["complete_clear_sha256"] == pb["accepted_prefix_clear_sha256"],
        "accepted clear prefix mismatch",
    )
    return media


def verify(args: Any) -> dict[str, Any]:
    summary = EVIDENCE["verify"](args.packet_evidence)
    raw_receipt = LAN["read_regular"](args.receipt, LAN["MAX_RECEIPT"])
    parent = json.loads(raw_receipt)
    credentials, _device, config_hash = LAN["private_config"](args.private_config)
    package = LAN["RUNTIME"]["package_fingerprint"](Path(pyezvizapi.__file__).parent)
    pb = receipt_binding(parent, summary, config_hash, package)
    root = EVIDENCE["directory"](args.packet_evidence)
    try:
        with EVIDENCE["regular"](root, "packet-bodies.bin", EVIDENCE["MAX_BYTES"]) as source:
            raw = source.read(EVIDENCE["MAX_BYTES"] + 1)
    finally:
        os.close(root)
    # Bind the immutable replay snapshot too, not only an earlier file read.
    require(
        len(raw) == summary["bytes"] and hashlib.sha256(raw).hexdigest() == summary["sha256"],
        "evidence changed before replay",
    )
    media = reconstruct(pb, raw, credentials.media_key)
    return dict(
        status="source-media-verified",
        receipt_sha256=hashlib.sha256(raw_receipt).hexdigest(),
        encrypted_sha256=summary["sha256"],
        clear_sha256=pb["accepted_prefix_clear_sha256"],
        media_receipt=media,
        camera_opened=False,
        output_devices_opened=False,
        physical_av_sync_measured=False,
        network_eof_established=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("private-config", "receipt", "packet-evidence", "result"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        fd = os.open(args.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        print("Result must be a new writable file.")
        return 2
    disabled = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    with os.fdopen(fd, "wb") as output:
        try:
            report = verify(args)
            code = 0
        except (KeyboardInterrupt, EOFError):
            report, code = dict(status="cancelled"), 130
        except Exception:
            # Never serialize decoder exception text, source metadata or private configuration.
            report, code = dict(status="verification-failed"), 2
        finally:
            logging.disable(disabled)
        output.write(canonical(report) + b"\n")
    print(json.dumps(dict(status=report["status"])))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
