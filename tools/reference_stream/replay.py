"""Replay identical private snapshots through host codecs and the real collector.

Offline host-only experiment, not Android/Frida transport or playback latency.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import tempfile
from typing import Any
import zlib

BASE = Path(__file__).resolve().parents[1]
REFERENCE = runpy.run_path(str(BASE / "app_reference_stream.py"))
require = REFERENCE["require"]
MAX_EVENTS_BYTES = 32 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_PIXELS = 240 * 1024 * 1024
MAX_SNAPSHOTS = 32
CODECS = ("raw", "zlib", "lz4")


@lru_cache(maxsize=1)
def lz4_encoder() -> Any:
    path = ctypes.util.find_library("lz4")
    require(path is not None, "optional system liblz4 unavailable")
    library = ctypes.CDLL(path)
    bound = library.LZ4_compressBound
    bound.argtypes, bound.restype = [ctypes.c_int], ctypes.c_int
    encode = library.LZ4_compress_default
    encode.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    encode.restype = ctypes.c_int
    return bound, encode


def encode_payload(payload: bytes, codec: str) -> tuple[bytes, str]:
    require(codec in CODECS, "unsupported replay codec")
    if codec == "raw":
        return payload, "raw"
    if codec == "zlib":
        encoded = zlib.compress(payload, 1)
    else:
        bound, encode = lz4_encoder()
        capacity = bound(len(payload))
        require(0 < capacity <= 12 * 1024 * 1024 + 65536, "LZ4 replay buffer bound")
        output = ctypes.create_string_buffer(capacity)
        count = encode(payload, output, len(payload), capacity)
        require(0 < count <= capacity, "LZ4 replay compression failed")
        encoded = output.raw[:count]
    return (encoded, codec) if len(encoded) < len(payload) else (payload, "raw")


def snapshots(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    size = total = 0
    with (root / "events.jsonl").open("rb") as source:
        for index in range(REFERENCE["MAX_ROWS"] + 1):
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            size += len(line)
            require(index < REFERENCE["MAX_ROWS"] and size <= MAX_EVENTS_BYTES
                    and len(line) <= MAX_LINE, "replay event limit")
            row = json.loads(line)
            require(isinstance(row, dict), "invalid replay row")
            require(row.get("event") != "error", "source contains native error")
            if row.get("event") not in {"native_pixels", "native_render_pixels"}:
                continue
            # Original persisted bytes, not old compressed lengths or timestamps.
            payload = REFERENCE["PROJECT"]["blob"](root, row)
            total += len(payload)
            require(total <= MAX_PIXELS and len(rows) < MAX_SNAPSHOTS,
                    "replay snapshot budget")
            rows.append(row)
    require(rows, "no replay snapshots")
    return rows


def trial(root: Path, rows: list[dict[str, Any]], codec: str, folder: Path) -> dict[str, Any]:
    encode_profile = REFERENCE["PROFILE"]["Profile"]()
    capture = REFERENCE["Capture"](folder)
    status, error = "ok", None
    verified = fallbacks = 0
    try:
        for index, original in enumerate(rows):
            with encode_profile.measure("source_read_and_verify", bytes=original["bytes"]):
                payload = REFERENCE["PROJECT"]["blob"](root, original)
            with encode_profile.measure("host_encode", bytes=len(payload)):
                wire, encoding = encode_payload(payload, codec)
            fallbacks += codec != "raw" and encoding == "raw"
            row = dict(event=original["event"], device_mono_ns=index,
                       bytes=len(payload), sha256=original["sha256"],
                       encoding=encoding, transport_bytes=len(wire))
            capture.message(dict(type="send", payload=row), wire)
            capture.snapshot()  # surface callback failures immediately
            verified += 1
    except Exception as caught:
        status, error = "failed", str(caught)
    finally:
        capture.close()
    return dict(codec=codec, status=status, error=error,
                verified_snapshots=verified, raw_fallbacks=fallbacks,
                payload_bytes=capture.bytes, binary_bytes=capture.transport_bytes,
                host_encode_profile=encode_profile.result(),
                collector_profile=capture.profile.result())


def replay(root: Path, output: Path, repeats: int = 3) -> dict[str, Any]:
    require(type(repeats) is int and 1 <= repeats <= 5, "replay repeats must be 1..5")
    output.mkdir(mode=0o700)  # exclusive; never overwrite a previous experiment
    report: dict[str, Any] = dict(
        status="failed", error=None, experiment="identical-snapshot-host-codec-collector",
        clock="host-monotonic", repeats=repeats, trials=[],
        runtime=dict(python=platform.python_version(), machine=platform.machine(),
                     system=platform.system(), zlib_runtime=zlib.ZLIB_RUNTIME_VERSION,
                     liblz4=ctypes.util.find_library("lz4")),
        codec_configuration=dict(zlib_level=1, lz4="LZ4_compress_default",
                                 raw_fallback_when_not_smaller=True),
        source_validation="payload lengths and SHA-256 only; not native crop/renderer audit",
        persistence="buffered write+flush, not fsync or durable-storage latency",
        android_measured=False, network_measured=False, playback_measured=False,
        sustained_realtime_verified=False, physical_av_measured=False,
    )
    try:
        rows = snapshots(root)
        identity = [[r["event"], r["bytes"], r["sha256"]] for r in rows]
        report.update(snapshots=len(rows), payload_bytes=sum(r["bytes"] for r in rows),
                      corpus_sha256=hashlib.sha256(json.dumps(identity).encode()).hexdigest())
        for iteration in range(repeats):
            # Rotate first codec to expose (not eliminate) cache/order effects.
            order = CODECS[iteration % len(CODECS):] + CODECS[:iteration % len(CODECS)]
            for codec in order:
                # Real collector rehydrates temporary pixel files; remove per trial.
                with tempfile.TemporaryDirectory(prefix="replay-", dir=output) as folder:
                    result = trial(root, rows, codec, Path(folder))
                report["trials"].append(dict(iteration=iteration, **result))
        report["status"] = "ok" if all(t["status"] == "ok" for t in report["trials"]) else "failed"
    except Exception as caught:
        report["error"] = str(caught)
    finally:
        with (output / "replay.json").open("x") as receipt:
            json.dump(report, receipt, indent=2)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path, help="new private experiment directory")
    parser.add_argument("--repeats", type=int, default=3, choices=range(1, 6))
    args = parser.parse_args()
    os.umask(0o077)
    report = replay(args.capture, args.output, args.repeats)
    print(json.dumps({key: report[key] for key in ("status", "error")}))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
