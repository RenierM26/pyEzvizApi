"""Bounded synthetic Android codec/Frida controls; no camera or native app hooks."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

BASE = Path(__file__).resolve().parent
REFERENCE = runpy.run_path(str(BASE.parent / "app_reference_stream.py"))
require = REFERENCE["require"]
CODECS = ("raw", "zlib", "lz4")
PATTERNS = ("mixed-v1", "striped-v1", "noise-v1")


def validate(config: dict[str, Any]) -> None:
    require(os.name == "posix", "synthetic device probe requires POSIX")
    require(config.get("codec") in CODECS and config.get("pattern") in PATTERNS,
            "invalid probe codec/pattern")
    require(type(config.get("size")) is int and 1 <= config["size"] <= 12 * 1024 * 1024
            and type(config.get("count")) is int and 1 <= config["count"] <= 32
            and config["size"] * config["count"] <= 240 * 1024 * 1024, "probe byte/count limit")
    require(type(config.get("timeout")) in {int, float} and math.isfinite(config["timeout"])
            and 5 <= config["timeout"] <= 60, "probe timeout must be finite 5..60 seconds")
    require(isinstance(config.get("endpoint"), str) and 0 < len(config["endpoint"]) <= 256,
            "explicit Gadget endpoint required")


def payload(size: int, pattern: str) -> bytes:
    require(type(size) is int and 1 <= size <= 12 * 1024 * 1024 and pattern in PATTERNS,
            "invalid synthetic payload")
    data = bytearray(size)
    state = 0x12345678
    for index in range(size):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        striped = pattern == "striped-v1" or (pattern == "mixed-v1" and (index >> 12) % 3 == 0)
        data[index] = (index * 17 + (index >> 12)) & 255 if striped else state >> 24
    return bytes(data)


def write_receipt(path: Path, report: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def prefix(capture: Any) -> dict[str, Any]:
    return dict(
        verified_snapshots=sum(r["event"] == "native_pixels" for r in capture.rows),
        observed_acknowledgements=sum(r["event"] == "transport_ack" for r in capture.rows),
        payload_bytes=capture.bytes, binary_bytes=capture.transport_bytes,
        raw_snapshots=sum(r["event"] == "native_pixels" and r.get("encoding", "raw") == "raw"
                          for r in capture.rows),
        host_posts=list(capture.acknowledgements),
        device_round_trips=REFERENCE["PROFILE"]["summarize"](
            [r for r in capture.rows if r["event"] == "transport_ack"]),
    )


def receive(capture: Any, message: dict[str, Any], data: bytes | None,
            config: dict[str, Any], receipt: Path) -> None:
    try:
        if data is not None:
            row = message.get("payload", {})
            require(row.get("event") == "native_pixels" and row.get("synthetic") is True
                    and row.get("pattern") == config["pattern"]
                    and row.get("sha256") == config["sha256"] and row.get("bytes") == config["size"],
                    "synthetic payload identity mismatch")
        capture.message(message, data)
    except Exception as error:
        capture.error = str(error)
    # Atomically preserve bounded prefix evidence even if the watchdog kills the worker.
    try:
        write_receipt(receipt, dict(status="in-progress", error=capture.error, **prefix(capture)))
    except Exception as error:
        capture.error = "checkpoint: " + str(error)


def worker(config: dict[str, Any], folder: Path) -> int:  # noqa: PLR0912 - one owned lifecycle
    validate(config)
    capture = REFERENCE["Capture"](folder)
    session = script = None
    report: dict[str, Any] = dict(status="failed", error=None, device=None)
    deadline = time.monotonic() + config["timeout"] - 2
    try:
        if config["codec"] == "lz4":
            REFERENCE["lz4_decoder"]()
        frida = importlib.import_module("frida")
        report["host_frida_version"] = frida.__version__
        session = frida.get_device_manager().add_remote_device(config["endpoint"]).attach("Gadget")
        source = "\n".join((BASE / name).read_text() for name in (
            "transport-ack.js", "snapshot-codec.js", "device-probe.js"))
        source += "\nrpc.exports=createDeviceProbe(" + json.dumps(config) + ");"
        script = session.create_script(source)
        capture.post = script.post
        script.on("message", lambda m, d: receive(capture, m, d, config, folder / "partial.json"))
        script.load()
        report["runtime"] = script.exports_sync.prepare()
        script.exports_sync.burst()
        while True:
            capture.snapshot()  # surface callback/identity/hash/post failures
            if prefix(capture)["observed_acknowledgements"] == config["count"]:
                break
            require(time.monotonic() < deadline, "probe acknowledgement timeout")
            time.sleep(0.01)
        report["status"] = "ok"
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="cancelled" if isinstance(error, KeyboardInterrupt) else "failed",
                      error=f"{type(error).__name__}: {error}")
    finally:
        cleanup = []
        if script is not None:
            try:
                report["device"] = script.exports_sync.finish()
            except Exception as error:
                cleanup.append("finish: " + str(error))
        for resource, method in ((script, "unload"), (session, "detach"), (capture, "close")):
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception as error:
                    cleanup.append(method + ": " + str(error))
        report.update(prefix(capture), collector_profile=capture.profile.result(), cleanup=cleanup)
        if cleanup or capture.error:
            report.update(status="failed", error=report["error"] or capture.error or str(cleanup))
        if report["status"] == "ok":
            require(report["device"] is not None, "missing device finish summary")
            if (report["verified_snapshots"] != config["count"]
                    or report["device"]["acknowledgements"]["pending_ids"]):
                report.update(status="failed", error="incomplete verified/acknowledged prefix")
        write_receipt(folder / "trial.json", report)
    return 0 if report["status"] == "ok" else 1


def stop_worker(process: Any) -> None:
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            process.wait(timeout=1)
            return
        try:
            process.wait(timeout=1)
            return
        except subprocess.TimeoutExpired:
            pass
    process.wait(timeout=1)


def read_receipt(path: Path) -> dict[str, Any]:
    require(path.stat().st_size <= 1024 * 1024, "probe receipt limit")
    value = json.loads(path.read_text())
    require(isinstance(value, dict), "invalid probe receipt")
    return value


@contextmanager
def supervisor_termination() -> Any:
    # Record rather than raise in the handlers: cancellation during Popen must not
    # interrupt child creation before its process handle can be owned/reaped.
    requested = [False]
    def request_stop(signum: int, frame: Any) -> None:
        requested[0] = True
    previous = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, request_stop)
        yield requested
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def wait_worker(process: Any, timeout: float, requested: list[bool]) -> None:
    deadline = time.monotonic() + timeout
    while True:
        if requested[0]:
            raise KeyboardInterrupt
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("probe worker", timeout)
        try:
            process.wait(timeout=min(0.1, remaining))
            return
        except subprocess.TimeoutExpired:
            pass


def supervised_trial(config: dict[str, Any], folder: Path) -> dict[str, Any]:
    with supervisor_termination() as requested:
        report = supervise_process(config, folder, requested)
        if requested[0] and not report["worker_deadline_exceeded"]:
            report.update(status="cancelled", error="operator cancelled")
        return report


def supervise_process(config: dict[str, Any], folder: Path, requested: list[bool]) -> dict[str, Any]:
    validate(config)
    config_path = folder / "config.json"
    config_path.write_text(json.dumps(config))
    failure = None
    timed_out = cancelled = False
    with (folder / "worker.log").open("w") as log:
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                    "--worker", str(config_path)], stdout=log,
                                   stderr=log, start_new_session=True)
        try:
            wait_worker(process, config["timeout"], requested)
        except subprocess.TimeoutExpired:
            timed_out = True
            failure = "worker deadline exceeded; pending device state unknown without finish summary"
        except KeyboardInterrupt:
            cancelled = True
        except BaseException:
            stop_worker(process)
            raise
        finally:
            stop_worker(process)
    report_path = folder / "trial.json"
    report = read_receipt(report_path) if report_path.exists() else (
        read_receipt(folder / "partial.json") if (folder / "partial.json").exists() else {})
    if not timed_out and (cancelled or report.get("status") == "cancelled"):
        report.update(status="cancelled", error="operator cancelled", worker_exit_code=process.returncode)
    elif failure or process.returncode != 0 or report.get("status") != "ok":
        report.update(status="failed", error=failure or report.get("error") or "worker failed",
                      worker_exit_code=process.returncode)
    report.setdefault("device", None)
    report["raw_fallbacks"] = report.get("raw_snapshots", 0) if config["codec"] != "raw" else 0
    report["worker_deadline_exceeded"] = timed_out
    return report


def probe(config: dict[str, Any], output: Path, repeats: int = 3) -> dict[str, Any]:
    validate(config)
    require(type(repeats) is int and 1 <= repeats <= 3, "probe repeats must be 1..3")
    output.mkdir(mode=0o700)
    report: dict[str, Any] = dict(
        status="failed", error=None, trials=[], configuration=config,
        synthetic=True, android_transport_requested=True, android_transport_measured=False,
        codec_configuration=dict(zlib_level=1, lz4="LZ4_compress_default",
                                 raw_fallback_when_not_smaller=True),
        native_app_hooks=False, camera_opened_by_probe=False, playback_measured=False,
        sustained_realtime_verified=False, physical_av_measured=False,
        note="single synchronous RPC bursts; synthetic bytes are not camera media; "
             "device callback scheduling/Frida queues/network not isolated; "
             "round trips are not one-way delay; buffered flush is not fsync; "
             "trial watchdog includes setup; device burst excludes generation/hash; "
             "cache/thermal/network conditions uncontrolled; rotated order not randomization",
    )
    try:
        identity = hashlib.sha256(payload(config["size"], config["pattern"])).hexdigest()
        for iteration in range(repeats):
            order = CODECS[iteration:] + CODECS[:iteration]
            for codec in order:
                with tempfile.TemporaryDirectory(dir=output, prefix="trial-") as temporary:
                    result = supervised_trial(dict(config, codec=codec, sha256=identity), Path(temporary))
                report["trials"].append(dict(iteration=iteration, codec=codec, **result))
                write_receipt(output / "probe.json", report)
                print(json.dumps(dict(iteration=iteration, codec=codec, status=result["status"],
                                      verified=result.get("verified_snapshots"))), flush=True)
                if result["status"] == "cancelled":
                    raise KeyboardInterrupt
                require(not result["worker_deadline_exceeded"], "stopped after worker deadline")
        report["status"] = "ok" if all(t["status"] == "ok" for t in report["trials"]) else "failed"
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="cancelled" if isinstance(error, KeyboardInterrupt) else "failed",
                      error=f"{type(error).__name__}: {error}")
    finally:
        report["android_transport_measured"] = any(
            trial.get("verified_snapshots", 0) > 0 for trial in report["trials"])
        write_receipt(output / "probe.json", report)
    return report


def main() -> int:
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        path = Path(sys.argv[2])
        return worker(read_receipt(path), path.parent)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="existing caller-owned Gadget forward")
    parser.add_argument("--output", type=Path, required=True, help="new private directory")
    parser.add_argument("--pattern", choices=PATTERNS, default="mixed-v1")
    parser.add_argument("--size", type=int, default=7007040)
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--repeats", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    config = dict(codec="raw", endpoint=args.endpoint, pattern=args.pattern,
                  size=args.size, count=args.count, timeout=args.timeout)
    try:
        validate(config)
    except ValueError as error:
        parser.error(str(error))
    return 0 if probe(config, args.output, args.repeats)["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
