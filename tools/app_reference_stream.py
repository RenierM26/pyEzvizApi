"""Bounded verified-build Android reference producer and dummy-host benchmark.

Development only: requires a fresh preview startup after READY, optional Frida,
ADB and the exact supported native build. Never launches UI or changes settings.
"""

from __future__ import annotations

import argparse
import collections
from contextlib import suppress
import hashlib
import importlib
import itertools
import json
import math
import os
from pathlib import Path
import runpy
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import zipfile

BASE = Path(__file__).parent
LIVE = runpy.run_path(str(BASE / "app_live_native_av.py"))
PROJECT = runpy.run_path(str(BASE / "reference_stream/project.py"))
require = PROJECT["require"]
HASHES = {
    "libPlayCtrl.so": "a719ac549516df28345536d7baf1cc22145996949e89f8c7fae2dc73a379cddc",
    "libezstreamclient.so": "184f8eb8ce29a2f4ce5c6a915dd9f5649907f55e410a92c6a3db8b414f665f6b",
}
ELF_MAGIC = b"\x7fELF"
NEWLINE = b"\n"
MIN_SINK_DEADLINE = 0.1
MAX_ROWS = 20_000
MAX_CAPTURE_BYTES = 248 * 1024 * 1024


def verify_profile(profile: dict[str, Any], read_module: Any) -> dict[str, Any]:
    require(
        profile.get("arch") == "arm" and profile.get("pointerSize") == 4,
        "unsupported reference ABI",
    )
    modules = profile.get("modules", [])
    require(
        len(modules) == 2 and {m["name"] for m in modules} == set(HASHES),
        "missing reference modules",
    )
    verified = {}
    for module in modules:
        data = read_module(module["path"])
        digest = hashlib.sha256(data).hexdigest()
        require(
            data[:4] == ELF_MAGIC and digest == HASHES[module["name"]],
            "unsupported reference ELF: " + module["name"],
        )
        verified[module["name"]] = digest
    return dict(arch="arm", pointer_size=4, elf_sha256=verified, provenance_authenticated=False)


def device_module(device: str, path: str, cache: dict[str, bytes]) -> bytes:
    # Module paths are discovered from the attached process, not guessed by version.
    require(path.startswith("/data/app/") and "!/" in path, "requires APK-mapped native module")
    apk, member = path.split("!/", 1)
    require(member in {"lib/armeabi-v7a/" + name for name in HASHES}, "unsupported APK member")
    if apk not in cache:
        info = subprocess.run(
            ["adb", "-s", device, "shell", "stat -c %s " + shlex.quote(apk)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        apk_size = int(info.stdout.strip())
        require(0 < apk_size <= 256 * 1024 * 1024, "APK size limit")
        with tempfile.TemporaryDirectory() as folder:
            local = Path(folder) / "split.apk"
            subprocess.run(
                ["adb", "-s", device, "pull", apk, str(local)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
            )
            require(local.stat().st_size == apk_size, "APK size changed during verification")
            # Retain only the two bounded ELF members, not an entire APK in memory.
            with zipfile.ZipFile(local) as archive:
                for name in HASHES:
                    member_info = archive.getinfo("lib/armeabi-v7a/" + name)
                    require(member_info.file_size <= 32 * 1024 * 1024, "ELF size limit")
                    cache[apk + "!/" + member_info.filename] = archive.read(member_info)
        cache[apk] = b""
    return cache[path]


class Capture:
    """Callback owner: flush blobs before publishing metadata; keep bounded private evidence."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.log = (root / "events.jsonl").open("x")
        self.files: dict[str, Any] = {}
        self.rows: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.error: str | None = None
        self.bytes = 0
        self.ready = threading.Event()

    def message(self, message: dict[str, Any], data: bytes | None) -> None:
        with self.lock:
            if self.error:
                return
            try:
                require(
                    message.get("type") == "send",
                    "Frida error: " + str(message.get("description", message)),
                )
                value = message["payload"]
                rows = value.get("batch", [value])
                require(
                    isinstance(rows, list) and len(self.rows) + len(rows) <= MAX_ROWS,
                    "capture metadata limit",
                )
                require(
                    all(
                        isinstance(row, dict) and type(row.get("device_mono_ns")) is int
                        for row in rows
                    ),
                    "invalid collector row",
                )
                if data is not None:
                    require(
                        len(rows) == 1
                        and value["event"]
                        in {
                            "native_pixels",
                            "native_render_pixels",
                            "audio_decoded",
                            "audio_vqe_input",
                            "audio_vqe_output",
                        },
                        "unexpected binary event",
                    )
                    require(self.bytes + len(data) <= MAX_CAPTURE_BYTES, "capture binary limit")
                    require(
                        len(data) == value["bytes"]
                        and hashlib.sha256(data).hexdigest() == value["sha256"],
                        "collector payload mismatch",
                    )
                    name = value["event"] + ".bin"
                    if name not in self.files:
                        self.files[name] = (self.root / name).open("xb")
                    output = self.files[name]
                    value.update(file=name, offset=output.tell())
                    output.write(data)
                    output.flush()
                    self.bytes += len(data)
                observed = time.monotonic_ns()
                for row in rows:
                    require(row.get("event") != "error", "native hook error: " + str(row))
                    row["collector_received_ns"] = observed
                    self.log.write(json.dumps(row) + "\n")
                    if row.get("event") == "ready":
                        self.ready.set()
                self.log.flush()
                self.rows.extend(rows)
            except Exception as error:
                self.error = str(error)

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            require(self.error is None, str(self.error))
            return sorted(self.rows, key=lambda row: row["device_mono_ns"])

    def close(self) -> None:
        with self.lock:
            for output in self.files.values():
                output.close()
            self.log.close()


class Host:
    """Nonblocking binary input and progress, with an explicit bounded write deadline."""

    def __init__(self, root: Path, deadline: float = 5) -> None:
        self.deadline = deadline
        self.process: Any = None
        self.stdin: Any = None
        self.stdout: Any = None
        self.errors: Any = None
        self.log: Any = None
        self.wire: Any = None
        try:
            self.errors = (root / "host-stderr.log").open("x")
            self.log = (root / "host-progress.jsonl").open("x")
            self.wire = (root / "live-source.bin").open("xb")
            self.progress: list[dict[str, Any]] = []
            self.pending = bytearray()
            self.writes: list[dict[str, Any]] = []
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    str(BASE / "app_live_native_av.py"),
                    "--play",
                    "--audio",
                    "observed-native-vqe",
                    "--clock",
                    "reference-native-events",
                    "--eof",
                    "retain",
                    "--progress",
                    "--deadline",
                    str(deadline),
                    "--receipt",
                    str(root / "live-receipt.json"),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.errors,
                bufsize=0,
                start_new_session=True,
                env=dict(os.environ, SDL_VIDEODRIVER="dummy", SDL_AUDIODRIVER="dummy"),
            )
            assert (
                self.process.stdin is not None and self.process.stdout is not None
            )  # PIPE guarantees
            self.stdin = self.process.stdin
            self.stdout = self.process.stdout
            os.set_blocking(self.stdin.fileno(), False)
            os.set_blocking(self.stdout.fileno(), False)
            self.eof = False
        except BaseException:
            self.close()
            raise

    def drain(self) -> None:
        while select.select([self.stdout], [], [], 0)[0]:
            chunk = os.read(self.stdout.fileno(), 65536)
            if not chunk:
                break
            self.pending.extend(chunk)
            while NEWLINE in self.pending:
                line, _, rest = self.pending.partition(b"\n")
                require(len(line) <= 65536, "host progress line limit")
                self.pending = bytearray(rest)
                require(len(self.progress) < 10_000, "host progress event limit")
                row = json.loads(line)
                self.progress.append(row)
                self.log.write(line.decode() + "\n")
                self.log.flush()
            require(len(self.pending) <= 65536, "host progress line limit")

    def send(
        self, row: dict[str, Any], payload: bytes = b"", observed_ns: int | None = None
    ) -> None:
        data = LIVE["encode"](row, payload)
        self.wire.write(data)
        self.wire.flush()
        started = time.monotonic_ns()
        at = 0
        until = time.monotonic() + 10
        while at < len(data):
            self.drain()
            require(self.process.poll() is None, "host exited during source write")
            require(time.monotonic() < until, "source write deadline")
            try:
                at += os.write(self.stdin.fileno(), memoryview(data)[at:])
            except BlockingIOError:
                select.select([], [self.stdin], [], 0.005)
        self.writes.append(
            dict(
                kind=row["kind"],
                bytes=len(data),
                started_ns=started,
                completed_ns=time.monotonic_ns(),
                collector_received_ns=observed_ns,
            )
        )

    def finish(self) -> None:
        self.stdin.close()
        self.eof = True
        until = time.monotonic() + 2 * self.deadline + 3
        while self.process.poll() is None:
            self.drain()
            require(time.monotonic() < until, "host shutdown deadline")
            time.sleep(0.005)
        self.drain()
        require(self.process.returncode == 0, "host failed; see private stderr/receipt")

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        # The child owns a new process session; force cleanup of any surviving
        # SDL/ffplay grandchildren if its normal cancellation path failed.
        if self.process is not None:
            with suppress(ProcessLookupError):
                os.killpg(self.process.pid, signal.SIGKILL)
        errors = []
        for handle in (self.stdin, self.stdout, self.errors, self.log, self.wire):
            try:
                if handle is not None:
                    handle.close()
            except Exception as failure:
                errors.append(str(failure))
        require(not errors, "host file cleanup failed: " + "; ".join(errors))


class Producer:
    def __init__(self, root: Path, host: Any, pairs: int) -> None:
        self.root, self.host, self.pairs = root, host, pairs
        self.sent: list[dict[str, Any]] = []
        self.sampled: set[tuple[int, int, int]] = set()
        self.used: set[int] = set()
        self.processed: set[int] = set()
        self.cutoff = 0

    def audio(self, rows: list[dict[str, Any]]) -> None:
        decoded = [r for r in rows if r.get("event") == "audio_decoded"]
        inputs = {r["call"]: r for r in rows if r.get("event") == "audio_vqe_input"}
        for output in [r for r in rows if r.get("event") == "audio_vqe_output"]:
            if output["call"] in self.processed or output["call"] not in inputs:
                continue
            source = inputs[output["call"]]
            candidates = [
                r
                for r in decoded
                if r["device_mono_ns"] <= source["device_mono_ns"]
                and r["sha256"] == source["sha256"]
                and r["id"] not in self.used
            ]
            if len(candidates) != 1:
                continue  # ambiguous correspondence is retained, never guessed
            block = candidates[0]
            require(block["rate"] == 16000 and output["status"] == 0, "unsupported native audio")
            row = dict(
                kind="native_vqe",
                id=f"vqe:{output['call']}",
                input_media_ms=block["media_ms"],
                status=0,
                sample_rate=16000,
                channels=1,
                samples=1024,
                format="s16le",
                decoded_sha256=block["sha256"],
                input_sha256=source["sha256"],
                output_sha256=output["sha256"],
                source_input_ns=source["device_mono_ns"],
                source_output_ns=output["device_mono_ns"],
            )
            data = b"".join(PROJECT["blob"](self.root, r) for r in (block, source, output))
            self.host.send(row, data, output.get("collector_received_ns"))
            self.used.add(block["id"])
            self.processed.add(output["call"])

    def pump(self, rows: list[dict[str, Any]]) -> None:
        self.audio(rows)  # ready audio gets a turn before each large paired snapshot
        children: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
        for row in rows:
            if row.get("schedule") is not None:
                children[row["schedule"]].append(row)
        completed = []
        for values in children.values():
            counts = [r for r in values if r["event"] == "node_count"]
            if len(counts) >= 2 and any(r["event"] == "render_callback" for r in values):
                completed.append(counts[-1]["device_mono_ns"])
        completed.sort()
        for index, cut in enumerate(completed[: self.pairs]):
            if cut <= self.cutoff:
                continue
            renders = [
                r
                for r in rows
                if r.get("event") == "native_render_pixels" and r["device_mono_ns"] <= cut
            ]
            if len(renders) != 2 * (index + 1):
                break  # incomplete transfer: wait, do not skip its selected frame
            for render in renders:
                key = (render["sid"], render["raw"], render["frame"])
                if key not in self.sampled:
                    manifest, data = PROJECT["manifest"](self.root, rows, render)
                    self.host.send(
                        dict(kind="sample", manifest=manifest),
                        data,
                        render.get("collector_received_ns"),
                    )
                    self.sampled.add(key)
            prefix = PROJECT["project"](rows, cut)
            require(
                prefix[: len(self.sent)] == self.sent, "source projection rewrote emitted prefix"
            )
            for event in prefix[len(self.sent) :]:
                self.host.send(dict(kind="event", event=event))
            self.sent = prefix
            self.cutoff = cut
            break  # allow ingestion/audio/progress between pairs


def intervals(values: list[int]) -> dict[str, Any]:
    gaps = [(b - a) / 1_000_000 for a, b in itertools.pairwise(values)]
    return dict(
        count=len(values),
        span_ms=(values[-1] - values[0]) / 1_000_000 if len(values) > 1 else 0,
        interval_ms=gaps,
        max_interval_ms=max(gaps, default=None),
    )


def metrics(
    rows: list[dict[str, Any]], host: Any, receipt: dict[str, Any], target: float
) -> dict[str, Any]:
    acks = [r for r in receipt.get("actions", []) if "host_completed_ns" in r]
    eof = receipt.get("source_eof_monotonic_ns")
    audio = receipt.get("audio", {})
    callbacks = [r["device_mono_ns"] for r in rows if r.get("event") == "render_callback"]
    video = [r["host_completed_ns"] for r in acks if r["kind"] == "host_video_acknowledged"]
    sound = [r["host_completed_ns"] for r in acks if r["kind"] == "host_audio_pipe_written"]
    delayed = [
        (r["completed_ns"] - r["collector_received_ns"]) / 1e6
        for r in host.writes
        if r["collector_received_ns"] is not None
    ]
    depth, peak = 0, 0
    for action in audio.get("actions", []):
        if action["kind"] == "audio_admitted":
            depth += 1
        elif action["kind"] == "audio_pipe_write_completed":
            depth -= 1
        peak = max(peak, depth)
    span = (video[-1] - video[0]) / 1e9 if len(video) > 1 else 0
    selections = {}
    for action in receipt.get("actions", []):
        if action["kind"] == "host_video_requested":
            pair = action["selection"]
            selections[pair["pair_id"]] = pair
    for pair in receipt.get("video_waiting", []):
        selections[pair["pair_id"]] = pair
    queue_points = [(int(pair["host_wait_started"] * 1e9), 1) for pair in selections.values()]
    queue_points += [
        (action["host_completed_ns"], -1)
        for action in acks
        if action["kind"] == "host_video_acknowledged"
    ]
    outstanding = peak_video = 0
    for _, delta in sorted(queue_points):
        outstanding += delta
        peak_video = max(peak_video, outstanding)
    return dict(
        host_video_peak_pending_including_active=peak_video,
        source_scope="contiguous validated prefix; later observed metadata is not forwarded",
        native_render_cadence=intervals(callbacks),
        host_video_cadence=intervals(video),
        host_audio_write_cadence=intervals(sound),
        host_video_span_seconds=span,
        requested_observation_seconds=target,
        requested_host_video_span_reached=span >= target,
        # A span alone does not prove stable cadence, low delay or no loss.
        sustained_realtime_verified=False,
        physical_av_measured=False,
        host_audio_peak_pending_including_active=peak,
        host_audio_rejected=audio.get("rejected"),
        host_audio_retained=len(audio.get("ring_pending", [])),
        host_audio_partial_bytes=audio.get("partial_pipe_bytes"),
        video_before_eof=sum(
            r["kind"] == "host_video_acknowledged"
            and eof is not None
            and r["host_completed_ns"] < eof
            for r in acks
        ),
        audio_before_eof=sum(
            r["kind"] == "host_audio_pipe_written"
            and eof is not None
            and r["host_completed_ns"] < eof
            for r in acks
        ),
        collector_callback_to_write_complete_ms=delayed,
        source_write_ms=[(r["completed_ns"] - r["started_ns"]) / 1e6 for r in host.writes],
        cross_device_transport_delay_ms=None,
        clock_note="device and host clocks are not synchronized",
    )


def observation_report(
    rows: list[dict[str, Any]],
    host: Any,
    producer: Any,
    receipt: dict[str, Any],
    seconds: float,
    summary: dict[str, Any],
) -> dict[str, Any]:
    report = metrics(rows, host, receipt, seconds)
    report.update(
        source_events=len(producer.sent),
        verified_samples=len(producer.sampled),
        native_vqe_records=len(producer.processed),
        collector_summary=summary,
        observed_audio_decoded=sum(r["event"] == "audio_decoded" for r in rows),
        observed_vqe_outputs=sum(r["event"] == "audio_vqe_output" for r in rows),
        unforwarded_vqe_outputs=sum(r["event"] == "audio_vqe_output" for r in rows)
        - len(producer.processed),
        captured_pairs_not_forwarded=(
            summary["capturedPairs"] - len(producer.sampled) // 2
            if "capturedPairs" in summary
            else None
        ),
    )
    return report


class Window:
    """Separate bounded preview startup from the requested media observation window."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.ready_ns = time.monotonic_ns()
        self.started_ns: int | None = None

    def stop_reason(self, rows: list[dict[str, Any]], now_ns: int) -> str | None:
        if self.started_ns is None:
            pictures = [
                r["collector_received_ns"]
                for r in rows
                if r.get("event") == "decoded_picture" and not r["payload_is_null"]
            ]
            if pictures:
                self.started_ns = min(pictures)
            elif now_ns - self.ready_ns >= 15 * 1e9:
                return "startup-timeout"
        if self.started_ns is not None and now_ns - self.started_ns >= self.seconds * 1e9:
            return "duration-limit"
        return None


def main() -> int:  # noqa: PLR0912, PLR0915 - one explicit bounded resource lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attach", action="store_true", required=True)
    parser.add_argument("--dummy-host", action="store_true", required=True)
    parser.add_argument("--device", required=True, help="ADB serial; forwarding is caller-owned")
    parser.add_argument(
        "--frida-endpoint", required=True, help="explicit forwarded Gadget endpoint"
    )
    parser.add_argument("--output", type=Path, required=True, help="new private capture directory")
    parser.add_argument("--seconds", type=float, default=20)
    parser.add_argument("--pairs", type=int, default=8)
    parser.add_argument("--sink-deadline", type=float, default=5)
    args = parser.parse_args()
    if (
        os.name != "posix"
        or not math.isfinite(args.seconds)
        or not 1 <= args.seconds <= 35
        or not 1 <= args.pairs <= 8
        or not math.isfinite(args.sink_deadline)
        or not MIN_SINK_DEADLINE <= args.sink_deadline <= 10
    ):
        parser.error(
            "requires POSIX, 1..35 seconds, 1..8 pairs and finite sink deadline 0.1..10 seconds"
        )
    # Secure-screen state is observed, never bypassed. UI startup remains manual.
    try:
        result = subprocess.run(
            ["adb", "-s", args.device, "shell", "dumpsys", "window", "policy"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        require("mIsShowing=false" in result.stdout, "unlock tablet manually before attaching")
    except (ValueError, subprocess.SubprocessError) as failure:
        print(str(failure), file=sys.stderr)
        return 2
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    session = probe = script = capture = host = producer = None
    summary: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    status, error, reason = "failed", None, "failure"
    profile: dict[str, Any] = {}
    report: dict[str, Any] = {}
    try:
        frida = importlib.import_module("frida")  # optional research dependency

        session = frida.get_device_manager().add_remote_device(args.frida_endpoint).attach("Gadget")
        probe = session.create_script(
            "rpc.exports={profile(){return {arch:Process.arch,pointerSize:Process.pointerSize,modules:['libPlayCtrl.so','libezstreamclient.so'].map(n=>{let m=Process.getModuleByName(n);return {name:n,path:m.path};})};}};"
        )
        probe.load()
        cache: dict[str, bytes] = {}
        profile = verify_profile(
            probe.exports_sync.profile(), lambda path: device_module(args.device, path, cache)
        )
        probe.unload()
        probe = None
        capture = Capture(args.output)
        host = Host(args.output, args.sink_deadline)
        producer = Producer(args.output, host, args.pairs)
        source = (
            "const REFERENCE_CONFIG=" + json.dumps(dict(verified=True, pairs=args.pairs)) + ";\n"
        )
        source += (BASE / "reference_stream/h9c-armv7.js").read_text()
        script = session.create_script(source)
        script.on("message", capture.message)
        script.load()
        require(capture.ready.wait(3), "collector did not become ready")
        print(
            "READY: open a fresh camera preview now; no UI/settings are changed by this tool.",
            flush=True,
        )
        window = Window(args.seconds)
        while True:
            host.drain()
            rows = capture.snapshot()
            stopped = window.stop_reason(rows, time.monotonic_ns())
            if stopped is not None:
                reason = stopped
                break
            producer.pump(rows)
            require(host.process.poll() is None, "host exited before source EOF")
            if sum(r["kind"] == "host_video_acknowledged" for r in host.progress) >= args.pairs:
                reason = "paired-frame-limit"
                break
            time.sleep(0.01)
        # Freeze source before final prefix. Do not drain unseen native selections.
        summary = script.exports_sync.finish()
        script.unload()
        script = None
        rows = capture.snapshot()
        host.finish()
        receipt = json.loads((args.output / "live-receipt.json").read_text())
        report = observation_report(rows, host, producer, receipt, args.seconds, summary)
        require(
            report["video_before_eof"] > 0 and report["audio_before_eof"] > 0,
            "no joint live output before EOF",
        )
        status = "bounded-software-observation-completed"
    except (Exception, KeyboardInterrupt) as failure:
        error = f"{type(failure).__name__}: {failure}"
        if isinstance(failure, KeyboardInterrupt):
            status = "cancelled"
    finally:
        cleanup = []
        for item, method in (
            (script, "unload"),
            (probe, "unload"),
            (session, "detach"),
            (host, "close"),
            (capture, "close"),
        ):
            if item is not None:
                try:
                    getattr(item, method)()
                except Exception as failure:
                    cleanup.append(str(failure))
        # A failed shutdown must not erase earlier acknowledgements or coverage.
        if (
            host is not None
            and producer is not None
            and (args.output / "live-receipt.json").exists()
        ):
            try:
                receipt = json.loads((args.output / "live-receipt.json").read_text())
                report = observation_report(rows, host, producer, receipt, args.seconds, summary)
                report["host_status"] = receipt["status"]
                report["host_error"] = receipt["error"]
            except Exception as failure:
                cleanup.append("measurement receipt: " + str(failure))
        if cleanup:
            status = "failed"
            error = f"{error}; cleanup: {cleanup}"
        with (args.output / "benchmark.json").open("x") as output:
            json.dump(
                dict(
                    status=status,
                    error=error,
                    stop_reason=reason,
                    profile=profile,
                    startup_timeout_seconds=15,
                    observation_origin="first decoded-picture callback on host clock",
                    sink_deadline_seconds=args.sink_deadline,
                    dummy_host=True,
                    reference_app_required=True,
                    **report,
                ),
                output,
                indent=2,
            )
            output.write("\n")
    print(
        json.dumps(
            dict(
                status=status,
                error=error,
                stop_reason=reason,
                video_before_eof=report.get("video_before_eof"),
                audio_before_eof=report.get("audio_before_eof"),
                sustained_realtime_verified=False,
            )
        ),
        flush=True,
    )
    return 0 if status == "bounded-software-observation-completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
