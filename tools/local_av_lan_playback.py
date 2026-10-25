"""Attended, finite direct-LAN dual-lens development command; no account login.

Private configuration stays in a local file. Offline runtime checks and Enter
precede acquisition. Not a production player or a measured device-clock sync.
"""

from __future__ import annotations

import argparse
from contextlib import suppress
import hashlib
import json
import logging
import os
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from typing import Any

import pyezvizapi
from pyezvizapi.hcnetsdk import EzvizCasDeviceInfo, HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import EzvizLocalSdkCredentials

BASE = Path(__file__).parent
CAPTURE = runpy.run_path(str(BASE / "local_av_capture_playback.py"))
RUNTIME = runpy.run_path(str(BASE / "local_av_runtime.py"))
EVIDENCE = runpy.run_path(str(BASE / "local_av_packet_evidence.py"))
MAX_CONFIG = 65536
MAX_RECEIPT = 2 * 1024 * 1024
PROFILES = runpy.run_path(str(Path(__file__).with_name('local_av_lan_profiles.py')))


def selected_profile(args: Any) -> dict[str, Any]:
    return PROFILES['get'](getattr(args, 'capture_profile', PROFILES['DEFAULT']))


LIMITS = dict(duration_seconds=30, max_packets=15000, max_bytes=32 * 1024 * 1024)
OPTIONS = dict(
    diagnostic_tail=2,
    identity_mode="source-sequence",
    decoder_deadline_mode="consumer-excluding",
    pair_limit=900,
    byte_limit=32 * 1024 * 1024,
)


def read_regular(path: Path, limit: int) -> bytes:
    """Open once, reject special files/links and bound reads before parsing."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("requires a bounded regular file")
        raw = source.read(limit + 1)
        if len(raw) != info.st_size:
            raise ValueError("file changed or exceeded its bound")
        return raw


def private_config(path: Path, expected: str | None = None) -> tuple[Any, dict[str, Any], str]:
    """Read the existing credentials.as_dict(include_media_key=True) shape."""
    try:
        raw = read_regular(path, MAX_CONFIG)
        digest = hashlib.sha256(raw).hexdigest()
        if expected is not None and expected != digest:
            raise ValueError("configuration changed")
        cfg = json.loads(raw)
        serial, endpoint, cas, key = cfg["serial"], cfg["endpoint"], cfg["cas"], cfg["media_key"]
        texts = [serial, endpoint["host"], cas["operation_code"], cas["key"], key]
        if any(
            type(value) is not str
            or not value
            or len(value) > 253
            or any(ord(c) < 32 for c in value)
            for value in texts
        ):
            raise ValueError("invalid text")
        ports = [endpoint["command_port"], endpoint["stream_port"]]
        if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise ValueError("invalid port")
        encrypt = cas.get("encrypt_type")
        if encrypt is not None and type(encrypt) is not int:
            raise ValueError("invalid encryption type")
        device = cfg.get("device", {})
        if type(device) is not dict:
            raise ValueError("invalid device metadata")
        credentials = EzvizLocalSdkCredentials(
            HcNetSdkLanEndpoint(
                serial, endpoint["host"], command_port=ports[0], stream_port=ports[1]
            ),
            EzvizCasDeviceInfo(serial, cas["operation_code"], cas["key"], encrypt),
            media_key=key,
        )
        # Validate control credentials before the prompt, without connecting.
        if len(credentials.device_info.key_bytes) != 16:
            raise ValueError("unsupported local control key")
        return credentials, device, digest
    except Exception:
        # Malformed input and downstream validation must not echo a credential.
        raise ValueError("invalid or changed private local configuration") from None


def output_arguments(args: Any, mono: str) -> Any:
    return SimpleNamespace(
        primary_stream=0,
        secondary_stream=1,
        audio_stream=2,
        audio_overlap_policy=args.audio_overlap_policy,
        max_audio_overlap_ms=args.max_audio_overlap_ms,
        max_audio_phase_ms=args.max_audio_phase_ms,
        video_transport="sealed-store",
        container="mpeg",
        deadline=5,
        max_late_ms=250,
        mono_option=mono,
        play=True,
        pairing="exact-pts",
        timing="host-submission",
        layout="side-by-side",
        processor="passthrough",
    )


def capture(args: Any, report: dict[str, Any]) -> None:
    """Worker-owned capture; no account client is constructed or borrowed."""
    profile = selected_profile(args)
    PROFILES['bind'](report, profile['name'])
    credentials, device, digest = private_config(args.private_config, args.config_sha256)
    report.update(
        config_sha256=digest,
        stage="live-acquisition",
        requested_options=dict(profile['options'], startup_pairing=args.startup_pairing),
        capture_limits=dict(profile['limits']),
        source_worker_retained=False,
        caller_cleanup_error_types=[],
    )
    # An object without account methods and offline/no-fallback selection makes
    # missing local metadata an error, never a reason to log in or discover cloud.
    owner: Any = pyezvizapi.AutoMediaStream(
        object(),
        credentials.endpoint.serial,
        pyezvizapi.AutoClipSource(
            mode="offline",
            credentials=credentials,
            device=device,
            allow_cloud_fallback=False,
            timeout=5,
        ),
        channel=0,
    )
    session = evidence = None
    try:
        if getattr(args, "packet_evidence", None) is not None:
            evidence = EVIDENCE["PacketEvidence"](args.packet_evidence,
                **({} if profile['name'] == PROFILES['DEFAULT'] else dict(capture_profile=profile['name'])))
            original = owner.iter_media_packets

            def retain(**kwargs: Any) -> Any:
                return evidence.retain(original(**kwargs))

            owner.iter_media_packets = retain
        session = CAPTURE["CapturePlayback"](
            owner,
            credentials.media_key,
            output_arguments(args, args.mono_option),
            report,
            limits=pyezvizapi.CaptureLimits(**profile['limits']),
            completion="bounded-prefix",
            codec="hevc",
            pes_ids=(0xE0, 0xE1, 0xC0),
            **profile['options'],
            startup_pairing=args.startup_pairing,
        )
        session.play()
    finally:
        if session is not None:
            state = session.pull.result()
            if state["worker_alive"] or not state["consumer_closed"]:
                try:
                    session.close(timeout=5)
                except Exception as error:
                    report["caller_cleanup_error_types"].append(type(error).__name__)
            report["source_pull"] = session.pull.result()
            report["source_worker_retained"] = report["source_pull"]["worker_alive"]
        if not report["source_worker_retained"]:
            try:
                owner.close()
            except Exception as error:
                report["caller_cleanup_error_types"].append(type(error).__name__)
        report["final_owner"] = owner.capture_result
        if evidence is not None:
            report["packet_evidence"] = dict(status="incomplete")
            if not report["source_worker_retained"]:
                try:
                    summary = evidence.finish(
                        dict(
                            package_sha256=args.expected_package_sha256,
                            config_sha256=digest,
                        )
                    )
                    report["packet_evidence"] = dict(status="finalized", summary=summary)
                except Exception as error:
                    report["caller_cleanup_error_types"].append(type(error).__name__)
        if report["source_worker_retained"] or report["caller_cleanup_error_types"]:
            report.update(status="failed", accepted_prefix_clear_sha256=None)
    if report["status"] != "prefix-output-completed":
        raise ValueError("capture cleanup failed")
    report["stage"] = "finished"


def safe_receipt(report: dict[str, Any], args: Any) -> bytes:
    """Never write credentials through nested diagnostics or exception text."""
    raw = json.dumps(report, ensure_ascii=True).encode() + b"\n"
    try:
        credentials, _device, _digest = private_config(
            args.private_config, report.get("config_sha256")
        )
        secrets = [
            credentials.media_key,
            credentials.device_info.operation_code,
            credentials.device_info.key,
        ]
        if any(
            value.encode() in raw or json.dumps(value)[1:-1].encode() in raw for value in secrets
        ):
            raise ValueError("credential in diagnostics")
        if len(raw) > MAX_RECEIPT:
            raise ValueError("receipt bound")
    except Exception:
        raw = (
            json.dumps(
                dict(
                    profile="attended-direct-lan-prefix-v1",
                    status="cancelled" if report.get("status") == "cancelled" else "failed",
                    stage="receipt-validation",
                    error_type="UnsafeOrUnavailableReceipt",
                    diagnostics_omitted=True,
                    physical_av_sync_measured=False,
                )
            ).encode()
            + b"\n"
        )
    return raw


def reap(child: Any) -> None:
    """Finite foreground escalation, not concurrent generator finalization."""
    try:
        if child.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
    finally:
        # A reaped leader does not establish that inherited SDL/ffplay group
        # members have exited. Always kill any remaining group, even on entry
        # with an already-exited worker or after successful TERM handling.
        with suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)


def worker_command(args: Any, digest: str, mono: str, receipt: Path) -> list[str]:
    command = [
        sys.executable,
        "-I",
        str(Path(__file__).resolve()),
        "--worker",
        "--play",
        "--private-config",
        str(args.private_config.resolve()),
        "--receipt",
        str(receipt),
        "--config-sha256",
        digest,
        "--expected-package-sha256",
        args.expected_package_sha256,
        "--mono-option",
        mono,
        "--startup-pairing",
        args.startup_pairing,
        "--audio-overlap-policy",
        args.audio_overlap_policy,
    ]
    for name in ("max_audio_overlap_ms", "max_audio_phase_ms"):
        if getattr(args, name) is not None:
            command.extend(["--" + name.replace("_", "-"), str(getattr(args, name))])
    if getattr(args, "packet_evidence", None) is not None:
        command.extend(["--packet-evidence", str(args.packet_evidence.resolve())])
    profile = selected_profile(args)
    if profile['name'] != PROFILES['DEFAULT']:
        command.extend(['--capture-profile', profile['name']])
    return command


def finish_child(child: Any, receipt: Path, report: dict[str, Any], primary: bool) -> None:
    try:
        reap(child)
    except Exception as error:
        report["child_cleanup_error_type"] = type(error).__name__
        if not primary:
            raise
    finally:
        report["worker_reaped"] = child.poll() is not None
    if report.get("playback") is None and receipt.exists():
        try:
            report["playback"] = json.loads(read_regular(receipt, MAX_RECEIPT))
        except Exception as error:
            report["child_receipt_error_type"] = type(error).__name__


def supervise(args: Any, report: dict[str, Any], digest: str, mono: str) -> None:
    profile = selected_profile(args)
    PROFILES['bind'](report, profile['name'])
    with tempfile.TemporaryDirectory(prefix="local-av-lan-") as temporary:
        receipt = Path(temporary) / "worker.json"
        command = worker_command(args, digest, mono, receipt)
        child = None
        primary = False
        try:
            child = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            code = child.wait(timeout=profile['worker_seconds'])
            report["playback"] = json.loads(read_regular(receipt, MAX_RECEIPT))
            playback = report["playback"]
            if code == 130:
                raise KeyboardInterrupt
            if (code or playback.get('status') != 'prefix-output-completed'
                    or playback.get('capture_profile', PROFILES['DEFAULT']) != profile['name']):
                raise ValueError("live prefix output failed")
            if (
                playback.get("package_sha256") != args.expected_package_sha256
                or playback.get("config_sha256") != digest
                or playback.get("source_worker_retained") is not False
                or playback.get("caller_cleanup_error_types")
                or playback.get("capture_limits") != profile['limits']
                or playback.get("requested_options")
                != dict(profile['options'], startup_pairing=args.startup_pairing)
            ):
                raise ValueError("worker receipt binding failed")
            CAPTURE["verify_output"](playback["preparation"], playback["output"])
            if getattr(args, "packet_evidence", None) is not None:
                summary = EVIDENCE["verify"](args.packet_evidence,
                    **({} if profile['name'] == PROFILES['DEFAULT'] else dict(capture_profile=profile['name'])))
                if (
                    playback.get("packet_evidence") != dict(status="finalized", summary=summary)
                    or summary["packets"] != playback["final_owner"]["packets_yielded"]
                    or summary["bytes"] != playback["final_owner"]["bytes_yielded"]
                    or summary["binding"]
                    != dict(
                        package_sha256=args.expected_package_sha256,
                        config_sha256=digest,
                    )
                ):
                    raise ValueError("packet evidence receipt binding failed")
                report["packet_evidence"] = dict(status="integrity-verified", summary=summary)
        except BaseException:
            primary = True
            raise
        finally:
            if child is not None:
                finish_child(child, receipt, report, primary)
    report.update(status="completed", stage="finished")


def attended(args: Any, report: dict[str, Any]) -> None:
    """Parent validates without IO, prompts once, then owns one bounded worker."""
    profile = selected_profile(args)
    PROFILES['bind'](report, profile['name'])
    CAPTURE["validate_output"](output_arguments(args, "channels"))
    CAPTURE["PREPARE"]["ONLINE"]["Policy"](
        (0, 1),
        2,
        args.audio_overlap_policy,
        args.max_audio_overlap_ms,
        args.max_audio_phase_ms,
        identity_mode="source-sequence",
        pair_limit=profile['options']['pair_limit'],
        span_limit=profile['options'].get('span_limit', 60),
    )
    CAPTURE["PREPARE"]["CHUNKED"]["DECODE"]["validate_startup_pairing"](args.startup_pairing)
    if not args.play:
        raise ValueError("--play is required")
    report["stage"] = "runtime-preflight"
    preflight = RUNTIME["run_worker"](args.expected_package_sha256, 15)
    report["preflight"] = preflight
    if preflight["status"] != "ready-for-offline-control":
        raise ValueError("offline preflight failed")
    report["stage"] = "private-readiness"
    _credentials, _device, digest = private_config(args.private_config)
    report["config_sha256"] = digest
    if getattr(args, "packet_evidence", None) is not None:
        # Claim a fresh directory before Enter; never reuse or overwrite data.
        args.packet_evidence.mkdir(mode=0o700)
    report["stage"] = "operator-readiness"
    print("Offline checks passed. Camera has NOT started.", flush=True)
    print(
        f"LIVE LAN channel 0: up to {profile['limits']['duration_seconds']} seconds / "
        f"{profile['limits']['max_bytes'] // 1048576} MiB / {profile['options']['pair_limit']} pairs. Startup: "
        + args.startup_pairing,
        flush=True,
    )
    input("Press Enter when ready to start LIVE acquisition: ")
    report["stage"] = "live-acquisition"
    supervise(args, report, digest, preflight["pcm"]["mono_option"])


def arguments() -> Any:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-config", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument(
        "--packet-evidence",
        type=Path,
        help="new private directory for bounded encrypted media bodies",
    )
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument('--capture-profile', choices=PROFILES['NAMES'], default=PROFILES['DEFAULT'])
    parser.add_argument("--play", action="store_true")
    parser.add_argument(
        "--startup-pairing", choices=["strict", "common-keyframe"], default="strict"
    )
    parser.add_argument(
        "--audio-overlap-policy", choices=["reject", "bounded-serial-pcm"], default="reject"
    )
    parser.add_argument("--max-audio-overlap-ms", type=int)
    parser.add_argument("--max-audio-phase-ms", type=int)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config-sha256", help=argparse.SUPPRESS)
    parser.add_argument("--mono-option", choices=["channels", "ch-layout"], help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    report: dict[str, Any] = dict(
        profile="attended-direct-lan-prefix-v1",
        status="failed",
        stage="argument-validation",
        error_type=None,
        physical_av_sync_measured=False,
    )
    try:
        fd = os.open(args.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        print("Receipt must be a new writable file.", file=sys.stderr)
        return 2
    previous = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    disabled = logging.root.manager.disable

    def stop(_signal: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.disable(logging.CRITICAL)
    with os.fdopen(fd, "wb") as output:
        try:
            if args.worker:
                if not args.play or not args.config_sha256 or not args.mono_option:
                    raise ValueError("internal worker binding required")
                report["stage"] = "private-readiness"
                actual = RUNTIME["package_fingerprint"](Path(pyezvizapi.__file__).parent)
                if actual != args.expected_package_sha256:
                    raise ValueError("worker package fingerprint changed")
                report["package_sha256"] = actual
                capture(args, report)
            else:
                attended(args, report)
        except (KeyboardInterrupt, EOFError):
            report.update(status="cancelled", error_type="KeyboardInterrupt")
        except Exception as error:
            report.update(status="failed", error_type=type(error).__name__)
        finally:
            signal.signal(signal.SIGTERM, previous)
            signal.signal(signal.SIGINT, previous_int)
            logging.disable(disabled)
        raw = safe_receipt(report, args)
        output.write(raw)
        output.flush()
        safe = json.loads(raw)
        status = safe["status"]
    code = (
        0
        if status in ("completed", "prefix-output-completed")
        else 130
        if status == "cancelled"
        else 2
    )
    print(
        json.dumps(
            dict(status=status, error_type=safe.get("error_type"), physical_av_sync_measured=False)
        ),
        flush=True,
    )
    if args.worker and report.get("source_worker_retained"):
        os._exit(code or 2)  # Durable failed receipt precedes teardown of unjoined native work.
    return code


if __name__ == "__main__":
    raise SystemExit(main())
