"""Attended local-only command boundaries; public synthetic credentials, no camera."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / "tools/local_av_lan_playback.py"))
G = M["main"].__globals__


@pytest.fixture
def config(tmp_path):
    data = dict(
        serial="123456789",
        endpoint=dict(host="192.0.2.1", command_port=8000, stream_port=8000),
        cas=dict(operation_code="ABCDEFG", key="0123456789abcdef"),
        media_key="public-test-key",
        device={},
    )
    path = tmp_path / "local.json"
    path.write_text(json.dumps(data))
    return path


def args(config, **changes):
    values = dict(
        private_config=config,
        receipt=config.with_name("receipt.json"),
        expected_package_sha256="a" * 64,
        play=True,
        startup_pairing="strict",
        audio_overlap_policy="reject",
        max_audio_overlap_ms=None,
        max_audio_phase_ms=None,
        worker=False,
        config_sha256=None,
        mono_option=None,
    )
    values.update(changes)
    return SimpleNamespace(**values)


def test_private_file_is_read_without_network_or_mutation(config):
    original = config.read_bytes()
    credential, device, digest = M["private_config"](config)
    assert credential.media_key == "public-test-key" and device == {}
    assert digest == hashlib.sha256(original).hexdigest() and config.read_bytes() == original
    with pytest.raises(ValueError, match="private local configuration"):
        M["private_config"](config, "0" * 64)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "json",
        "text",
        "port",
        "bool-port",
        "key",
        "encrypt",
        "device",
        "large",
        "directory",
        "symlink",
        "fifo",
    ],
)
def test_invalid_private_config_is_bounded_and_never_echoes_values(config, tmp_path, change):
    data = json.loads(config.read_text())
    if change == "missing":
        config.unlink()
    elif change == "json":
        config.write_text("public-test-key not JSON")
    elif change in ("large", "directory", "symlink", "fifo"):
        if change == "large":
            config.write_bytes(bytes(65537))
        else:
            config.unlink()
            if change == "directory":
                config.mkdir()
            elif change == "symlink":
                target = tmp_path / "target"
                target.write_text(json.dumps(data))
                config.symlink_to(target)
            else:
                os.mkfifo(config)
    else:
        path, value = {
            "text": (("media_key",), True),
            "port": (("endpoint", "stream_port"), 65536),
            "bool-port": (("endpoint", "command_port"), True),
            "key": (("cas", "key"), "bad-key-secret"),
            "encrypt": (("cas", "encrypt_type"), True),
            "device": (("device",), []),
        }[change]
        target = data
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = value
        config.write_text(json.dumps(data))
    with pytest.raises(ValueError) as error:
        M["private_config"](config)
    assert str(error.value) == "invalid or changed private local configuration"


def preflight(monkeypatch, *, ready=True):
    calls: list[Any] = []

    def check(expected, timeout):
        calls.append((expected, timeout))
        return dict(
            status="ready-for-offline-control" if ready else "failed",
            pcm=dict(mono_option="ch-layout"),
        )

    monkeypatch.setitem(M["RUNTIME"], "run_worker", check)
    return calls


@pytest.mark.parametrize("case", ["no-play", "audio", "startup", "preflight", "private", "cancel"])
def test_checks_and_cancel_happen_before_any_capture(config, monkeypatch, case):
    options = args(config)
    if case == "no-play":
        options.play = False
    if case == "audio":
        options.audio_overlap_policy = "unknown"
    if case == "startup":
        options.startup_pairing = "nearest"
    if case == "private":
        options.private_config = config.with_name("absent")
    calls = preflight(monkeypatch, ready=case != "preflight")

    def prompt(_text):
        assert case == "cancel"
        raise EOFError

    monkeypatch.setattr("builtins.input", prompt)

    def forbidden(*_a, **_kw):
        pytest.fail("acquisition before successful attended readiness")

    monkeypatch.setattr(M["subprocess"], "Popen", forbidden)
    monkeypatch.setitem(G, "arguments", lambda: options)
    result = M["main"]()
    assert result == (130 if case == "cancel" else 2)
    receipt = json.loads(options.receipt.read_text())
    assert receipt["status"] == ("cancelled" if case == "cancel" else "failed")
    assert "playback" not in receipt and config.exists()
    assert bool(calls) == (case not in ("no-play", "audio", "startup"))


def test_existing_receipt_is_preserved_before_preflight_or_prompt(config, monkeypatch):
    options = args(config)
    options.receipt.write_text("existing")
    monkeypatch.setitem(G, "arguments", lambda: options)
    monkeypatch.setitem(G, "attended", lambda *_a: pytest.fail("existing receipt claimed"))
    assert M["main"]() == 2 and options.receipt.read_text() == "existing"


@pytest.mark.parametrize(
    "case", ["good", "config", "package", "limits", "options", "retained", "exit"]
)
def test_attended_parent_binds_child_after_prompt_and_reaps(config, monkeypatch, case):
    options = args(config, startup_pairing="common-keyframe")
    preflight(monkeypatch)
    prompted = []
    monkeypatch.setattr("builtins.input", lambda _text: prompted.append(True))
    verified = []
    monkeypatch.setitem(
        M["CAPTURE"], "verify_output", lambda prep, out: verified.append((prep, out))
    )

    class Child:
        def __init__(self, command, **kwargs):
            assert (
                prompted and kwargs["stdin"] == subprocess.DEVNULL and kwargs["start_new_session"]
            )
            assert "public-test-key" not in repr(command) and "0123456789abcdef" not in repr(
                command
            )
            assert (
                "--worker" in command and command[command.index("--mono-option") + 1] == "ch-layout"
            )
            dest = Path(command[command.index("--receipt") + 1])
            dest.write_text(
                json.dumps(
                    dict(
                        package_sha256="a" * 64,
                        status="prefix-output-completed",
                        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
                        requested_options=dict(M["OPTIONS"], startup_pairing="common-keyframe"),
                        capture_limits=M["LIMITS"],
                        source_worker_retained=False,
                        caller_cleanup_error_types=[],
                        preparation={},
                        output={},
                    )
                )
            )

            data = json.loads(dest.read_text())
            if case not in ("good", "exit"):
                field, value = {
                    "config": ("config_sha256", "0" * 64),
                    "package": ("package_sha256", "0" * 64),
                    "limits": ("capture_limits", {}),
                    "options": ("requested_options", {}),
                    "retained": ("source_worker_retained", True),
                }[case]
                data[field] = value
                dest.write_text(json.dumps(data))

        def wait(self, timeout):
            assert timeout == 70
            return 2 if case == "exit" else 0

        def poll(self):
            return 0

    monkeypatch.setattr(M["subprocess"], "Popen", Child)
    monkeypatch.setitem(G, "reap", lambda _child: None)
    report: dict[str, Any] = {}
    if case == "good":
        M["attended"](options, report)
        assert report["status"] == "completed" and verified
    else:
        with pytest.raises(ValueError):
            M["attended"](options, report)
        assert not verified
    assert report["worker_reaped"]
    assert config.exists()


@pytest.mark.parametrize("case", ["timeout", "cancel"])
def test_active_parent_interruption_reaps_child_without_success(config, monkeypatch, case):
    preflight(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _text: None)
    reaped: list[Any] = []

    class Child:
        def __init__(self, *_a, **_kw):
            pass

        def wait(self, timeout):
            if case == "cancel":
                raise KeyboardInterrupt
            raise subprocess.TimeoutExpired("worker", timeout)

        def poll(self):
            return 2 if reaped else None

    monkeypatch.setattr(M["subprocess"], "Popen", Child)
    monkeypatch.setitem(G, "reap", lambda _child: None)
    monkeypatch.setitem(G, "reap", reaped.append)
    monkeypatch.setitem(G, "arguments", lambda: args(config))
    assert M["main"]() == (130 if case == "cancel" else 2)
    report = json.loads(config.with_name("receipt.json").read_text())
    assert reaped and report["worker_reaped"] and report["status"] != "completed"


@pytest.mark.parametrize("case", ["secret", "escaped-secret", "oversize", "changed", "missing"])
def test_nested_diagnostics_never_write_credentials_or_claim_unsafe_success(config, case):
    options = args(config)
    report = dict(status="completed", config_sha256=hashlib.sha256(config.read_bytes()).hexdigest())
    if case == "secret":
        report["diagnostic"] = "public-test-key"
    elif case == "escaped-secret":
        report["diagnostic"] = json.dumps("public-test-key")
    elif case == "oversize":
        report["diagnostic"] = "a" * (2 * 1024 * 1024)
    elif case == "changed":
        config.write_text(config.read_text().replace("public-test-key", "another-key"))
    else:
        config.unlink()
    raw = M["safe_receipt"](report, options)
    result = json.loads(raw)
    public_key = b"public-test-key"
    assert public_key not in raw and result["status"] == "failed" and result["diagnostics_omitted"]


@pytest.mark.parametrize("blocked", [False, True])
def test_foreground_reaping_escalates_only_after_grace(monkeypatch, blocked):
    calls: list[Any] = []

    class Child:
        pid = 123

        def poll(self):
            return None

        def wait(self, timeout):
            calls.append(("wait", timeout))
            if blocked and timeout == 10:
                raise subprocess.TimeoutExpired("worker", timeout)

    monkeypatch.setattr(M["os"], "killpg", lambda pid, sig: calls.append((pid, sig)))
    M["reap"](Child())
    assert calls[:2] == [(123, signal.SIGTERM), ("wait", 10)]
    assert calls[2:] == (
        [(123, signal.SIGKILL), ("wait", 3), (123, signal.SIGKILL)]
        if blocked
        else [(123, signal.SIGKILL)]
    )


@pytest.mark.parametrize("case", ["success", "constructor", "playback", "close", "unjoined"])
def test_worker_uses_local_only_source_and_preserves_ownership_until_join(
    config, monkeypatch, case
):
    options = args(
        config,
        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        mono_option="channels",
    )
    calls: list[Any] = []

    class Owner:
        def __init__(self):
            self.capture_result = dict(owner_closed=False)

        def close(self):
            calls.append("owner-close")
            if case == "close":
                raise OSError("cleanup")
            self.capture_result = dict(owner_closed=True)

    owner = Owner()

    def make(client, serial, source, channel):
        assert type(client) is object and serial == "123456789" and channel == 0
        assert source.mode == "offline" and source.allow_cloud_fallback is False
        assert source.credentials.media_key == "public-test-key"
        return owner

    monkeypatch.setattr(M["pyezvizapi"], "AutoMediaStream", make)

    class Session:
        def __init__(self, actual, key, output, report, **kwargs):
            assert actual is owner and key == "public-test-key"
            assert kwargs["pes_ids"] == (224, 225, 192) and kwargs["completion"] == "bounded-prefix"
            assert kwargs["limits"].duration_seconds == 30 and kwargs["diagnostic_tail"] == 2
            if case == "constructor":
                raise ValueError("constructor")
            self.pull = SimpleNamespace(
                result=lambda: dict(worker_alive=case == "unjoined", consumer_closed=True)
            )
            self.report = report

        def play(self):
            calls.append("play")
            if case in ("playback", "unjoined"):
                raise ValueError("primary-playback")
            self.report["status"] = "prefix-output-completed"

        def close(self, timeout):
            calls.append(("join", timeout))
            raise TimeoutError("still executing")

    monkeypatch.setitem(M["CAPTURE"], "CapturePlayback", Session)
    report: dict[str, Any] = {}
    if case == "success":
        M["capture"](options, report)
        assert report["status"] == "prefix-output-completed"
    else:
        with pytest.raises(ValueError):
            M["capture"](options, report)
    if case == "unjoined":
        assert report["source_worker_retained"] and "owner-close" not in calls
        assert report["caller_cleanup_error_types"] == ["TimeoutError"]
    else:
        assert "owner-close" in calls and not report["source_worker_retained"]
    if case == "close":
        assert report["status"] == "failed" and report["accepted_prefix_clear_sha256"] is None


def test_internal_unjoined_worker_writes_failed_receipt_before_hard_exit(config, monkeypatch):
    options = args(
        config,
        worker=True,
        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        mono_option="channels",
    )
    monkeypatch.setitem(G, "arguments", lambda: options)

    def unjoined(_args, report):
        report.update(status="failed", source_worker_retained=True)
        raise TimeoutError

    monkeypatch.setitem(G, "capture", unjoined)
    monkeypatch.setitem(M["RUNTIME"], "package_fingerprint", lambda _root: "a" * 64)
    exited = []

    def exit_after_receipt(code):
        assert json.loads(options.receipt.read_text())["source_worker_retained"]
        exited.append(code)

    monkeypatch.setattr(M["os"], "_exit", exit_after_receipt)
    assert M["main"]() == 2 and exited == [2]


def test_cleanup_failure_preserves_the_primary_parent_cancellation(config, monkeypatch):
    preflight(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _text: None)

    class Child:
        def __init__(self, *_a, **_kw):
            pass

        def wait(self, timeout):
            raise KeyboardInterrupt

        def poll(self):
            return None

    monkeypatch.setattr(M["subprocess"], "Popen", Child)

    def fail(_child):
        raise OSError("secondary reap")

    monkeypatch.setitem(G, "reap", fail)
    monkeypatch.setitem(G, "arguments", lambda: args(config))
    assert M["main"]() == 130
    report = json.loads(config.with_name("receipt.json").read_text())
    assert report["status"] == "cancelled" and report["child_cleanup_error_type"] == "OSError"
    assert not report["worker_reaped"]


def test_encoded_cas_credentials_do_not_require_an_unused_legacy_iv(config):
    data = json.loads(config.read_text())
    data["cas"]["operation_code"] = "A" * 40
    data["cas"]["key"] = "MDEyMzQ1Njc4OWFiY2RlZg=="
    config.write_text(json.dumps(data))
    credential, _, _ = M["private_config"](config)
    expected = b"0123456789abcdef"
    assert credential.device_info.key_bytes == expected


def test_worker_rechecks_installed_package_before_capture(config, monkeypatch):
    options = args(
        config,
        worker=True,
        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        mono_option="channels",
    )
    monkeypatch.setitem(G, "arguments", lambda: options)
    monkeypatch.setitem(M["RUNTIME"], "package_fingerprint", lambda _root: "0" * 64)
    monkeypatch.setitem(
        G, "capture", lambda *_a: pytest.fail("changed installed package acquired camera")
    )
    assert M["main"]() == 2
    assert json.loads(options.receipt.read_text())["error_type"] == "ValueError"


def test_parent_keeps_partial_receipt_after_timeout_and_reap(config, monkeypatch):
    preflight(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda _text: None)

    class Child:
        def __init__(self, command, **_kwargs):
            Path(command[command.index("--receipt") + 1]).write_text(
                json.dumps(dict(status="cancelled", partial=True))
            )

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("worker", timeout)

        def poll(self):
            return 2

    monkeypatch.setattr(M["subprocess"], "Popen", Child)
    monkeypatch.setitem(G, "reap", lambda _child: None)
    monkeypatch.setitem(G, "arguments", lambda: args(config))
    assert M["main"]() == 2
    report = json.loads(config.with_name("receipt.json").read_text())
    assert report["error_type"] == "TimeoutExpired" and report["worker_reaped"]
    assert report["playback"] == dict(status="cancelled", partial=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process-group lifecycle")
@pytest.mark.parametrize("mode", ["already-exited", "term-exit"])
def test_reap_kills_surviving_output_descendants_even_when_leader_exits(tmp_path, mode):
    child = tmp_path / "output.py"
    child.write_text("""import signal,sys,time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text('ready')
time.sleep(60)
""")
    worker = tmp_path / "worker.py"
    worker.write_text("""import os,subprocess,sys,time
from pathlib import Path
p=subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])
Path(sys.argv[3]).write_text(str(p.pid))
while not Path(sys.argv[2]).exists():time.sleep(.01)
if sys.argv[4]=='already-exited':os._exit(2)
time.sleep(60)
""")
    # A scoped subreaper lets this isolated probe reap its adopted output child;
    # the test does not leave an orphan zombie or alter pytest's process state.
    probe = """import ctypes,os,runpy,signal,subprocess,sys,time
from contextlib import suppress
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(36,1,0,0,0)==0
module=runpy.run_path(sys.argv[1]);worker=Path(sys.argv[2]);ready=worker.with_name('ready');pidfile=worker.with_name('pid')
p=subprocess.Popen([sys.executable,str(worker),sys.argv[3],str(ready),str(pidfile),sys.argv[4]],start_new_session=True)
output_pid=None
try:
 deadline=time.monotonic()+5
 while not ready.exists() or not pidfile.exists():
  assert time.monotonic()<deadline
  time.sleep(.01)
 output_pid=int(pidfile.read_text())
 if sys.argv[4]=='already-exited':p.wait(timeout=3)
 module['reap'](p)
 assert p.poll() is not None
 deadline=time.monotonic()+3
 while True:
  pid,status=os.waitpid(output_pid,os.WNOHANG)
  if pid:
   assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
   output_pid=None
   break
  assert time.monotonic()<deadline,'output process survived worker reaping'
  time.sleep(.01)
finally:
 with suppress(ProcessLookupError):os.killpg(p.pid,signal.SIGKILL)
 p.wait(timeout=3)
 if output_pid is not None:
  with suppress(ProcessLookupError):os.kill(output_pid,signal.SIGKILL)
  os.waitpid(output_pid,0)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            probe,
            str(Path(__file__).parents[1] / "tools/local_av_lan_playback.py"),
            str(worker),
            str(child),
            mode,
        ],
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()


def test_secret_redaction_does_not_echo_diagnostic_labels_in_its_fallback(config):
    report = dict(status="failed", stage="public-test-key", error_type="public-test-key")
    raw = M["safe_receipt"](report, args(config))
    secret = b"public-test-key"
    assert secret not in raw
    result = json.loads(raw)
    assert result["status"] == "failed" and result["diagnostics_omitted"]
    assert result["error_type"] == "UnsafeOrUnavailableReceipt"


@pytest.mark.parametrize(
    "case", ["success", "source-error", "unjoined", "finalize-error", "source-and-finalize-error"]
)
def test_optional_packet_evidence_follows_source_worker_ownership(config, monkeypatch, case):
    root = config.with_name("evidence")
    root.mkdir(mode=0o700)
    options = args(
        config,
        packet_evidence=root,
        config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        mono_option="channels",
    )
    closed = []
    writers = []
    evidence_type = M["EVIDENCE"]["PacketEvidence"]

    def make_evidence(path):
        writer = evidence_type(path)
        writers.append(writer)
        if case in ("finalize-error", "source-and-finalize-error"):

            def fail(_binding):
                writer.output.close()
                os.close(writer.root)
                raise OSError("storage failure")

            writer.finish = fail
        return writer

    monkeypatch.setitem(M["EVIDENCE"], "PacketEvidence", make_evidence)

    class Owner:
        def __init__(self):
            self.capture_result = dict(packets_yielded=0, bytes_yielded=0)

        def iter_media_packets(self, **_kwargs):
            try:
                for body in (b"first", b"second"):
                    self.capture_result["packets_yielded"] += 1
                    self.capture_result["bytes_yielded"] += len(body)
                    yield SimpleNamespace(body=body)
                    if case in ("source-error", "source-and-finalize-error"):
                        raise ValueError("source-primary")
            finally:
                closed.append("iterator")

        def close(self):
            closed.append("owner")

    owner = Owner()
    monkeypatch.setattr(M["pyezvizapi"], "AutoMediaStream", lambda *_a, **_kw: owner)
    held = []

    class Session:
        def __init__(self, actual, _key, _args, report, **_kwargs):
            self.iterator = actual.iter_media_packets()
            held.append(self.iterator)
            self.report = report
            self.pull = SimpleNamespace(
                result=lambda: dict(
                    worker_alive=case == "unjoined",
                    consumer_closed=True,
                )
            )

        def play(self):
            if case == "unjoined":
                next(self.iterator)
                raise ValueError("source-primary")
            assert [p.body for p in self.iterator] == [b"first", b"second"]
            self.report["status"] = "prefix-output-completed"

        def close(self, timeout):
            raise TimeoutError

    monkeypatch.setitem(M["CAPTURE"], "CapturePlayback", Session)
    report: dict[str, Any] = {}
    if case == "success":
        M["capture"](options, report)
    else:
        message = "capture cleanup failed" if case == "finalize-error" else "source-primary"
        with pytest.raises(ValueError, match=message):
            M["capture"](options, report)
    if case == "unjoined":
        assert not closed and not (root / "manifest.json").exists()
        assert report["packet_evidence"] == dict(status="incomplete")
        # Only this fake worker is idle: release its retained generator/file.
        held[0].close()
        writers[0].output.close()
        os.close(writers[0].root)
    elif case in ("finalize-error", "source-and-finalize-error"):
        assert report["status"] == "failed" and report["caller_cleanup_error_types"] == ["OSError"]
        assert report["packet_evidence"] == dict(status="incomplete")
        assert not (root / "manifest.json").exists()
        assert closed == ["iterator", "owner"]
    else:
        summary = M["EVIDENCE"]["verify"](root)
        assert report["packet_evidence"] == dict(status="finalized", summary=summary)
        assert summary["packets"] == (2 if case == "success" else 1)
        assert closed == ["iterator", "owner"]


def test_existing_evidence_directory_rejected_before_enter(config, monkeypatch):
    root = config.with_name("evidence")
    root.mkdir()
    (root / "keep").write_text("unchanged")
    preflight(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *_a: pytest.fail("existing evidence accepted"))
    with pytest.raises(FileExistsError):
        M["attended"](args(config, packet_evidence=root), {})
    assert (root / "keep").read_text() == "unchanged"


@pytest.mark.parametrize("case", ["good", "summary", "binding", "count", "bytes"])
def test_parent_independently_checks_evidence_before_success(config, monkeypatch, case):
    root = config.with_name("evidence")
    root.mkdir()
    writer = M["EVIDENCE"]["PacketEvidence"](root)
    list(writer.retain(iter_packets()))
    digest = hashlib.sha256(config.read_bytes()).hexdigest()
    summary = writer.finish(dict(package_sha256="a" * 64, config_sha256=digest))
    evidence = dict(status="finalized", summary=summary)
    owner = dict(packets_yielded=1, bytes_yielded=3)
    if case == "summary":
        evidence = dict(status="incomplete")
    elif case == "binding":
        # Internally consistent saved files from another configuration still fail.
        manifest = root / "manifest.json"
        other = dict(summary, binding=dict(package_sha256="a" * 64, config_sha256="0" * 64))
        manifest.write_text(json.dumps(other))
        evidence = dict(status="finalized", summary=other)
    elif case in ("count", "bytes"):
        owner["packets_yielded" if case == "count" else "bytes_yielded"] += 1

    class Child:
        def __init__(self, command, **_kwargs):
            assert command[command.index("--packet-evidence") + 1] == str(root.resolve())
            Path(command[command.index("--receipt") + 1]).write_text(
                json.dumps(
                    dict(
                        status="prefix-output-completed",
                        package_sha256="a" * 64,
                        config_sha256=digest,
                        source_worker_retained=False,
                        caller_cleanup_error_types=[],
                        capture_limits=M["LIMITS"],
                        requested_options=dict(M["OPTIONS"], startup_pairing="strict"),
                        preparation={},
                        output={},
                        packet_evidence=evidence,
                        final_owner=owner,
                    )
                )
            )

        def wait(self, timeout):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr(M["subprocess"], "Popen", Child)
    monkeypatch.setitem(G, "reap", lambda _child: None)
    monkeypatch.setitem(M["CAPTURE"], "verify_output", lambda *_a: None)
    report: dict[str, Any] = {}
    options = args(config, packet_evidence=root)
    if case == "good":
        M["supervise"](options, report, digest, "channels")
        assert report["status"] == "completed"
        assert report["packet_evidence"]["status"] == "integrity-verified"
    else:
        with pytest.raises(ValueError, match="receipt binding"):
            M["supervise"](options, report, digest, "channels")
        assert report.get("status") != "completed"
    assert report["worker_reaped"]


def iter_packets():
    yield SimpleNamespace(body=b"abc")
