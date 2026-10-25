"""One-command workflow wiring, stdin gate and foreground cancellation; no camera."""

from contextlib import suppress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

import pytest

SCRIPT = Path(__file__).parents[1] / "tools/local_av_lan_session.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="Bash Linux/WSL entrypoint")


@pytest.fixture
def rig(tmp_path):
    log = tmp_path / "calls.jsonl"
    ready = tmp_path / "ready"
    stopped = tmp_path / "stopped"
    python = tmp_path / "python with spaces"
    python.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """import json,os,signal,sys,time
from pathlib import Path
args=sys.argv[1:]; assert args[0]=='-I'
kind='capture' if args[1].endswith('local_av_lan_playback.py') else 'verify'
log=Path(os.environ['SESSION_TEST_LOG'])
with log.open('a') as f:f.write(json.dumps(dict(kind=kind,args=args))+'\\n')
def stop(*_args):
 Path(os.environ['SESSION_TEST_STOPPED']).write_text(kind)
 raise SystemExit(130)
signal.signal(signal.SIGTERM,stop)
if os.environ.get('SESSION_TEST_BLOCK')==kind:
 Path(os.environ['SESSION_TEST_READY']).write_text(str(os.getpid()))
 time.sleep(60)
def value(name):return Path(args[args.index(name)+1])
if kind=='capture':
 entered=sys.stdin.readline()
 if not entered:raise SystemExit(130)
 value('--receipt').write_text('capture-receipt')
 value('--packet-evidence').mkdir(mode=0o700)
 if os.environ.get('SESSION_TEST_FAIL')=='capture':raise SystemExit(2)
else:
 assert value('--receipt').read_text()=='capture-receipt'
 value('--result').write_text('verification-result')
 if os.environ.get('SESSION_TEST_FAIL')=='verify':raise SystemExit(2)
"""
    )
    python.chmod(0o700)
    config = tmp_path / "private file.json"
    config.write_text("synthetic-private-configuration")
    results = tmp_path / "results with spaces"
    command = [
        "bash",
        str(SCRIPT),
        "--python",
        str(python),
        "--results",
        str(results),
        "--private-config",
        str(config),
        "--expected-package-sha256",
        "a" * 64,
        "--play",
    ]
    env = dict(
        os.environ,
        SESSION_TEST_LOG=str(log),
        SESSION_TEST_READY=str(ready),
        SESSION_TEST_STOPPED=str(stopped),
    )
    return command, env, results, config, log, ready, stopped


def calls(log):
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def test_explicit_long_profile_is_forwarded_to_capture_and_verification(rig):
    command, env, _results, _config, log, _ready, _stopped = rig
    p = subprocess.run([*command, '--capture-profile', 'two-minute'], input='\n', text=True,
        capture_output=True, env=env, timeout=5, check=False)
    assert p.returncode == 0, p.stderr
    invocations = calls(log)
    assert len(invocations) == 2
    for invocation in invocations:
        args = invocation['args']
        assert args[args.index('--capture-profile') + 1] == 'two-minute'


def test_unknown_profile_is_rejected_before_any_step_or_results_creation(rig):
    command, env, results, _config, log, _ready, _stopped = rig
    p = subprocess.run([*command, '--capture-profile', 'automatic'], input='\n', text=True,
        capture_output=True, env=env, timeout=5, check=False)
    assert p.returncode == 2 and not results.exists() and not calls(log)


@pytest.mark.parametrize("case", ["good", "capture-failed", "verify-failed", "no-enter"])
def test_workflow_preserves_stdin_and_verifies_only_after_capture_success(rig, case):
    command, env, results, config, log, _ready, _stopped = rig
    if case.endswith("-failed"):
        env["SESSION_TEST_FAIL"] = case.split("-")[0]
    command += [
        "--startup-pairing",
        "common-keyframe",
        "--audio-overlap-policy",
        "bounded-serial-pcm",
        "--max-audio-overlap-ms",
        "1",
        "--max-audio-phase-ms",
        "1",
    ]
    p = subprocess.run(
        command,
        env=env,
        input="" if case == "no-enter" else "\n",
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert p.returncode == (0 if case == "good" else 130 if case == "no-enter" else 2)
    observed = calls(log)
    assert [c["kind"] for c in observed] == (
        ["capture", "verify"] if case in ("good", "verify-failed") else ["capture"]
    )
    assert results.stat().st_mode & 0o777 == 0o700
    assert config.read_text() == "synthetic-private-configuration"
    assert "--play" in observed[0]["args"] and "--startup-pairing" in observed[0]["args"]
    assert "--receipt" in observed[0]["args"] and "--packet-evidence" in observed[0]["args"]
    if case == "good":
        assert (results / "verification.json").read_text() == "verification-result"
        assert "completed:" in p.stdout
    else:
        assert "Session capture and saved-media verification completed" not in p.stdout
    assert "synthetic-private-configuration" not in p.stdout + p.stderr


@pytest.mark.parametrize(
    "option", ["--receipt", "--recei", "--packet-evidence", "--worker", "--result", "--unknown"]
)
def test_managed_hidden_abbreviated_and_unknown_options_rejected_before_start(rig, option):
    command, env, results, _config, log, _ready, _stopped = rig
    p = subprocess.run(
        [*command, option, "bad"], env=env, capture_output=True, timeout=5, check=False
    )
    assert p.returncode == 2 and not results.exists() and not log.exists()


@pytest.mark.parametrize("case", ["existing", "duplicate", "no-play", "missing-value", "no-python"])
def test_invalid_workflow_never_claims_or_overwrites_results(rig, case):
    command, env, results, _config, log, _ready, _stopped = rig
    if case == "existing":
        results.mkdir()
        (results / "keep").write_text("keep")
    elif case == "duplicate":
        command += ["--play"]
    elif case == "no-play":
        command.remove("--play")
    elif case == "missing-value":
        command += ["--startup-pairing"]
    elif case == "no-python":
        command[command.index("--python") + 1] = "python3"
    p = subprocess.run(command, env=env, capture_output=True, timeout=5, check=False)
    assert p.returncode == 2 and not calls(log)
    if case == "existing":
        assert (results / "keep").read_text() == "keep"
    else:
        assert not results.exists()


@pytest.mark.parametrize("phase", ["capture", "verify"])
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_stop_signal_is_forwarded_and_owned_step_finishes_before_session_returns(
    rig, phase, stop_signal
):
    command, env, results, _config, log, ready, stopped = rig
    env["SESSION_TEST_BLOCK"] = phase
    p = subprocess.Popen(
        command,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    child_pid = None
    try:
        assert p.stdin is not None
        p.stdin.write("\n")
        p.stdin.flush()
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert p.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        child_pid = int(ready.read_text())
        p.send_signal(stop_signal)
        stdout, _stderr = p.communicate(timeout=5)
        assert p.returncode == 130 and stopped.read_text() == phase
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
        child_pid = None
        assert "Session capture and saved-media verification completed" not in stdout
        assert results.exists() and len(calls(log)) == (1 if phase == "capture" else 2)
    finally:
        if p.poll() is None:
            p.kill()
        p.communicate(timeout=3)
        if child_pid is not None:
            with suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)


def test_help_and_syntax_check_do_not_start_python_or_claim_results(rig):
    _command, env, results, _config, log, _ready, _stopped = rig
    p = subprocess.run(
        ["bash", str(SCRIPT), "--help"], env=env, capture_output=True, timeout=5, check=False
    )
    assert p.returncode == 0 and not results.exists() and not log.exists()
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=5)
