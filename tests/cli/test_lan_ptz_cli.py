"""LAN PTZ is local-only, bounded in time and always followed by a stop."""

import json
import socket
import struct
import time
from typing import Any

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.cli.commands import lan
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    EZVIZ_LAN_PTZ_ACTION_START,
    EZVIZ_LAN_PTZ_ACTION_STOP,
    EzvizPtzCommand,
    HcNetSdkCommandPortControlResponse,
    build_hcnetsdk_tcp_frame,
    parse_hcnetsdk_tcp_frame,
)

SECRET = b"synthetic-secret"
ACK = bytes.fromhex("00000010000000010000000100000000")
NACK = bytes.fromhex("00000010000000020000000100000000")
DEFAULT_DURATION = 0.5
LONG_DURATION = 2.0
WIRE_DURATION = 0.2
# Scheduling slack for the real-time tests; far below the 10 s socket timeout.
WIRE_SLACK = 0.4
WIRE_STOP_TIMEOUT = 0.4
_LINGER_RESET = struct.pack("ii", 1, 0)
_LINGER_OFF = struct.pack("ii", 0, 0)


def _response(frame: bytes) -> HcNetSdkCommandPortControlResponse:
    return HcNetSdkCommandPortControlResponse(
        login_session=None,  # type: ignore[arg-type]
        request=b"",
        response=parse_hcnetsdk_tcp_frame(frame),
    )


@pytest.fixture
def setup(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("LAN PTZ attempted cloud/token access")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    monkeypatch.setattr(cli, "_load_token_file", forbidden)
    password = tmp_path / "password"
    password.write_bytes(b"synthetic-secret\n")
    calls: list[Any] = []

    clock = [100.0]

    class Client:
        def __init__(self) -> None:
            self.start_reply: bytes | Exception = ACK
            self.stop_replies: list[bytes | Exception] = [ACK]
            # Errors raised after the frame was written, like a late or lost ack.
            self.start_written = False
            self.ack_timeouts: list[float | None] = []
            self.deadlines: list[float | None] = []
            self.sent_at: list[float] = []

        def ptz_control(
            self, command, *, action, channel, speed, on_sent, ack_timeout=None, deadline=None
        ):
            calls.append(("ptz", command, action, channel, speed))
            self.ack_timeouts.append(ack_timeout)
            self.deadlines.append((deadline - clock[0]) if deadline is not None else None)
            if action == EZVIZ_LAN_PTZ_ACTION_START:
                reply = self.start_reply
                written = not isinstance(reply, Exception) or self.start_written
            else:
                replies = self.stop_replies
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                written = not isinstance(reply, Exception)
            if written:
                self.sent_at.append(clock[0])
                on_sent()
            if isinstance(reply, EzvizLocalSdkDeadlineExpired):
                assert ack_timeout is not None
                clock[0] += ack_timeout
            if isinstance(reply, Exception):
                raise reply
            return _response(reply)

    client = Client()

    def factory(endpoint, secret, **kwargs):
        calls.append(("client", endpoint, secret, kwargs))
        return client

    monkeypatch.setattr(lan, "HcNetSdkPurePythonClient", factory)

    def sleep(seconds: float) -> None:
        calls.append(("sleep", seconds))
        clock[0] += seconds

    monkeypatch.setattr(lan.time, "sleep", sleep)
    monkeypatch.setattr(lan.time, "monotonic", lambda: clock[0])
    args = [
        "lan",
        "ptz",
        "left",
        "--host",
        "192.0.2.10",
        "--serial",
        "CAM123",
        "--lan-password-file",
        str(password),
    ]
    return args, client, calls, password


def _kinds(calls: list[Any]) -> list[str]:
    return [item[0] if item[0] != "ptz" else f"ptz-{item[2]}" for item in calls]


@pytest.mark.parametrize(
    ("direction", "command"),
    [
        ("up", EzvizPtzCommand.UP),
        ("down", EzvizPtzCommand.DOWN),
        ("left", EzvizPtzCommand.LEFT),
        ("right", EzvizPtzCommand.RIGHT),
    ],
)
def test_move_starts_waits_and_stops(setup, capsys, direction, command):
    args, _, calls, _ = setup
    args[2] = direction
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "direction": direction,
        "duration": 0.5,
        "stopped": True,
        "verified": "acknowledgment",
    }
    assert _kinds(calls) == [
        "client",
        f"ptz-{EZVIZ_LAN_PTZ_ACTION_START}",
        "sleep",
        f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}",
    ]
    assert calls[0][1].command_port == 8000
    assert calls[0][2] == SECRET
    assert calls[1] == ("ptz", command, EZVIZ_LAN_PTZ_ACTION_START, 1, 4)
    assert calls[2] == ("sleep", 0.5)
    assert calls[3] == ("ptz", command, EZVIZ_LAN_PTZ_ACTION_STOP, 1, 4)


def test_options_reach_the_client(setup, capsys):
    args, _, calls, _ = setup
    args += ["--duration", "2", "--speed", "7", "--channel", "2", "--command-port", "8123"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["duration"] == calls[2][1]
    assert calls[0][1].command_port == 8123
    assert calls[1][3:] == (2, 7)
    assert calls[2] == ("sleep", 2.0)


@pytest.mark.parametrize(
    "extra",
    [
        ["--duration", "0"],
        ["--duration", "-1"],
        ["--duration", "5.1"],
        ["--duration", "nan"],
        ["--duration", "inf"],
        ["--speed", "0"],
        ["--speed", "8"],
        ["--channel", "-1"],
        ["--timeout", "0"],
        ["--host", "camera.example.test"],
        ["--serial", " "],
    ],
)
def test_invalid_arguments_precede_client_creation(setup, capsys, extra):
    args, _, calls, _ = setup
    assert cli.main(args + extra) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["stage"] == "arguments"
    assert output["stopped"] is False
    assert not calls


@pytest.mark.parametrize("error", [OSError("synthetic-secret"), PyEzvizError("synthetic-secret")])
def test_failed_start_still_sends_stop_and_is_redacted(setup, capsys, error):
    args, client, calls, _ = setup
    client.start_reply = error
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert "synthetic-secret" not in output.out + output.err
    assert json.loads(output.out) == {
        "ok": False,
        "stage": "start",
        "message": "PTZ command unavailable, refused, or not acknowledged",
        "start": "not-sent",
        "stop": "acknowledged",
        "stopped": True,
    }
    assert _kinds(calls) == [
        "client",
        f"ptz-{EZVIZ_LAN_PTZ_ACTION_START}",
        f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}",
    ]


def test_unacknowledged_start_skips_wait_but_stops(setup, capsys):
    args, client, calls, _ = setup
    client.start_reply = NACK
    assert cli.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["stage"] == "start"
    assert output["start"] == "unacknowledged"
    assert output["stopped"] is True
    assert "sleep" not in _kinds(calls)
    assert _kinds(calls)[-1] == f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}"


def test_stop_is_retried_once_after_transport_error(setup, capsys):
    args, client, calls, _ = setup
    client.stop_replies = [OSError("synthetic-secret"), ACK]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["stopped"] is True
    assert _kinds(calls).count(f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}") == 2
    assert _kinds(calls).count(f"ptz-{EZVIZ_LAN_PTZ_ACTION_START}") == 1


def test_stop_failure_is_reported_and_not_retried_forever(setup, capsys):
    args, client, calls, _ = setup
    client.stop_replies = [OSError("synthetic-secret")]
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert "synthetic-secret" not in output.out + output.err
    assert json.loads(output.out)["stage"] == "stop"
    assert json.loads(output.out)["stopped"] is False
    assert _kinds(calls).count(f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}") == 2


def test_unacknowledged_stop_is_not_success(setup, capsys):
    args, client, calls, _ = setup
    client.stop_replies = [NACK]
    assert cli.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["stage"] == "stop"
    assert output["stopped"] is False
    assert _kinds(calls).count(f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}") == 2


def test_stop_retried_after_missing_acknowledgment(setup, capsys):
    args, client, calls, _ = setup
    client.stop_replies = [NACK, ACK]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["stopped"] is True
    assert _kinds(calls).count(f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}") == 2


def test_interrupted_wait_still_sends_stop(setup, monkeypatch):
    args, _, calls, _ = setup

    def interrupted(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(lan.time, "sleep", interrupted)
    with pytest.raises(KeyboardInterrupt):
        cli.main(args)
    assert _kinds(calls)[-1] == f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}"


def test_duration_counts_from_the_written_start_frame(setup, capsys):
    args, client, _, _ = setup
    args += ["--duration", str(LONG_DURATION)]
    assert cli.main(args) == 0
    capsys.readouterr()
    assert client.ack_timeouts == [LONG_DURATION, None]
    assert client.sent_at[1] - client.sent_at[0] == LONG_DURATION


@pytest.mark.parametrize(
    "error",
    [EzvizLocalSdkDeadlineExpired("late"), OSError("reset")],
    ids=["ack-late", "ack-read-error"],
)
def test_start_written_without_ack_stops_by_the_deadline(setup, capsys, error):
    args, client, calls, _ = setup
    client.start_reply = error
    client.start_written = True
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "stage": "start",
        "message": "PTZ command unavailable, refused, or not acknowledged",
        "start": "unacknowledged",
        "stop": "acknowledged",
        "stopped": True,
    }
    assert client.ack_timeouts[0] == DEFAULT_DURATION
    assert client.sent_at[1] - client.sent_at[0] <= DEFAULT_DURATION
    assert "sleep" not in _kinds(calls)
    assert _kinds(calls)[-1] == f"ptz-{EZVIZ_LAN_PTZ_ACTION_STOP}"


def test_each_stop_attempt_is_bounded_by_the_timeout(setup, capsys):
    args, client, _, _ = setup
    args += ["--timeout", "1.5"]
    client.stop_replies = [OSError("refused"), ACK]
    assert cli.main(args) == 0
    capsys.readouterr()
    # The start is not bounded as a whole; each stop attempt gets now + --timeout.
    assert client.deadlines == [None, 1.5, 1.5]


def test_written_stop_without_ack_is_reported(setup, capsys):
    args, client, _, _ = setup
    client.stop_replies = [NACK]
    assert cli.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert (output["start"], output["stop"], output["stopped"]) == (
        "acknowledged",
        "unacknowledged",
        False,
    )


class _TimedSocket:
    """Fake command-port socket whose reply arrives a set time after the write."""

    def __init__(
        self, reply: bytes, delay: float | None, log: list[Any], name: str, trickle: float = 0.0
    ) -> None:
        self._buffer = reply
        self._delay = delay
        self._ready_at: float | None = None if delay is None else float("-inf")
        self._log = log
        self._name = name
        # When set, each recv returns one byte after this many seconds.
        self._trickle = trickle
        self.timeout: float | None = None
        self.linger: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self._log.append(("sent", self._name, time.monotonic()))
        if self._delay is not None and self._delay > 0:
            self._ready_at = time.monotonic() + self._delay

    def recv(self, length: int) -> bytes:
        wait = float("inf") if self._ready_at is None else self._ready_at - time.monotonic()
        if wait > 0:
            if self.timeout is None:
                raise AssertionError("unbounded wait for a reply")
            if self.timeout < wait:
                time.sleep(self.timeout)
                raise TimeoutError("timed out")
            time.sleep(wait)
        if self._trickle:
            if self.timeout is not None and self.timeout < self._trickle:
                time.sleep(self.timeout)
                raise TimeoutError("timed out")
            time.sleep(self._trickle)
            length = 1
        chunk, self._buffer = self._buffer[:length], self._buffer[length:]
        return chunk

    def setsockopt(self, level: int, option: int, value: bytes) -> None:
        assert (level, option) == (socket.SOL_SOCKET, socket.SO_LINGER)
        self.linger.append(value)

    def gettimeout(self) -> float | None:
        return self.timeout

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def close(self) -> None:
        pass


@pytest.fixture(scope="module")
def rsa_key():
    return RSA.generate(1024)


@pytest.fixture
def wire(monkeypatch, tmp_path, rsa_key):
    """Run the CLI against the real client over scripted fake sockets."""
    password = tmp_path / "password"
    password.write_bytes(b"123456\n")
    log: list[Any] = []
    plan: list[Any] = []

    def login(name: str, trickle: float = 0.0) -> _TimedSocket:
        challenge = b"0123456789abcdef0123456789abcdef"
        reply = build_hcnetsdk_tcp_frame(
            PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge) + b"s" * 64
        ) + build_hcnetsdk_tcp_frame(b"\x12\x34\x56\x78CAM123\x00", field_4=0x10A24BF1)
        return _TimedSocket(reply, 0.0, log, name, trickle)

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _TimedSocket:
        assert address == ("192.0.2.10", 8000)
        log.append(("connect", None, time.monotonic()))
        item = plan.pop(0)
        if isinstance(item, Exception):
            raise item
        item.timeout = timeout
        return item

    real = lan.HcNetSdkPurePythonClient

    def client(endpoint, secret, **kwargs):
        return real(endpoint, secret, socket_factory=socket_factory, rsa_key=rsa_key, **kwargs)

    monkeypatch.setattr(lan, "HcNetSdkPurePythonClient", client)
    args = [
        "lan",
        "ptz",
        "right",
        "--duration",
        str(WIRE_DURATION),
        "--host",
        "192.0.2.10",
        "--serial",
        "CAM123",
        "--local-ip",
        "192.0.2.56",
        "--lan-password-file",
        str(password),
    ]
    return args, plan, log, login


def _start_to_stop(log: list[Any]) -> float:
    started = next(t for kind, name, t in log if (kind, name) == ("sent", "start"))
    stop_index = next(i for i, (_, name, _) in enumerate(log) if name == "stop-login")
    # The stop's login socket is opened by the connect logged just before it.
    return log[stop_index - 1][2] - started


def test_wire_normal_move_waits_the_duration_then_stops(wire, capsys):
    args, plan, log, login = wire
    start = _TimedSocket(ACK, 0.0, log, "start")
    plan += [
        login("start-login"),
        start,
        login("stop-login"),
        _TimedSocket(ACK, 0.0, log, "stop"),
    ]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["stopped"] is True
    assert WIRE_DURATION <= _start_to_stop(log) < WIRE_DURATION + WIRE_SLACK
    assert plan == []
    # An acknowledged start is closed normally.
    assert start.linger == [_LINGER_RESET, _LINGER_OFF]


@pytest.mark.parametrize("delay", [1.0, None], ids=["ack-late", "ack-lost"])
def test_wire_late_or_lost_start_ack_stops_at_the_duration(wire, capsys, delay):
    args, plan, log, login = wire
    start = _TimedSocket(ACK, delay, log, "start")
    plan += [
        login("start-login"),
        start,
        login("stop-login"),
        _TimedSocket(ACK, 0.0, log, "stop"),
    ]
    assert cli.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert (output["stage"], output["start"], output["stop"], output["stopped"]) == (
        "start",
        "unacknowledged",
        "acknowledged",
        True,
    )
    # Without the bound the stop would wait for the 10 s socket timeout.
    assert WIRE_DURATION - 0.05 <= _start_to_stop(log) < WIRE_DURATION + WIRE_SLACK
    assert log[-1][:2] == ("sent", "stop")
    # A start without an ack is closed with a reset, so it is not resent later.
    assert start.linger == [_LINGER_RESET]


def test_wire_slow_stop_login_is_cut_at_the_timeout(wire, capsys):
    args, plan, log, login = wire
    args += ["--timeout", str(WIRE_STOP_TIMEOUT)]
    plan += [
        login("start-login"),
        _TimedSocket(ACK, 0.0, log, "start"),
        # Answers one byte at a time, each just inside the socket timeout.
        login("stop-login", trickle=WIRE_STOP_TIMEOUT / 4),
        login("stop-login-2"),
        _TimedSocket(ACK, 0.0, log, "stop"),
    ]
    assert cli.main(args) == 0
    capsys.readouterr()
    started = next(t for kind, name, t in log if (kind, name) == ("sent", "start"))
    stopped = next(t for kind, name, t in log if (kind, name) == ("sent", "stop"))
    # Duration, one cut stop attempt, then a normal one.
    assert stopped - started < WIRE_DURATION + WIRE_STOP_TIMEOUT + WIRE_SLACK
    assert plan == []


def test_wire_login_failure_writes_no_start_frame(wire, capsys, monkeypatch):
    args, plan, log, _ = wire
    plan += [ConnectionRefusedError(), ConnectionRefusedError(), ConnectionRefusedError()]
    def unexpected_wait(seconds: float) -> None:
        pytest.fail(f"Login failure must not wait for motion ({seconds}s)")

    monkeypatch.setattr(lan.time, "sleep", unexpected_wait)
    assert cli.main(args) == 1
    output = json.loads(capsys.readouterr().out)
    assert (output["stage"], output["start"], output["stop"], output["stopped"]) == (
        "start",
        "not-sent",
        "not-sent",
        False,
    )
    assert not any(kind == "sent" for kind, _, _ in log)
