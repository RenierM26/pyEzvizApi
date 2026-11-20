"""LAN PTZ is local-only, bounded in time and always followed by a stop."""

import json
from typing import Any

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.cli.commands import lan
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    EZVIZ_LAN_PTZ_ACTION_START,
    EZVIZ_LAN_PTZ_ACTION_STOP,
    EzvizPtzCommand,
    HcNetSdkCommandPortControlResponse,
    parse_hcnetsdk_tcp_frame,
)

SECRET = b"synthetic-secret"
ACK = bytes.fromhex("00000010000000010000000100000000")
NACK = bytes.fromhex("00000010000000020000000100000000")


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

    class Client:
        def __init__(self) -> None:
            self.start_reply: bytes | Exception = ACK
            self.stop_replies: list[bytes | Exception] = [ACK]

        def ptz_control(self, command, *, action, channel, speed):
            calls.append(("ptz", command, action, channel, speed))
            if action == EZVIZ_LAN_PTZ_ACTION_START:
                reply = self.start_reply
            else:
                replies = self.stop_replies
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
            if isinstance(reply, Exception):
                raise reply
            return _response(reply)

    client = Client()

    def factory(endpoint, secret, **kwargs):
        calls.append(("client", endpoint, secret, kwargs))
        return client

    monkeypatch.setattr(lan, "HcNetSdkPurePythonClient", factory)
    monkeypatch.setattr(lan.time, "sleep", lambda seconds: calls.append(("sleep", seconds)))
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
