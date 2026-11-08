"""RTSP configuration is local-only, targeted and not a playback claim."""

import json
from typing import Any

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.cli.commands import lan
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    EzvizLanServicesSwitchState,
    HcNetSdkStdXmlConfigResponse,
    ezviz_lan_services_switch_set_payload,
)

SECRET = b"synthetic-secret"


@pytest.fixture
def setup(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("LAN RTSP attempted cloud/token access")

    monkeypatch.setattr(cli, "EzvizClient", forbidden)
    monkeypatch.setattr(cli, "_load_token_file", forbidden)
    password = tmp_path / "password"
    password.write_bytes(b"synthetic-secret\n")
    calls: list[Any] = []
    payload = {"servicesSwitch": {"rtsp": 0, "web": 0, "hiksdk": 1, "upnp": 0}, "extra": 17}

    class Client:
        value = payload
        response = HcNetSdkStdXmlConfigResponse(True, b'{"statusCode":1}')
        read_error = None
        write_error = None
        ignore_write = False

        def services_switch_state(self):
            calls.append("read")
            if self.read_error:
                raise self.read_error
            return EzvizLanServicesSwitchState(raw=self.value)

        def services_switch_set(self, current_payload, **kwargs):
            calls.append(("write", current_payload, kwargs))
            if self.write_error:
                raise self.write_error
            if not self.ignore_write:
                self.value = ezviz_lan_services_switch_set_payload(current_payload, **kwargs)
            return self.response

    client = Client()

    def factory(endpoint, secret, **kwargs):
        calls.append(("client", endpoint, secret, kwargs))
        return client

    monkeypatch.setattr(lan, "HcNetSdkPurePythonClient", factory)
    args = [
        "lan",
        "rtsp",
        "enable",
        "--host",
        "192.0.2.10",
        "--serial",
        "CAM123",
        "--lan-password-file",
        str(password),
    ]
    return args, client, calls, password


def test_enable_preserves_other_services_and_verifies(setup, capsys):
    args, client, calls, _ = setup
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {
        "ok": True,
        "rtsp": 1,
        "enabled": True,
        "changed": True,
        "verified": "configuration",
    }
    assert [item if isinstance(item, str) else item[0] for item in calls] == [
        "client",
        "read",
        "write",
        "read",
    ]
    assert calls[0][1].command_port == 8000
    assert calls[0][2] == SECRET
    assert calls[2][2] == {"rtsp": 1}
    assert calls[2][1]["servicesSwitch"]["rtsp"] == 0
    assert client.value == {
        "servicesSwitch": {"rtsp": 1, "web": 0, "hiksdk": 1, "upnp": 0},
        "extra": 17,
    }


@pytest.mark.parametrize(
    ("action", "value"), [("status", 0), ("status", 1), ("enable", 1), ("disable", 0)]
)
def test_read_only_and_idempotent_operations_never_write(setup, capsys, action, value):
    args, client, calls, _ = setup
    args[2] = action
    client.value = {"servicesSwitch": {"rtsp": value}}
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is False
    assert calls[-1] == "read"
    assert len(calls) == 2


def test_disable_readback_and_endpoint_options(setup, capsys):
    args, client, calls, _ = setup
    args[2] = "disable"
    client.value = {"servicesSwitch": {"rtsp": 1}}
    args += [
        "--command-port",
        "8123",
        "--lan-username",
        "operator",
        "--local-ip",
        "192.0.2.20",
        "--timeout",
        "2",
    ]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["rtsp"] == 0
    assert calls[0][1].command_port == 8123
    assert calls[0][3] == {"username": "operator", "local_ip": "192.0.2.20", "timeout": 2.0}


@pytest.mark.parametrize("value", [None, 2, -1, "enabled", "1.0", 1.0, True, [], {}])
def test_unknown_switch_never_written(setup, capsys, value):
    args, client, calls, _ = setup
    client.value = {"servicesSwitch": {"rtsp": value}}
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["outcome"] == "not-written"
    assert len(calls) == 2


@pytest.mark.parametrize("payload", [{}, {"servicesSwitch": []}, {"servicesSwitch": None}])
def test_absent_service_never_written(setup, capsys, payload):
    args, client, calls, _ = setup
    client.value = payload
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "read"
    assert len(calls) == 2


@pytest.mark.parametrize(
    "extra",
    [
        ["--timeout", "nan"],
        ["--timeout", "inf"],
        ["--timeout", "0"],
        ["--command-port", "0"],
        ["--command-port", "65536"],
        ["--host", "camera.example.test"],
        ["--local-ip", "bad"],
        ["--serial", " "],
        ["--lan-username", ""],
    ],
)
def test_invalid_arguments_precede_client_creation(setup, capsys, extra):
    args, _, calls, _ = setup
    assert cli.main(args + extra) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "arguments"
    assert not calls


@pytest.mark.parametrize("content", [b"", b"\n", b"x" * 2048, b"secret\0junk"])
def test_invalid_password_files_precede_client_creation(setup, capsys, content):
    args, _, calls, path = setup
    path.write_bytes(content)
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "arguments"
    assert not calls


@pytest.mark.parametrize(
    "response",
    [
        HcNetSdkStdXmlConfigResponse(False, b'{"statusCode":1}'),
        HcNetSdkStdXmlConfigResponse(True, b'{"statusCode":4}'),
        HcNetSdkStdXmlConfigResponse(True, b'{"statusCode":true}'),
        HcNetSdkStdXmlConfigResponse(True, b"{}"),
        HcNetSdkStdXmlConfigResponse(True, b"private malformed"),
    ],
)
def test_refused_or_malformed_acknowledgment_not_success(setup, capsys, response):
    args, client, calls, _ = setup
    client.response = response
    assert cli.main(args) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["stage"] == "write"
    assert json.loads(output)["outcome"] == "unknown"
    assert "private" not in output
    assert len(calls) == 3


def test_mismatched_readback_is_not_success(setup, capsys):
    args, client, calls, _ = setup
    client.ignore_write = True
    assert cli.main(args) == 1
    assert json.loads(capsys.readouterr().out)["stage"] == "read-back"
    assert len(calls) == 4


@pytest.mark.parametrize("stage", ["read", "write", "read-back"])
@pytest.mark.parametrize("error", [OSError("synthetic-secret"), PyEzvizError("synthetic-secret")])
def test_transport_failure_is_redacted_and_writes_never_retried(
    setup, capsys, monkeypatch, stage, error
):
    args, client, calls, _ = setup
    if stage == "read":
        client.read_error = error
    elif stage == "write":
        client.write_error = error
    else:
        write = client.services_switch_set

        def set_then_fail(*args, **kwargs):
            result = write(*args, **kwargs)
            client.read_error = error
            return result

        monkeypatch.setattr(client, "services_switch_set", set_then_fail)
    assert cli.main(args) == 1
    output = capsys.readouterr()
    assert "synthetic-secret" not in output.out + output.err
    assert json.loads(output.out)["stage"] == stage
    assert len([item for item in calls if not isinstance(item, str) and item[0] == "write"]) <= 1
