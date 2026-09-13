"""CLI persistence must precede authentication and push setup."""

import json
from unittest.mock import Mock

import pytest

import pyezvizapi.__main__ as cli
from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizTokenPersistenceError


def test_mqtt_installs_storage_before_login_and_handles_mfa(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = Mock()
    callback = Mock()
    attempts = []

    def construct(*args, **kwargs):
        nonlocal callback
        callback = kwargs["on_token_updated"]
        return client

    def enable(sms_code=None):
        attempts.append(sms_code)
        if sms_code is None:
            raise EzvizAuthVerificationCode
        callback({"session_id": "rotated", "push_state": {"device": "synthetic"}})

    def connect():
        assert json.loads((tmp_path / "ezviz_token.json").read_text())["session_id"] == "rotated"

    client.enable_channel99.side_effect = enable
    client.get_mqtt_client.return_value.connect.side_effect = connect
    monkeypatch.setattr(cli, "EzvizClient", construct)
    monkeypatch.setattr("builtins.input", lambda prompt: "123456")
    monkeypatch.setattr(cli.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    assert cli.main(["-u", "synthetic", "-p", "synthetic", "mqtt"]) == 0
    assert attempts == [None, 123456]
    client.login.assert_not_called()
    client.get_mqtt_client.return_value.stop.assert_called_once()
    client.close_session.assert_called_once()
    assert (tmp_path / "ezviz_token.json").stat().st_mode & 0o777 == 0o600


def test_mqtt_storage_failure_prevents_connection(tmp_path, monkeypatch):
    client = Mock()

    def construct(*args, **kwargs):
        client.enable_channel99.side_effect = lambda: kwargs["on_token_updated"]({"session_id": "rotated"})
        return client

    monkeypatch.setattr(cli, "EzvizClient", construct)
    monkeypatch.setattr(cli, "save_private_token", Mock(side_effect=OSError("disk full")))
    assert cli.main(["-u", "synthetic", "-p", "synthetic", "--token-file", str(tmp_path / "token.json"), "mqtt"]) == 1
    client.get_mqtt_client.assert_not_called()
    client.close_session.assert_called_once()


def test_saved_push_token_installs_callback_for_non_push_action(tmp_path, monkeypatch):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"session_id": "old", "push_profile": "android-channel99"}))
    client = Mock()

    def construct(*args, **kwargs):
        def devices(*unused):
            kwargs["on_token_updated"]({"session_id": "refreshed"})
            return 0
        monkeypatch.setattr(cli, "_handle_devices", devices)
        return client

    monkeypatch.setattr(cli, "EzvizClient", construct)
    assert cli.main(["--token-file", str(path), "devices", "status"]) == 0
    assert json.loads(path.read_text())["session_id"] == "refreshed"


def test_token_write_failure_is_not_silenced(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "save_private_token", Mock(side_effect=OSError("disk full")))
    with pytest.raises(cli.PyEzvizError, match="Failed to save token file"):
        cli._save_token_file(str(tmp_path / "token.json"), {})  # noqa: SLF001


def test_cli_invalid_host_token_returns_error_without_traceback(tmp_path, caplog):
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"session_id": "old", "push_profile": "android-channel99",
                                "feature_code": "different-host"}))
    assert cli.main(["--token-file", str(path), "devices", "status"]) == 1
    assert "host feature code" in caplog.text
    assert "Traceback" not in caplog.text


def test_cli_surfaces_worker_failure_and_stops(tmp_path, monkeypatch):

    client = Mock()
    push = client.get_mqtt_client.return_value
    push.raise_if_failed.side_effect = EzvizTokenPersistenceError("Storage failed")
    monkeypatch.setattr(cli, "EzvizClient", Mock(return_value=client))
    assert cli.main(["-u", "synthetic", "-p", "synthetic", "--token-file",
                     str(tmp_path / "token.json"), "mqtt"]) == 1
    push.stop.assert_called_once()
    client.close_session.assert_called_once()


def test_cli_shutdown_timeout_returns_failure_without_traceback(tmp_path, monkeypatch, caplog):
    client = Mock()
    push = client.get_mqtt_client.return_value
    push.raise_if_failed.side_effect = KeyboardInterrupt
    push.stop.side_effect = TimeoutError
    monkeypatch.setattr(cli, "EzvizClient", Mock(return_value=client))
    assert cli.main(["-u", "synthetic", "-p", "synthetic", "--token-file",
                     str(tmp_path / "token.json"), "mqtt"]) == 1
    assert "cancellation remains signalled" in caplog.text
    assert "Traceback" not in caplog.text
    client.close_session.assert_called_once()
