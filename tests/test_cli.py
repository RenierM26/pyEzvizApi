from __future__ import annotations

import importlib.util
import json
from typing import Any, ClassVar, cast

import pyezvizapi.__main__ as cli_module
from pyezvizapi.__main__ import _format_cell, _write_table
from pyezvizapi.exceptions import EzvizAuthVerificationCode


def test_cli_imports_without_pandas_installed() -> None:
    assert importlib.util.find_spec("pandas") is None


def test_format_cell_handles_common_table_values() -> None:
    assert _format_cell(None) == ""
    assert _format_cell(True) == "True"
    assert _format_cell({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'


def test_write_table_outputs_fixed_width_rows(capsys) -> None:
    _write_table(
        [
            {"serial": "ABC", "name": "Front", "online": True},
            {"serial": "XYZ", "name": None, "online": False},
        ],
        ["serial", "name", "online"],
    )

    output = capsys.readouterr().out
    assert "serial" in output
    assert "ABC" in output
    assert "Front" in output
    assert "XYZ" in output
    assert "False" in output


class _FakeClient:
    instances: ClassVar[list[_FakeClient]] = []

    def __init__(
        self,
        account: str | None = None,
        password: str | None = None,
        url: str | None = None,
        *,
        token: dict[str, Any] | None = None,
        **_kwargs: Any,
    ) -> None:
        self.account = account
        self.password = password
        self.url = url
        self.token = token
        self.login_calls: list[int | None] = []
        self.closed = False
        self.exported_token = {"session_id": "new-session", "api_url": url}
        self.device_infos = {"CAM123": {"deviceInfos": {"name": "Front"}}}
        self.__class__.instances.append(self)

    def login(self, sms_code: int | None = None) -> None:
        self.login_calls.append(sms_code)

    def get_device_infos(self, serial: str | None = None) -> dict[str, Any]:
        if serial:
            return self.device_infos.get(serial, {})
        return self.device_infos

    def export_token(self) -> dict[str, Any]:
        return dict(self.exported_token)

    def close_session(self) -> None:
        self.closed = True


def _install_fake_client(monkeypatch) -> type[_FakeClient]:
    _FakeClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", _FakeClient)
    return _FakeClient


def test_main_requires_existing_token_or_credentials(tmp_path, caplog) -> None:
    missing_token = tmp_path / "missing-token.json"

    assert cli_module.main(["--token-file", str(missing_token), "device_infos"]) == 2

    assert "Provide --token-file" in caplog.text


def test_main_uses_existing_token_file_without_login(monkeypatch, tmp_path, capsys) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "token.json"
    token_file.write_text(
        json.dumps({"session_id": "saved-session", "api_url": "apiieu.ezvizlife.com"}),
        encoding="utf-8",
    )

    assert cli_module.main(["--token-file", str(token_file), "device_infos", "--serial", "CAM123"]) == 0

    client = fake_client.instances[0]
    assert client.account is None
    assert client.password is None
    assert client.token == {"session_id": "saved-session", "api_url": "apiieu.ezvizlife.com"}
    assert client.login_calls == []
    assert client.closed is True
    assert json.loads(capsys.readouterr().out) == {"deviceInfos": {"name": "Front"}}


def test_main_logs_in_with_credentials_and_saves_token(monkeypatch, tmp_path) -> None:
    fake_client = _install_fake_client(monkeypatch)
    token_file = tmp_path / "saved-token.json"

    assert (
        cli_module.main(
            [
                "--username",
                "user@example.test",
                "--password",
                "secret",
                "--region",
                "apiieu.ezvizlife.com",
                "--token-file",
                str(token_file),
                "--save-token",
                "device_infos",
            ]
        )
        == 0
    )

    client = fake_client.instances[0]
    assert client.login_calls == [None]
    assert client.closed is True
    assert json.loads(token_file.read_text(encoding="utf-8")) == {
        "session_id": "new-session",
        "api_url": "apiieu.ezvizlife.com",
    }


def test_main_prompts_for_mfa_code_and_retries_login(monkeypatch, tmp_path) -> None:
    class MfaClient(_FakeClient):
        def login(self, sms_code: int | None = None) -> None:
            self.login_calls.append(sms_code)
            if sms_code is None:
                raise EzvizAuthVerificationCode("MFA required")

    MfaClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MfaClient)
    monkeypatch.setattr("builtins.input", lambda _prompt: "123456")
    token_file = tmp_path / "unused-token.json"

    assert (
        cli_module.main(
            [
                "--username",
                "user@example.test",
                "--password",
                "secret",
                "--token-file",
                str(token_file),
                "device_infos",
            ]
        )
        == 0
    )

    client = MfaClient.instances[0]
    assert client.login_calls == [None, 123456]
    assert client.closed is True


def test_unifiedmsg_json_outputs_messages(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(
            self,
            *,
            serials: str | None = None,
            limit: int = 20,
            date: str | None = None,
            end_time: str = "",
        ) -> dict[str, Any]:
            self.request = {
                "serials": serials,
                "limit": limit,
                "date": date,
                "end_time": end_time,
            }
            return {
                "message": [
                    {
                        "deviceSerial": "CAM123",
                        "timeStr": "2026-04-27 08:00:00",
                        "subType": "motion",
                        "title": "Motion detected",
                    }
                ]
            }

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "unifiedmsg",
                "--serials",
                "CAM123",
                "--limit",
                "5",
                "--date",
                "20260427",
                "--end-time",
                "cursor-1",
            ]
        )
        == 0
    )

    client = cast(UnifiedClient, UnifiedClient.instances[0])
    assert client.request == {
        "serials": "CAM123",
        "limit": 5,
        "date": "20260427",
        "end_time": "cursor-1",
    }
    assert json.loads(capsys.readouterr().out) == [
        {
            "deviceSerial": "CAM123",
            "timeStr": "2026-04-27 08:00:00",
            "subType": "motion",
            "title": "Motion detected",
        }
    ]


def test_unifiedmsg_urls_only_extracts_media_urls(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(self, **_kwargs: Any) -> dict[str, Any]:
            return {
                "messages": [
                    {"deviceSerial": "CAM1", "pic": "https://example.test/pic.jpg"},
                    {
                        "deviceSerial": "CAM2",
                        "defaultPic": "https://example.test/default.jpg",
                    },
                    {
                        "deviceSerial": "CAM3",
                        "ext": {
                            "pics": "https://example.test/first.jpg;https://example.test/second.jpg"
                        },
                    },
                    {"deviceSerial": "CAM4"},
                    "not-a-message",
                ]
            }

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert cli_module.main(["--token-file", str(token_file), "unifiedmsg", "--urls-only"]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "CAM1: https://example.test/pic.jpg",
        "CAM2: https://example.test/default.jpg",
        "CAM3: https://example.test/first.jpg",
    ]


def test_unifiedmsg_table_output_handles_empty_response(monkeypatch, tmp_path, capsys) -> None:
    class UnifiedClient(_FakeClient):
        def get_device_messages_list(self, **_kwargs: Any) -> dict[str, Any]:
            return {"messages": []}

    UnifiedClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", UnifiedClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert cli_module.main(["--token-file", str(token_file), "unifiedmsg"]) == 0

    assert capsys.readouterr().out == "No unified messages returned.\n"
