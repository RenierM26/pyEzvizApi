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


def test_devices_status_table_expands_switch_flags(monkeypatch, tmp_path, capsys) -> None:
    class DevicesClient(_FakeClient):
        def load_cameras(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "CAM123": {
                    "name": "Front Door",
                    "status": 1,
                    "device_category": "camera",
                    "device_sub_category": "doorbell",
                    "local_ip": "192.0.2.10",
                    "local_rtsp_port": "554",
                    "battery_level": 87,
                    "alarm_schedules_enabled": True,
                    "alarm_notify": False,
                    "Motion_Trigger": True,
                    "SWITCH": [
                        {"type": 21, "enable": 1},
                        {"type": 7, "enable": 0},
                        {"type": 22, "enable": True},
                        {"type": 10, "enable": False},
                        {"type": 3, "enable": 1},
                        {"type": "ignored", "enable": 1},
                    ],
                }
            }

    DevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", DevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "devices",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    client = cast(DevicesClient, DevicesClient.instances[0])
    assert client.refresh is False
    output = capsys.readouterr().out
    assert "serial" in output
    assert "CAM123" in output
    assert "Front Door" in output
    assert "doorbell" in output
    assert "192.0.2.10" in output
    assert "554" in output
    assert "87" in output
    # Legacy-friendly switch columns should be present in table output.
    assert "True" in output
    assert "False" in output


def test_devices_status_json_preserves_payload_without_table_enrichment(
    monkeypatch, tmp_path, capsys
) -> None:
    class DevicesClient(_FakeClient):
        def load_cameras(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "CAM123": {
                    "name": "Front Door",
                    "SWITCH": [{"type": 21, "enable": 1}],
                }
            }

    DevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", DevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "devices",
                "status",
            ]
        )
        == 0
    )

    client = cast(DevicesClient, DevicesClient.instances[0])
    assert client.refresh is True
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "CAM123": {
            "name": "Front Door",
            "SWITCH": [{"type": 21, "enable": 1}],
        }
    }
    assert "switch_flags" not in payload["CAM123"]


def test_devices_light_status_table_forwards_refresh(monkeypatch, tmp_path, capsys) -> None:
    class LightDevicesClient(_FakeClient):
        def load_light_bulbs(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {
                "LIGHT123": {
                    "name": "Porch Light",
                    "status": 1,
                    "device_category": "lighting",
                    "device_sub_category": "bulb",
                    "local_ip": "192.0.2.50",
                    "productId": "prod-light",
                    "is_on": True,
                    "brightness": 66,
                    "color_temperature": 4200,
                }
            }

    LightDevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", LightDevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "devices_light",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    client = cast(LightDevicesClient, LightDevicesClient.instances[0])
    assert client.refresh is False
    output = capsys.readouterr().out
    assert "LIGHT123" in output
    assert "Porch Light" in output
    assert "lighting" in output
    assert "192.0.2.50" in output
    assert "prod-light" in output
    assert "66" in output
    assert "4200" in output


def test_devices_light_status_json_preserves_payload(monkeypatch, tmp_path, capsys) -> None:
    class LightDevicesClient(_FakeClient):
        def load_light_bulbs(self, *, refresh: bool = True) -> dict[str, dict[str, Any]]:
            self.refresh = refresh
            return {"LIGHT123": {"name": "Porch Light", "is_on": True}}

    LightDevicesClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", LightDevicesClient)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "--json",
                "devices_light",
                "status",
            ]
        )
        == 0
    )

    client = cast(LightDevicesClient, LightDevicesClient.instances[0])
    assert client.refresh is True
    assert json.loads(capsys.readouterr().out) == {
        "LIGHT123": {"name": "Porch Light", "is_on": True}
    }


def test_light_status_outputs_json(monkeypatch, tmp_path, capsys) -> None:
    class FakeLightBulb:
        instances: ClassVar[list[FakeLightBulb]] = []

        def __init__(self, client: _FakeClient, serial: str) -> None:
            self.client = client
            self.serial = serial
            self.toggled = False
            self.__class__.instances.append(self)

        def status(self) -> dict[str, Any]:
            return {"serial": self.serial, "name": "Porch Light", "is_on": True}

        def toggle_switch(self) -> None:
            self.toggled = True

    _install_fake_client(monkeypatch)
    FakeLightBulb.instances = []
    monkeypatch.setattr(cli_module, "EzvizLightBulb", FakeLightBulb)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "light",
                "--serial",
                "LIGHT123",
                "status",
            ]
        )
        == 0
    )

    light = FakeLightBulb.instances[0]
    assert light.serial == "LIGHT123"
    assert json.loads(capsys.readouterr().out) == {
        "serial": "LIGHT123",
        "name": "Porch Light",
        "is_on": True,
    }


def test_light_toggle_invokes_light_wrapper(monkeypatch, tmp_path) -> None:
    class FakeLightBulb:
        instances: ClassVar[list[FakeLightBulb]] = []

        def __init__(self, client: _FakeClient, serial: str) -> None:
            self.client = client
            self.serial = serial
            self.toggled = False
            self.__class__.instances.append(self)

        def status(self) -> dict[str, Any]:
            return {}

        def toggle_switch(self) -> None:
            self.toggled = True

    _install_fake_client(monkeypatch)
    FakeLightBulb.instances = []
    monkeypatch.setattr(cli_module, "EzvizLightBulb", FakeLightBulb)
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")

    assert (
        cli_module.main(
            [
                "--token-file",
                str(token_file),
                "light",
                "--serial",
                "LIGHT123",
                "toggle",
            ]
        )
        == 0
    )

    light = FakeLightBulb.instances[0]
    assert light.serial == "LIGHT123"
    assert light.toggled is True
