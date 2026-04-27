from __future__ import annotations

import importlib.util
import json
from typing import Any, ClassVar, cast

from cli_fakes import (
    FakeClient as _FakeClient,
    install_fake_camera as _install_fake_camera,
    install_fake_client as _install_fake_client,
    token_file as _token_file,
)

import pyezvizapi.__main__ as cli_module
from pyezvizapi.exceptions import EzvizAuthVerificationCode, PyEzvizError

_format_cell = cli_module._format_cell  # noqa: SLF001
_write_table = cli_module._write_table  # noqa: SLF001


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


def test_camera_status_outputs_json_and_forwards_refresh(monkeypatch, tmp_path, capsys) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "status",
                "--no-refresh",
            ]
        )
        == 0
    )

    camera = fake_camera.instances[0]
    assert camera.serial == "CAM123"
    assert camera.calls == [("status", (False,))]
    assert json.loads(capsys.readouterr().out) == {
        "serial": "CAM123",
        "name": "Front Door",
        "refresh": False,
    }


def test_camera_move_and_coordinate_commands_dispatch(monkeypatch, tmp_path) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "move",
                "--direction",
                "left",
                "--speed",
                "7",
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("move", ("left", 7))]

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "move_coords",
                "--x",
                "0.25",
                "--y",
                "0.75",
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("move_coordinates", (0.25, 0.75))]


def test_camera_lock_and_switch_commands_dispatch(monkeypatch, tmp_path, capsys) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            ["--token-file", _token_file(tmp_path), "camera", "--serial", "CAM123", "unlock-door"]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("door_unlock", ())]

    assert (
        cli_module.main(
            ["--token-file", _token_file(tmp_path), "camera", "--serial", "CAM123", "unlock-gate"]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [("gate_unlock", ())]

    switch_cases = [
        ("ir", "switch_device_ir_led", 0),
        ("state", "switch_device_state_led", 1),
        ("audio", "switch_device_audio", 1),
        ("privacy", "switch_privacy_mode", 1),
        ("sleep", "switch_sleep_mode", 1),
        ("follow_move", "switch_follow_move", 1),
        ("sound_alarm", "switch_sound_alarm", 2),
    ]
    for switch_name, method_name, expected_enable in switch_cases:
        assert (
            cli_module.main(
                [
                    "--token-file",
                    _token_file(tmp_path),
                    "camera",
                    "--serial",
                    "CAM123",
                    "switch",
                    "--switch",
                    switch_name,
                    "--enable",
                    "1" if switch_name != "ir" else "0",
                ]
            )
            == 0
        )
        assert fake_camera.instances[-1].calls == [(method_name, (expected_enable,))]

    assert "1" in capsys.readouterr().out


def test_camera_alarm_and_select_commands_dispatch(monkeypatch, tmp_path) -> None:
    fake_camera = _install_fake_camera(monkeypatch)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "alarm",
                "--sound",
                "1",
                "--notify",
                "0",
                "--sensibility",
                "42",
                "--do_not_disturb",
                "1",
                "--schedule",
                '{"enabled": true}',
            ]
        )
        == 0
    )
    assert fake_camera.instances[-1].calls == [
        ("alarm_sound", (1,)),
        ("alarm_notify", (0,)),
        ("alarm_detection_sensibility", (42,)),
        ("do_not_disturb", (1,)),
        ("change_defence_schedule", ('{"enabled": true}',)),
    ]

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "camera",
                "--serial",
                "CAM123",
                "select",
                "--battery_work_mode",
                "POWER_SAVE",
            ]
        )
        == 0
    )
    method_name, args = fake_camera.instances[-1].calls[0]
    assert method_name == "set_battery_camera_work_mode"
    assert args[0].name == "POWER_SAVE"


def test_pagelist_outputs_raw_json(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def get_page_list(self) -> dict[str, Any]:
            return {"deviceInfos": [{"deviceSerial": "CAM123"}]}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "pagelist"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "deviceInfos": [{"deviceSerial": "CAM123"}]
    }
    assert MiscClient.instances[0].closed is True


def test_device_infos_outputs_all_or_filtered_serial(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def get_device_infos(self, serial: str | None = None) -> dict[str, Any]:
            self.requested_serial = serial
            if serial:
                return {"deviceInfos": {"deviceSerial": serial}}
            return {"CAM123": {"deviceInfos": {"name": "Front"}}}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "device_infos"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "CAM123": {"deviceInfos": {"name": "Front"}}
    }
    assert cast(MiscClient, MiscClient.instances[-1]).requested_serial is None

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "device_infos",
                "--serial",
                "CAM456",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "deviceInfos": {"deviceSerial": "CAM456"}
    }
    assert cast(MiscClient, MiscClient.instances[-1]).requested_serial == "CAM456"


def test_home_defence_mode_dispatches_selected_mode(monkeypatch, tmp_path, capsys) -> None:
    class MiscClient(_FakeClient):
        def api_set_defence_mode(self, mode: int) -> dict[str, Any]:
            self.mode = mode
            return {"mode": mode, "result": "ok"}

    MiscClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", MiscClient)

    assert (
        cli_module.main(
            [
                "--token-file",
                _token_file(tmp_path),
                "home_defence_mode",
                "--mode",
                "HOME_MODE",
            ]
        )
        == 0
    )

    client = cast(MiscClient, MiscClient.instances[0])
    assert isinstance(client.mode, int)
    assert json.loads(capsys.readouterr().out) == {"mode": client.mode, "result": "ok"}


def test_home_defence_mode_without_mode_returns_not_implemented(monkeypatch, tmp_path) -> None:
    _install_fake_client(monkeypatch)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "home_defence_mode"]) == 2


def test_pyezviz_error_returns_cli_error(monkeypatch, tmp_path, caplog) -> None:
    class ErrorClient(_FakeClient):
        def get_page_list(self) -> dict[str, Any]:
            raise PyEzvizError("cloud exploded")

    ErrorClient.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", ErrorClient)

    assert cli_module.main(["--token-file", _token_file(tmp_path), "pagelist"]) == 1

    assert "cloud exploded" in caplog.text
    assert ErrorClient.instances[0].closed is True
