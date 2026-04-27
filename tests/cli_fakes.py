from __future__ import annotations

import json
from typing import Any, ClassVar

import pyezvizapi.__main__ as cli_module


class FakeClient:
    instances: ClassVar[list[FakeClient]] = []

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


class FakeCamera:
    instances: ClassVar[list[FakeCamera]] = []

    def __init__(self, client: FakeClient, serial: str) -> None:
        self.client = client
        self.serial = serial
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.__class__.instances.append(self)

    def status(self, *, refresh: bool = True) -> dict[str, Any]:
        self.calls.append(("status", (refresh,)))
        return {"serial": self.serial, "name": "Front Door", "refresh": refresh}

    def move(self, direction: str, speed: int) -> None:
        self.calls.append(("move", (direction, speed)))

    def move_coordinates(self, x: float, y: float) -> None:
        self.calls.append(("move_coordinates", (x, y)))

    def door_unlock(self) -> None:
        self.calls.append(("door_unlock", ()))

    def gate_unlock(self) -> None:
        self.calls.append(("gate_unlock", ()))

    def switch_device_ir_led(self, enable: int) -> None:
        self.calls.append(("switch_device_ir_led", (enable,)))

    def switch_device_state_led(self, enable: int) -> None:
        self.calls.append(("switch_device_state_led", (enable,)))

    def switch_device_audio(self, enable: int) -> None:
        self.calls.append(("switch_device_audio", (enable,)))

    def switch_privacy_mode(self, enable: int) -> None:
        self.calls.append(("switch_privacy_mode", (enable,)))

    def switch_sleep_mode(self, enable: int) -> None:
        self.calls.append(("switch_sleep_mode", (enable,)))

    def switch_follow_move(self, enable: int) -> None:
        self.calls.append(("switch_follow_move", (enable,)))

    def switch_sound_alarm(self, enable: int) -> None:
        self.calls.append(("switch_sound_alarm", (enable,)))

    def alarm_sound(self, sound_type: int) -> None:
        self.calls.append(("alarm_sound", (sound_type,)))

    def alarm_notify(self, enable: int) -> None:
        self.calls.append(("alarm_notify", (enable,)))

    def alarm_detection_sensibility(self, sensibility: int) -> None:
        self.calls.append(("alarm_detection_sensibility", (sensibility,)))

    def do_not_disturb(self, enable: int) -> None:
        self.calls.append(("do_not_disturb", (enable,)))

    def change_defence_schedule(self, schedule: str) -> None:
        self.calls.append(("change_defence_schedule", (schedule,)))

    def set_battery_camera_work_mode(self, mode: Any) -> None:
        self.calls.append(("set_battery_camera_work_mode", (mode,)))


def install_fake_client(monkeypatch, client_cls: type[FakeClient] = FakeClient) -> type[FakeClient]:
    client_cls.instances = []
    monkeypatch.setattr(cli_module, "EzvizClient", client_cls)
    return client_cls


def install_fake_camera(monkeypatch) -> type[FakeCamera]:
    install_fake_client(monkeypatch)
    FakeCamera.instances = []
    monkeypatch.setattr(cli_module, "EzvizCamera", FakeCamera)
    return FakeCamera


def token_file(tmp_path) -> str:
    path = tmp_path / "token.json"
    path.write_text(json.dumps({"session_id": "saved"}), encoding="utf-8")
    return str(path)
