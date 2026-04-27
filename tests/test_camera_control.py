from __future__ import annotations

from typing import Any, cast

import pytest

from pyezvizapi.camera import EzvizCamera
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import BatteryCameraWorkMode, DeviceSwitchType
from pyezvizapi.exceptions import PyEzvizError


class _FakeCameraClient:
    def __init__(self) -> None:
        self._token = {"username": "user@example.test"}
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def _record(self, name: str, *args: Any, **kwargs: Any) -> bool:
        self.calls.append((name, args, kwargs))
        return True

    def ptz_control(self, direction: str, serial: str, command: str, speed: int) -> bool:
        return self._record("ptz_control", direction, serial, command, speed)

    def ptz_control_coordinates(self, serial: str, x_axis: float, y_axis: float) -> bool:
        return self._record("ptz_control_coordinates", serial, x_axis, y_axis)

    def remote_unlock(self, serial: str, user: str, lock_id: int, **kwargs: Any) -> bool:
        return self._record("remote_unlock", serial, user, lock_id, **kwargs)

    def remote_lock(self, serial: str, user: str, lock_id: int, **kwargs: Any) -> bool:
        return self._record("remote_lock", serial, user, lock_id, **kwargs)

    def set_camera_defence(self, serial: str, enable: int) -> bool:
        return self._record("set_camera_defence", serial, enable)

    def alarm_sound(self, serial: str, sound_type: int, enable: int) -> bool:
        return self._record("alarm_sound", serial, sound_type, enable)

    def do_not_disturb(self, serial: str, enable: int) -> bool:
        return self._record("do_not_disturb", serial, enable)

    def detection_sensibility(self, serial: str, sensitivity: int, type_value: int) -> bool:
        return self._record("detection_sensibility", serial, sensitivity, type_value)

    def switch_status(self, serial: str, switch_type: int, enable: int) -> bool:
        return self._record("switch_status", serial, switch_type, enable)

    def sound_alarm(self, serial: str, enable: int) -> bool:
        return self._record("sound_alarm", serial, enable)

    def api_set_defence_schedule(self, serial: str, schedule: str, enable: int) -> bool:
        return self._record("api_set_defence_schedule", serial, schedule, enable)

    def set_battery_camera_work_mode(self, serial: str, mode: int) -> bool:
        return self._record("set_battery_camera_work_mode", serial, mode)


def _camera(client: _FakeCameraClient | None = None) -> tuple[EzvizCamera, _FakeCameraClient]:
    fake_client = client or _FakeCameraClient()
    camera = EzvizCamera(
        cast(EzvizClient, fake_client),
        "CAM123",
        device_obj={
            "deviceInfos": {"name": "Front Door"},
            "STATUS": {"optionals": {"timeZone": "UTC+02:00"}},
            "resourceInfos": [
                {
                    "resourceId": "DoorLock",
                    "localIndex": 2,
                    "streamToken": "stream-token",
                    "type": "lock",
                }
            ],
        },
    )
    return camera, fake_client


def test_camera_move_sends_start_and_stop_ptz_commands() -> None:
    camera, client = _camera()

    assert camera.move("left", speed=4) is True

    assert client.calls == [
        ("ptz_control", ("LEFT", "CAM123", "START", 4), {}),
        ("ptz_control", ("LEFT", "CAM123", "STOP", 4), {}),
    ]


def test_camera_move_rejects_invalid_speed() -> None:
    camera, client = _camera()

    with pytest.raises(PyEzvizError, match="Invalid speed"):
        camera.move("right", speed=0)

    assert client.calls == []


def test_camera_coordinates_and_locks_forward_resource_route() -> None:
    camera, client = _camera()

    assert camera.move_coordinates(0.25, 0.75) is True
    assert camera.door_unlock() is True
    assert camera.gate_unlock() is True
    assert camera.door_lock() is True
    assert camera.gate_lock() is True

    assert client.calls == [
        ("ptz_control_coordinates", ("CAM123", 0.25, 0.75), {}),
        (
            "remote_unlock",
            ("CAM123", "user@example.test", 2),
            {
                "resource_id": "DoorLock",
                "local_index": "2",
                "stream_token": "stream-token",
                "lock_type": "lock",
            },
        ),
        (
            "remote_unlock",
            ("CAM123", "user@example.test", 1),
            {
                "resource_id": "DoorLock",
                "local_index": "2",
                "stream_token": "stream-token",
                "lock_type": "lock",
            },
        ),
        (
            "remote_lock",
            ("CAM123", "user@example.test", 2),
            {
                "resource_id": "DoorLock",
                "local_index": "2",
                "stream_token": "stream-token",
                "lock_type": "lock",
            },
        ),
        (
            "remote_lock",
            ("CAM123", "user@example.test", 1),
            {
                "resource_id": "DoorLock",
                "local_index": "2",
                "stream_token": "stream-token",
                "lock_type": "lock",
            },
        ),
    ]


def test_camera_alarm_control_methods_forward_to_client() -> None:
    camera, client = _camera()

    assert camera.alarm_notify(True) is True
    assert camera.alarm_sound(1) is True
    assert camera.do_not_disturb(False) is True
    assert camera.alarm_detection_sensitivity(42, type_value=3) is True
    assert camera.alarm_detection_sensibility(24) is True
    assert camera.change_defence_schedule('{"enabled": true}', enable=1) is True

    assert client.calls == [
        ("set_camera_defence", ("CAM123", 1), {}),
        ("alarm_sound", ("CAM123", 1, 1), {}),
        ("do_not_disturb", ("CAM123", 0), {}),
        ("detection_sensibility", ("CAM123", 42, 3), {}),
        ("detection_sensibility", ("CAM123", 24, 0), {}),
        ("api_set_defence_schedule", ("CAM123", '{"enabled": true}', 1), {}),
    ]


def test_camera_switch_helpers_forward_device_switch_values() -> None:
    camera, client = _camera()

    assert camera.set_switch(DeviceSwitchType.PRIVACY, True) is True
    assert camera.switch_device_audio(True) is True
    assert camera.switch_device_state_led(False) is True
    assert camera.switch_device_ir_led(True) is True
    assert camera.switch_privacy_mode(False) is True
    assert camera.switch_sleep_mode(True) is True
    assert camera.switch_follow_move(True) is True
    assert camera.switch_sound_alarm(2) is True

    assert client.calls == [
        ("switch_status", ("CAM123", DeviceSwitchType.PRIVACY.value, 1), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.SOUND.value, 1), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.LIGHT.value, 0), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.INFRARED_LIGHT.value, 1), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.PRIVACY.value, 0), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.SLEEP.value, 1), {}),
        ("switch_status", ("CAM123", DeviceSwitchType.MOBILE_TRACKING.value, 1), {}),
        ("sound_alarm", ("CAM123", 2), {}),
    ]


def test_camera_battery_work_mode_forwards_enum_value() -> None:
    camera, client = _camera()

    assert camera.set_battery_camera_work_mode(BatteryCameraWorkMode.POWER_SAVE) is True

    assert client.calls == [
        ("set_battery_camera_work_mode", ("CAM123", BatteryCameraWorkMode.POWER_SAVE.value), {})
    ]
