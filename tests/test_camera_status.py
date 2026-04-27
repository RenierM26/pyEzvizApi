from __future__ import annotations

import time
from typing import Any, cast

from pyezvizapi.camera import EzvizCamera
from pyezvizapi.client import EzvizClient
from pyezvizapi.models import EzvizDeviceRecord


def _camera_payload() -> dict:
    return {
        "deviceInfos": {
            "name": "Front Door",
            "version": "1.2.3",
            "status": 1,
            "deviceCategory": "camera",
            "deviceSubCategory": "doorbell",
            "supportExt": {"SupportExt": "1"},
            "mac": "AA:BB:CC:DD:EE:FF",
            "offlineNotify": 1,
            "offlineTime": "2026-04-26 10:00:00",
            "channelNumber": 2,
        },
        "STATUS": {
            "globalStatus": 1,
            "alarmSoundMode": 0,
            "isEncrypt": 1,
            "encryptPwd": "hashed",
            "upgradeProcess": 42,
            "upgradeStatus": 0,
            "pirStatus": 1,
            "optionals": {
                "powerRemaining": 87,
                "timeZone": "UTC+02:00",
                "Alarm_Light": {"luminance": 55},
                "Alarm_DetectHumanCar": {"type": 3},
                "diskCapacity": "64,32",
                "NightVision_Model": 2,
                "batteryCameraWorkMode": 1,
                "Alarm_AdvancedDetect": {"type": 4},
            },
        },
        "CONNECTION": {
            "localIp": "192.0.2.25",
            "netIp": "198.51.100.25",
            "localRtspPort": 0,
        },
        "WIFI": {"address": "0.0.0.0"},
        "UPGRADE": {"isNeedUpgrade": 3, "upgradePackageInfo": {"version": "1.2.4"}},
        "TIME_PLAN": [{"type": 2, "enable": 1}],
        "NODISTURB": {"alarmEnable": 0, "callingEnable": 1},
        "SWITCH": [
            {"type": 7, "enable": 1},
            {"type": 21, "enable": 0},
            {"type": "ignored", "enable": 1},
        ],
        "resourceInfos": [{"resourceId": "Video", "localIndex": 1}],
        "CUSTOM_TOP_LEVEL": {"kept": True},
    }


def test_camera_status_extracts_integration_facing_keys_without_refresh() -> None:
    camera = EzvizCamera(
        cast(EzvizClient, object()),
        "CAM123",
        device_obj=_camera_payload(),
    )

    status = camera.status(refresh=False)

    assert status["serial"] == "CAM123"
    assert status["name"] == "Front Door"
    assert status["version"] == "1.2.3"
    assert status["status"] == 1
    assert status["device_category"] == "camera"
    assert status["device_sub_category"] == "doorbell"
    assert status["upgrade_available"] is True
    assert status["upgrade_percent"] == 42
    assert status["upgrade_in_progress"] is True
    assert status["alarm_notify"] is True
    assert status["alarm_schedules_enabled"] is True
    assert status["encrypted"] is True
    assert status["encrypted_pwd_hash"] == "hashed"
    assert status["local_ip"] == "192.0.2.25"
    assert status["wan_ip"] == "198.51.100.25"
    assert status["supportExt"] == {"SupportExt": "1"}
    assert status["optionals"]["powerRemaining"] == 87
    assert status["switches"] == {7: True, 21: False}
    assert status["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert status["offline_notify"] is True
    assert status["last_offline_time"] == "2026-04-26 10:00:00"
    assert status["local_rtsp_port"] == "554"
    assert status["supported_channels"] == 2
    assert status["battery_level"] == 87
    assert status["PIR_Status"] == 1
    assert status["Motion_Trigger"] is False
    assert status["Seconds_Last_Trigger"] is None
    assert status["cam_timezone"] == "UTC+02:00"
    assert status["push_notify_alarm"] is True
    assert status["push_notify_call"] is False
    assert status["alarm_light_luminance"] == 55
    assert status["Alarm_DetectHumanCar"] == 3
    assert status["diskCapacity"] == ["64", "32"]
    assert status["NightVision_Model"] == 2
    assert status["battery_camera_work_mode"] == 1
    assert status["Alarm_AdvancedDetect"] == 4
    assert status["resouceid"] == "Video"
    assert cast(dict[str, Any], status)["CUSTOM_TOP_LEVEL"] == {"kept": True}


def test_camera_status_uses_prefetched_alarm_without_network_refresh() -> None:
    camera = EzvizCamera(
        cast(EzvizClient, object()),
        "CAM123",
        device_obj=_camera_payload(),
    )
    now_ms = int((time.time() - 5) * 1000)

    status = camera.status(
        refresh=True,
        latest_alarm={
            "deviceSerial": "CAM123",
            "time": now_ms,
            "title": "Motion detected",
            "ext": {
                "alarmType": "10000",
                "pics": "https://example.test/first.jpg;https://example.test/second.jpg",
                "picChecksum": "checksum",
                "picCrypt": "0",
            },
        },
    )

    assert status["Motion_Trigger"] is True
    assert status["Seconds_Last_Trigger"] < 60
    assert status["last_alarm_pic"] == "https://example.test/first.jpg"
    assert status["last_alarm_type_code"] == "10000"
    assert status["last_alarm_type_name"] == "Motion detected"


def test_camera_status_prefers_typed_record_core_fields_and_switches() -> None:
    payload = _camera_payload()
    payload["deviceInfos"]["name"] = "Back Yard"
    record = EzvizDeviceRecord.from_api("CAM456", payload)

    camera = EzvizCamera(
        cast(EzvizClient, object()),
        "CAM456",
        device_obj=record,
    )

    status = camera.status(refresh=False)

    assert status["serial"] == "CAM456"
    assert status["name"] == "Back Yard"
    assert status["supportExt"] == {"SupportExt": "1"}
    assert status["switches"] == {7: True, 21: False}
    assert cast(dict[str, Any], status)["CUSTOM_TOP_LEVEL"] == {"kept": True}


def test_camera_fetch_key_and_refresh_alarms_delegate(monkeypatch) -> None:
    camera = EzvizCamera(cast(EzvizClient, object()), "CAM123", _camera_payload())
    calls = 0

    def fake_alarm_list(prefetched: dict[str, object] | None = None) -> None:
        nonlocal calls
        assert prefetched is None
        calls += 1

    monkeypatch.setattr(camera, "_alarm_list", fake_alarm_list)

    assert camera.fetch_key(["deviceInfos", "name"]) == "Front Door"
    assert camera.fetch_key(["missing"], default_value="fallback") == "fallback"
    camera.refresh_alarms()

    assert calls == 1
