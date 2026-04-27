from __future__ import annotations

from typing import Any

import pyezvizapi.client as client_module
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import DeviceCatagories


def _page_list_fixture() -> dict[str, Any]:
    return {
        "deviceInfos": [
            {
                "deviceSerial": "CAM123",
                "name": "Front Camera",
                "deviceCategory": DeviceCatagories.CAMERA_DEVICE_CATEGORY.value,
                "deviceSubCategory": "C3X",
                "status": 1,
                "version": "1.0.0",
                "supportExt": '{"SupportExt": "camera"}',
            },
            {
                "deviceSerial": "LIGHT123",
                "name": "Porch Light",
                "deviceCategory": DeviceCatagories.LIGHTING.value,
                "deviceSubCategory": "bulb",
                "status": 1,
                "supportExt": "{}",
            },
            {
                "deviceSerial": "PLUG123",
                "name": "Heater Plug",
                "deviceCategory": DeviceCatagories.SOCKET.value,
                "deviceSubCategory": "plug",
                "status": 1,
                "supportExt": "{}",
            },
            {
                "deviceSerial": "COMMON123",
                "name": "Unsupported Common Device",
                "deviceCategory": DeviceCatagories.COMMON_DEVICE_CATEGORY.value,
                "status": 1,
                "hik": False,
            },
        ],
        "CLOUD": {
            "res-cam": {"deviceSerial": "CAM123", "cloud": True},
            "res-light": {"deviceSerial": "LIGHT123", "cloud": True},
            "res-plug": {"deviceSerial": "PLUG123", "cloud": True},
        },
        "VTM": {
            "res-cam": {"batteryLevel": 87},
            "res-light": {},
            "res-plug": {},
        },
        "P2P": {"CAM123": {"p2p": True}},
        "CONNECTION": {"CAM123": {"localIp": "192.0.2.10"}},
        "KMS": {"CAM123": {"kms": True}},
        "STATUS": {
            "CAM123": {"globalStatus": 1, "optionals": {"NightVision_Model": "{}"}},
            "LIGHT123": {"globalStatus": 1},
            "PLUG123": {"globalStatus": 1},
        },
        "TIME_PLAN": {"CAM123": {"schedule": True}},
        "CHANNEL": {"res-cam": {"channelNo": 1}},
        "QOS": {"CAM123": {"qos": True}},
        "NODISTURB": {"CAM123": {"enabled": False}},
        "FEATURE": {"CAM123": {"featureJson": "{}"}},
        "UPGRADE": {"CAM123": {"latestVersion": "1.0.1"}},
        "FEATURE_INFO": {"CAM123": {"0": {"Video": {}}}},
        "SWITCH": {"CAM123": [{"type": 7, "enable": 1}]},
        "CUSTOM_TAG": {"CAM123": {"tag": "front"}},
        "VIDEO_QUALITY": {"res-cam": {"quality": "hd"}},
        "resourceInfos": [
            {"deviceSerial": "CAM123", "resourceId": "res-cam"},
            {"deviceSerial": "OTHER", "resourceId": "res-other"},
        ],
        "WIFI": {"CAM123": {"address": "192.0.2.10"}},
    }


def _client_with_fixture(monkeypatch) -> EzvizClient:
    client = EzvizClient(token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"})
    monkeypatch.setattr(client, "_get_page_list", _page_list_fixture)
    return client


def test_get_device_infos_builds_serial_keyed_payloads(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    devices = client.get_device_infos()

    assert set(devices) == {"CAM123", "LIGHT123", "PLUG123", "COMMON123"}
    camera = devices["CAM123"]
    assert camera["deviceInfos"]["supportExt"] == {"SupportExt": "camera"}
    assert camera["CLOUD"] == {"res-cam": {"deviceSerial": "CAM123", "cloud": True}}
    assert camera["CHANNEL"] == {"res-cam": {"channelNo": 1}}
    assert camera["VIDEO_QUALITY"] == {"res-cam": {"quality": "hd"}}
    assert camera["resourceInfos"] == [
        {"deviceSerial": "CAM123", "resourceId": "res-cam"}
    ]
    assert camera["SWITCH"] == [{"type": 7, "enable": 1}]


def test_get_device_infos_can_filter_to_one_serial(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    camera = client.get_device_infos("CAM123")

    assert camera["deviceInfos"]["name"] == "Front Camera"
    assert client.get_device_infos("MISSING") == {}


def test_load_devices_routes_supported_categories(monkeypatch) -> None:
    client = _client_with_fixture(monkeypatch)

    class FakeCamera:
        def __init__(self, _client: EzvizClient, serial: str, device_obj: dict[str, Any]) -> None:
            self.serial = serial
            self.device_obj = device_obj

        def status(self, *, refresh: bool = True, latest_alarm: dict[str, Any] | None = None) -> dict[str, Any]:
            return {
                "kind": "camera",
                "serial": self.serial,
                "refresh": refresh,
                "latest_alarm": latest_alarm,
                "name": self.device_obj["deviceInfos"]["name"],
            }

    class FakeLightBulb:
        def __init__(self, _client: EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "light", "serial": self.serial}

    class FakeSmartPlug:
        def __init__(self, _client: EzvizClient, serial: str, _device_obj: dict[str, Any]) -> None:
            self.serial = serial

        def status(self) -> dict[str, Any]:
            return {"kind": "plug", "serial": self.serial}

    monkeypatch.setattr(client_module, "EzvizCamera", FakeCamera)
    monkeypatch.setattr(client_module, "EzvizLightBulb", FakeLightBulb)
    monkeypatch.setattr(client_module, "EzvizSmartPlug", FakeSmartPlug)

    loaded = client.load_devices(refresh=False)

    assert loaded == {
        "CAM123": {
            "kind": "camera",
            "serial": "CAM123",
            "refresh": False,
            "latest_alarm": None,
            "name": "Front Camera",
        },
        "LIGHT123": {"kind": "light", "serial": "LIGHT123"},
        "PLUG123": {"kind": "plug", "serial": "PLUG123"},
    }
    assert "COMMON123" not in loaded
