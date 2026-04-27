from __future__ import annotations

from typing import cast

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import DeviceSwitchType
from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.light_bulb import EzvizLightBulb
from pyezvizapi.models import EzvizDeviceRecord
from pyezvizapi.smart_plug import EzvizSmartPlug


def _feature_json() -> str:
    return (
        '{"productId": "prod-light", "featureItemDtos": ['
        '{"itemKey": "light_switch", "dataValue": true},'
        '{"itemKey": "brightness", "dataValue": 66},'
        '{"itemKey": "color_temperature", "dataValue": 4200}'
        "]}"
    )


def _light_payload() -> dict:
    return {
        "deviceInfos": {
            "name": "Porch Light",
            "version": "2.0.0",
            "status": 1,
            "deviceCategory": "lighting",
            "deviceSubCategory": "bulb",
            "supportExt": {"SupportExt": "light"},
            "mac": "AA:AA:AA:AA:AA:AA",
            "channelNumber": 1,
            "ezDeviceCapability": {"capable": True},
        },
        "STATUS": {
            "upgradeProcess": 25,
            "upgradeStatus": 0,
            "optionals": {"mode": "warm"},
        },
        "CONNECTION": {"localIp": "192.0.2.50", "netIp": "198.51.100.50"},
        "WIFI": {"address": "0.0.0.0", "ssid": "TestWifi"},
        "UPGRADE": {"isNeedUpgrade": 3, "upgradePackageInfo": {"version": "2.0.1"}},
        "SWITCH": [{"type": 7, "enable": 1}],
        "FEATURE": {"featureJson": _feature_json()},
    }


def _plug_payload() -> dict:
    return {
        "deviceInfos": {
            "name": "Heater Plug",
            "version": "3.0.0",
            "status": 1,
            "deviceCategory": "Socket",
            "deviceSubCategory": "plug",
            "supportExt": {"SupportExt": "plug"},
            "mac": "BB:BB:BB:BB:BB:BB",
            "channelNumber": 1,
            "ezDeviceCapability": {"power": True},
        },
        "STATUS": {
            "upgradeProcess": 0,
            "upgradeStatus": 1,
            "optionals": {"child_lock": False},
        },
        "CONNECTION": {"localIp": "192.0.2.60", "netIp": "198.51.100.60"},
        "WIFI": {"address": "192.0.2.61", "ssid": "TestWifi"},
        "UPGRADE": {"isNeedUpgrade": 0, "upgradePackageInfo": None},
        "SWITCH": [
            {"type": DeviceSwitchType.PLUG.value, "enable": 1},
            {"type": 600, "enable": 0},
            {"type": "ignored", "enable": 1},
        ],
    }


def test_light_status_extracts_feature_values_and_fallbacks() -> None:
    light = EzvizLightBulb(cast(EzvizClient, object()), "LIGHT123", _light_payload())

    status = light.status()

    assert status["serial"] == "LIGHT123"
    assert status["name"] == "Porch Light"
    assert status["version"] == "2.0.0"
    assert status["upgrade_available"] is True
    assert status["status"] == 1
    assert status["device_category"] == "lighting"
    assert status["device_sub_category"] == "bulb"
    assert status["upgrade_percent"] == 25
    assert status["upgrade_in_progress"] is True
    assert status["latest_firmware_info"] == {"version": "2.0.1"}
    assert status["local_ip"] == "192.0.2.50"
    assert status["wan_ip"] == "198.51.100.50"
    assert status["mac_address"] == "AA:AA:AA:AA:AA:AA"
    assert status["supported_channels"] == 1
    assert status["wifiInfos"] == {"address": "0.0.0.0", "ssid": "TestWifi"}
    assert status["switches"] == {7: True, DeviceSwitchType.ALARM_LIGHT.value: True}
    assert status["optionals"] == {"mode": "warm"}
    assert status["supportExt"] == {"SupportExt": "light"}
    assert status["ezDeviceCapability"] == {"capable": True}
    assert status["productId"] == "prod-light"
    assert status["is_on"] is True
    assert status["brightness"] == 66
    assert status["alarm_light_luminance"] == 66
    assert status["color_temperature"] == 4200


def test_light_status_accepts_typed_device_record() -> None:
    record = EzvizDeviceRecord.from_api("LIGHT456", _light_payload())

    light = EzvizLightBulb(cast(EzvizClient, object()), "LIGHT456", record)

    status = light.status()

    assert status["serial"] == "LIGHT456"
    assert status["name"] == "Porch Light"
    assert status["switches"][DeviceSwitchType.ALARM_LIGHT.value] is True


def test_light_invalid_feature_json_raises_library_error() -> None:
    payload = _light_payload()
    payload["FEATURE"] = {"featureJson": "not json"}

    with pytest.raises(PyEzvizError, match="Impossible to decode FEATURE"):
        EzvizLightBulb(cast(EzvizClient, object()), "LIGHT123", payload)


def test_smart_plug_status_extracts_switch_state_and_wifi_ip() -> None:
    plug = EzvizSmartPlug(cast(EzvizClient, object()), "PLUG123", _plug_payload())

    status = plug.status()

    assert status["serial"] == "PLUG123"
    assert status["name"] == "Heater Plug"
    assert status["version"] == "3.0.0"
    assert status["upgrade_available"] is False
    assert status["status"] == 1
    assert status["device_category"] == "Socket"
    assert status["device_sub_category"] == "plug"
    assert status["upgrade_percent"] == 0
    assert status["upgrade_in_progress"] is False
    assert status["latest_firmware_info"] is None
    assert status["local_ip"] == "192.0.2.61"
    assert status["wan_ip"] == "198.51.100.60"
    assert status["mac_address"] == "BB:BB:BB:BB:BB:BB"
    assert status["supported_channels"] == 1
    assert status["wifiInfos"] == {"address": "192.0.2.61", "ssid": "TestWifi"}
    assert status["switches"] == {DeviceSwitchType.PLUG.value: True, 600: False}
    assert status["optionals"] == {"child_lock": False}
    assert status["supportExt"] == {"SupportExt": "plug"}
    assert status["ezDeviceCapability"] == {"power": True}
    assert status["is_on"] is True


def test_smart_plug_status_accepts_typed_device_record() -> None:
    record = EzvizDeviceRecord.from_api("PLUG456", _plug_payload())

    plug = EzvizSmartPlug(cast(EzvizClient, object()), "PLUG456", record)

    status = plug.status()

    assert status["serial"] == "PLUG456"
    assert status["name"] == "Heater Plug"
    assert status["is_on"] is True
