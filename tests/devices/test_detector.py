"""Synthetic PR99-shaped sensor payloads; no account, hardware or control actions."""

from copy import deepcopy
import json
import logging
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from pyezvizapi import EzvizClient, EzvizDetector
from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.devices import factory
from pyezvizapi.devices.detector import EzvizDetector as CanonicalDetector
from pyezvizapi.models import EzvizDeviceRecord

FIXTURE = Path(__file__).parents[1] / "fixtures/detector_page_list.json"


@pytest.fixture
def client():
    value = EzvizClient()
    try:
        yield value
    finally:
        value.close_session()


def page():
    return json.loads(FIXTURE.read_text())


def payload(serial="CONTACT001"):
    data = page()
    return {
        "deviceInfos": next(v for v in data["deviceInfos"] if v["deviceSerial"] == serial),
        "FEATURE_INFO": data["FEATURE_INFO"][serial],
    }


def forbidden(*args, **kwargs):
    pytest.fail("Unexpected account/camera operation")


def test_contact_preserves_zero_false_and_unknown_properties():
    value = payload()
    before = deepcopy(value)
    result = EzvizDetector(
        SimpleNamespace(get_device_infos=forbidden), "CONTACT001", value
    ).status()
    assert result["name"] == "Synthetic contact" and result["version"] == "V1.0"
    assert result["device_category"] == "Detector" and result["device_sub_category"] == "T2C"
    assert result["door_status"] == 1 and result["battery_level"] == 0
    assert result["door_open_remind"] is False and result["door_closed_remind"] == 0
    assert result["door_open_gateway_alarm"] == 1 and result["door_closed_gateway_alarm"] == 0
    assert result["door_open_detection_time"] == 30
    assert result["water_leak_status"] is None and result["siren_work_state"] is None
    assert result["switches"] == {} and value == before


def test_water_and_siren_extract_nested_properties():
    water = EzvizDetector(None, "WATER00001", payload("WATER00001")).status()
    assert water["water_leak_status"] == 0 and water["battery_level"] == 75
    siren = EzvizDetector(None, "SIREN00001", payload("SIREN00001")).status()
    assert siren["status"] == 0
    assert siren["siren_work_state"] == 0 and siren["siren_alarm_volume"] == 0
    assert siren["siren_alarm_duration"] == 60 and siren["siren_tamper_detection"] is False
    assert siren["siren_motion_detection"] == 1 and siren["zigbee_signal"] == -65
    assert siren["power_mode"] == 1 and siren["battery_level"] is None


@pytest.mark.parametrize("wrapped", [False, True])
def test_record_and_lookup_constructors(wrapped):
    raw = payload()
    data = EzvizDeviceRecord.from_api("CONTACT001", raw) if wrapped else MappingProxyType(raw)
    detector = EzvizDetector(None, "CONTACT001", data)
    assert detector.status()["door_status"] == 1
    calls = []

    def lookup(serial):
        calls.append(serial)
        return raw

    client = SimpleNamespace(get_device_infos=lookup)
    assert EzvizDetector(client, "CONTACT001").status() == detector.status()
    assert calls == ["CONTACT001"]


@pytest.mark.parametrize("value", [None, False, 0, "bad", [], [1]])
@pytest.mark.parametrize("level", ["FEATURE_INFO", "channel", "global", "domain"])
def test_partial_or_malformed_feature_containers_stay_unknown(value, level):
    raw = payload()
    if level == "FEATURE_INFO":
        raw["FEATURE_INFO"] = value
    elif level == "channel":
        raw["FEATURE_INFO"]["0"] = value
    elif level == "global":
        raw["FEATURE_INFO"]["0"]["global"] = value
    else:
        raw["FEATURE_INFO"]["0"]["global"]["DoorMagnetic"] = value
    result = EzvizDetector(None, "CONTACT001", raw).status()
    assert result["door_status"] is None and result["door_open_remind"] is None
    assert result["serial"] == "CONTACT001"


@pytest.mark.parametrize("value", [None, False, "bad", [], 2])
def test_malformed_siren_property_is_not_a_false_alarm(value):
    raw = payload("SIREN00001")
    raw["FEATURE_INFO"]["0"]["global"]["SirenMgr"]["SirenWorkState"] = value
    result = EzvizDetector(None, "SIREN00001", raw).status()
    assert result["siren_work_state"] is None and result["siren_alarm_duration"] == 60


def test_integer_channel_and_primary_channel_precedence():
    raw = payload()
    raw["FEATURE_INFO"][0] = raw["FEATURE_INFO"].pop("0")
    assert EzvizDetector(None, "CONTACT001", raw).status()["door_status"] == 1
    raw["FEATURE_INFO"]["0"] = {}
    assert EzvizDetector(None, "CONTACT001", raw).status()["door_status"] is None


def test_unknown_enum_is_not_guessed_or_booleanized():
    raw = payload()
    raw["FEATURE_INFO"]["0"]["global"]["DoorMagnetic"]["DoorStatus"] = "future-state"
    assert EzvizDetector(None, "CONTACT001", raw).status()["door_status"] == "future-state"


def test_null_primary_battery_falls_back_without_losing_zero():
    raw = payload()
    raw["FEATURE_INFO"]["0"]["global"]["BatteryInfo"]["SurplusPower"] = None
    assert EzvizDetector(None, "CONTACT001", raw).status()["battery_level"] == 88


def test_mixed_inventory_never_routes_detectors_as_cameras(monkeypatch, client):
    data = page()
    data["deviceInfos"].extend(
        [
            {"deviceSerial": "CAMERA001", "deviceCategory": "IPC"},
            {"deviceSerial": "IGNORED01", "deviceCategory": "UnknownCategory"},
        ]
    )
    monkeypatch.setattr(client, "_get_page_list", lambda: data)
    monkeypatch.setattr(client, "_request_json", forbidden)
    prefetched = []

    def prefetch(serials):
        prefetched.extend(serials)
        return {}

    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", prefetch)

    def camera(_client, serial, raw, **kwargs):
        assert serial == "CAMERA001"
        return {"serial": serial, "kind": "camera"}

    monkeypatch.setattr(factory, "camera_status", camera)
    loaded = client.load_devices(refresh=True)
    assert set(loaded) == {"CONTACT001", "WATER00001", "SIREN00001", "CAMERA001"}
    assert prefetched == ["CAMERA001"]
    assert set(client.load_cameras(refresh=False)) == {"CAMERA001"}
    assert set(client.load_detectors(refresh=False)) == {
        "CONTACT001",
        "WATER00001",
        "SIREN00001",
    }


def test_failed_detector_does_not_hide_other_devices_or_log_private_data(
    monkeypatch, caplog, client
):
    data = page()
    original = factory.detector_status

    def detector(client, serial, raw):
        if serial == "CONTACT001":
            raise ValueError("SYNTHETIC_PRIVATE_CANARY")
        return original(client, serial, raw)

    monkeypatch.setattr(client, "_get_page_list", lambda: data)
    monkeypatch.setattr(factory, "detector_status", detector)
    with caplog.at_level(logging.WARNING, logger="pyezvizapi.client"):
        loaded = client.load_devices(refresh=False)
    assert set(loaded) == {"WATER00001", "SIREN00001"}
    assert "stage=detector_status" in caplog.text
    assert "SYNTHETIC_PRIVATE_CANARY" not in caplog.text


def test_root_export_and_native_category_identity():
    assert EzvizDetector is CanonicalDetector
    assert DeviceCatagories.DETECTOR_DEVICE_CATEGORY.value == "Detector"
