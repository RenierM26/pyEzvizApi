"""Bounded mixed-device polling contracts; no account, device or HA required."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
import json
from pathlib import Path
import threading
from typing import Any
from unittest.mock import Mock

import pytest

import pyezvizapi
from pyezvizapi.cloud import deadline
from pyezvizapi.cloud.operations import snapshot as operation
from pyezvizapi.constants import DeviceSwitchType
from pyezvizapi.devices import factory
from pyezvizapi.devices.snapshot import (
    CameraState,
    DetectorState,
    DeviceCapabilities,
    DeviceHealth,
    DevicePollOptions,
    DeviceSnapshot,
    DeviceState,
    LightState,
    PlugState,
)
from pyezvizapi.exceptions import EzvizAuthTokenExpired, PyEzvizError
from pyezvizapi.models import EzvizDeviceRecord


@pytest.fixture
def client():
    value = pyezvizapi.EzvizClient()
    yield value
    value.close_session()


def record(serial, category="IPC"):
    return EzvizDeviceRecord.from_api(
        serial,
        {
            "deviceInfos": {"deviceSerial": serial, "deviceCategory": category, "status": 1},
        },
    )


def test_one_acquisition_for_mixed_inventory_and_pure_selectors(client, monkeypatch):
    records = {
        s: record(s, kind)
        for s, kind in (
            ("cam", "IPC"),
            ("det", "Detector"),
            ("light", "lighting"),
            ("plug", "Socket"),
        )
    }
    records["plug"] = EzvizDeviceRecord.from_api(
        "plug",
        {
            "deviceInfos": {"deviceCategory": "Socket"},
            "SWITCH": [{"type": DeviceSwitchType.PLUG.value, "enable": 0}],
        },
    )
    fetch = Mock(return_value=records)
    alarms = Mock(return_value={"cam": {"alarm": "synthetic"}})
    monkeypatch.setattr(client, "get_device_records", fetch)
    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", alarms)
    monkeypatch.setattr(factory, "camera_status", lambda *a, **k: {"Motion_Trigger": True})
    monkeypatch.setattr(factory, "light_bulb_status", lambda *a: {"is_on": "1"})
    monkeypatch.setattr(factory, "smart_plug_status", lambda *a: {"is_on": 0})
    snap = client.poll_devices()
    assert set(snap.devices) == set(records)
    assert isinstance(snap.devices["cam"], CameraState)
    assert isinstance(snap.devices["det"], DetectorState)
    assert isinstance(snap.devices["light"], LightState)
    assert isinstance(snap.devices["plug"], PlugState)
    assert snap.devices["light"].is_on is True and snap.devices["plug"].is_on is False
    assert set(snap.select("detector")) == {"det"}
    assert set(snap.as_dict("camera")) == {"cam"}
    assert client.device_snapshot is snap and all(h.current for h in snap.health.values())
    fetch.assert_called_once_with(None)
    alarms.assert_called_once_with(["cam"])


def test_snapshot_deep_immutability_and_detached_adapters():
    raw: dict[str, Any] = {"nested": [{"flag": False}], "tuple": ("value",), "status": 1}
    state = DeviceState("x", "camera", raw)
    snap = DeviceSnapshot(1, datetime.now(UTC), {"x": state}, {})
    raw["nested"][0]["flag"] = True
    assert state.values["nested"][0]["flag"] is False
    with pytest.raises(TypeError):
        state.values["nested"][0]["flag"] = True
    with pytest.raises(TypeError):
        snap.devices["other"] = state  # type: ignore[index]  # intentional mutation probe
    with pytest.raises(FrozenInstanceError):
        state.serial = "other"  # type: ignore[misc]  # intentional mutation probe
    adapted = snap.as_dict()
    adapted["x"]["nested"][0]["flag"] = True
    assert state.as_dict()["nested"] == [{"flag": False}]
    assert state.as_dict()["tuple"] == ("value",)


def test_freshness_retains_failed_missing_and_now_unsupported_devices(client, monkeypatch):
    records = {s: record(s) for s in ("ok", "failed", "missing", "unsupported")}
    monkeypatch.setattr(client, "get_device_records", lambda _: records)
    monkeypatch.setattr(factory, "camera_status", lambda c, s, *a, **k: {"name": s})
    options = DevicePollOptions(include_camera_alarms=False)
    first = client.poll_devices(options)
    records.pop("missing")
    records["unsupported"] = record("unsupported", "FutureType")

    def render(c, s, *args, **kwargs):
        if s == "failed":
            raise ValueError("PRIVATE_CANARY")
        return {"name": "new"}

    monkeypatch.setattr(factory, "camera_status", render)
    second = client.poll_devices(options)
    assert second.revision == 2 and first.devices["ok"].values["name"] == "ok"
    assert second.devices["ok"].values["name"] == "new"
    assert second.devices["failed"] is first.devices["failed"]
    assert second.health["failed"] == DeviceHealth(True, False, first.received_at, "ValueError")
    assert second.health["missing"] == DeviceHealth(
        False, False, first.received_at, "MissingFromInventory"
    )
    assert second.health["unsupported"] == DeviceHealth(
        True, False, first.received_at, "UnsupportedCategory"
    )
    assert "PRIVATE_CANARY" not in repr(second.health)


def test_global_failure_and_late_deadline_do_not_publish(client, monkeypatch):
    monkeypatch.setattr(client, "get_device_records", lambda _: {})
    first = client.poll_devices()
    monkeypatch.setattr(client, "get_device_records", Mock(side_effect=PyEzvizError("offline")))
    with pytest.raises(PyEzvizError):
        client.poll_devices()
    assert client.device_snapshot is first
    monkeypatch.setattr(client, "get_device_records", lambda _: {})
    check = operation.remaining_request_budget
    # Deadline failure at the final context-exit check must not publish a partial revision.

    original = deadline.remaining_request_budget
    calls = 0

    def remaining():
        nonlocal calls
        calls += 1
        if calls == 3:
            raise TimeoutError("expired")
        return original()

    monkeypatch.setattr(deadline, "remaining_request_budget", remaining)
    with pytest.raises(TimeoutError):
        client.poll_devices()
    assert client.device_snapshot is first
    assert check() is None


def test_lock_wait_is_bounded_and_no_replacement_worker(client):
    ready = threading.Event()
    release = threading.Event()

    def hold():
        with client._inventory_lock:  # noqa: SLF001 -- exercise contention boundary
            ready.set()
            release.wait(2)

    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(1)
    try:
        with pytest.raises(TimeoutError, match="Inventory lock"):
            client.poll_devices(DevicePollOptions(timeout=0.01))
        assert client.device_snapshot is None
    finally:
        release.set()
        thread.join(1)


def test_alarms_excluded_are_unknown_not_false(client, monkeypatch):
    monkeypatch.setattr(client, "get_device_records", lambda _: {"cam": record("cam")})
    monkeypatch.setattr(client, "_prefetch_latest_camera_alarms", Mock(side_effect=AssertionError))
    monkeypatch.setattr(factory, "camera_status", lambda *a, **k: {"Motion_Trigger": False})
    snap = client.poll_devices(DevicePollOptions(include_camera_alarms=False))
    assert snap.devices["cam"].motion is None
    assert snap.devices["cam"].capabilities.has("Motion_Trigger") is None


@pytest.mark.parametrize(
    "options",
    [
        {"timeout": True},
        {"timeout": 0},
        {"timeout": float("inf")},
        {"timeout": "2"},
        {"max_devices": 0},
        {"max_devices": True},
        {"include_camera_alarms": 1},
    ],
)
def test_invalid_options(options):
    with pytest.raises(PyEzvizError):
        DevicePollOptions(**options)


def test_inventory_budget_and_malformed_mapping_fail_globally(client, monkeypatch):
    records: Any
    for records in ({"x": {}}, [], {"x": record("x"), "y": record("y")}):
        monkeypatch.setattr(client, "get_device_records", lambda _, r=records: r)
        with pytest.raises(PyEzvizError):
            client.poll_devices(DevicePollOptions(max_devices=1))
        assert client.device_snapshot is None


@pytest.mark.parametrize(
    "raw, expected",
    [
        (1, True),
        ("1", True),
        (2, False),
        ("2", False),
        (True, None),
        (1.0, None),
        (0, None),
        (99, None),
    ],
)
def test_online_known_enum_only(raw, expected):
    assert DeviceState("x", "camera", {"status": raw}).online is expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        (0, 0),
        (100, 100),
        ("75", 75),
        (False, None),
        (-1, None),
        (101, None),
        (50.0, None),
        ("bad", None),
    ],
)
def test_battery_validation(raw, expected):
    assert DetectorState("x", "detector", {"battery_level": raw}).battery_level == expected


def test_raw_detector_codes_remain_unknown_and_present_null_is_observed(client, monkeypatch):
    page = json.loads((Path(__file__).parents[1] / "fixtures/detector_page_list.json").read_text())
    serial = "CONTACT001"
    raw = {
        "deviceInfos": next(v for v in page["deviceInfos"] if v["deviceSerial"] == serial),
        "FEATURE_INFO": page["FEATURE_INFO"][serial],
    }
    raw["FEATURE_INFO"]["0"]["global"]["DoorMagnetic"]["DoorStatus"] = None
    before = deepcopy(raw)
    monkeypatch.setattr(
        client, "get_device_records", lambda _: {serial: EzvizDeviceRecord.from_api(serial, raw)}
    )
    state = client.poll_devices().devices[serial]
    assert state.door_open is None and state.water_leak is None
    assert state.capabilities.has("door_status") is True
    assert state.values["door_status"] is None and raw == before
    assert DeviceCapabilities().has("future") is None
    with pytest.raises(PyEzvizError):
        DeviceCapabilities(verified_booleans={"door_open": 1})  # type: ignore[dict-item]
    with pytest.raises(PyEzvizError):
        DeviceState("x", "detector", {"mutable": set()})


def test_public_exports():

    for cls in (
        DevicePollOptions,
        DeviceSnapshot,
        DeviceState,
        CameraState,
        DetectorState,
        LightState,
        PlugState,
    ):
        assert getattr(pyezvizapi, cls.__name__) is cls


def test_camera_auth_failure_is_global_not_a_device_render_defect(client, monkeypatch):
    monkeypatch.setattr(client, "get_device_records", lambda _: {"cam": record("cam")})
    monkeypatch.setattr(factory, "camera_status", Mock(side_effect=EzvizAuthTokenExpired()))
    with pytest.raises(EzvizAuthTokenExpired):
        client.poll_devices(DevicePollOptions(include_camera_alarms=False))
    assert client.device_snapshot is None


@pytest.mark.parametrize(
    "code,expected",
    [
        (0, False),
        (1, True),
        ("0", False),
        ("1", True),
        (2, None),
        (-1, None),
        (None, None),
        ("future", None),
    ],
)
def test_typed_plug_preserves_source_power_code_without_changing_legacy(
    client, monkeypatch, code, expected
):
    raw = {
        "deviceInfos": {"deviceCategory": "Socket", "supportExt": {}},
        "WIFI": {},
        "SWITCH": [{"type": DeviceSwitchType.PLUG.value, "enable": code}],
    }
    # Exercise the actual renderer for every raw code, including strings/null.
    if type(code) in (int, bool):
        legacy = factory.smart_plug_status(client, "plug", raw)
        assert legacy["is_on"] is bool(code)
    else:
        with pytest.raises(KeyError):
            factory.smart_plug_status(client, "plug", raw)
    monkeypatch.setattr(
        client, "get_device_records", lambda _: {"plug": EzvizDeviceRecord.from_api("plug", raw)}
    )
    state = client.poll_devices().devices["plug"]
    assert state.is_on is expected
    assert state.values["is_on"] == code
    assert state.values["switches"].get(DeviceSwitchType.PLUG.value) is expected
    assert state.capabilities.has("is_on") is True


def test_observed_camera_properties_do_not_inherit_compatibility_defaults(client, monkeypatch):
    raw: dict[str, Any] = {"deviceInfos": {"deviceCategory": "IPC"}}
    monkeypatch.setattr(
        client, "get_device_records", lambda _: {"cam": EzvizDeviceRecord.from_api("cam", raw)}
    )
    first = client.poll_devices(DevicePollOptions(include_camera_alarms=False)).devices["cam"]
    assert first.values["alarm_notify"] is False
    assert first.capabilities.has("alarm_notify") is None
    assert first.capabilities.has("encrypted") is None
    raw["STATUS"] = {"globalStatus": None, "isEncrypt": None}
    second = client.poll_devices(DevicePollOptions(include_camera_alarms=False)).devices["cam"]
    assert second.capabilities.has("alarm_notify") is True
    assert second.capabilities.has("encrypted") is True


def test_observed_light_property_paths_include_null_and_not_synthetic_defaults(client, monkeypatch):
    raw = {
        "deviceInfos": {"deviceCategory": "lighting", "supportExt": {}},
        "WIFI": {},
        "FEATURE": {
            "featureJson": json.dumps(
                {
                    "productId": "synthetic",
                    "featureItemDtos": [{"itemKey": "light_switch", "dataValue": None}],
                }
            )
        },
    }
    monkeypatch.setattr(
        client, "get_device_records", lambda _: {"light": EzvizDeviceRecord.from_api("light", raw)}
    )
    state = client.poll_devices().devices["light"]
    assert state.capabilities.has("is_on") is True and state.is_on is None
    assert state.capabilities.has("brightness") is None


def test_alarm_defence_status_is_not_connectivity(client, monkeypatch):
    raw = {"deviceInfos": {"deviceCategory": "IPC"}, "STATUS": {"globalStatus": 1}}
    record = EzvizDeviceRecord.from_api("cam", raw)
    assert record.status == 1  # Legacy record fallback remains compatible.
    monkeypatch.setattr(client, "get_device_records", lambda _: {"cam": record})
    state = client.poll_devices(DevicePollOptions(include_camera_alarms=False)).devices["cam"]
    assert state.online is None and state.values["status"] is None
    assert state.capabilities.has("status") is None


def test_actual_camera_attribute_error_isolated_from_healthy_sibling(client, monkeypatch):
    records = {s: record(s) for s in ("good", "bad")}
    monkeypatch.setattr(client, "get_device_records", lambda _: records)
    options = DevicePollOptions(include_camera_alarms=False)
    first = client.poll_devices(options)
    records["bad"] = EzvizDeviceRecord.from_api("bad", {**records["bad"].raw, "CONNECTION": [1]})
    records["good"] = EzvizDeviceRecord.from_api(
        "good", {"deviceInfos": {"deviceCategory": "IPC", "status": 1, "version": "new-version"}}
    )
    second = client.poll_devices(options)
    assert second.devices["good"].values["version"] == "new-version"
    assert second.health["good"].current
    assert second.devices["bad"] is first.devices["bad"]
    assert second.health["bad"] == DeviceHealth(True, False, first.received_at, "AttributeError")
