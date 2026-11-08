"""One bounded inventory acquisition, with isolated per-device rendering errors."""

from __future__ import annotations

# ruff: noqa: SLF001 -- inventory operation owns the client's private poll lock/cache
from collections.abc import Mapping
from datetime import UTC, datetime
import time
from typing import Any

from pyezvizapi.cloud.deadline import remaining_request_budget, request_deadline
from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.devices import factory
from pyezvizapi.devices.detector import EzvizDetector
from pyezvizapi.devices.observation import observed_fields, plug_power
from pyezvizapi.devices.snapshot import (
    CameraState,
    DetectorState,
    DeviceCapabilities,
    DeviceHealth,
    DeviceKind,
    DevicePollOptions,
    DeviceSnapshot,
    DeviceState,
    LightState,
    PlugState,
)
from pyezvizapi.exceptions import EzvizAuthTokenExpired, EzvizAuthVerificationCode, PyEzvizError
from pyezvizapi.models import EzvizDeviceRecord


def _kind(record: EzvizDeviceRecord, supported: list[str]) -> DeviceKind | None:
    category = record.device_category
    if category not in supported:
        return None
    info = record.raw.get("deviceInfos")
    if category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value and (
        not isinstance(info, Mapping) or not info.get("hik")
    ):
        return None
    categories: dict[str, DeviceKind] = {
        DeviceCatagories.LIGHTING.value: "light",
        DeviceCatagories.SOCKET.value: "plug",
        DeviceCatagories.DETECTOR_DEVICE_CATEGORY.value: "detector",
    }
    return categories.get(category, "camera")


def _render(
    client: Any,
    serial: str,
    record: EzvizDeviceRecord,
    kind: DeviceKind,
    alarms: dict,
    refresh: bool,
) -> DeviceState:
    raw = dict(record.raw)
    info = raw.get("deviceInfos")
    connectivity = info.get("status") if isinstance(info, Mapping) else None
    observed: frozenset[str] = frozenset()
    state_type: type[DeviceState]
    if kind == "camera":
        values = factory.camera_status(
            client, serial, raw, refresh=refresh, latest_alarm=alarms.get(serial)
        )
        if not refresh:
            for key in (
                "Motion_Trigger",
                "Seconds_Last_Trigger",
                "last_alarm_time",
                "last_alarm_pic",
                "last_alarm_type_code",
                "last_alarm_type_name",
            ):
                values[key] = None
        state_type = CameraState
    elif kind == "detector":
        wrapper = EzvizDetector(client, serial, record)
        values = wrapper.status()
        values["status"] = connectivity
        observed = wrapper.observed_fields()
        return DetectorState(serial, kind, values, DeviceCapabilities(observed))
    elif kind == "light":
        values = factory.light_bulb_status(client, serial, raw)
        state_type = LightState
    else:
        values = factory.smart_plug_status(client, serial, raw)
        state_type = PlugState
    values["status"] = connectivity
    if kind == "plug":
        values["is_on"] = plug_power(raw)[1]
    observed = observed_fields(raw, kind)
    return state_type(serial, kind, values, DeviceCapabilities(observed))


def poll_devices(client: Any, options: DevicePollOptions) -> DeviceSnapshot:
    """Publish once after a complete bounded poll; global failures keep the prior snapshot."""
    deadline = time.monotonic() + options.timeout
    parent = remaining_request_budget()
    wait = options.timeout if parent is None else min(options.timeout, parent)
    if not client._inventory_lock.acquire(timeout=wait):
        raise TimeoutError("Inventory lock exhausted polling deadline")
    try:
        with request_deadline(deadline):
            records = client.get_device_records(None)
            if not isinstance(records, dict) or any(
                not isinstance(v, EzvizDeviceRecord) for v in records.values()
            ):
                raise PyEzvizError("Inventory response is not a device-record mapping")
            if len(records) > options.max_devices:
                raise PyEzvizError("Inventory device budget exhausted")
            kinds: dict[str, DeviceKind | None] = {
                s: _kind(r, client.SUPPORTED_CATEGORIES) for s, r in records.items()
            }
            alarms = (
                client._prefetch_latest_camera_alarms(
                    [s for s, k in kinds.items() if k == "camera"]
                )
                if options.include_camera_alarms
                else {}
            )
            previous = client._device_snapshot
            states = dict(previous.devices) if previous else {}
            health = (
                {
                    s: DeviceHealth(False, False, v.last_success, "MissingFromInventory")
                    for s, v in previous.health.items()
                }
                if previous
                else {}
            )
            instant = datetime.now(UTC)
            for serial, record in records.items():
                remaining_request_budget()
                kind = kinds[serial]
                if kind is None:
                    if serial in health:
                        health[serial] = DeviceHealth(
                            True, False, health[serial].last_success, "UnsupportedCategory"
                        )
                    continue
                try:
                    states[serial] = _render(
                        client, serial, record, kind, alarms, options.include_camera_alarms
                    )
                except (EzvizAuthTokenExpired, EzvizAuthVerificationCode):
                    raise  # Account authentication failure is not a device defect.
                except (PyEzvizError, KeyError, TypeError, ValueError) as error:
                    health[serial] = DeviceHealth(
                        True,
                        False,
                        health.get(serial, DeviceHealth(True, False, None)).last_success,
                        type(error).__name__,
                    )
                else:
                    health[serial] = DeviceHealth(True, True, instant)
            remaining_request_budget()
            snapshot = DeviceSnapshot(
                1 if previous is None else previous.revision + 1, instant, states, health
            )
        client._device_snapshot = snapshot
        return snapshot
    finally:
        client._inventory_lock.release()
