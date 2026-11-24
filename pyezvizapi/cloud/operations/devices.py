# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
"""devices implementation; runtime hooks arrive through an explicit owner context.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
import contextlib
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi._shared.image_crypto import ImageKeyMode
from pyezvizapi._shared.image_records import (
    decode_image_records,
    is_clear_image,
    is_image_envelope,
    parse_image_envelope,
)
from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.devices.snapshot import DeviceKind

if TYPE_CHECKING:
    import pyezvizapi._typing.client as _owner_types


_DEVICE_KINDS: dict[str, DeviceKind] = {
    DeviceCatagories.LIGHTING.value: "light",
    DeviceCatagories.SOCKET.value: "plug",
    DeviceCatagories.DETECTOR_DEVICE_CATEGORY.value: "detector",
    DeviceCatagories.INTERCOM_MONITOR_CATEGORY.value: "monitor",
}


def _device_kind(record: _owner_types.EzvizDeviceRecord, supported: list[str]) -> DeviceKind | None:
    """Classify a device without changing how callers render or cache it."""
    category = record.device_category
    if category is None or category not in supported:
        return None
    info = record.raw.get("deviceInfos")
    if category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value and (
        not isinstance(info, _StaticMapping) or not info.get("hik")
    ):
        return None
    return _DEVICE_KINDS.get(category, "camera")


def load_devices(
    self: _owner_types.EzvizClient, refresh: bool, *, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Build and retain the legacy per-family status maps."""
    records = _owner.cast(
        "dict[str, _owner_types.EzvizDeviceRecord]", self.get_device_records(None)
    )
    kinds = {
        serial: _device_kind(record, self.SUPPORTED_CATEGORIES)
        for serial, record in records.items()
    }
    latest_alarms = (
        self._prefetch_latest_camera_alarms(
            [serial for serial, kind in kinds.items() if kind == "camera"]
        )
        if refresh
        else {}
    )
    factory = _owner.device_factory
    renderers = {
        "light": ("light_bulb_status", factory.light_bulb_status, self._light_bulbs),
        "plug": ("smart_plug_status", factory.smart_plug_status, self._smart_plugs),
        "detector": ("detector_status", factory.detector_status, self._detectors),
    }
    for serial, record in records.items():
        kind = kinds[serial]
        # Monitors are exposed by poll_devices(), never legacy camera maps.
        if kind is None or kind == "monitor":
            continue
        stage = "camera_status"
        try:
            if kind == "camera":
                alarm = latest_alarms.get(serial)
                self._cameras[serial] = factory.camera_status(
                    self,
                    serial,
                    dict(record.raw),
                    refresh=refresh and (alarm is not None or serial not in latest_alarms),
                    latest_alarm=alarm,
                    switches=record.switches,
                )
            else:
                stage, render, cache = renderers[kind]
                cache[serial] = render(self, serial, dict(record.raw))
        except (_owner.PyEzvizError, KeyError, TypeError, ValueError) as err:
            _owner._LOGGER.warning(
                "Load_device_failed: serial=%s code=%s stage=%s error_type=%s",
                serial,
                "load_error",
                stage,
                type(err).__name__,
            )
    return {**self._cameras, **self._light_bulbs, **self._smart_plugs, **self._detectors}


def _prefetch_latest_camera_alarms(
    self: _owner_types.EzvizClient,
    serials: _owner_types.Iterable[str],
    *,
    chunk_size: int,
    _owner: _ModuleType,
) -> dict[str, _owner_types.JsonDict | None]:
    """Return found alarms and confirmed absences, omitting unresolved serials."""
    serial_list = list(dict.fromkeys(serial for serial in serials if serial))
    if not serial_list:
        return {}
    latest: dict[str, _owner_types.JsonDict | None] = {}

    def _query_chunk(missing: set[str], *, serials: str | None) -> bool:
        """Collect latest matches, returning True only for a complete filtered batch."""
        cursor: str | int = ""
        seen_cursors: set[str] = set()
        requested = missing.copy()
        # Prefetch is a latency optimization, not an exhaustive history scan.
        # After two pages, let narrower queries resolve the remaining cameras.
        for _ in range(min(2, _owner.MAX_UNIFIEDMSG_PAGES)):
            try:
                response = self.get_device_messages_list(
                    serials=serials, limit=50, date="", end_time=cursor, max_retries=1
                )
            except _owner.PyEzvizError as err:
                _owner._LOGGER.debug(
                    "alarm_prefetch_failed: serials=%s error=%r", serials or "", err
                )
                return False
            items = response.get("message")
            if not items:
                items = response.get("messages", items)
            if not isinstance(items, list):
                return False
            scoped_rows = True
            for item in items:
                serial = item.get("deviceSerial") if isinstance(item, dict) else None
                if not isinstance(serial, str) or serial not in requested:
                    scoped_rows = False
                elif serial in missing:
                    latest[serial] = item
                    missing.remove(serial)

            has_next = response.get("hasNext")
            if not missing or has_next is not True or not items:
                # A timestamp-only cursor can skip messages tied at a page boundary.
                # Only a complete first page can rule out an alarm for a missing serial.
                return (
                    serials is not None
                    and cursor == ""
                    and has_next is False
                    and scoped_rows
                    and not response.get("failureSubTypes")
                    and not response.get("noMessageAbility")
                )

            tail = items[-1]
            next_cursor = tail.get("time") if isinstance(tail, dict) else None
            if not isinstance(next_cursor, (str, int)):
                return False
            cursor_text = str(next_cursor)
            cursor_key = cursor_text.lstrip("0")
            if (
                not cursor_text.isascii()
                or not cursor_text.isdecimal()
                or not cursor_key
                or cursor_key in seen_cursors
            ):
                return False
            cursor = next_cursor
            seen_cursors.add(cursor_key)
        return False

    remaining_serials = set(serial_list)
    _query_chunk(remaining_serials, serials=None)
    for start_idx in range(0, len(serial_list), chunk_size):
        chunk = serial_list[start_idx : start_idx + chunk_size]
        remaining = remaining_serials.intersection(chunk)
        if not remaining:
            continue
        serial_param = ",".join(sorted(remaining))
        if _query_chunk(remaining, serials=serial_param):
            latest.update(dict.fromkeys(remaining))
        elif remaining:
            _owner._LOGGER.debug(
                "alarm_prefetch_incomplete: serials=%s missing=%s",
                serial_param,
                ",".join(sorted(remaining)),
            )
    return latest


def load_cameras(
    self: _owner_types.EzvizClient, refresh: bool, *, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Load and return all camera status mappings.

    refresh: pass-through to load_devices() to control network fetches.
    """
    self.load_devices(refresh=refresh)
    return self._cameras


def load_light_bulbs(
    self: _owner_types.EzvizClient, refresh: bool, *, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Load and return all light bulb status mappings.

    refresh: pass-through to load_devices().
    """
    self.load_devices(refresh=refresh)
    return self._light_bulbs


def load_smart_plugs(
    self: _owner_types.EzvizClient, refresh: bool, *, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Load and return all smart plugs status mappings.

    refresh: pass-through to load_devices().
    """
    self.load_devices(refresh=refresh)
    return self._smart_plugs


def load_detectors(
    self: _owner_types.EzvizClient, refresh: bool, *, _owner: _ModuleType
) -> _owner_types.JsonDict:
    """Return detectors only; never route them through camera status/prefetch."""
    self.load_devices(refresh=refresh)
    return self._detectors


def _cloud_resource_keys(
    cloud: _owner_types.JsonDict,
    devices: dict[str, _owner_types.JsonDict],
    resource_ids: dict[str, set[str]],
) -> dict[str, str]:
    """Choose the legacy single CLOUD resource for each requested device."""
    cloud_keys: dict[str, tuple[bool, str]] = {}
    for resource_id, row in cloud.items():
        if not isinstance(row, dict):
            continue
        resource_serial = row.get("deviceSerial")
        if isinstance(resource_serial, str) and resource_serial in devices:
            resource_ids.setdefault(resource_serial, set()).add(resource_id)
            # Keep the single-resource shape, preferring channel 1 when present.
            # Tie-break by resource ID so pagelist dict ordering cannot change it.
            priority = (row.get("channelNo") not in (1, "1"), resource_id)
            if resource_serial not in cloud_keys or priority < cloud_keys[resource_serial]:
                cloud_keys[resource_serial] = priority
    return {serial: resource_id for serial, (_, resource_id) in cloud_keys.items()}


def get_device_infos(
    self: _owner_types.EzvizClient,
    serial: str | None,
    *,
    _owner: _ModuleType,
    sources: dict[str, _owner_types.JsonDict] | None = None,
) -> _owner_types.JsonDict:
    """Load all devices and build dict per device serial."""
    devices = self._get_device_page(serial) if serial else None
    if devices is None:
        devices = self._get_page_list()
    device_rows = {
        device["deviceSerial"]: device
        for device in devices.get("deviceInfos") or []
        if not serial or device["deviceSerial"] == serial
    }
    if not device_rows:
        return {}

    cloud = devices.get("CLOUD", {})
    resource_ids: dict[str, set[str]] = {}
    cloud_keys = _cloud_resource_keys(cloud, device_rows, resource_ids)

    resources: dict[str, list[_owner_types.JsonDict]] = {}
    for row in devices.get("resourceInfos") or []:
        if not isinstance(row, dict):
            continue
        resource_serial = row.get("deviceSerial")
        if isinstance(resource_serial, str) and resource_serial in device_rows:
            resources.setdefault(resource_serial, []).append(row)

    result: dict[str, _owner_types.Any] = {}
    for _serial, device in device_rows.items():
        _res_id = cloud_keys.get(_serial, "NONE")
        result[_serial] = {
            "CLOUD": {_res_id: cloud.get(_res_id, {})},
            "VTM": {_res_id: devices.get("VTM", {}).get(_res_id, {})},
            "P2P": devices.get("P2P", {}).get(_serial, {}),
            "CONNECTION": devices.get("CONNECTION", {}).get(_serial, {}),
            "KMS": devices.get("KMS", {}).get(_serial, {}),
            "STATUS": devices.get("STATUS", {}).get(_serial, {}),
            "TIME_PLAN": devices.get("TIME_PLAN", {}).get(_serial, {}),
            "CHANNEL": {_res_id: devices.get("CHANNEL", {}).get(_res_id, {})},
            "QOS": devices.get("QOS", {}).get(_serial, {}),
            "NODISTURB": devices.get("NODISTURB", {}).get(_serial, {}),
            "FEATURE": devices.get("FEATURE", {}).get(_serial, {}),
            "UPGRADE": devices.get("UPGRADE", {}).get(_serial, {}),
            "FEATURE_INFO": devices.get("FEATURE_INFO", {}).get(_serial, {}),
            "SWITCH": devices.get("SWITCH", {}).get(_serial, {}),
            "CUSTOM_TAG": devices.get("CUSTOM_TAG", {}).get(_serial, {}),
            "VIDEO_QUALITY": {_res_id: devices.get("VIDEO_QUALITY", {}).get(_res_id, {})},
            "resourceInfos": resources.get(_serial, []),
            "WIFI": devices.get("WIFI", {}).get(_serial, {}),
            "deviceInfos": device,
        }
        projected = result[_serial]
        if sources is not None:
            ids = resource_ids.get(_serial, set()) | {
                resource_id
                for row in projected["resourceInfos"]
                if isinstance(resource_id := row.get("resourceId"), str)
            }
            sources[_serial] = {
                **projected,
                **{
                    section: {
                        resource_id: rows[resource_id] for resource_id in ids if resource_id in rows
                    }
                    for section in ("CLOUD", "VTM", "CHANNEL", "VIDEO_QUALITY")
                    if isinstance(rows := devices.get(section), dict)
                },
            }
        _decode_device_fields(projected, _owner=_owner)
    if not serial:
        return result
    return _owner.cast("dict[_owner_types.Any, _owner_types.Any]", result.get(serial, {}))


def _decode_device_fields(device: _owner_types.JsonDict, *, _owner: _ModuleType) -> None:
    """Decode the legacy view without mutating the original pagelist."""
    info = device["deviceInfos"]
    support_ext = info.get("supportExt")
    if isinstance(support_ext, str) and support_ext:
        with contextlib.suppress(TypeError, ValueError):
            device["deviceInfos"] = {**info, "supportExt": _owner.json.loads(support_ext)}
    status = device["STATUS"]
    if isinstance(status, _StaticMapping) and isinstance(
        optionals := status.get("optionals"), dict
    ):
        decoded = dict(optionals)
        _owner.convert_to_dict(decoded)
        device["STATUS"] = {**status, "optionals": decoded}


def get_device_records(
    self: _owner_types.EzvizClient, serial: str | None, *, _owner: _ModuleType
) -> (
    dict[str, _owner_types.EzvizDeviceRecord]
    | _owner_types.EzvizDeviceRecord
    | _owner_types.JsonDict
):
    """Return records with both the legacy projection and preserved wire values."""
    sources: dict[str, _owner_types.JsonDict] = {}
    devices = get_device_infos(self, serial, _owner=_owner, sources=sources)
    if serial:
        return (
            _owner.EzvizDeviceRecord.from_api(serial, devices, source=sources[serial])
            if devices
            else {}
        )
    records = {
        key: _owner.EzvizDeviceRecord.from_api(key, device, source=sources[key])
        for key, device in devices.items()
    }
    return records if serial is None else records.get(serial, {})


def get_accessory(
    self: _owner_types.EzvizClient,
    serial: str,
    local_index: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve accessory information linked to a device."""
    path = f"{_owner.API_ENDPOINT_DEVICE_ACCESSORY_LINK}{serial}/{local_index}/1/linked/info"
    json_output = self._request_json("GET", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not get accessory info")
    return json_output


def get_dev_config(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    key: str,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Retrieve a devconfig value by key."""
    params = {"key": key}
    json_output = self._request_json(
        "GET",
        f"{_owner.API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
        params=params,
        retry_401=True,
        max_retries=max_retries,
    )
    self._ensure_ok(json_output, "Could not get devconfig value")
    return json_output


def ptz_control(
    self: _owner_types.EzvizClient,
    command: str,
    serial: str,
    action: str,
    speed: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.Any:
    """PTZ Control by API."""
    if command is None:
        raise _owner.PyEzvizError("Trying to call ptzControl without command")
    if action is None:
        raise _owner.PyEzvizError("Trying to call ptzControl without action")
    json_output = self._request_json(
        "PUT",
        f"{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_PTZCONTROL}",
        data={
            "command": command,
            "action": action,
            "channelNo": 1,
            "speed": speed,
            "uuid": str(_owner.uuid4()),
            "serial": serial,
        },
        retry_401=False,
    )
    _owner._LOGGER.debug(
        "http_debug: serial=%s code=%s msg=%s", serial, self._meta_code(json_output), "ptz_control"
    )
    self._ensure_ok(json_output, "Could not control PTZ")
    return True


def capture_picture(
    self: _owner_types.EzvizClient,
    serial: str,
    channel: int,
    *,
    max_retries: int,
    _owner: _ModuleType,
) -> _owner_types.JsonDict:
    """Trigger a snapshot capture on the device."""
    path = f"/v3/devconfig/v1/{serial}/{channel}/capture"
    json_output = self._request_json("PUT", path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, "Could not capture picture")
    return json_output


def get_cam_key(
    self: _owner_types.EzvizClient,
    serial: str,
    smscode: str | int | None,
    max_retries: int,
    *,
    _owner: _ModuleType,
) -> _owner_types.Any:
    """Get Camera encryption key. The key that is set after the camera is added to the account.

    Args:
        serial (str): The camera serial number.
        smscode (str | int | None): The 2FA code account when rights elevation is required.
        max_retries (int): The maximum number of retries. Defaults to 0.

    Raises:
        PyEzvizError: If the camera encryption key can't be retrieved.
        EzvizAuthVerificationCode: If the account requires elevation with 2FA code.
        DeviceException: If the physical device is not reachable.

    Returns:
        Any: JSON response, filtered to return encryptkey:
            {
                "resultCode": int,     # Result code (0 if successful)
                "encryptkey": str,     # Camera encryption key
                "resultDes": str       # Status message in chinese
            }
    """
    attempts = max(0, max_retries)
    for attempt in range(attempts + 1):
        json_output = self._request_json(
            "POST",
            _owner.API_ENDPOINT_CAM_ENCRYPTKEY,
            data={
                "checkcode": smscode,
                "serial": serial,
                "clientNo": "web_site",
                "clientType": 3,
                "netType": "WIFI",
                "featureCode": self.feature_code,
                "sessionId": self._token.get("session_id"),
            },
            retry_401=True,
            max_retries=0,
        )
        code = str(json_output.get("resultCode"))
        if code == "20002":
            raise _owner.EzvizAuthVerificationCode(
                f"MFA code required: Got {self._response_summary(json_output)})"
            )
        if code == "2009":
            raise _owner.DeviceException(
                f"Device not reachable: Got {self._response_summary(json_output)})"
            )
        if code == "0":
            return json_output.get("encryptkey")
        if code == "-1" and attempt < attempts:
            _owner._LOGGER.warning(
                "Http_retry: serial=%s code=%s msg=%s", serial, code, "cam_key_not_found"
            )
            continue
        raise _owner.PyEzvizError(
            f"Could not get camera encryption key: Got {self._response_summary(json_output)})"
        )
    raise _owner.PyEzvizError("Could not get camera encryption key: exceeded retries")


def download_alarm_image(
    self: _owner_types.EzvizClient,
    image_url: str,
    serial: str | None,
    *,
    encryption_key: str | None,
    smscode: str | int | None,
    decrypt: bool,
    max_retries: int,
    _owner: _ModuleType,
    key_mode: ImageKeyMode | str = ImageKeyMode.TEXT,
    key_candidates: tuple[str, ...] = (),
) -> bytes:
    """Download an alarm image and decrypt EZVIZ/Hik encrypted payloads.

    Decode recognized envelopes even without encryption; only encrypted records
    need credentials. Explicit candidates suppress cloud key acquisition and hex
    mode never falls back to text or a fetched key. Legacy default patch hooks
    remain supported. No credential or decoded-image cache is owned here.
    """
    resp = self._http_request("GET", image_url, retry_401=False, max_retries=0)
    image_data = resp.content
    if not decrypt or not image_data:
        return image_data
    try:
        key_mode = ImageKeyMode(key_mode)
    except ValueError as err:
        raise _owner.PyEzvizError("Unsupported image key mode") from err
    records = parse_image_envelope(image_data)
    needs_key = (
        any(
            not is_clear_image(record.image_data)
            and (
                key_mode is ImageKeyMode.HEX
                or record.image_data.startswith(_owner.HIK_ENCRYPTION_HEADER)
            )
            for record in records
        )
        if records is not None
        else not is_clear_image(image_data)
        and (key_mode is ImageKeyMode.HEX or _owner.HIK_ENCRYPTION_HEADER in image_data)
    )
    if not needs_key and not is_image_envelope(image_data):
        return image_data
    key = encryption_key
    if needs_key and key is None and not key_candidates:
        if not serial:
            raise _owner.PyEzvizError(
                "Camera serial or encryption key is required to decrypt image"
            )
        if key_mode == ImageKeyMode.HEX:
            raise _owner.PyEzvizError("Hex image mode requires an explicitly supplied key")
        key = self.get_cam_key(serial, smscode=smscode, max_retries=max_retries)
    if records is not None or key_mode != ImageKeyMode.TEXT or key_candidates:
        return b"".join(
            record.image_data
            for record in decode_image_records(
                image_data, key, key_mode=key_mode, key_candidates=key_candidates
            )
        )
    return _owner.decrypt_image(image_data, key)
