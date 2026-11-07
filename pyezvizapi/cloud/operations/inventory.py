# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'inventory implementation; runtime hooks arrive through an explicit owner context.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from collections.abc import Iterable as _StaticIterable
import datetime as _StaticDateTime
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi.client as _owner_types

def get_device_messages_list(self: _owner_types.EzvizClient, serials: str | None, s_type: str | int | _owner_types.Iterable[str | int] | None, *, limit: int, date: str | _owner_types.dt.date | _owner_types.dt.datetime | None, end_time: str | int | None, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Return unified alarm/message list for the requested devices.

        Args:
            serials: Optional CSV string of serial numbers. ``None`` returns all.
            s_type: Can be a string, int, iterable of either, or
                :class:`~pyezvizapi.constants.UnifiedMessageSubtype`.
            limit: Clamp between 1 and 50 as enforced by the public API.
            date: Accepts ``YYYYMMDD`` string, :class:`datetime.date`, or
                :class:`datetime.datetime`. Defaults to "today" in API format.
            end_time: Pass the ``msgId`` (string) returned by the previous call
                for pagination. The mobile app sends an empty string to fetch the
                most recent message, so ``""`` is preserved on purpose here.
            max_retries: Number of additional attempts when the backend reports
                temporary failures. Capped by :data:`MAX_RETRIES`.
        """
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")

    def _stringify(value: _owner_types.Any) -> str:
        raw = getattr(value, 'value', value)
        return str(raw)
    stype_param: str | None
    if s_type is None:
        stype_param = _owner.DEFAULT_UNIFIEDMSG_STYPE
    elif isinstance(s_type, str):
        stype_param = s_type
    elif isinstance(s_type, _StaticIterable) and (not isinstance(s_type, (bytes, bytearray))):
        parts = [_stringify(item) for item in s_type if item not in (None, '')]
        stype_param = ','.join(parts) if parts else _owner.DEFAULT_UNIFIEDMSG_STYPE
    else:
        stype_param = _stringify(s_type)
    if date is None:
        date_value = _owner.dt.datetime.now().strftime('%Y%m%d')
    elif isinstance(date, (_StaticDateTime.date, _StaticDateTime.datetime)):
        date_value = date.strftime('%Y%m%d')
    else:
        date_value = str(date)
    try:
        limit_value = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit_value = 20
    end_time_value: str = '' if end_time is None else str(end_time)
    params: dict[str, _owner_types.Any] = {'serials': serials, 'stype': stype_param, 'limit': limit_value, 'date': date_value, 'endTime': end_time_value}
    filtered_params = {k: v for k, v in params.items() if v not in (None, '')}
    if end_time_value == '':
        filtered_params['endTime'] = ''
    json_output = self._request_json('GET', _owner.API_ENDPOINT_UNIFIEDMSG_LIST_GET, params=filtered_params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get unified message list')
    if _owner._LOGGER.isEnabledFor(_owner.logging.DEBUG):
        counter_key = 'unifiedmsg'
        self._debug_request_counters[counter_key] = self._debug_request_counters.get(counter_key, 0) + 1
        _owner._LOGGER.debug('req_counter[%s]=%s params=%s', counter_key, self._debug_request_counters[counter_key], filtered_params)
    return json_output

def add_device(self: _owner_types.EzvizClient, serial: str, validate_code: str, *, add_type: str | None, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Add a new device to the current account."""
    data = {'deviceSerial': serial, 'validateCode': validate_code}
    if add_type is not None:
        data['addType'] = add_type
    json_output = self._request_json('POST', _owner.API_ENDPOINT_USERDEVICES_V2, data=data, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not add device')
    return json_output

def add_hik_activate(self: _owner_types.EzvizClient, serial: str, payload: _owner_types.Any, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Activate a Hikvision device using the security endpoint."""
    body = self._normalize_json_payload(payload)
    json_output = self._request_json('POST', f'{_owner.API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE}{serial}', json_body=body, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not activate Hik device')
    return json_output

def add_hik_challenge(self: _owner_types.EzvizClient, serial: str, payload: _owner_types.Any, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Request a Hikvision security challenge."""
    body = self._normalize_json_payload(payload)
    json_output = self._request_json('POST', f'{_owner.API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE}{serial}', json_body=body, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not request Hik challenge')
    return json_output

def add_local_device(self: _owner_types.EzvizClient, payload: _owner_types.Any, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Add a device discovered on the local network."""
    body = self._normalize_json_payload(payload)
    json_output = self._request_json('POST', _owner.API_ENDPOINT_DEVICES_LOC, json_body=body, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not add local device')
    return json_output

def save_hik_dev_code(self: _owner_types.EzvizClient, payload: _owner_types.Any, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Submit a Hikvision device code via the SCD endpoint."""
    body = self._normalize_json_payload(payload)
    json_output = self._request_json('POST', _owner.API_ENDPOINT_SCD_APP_DEVICE_ADD, json_body=body, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not save Hik device code')
    return json_output

def bind_virtual_device(self: _owner_types.EzvizClient, product_id: str, version: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Bind a virtual IoT device using product identifier and version."""
    params = {'productId': product_id, 'version': version}
    json_output = self._request_json('PUT', _owner.API_ENDPOINT_IOT_VIRTUAL_BIND, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not bind virtual device')
    return json_output

def dev_config_search(self: _owner_types.EzvizClient, serial: str, channel: int, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Trigger a network search on the device."""
    path = f'{_owner.API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork'
    json_output = self._request_json('POST', path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not start network search')
    return json_output

def dev_config_send_config_command(self: _owner_types.EzvizClient, serial: str, channel: int, target_serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Send a network configuration command to a target device."""
    path = f'{_owner.API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/command'
    json_output = self._request_json('POST', path, params={'targetDeviceSerial': target_serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not send network command')
    return json_output

def dev_config_wifi_list(self: _owner_types.EzvizClient, serial: str, channel: int, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Retrieve Wi-Fi network list detected by the device."""
    path = f'{_owner.API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork'
    json_output = self._request_json('GET', path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get Wi-Fi list')
    return json_output

def device_between_error(self: _owner_types.EzvizClient, serial: str, channel: int, target_serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Retrieve error details for a network configuration attempt."""
    path = f'{_owner.API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/result'
    json_output = self._request_json('GET', path, params={'targetDeviceSerial': target_serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get network error info')
    return json_output
