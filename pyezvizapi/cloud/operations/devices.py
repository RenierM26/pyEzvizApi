# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""devices implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
from __future__ import annotations

import pyezvizapi.client as _owner


def load_devices(self: _owner.EzvizClient, refresh: bool=True) -> _owner.JsonDict:
    """Build status maps for cameras and light bulbs.

        refresh: if True, camera.status() may perform network fetches (e.g. alarms).
        Returns a combined mapping of serial -> status dict for both cameras and bulbs.

        Note: We update in place and do not remove keys for devices that may
        have disappeared. Users who intentionally remove a device can restart
        the integration to flush stale entries.
        """
    records = _owner.cast(dict[str, _owner.EzvizDeviceRecord], self.get_device_records(None))
    supported_categories = self.SUPPORTED_CATEGORIES

    def _is_supported_camera(rec: _owner.EzvizDeviceRecord) -> bool:
        """Return True if record should be treated as a camera."""
        if rec.device_category not in supported_categories:
            return False
        if rec.device_category in (_owner.DeviceCatagories.LIGHTING.value, _owner.DeviceCatagories.SOCKET.value):
            return False
        return not (rec.device_category == _owner.DeviceCatagories.COMMON_DEVICE_CATEGORY.value and (not (rec.raw.get('deviceInfos') or {}).get('hik')))
    latest_alarms: dict[str, dict[str, _owner.Any]] = {}
    if refresh:
        camera_serials = [serial for serial, record in records.items() if _is_supported_camera(record)]
        latest_alarms = self._prefetch_latest_camera_alarms(camera_serials)
    for device, rec in records.items():
        if rec.device_category in supported_categories:
            if rec.device_category == _owner.DeviceCatagories.COMMON_DEVICE_CATEGORY.value and (not (rec.raw.get('deviceInfos') or {}).get('hik')):
                continue
            if rec.device_category == _owner.DeviceCatagories.LIGHTING.value:
                try:
                    self._light_bulbs[device] = _owner.device_factory.light_bulb_status(self, device, dict(rec.raw))
                except (_owner.PyEzvizError, KeyError, TypeError, ValueError) as err:
                    _owner._LOGGER.warning('Load_device_failed: serial=%s code=%s stage=%s error_type=%s', device, 'load_error', 'light_bulb_status', type(err).__name__)
            elif rec.device_category == _owner.DeviceCatagories.SOCKET.value:
                try:
                    self._smart_plugs[device] = _owner.device_factory.smart_plug_status(self, device, dict(rec.raw))
                except (_owner.PyEzvizError, KeyError, TypeError, ValueError) as err:
                    _owner._LOGGER.warning('Load_device_failed: serial=%s code=%s stage=%s error_type=%s', device, 'load_error', 'smart_plug_status', type(err).__name__)
            else:
                try:
                    self._cameras[device] = _owner.device_factory.camera_status(self, device, dict(rec.raw), refresh=refresh, latest_alarm=latest_alarms.get(device))
                except (_owner.PyEzvizError, KeyError, TypeError, ValueError) as err:
                    _owner._LOGGER.warning('Load_device_failed: serial=%s code=%s stage=%s error_type=%s', device, 'load_error', 'camera_status', type(err).__name__)
    return {**self._cameras, **self._light_bulbs, **self._smart_plugs}

def _prefetch_latest_camera_alarms(self: _owner.EzvizClient, serials: _owner.Iterable[str], *, chunk_size: int=20) -> dict[str, dict[str, _owner.Any]]:
    """Attempt to fetch the most recent unified message per camera serial."""
    serial_list = [serial for serial in serials if serial]
    if not serial_list:
        return {}
    latest: dict[str, dict[str, _owner.Any]] = {}

    def _query_chunk(missing: set[str], limit: int, *, filtered: bool) -> None:
        """Populate latest alarms for a given chunk, retrying a few times."""
        attempts = 0
        while missing and attempts < _owner.MAX_UNIFIEDMSG_PAGES:
            attempts += 1
            serial_param = None if not filtered else ','.join(sorted(missing))
            try:
                response = self.get_device_messages_list(serials=serial_param, limit=limit, date='', end_time='', max_retries=1)
            except _owner.PyEzvizError as err:
                _owner._LOGGER.debug('alarm_prefetch_failed: serials=%s error=%r', serial_param or '', err)
                return
            items = response.get('message') or response.get('messages') or []
            if not isinstance(items, list) or not items:
                return
            matched = 0
            for item in items:
                serial = item.get('deviceSerial')
                if isinstance(serial, str) and serial in missing and (serial not in latest):
                    latest[serial] = item
                    missing.discard(serial)
                    matched += 1
            if filtered and matched < len(missing):
                return
            if not response.get('hasNext'):
                return
    remaining_serials = set(serial_list)
    before = set(remaining_serials)
    _query_chunk(remaining_serials, limit=50, filtered=False)
    satisfied = before - remaining_serials
    if satisfied:
        remaining_serials.difference_update(satisfied)
    for start_idx in range(0, len(serial_list), chunk_size):
        chunk = [serial for serial in serial_list[start_idx:start_idx + chunk_size] if serial]
        if not chunk:
            continue
        remaining = {serial for serial in chunk if serial in remaining_serials}
        if not remaining:
            continue
        chunk_key = ','.join(chunk)
        limit = min(50, max(len(chunk), 20))
        before_chunk = set(remaining)
        _query_chunk(remaining, limit, filtered=True)
        satisfied_chunk = before_chunk - remaining
        if satisfied_chunk:
            remaining_serials.difference_update(satisfied_chunk)
        if remaining:
            _owner._LOGGER.debug('alarm_prefetch_incomplete: serials=%s missing=%s', chunk_key, ','.join(sorted(remaining)))
    return latest

def load_cameras(self: _owner.EzvizClient, refresh: bool=True) -> _owner.JsonDict:
    """Load and return all camera status mappings.

        refresh: pass-through to load_devices() to control network fetches.
        """
    self.load_devices(refresh=refresh)
    return self._cameras

def load_light_bulbs(self: _owner.EzvizClient, refresh: bool=True) -> _owner.JsonDict:
    """Load and return all light bulb status mappings.

        refresh: pass-through to load_devices().
        """
    self.load_devices(refresh=refresh)
    return self._light_bulbs

def load_smart_plugs(self: _owner.EzvizClient, refresh: bool=True) -> _owner.JsonDict:
    """Load and return all smart plugs status mappings.

        refresh: pass-through to load_devices().
        """
    self.load_devices(refresh=refresh)
    return self._smart_plugs

def get_device_infos(self: _owner.EzvizClient, serial: str | None=None) -> _owner.JsonDict:
    """Load all devices and build dict per device serial."""
    devices = self._get_page_list()
    result: dict[str, _owner.Any] = {}
    for device in devices.get('deviceInfos', []) or []:
        _serial = device['deviceSerial']
        _res_id_list = {item for item in devices.get('CLOUD', {}) if devices['CLOUD'][item].get('deviceSerial') == _serial}
        _res_id = _res_id_list.pop() if _res_id_list else 'NONE'
        result[_serial] = {'CLOUD': {_res_id: devices.get('CLOUD', {}).get(_res_id, {})}, 'VTM': {_res_id: devices.get('VTM', {}).get(_res_id, {})}, 'P2P': devices.get('P2P', {}).get(_serial, {}), 'CONNECTION': devices.get('CONNECTION', {}).get(_serial, {}), 'KMS': devices.get('KMS', {}).get(_serial, {}), 'STATUS': devices.get('STATUS', {}).get(_serial, {}), 'TIME_PLAN': devices.get('TIME_PLAN', {}).get(_serial, {}), 'CHANNEL': {_res_id: devices.get('CHANNEL', {}).get(_res_id, {})}, 'QOS': devices.get('QOS', {}).get(_serial, {}), 'NODISTURB': devices.get('NODISTURB', {}).get(_serial, {}), 'FEATURE': devices.get('FEATURE', {}).get(_serial, {}), 'UPGRADE': devices.get('UPGRADE', {}).get(_serial, {}), 'FEATURE_INFO': devices.get('FEATURE_INFO', {}).get(_serial, {}), 'SWITCH': devices.get('SWITCH', {}).get(_serial, {}), 'CUSTOM_TAG': devices.get('CUSTOM_TAG', {}).get(_serial, {}), 'VIDEO_QUALITY': {_res_id: devices.get('VIDEO_QUALITY', {}).get(_res_id, {})}, 'resourceInfos': [item for item in devices.get('resourceInfos') or [] if isinstance(item, dict) and item.get('deviceSerial') == _serial], 'WIFI': devices.get('WIFI', {}).get(_serial, {}), 'deviceInfos': device}
        try:
            support_ext = result[_serial].get('deviceInfos', {}).get('supportExt')
            if isinstance(support_ext, str) and support_ext:
                result[_serial]['deviceInfos']['supportExt'] = _owner.json.loads(support_ext)
        except (TypeError, ValueError):
            pass
        _owner.convert_to_dict(result[_serial]['STATUS'].get('optionals'))
    if not serial:
        return result
    return _owner.cast(dict[_owner.Any, _owner.Any], result.get(serial, {}))

def get_device_records(self: _owner.EzvizClient, serial: str | None=None) -> dict[str, _owner.EzvizDeviceRecord] | _owner.EzvizDeviceRecord | _owner.JsonDict:
    """Return devices as EzvizDeviceRecord mapping (or single record).

        Falls back to raw when a specific serial is requested but not found.
        """
    devices = self.get_device_infos()
    records = _owner.build_device_records_map(devices)
    if serial is None:
        return records
    return records.get(serial) or devices.get(serial, {})

def get_accessory(self: _owner.EzvizClient, serial: str, local_index: str, *, max_retries: int=0) -> _owner.JsonDict:
    """Retrieve accessory information linked to a device."""
    path = f'{_owner.API_ENDPOINT_DEVICE_ACCESSORY_LINK}{serial}/{local_index}/1/linked/info'
    json_output = self._request_json('GET', path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get accessory info')
    return json_output

def get_dev_config(self: _owner.EzvizClient, serial: str, channel: int, key: str, *, max_retries: int=0) -> _owner.JsonDict:
    """Retrieve a devconfig value by key."""
    params = {'key': key}
    json_output = self._request_json('GET', f'{_owner.API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op', params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get devconfig value')
    return json_output

def ptz_control(self: _owner.EzvizClient, command: str, serial: str, action: str, speed: int=5) -> _owner.Any:
    """PTZ Control by API."""
    if command is None:
        raise _owner.PyEzvizError('Trying to call ptzControl without command')
    if action is None:
        raise _owner.PyEzvizError('Trying to call ptzControl without action')
    json_output = self._request_json('PUT', f'{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_PTZCONTROL}', data={'command': command, 'action': action, 'channelNo': 1, 'speed': speed, 'uuid': str(_owner.uuid4()), 'serial': serial}, retry_401=False)
    _owner._LOGGER.debug('http_debug: serial=%s code=%s msg=%s', serial, self._meta_code(json_output), 'ptz_control')
    self._ensure_ok(json_output, 'Could not control PTZ')
    return True

def capture_picture(self: _owner.EzvizClient, serial: str, channel: int, *, max_retries: int=0) -> _owner.JsonDict:
    """Trigger a snapshot capture on the device."""
    path = f'/v3/devconfig/v1/{serial}/{channel}/capture'
    json_output = self._request_json('PUT', path, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not capture picture')
    return json_output

def get_cam_key(self: _owner.EzvizClient, serial: str, smscode: str | int | None=None, max_retries: int=0) -> _owner.Any:
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
        json_output = self._request_json('POST', _owner.API_ENDPOINT_CAM_ENCRYPTKEY, data={'checkcode': smscode, 'serial': serial, 'clientNo': 'web_site', 'clientType': 3, 'netType': 'WIFI', 'featureCode': _owner.FEATURE_CODE, 'sessionId': self._token.get('session_id')}, retry_401=True, max_retries=0)
        code = str(json_output.get('resultCode'))
        if code == '20002':
            raise _owner.EzvizAuthVerificationCode(f'MFA code required: Got {self._response_summary(json_output)})')
        if code == '2009':
            raise _owner.DeviceException(f'Device not reachable: Got {self._response_summary(json_output)})')
        if code == '0':
            return json_output.get('encryptkey')
        if code == '-1' and attempt < attempts:
            _owner._LOGGER.warning('Http_retry: serial=%s code=%s msg=%s', serial, code, 'cam_key_not_found')
            continue
        raise _owner.PyEzvizError(f'Could not get camera encryption key: Got {self._response_summary(json_output)})')
    raise _owner.PyEzvizError('Could not get camera encryption key: exceeded retries')

def download_alarm_image(self: _owner.EzvizClient, image_url: str, serial: str | None=None, *, encryption_key: str | None=None, smscode: str | int | None=None, decrypt: bool=True, max_retries: int=0) -> bytes:
    """Download an alarm image and decrypt EZVIZ/Hik encrypted payloads.

        Encrypted alarm snapshots contain the ``hikencodepicture`` header. When
        that header is present and no explicit ``encryption_key`` is supplied,
        ``serial`` is used to fetch the camera encryption key from the EZVIZ API.
        """
    resp = self._http_request('GET', image_url, retry_401=False, max_retries=0)
    image_data = resp.content
    if not decrypt or not image_data or _owner.HIK_ENCRYPTION_HEADER not in image_data:
        return image_data
    key = encryption_key
    if key is None:
        if not serial:
            raise _owner.PyEzvizError('Camera serial or encryption key is required to decrypt image')
        key = self.get_cam_key(serial, smscode=smscode, max_retries=max_retries)
    return _owner.decrypt_image(image_data, key)
