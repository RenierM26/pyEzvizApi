# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'recordings implementation; runtime hooks arrive through an explicit owner context.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pyezvizapi.client as _owner_types

def search_records(self: _owner_types.EzvizClient, serial: str, channel: int, channel_serial: str, start_time: str, stop_time: str, *, size: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Search recorded video clips for a device."""
    params = {'deviceSerial': serial, 'channelNo': channel, 'channelSerial': channel_serial, 'startTime': start_time, 'stopTime': stop_time, 'size': size}
    json_output = self._request_json('GET', _owner.API_ENDPOINT_STREAMING_RECORDS, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not search records')
    return json_output

def search_records_v2(self: _owner_types.EzvizClient, serial: str, channel: int, start_time: str, stop_time: str, *, size: int, sort_by: int, require_label: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Search SD-card playback records with the app's v2 record endpoint."""
    params = {'deviceSerial': serial, 'channelNo': channel, 'startTime': start_time, 'stopTime': stop_time, 'size': size, 'sortBy': sort_by, 'requireLabel': require_label}
    json_output = self._request_json('GET', _owner.API_ENDPOINT_STREAMING_RECORDS_V2, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not search v2 records')
    return json_output

def search_common_records(self: _owner_types.EzvizClient, serial: str, channel: int, start_time: str, stop_time: str, *, channel_serial: str | None, record_type: int, size: int, version: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Search common SD-card playback records.

        This mirrors the EZVIZ app's ``PlaybackRecordApi.searchRecordV3`` path.
        """
    params: dict[str, _owner_types.Any] = {'deviceSerial': serial, 'channelNo': channel, 'startTime': start_time, 'stopTime': stop_time, 'recordType': record_type, 'size': size, 'version': version}
    if channel_serial is not None:
        params['channelSerial'] = channel_serial
    json_output = self._request_json('GET', _owner.API_ENDPOINT_STREAMING_RECORDS_COMMON, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not search common records')
    return json_output

def search_intelligent_records(self: _owner_types.EzvizClient, serial: str, channel: int, start_time: str, stop_time: str, *, version: int, record_filter: str | None, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Search intelligent SD-card playback records."""
    params: dict[str, _owner_types.Any] = {'deviceSerial': serial, 'channelNo': channel, 'startTime': start_time, 'stopTime': stop_time, 'version': version}
    if record_filter is not None:
        params['filter'] = record_filter
    json_output = self._request_json('GET', _owner.API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not search intelligent records')
    return json_output

def decode_records_payload(value: str, *, _owner: _ModuleType) -> list[_owner_types.Any]:
    """Decode an EZVIZ base64+zlib JSON record-list payload."""
    try:
        raw = _owner.base64.b64decode(value, validate=True)
        decoded = _owner.zlib.decompress(raw).decode('utf-8').strip()
        parsed = _owner.json.loads(decoded)
    except (ValueError, _owner.zlib.error, UnicodeDecodeError, _owner.json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []

def extract_record_list(cls: type[_owner_types.EzvizClient], payload: _owner_types.Any, *, _owner: _ModuleType) -> list[_owner_types.Any]:
    """Return the first plain or compressed record list in a response."""
    if isinstance(payload, str):
        return cls.decode_records_payload(payload)
    if not isinstance(payload, _StaticMapping):
        return payload if isinstance(payload, list) else []
    records: list[_owner_types.Any] = []
    for key in ('records', 'record', 'files', 'fileList', 'videos', 'videoList', 'data'):
        value = payload.get(key)
        if isinstance(value, list):
            records = value
            break
        if isinstance(value, str):
            nested = cls.decode_records_payload(value)
            if nested:
                records = nested
                break
        if isinstance(value, _StaticMapping):
            nested = cls.extract_record_list(value)
            if nested:
                records = nested
                break
    if not records:
        for value in payload.values():
            if isinstance(value, _StaticMapping):
                nested = cls.extract_record_list(value)
                if nested:
                    records = nested
                    break
    return records

def get_cloud_videos(self: _owner_types.EzvizClient, serial: str, channel: int, *, limit: int, video_type: int, support_multi_channel_shared_service: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Return cloud video descriptors for a device.

        The EZVIZ app uses this endpoint before native cloud download. Returned
        items may include ``streamUrl``, ``seqId``, ``storageVersion``,
        ``fileSize``, ``crypt``, and ``keyChecksum``.
        """
    params = {'deviceSerial': serial, 'channelNo': channel, 'limit': limit, 'videoType': video_type, 'supportMultiChannelSharedService': support_multi_channel_shared_service}
    json_output = self._request_json('GET', _owner.API_ENDPOINT_CLOUD_VIDEOS_LIST, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get cloud videos')
    return json_output

def get_cloud_video_details(self: _owner_types.EzvizClient, serial: str, channel: int, videos: _owner_types.Iterable[_owner_types.Mapping[str, _owner_types.Any]], *, support_multi_channel_shared_service: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Return detailed cloud video descriptors for selected videos."""
    body = {'deviceSerial': serial, 'channelNo': channel, 'supportMultiChannelSharedService': support_multi_channel_shared_service, 'videos': [{'seqId': video['seqId'], 'startTime': video['startTime'], 'stopTime': video['stopTime'], 'storageVersion': video.get('storageVersion', 2)} for video in videos]}
    json_output = self._request_json('POST', _owner.API_ENDPOINT_CLOUD_VIDEO_DETAILS, json_body=body, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get cloud video details')
    return json_output

def get_camera_ticket_info(self: _owner_types.EzvizClient, serial: str, channel: int, *, support_multi_channel_shared_service: int, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Return the camera playback ticket used by native cloud storage downloads.

        The official app feeds ``ticketInfo.ticket`` into
        ``DownloadCloudParam.szTicketToken`` for normal cloud-storage clips.
        """
    params = {'deviceSerial': serial, 'channelNo': channel, 'supportMultiChannelSharedService': support_multi_channel_shared_service}
    json_output = self._request_json('GET', _owner.API_ENDPOINT_CAMERA_TICKET_INFO, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get camera ticket info')
    return json_output

def _extract_cloud_video_download_url(video: _owner_types.Mapping[str, _owner_types.Any], *, _owner: _ModuleType) -> str | None:
    """Return the first direct HTTP(S) video URL in a cloud video descriptor."""
    media_url_keys = {'downloadUrl', 'downloadURL', 'fileUrl', 'fileURL', 'playbackUrl', 'playbackURL', 'videoUrl', 'videoURL'}
    media_container_keys = {'clip', 'clips', 'download', 'downloadInfo', 'file', 'files', 'media', 'playback', 'playbackInfo', 'video', 'videos'}
    queue: list[tuple[_owner_types.Any, bool]] = [(video, False)]
    while queue:
        current, is_media_container = queue.pop(0)
        if isinstance(current, _StaticMapping):
            for key, value in current.items():
                child_is_media_container = is_media_container or key in media_container_keys
                if isinstance(value, str):
                    if key in media_url_keys and value.startswith(('http://', 'https://')):
                        return value
                    if key == 'url' and is_media_container and value.startswith(('http://', 'https://')):
                        return value
                elif isinstance(value, _StaticMapping | list):
                    queue.append((value, child_is_media_container))
        elif isinstance(current, list):
            queue.extend((item, is_media_container) for item in current)
    return None

def download_cloud_video(self: _owner_types.EzvizClient, video: _owner_types.Mapping[str, _owner_types.Any], *, max_retries: int, _owner: _ModuleType) -> bytes:
    """Download a cloud video when the descriptor contains a direct HTTP URL.

        Most EZVIZ cloud clip descriptors returned by ``/v3/clouds/videoDetails``
        expose a native SDK ``streamUrl`` host/port instead of a direct media URL.
        Those native stream descriptors cannot be downloaded through this helper.
        """
    url = self._extract_cloud_video_download_url(video)
    if url is None:
        stream_url = video.get('streamUrl')
        suffix = f' Native streamUrl={stream_url!r} requires the EZVIZ SDK path.' if stream_url else ''
        raise _owner.PyEzvizError('Cloud video descriptor does not include a direct HTTP(S) download URL.' + suffix)
    resp = self._http_request('GET', url, retry_401=False, max_retries=max_retries)
    return resp.content

def search_device(self: _owner_types.EzvizClient, serial: str, *, user_ssid: str | None, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Find device information by serial."""
    headers = dict(self._session.headers)
    if user_ssid is not None:
        headers['userSsid'] = user_ssid
    params = {'deviceSerial': serial}
    req = _owner.requests.Request(method='GET', url=self._url(_owner.API_ENDPOINT_USERDEVICES_SEARCH), headers=headers, params=params).prepare()
    resp = self._send_prepared(req, retry_401=True, max_retries=max_retries)
    json_output = self._parse_json(resp)
    if not self._meta_ok(json_output):
        raise _owner.PyEzvizError(f'Could not search device: Got {self._response_summary(json_output)})')
    return json_output

def get_socket_log_info(self: _owner_types.EzvizClient, serial: str, start: str, end: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Fetch smart outlet switch logs within a time range."""
    path = _owner.API_ENDPOINT_SMARTHOME_OUTLET_LOG.format(**{'from': start, 'to': end})
    json_output = self._request_json('GET', path, params={'deviceSerial': serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get socket log info')
    return json_output

def linked_cameras(self: _owner_types.EzvizClient, serial: str, detector_serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """List cameras linked to a detector device."""
    params = {'deviceSerial': serial, 'detectorDeviceSerial': detector_serial}
    json_output = self._request_json('GET', _owner.API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not get linked cameras')
    return json_output

def set_microscope(self: _owner_types.EzvizClient, serial: str, multiple: float, x: int, y: int, index: int, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Configure microscope lens parameters."""
    data = {'multiple': multiple, 'x': x, 'y': y, 'index': index}
    json_output = self._request_json('PUT', f'{_owner.API_ENDPOINT_DEVICES}{serial}/microscope', data=data, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not set microscope')
    return json_output

def share_accept(self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Accept a device share invitation."""
    json_output = self._request_json('POST', _owner.API_ENDPOINT_SHARE_ACCEPT, data={'deviceSerial': serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not accept share')
    return json_output

def share_quit(self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Leave a shared device."""
    json_output = self._request_json('DELETE', _owner.API_ENDPOINT_SHARE_QUIT, params={'deviceSerial': serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not quit share')
    return json_output

def send_feedback(self: _owner_types.EzvizClient, *, email: str, account: str, score: int, feedback: str, pic_url: str | None, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Submit feedback to Ezviz support."""
    params: dict[str, _owner_types.Any] = {'email': email, 'account': account, 'score': score, 'feedback': feedback}
    if pic_url is not None:
        params['picUrl'] = pic_url
    json_output = self._request_json('POST', _owner.API_ENDPOINT_FEEDBACK, params=params, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not send feedback')
    return json_output

def upload_device_log(self: _owner_types.EzvizClient, serial: str, *, max_retries: int, _owner: _ModuleType) -> _owner_types.JsonDict:
    """Trigger device log upload to Ezviz cloud."""
    json_output = self._request_json('POST', '/v3/devconfig/dump/app/trigger', data={'deviceSerial': serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(json_output, 'Could not upload device log')
    return json_output

def alarm_sound(self: _owner_types.EzvizClient, serial: str, sound_type: int, enable: int, voice_id: int | None, max_retries: int, *, _owner: _ModuleType) -> bool:
    """Enable alarm sound by API."""
    if max_retries > _owner.MAX_RETRIES:
        raise _owner.PyEzvizError("Can't gather proper data. Max retries exceeded.")
    if sound_type not in [0, 1, 2]:
        raise _owner.PyEzvizError('Invalid sound_type, should be 0,1,2: ' + str(sound_type))
    voice_id_value = 0 if voice_id is None else voice_id
    response_json = self._request_json('PUT', f'{_owner.API_ENDPOINT_DEVICES}{serial}{_owner.API_ENDPOINT_ALARM_SOUND}', data={'enable': enable, 'soundType': sound_type, 'voiceId': voice_id_value, 'deviceSerial': serial}, retry_401=True, max_retries=max_retries)
    self._ensure_ok(response_json, 'Could not set alarm sound')
    _owner._LOGGER.debug('http_debug: serial=%s code=%s msg=%s', serial, self._meta_code(response_json), 'alarm_sound')
    return True
