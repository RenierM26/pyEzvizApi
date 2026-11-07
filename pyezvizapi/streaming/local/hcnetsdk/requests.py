# Runtime hook context is explicit; immutable value types come from dependency leaves.
# ruff: noqa: SLF001
'requests implementation; legacy runtime hooks remain on the owner module.\n\nAccess through _owner is deliberate: callers that patch the compatibility\nmodule must still affect dependent operations. No copied hook snapshots.\n'
from __future__ import annotations

from collections.abc import Mapping as _StaticMapping
from contextlib import suppress as _suppress
from datetime import date as _Staticdate, datetime as _Staticdatetime
from types import ModuleType as _ModuleType
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkTime as _StaticHcNetSdkTime

if TYPE_CHECKING:
    import pyezvizapi._typing.hcnetsdk as _owner_types

def hcnetsdk_real_data_to_media_packet(packet: _owner_types.HcNetSdkRealDataPacket, *, _owner: _ModuleType) -> _owner_types.MediaPacket:
    """Normalize an HCNetSDK callback packet without changing its SDK model."""
    return _owner.MediaPacket(body=packet.body, metadata=_owner.MediaPacketMetadata(source='hcnetsdk', data_type=packet.data_type, attributes={'real_handle': packet.real_handle, 'payload_kind': packet.payload_kind}))

def hcnetsdk_media_packet_source(packets: _owner_types.Iterable[_owner_types.HcNetSdkRealDataPacket], *, cancel: _owner_types.Callable[[], None] | None, _owner: _ModuleType) -> _owner_types.IterableMediaPacketSource[_owner_types.HcNetSdkRealDataPacket]:
    """Adapt HCNetSDK callback media packets to the shared packet contract."""
    return _owner.IterableMediaPacketSource(packets, _owner.hcnetsdk_real_data_to_media_packet, predicate=lambda packet: packet.is_media, cancel=cancel)

def hcnetsdk_time(year: int, month: int, day: int, *, hour: int, minute: int, second: int, _owner: _ModuleType) -> _owner_types.HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` field model."""
    return _owner.HcNetSdkTime(year=year, month=month, day=day, hour=hour, minute=minute, second=second)

def hcnetsdk_time_from_datetime(value: _owner_types.datetime, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` model from a Python ``datetime``."""
    return _owner.HcNetSdkTime.from_datetime(value)

def hcnetsdk_file_search_condition(channel: int, start_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, stop_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, *, file_type: int, is_locked: int, use_card_no: int, card_number: str | bytes, _owner: _ModuleType) -> _owner_types.HcNetSdkFileCond:
    """Return a generic ``NET_DVR_FILECOND`` playback search condition."""
    return _owner.HcNetSdkFileCond(channel=channel, start_time=_owner._hcnetsdk_time_value(start_time), stop_time=_owner._hcnetsdk_time_value(stop_time, end_of_day=True), file_type=file_type, is_locked=is_locked, use_card_no=use_card_no, card_number=card_number)

def ezviz_lan_playback_file_search_condition(channel: int, start_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, stop_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, *, _owner: _ModuleType) -> _owner_types.HcNetSdkFileCond:
    """Return the APK-observed LAN playback file-search condition."""
    return _owner.hcnetsdk_file_search_condition(channel, start_time, stop_time, file_type=_owner.HCNETSDK_PLAYBACK_FILE_TYPE_ALL, is_locked=_owner.HCNETSDK_PLAYBACK_LOCK_STATE_ALL, use_card_no=0)

def hcnetsdk_playback_condition(channel: int, start_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, stop_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, *, draw_frame: int, stream_type: int, stream_id: str | bytes, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayCond:
    """Return a generic ``NET_DVR_PLAYCOND`` time-playback condition."""
    return _owner.HcNetSdkPlayCond(channel=channel, start_time=_owner._hcnetsdk_time_value(start_time), stop_time=_owner._hcnetsdk_time_value(stop_time, end_of_day=True), draw_frame=draw_frame, stream_type=stream_type, stream_id=stream_id)

def ezviz_lan_playback_condition(channel: int, start_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, stop_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, *, stream_type: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayCond:
    """Return the APK-compatible LAN playback-by-time condition."""
    return _owner.hcnetsdk_playback_condition(channel, start_time, stop_time, draw_frame=0, stream_type=stream_type)

def hcnetsdk_init_request(playctrl_library: str | None, *, _owner: _ModuleType) -> _owner_types.HcNetSdkInitRequest:
    """Return the ``NET_DVR_Init`` request shape used before LAN SDK calls."""
    return _owner.HcNetSdkInitRequest(playctrl_library=playctrl_library)

def hcnetsdk_cleanup_request(*, _owner: _ModuleType) -> _owner_types.HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_Cleanup`` request shape."""
    return _owner.HcNetSdkNoArgRequest(api=_owner.HCNETSDK_CLEANUP)

def hcnetsdk_set_connect_time_request(connect_time_ms: int, retry_count: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkSetConnectTimeRequest:
    """Return the APK-style ``NET_DVR_SetConnectTime`` request shape."""
    return _owner.HcNetSdkSetConnectTimeRequest(connect_time_ms=connect_time_ms, retry_count=retry_count)

def hcnetsdk_get_last_error_request(*, _owner: _ModuleType) -> _owner_types.HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetLastError`` request shape."""
    return _owner.HcNetSdkNoArgRequest(api=_owner.HCNETSDK_GET_LAST_ERROR)

def hcnetsdk_get_error_msg_request(error_code: int | None, *, _owner: _ModuleType) -> _owner_types.HcNetSdkGetErrorMsgRequest:
    """Return the ``NET_DVR_GetErrorMsg`` request shape."""
    return _owner.HcNetSdkGetErrorMsgRequest(error_code=error_code)

def hcnetsdk_get_sdk_version_request(*, _owner: _ModuleType) -> _owner_types.HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKVersion`` request shape."""
    return _owner.HcNetSdkNoArgRequest(api=_owner.HCNETSDK_GET_SDK_VERSION)

def hcnetsdk_get_sdk_build_version_request(*, _owner: _ModuleType) -> _owner_types.HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKBuildVersion`` request shape."""
    return _owner.HcNetSdkNoArgRequest(api=_owner.HCNETSDK_GET_SDK_BUILD_VERSION)

def hcnetsdk_logout_v30_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkLogoutRequest:
    """Return the ``NET_DVR_Logout_V30`` request shape."""
    return _owner.HcNetSdkLogoutRequest(login_id=login_id)

def hcnetsdk_find_file_v30_request(login_id: int, file_cond: _owner_types.HcNetSdkFileCond, *, _owner: _ModuleType) -> _owner_types.HcNetSdkFindFileRequest:
    """Return the ``NET_DVR_FindFile_V30`` request shape."""
    return _owner.HcNetSdkFindFileRequest(login_id=login_id, file_cond=file_cond)

def hcnetsdk_find_next_file_v30_request(find_handle: int, *, find_data: _owner_types.HcNetSdkFindDataV30 | None, _owner: _ModuleType) -> _owner_types.HcNetSdkFindNextFileRequest:
    """Return the ``NET_DVR_FindNextFile_V30`` request shape."""
    return _owner.HcNetSdkFindNextFileRequest(find_handle=find_handle, find_data=find_data)

def hcnetsdk_find_close_v30_request(find_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkFindCloseRequest:
    """Return the ``NET_DVR_FindClose_V30`` request shape."""
    return _owner.HcNetSdkFindCloseRequest(find_handle=find_handle)

def hcnetsdk_playback_by_time_v40_request(login_id: int, play_cond: _owner_types.HcNetSdkPlayCond, *, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayBackByTimeRequest:
    """Return the ``NET_DVR_PlayBackByTime_V40`` request shape."""
    return _owner.HcNetSdkPlayBackByTimeRequest(login_id=login_id, play_cond=play_cond)

def hcnetsdk_playback_control_v40_request(play_handle: int, command: int | _owner_types.HcNetSdkPlaybackControlCommand, *, in_buffer: str | bytes | None, out_buffer_size: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayBackControlRequest:
    """Return the ``NET_DVR_PlayBackControl_V40`` request shape."""
    return _owner.HcNetSdkPlayBackControlRequest(play_handle=play_handle, command=int(command), in_buffer=in_buffer, out_buffer_size=out_buffer_size)

def hcnetsdk_stop_playback_request(play_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkStopPlayBackRequest:
    """Return the ``NET_DVR_StopPlayBack`` request shape."""
    return _owner.HcNetSdkStopPlayBackRequest(play_handle=play_handle)

def hcnetsdk_playback_capture_file_request(play_handle: int, saved_file_name: str | bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayBackCaptureFileRequest:
    """Return the ``NET_DVR_PlayBackCaptureFile`` request shape."""
    return _owner.HcNetSdkPlayBackCaptureFileRequest(play_handle=play_handle, saved_file_name=saved_file_name)

def hcnetsdk_set_play_data_callback_request(play_handle: int, *, callback: str | None, user_data: str | int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack`` request shape."""
    return _owner.HcNetSdkPlayDataCallbackRequest(play_handle=play_handle, callback=callback, user_data=user_data)

def hcnetsdk_set_play_data_callback_v40_request(play_handle: int, *, callback: str | None, user_data: str | int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack_V40`` request shape."""
    return _owner.HcNetSdkPlayDataCallbackRequest(play_handle=play_handle, callback=callback, user_data=user_data, api=_owner.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40)

def hcnetsdk_set_playback_response_callback_request(play_handle: int, *, callback: str | None, user_data: str | int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlaybackResponseCallBack`` request shape."""
    return _owner.HcNetSdkPlaybackCallbackRequest(play_handle=play_handle, callback=callback, user_data=user_data)

def hcnetsdk_set_playback_es_callback_request(play_handle: int, *, callback: str | None, user_data: str | int | None, _owner: _ModuleType) -> _owner_types.HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlayBackESCallBack`` request shape."""
    return _owner.HcNetSdkPlaybackCallbackRequest(play_handle=play_handle, callback=callback, user_data=user_data, api=_owner.HCNETSDK_SET_PLAYBACK_ES_CALLBACK)

def hcnetsdk_set_playback_secret_key_request(play_handle: int, secret_key: str | bytes, *, secret_key_type: int, _owner: _ModuleType) -> _owner_types.HcNetSdkPlayBackSecretKeyRequest:
    """Return the ``NET_DVR_SetPlayBackSecretKey`` request shape."""
    return _owner.HcNetSdkPlayBackSecretKeyRequest(play_handle=play_handle, secret_key=secret_key, secret_key_type=secret_key_type)

def hcnetsdk_get_file_by_name_request(login_id: int, dvr_file_name: str | bytes, saved_file_name: str | bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkGetFileByNameRequest:
    """Return the ``NET_DVR_GetFileByName`` request shape."""
    return _owner.HcNetSdkGetFileByNameRequest(login_id=login_id, dvr_file_name=dvr_file_name, saved_file_name=saved_file_name)

def hcnetsdk_get_file_by_time_request(login_id: int, channel: int, start_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, stop_time: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, saved_file_name: str | bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkGetFileByTimeRequest:
    """Return the ``NET_DVR_GetFileByTime`` request shape."""
    return _owner.HcNetSdkGetFileByTimeRequest(login_id=login_id, channel=channel, start_time=_owner._hcnetsdk_time_value(start_time), stop_time=_owner._hcnetsdk_time_value(stop_time, end_of_day=True), saved_file_name=saved_file_name)

def hcnetsdk_stop_get_file_request(file_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkStopGetFileRequest:
    """Return the ``NET_DVR_StopGetFile`` request shape."""
    return _owner.HcNetSdkStopGetFileRequest(file_handle=file_handle)

def hcnetsdk_get_download_pos_request(file_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkGetDownloadPosRequest:
    """Return the ``NET_DVR_GetDownloadPos`` request shape."""
    return _owner.HcNetSdkGetDownloadPosRequest(file_handle=file_handle)

def hcnetsdk_find_next_file_status(native_result: int, *, _owner: _ModuleType) -> str:
    """Return the app-observed meaning of ``NET_DVR_FindNextFile_V30``."""
    if native_result == _owner.HCNETSDK_FIND_NEXT_FILE_SUCCESS:
        return 'file'
    if native_result == _owner.HCNETSDK_FIND_NEXT_FILE_NO_FILE:
        return 'no_file'
    if native_result == _owner.HCNETSDK_FIND_NEXT_FILE_IS_FINDING:
        return 'finding'
    if native_result == _owner.HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE:
        return 'no_more_file'
    if native_result == _owner.HCNETSDK_FIND_NEXT_FILE_EXCEPTION:
        return 'exception'
    return 'unknown'

def ezviz_lan_playback_video_type(native_file_type: int, *, _owner: _ModuleType) -> int:
    """Map native file type to the EZVIZ ``CloudFile.videoType`` value."""
    return _owner.EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP.get(native_file_type, 0)

def hcnetsdk_stdxml_isapi_request(method: str, path: str, body: _owner_types.Mapping[str, _owner_types.Any] | str | bytes | None, *, _owner: _ModuleType) -> str:
    """Return the ISAPI request text passed to ``NET_DVR_STDXMLConfig``."""
    method_name = method.strip().upper()
    if not method_name or any(char in method_name for char in ' \r\n\t'):
        raise _owner.PyEzvizError('HCNetSDK STDXML method is invalid')
    if not path.startswith('/') or '\r' in path or '\n' in path:
        raise _owner.PyEzvizError('HCNetSDK STDXML path is invalid')
    request = f'{method_name} {path}\r\n'
    if body is None:
        return request
    if isinstance(body, _StaticMapping):
        body_text = _owner.json.dumps(dict(body), separators=(',', ':'))
    elif isinstance(body, bytes):
        body_text = body.decode('utf-8')
    else:
        body_text = body
    return request + body_text + '\r\n'

def ezviz_lan_connect_mode_payload(mode: int, *, _owner: _ModuleType) -> dict[str, _owner_types.Any]:
    """Return the local ``connectMode`` payload used when leaving AP mode."""
    if mode < 0:
        raise _owner.PyEzvizError('EZVIZ LAN connect mode must be non-negative')
    return {'ConnectMode': {'mode': mode}}

def ezviz_lan_connect_mode_put_request(mode: int, *, _owner: _ModuleType) -> str:
    """Return the raw local ISAPI ``connectMode`` PUT request."""
    return _owner.hcnetsdk_stdxml_isapi_request('PUT', '/ISAPI/EZVIZ/IPC/System/Network/connectMode?format=json', _owner.ezviz_lan_connect_mode_payload(mode))

def ezviz_lan_audio_input_param(data: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> _owner_types.EzvizLanAudioInputParam:
    """Parse known ``NET_DVR_AUDIO_INPUT_PARAM`` fields from command output."""
    raw = bytes(data)
    if len(raw) < _owner.HCNETSDK_AUDIO_INPUT_PARAM_SIZE:
        raise _owner.PyEzvizError('EZVIZ LAN audio-input response is too short')
    return _owner.EzvizLanAudioInputParam(audio_input_type=raw[0], volume=raw[1], noise_filter_enabled=raw[2], raw=raw[:_owner.HCNETSDK_AUDIO_INPUT_PARAM_SIZE])

def ezviz_lan_ezviz_access_replacement_domain(domain: str | bytes | None, *, fallback: str, _owner: _ModuleType) -> str:
    """Return the domain rewrite performed by ``HCNETUtil.g``."""
    text = _owner._nul_stripped_text(domain)
    return text.replace('ezvizlife', 'ezvizru') if text else fallback

def ezviz_lan_ezviz_access_set_domain_request(login_id: int, domain: str | bytes, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` domain update shape."""
    domain_bytes = _owner._bounded_bytes('EZVIZ access domain', domain, 64)
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_EZVIZ_ACCESS_CFG, channel=1, structure='NET_DVR_EZVIZ_ACCESS_CFG', field_updates={'byDomainName': domain_bytes, 'byDomainNameLength': len(domain_bytes)}, read_before_write=True)

def ezviz_lan_ezviz_access_replacement_domain_request(login_id: int, current_domain: str | bytes | None, *, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the local-add domain rewrite request used on RU accounts."""
    return _owner.ezviz_lan_ezviz_access_set_domain_request(login_id, _owner.ezviz_lan_ezviz_access_replacement_domain(current_domain))

def ezviz_lan_video_coding_update_request(login_id: int, channel: int, *, video_encoding_type: int, video_frame_rate: int, video_bitrate: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN video-coding update request shape."""
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_COMPRESSION_CFG_V30, channel=channel, structure='NET_DVR_COMPRESSIONCFG_V30', field_updates={'struNormHighRecordPara.byVideoEncType': _owner._byte_value('video encoding type', video_encoding_type), 'struNormHighRecordPara.dwVideoFrameRate': _owner._byte_value('video frame rate', video_frame_rate), 'struNormHighRecordPara.dwVideoBitrate': _owner._dword_value('video bitrate', video_bitrate)}, read_before_write=True)

def hcnetsdk_setup_alarm_v30_request(login_id: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkSetupAlarmRequest:
    """Return the legacy ``NET_DVR_SetupAlarmChan_V30`` request shape."""
    return _owner.HcNetSdkSetupAlarmRequest(login_id=login_id)

def hcnetsdk_setup_alarm_v41_request(login_id: int, *, level: int, alarm_info_type: int, ret_alarm_type_v40: int, ret_dev_info_version: int, ret_vqd_alarm_type: int, face_alarm_detection: int, support: int, broken_net_http: int, task_no: int, _owner: _ModuleType) -> _owner_types.HcNetSdkSetupAlarmRequest:
    """Return a ``NET_DVR_SetupAlarmChan_V41`` request model."""
    return _owner.HcNetSdkSetupAlarmRequest(login_id=login_id, setup_param=_owner.HcNetSdkSetupAlarmParam(level=level, alarm_info_type=alarm_info_type, ret_alarm_type_v40=ret_alarm_type_v40, ret_dev_info_version=ret_dev_info_version, ret_vqd_alarm_type=ret_vqd_alarm_type, face_alarm_detection=face_alarm_detection, support=support, broken_net_http=broken_net_http, task_no=task_no))

def hcnetsdk_close_alarm_request(alarm_handle: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkCloseAlarmRequest:
    """Return the ``NET_DVR_CloseAlarmChan_V30`` request shape."""
    return _owner.HcNetSdkCloseAlarmRequest(alarm_handle=alarm_handle)

def hcnetsdk_set_sdk_local_cfg_request(cfg_type: int, *, structure: str, field_updates: _owner_types.Mapping[str, _owner_types.Any] | None, field_order: tuple[str, ...] | None, _owner: _ModuleType) -> _owner_types.HcNetSdkSetSdkLocalCfgRequest:
    """Return a generic ``NET_DVR_SetSDKLocalCfg`` request model."""
    return _owner.HcNetSdkSetSdkLocalCfgRequest(cfg_type=int(cfg_type), structure=structure, field_updates=field_updates, field_order=field_order)

def ezviz_lan_video_effect_update_request(login_id: int, *, brightness: int, contrast: int, saturation: int, sharpness: int, _owner: _ModuleType) -> _owner_types.HcNetSdkDvrConfigRequest:
    """Return the RN LAN camera video-effect update request shape."""
    return _owner.hcnetsdk_dvr_config_set_request(login_id, _owner.HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG, structure='NET_DVR_CAMERAPARAMCFG', field_updates={'struVideoEffect.byBrightnessLevel': _owner._byte_value('brightness level', brightness), 'struVideoEffect.byContrastLevel': _owner._byte_value('contrast level', contrast), 'struVideoEffect.bySaturationLevel': _owner._byte_value('saturation level', saturation), 'struVideoEffect.bySharpnessLevel': _owner._byte_value('sharpness level', sharpness)}, read_before_write=True)

def ezviz_lan_audio_video_compress_info_input(channel: int, *, _owner: _ModuleType) -> bytes:
    """Return the stream-config video ability XML used by the APK."""
    return _owner.hcnetsdk_device_ability_xml('AudioVideoCompressInfo', channel=channel, channel_tag='VideoChannelNumber', version=None)

def ezviz_lan_audio_video_compress_info(response: str | bytes, *, _owner: _ModuleType) -> _owner_types.EzvizLanAudioVideoCompressInfo:
    """Parse safe stream/audio fields from ``AudioVideoCompressInfo`` XML."""
    try:
        root = _owner.ET.fromstring(_owner._device_ability_response_text(response))
    except _owner.ET.ParseError as err:
        raise _owner.PyEzvizError('Invalid EZVIZ LAN audio/video compress XML') from err
    video_root = _owner._xml_first_child(root, 'VideoCompressInfo')
    audio_root = _owner._xml_first_child(root, 'AudioCompressInfo')
    video_channels = _owner._audio_video_compress_video_channels(video_root) if video_root is not None else ()
    audio_channels: tuple[_owner_types.EzvizLanAudioVideoCompressAudioChannel, ...] = ()
    voice_talk_channels: tuple[_owner_types.EzvizLanAudioVideoCompressVoiceTalkChannel, ...] = ()
    if audio_root is not None:
        audio_section = _owner._xml_first_child(audio_root, 'Audio')
        voice_talk_section = _owner._xml_first_child(audio_root, 'VoiceTalk')
        if audio_section is not None:
            audio_channels = _owner._audio_video_compress_audio_channels(audio_section)
        if voice_talk_section is not None:
            voice_talk_channels = _owner._audio_video_compress_voice_talk_channels(voice_talk_section)
    return _owner.EzvizLanAudioVideoCompressInfo(video_channels=video_channels, audio_channels=audio_channels, voice_talk_channels=voice_talk_channels, has_video_compress_info=video_root is not None, has_audio_compress_info=audio_root is not None)

def ezviz_lan_settings_error_code(hcnetsdk_error: int, *, _owner: _ModuleType) -> int:
    """Return the LAN settings UI error code for an HCNetSDK error."""
    return _owner.HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE + hcnetsdk_error

def read_hcnetsdk_tcp_frame(sock: _owner_types.Any, *, max_frame_bytes: int | None, allow_short_ack: bool, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpFrame:
    """Read one complete HCNetSDK command-port frame from a socket-like object."""
    if max_frame_bytes is not None and max_frame_bytes < _owner.HCNETSDK_TCP_HEADER_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK frame limit must include the 16-byte header')
    header_bytes = _owner._recv_exact(sock, _owner.HCNETSDK_TCP_HEADER_LENGTH)
    total_length = int.from_bytes(header_bytes[0:4], 'big')
    if max_frame_bytes is not None and total_length > max_frame_bytes:
        raise _owner.PyEzvizError('HCNetSDK response exceeds discovery frame limit')
    if total_length < _owner.HCNETSDK_TCP_HEADER_LENGTH:
        if not allow_short_ack:
            raise _owner.PyEzvizError('HCNetSDK TCP frame total length is too small')
        header = _owner.HcNetSdkTcpFrameHeader(total_length=_owner.HCNETSDK_TCP_HEADER_LENGTH, field_4=int.from_bytes(header_bytes[4:8], 'big'), field_8=int.from_bytes(header_bytes[8:12], 'big'), field_12=int.from_bytes(header_bytes[12:16], 'big'))
        return _owner.HcNetSdkTcpFrame(header=header, body=b'')
    header = _owner.parse_hcnetsdk_tcp_frame_header(header_bytes)
    return _owner.HcNetSdkTcpFrame(header=header, body=_owner._recv_exact(sock, header.body_length))

def _hcnetsdk_command_port_md5_digest(data: bytes, *, _owner: _ModuleType) -> _owner_types.Any:
    return _owner.hashlib.md5(data, usedforsecurity=False)

def _hcnetsdk_command_port_md5_hmac(key: bytes, data: bytes, *, _owner: _ModuleType) -> bytes:
    return _owner.hmac.new(key, data, _owner._hcnetsdk_command_port_md5_digest).digest()

def hcnetsdk_command_port_control_template_from_frame(frame: bytes, *, addend: int | None, addend_delta: int | None, auth_seed: int | None, key: bytes | None, mask_seed: bytes, body_tail_transform: str | None, name: str | None, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortControlTemplate:
    """Extract the reusable command id and body tail from a ``0x63`` frame."""
    parsed = _owner.parse_hcnetsdk_tcp_frame(frame)
    if parsed.header.field_4 != _owner.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY:
        raise _owner.PyEzvizError('HCNetSDK command-port template requires a 0x63 frame')
    if len(parsed.body) < 16:
        raise _owner.PyEzvizError('HCNetSDK command-port control body is truncated')
    if parsed.body[8:16] != b'\x00' * 8:
        raise _owner.PyEzvizError('HCNetSDK command-port control reserved bytes are invalid')
    if addend is not None and addend_delta is not None:
        raise _owner.PyEzvizError('HCNetSDK command-port template cannot set addend and addend_delta')
    if addend is None and addend_delta is None and (auth_seed is not None) and (key is not None):
        session_id = parsed.body[4:8]
        folded = _owner.hcnetsdk_command_port_auth_word(session_id=session_id, auth_seed=auth_seed, command_id=parsed.header.field_12, key=key, addend=0, mask_seed=mask_seed)
        inferred_addend = parsed.header.field_8 - folded & 4294967295
        addend_delta = inferred_addend - int.from_bytes(session_id, 'big') & 4294967295
    return _owner.HcNetSdkCommandPortControlTemplate(command_id=parsed.header.field_12, body_tail=parsed.body[16:], addend=addend, addend_delta=addend_delta, mask_seed=mask_seed, body_tail_transform=body_tail_transform, name=name)

def hcnetsdk_command_port_public_key_der(rsa_key: _owner_types.Any, *, _owner: _ModuleType) -> bytes:
    """Return PKCS#1 ``RSAPublicKey`` DER for a PyCryptodome RSA key."""
    public_key = rsa_key.publickey() if rsa_key.has_private() else rsa_key
    return bytes(_owner.DerSequence([public_key.n, public_key.e]).encode())

def hcnetsdk_command_port_rsa_key(*, _owner: _ModuleType) -> _owner_types.Any:
    """Generate the protocol-mandated RSA key for command-port login."""
    return _owner.RSA.generate(_owner.HCNETSDK_COMMAND_PORT_RSA_BITS)

def iter_hcnetsdk_tcp_frame_shapes(records: _owner_types.Iterable[_owner_types.HcNetSdkTcpShapeLogRecord], *, _owner: _ModuleType) -> _owner_types.Iterator[_owner_types.HcNetSdkTcpFrameShape]:
    """Yield command frames reconstructed from secret-safe socket shape logs.

    Some logs record response headers and bodies as separate reads when the app
    asks libc for 16 bytes first and then the implied body length. This reducer
    pairs those adjacent records without needing payload bytes. Whole-frame
    writes are yielded as header-only shapes because their body content remains
    intentionally redacted.
    """
    pending = list(records)
    index = 0
    while index < len(pending):
        record = pending[index]
        total_length = record.shape.declared_length
        if record.shape.length == _owner.HCNETSDK_TCP_HEADER_LENGTH:
            total_length = record.shape.u32be_0
        if total_length is None or (record.shape.declared_length_offset != 0 and record.shape.length != _owner.HCNETSDK_TCP_HEADER_LENGTH) or total_length < _owner.HCNETSDK_TCP_HEADER_LENGTH:
            index += 1
            continue
        is_split_header = record.shape.length == _owner.HCNETSDK_TCP_HEADER_LENGTH
        is_whole_write = record.direction in {'send', 'write'} and record.shape.length == total_length
        if not is_split_header and (not is_whole_write):
            index += 1
            continue
        body_shape: _owner_types.HcNetSdkTcpPayloadShape | None = None
        if is_split_header:
            next_index = index + 1
            if next_index < len(pending):
                candidate = pending[next_index]
                same_stream = candidate.direction == record.direction and candidate.fd == record.fd and (candidate.host == record.host) and (candidate.port == record.port)
                if same_stream and candidate.shape.length == total_length - _owner.HCNETSDK_TCP_HEADER_LENGTH:
                    body_shape = candidate.shape
                    index += 1
        yield _owner.HcNetSdkTcpFrameShape(direction=record.direction, fd=record.fd, host=record.host, port=record.port, total_length=total_length, header_shape=record.shape, body_shape=body_shape)
        index += 1

def iter_hcnetsdk_real_data_mpegps(packets: _owner_types.Iterable[_owner_types.HcNetSdkRealDataPacket], *, include_system_header: bool, _owner: _ModuleType) -> _owner_types.Iterator[bytes]:
    """Yield MPEG-PS-like payloads from HCNetSDK real-play callback packets."""
    for packet in packets:
        if packet.data_type == _owner.HcNetSdkRealDataType.SYSTEM_HEADER:
            if include_system_header and packet.body:
                yield packet.body
            continue
        if not packet.is_media:
            continue
        if packet.payload_kind in {'mpeg_ps', 'mpeg_ps_start'}:
            yield packet.body

def ezviz_lan_settings_channel_number(*, analog_channel_count: int, digital_channel_count: int, analog_start_channel: int, digital_start_channel: int, _owner: _ModuleType) -> int:
    """Return the channel selected by LanDeviceListActivity.z0(...)."""
    total_channels = analog_channel_count + digital_channel_count
    if total_channels != 1:
        raise _owner.PyEzvizError('EZVIZ LAN single-preview handoff requires one channel')
    if analog_channel_count > 0:
        return analog_start_channel
    return digital_start_channel

def ezviz_lan_playback_intent(serial: str, *, channel_number: int, netsdk_login_id: int, ssid: str | None, lan_user_id: int | None, _owner: _ModuleType) -> _owner_types.EzvizLanPlaybackIntent:
    """Build the LAN playback extras passed into VideoPlayActivity.

    netsdk_login_id is validated because the settings screen only opens
    playback after HCNetSDK login succeeds. The intent EXTRA_LAN_USERID is
    separate: ActivityUtil.b(...) parses it from the optional SSID string and
    otherwise sends -1. The stream core performs/uses its own NetSDK login
    when creating the native init params.
    """
    device_serial = serial.strip()
    if not device_serial:
        raise _owner.PyEzvizError('Missing EZVIZ LAN playback device serial')
    if channel_number < 0:
        raise _owner.PyEzvizError('EZVIZ LAN playback channel number must be non-negative')
    if not _owner.ezviz_lan_settings_login_succeeded(netsdk_login_id):
        raise _owner.PyEzvizError('EZVIZ LAN playback requires a successful login id')
    wifi_ssid = ssid or ''
    extra_lan_user_id = -1
    if lan_user_id is not None:
        extra_lan_user_id = lan_user_id
    elif wifi_ssid:
        try:
            extra_lan_user_id = int(wifi_ssid)
        except ValueError:
            extra_lan_user_id = -1
    return _owner.EzvizLanPlaybackIntent(serial=device_serial, channel_number=channel_number, lan_user_id=extra_lan_user_id, ssid=wifi_ssid)

def ezviz_lan_video_qualities(*, _owner: _ModuleType) -> tuple[_owner_types.EzvizLanVideoQuality, ...]:
    """Return the two LAN quality entries exposed by the EZVIZ app."""
    return (_owner.EzvizLanVideoQuality(stream_type=_owner.EZVIZ_LAN_MAIN_STREAM_TYPE, video_level=_owner.EZVIZ_LAN_MAIN_VIDEO_LEVEL), _owner.EzvizLanVideoQuality(stream_type=_owner.EZVIZ_LAN_SUB_STREAM_TYPE, video_level=_owner.EZVIZ_LAN_SUB_VIDEO_LEVEL))

def ezviz_lan_video_level_for_stream_type(stream_type: int, *, _owner: _ModuleType) -> int:
    """Return the app's default LAN video level for a main/sub stream type."""
    if stream_type == _owner.EZVIZ_LAN_SUB_STREAM_TYPE:
        return _owner.EZVIZ_LAN_SUB_VIDEO_LEVEL
    return _owner.EZVIZ_LAN_MAIN_VIDEO_LEVEL

def ezviz_lan_live_view_params(endpoint: _owner_types.HcNetSdkLanEndpoint, *, channel_number: int, channel_serial: str | None, channel_index: str | None, channel_count: int | None, stream_type: int, video_level: int | None, netsdk_login_id: int, _owner: _ModuleType) -> _owner_types.EzvizLanLiveViewParams:
    """Build the LAN fields the EZVIZ player passes into its stream SDK.

    The Android app still uses ``LivePlaySource`` for LAN preview. The key
    difference is that the converted device param has ``isLocal()`` true and
    carries local IP/command/stream ports; when HCNetSDK login succeeds, the
    stream core also forwards the NetSDK login id and channel number.
    """
    if channel_number < 0:
        raise _owner.PyEzvizError('LAN live-view channel number must be non-negative')
    if stream_type < 1:
        raise _owner.PyEzvizError('LAN live-view stream type must be positive')
    return _owner.EzvizLanLiveViewParams(serial=endpoint.serial, channel_number=channel_number, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=max(1, min(stream_type, 2)), video_level=_owner.ezviz_lan_video_level_for_stream_type(stream_type) if video_level is None else video_level, device_ip=endpoint.net_host, device_local_ip=endpoint.host, device_cmd_port=endpoint.net_command_port, device_cmd_local_port=endpoint.command_port, device_stream_local_port=endpoint.stream_port, device_stream_port=endpoint.net_stream_port, netsdk_login_id=netsdk_login_id, netsdk_channel_number=channel_number if netsdk_login_id > -1 else None)

def ezviz_lan_preview_plan(endpoint: _owner_types.HcNetSdkLanEndpoint, verification_code: str, *, channel_number: int, channel_serial: str | None, channel_index: str | None, channel_count: int | None, stream_type: int, video_level: int | None, netsdk_login_id: int, username: str, _owner: _ModuleType) -> _owner_types.EzvizLanPreviewPlan:
    """Build the APK-observed LAN preview setup sequence.

    The Java layer logs in through HCNetSDK first, passes the resulting login
    id into EZ stream ``InitParam``, starts native preview through
    ``NativeApi.startPreview()``, then asks HCNetSDK to force an I-frame for
    the selected channel and stream type.
    """
    live_view = _owner.ezviz_lan_live_view_params(endpoint, channel_number=channel_number, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=stream_type, video_level=video_level, netsdk_login_id=netsdk_login_id)
    return _owner.EzvizLanPreviewPlan(login_candidates=tuple(_owner.ezviz_lan_login_candidates(verification_code, username=username, command_port=endpoint.command_port, tls_port=endpoint.sdk_tls_port)), live_view=live_view, play_device_login=_owner.ezviz_lan_play_device_login(endpoint))

def ezviz_lan_complete_playback_path(endpoint: _owner_types.HcNetSdkLanEndpoint, verification_code: str, *, settings_login_id: int, play_device_login_id: int, analog_channel_count: int, digital_channel_count: int, analog_start_channel: int, digital_start_channel: int, channel_serial: str | None, channel_index: str | None, channel_count: int | None, stream_type: int, video_level: int | None, username: str, ssid: str | None, lan_user_id: int | None, _owner: _ModuleType) -> _owner_types.EzvizLanPlaybackPath:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Build the full APK-observed LAN Live View playback path.

    The settings-screen login id and the player-owned NetSDK login id are
    intentionally separate. The app first uses the settings login to allow the
    handoff into the player, then the player obtains/reuses a NetSDK id through
    DeviceInfoEx.loginPlayDevice(...) and passes that id into native preview
    and the post-start keyframe request.
    """
    if not _owner.ezviz_lan_settings_login_succeeded(settings_login_id):
        raise _owner.PyEzvizError('EZVIZ LAN playback requires successful settings login')
    if not _owner.ezviz_lan_play_device_login_succeeded(play_device_login_id):
        raise _owner.PyEzvizError('EZVIZ LAN playback requires successful play-device login')
    channel_number = _owner.ezviz_lan_settings_channel_number(analog_channel_count=analog_channel_count, digital_channel_count=digital_channel_count, analog_start_channel=analog_start_channel, digital_start_channel=digital_start_channel)
    playback_intent = _owner.ezviz_lan_playback_intent(endpoint.serial, channel_number=channel_number, netsdk_login_id=settings_login_id, ssid=ssid, lan_user_id=lan_user_id)
    play_device_login = _owner.ezviz_lan_play_device_login(endpoint)
    live_view = _owner.ezviz_lan_live_view_params(endpoint, channel_number=channel_number, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=stream_type, video_level=video_level, netsdk_login_id=play_device_login_id)
    return _owner.EzvizLanPlaybackPath(settings_login_candidates=tuple(_owner.ezviz_lan_settings_login_candidates(verification_code, username=username, command_port=endpoint.command_port, tls_port=endpoint.sdk_tls_port)), settings_login_id=settings_login_id, channel_number=channel_number, playback_intent=playback_intent, play_device_login=play_device_login, play_device_login_id=play_device_login_id, live_view=live_view)

def build_ezviz_local_stream_setup_request_body(*, session: str | int, rate: str | int, mode: str | int, _owner: _ModuleType) -> bytes:
    """Build the plaintext XML body for the observed 0x3105 request."""
    return _owner._build_local_sdk_request_xml((('Session', session), ('Rate', rate), ('Mode', mode)))

def build_ezviz_local_stop_preview_request_body(*, operation_code: str, session: str | int, _owner: _ModuleType) -> bytes:
    """Build the native session-scoped bye; never generate wildcard stops."""
    if isinstance(session, bool) or not str(session).isascii() or (not str(session).isdigit()) or (len(str(session)) > 10) or (not 0 < int(session) <= 2147483647):
        raise _owner.PyEzvizError('EZVIZ stop preview requires a positive owned session')
    if not operation_code:
        raise _owner.PyEzvizError('EZVIZ stop preview requires supplied operation code')
    return _owner._build_local_sdk_request_xml((('OperationCode', operation_code), ('Session', session)))

def _wait_for_socket_io(sock: _owner_types.Any, *, readable: bool, timeout: float, _owner: _ModuleType) -> bool | None:
    """Wait for real socket readiness without changing its shared timeout."""
    try:
        file_descriptor = sock.fileno()
    except (AttributeError, TypeError):
        return None
    if file_descriptor < 0:
        raise OSError(_owner.errno.EBADF, 'Bad file descriptor')
    read_list = [sock] if readable else []
    write_list = [] if readable else [sock]
    ready_read, ready_write, _ = _owner.select.select(read_list, write_list, [], timeout)
    return bool(ready_read if readable else ready_write)

def _remaining_timeout(deadline: float | None, monotonic: _owner_types.Callable[[], float], *, _owner: _ModuleType) -> float | None:
    """Return time left before an absolute local-stream deadline."""
    if deadline is None:
        return None
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK operation exceeded its deadline')
    return remaining

def _send_all_with_timeout(sock: _owner_types.Any, data: bytes, *, timeout: float | None, deadline: float | None, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> None:
    """Send a frame without letting writes exceed an optional deadline."""
    effective_timeout = _owner._remaining_timeout(deadline, monotonic) if deadline is not None else timeout
    if effective_timeout is None:
        _owner._send_all(sock, data)
        return
    previous_timeout = sock.gettimeout()
    operation_deadline = deadline if deadline is not None else monotonic() + effective_timeout
    if callable(getattr(sock, 'fileno', None)) and _owner._send_all_before_deadline(sock, data, operation_deadline=operation_deadline, configured_timeout=previous_timeout, capture_deadline=deadline is not None, monotonic=monotonic):
        return
    write_timeout = effective_timeout if previous_timeout is None else min(previous_timeout, effective_timeout)
    deadline_limits_write = deadline is not None and (previous_timeout is None or effective_timeout <= previous_timeout)
    sock.settimeout(write_timeout)
    try:
        _owner._send_all(sock, data)
    except TimeoutError as err:
        if deadline_limits_write:
            raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK frame write exceeded its deadline') from err
        raise
    finally:
        sock.settimeout(previous_timeout)

def _send_all_before_deadline(sock: _owner_types.Any, data: bytes, *, operation_deadline: float, configured_timeout: float | None, capture_deadline: bool, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> bool:
    """Partially send on a real socket while recomputing its deadline."""
    remaining_data = memoryview(data)
    while remaining_data:
        remaining = operation_deadline - monotonic()
        if remaining <= 0:
            if capture_deadline:
                raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK frame write exceeded its deadline')
            raise TimeoutError('timed out')
        write_timeout = remaining if configured_timeout is None else min(configured_timeout, remaining)
        deadline_limits_write = capture_deadline and (configured_timeout is None or remaining <= configured_timeout)
        writable = _owner._wait_for_socket_io(sock, readable=False, timeout=write_timeout)
        if writable is None:
            return False
        if not writable:
            if deadline_limits_write:
                raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK frame write exceeded its deadline')
            raise TimeoutError('timed out')
        try:
            sent = sock.send(remaining_data)
        except TimeoutError as err:
            if deadline_limits_write:
                raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK frame write exceeded its deadline') from err
            raise
        if sent <= 0:
            raise _owner.PyEzvizError('Socket closed before EZVIZ frame was sent')
        remaining_data = remaining_data[sent:]
    return True

def _connect_with_optional_source_address(socket_factory: _owner_types.SocketFactory, address: tuple[str, int], timeout: float | None, *, source_address: _owner_types.SocketSourceAddress, deadline: float | None, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> _owner_types.Any:
    if source_address is None:
        if socket_factory is _owner.socket.create_connection and deadline is not None:
            return _owner._create_deadline_connection(address, timeout, deadline=deadline, monotonic=monotonic)
        return socket_factory(address, timeout)
    try:
        if socket_factory is _owner.socket.create_connection:
            return _owner._create_reusable_source_connection(address, timeout, source_address=source_address, deadline=deadline, monotonic=monotonic)
        source_socket_factory = _owner.cast('_owner_types.SourceAddressSocketFactory', socket_factory)
        return source_socket_factory(address, timeout, source_address)
    except OSError as err:
        if err.errno == _owner.errno.EADDRINUSE or isinstance(err, _owner._SourcePortConflictError):
            raise _owner.PyEzvizError(f'EZVIZ local SDK receiver port {source_address[1]} is already in use') from err
        raise

def _create_reusable_source_connection(address: tuple[str, int], timeout: float | None, *, source_address: tuple[str, int], deadline: float | None, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> _owner_types.socket.socket:
    """Connect from an exact source port with platform-safe ownership."""
    last_error: OSError | None = None
    host, port = address
    for family, sock_type, protocol, _, target in _owner._getaddrinfo_before_deadline(host, port, deadline=deadline, monotonic=monotonic):
        try:
            attempt_timeout, deadline_limits_attempt = _owner._connect_attempt_settings(timeout, deadline=deadline, monotonic=monotonic)
            if _owner._WINDOWS_EXCLUSIVE_SOURCE_BIND:
                try:
                    return _owner._connect_bound_source_socket(family, sock_type, protocol, target, attempt_timeout, source_address=source_address, exclusive=True)
                except OSError as err:
                    if err.errno != _owner.errno.EADDRINUSE:
                        raise
                    concrete_source_address = _owner._windows_concrete_source_address(source_address, family, target)
                    if concrete_source_address == source_address:
                        raise
                    concrete_timeout, deadline_limits_attempt = _owner._connect_attempt_settings(timeout, deadline=deadline, monotonic=monotonic)
                    return _owner._connect_bound_source_socket(family, sock_type, protocol, target, concrete_timeout, source_address=concrete_source_address, exclusive=True)
            return _owner._connect_bound_source_socket(family, sock_type, protocol, target, attempt_timeout, source_address=source_address, exclusive=False)
        except OSError as err:
            if isinstance(err, TimeoutError) and deadline_limits_attempt:
                raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK connect exceeded its deadline') from err
            last_error = err
    if last_error is not None:
        raise last_error
    raise OSError('getaddrinfo returned no addresses')

def _connect_attempt_settings(timeout: float | None, *, deadline: float | None, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> tuple[float | None, bool]:
    """Return the timeout and whether the absolute deadline constrains it."""
    if deadline is None:
        return (timeout, False)
    remaining = _owner._remaining_timeout(deadline, monotonic)
    assert remaining is not None
    return (remaining if timeout is None else min(timeout, remaining), timeout is None or remaining <= timeout)

def _create_deadline_connection(address: tuple[str, int], timeout: float | None, *, deadline: float, monotonic: _owner_types.Callable[[], float], _owner: _ModuleType) -> _owner_types.socket.socket:
    """Connect to resolved addresses without renewing an absolute deadline."""
    last_error: OSError | None = None
    host, port = address
    for family, sock_type, protocol, _, target in _owner._getaddrinfo_before_deadline(host, port, deadline=deadline, monotonic=monotonic):
        remaining = _owner._remaining_timeout(deadline, monotonic)
        assert remaining is not None
        attempt_timeout = remaining if timeout is None else min(timeout, remaining)
        deadline_limits_attempt = timeout is None or remaining <= timeout
        sock = _owner.socket.socket(family, sock_type, protocol)
        try:
            sock.settimeout(attempt_timeout)
            sock.connect(target)
            return sock
        except OSError as err:
            last_error = err
            sock.close()
            if isinstance(err, TimeoutError) and deadline_limits_attempt:
                raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK connect exceeded its deadline') from err
    if last_error is not None:
        raise last_error
    raise OSError('getaddrinfo returned no addresses')

def _getaddrinfo_before_deadline(host: str, port: int, *, deadline: float | None, monotonic: _owner_types.Callable[[], float], resolver: _owner_types.BoundedResolver | None, _owner: _ModuleType) -> list[tuple[_owner_types.Any, ...]]:
    """Use the shared bounded resolver, or an explicitly owned injected service."""
    remaining = _owner._remaining_timeout(deadline, monotonic)
    try:
        return (resolver or _owner.DEFAULT_RESOLVER).resolve(host, port, timeout=remaining)
    except _owner.ResolverBusy as err:
        raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK hostname resolver is still busy') from err
    except TimeoutError as err:
        raise _owner.EzvizLocalSdkDeadlineExpired('EZVIZ local SDK hostname resolution exceeded its deadline') from err

def _connect_bound_source_socket(family: int, sock_type: int, protocol: int, target: _owner_types.Any, timeout: float | None, *, source_address: _owner_types.SocketBindAddress, exclusive: bool, _owner: _ModuleType) -> _owner_types.socket.socket:
    """Bind and connect one source socket with the requested ownership mode."""
    sock = _owner.socket.socket(family, sock_type, protocol)
    try:
        sock.settimeout(timeout)
        if exclusive:
            exclusive_option = getattr(_owner.socket, 'SO_EXCLUSIVEADDRUSE', None)
            if exclusive_option is None:
                raise _owner.PyEzvizError('Windows does not expose exclusive source-port binding support')
            sock.setsockopt(_owner.socket.SOL_SOCKET, exclusive_option, 1)
        else:
            sock.setsockopt(_owner.socket.SOL_SOCKET, _owner.socket.SO_REUSEADDR, 1)
        sock.bind(source_address)
        try:
            sock.connect(target)
        except OSError as err:
            if err.errno == _owner.errno.EADDRNOTAVAIL:
                raise _owner._SourcePortConflictError(err.errno, str(err)) from err
            raise
        if sock.getsockname()[1] != source_address[1]:
            raise _owner.PyEzvizError('EZVIZ local SDK receiver port changed while opening the socket')
        return sock
    except Exception:
        sock.close()
        raise

def _windows_concrete_source_address(source_address: tuple[str, int], family: int, target: _owner_types.Any, *, _owner: _ModuleType) -> _owner_types.SocketBindAddress:
    """Resolve a wildcard source to the interface selected for the target."""
    host, port = source_address
    wildcard_hosts = {'', '::'} if family == _owner.socket.AF_INET6 else {'', '0.0.0.0'}
    if host not in wildcard_hosts:
        return source_address
    route_probe = _owner.socket.socket(family, _owner.socket.SOCK_DGRAM)
    try:
        route_probe.connect(target)
        routed_address = route_probe.getsockname()
        routed_host = str(routed_address[0])
    finally:
        route_probe.close()
    if family == _owner.socket.AF_INET6:
        return (routed_host, port, int(routed_address[2]), int(routed_address[3]))
    return (routed_host, port)

def build_ezviz_local_sdk_frame_header(*, command: int, body_length: int, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build the 32-byte EZVIZ local SDK header observed in app traces.

    This helper intentionally handles only the non-secret binary envelope. The
    body is caller-supplied because the XML fields still need classification
    before they are safe to persist or synthesize from app captures.
    """
    if not 0 <= command <= 65535:
        raise _owner.PyEzvizError('EZVIZ local SDK command must fit in 16 bits')
    if body_length < 0:
        raise _owner.PyEzvizError('EZVIZ local SDK body length must be non-negative')
    if not 0 <= status <= 4294967295:
        raise _owner.PyEzvizError('EZVIZ local SDK status must fit in 32 bits')
    return b''.join((_owner.EZVIZ_LOCAL_SDK_MAGIC, version.to_bytes(4, 'big'), sequence.to_bytes(4, 'big'), marker.to_bytes(4, 'big'), b'\x00\x00', command.to_bytes(2, 'big'), status.to_bytes(4, 'big'), body_length.to_bytes(4, 'big'), reserved.to_bytes(4, 'big')))

def build_ezviz_local_sdk_frame(*, command: int, body: bytes | str, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build an EZVIZ local SDK frame from a command and caller-owned body."""
    body_bytes = body.encode('utf-8') if isinstance(body, str) else body
    return _owner.build_ezviz_local_sdk_frame_header(command=command, body_length=len(body_bytes), sequence=sequence, version=version, marker=marker, status=status, reserved=reserved) + body_bytes

def build_encrypted_ezviz_local_sdk_frame(*, command: int, body: bytes | str, key: bytes | str, iv: bytes | str, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build an encrypted EZVIZ local SDK control frame.

    This is the reusable piece needed by the standalone reproducer after
    a caller has resolved the local CAS device-info key and IV source.
    """
    return _owner.build_ezviz_local_sdk_frame(command=command, body=_owner.encrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv), sequence=sequence, version=version, marker=marker, status=status, reserved=reserved)

def build_ezviz_local_sdk_ssl_frame(*, command: int, body: bytes | str, key: bytes | str, iv: bytes | str, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build the app-observed local SDK SSL-like frame.

    Normal EZVIZ live view sends local control frames as a 32-byte local SDK
    header, AES-CBC/PKCS#5 ciphertext, and a 32-byte lowercase ASCII MD5 hex
    trailer over that ciphertext. The header body length covers only the
    ciphertext, matching the observed ``0x2011`` and ``0x3105`` sends.
    """
    iv_bytes = _owner._local_sdk_aes_bytes('IV', iv)
    frame = _owner.build_encrypted_ezviz_local_sdk_frame(command=command, body=body, key=key, iv=iv_bytes, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved)
    parsed = _owner.parse_ezviz_local_sdk_frame(frame)
    trailer = _owner.hashlib.md5(parsed.body, usedforsecurity=False).hexdigest().encode('ascii')
    return frame + trailer

def build_ezviz_cas_encrypted_local_sdk_frame(*, command: int, body: bytes | str, device_info: _owner_types.EzvizCasDeviceInfo, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build a local SDK frame using the app-observed CAS device-info tuple."""
    return _owner.build_encrypted_ezviz_local_sdk_frame(command=command, body=body, key=device_info.key_bytes, iv=device_info.iv_bytes, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved)

def build_ezviz_cas_ssl_local_sdk_frame(*, command: int, body: bytes | str, device_info: _owner_types.EzvizCasDeviceInfo, iv: bytes | str, sequence: int, version: int, marker: int, status: int, reserved: int, _owner: _ModuleType) -> bytes:
    """Build a direct-local SDK frame with CAS key and ciphertext MD5 trailer."""
    return _owner.build_ezviz_local_sdk_ssl_frame(command=command, body=body, key=device_info.key_bytes, iv=iv, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved)

def read_ezviz_local_sdk_frame(sock: _owner_types.Any, *, trailer_length: int, _owner: _ModuleType) -> _owner_types.EzvizLocalSdkFrame:
    """Read one complete EZVIZ local SDK frame from a socket-like object."""
    if trailer_length < 0:
        raise _owner.PyEzvizError('EZVIZ local SDK trailer length must be non-negative')
    header_bytes = _owner._recv_exact(sock, _owner.EZVIZ_LOCAL_SDK_HEADER_LENGTH)
    header = _owner.parse_ezviz_local_sdk_frame_header(header_bytes)
    return _owner.EzvizLocalSdkFrame(header=header, body=_owner._recv_exact(sock, header.body_length), trailer=_owner._recv_exact(sock, trailer_length) if trailer_length else b'')

def build_ezviz_interleaved_rtp_frame_header(*, channel: int, payload_length: int, _owner: _ModuleType) -> bytes:
    """Build a 4-byte interleaved RTP header."""
    if not 0 <= channel <= 255:
        raise _owner.PyEzvizError('EZVIZ interleaved RTP channel must fit in 8 bits')
    if not 0 <= payload_length <= 65535:
        raise _owner.PyEzvizError('EZVIZ interleaved RTP payload length must fit in 16 bits')
    return bytes((_owner.EZVIZ_RTP_INTERLEAVED_MAGIC, channel, *payload_length.to_bytes(2, 'big')))

def read_ezviz_interleaved_rtp_frame(sock: _owner_types.Any, *, _owner: _ModuleType) -> _owner_types.EzvizInterleavedRtpFrame:
    """Read one complete interleaved RTP frame from a socket-like object."""
    header = _owner.parse_ezviz_interleaved_rtp_frame_header(_owner._recv_exact(sock, 4))
    return _owner.EzvizInterleavedRtpFrame(header=header, payload=_owner._recv_exact(sock, header.payload_length))

def read_ezviz_interleaved_rtp_frame_after_prefix(sock: _owner_types.Any, *, max_prefix_bytes: int, _owner: _ModuleType) -> _owner_types.EzvizInterleavedRtpFrameWithPrefix:
    """Read the first interleaved RTP frame, preserving any binary preface.

    The local stream port sends a short binary preface after the encrypted
    ``0x3105`` setup succeeds, then switches to ``$`` interleaved RTP frames.
    A standalone reproducer needs to tolerate that preface without discarding
    it silently.
    """
    if max_prefix_bytes < 0:
        raise _owner.PyEzvizError('EZVIZ RTP prefix limit must be non-negative')
    prefix = bytearray()
    while True:
        byte = _owner._recv_exact(sock, 1)
        if byte[0] == _owner.EZVIZ_RTP_INTERLEAVED_MAGIC:
            header_tail = _owner._recv_exact(sock, 3)
            header = _owner.parse_ezviz_interleaved_rtp_frame_header(byte + header_tail)
            return _owner.EzvizInterleavedRtpFrameWithPrefix(prefix=bytes(prefix), frame=_owner.EzvizInterleavedRtpFrame(header=header, payload=_owner._recv_exact(sock, header.payload_length)))
        prefix.extend(byte)
        if len(prefix) > max_prefix_bytes:
            raise _owner.PyEzvizError('EZVIZ RTP prefix exceeded limit before frame magic')

def read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock: _owner_types.Any, *, max_prefix_bytes: int, _owner: _ModuleType) -> _owner_types.EzvizInterleavedRtpFrameWithPrefix:
    """Read one HCNetSDK command-port interleaved media frame.

    The local stream port uses ``$`` + channel + big-endian payload length.
    Port 8000 uses the same magic byte, but its two length bytes are a
    little-endian total frame length. Keeping this reader separate prevents the
    command-port path from coalescing adjacent media frames.
    """
    if max_prefix_bytes < 0:
        raise _owner.PyEzvizError('HCNetSDK command-port prefix limit must be non-negative')
    prefix = bytearray()
    while True:
        byte = _owner._recv_exact(sock, 1)
        if byte[0] == _owner.EZVIZ_RTP_INTERLEAVED_MAGIC:
            header_tail = _owner._recv_exact(sock, 3)
            total_length = int.from_bytes(header_tail[1:3], 'little')
            if total_length < 4:
                raise _owner.PyEzvizError('HCNetSDK command-port interleaved frame length is invalid')
            payload_length = total_length - 4
            return _owner.EzvizInterleavedRtpFrameWithPrefix(prefix=bytes(prefix), frame=_owner.EzvizInterleavedRtpFrame(header=_owner.EzvizInterleavedRtpFrameHeader(channel=header_tail[0], payload_length=payload_length), payload=_owner._recv_exact(sock, payload_length)))
        prefix.extend(byte)
        if len(prefix) > max_prefix_bytes:
            raise _owner.PyEzvizError('HCNetSDK command-port prefix exceeded limit before frame magic')

def hcnetsdk_command_port_execute_template(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, template: _owner_types.HcNetSdkCommandPortControlTemplate, *, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.HcNetSdkCommandPortControlResponse:
    """Execute one generated command-port control template in pure Python.

    The EZVIZ devices tested so far accept this pattern for local capability
    reads: perform the RSA login on one socket, close it, then send the
    authenticated control command on a fresh command-port socket.
    """
    with _owner.HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory) as login_client:
        actual_local_ip = local_ip
        if actual_local_ip is None:
            try:
                actual_local_ip = str(login_client.sock.getsockname()[0])
            except (AttributeError, OSError, TypeError) as err:
                raise _owner.PyEzvizError('HCNetSDK command-port control requires local_ip when the socket does not expose getsockname()') from err
        login_session = login_client.login(password=password, username=username, local_ip=actual_local_ip, rsa_key=rsa_key)
    request = template.to_frame(session_id=login_session.session_id, auth_seed=login_session.auth_seed, key=login_session.challenge, local_ip=actual_local_ip)
    with _owner.HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory) as control_client:
        control_client.send_command_frame(request)
        response = control_client.read_tcp_frame()
    return _owner.HcNetSdkCommandPortControlResponse(login_session=login_session, request=request, response=response)

def hcnetsdk_stdxml_isapi_command_port(endpoint: _owner_types.HcNetSdkLanEndpoint, password: str | bytes, method: str, path: str, body: _owner_types.Mapping[str, _owner_types.Any] | str | bytes | None, *, command_id: int, body_prefix: str | bytes | None, addend_delta: int | None, addend: int | None, name: str | None, username: str, local_ip: str | None, timeout: float | None, socket_factory: _owner_types.SocketFactory, rsa_key: _owner_types.Any | None, _owner: _ModuleType) -> _owner_types.HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913 -- explicit runtime context plus retained signature
    """Execute a generic ISAPI request through pure command-port STDXML."""
    request = _owner.hcnetsdk_stdxml_isapi_request(method, path, body)
    return _owner.hcnetsdk_stdxml_config_command_port_from_trace(endpoint, password, request, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name=name or f'{method.strip().upper()} {path}', username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key)

def _hcnetsdk_time_value(value: _owner_types.HcNetSdkTime | _owner_types.datetime | _owner_types.date, *, end_of_day: bool, _owner: _ModuleType) -> _owner_types.HcNetSdkTime:
    if isinstance(value, _StaticHcNetSdkTime):
        return value
    if isinstance(value, _Staticdatetime):
        return _owner.HcNetSdkTime.from_datetime(value)
    if isinstance(value, _Staticdate):
        return _owner.HcNetSdkTime.from_date(value, end_of_day=end_of_day)
    raise _owner.PyEzvizError('HCNetSDK time value must be date, datetime, or HcNetSdkTime')

def _native_string_bytes(label: str, value: str, *, _owner: _ModuleType) -> bytes:
    if not value:
        raise _owner.PyEzvizError(f'HCNetSDK {label} must not be empty')
    if '\x00' in value:
        raise _owner.PyEzvizError(f'HCNetSDK {label} must not contain NUL bytes')
    return value.encode('utf-8')

def _fixed_ipv4_text(value: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> str:
    raw = bytes(value)
    with _suppress(UnicodeDecodeError):
        text = _owner._nul_stripped_text(raw)
        if text and text.isprintable():
            with _suppress(ValueError):
                return str(_owner.ipaddress.ip_address(text))
            return text
    binary_ipv4 = raw[:4]
    if any(binary_ipv4) and (not any(raw[4:])):
        return str(_owner.ipaddress.ip_address(bytes(reversed(binary_ipv4))))
    return ''

def _mac_address_text(value: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> str:
    raw = bytes(value)
    if len(raw) != 6 or not any(raw):
        return ''
    return ':'.join(f'{byte:02x}' for byte in raw)

def _byte_tuple(value: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> tuple[int, ...]:
    return tuple(bytes(value))

def _fixed_secret_bytes(value: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> bytes:
    return bytes(value).split(_owner.SADP_NUL_BYTE, 1)[0]

def _fixed_secret_text(value: bytes | bytearray | memoryview, *, _owner: _ModuleType) -> str:
    raw = bytes(value)
    if not raw:
        return ''
    with _suppress(UnicodeDecodeError):
        return raw.decode('utf-8')
    return raw.decode('latin-1')

def _mac_address_bytes(value: str | bytes, *, _owner: _ModuleType) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 6:
            raise _owner.PyEzvizError('EZVIZ LAN MAC address must be 6 bytes')
        return value
    parts = value.split(':')
    if len(parts) != 6:
        raise _owner.PyEzvizError('EZVIZ LAN MAC address must contain 6 octets')
    try:
        return bytes(int(part, 16) for part in parts)
    except ValueError as err:
        raise _owner.PyEzvizError('EZVIZ LAN MAC address has invalid hex') from err

def _dword_value(label: str, value: int, *, _owner: _ModuleType) -> int:
    if not 0 <= value <= 4294967295:
        raise _owner.PyEzvizError(f'EZVIZ LAN {label} must fit in one unsigned dword')
    return value

def _xml_local_name(element: _owner_types.ET.Element, *, _owner: _ModuleType) -> str:
    return element.tag.rsplit('}', 1)[-1]

def _xml_opt_attr(root: _owner_types.ET.Element, name: str, *, parent: str | None, _owner: _ModuleType) -> str | None:
    return _owner._xml_attr(root, name, 'opt', parent=parent)

def _xml_attr(root: _owner_types.ET.Element, name: str, attr: str, *, parent: str | None, _owner: _ModuleType) -> str | None:
    for element in root.iter():
        if _owner._xml_local_name(element).lower() != name.lower():
            continue
        if parent is not None and (not _owner._xml_has_parent(root, element, parent)):
            continue
        value = element.attrib.get(attr)
        return value if value else None
    return None

def _xml_attr_int(root: _owner_types.ET.Element, name: str, attr: str, *, parent: str | None, default: int, _owner: _ModuleType) -> int:
    value = _owner._xml_attr(root, name, attr, parent=parent)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default

def _xml_bool_opt_attr(root: _owner_types.ET.Element, name: str, *, _owner: _ModuleType) -> bool | None:
    value = _owner._xml_opt_attr(root, name)
    if value is None:
        return None
    return value.lower() == 'true'

def _xml_descendant_int(root: _owner_types.ET.Element, name: str, *, parent: str | None, default: int, _owner: _ModuleType) -> int:
    value = _owner._xml_descendant_text(root, name, parent=parent)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default

def _xml_descendant_bool_text(root: _owner_types.ET.Element, name: str, *, parent: str | None, default: bool, _owner: _ModuleType) -> bool:
    value = _owner._xml_descendant_text(root, name, parent=parent)
    return default if value is None else value.lower() == 'true'

def _xml_descendant_text(root: _owner_types.ET.Element, name: str, *, parent: str | None, _owner: _ModuleType) -> str | None:
    for element in root.iter():
        if _owner._xml_local_name(element).lower() != name.lower():
            continue
        if parent is not None and (not _owner._xml_has_parent(root, element, parent)):
            continue
        text = element.text
        return text.strip() if text and text.strip() else None
    return None

def _xml_has_descendant(root: _owner_types.ET.Element, name: str, *, _owner: _ModuleType) -> bool:
    return any(_owner._xml_local_name(element).lower() == name.lower() for element in root.iter())

def _xml_int_csv(value: str | None, *, _owner: _ModuleType) -> tuple[int, ...]:
    if not value:
        return ()
    parsed: list[int] = []
    for part in value.split(','):
        text = part.strip()
        if not text:
            continue
        with _suppress(ValueError):
            parsed.append(int(text))
    return tuple(parsed)

def _xml_child_int_csv_with_prefix(root: _owner_types.ET.Element, prefix: str, *, _owner: _ModuleType) -> tuple[int, ...]:
    parsed: list[int] = []
    prefix_lower = prefix.lower()
    for child in list(root):
        if not _owner._xml_local_name(child).lower().startswith(prefix_lower):
            continue
        text = child.text.strip() if child.text and child.text.strip() else None
        parsed.extend(_owner._xml_int_csv(text))
    return tuple(parsed)

def _xml_child_text(root: _owner_types.ET.Element, path: tuple[str, ...], *, _owner: _ModuleType) -> str | None:
    elements = [root]
    for name in path:
        next_elements: list[_owner_types.ET.Element] = []
        for element in elements:
            next_elements.extend(child for child in list(element) if _owner._xml_local_name(child).lower() == name.lower())
        elements = next_elements
        if not elements:
            return None
    text = elements[0].text
    return text.strip() if text and text.strip() else None

def _xml_children(root: _owner_types.ET.Element, name: str, *, _owner: _ModuleType) -> tuple[_owner_types.ET.Element, ...]:
    return tuple(child for child in list(root) if _owner._xml_local_name(child).lower() == name.lower())

def _xml_first_child(root: _owner_types.ET.Element, name: str, *, _owner: _ModuleType) -> _owner_types.ET.Element | None:
    children = _owner._xml_children(root, name)
    return children[0] if children else None

def _ipc_front_parameter_field_root(root: _owner_types.ET.Element, *, _owner: _ModuleType) -> _owner_types.ET.Element:
    channel_list = _owner._xml_first_child(root, 'ChannelList')
    if channel_list is None:
        return root
    channel_entry = _owner._xml_first_child(channel_list, 'ChannelEntry')
    return channel_entry if channel_entry is not None else root

def _xml_child_int(root: _owner_types.ET.Element, path: tuple[str, ...], *, default: int, _owner: _ModuleType) -> int:
    value = _owner._xml_child_text(root, path)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default

def _xml_child_optional_int(root: _owner_types.ET.Element, path: tuple[str, ...], *, _owner: _ModuleType) -> int | None:
    value = _owner._xml_child_text(root, path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None

def _xml_child_int_range(root: _owner_types.ET.Element, path: tuple[str, ...], *, _owner: _ModuleType) -> _owner_types.EzvizLanIpcFrontParameterRange:
    return _owner.EzvizLanIpcFrontParameterRange(minimum=_owner._xml_child_int(root, (*path, 'Min')), maximum=_owner._xml_child_int(root, (*path, 'Max')), default=_owner._xml_child_optional_int(root, (*path, 'Default')))

def _audio_video_compress_stream(root: _owner_types.ET.Element, *, index: int | None, _owner: _ModuleType) -> _owner_types.EzvizLanAudioVideoCompressStream:
    resolutions: list[_owner_types.EzvizLanVideoResolution] = []
    bitrate_mins: list[int] = []
    bitrate_maxes: list[int] = []
    resolution_indexes: list[int] = []
    frame_rates: list[int] = []
    frame_rates.extend(_owner._xml_child_int_csv_with_prefix(root, 'VideoFrameRate'))
    resolution_list = _owner._xml_first_child(root, 'VideoResolutionList')
    if resolution_list is not None:
        for entry in _owner._xml_children(resolution_list, 'VideoResolutionEntry'):
            dimensions = _owner._xml_child_text(entry, ('Resolution',))
            size = _owner.re.fullmatch('([0-9]+)\\s*[*xX]\\s*([0-9]+)', dimensions or '')
            width = int(size[1]) if size and int(size[1]) > 0 else None
            height = int(size[2]) if size and int(size[2]) > 0 else None
            if width is None or height is None:
                width = height = None
            resolutions.append(_owner.EzvizLanVideoResolution(index=_owner._xml_child_optional_int(entry, ('Index',)), name=_owner._xml_child_text(entry, ('Name',)), dimensions=dimensions, width=width, height=height, frame_rate_codes=tuple(_owner._xml_child_int_csv_with_prefix(entry, 'VideoFrameRate')), bitrate_min=_owner._xml_child_optional_int(entry, ('VideoBitrate', 'Min')), bitrate_max=_owner._xml_child_optional_int(entry, ('VideoBitrate', 'Max')), bitrate_codes=_owner._xml_int_csv(_owner._xml_child_text(entry, ('VideoBitrate', 'Range')))))
            resolution_indexes.append(_owner._xml_child_int(entry, ('Index',)))
            frame_rates.extend(_owner._xml_child_int_csv_with_prefix(entry, 'VideoFrameRate'))
            bitrate_min = _owner._xml_child_int(entry, ('VideoBitrate', 'Min'))
            bitrate_max = _owner._xml_child_int(entry, ('VideoBitrate', 'Max'))
            if bitrate_min:
                bitrate_mins.append(bitrate_min)
            if bitrate_max:
                bitrate_maxes.append(bitrate_max)
    return _owner.EzvizLanAudioVideoCompressStream(index=index, video_encode_type_range=_owner._xml_child_text(root, ('VideoEncodeType', 'Range')), video_encode_efficiency_range=_owner._xml_child_text(root, ('VideoEncodeEfficiency', 'Range')), interval_bp_frame_range=_owner._xml_child_text(root, ('IntervalBPFrame', 'Range')), e_frame=_owner._xml_child_int(root, ('EFrame',)), resolution_indexes=tuple(resolution_indexes), frame_rates=tuple(dict.fromkeys(frame_rates)), bitrate_min=min(bitrate_mins) if bitrate_mins else 0, bitrate_max=max(bitrate_maxes) if bitrate_maxes else 0, resolutions=tuple(resolutions), bitrate_codes=_owner._xml_int_csv(_owner._xml_child_text(root, ('VideoBitrate', 'Range'))))

def _audio_video_compress_video_channels(root: _owner_types.ET.Element, *, _owner: _ModuleType) -> tuple[_owner_types.EzvizLanAudioVideoCompressVideoChannel, ...]:
    channel_list = _owner._xml_first_child(root, 'ChannelList')
    if channel_list is None:
        return ()
    channels: list[_owner_types.EzvizLanAudioVideoCompressVideoChannel] = []
    for entry in _owner._xml_children(channel_list, 'ChannelEntry'):
        main = _owner._xml_first_child(entry, 'MainChannel')
        sub_list = _owner._xml_first_child(entry, 'SubChannelList')
        sub_streams: list[_owner_types.EzvizLanAudioVideoCompressStream] = []
        if sub_list is not None:
            for sub_entry in _owner._xml_children(sub_list, 'SubChannelEntry'):
                sub_streams.append(_owner._audio_video_compress_stream(sub_entry, index=_owner._xml_child_optional_int(sub_entry, ('index',))))
        channels.append(_owner.EzvizLanAudioVideoCompressVideoChannel(channel_number=_owner._xml_child_int(entry, ('ChannelNumber',)), main_stream=_owner._audio_video_compress_stream(main) if main is not None else None, sub_streams=tuple(sub_streams)))
    return tuple(channels)

def _audio_video_compress_audio_channels(root: _owner_types.ET.Element, *, _owner: _ModuleType) -> tuple[_owner_types.EzvizLanAudioVideoCompressAudioChannel, ...]:
    channel_list = _owner._xml_first_child(root, 'ChannelList')
    if channel_list is None:
        return ()
    return tuple(_owner.EzvizLanAudioVideoCompressAudioChannel(channel_number=_owner._xml_child_int(entry, ('ChannelNumber',)), main_audio_encode_type_range=_owner._xml_child_text(entry, ('MainAudioEncodeType', 'Range')), sub_audio_encode_type_range=_owner._xml_child_text(entry, ('SubAudioEncodeType', 'Range')), audio_in_type_range=_owner._xml_child_text(entry, ('AudioInType', 'Range')), audio_in_volume_min=_owner._xml_child_int(entry, ('AudioInVolume', 'Min')), audio_in_volume_max=_owner._xml_child_int(entry, ('AudioInVolume', 'Max'))) for entry in _owner._xml_children(channel_list, 'ChannelEntry'))

def _audio_video_compress_voice_talk_channels(root: _owner_types.ET.Element, *, _owner: _ModuleType) -> tuple[_owner_types.EzvizLanAudioVideoCompressVoiceTalkChannel, ...]:
    channel_list = _owner._xml_first_child(root, 'ChannelList')
    if channel_list is None:
        return ()
    return tuple(_owner.EzvizLanAudioVideoCompressVoiceTalkChannel(channel_number=_owner._xml_child_int(entry, ('ChannelNumber',)), voice_talk_encode_type_range=_owner._xml_child_text(entry, ('VoiceTalkEncodeType', 'Range')), voice_talk_in_type_range=_owner._xml_child_text(entry, ('VoiceTalkInType', 'Range'))) for entry in _owner._xml_children(channel_list, 'ChannelEntry'))

def _xml_has_parent(root: _owner_types.ET.Element, child: _owner_types.ET.Element, parent: str, *, _owner: _ModuleType) -> bool:
    for candidate in root.iter():
        if _owner._xml_local_name(candidate).lower() != parent.lower():
            continue
        if any(descendant is child for descendant in candidate.iter()):
            return True
    return False

def _looks_tls_record(data: bytes, *, _owner: _ModuleType) -> bool:
    if len(data) < 5:
        return False
    content_type = data[0]
    major = data[1]
    minor = data[2]
    record_length = int.from_bytes(data[3:5], 'big')
    return content_type in {20, 21, 22, 23} and major == 3 and (0 <= minor <= 4) and (record_length <= max(0, len(data) - 5))

def _hcnetsdk_tcp_payload_kind(data: bytes, *, printable_ratio: float, high_bit_ratio: float, xml_offset: int | None, xml_tags: tuple[str, ...], declared_length_offset: int | None, _owner: _ModuleType) -> str:
    known_kind = _owner._hcnetsdk_known_prefix_kind(data)
    if known_kind is not None:
        kind = known_kind
    elif xml_tags and xml_offset == 0:
        kind = 'xml'
    elif xml_tags:
        kind = 'prefixed_xml'
    elif declared_length_offset is not None:
        kind = 'length_prefixed_binary'
    elif high_bit_ratio > _owner.EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD:
        kind = 'opaque_binary'
    elif printable_ratio > _owner.EZVIZ_BODY_PRINTABLE_THRESHOLD:
        kind = 'printable_non_xml'
    else:
        kind = 'binary'
    return kind

def _hcnetsdk_known_prefix_kind(data: bytes, *, _owner: _ModuleType) -> str | None:
    if data.startswith(bytes((_owner.EZVIZ_RTP_INTERLEAVED_MAGIC,))):
        return 'interleaved_media'
    if _owner._looks_tls_record(data):
        return 'tls_record'
    for prefix, kind in ((_owner.EZVIZ_LOCAL_SDK_MAGIC, 'ezviz_local_sdk_frame'), (b'HTTP/', 'http'), (b'GET ', 'http'), (b'POST ', 'http'), (b'PUT ', 'http'), (_owner.HCNETSDK_HKMI_PREFIX, 'hik_hkmi'), (_owner.HCNETSDK_HIK_PRIVATE_PREFIX, 'hik_private'), (_owner.HCNETSDK_MPEG_PS_PACK_HEADER, 'mpeg_ps')):
        if data.startswith(prefix):
            return kind
    return None

def _hcnetsdk_declared_length(data: bytes, *, _owner: _ModuleType) -> tuple[int | None, int | None]:
    """Return a plausible embedded length field if one matches captured bytes."""
    candidates: list[tuple[int, int]] = []
    for offset in (0, 2, 4, 8, 12, 16, 20, 24):
        if len(data) >= offset + 4:
            candidates.append((offset, int.from_bytes(data[offset:offset + 4], 'big')))
            candidates.append((offset, int.from_bytes(data[offset:offset + 4], 'little')))
        if len(data) >= offset + 2:
            candidates.append((offset, int.from_bytes(data[offset:offset + 2], 'big')))
            candidates.append((offset, int.from_bytes(data[offset:offset + 2], 'little')))
    for offset, value in candidates:
        if value in {len(data), len(data) - offset, len(data) - offset - 4}:
            return (offset, value)
    return (None, None)

def _event_field_int(event: _owner_types.HcNetSdkSemanticLogEvent, name: str, *, _owner: _ModuleType) -> int | None:
    fields = event.fields or {}
    return _owner._parse_int(fields.get(name))

def _event_field_bool(event: _owner_types.HcNetSdkSemanticLogEvent, name: str, *, _owner: _ModuleType) -> bool:
    fields = event.fields or {}
    return fields.get(name, '').lower() == 'true'

def _hcnetsdk_shape_command_candidate(record: _owner_types.HcNetSdkTcpShapeLogRecord, *, _owner: _ModuleType) -> int | None:
    if record.direction not in {'send', 'write'}:
        return None
    candidate = record.shape.u32le_4
    if _owner.hcnetsdk_command_candidate_role(candidate) is None:
        return None
    return candidate

def _hcnetsdk_command_port_username(username: str, *, _owner: _ModuleType) -> bytes:
    username_bytes = username.encode()
    if len(username_bytes) > _owner.HCNETSDK_COMMAND_PORT_USERNAME_LENGTH:
        raise _owner.PyEzvizError('HCNetSDK command-port username is too long')
    return username_bytes.ljust(_owner.HCNETSDK_COMMAND_PORT_USERNAME_LENGTH, b'\x00')

def _recv_exact(sock: _owner_types.Any, length: int, *, _owner: _ModuleType) -> bytes:
    if length < 0:
        raise _owner.PyEzvizError('Cannot read a negative byte count')
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except TimeoutError as err:
            raise _owner.DeviceException('Device offline or unreachable: timed out waiting for EZVIZ local SDK data') from err
        if not chunk:
            raise _owner.EzvizLocalSdkStreamClosed('Socket closed before expected EZVIZ frame bytes')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)

def _send_all(sock: _owner_types.Any, data: bytes, *, _owner: _ModuleType) -> None:
    sendall = getattr(sock, 'sendall', None)
    if callable(sendall):
        sendall(data)
        return
    sent = 0
    while sent < len(data):
        count = sock.send(data[sent:])
        if count <= 0:
            raise _owner.PyEzvizError('Socket closed before EZVIZ frame was sent')
        sent += count

def _pkcs5_pad(data: bytes, *, _owner: _ModuleType) -> bytes:
    pad_len = _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE - len(data) % _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
    return data + bytes((pad_len,)) * pad_len

def _pkcs5_unpad(data: bytes, *, _owner: _ModuleType) -> bytes:
    if not data or len(data) % _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise _owner.PyEzvizError('EZVIZ local SDK AES body has invalid padded length')
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _owner.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise _owner.PyEzvizError('EZVIZ local SDK AES body has invalid padding')
    if data[-pad_len:] != bytes((pad_len,)) * pad_len:
        raise _owner.PyEzvizError('EZVIZ local SDK AES body has inconsistent padding')
    return data[:-pad_len]

def _entropy_bits_per_byte(data: bytes, *, _owner: _ModuleType) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for byte in set(data):
        probability = data.count(byte) / length
        entropy -= probability * _owner.math.log2(probability)
    return entropy

def _xml_offset(data: bytes, *, _owner: _ModuleType) -> int | None:
    limit = min(len(data), _owner.EZVIZ_XML_DETECT_PREFIX_LIMIT)
    for offset in range(limit):
        if data[offset:offset + 1] != _owner.EZVIZ_XML_START_BYTE:
            continue
        if _owner._xml_tag_names(data[offset:]):
            return offset
    return None

def _xml_tag_names(data: bytes, *, _owner: _ModuleType) -> tuple[str, ...]:
    text = data.decode('utf-8', 'ignore')
    tags: list[str] = []
    seen: set[str] = set()
    for match in _owner.re.finditer('</?([A-Za-z_][A-Za-z0-9_.:-]*)\\b[^>]*>', text):
        tag = match.group(1)
        if tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tuple(tags)

def _hcnetsdk_stream_details_query(endpoint: _owner_types.HcNetSdkLanEndpoint, template: _owner_types.HcNetSdkCommandPortControlTemplate, session: _owner_types.HcNetSdkCommandPortLoginSession, address: str, timeout: float, socket_factory: _owner_types.SocketFactory, deadline: float, monotonic: _owner_types.Callable[[], float], max_response_bytes: int, *, _owner: _ModuleType) -> _owner_types.HcNetSdkTcpFrame:
    request = template.to_frame(session_id=session.session_id, auth_seed=session.auth_seed, key=session.challenge, local_ip=address)
    with _owner.closing(_owner.HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        client.send_command_frame(request, deadline=deadline, monotonic=monotonic)
        return client.read_tcp_frame(deadline=deadline, monotonic=monotonic, max_frame_bytes=max_response_bytes, allow_short_ack=False)
