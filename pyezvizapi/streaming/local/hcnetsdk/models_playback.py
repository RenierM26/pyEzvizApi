# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001

"""models playback implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""
from __future__ import annotations

import pyezvizapi.streaming.local.hcnetsdk.protocol as _owner


class HcNetSdkRealDataType(_owner.IntEnum):
    """HCNetSDK real-play callback data types used by ``RealDataCallBack``."""
    SYSTEM_HEADER = 1
    STREAM_DATA = 2
    AUDIO_STREAM_DATA = 3
    PRIVATE_DATA = 112

@_owner.dataclass(frozen=True)
class HcNetSdkLanEndpoint:
    """LAN endpoint metadata derived from EZVIZ pagelist ``CONNECTION``."""
    serial: str
    host: str
    net_host: str | None = None
    command_port: int = _owner.HCNETSDK_DEFAULT_SERVER_PORT
    net_command_port: int | None = None
    stream_port: int | None = None
    net_stream_port: int | None = None
    rtsp_port: int | None = None
    sdk_tls_port: int = _owner.HCNETSDK_DEFAULT_TLS_PORT

    @classmethod
    def from_connection(cls, serial: str, connection: _owner.Mapping[str, _owner.Any] | None) -> _owner.HcNetSdkLanEndpoint:
        """Build LAN endpoint metadata from a pagelist ``CONNECTION`` mapping."""
        if not connection:
            raise _owner.PyEzvizError(f'Missing CONNECTION metadata for {serial}')
        host = connection.get('localIp')
        if not isinstance(host, str) or not host.strip():
            raise _owner.PyEzvizError(f'Missing localIp in CONNECTION metadata for {serial}')
        return cls(serial=serial, host=host.strip(), net_host=_owner._mapping_str(connection, 'netIp'), command_port=_owner._mapping_int(connection, 'localCmdPort', default=_owner.HCNETSDK_DEFAULT_SERVER_PORT) or _owner.HCNETSDK_DEFAULT_SERVER_PORT, net_command_port=_owner._mapping_int(connection, 'netCmdPort', default=None), stream_port=_owner._mapping_int(connection, 'localStreamPort', default=None), net_stream_port=_owner._mapping_int(connection, 'netStreamPort', default=None), rtsp_port=_owner._mapping_int(connection, 'localRtspPort', default=_owner.HCNETSDK_DEFAULT_RTSP_PORT, zero_is_missing=True))

@_owner.dataclass(frozen=True)
class HcNetSdkSetupAlarmRequest:
    """Native ``NET_DVR_SetupAlarmChan_V30`` / ``V41`` call shape."""
    login_id: int
    setup_param: _owner.HcNetSdkSetupAlarmParam | None = None

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for setting up an alarm channel."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK alarm setup requires a successful login id')
        if self.setup_param is None:
            return {'api': _owner.HCNETSDK_SETUP_ALARM_CHAN_V30, 'lUserID': self.login_id, 'failureHandle': -1}
        return {'api': _owner.HCNETSDK_SETUP_ALARM_CHAN_V41, 'lUserID': self.login_id, 'lpSetupParam': self.setup_param.to_native_dict(), 'failureHandle': -1}

@_owner.dataclass(frozen=True)
class HcNetSdkCloseAlarmRequest:
    """Native ``NET_DVR_CloseAlarmChan_V30`` call shape."""
    alarm_handle: int
    api: str = _owner.HCNETSDK_CLOSE_ALARM_CHAN_V30

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for closing an alarm channel."""
        if self.alarm_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK alarm handle must be non-negative')
        if self.api != _owner.HCNETSDK_CLOSE_ALARM_CHAN_V30:
            raise _owner.PyEzvizError('HCNetSDK close-alarm API is unsupported')
        return {'api': self.api, 'lAlarmHandle': self.alarm_handle}

@_owner.dataclass(frozen=True)
class EzvizLanVideoResolution:
    """Camera-advertised resolution with its own native rate/bitrate limits."""
    index: int | None = None
    name: str | None = None
    dimensions: str | None = None
    width: int | None = None
    height: int | None = None
    frame_rate_codes: tuple[int, ...] = ()
    bitrate_min: int | None = None
    bitrate_max: int | None = None
    bitrate_codes: tuple[int, ...] = ()

@_owner.dataclass(frozen=True)
class HcNetSdkStreamDetails:
    """One fresh camera snapshot: current configuration is not observed media."""
    channel: int
    configuration: _owner.EzvizLanCompressionConfig = _owner.field(repr=False)
    capabilities: _owner.EzvizLanAudioVideoCompressInfo
    reported_login_serial: str = _owner.field(default='', repr=False)
    capabilities_error: int | None = None

    def configured_media(self, *, sub_stream: bool=False) -> _owner.HcNetSdkConfiguredMedia | None:
        """Translate configured SDK codes; this is not a negotiated media profile."""
        block = self.configuration.network if sub_stream else self.configuration.normal_record
        if block is None:
            return None
        resolution = self.configured_resolution(sub_stream=sub_stream)
        return _owner.normalize_hcnetsdk_parameters(video_encoding_type=block.video_encoding_type, audio_encoding_type=block.audio_encoding_type, video_frame_rate=block.video_frame_rate, video_bitrate=block.video_bitrate, audio_sampling_rate=block.audio_sampling_rate, format_type=block.format_type, width=resolution.width if resolution else None, height=resolution.height if resolution else None)

    def configured_resolution(self, *, sub_stream: bool=False) -> _owner.EzvizLanVideoResolution | None:
        """Resolve a configured SDK index using this camera's own resolution list."""
        block = self.configuration.network if sub_stream else self.configuration.normal_record
        if block is None:
            return None
        channels = [c for c in self.capabilities.video_channels if c.channel_number == self.channel]
        if len(channels) != 1:
            return None
        channel = channels[0]
        if sub_stream:
            profiles = [p for p in channel.sub_streams if p.index == 1]
            profile = profiles[0] if len(profiles) == 1 else None
        else:
            profile = channel.main_stream
        if profile is None:
            return None
        matches = [r for r in profile.resolutions if r.index == block.resolution]
        return matches[0] if len(matches) == 1 else None

    def as_dict(self) -> dict[str, _owner.Any]:
        """Return configuration and capability fields without raw replies/auth data."""

        def configured(block: _owner.EzvizLanCompressionInfoV30 | None) -> dict[str, _owner.Any] | None:
            if block is None:
                return None
            return {key: value for key, value in _owner.asdict(block).items() if key != 'raw'}
        return {'channel': self.channel, 'reported_login_serial': self.reported_login_serial, 'source': 'hcnetsdk_command_port', 'observed_media': False, 'transport_protocol': None, 'main': configured(self.configuration.normal_record), 'sub': configured(self.configuration.network), 'main_configured_media': _owner.asdict(p) if (p := self.configured_media()) is not None else None, 'sub_configured_media': _owner.asdict(p) if (p := self.configured_media(sub_stream=True)) is not None else None, 'main_resolution': _owner.asdict(r) if (r := self.configured_resolution()) is not None else None, 'sub_resolution': _owner.asdict(r) if (r := self.configured_resolution(sub_stream=True)) is not None else None, 'capabilities': _owner.asdict(self.capabilities), 'capabilities_error': self.capabilities_error}

@_owner.dataclass(frozen=True)
class EzvizLanPlaybackConvertResolution:
    """One playback conversion resolution entry from ``RecordAbility`` XML."""
    index: int
    frame_rates: tuple[int, ...] = ()
    bitrates: tuple[int, ...] = ()

@_owner.dataclass(frozen=True)
class HcNetSdkPtzControlRequest:
    """Native ``NET_DVR_PTZControlWithSpeed_Other`` call shape."""
    login_id: int
    channel: int
    command: int
    stop: int
    speed: int = _owner.EZVIZ_LAN_PTZ_SPEED_DEFAULT
    api: str = _owner.HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ control requires a successful login id')
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ control channel must be non-negative')
        if self.command < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ control command must be non-negative')
        if self.stop not in {0, 1}:
            raise _owner.PyEzvizError('HCNetSDK PTZ control stop flag must be 0 or 1')
        if self.speed < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ control speed must be non-negative')
        return {'api': self.api, 'lUserID': self.login_id, 'lChannel': self.channel, 'dwPTZCommand': self.command, 'dwStop': self.stop, 'dwSpeed': self.speed}

@_owner.dataclass(frozen=True)
class HcNetSdkPtzPresetRequest:
    """Native ``NET_DVR_PTZPreset_Other`` call shape."""
    login_id: int
    channel: int
    command: int
    preset_index: int = 0
    api: str = _owner.HCNETSDK_PTZ_PRESET_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ preset requires a successful login id')
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ preset channel must be non-negative')
        if self.command not in {8, 9, 39}:
            raise _owner.PyEzvizError('HCNetSDK PTZ preset command is unsupported')
        if self.preset_index < 0:
            raise _owner.PyEzvizError('HCNetSDK PTZ preset index must be non-negative')
        return {'api': self.api, 'lUserID': self.login_id, 'lChannel': self.channel, 'dwPTZPresetCmd': self.command, 'dwPresetIndex': self.preset_index}

@_owner.dataclass(frozen=True)
class EzvizLanPlaybackIntent:
    """Intent extras used to hand a LAN HCNetSDK login to the player UI."""
    serial: str
    channel_number: int
    lan_user_id: int = -1
    ssid: str = ''
    lan_flag: int = _owner.EZVIZ_PLAYER_LAN_FLAG_HCNETSDK

    def to_extra_dict(self) -> dict[str, int | str]:
        """Return the exact extras written by startLanVideoPlay(...)."""
        return {_owner.EZVIZ_PLAYER_EXTRA_DEVICE_ID: self.serial, _owner.EZVIZ_PLAYER_EXTRA_CHANNEL_NO: self.channel_number, _owner.EZVIZ_PLAYER_EXTRA_LAN_FLAG: self.lan_flag, _owner.EZVIZ_PLAYER_EXTRA_LAN_USERID: self.lan_user_id, _owner.EZVIZ_PLAYER_EXTRA_WIFI_SSID: self.ssid}

@_owner.dataclass(frozen=True)
class EzvizLanVideoQuality:
    """LAN quality pair exposed by ``LanItemDataHolder.getVideoQualityInfo()``."""
    stream_type: int
    video_level: int

    @property
    def native_video_level(self) -> int:
        """Return the value written to ``InitParam.iVideoLevel`` by the player."""
        return _owner.ezviz_native_video_level(self.video_level)

@_owner.dataclass(frozen=True)
class EzvizLanKeyframeRequest:
    """HCNetSDK I-frame request made after LAN native preview starts."""
    api: str
    netsdk_login_id: int
    netsdk_channel_number: int

@_owner.dataclass(frozen=True)
class HcNetSdkRealDataPacket:
    """One packet emitted by an HCNetSDK real-play data callback."""
    real_handle: int
    data_type: int
    body: bytes

    @property
    def is_media(self) -> bool:
        """Return whether this callback packet can carry remuxable media."""
        return _owner.hcnetsdk_real_data_type_is_media(self.data_type)

    @property
    def payload_kind(self) -> str:
        """Return a small, non-secret classification of the callback body."""
        return _owner.classify_hcnetsdk_real_data_payload(self.body)

@_owner.dataclass(frozen=True)
class HcNetSdkSemanticLogEvent:
    """One secret-safe semantic HCNetSDK event."""
    name: str
    phase: str | None = None
    fields: _owner.Mapping[str, str] | None = None

@_owner.dataclass(frozen=True)
class HcNetSdkCommandTraceSummary:
    """Secret-safe summary of one mixed HCNetSDK command-port trace.

    Shape logs intentionally avoid raw payloads. This summary preserves only
    the useful correlation: which command candidates were sent during the
    settings login call, which follow-up command candidates appeared afterward,
    and whether playback/media/keyframe boundaries were observed.
    """
    settings_login_commands: tuple[int, ...] = ()
    followup_commands: tuple[int, ...] = ()
    settings_login_success: bool = False
    play_device_login_success: bool = False
    keyframe_requested: bool = False
    media_on_command_socket: bool = False

@_owner.dataclass(frozen=True)
class HcNetSdkClientInfo:
    """Python model of the Java/native ``NET_DVR_CLIENTINFO`` preview input."""
    channel: int = 1
    link_mode: int = 0
    multicast_ip: str = ''

    def to_native_dict(self) -> dict[str, int | str]:
        """Return the field names from the APK's ``NET_DVR_CLIENTINFO`` class."""
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK client channel must be non-negative')
        if self.link_mode < 0:
            raise _owner.PyEzvizError('HCNetSDK client link mode must be non-negative')
        return {'lChannel': self.channel, 'lLinkMode': self.link_mode, 'sMultiCastIP': self.multicast_ip}

@_owner.dataclass(frozen=True)
class HcNetSdkRealPlayRequest:
    """Arguments needed for ``EZ_NET_DVR_RealPlay_V30`` plus callback metadata."""
    login_id: int
    client_info: HcNetSdkClientInfo
    blocked: bool = False
    callback_api: str = _owner.HCNETSDK_REALDATA_CALLBACK_V30
    api: str = _owner.HCNETSDK_REALPLAY_V30

    def to_native_args_hint(self) -> dict[str, int | str | dict[str, int | str]]:
        """Return a serializable hint for HCNetSDK-compatible real-play calls."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK real-play requires a successful login id')
        return {'api': self.api, 'login_id': self.login_id, 'client_info': self.client_info.to_native_dict(), 'callback': self.callback_api, 'blocked': int(self.blocked)}

@_owner.dataclass(frozen=True)
class EzvizLanPlaybackPath:
    """Complete LAN Live View path observed in the EZVIZ Android app."""
    settings_login_candidates: tuple[_owner.HcNetSdkLoginCandidate, ...]
    settings_login_id: int
    channel_number: int
    playback_intent: EzvizLanPlaybackIntent
    play_device_login: _owner.EzvizLanPlayDeviceLogin
    play_device_login_id: int
    live_view: _owner.EzvizLanLiveViewParams
    create_client_api: str = _owner.EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = _owner.EZVIZ_NATIVE_START_PREVIEW

    @property
    def post_start_keyframe_request(self) -> _owner.EzvizLanKeyframeRequest | None:
        """Return the keyframe request made after native preview starts."""
        return _owner.EzvizLanPreviewPlan(login_candidates=self.settings_login_candidates, live_view=self.live_view, play_device_login=self.play_device_login, create_client_api=self.create_client_api, start_preview_api=self.start_preview_api).post_start_keyframe_request

    def call_sequence(self) -> tuple[str, ...]:
        """Return the app-level calls needed for a complete LAN playback start."""
        calls = [_owner.EZVIZ_HCNETUTIL_LOGIN_V40, _owner.EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF, _owner.EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY, self.play_device_login.api, self.create_client_api, self.start_preview_api]
        if self.post_start_keyframe_request is not None:
            calls.append(self.post_start_keyframe_request.api)
        return tuple(calls)

@_owner.dataclass(frozen=True)
class HcNetSdkNoArgRequest:
    """Native no-argument HCNetSDK call shape."""
    api: str

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the no-argument native call name."""
        if self.api not in {_owner.HCNETSDK_CLEANUP, _owner.HCNETSDK_GET_LAST_ERROR, _owner.HCNETSDK_GET_SDK_VERSION, _owner.HCNETSDK_GET_SDK_BUILD_VERSION}:
            raise _owner.PyEzvizError('HCNetSDK no-argument API is unsupported')
        return {'api': self.api}

@_owner.dataclass(frozen=True)
class HcNetSdkInitRequest:
    """Native ``NET_DVR_Init`` call shape."""
    playctrl_library: str | None = 'libPlayCtrl.so'
    api: str = _owner.HCNETSDK_INIT

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for SDK initialization."""
        if self.api != _owner.HCNETSDK_INIT:
            raise _owner.PyEzvizError('HCNetSDK init API is unsupported')
        if self.playctrl_library is None:
            return {'api': self.api, 'overload': 'android-default-playctrl-library'}
        playctrl_library = self.playctrl_library.strip()
        if not playctrl_library or '\x00' in playctrl_library:
            raise _owner.PyEzvizError('HCNetSDK PlayCtrl library name is invalid')
        return {'api': self.api, 'sPlayCtrlPath': playctrl_library}

@_owner.dataclass(frozen=True)
class HcNetSdkSetConnectTimeRequest:
    """Native ``NET_DVR_SetConnectTime`` call shape used by the APK."""
    connect_time_ms: int = 5000
    retry_count: int = 3
    api: str = _owner.HCNETSDK_SET_CONNECT_TIME

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for setting SDK connect timeout."""
        if self.connect_time_ms < 0:
            raise _owner.PyEzvizError('HCNetSDK connect time must be non-negative')
        if self.retry_count < 0:
            raise _owner.PyEzvizError('HCNetSDK connect retry count must be non-negative')
        if self.api != _owner.HCNETSDK_SET_CONNECT_TIME:
            raise _owner.PyEzvizError('HCNetSDK connect-time API is unsupported')
        return {'api': self.api, 'dwWaitTime': self.connect_time_ms, 'dwTryTimes': self.retry_count}

@_owner.dataclass(frozen=True)
class HcNetSdkGetErrorMsgRequest:
    """Native ``NET_DVR_GetErrorMsg`` call shape."""
    error_code: int | None = None
    api: str = _owner.HCNETSDK_GET_ERROR_MSG

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for resolving an HCNetSDK error."""
        if self.api != _owner.HCNETSDK_GET_ERROR_MSG:
            raise _owner.PyEzvizError('HCNetSDK error-message API is unsupported')
        hint: dict[str, _owner.Any] = {'api': self.api, 'pErrorNo': '<INT_PTR>'}
        if self.error_code is not None:
            if self.error_code < 0:
                raise _owner.PyEzvizError('HCNetSDK error code must be non-negative')
            hint['intPointerValue'] = self.error_code
        return hint

@_owner.dataclass(frozen=True)
class HcNetSdkLogoutRequest:
    """Native ``NET_DVR_Logout_V30`` call shape."""
    login_id: int
    api: str = _owner.HCNETSDK_LOGOUT_V30

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for logging out a local SDK session."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK logout requires a successful login id')
        if self.api != _owner.HCNETSDK_LOGOUT_V30:
            raise _owner.PyEzvizError('HCNetSDK logout API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id}

@_owner.dataclass(frozen=True)
class HcNetSdkTime:
    """Native ``NET_DVR_TIME`` field set."""
    year: int
    month: int
    day: int
    hour: int = 0
    minute: int = 0
    second: int = 0

    @classmethod
    def from_datetime(cls, value: _owner.datetime) -> _owner.HcNetSdkTime:
        """Build a native time from a Python ``datetime``."""
        return cls(year=value.year, month=value.month, day=value.day, hour=value.hour, minute=value.minute, second=value.second)

    @classmethod
    def from_date(cls, value: _owner.date, *, end_of_day: bool=False) -> _owner.HcNetSdkTime:
        """Build a native day boundary from a Python ``date``."""
        return cls(year=value.year, month=value.month, day=value.day, hour=23 if end_of_day else 0, minute=59 if end_of_day else 0, second=59 if end_of_day else 0)

    def to_native_dict(self) -> dict[str, _owner.Any]:
        """Return the Java ``NET_DVR_TIME`` field names and values."""
        if self.year < 0:
            raise _owner.PyEzvizError('HCNetSDK time year must be non-negative')
        if not 1 <= self.month <= 12:
            raise _owner.PyEzvizError('HCNetSDK time month must be between 1 and 12')
        if not 1 <= self.day <= 31:
            raise _owner.PyEzvizError('HCNetSDK time day must be between 1 and 31')
        if not 0 <= self.hour <= 23:
            raise _owner.PyEzvizError('HCNetSDK time hour must be between 0 and 23')
        if not 0 <= self.minute <= 59:
            raise _owner.PyEzvizError('HCNetSDK time minute must be between 0 and 59')
        if not 0 <= self.second <= 59:
            raise _owner.PyEzvizError('HCNetSDK time second must be between 0 and 59')
        return {'structure': 'NET_DVR_TIME', 'fieldOrder': _owner.HCNETSDK_TIME_FIELD_ORDER, 'dwYear': self.year, 'dwMonth': self.month, 'dwDay': self.day, 'dwHour': self.hour, 'dwMinute': self.minute, 'dwSecond': self.second}

@_owner.dataclass(frozen=True)
class HcNetSdkFileCond:
    """Native ``NET_DVR_FILECOND`` search condition used by LAN playback."""
    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    file_type: int = _owner.HCNETSDK_PLAYBACK_FILE_TYPE_ALL
    is_locked: int = _owner.HCNETSDK_PLAYBACK_LOCK_STATE_ALL
    use_card_no: int = 0
    card_number: str | bytes = b''

    def to_native_dict(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the Java ``NET_DVR_FILECOND`` field shape."""
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK file search channel must be non-negative')
        if self.file_type < 0:
            raise _owner.PyEzvizError('HCNetSDK file search file type must be non-negative')
        if self.is_locked < 0:
            raise _owner.PyEzvizError('HCNetSDK file search lock state must be non-negative')
        if self.use_card_no < 0:
            raise _owner.PyEzvizError('HCNetSDK file search card flag must be non-negative')
        card_number = _owner._bounded_bytes('HCNetSDK file search card number', self.card_number, 32)
        return {'structure': 'NET_DVR_FILECOND', 'fieldOrder': _owner.HCNETSDK_FILECOND_FIELD_ORDER, 'lChannel': self.channel, 'dwFileType': self.file_type, 'dwIsLocked': self.is_locked, 'dwUseCardNo': self.use_card_no, 'sCardNumber': card_number if include_buffers else _owner._nul_stripped_text(card_number), 'sCardNumberBufferSize': 32, 'struStartTime': self.start_time.to_native_dict(), 'struStopTime': self.stop_time.to_native_dict()}

@_owner.dataclass(frozen=True)
class HcNetSdkFindFileRequest:
    """Native ``NET_DVR_FindFile_V30`` call shape."""
    login_id: int
    file_cond: HcNetSdkFileCond
    api: str = _owner.HCNETSDK_FIND_FILE_V30

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for starting playback file search."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK file search requires a successful login id')
        if self.api != _owner.HCNETSDK_FIND_FILE_V30:
            raise _owner.PyEzvizError('HCNetSDK find-file API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id, 'lpFindCond': self.file_cond.to_native_dict(include_buffers=include_buffers), 'failureHandle': _owner.HCNETSDK_FIND_FILE_FAILED}

@_owner.dataclass(frozen=True)
class HcNetSdkFindDataV30:
    """Native ``NET_DVR_FINDDATA_V30`` output-buffer shape."""
    file_name: str | bytes = b''
    start_time: HcNetSdkTime | None = None
    stop_time: HcNetSdkTime | None = None
    file_size: int = 0
    card_number: str | bytes = b''
    locked: int = 0
    file_type: int = 0

    def to_native_dict(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the Java ``NET_DVR_FINDDATA_V30`` field shape."""
        if self.file_size < 0:
            raise _owner.PyEzvizError('HCNetSDK find data file size must be non-negative')
        file_name = _owner._bounded_bytes('HCNetSDK find data file name', self.file_name, 100)
        card_number = _owner._bounded_bytes('HCNetSDK find data card number', self.card_number, 32)
        return {'structure': 'NET_DVR_FINDDATA_V30', 'fieldOrder': _owner.HCNETSDK_FINDDATA_V30_FIELD_ORDER, 'sFileName': file_name if include_buffers else _owner._nul_stripped_text(file_name), 'sFileNameBufferSize': 100, 'struStartTime': (self.start_time or _owner.HcNetSdkTime(0, 1, 1)).to_native_dict(), 'struStopTime': (self.stop_time or _owner.HcNetSdkTime(0, 1, 1)).to_native_dict(), 'dwFileSize': self.file_size, 'sCardNum': card_number if include_buffers else _owner._nul_stripped_text(card_number), 'sCardNumBufferSize': 32, 'byLocked': _owner._byte_value('find data locked', self.locked), 'byFileType': _owner._byte_value('find data file type', self.file_type), 'byResLength': 2}

@_owner.dataclass(frozen=True)
class HcNetSdkFindNextFileRequest:
    """Native ``NET_DVR_FindNextFile_V30`` call shape."""
    find_handle: int
    find_data: HcNetSdkFindDataV30 | None = None
    api: str = _owner.HCNETSDK_FIND_NEXT_FILE_V30

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for polling playback file search."""
        if self.find_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK find handle must be non-negative')
        if self.api != _owner.HCNETSDK_FIND_NEXT_FILE_V30:
            raise _owner.PyEzvizError('HCNetSDK find-next-file API is unsupported')
        find_data = self.find_data or _owner.HcNetSdkFindDataV30()
        return {'api': self.api, 'lFindHandle': self.find_handle, 'lpFindData': find_data.to_native_dict(include_buffers=include_buffers)}

@_owner.dataclass(frozen=True)
class HcNetSdkFindCloseRequest:
    """Native ``NET_DVR_FindClose_V30`` call shape."""
    find_handle: int
    api: str = _owner.HCNETSDK_FIND_CLOSE_V30

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for closing a playback file search."""
        if self.find_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK find handle must be non-negative')
        if self.api != _owner.HCNETSDK_FIND_CLOSE_V30:
            raise _owner.PyEzvizError('HCNetSDK find-close API is unsupported')
        return {'api': self.api, 'lFindHandle': self.find_handle}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayCond:
    """Native ``NET_DVR_PLAYCOND`` time-playback condition."""
    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    draw_frame: int = 0
    stream_type: int = 0
    stream_id: str | bytes = b''

    def to_native_dict(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the Java ``NET_DVR_PLAYCOND`` field shape."""
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK playback channel must be non-negative')
        stream_id = _owner._bounded_bytes('HCNetSDK playback stream id', self.stream_id, 32)
        return {'structure': 'NET_DVR_PLAYCOND', 'fieldOrder': _owner.HCNETSDK_PLAYCOND_FIELD_ORDER, 'dwChannel': self.channel, 'struStartTime': self.start_time.to_native_dict(), 'struStopTime': self.stop_time.to_native_dict(), 'byDrawFrame': _owner._byte_value('playback draw-frame flag', self.draw_frame), 'byStreamType': _owner._byte_value('playback stream type', self.stream_type), 'byStreamID': stream_id if include_buffers else _owner._nul_stripped_text(stream_id), 'byStreamIDBufferSize': 32, 'byResLength': 30}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayBackByTimeRequest:
    """Native ``NET_DVR_PlayBackByTime_V40`` call shape."""
    login_id: int
    play_cond: HcNetSdkPlayCond
    api: str = _owner.HCNETSDK_PLAYBACK_BY_TIME_V40

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for time-based playback start."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK playback requires a successful login id')
        if self.api != _owner.HCNETSDK_PLAYBACK_BY_TIME_V40:
            raise _owner.PyEzvizError('HCNetSDK playback-by-time API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id, 'lpPlayCond': self.play_cond.to_native_dict(include_buffers=include_buffers), 'failureHandle': _owner.HCNETSDK_PLAYBACK_FAILED}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayBackControlRequest:
    """Native ``NET_DVR_PlayBackControl_V40`` call shape."""
    play_handle: int
    command: int
    in_buffer: str | bytes | None = None
    out_buffer_size: int = 0
    api: str = _owner.HCNETSDK_PLAYBACK_CONTROL_V40

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for playback control."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        if self.command < 0:
            raise _owner.PyEzvizError('HCNetSDK playback control command must be non-negative')
        if self.out_buffer_size < 0:
            raise _owner.PyEzvizError('HCNetSDK playback output size must be non-negative')
        if self.api != _owner.HCNETSDK_PLAYBACK_CONTROL_V40:
            raise _owner.PyEzvizError('HCNetSDK playback-control API is unsupported')
        in_buffer = _owner._optional_native_bytes('HCNetSDK playback control input buffer', self.in_buffer)
        return {'api': self.api, 'lPlayHandle': self.play_handle, 'dwControlCode': int(self.command), 'lpInBuffer': in_buffer if include_buffers and in_buffer else '<input-buffer>' if in_buffer else None, 'dwInLen': len(in_buffer), 'lpOutBuffer': '<output-buffer>' if self.out_buffer_size else None, 'dwOutLen': self.out_buffer_size, 'lpOutLen': '<DWORD_PTR>' if self.out_buffer_size else None}

@_owner.dataclass(frozen=True)
class HcNetSdkStopPlayBackRequest:
    """Native ``NET_DVR_StopPlayBack`` call shape."""
    play_handle: int
    api: str = _owner.HCNETSDK_STOP_PLAYBACK

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for stopping playback."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        if self.api != _owner.HCNETSDK_STOP_PLAYBACK:
            raise _owner.PyEzvizError('HCNetSDK stop-playback API is unsupported')
        return {'api': self.api, 'lPlayHandle': self.play_handle}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayBackCaptureFileRequest:
    """Native ``NET_DVR_PlayBackCaptureFile`` call shape."""
    play_handle: int
    saved_file_name: str | bytes
    api: str = _owner.HCNETSDK_PLAYBACK_CAPTURE_FILE

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for a playback snapshot."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        if self.api != _owner.HCNETSDK_PLAYBACK_CAPTURE_FILE:
            raise _owner.PyEzvizError('HCNetSDK playback-capture API is unsupported')
        return {'api': self.api, 'lPlayHandle': self.play_handle, 'sFileName': _owner._native_path_value('playback capture file name', self.saved_file_name, include_buffers=include_buffers)}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayDataCallbackRequest:
    """Native ``NET_DVR_SetPlayDataCallBack`` / ``V40`` call shape."""
    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = _owner.HCNETSDK_SET_PLAY_DATA_CALLBACK

    @property
    def is_v40(self) -> bool:
        """Return whether this is the V40 callback setter variant."""
        return self.api == _owner.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for registering playback data callbacks."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        if self.api not in {_owner.HCNETSDK_SET_PLAY_DATA_CALLBACK, _owner.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40}:
            raise _owner.PyEzvizError('HCNetSDK playback data callback API is unsupported')
        if self.is_v40:
            return {'api': self.api, 'lPlayHandle': self.play_handle, 'fPlayDataCallBack_V40': self.callback or '<PlayDataCallBack_V40>', 'pUser': self.user_data if self.user_data is not None else None, 'callbackSignature': 'void(int playHandle, int dataType, byte* buffer, uint length, void* user)'}
        return {'api': self.api, 'lPlayHandle': self.play_handle, 'fPlayDataCallBack': self.callback or '<PlayDataCallBack>', 'dwUser': self.user_data if self.user_data is not None else 0, 'callbackSignature': 'void(int playHandle, uint dataType, byte* buffer, uint length, uint user)'}

@_owner.dataclass(frozen=True)
class HcNetSdkPlaybackCallbackRequest:
    """Native playback response / elementary-stream callback setter shape."""
    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = _owner.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for playback callback registration."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        callback_names = {_owner.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK: ('fPlaybackResponseCallBack', '<PlaybackResponseCallBack>'), _owner.HCNETSDK_SET_PLAYBACK_ES_CALLBACK: ('fPlayBackESCallBack', '<PlayBackESCallBack>')}
        if self.api not in callback_names:
            raise _owner.PyEzvizError('HCNetSDK playback callback API is unsupported')
        arg_name, placeholder = callback_names[self.api]
        return {'api': self.api, 'lPlayHandle': self.play_handle, arg_name: self.callback or placeholder, 'pUser': self.user_data if self.user_data is not None else None}

@_owner.dataclass(frozen=True)
class HcNetSdkPlayBackSecretKeyRequest:
    """Native ``NET_DVR_SetPlayBackSecretKey`` call shape."""
    play_handle: int
    secret_key: str | bytes
    secret_key_type: int = _owner.HCNETSDK_SECRET_KEY_TYPE_AES
    api: str = _owner.HCNETSDK_SET_PLAYBACK_SECRET_KEY

    def to_native_args_hint(self, *, include_secret: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for setting a playback stream key."""
        if self.play_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK playback handle must be non-negative')
        if self.secret_key_type < 0:
            raise _owner.PyEzvizError('HCNetSDK playback secret-key type must be non-negative')
        if self.api != _owner.HCNETSDK_SET_PLAYBACK_SECRET_KEY:
            raise _owner.PyEzvizError('HCNetSDK playback secret-key API is unsupported')
        secret_key = _owner._native_secret_key_bytes('HCNetSDK playback secret key', self.secret_key)
        return {'api': self.api, 'lPlayHandle': self.play_handle, 'dwSecretKeyType': self.secret_key_type, 'pSecretKey': secret_key if include_secret else '<secret-key>', 'dwSecretKeyLen': len(secret_key)}

@_owner.dataclass(frozen=True)
class HcNetSdkGetFileByNameRequest:
    """Native ``NET_DVR_GetFileByName`` download-start call shape."""
    login_id: int
    dvr_file_name: str | bytes
    saved_file_name: str | bytes
    api: str = _owner.HCNETSDK_GET_FILE_BY_NAME

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for file-name based download."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK file download requires a successful login id')
        if self.api != _owner.HCNETSDK_GET_FILE_BY_NAME:
            raise _owner.PyEzvizError('HCNetSDK get-file-by-name API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id, 'sDVRFileName': _owner._native_path_value('DVR file name', self.dvr_file_name, include_buffers=include_buffers), 'sSavedFileName': _owner._native_path_value('saved file name', self.saved_file_name, include_buffers=include_buffers), 'failureHandle': _owner.HCNETSDK_GET_FILE_FAILED}

@_owner.dataclass(frozen=True)
class HcNetSdkGetFileByTimeRequest:
    """Native ``NET_DVR_GetFileByTime`` download-start call shape."""
    login_id: int
    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    saved_file_name: str | bytes
    api: str = _owner.HCNETSDK_GET_FILE_BY_TIME

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for time-based download."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK file download requires a successful login id')
        if self.channel < 0:
            raise _owner.PyEzvizError('HCNetSDK file download channel must be non-negative')
        if self.api != _owner.HCNETSDK_GET_FILE_BY_TIME:
            raise _owner.PyEzvizError('HCNetSDK get-file-by-time API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id, 'lChannel': self.channel, 'lpStartTime': self.start_time.to_native_dict(), 'lpStopTime': self.stop_time.to_native_dict(), 'sSavedFileName': _owner._native_path_value('saved file name', self.saved_file_name, include_buffers=include_buffers), 'failureHandle': _owner.HCNETSDK_GET_FILE_FAILED}

@_owner.dataclass(frozen=True)
class HcNetSdkStopGetFileRequest:
    """Native ``NET_DVR_StopGetFile`` call shape."""
    file_handle: int
    api: str = _owner.HCNETSDK_STOP_GET_FILE

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for stopping a file download."""
        if self.file_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK file handle must be non-negative')
        if self.api != _owner.HCNETSDK_STOP_GET_FILE:
            raise _owner.PyEzvizError('HCNetSDK stop-get-file API is unsupported')
        return {'api': self.api, 'lFileHandle': self.file_handle}

@_owner.dataclass(frozen=True)
class HcNetSdkGetDownloadPosRequest:
    """Native ``NET_DVR_GetDownloadPos`` call shape."""
    file_handle: int
    api: str = _owner.HCNETSDK_GET_DOWNLOAD_POS

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for polling download progress."""
        if self.file_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK file handle must be non-negative')
        if self.api != _owner.HCNETSDK_GET_DOWNLOAD_POS:
            raise _owner.PyEzvizError('HCNetSDK get-download-position API is unsupported')
        return {'api': self.api, 'lFileHandle': self.file_handle}

@_owner.dataclass(frozen=True)
class SadpActivateDeviceRequest:
    """Android ``SADP_ActivateDevice`` call shape."""
    serial: str
    password: str
    api: str = _owner.SADP_ACTIVATE_DEVICE

    def to_native_args_hint(self, *, include_password: bool=False) -> dict[str, _owner.Any]:
        """Return the native argument names for a local SADP bridge."""
        serial = self.serial.strip()
        if not serial:
            raise _owner.PyEzvizError('SADP activation serial cannot be empty')
        password = self.password
        if not password:
            raise _owner.PyEzvizError('SADP activation password cannot be empty')
        return {'api': self.api, 'serial': serial, 'password': password if include_password else '<password>', 'passwordLength': len(password.encode('utf-8')), 'lastErrorApi': _owner.SADP_GET_LAST_ERROR}

@_owner.dataclass(frozen=True)
class SadpNoArgRequest:
    """Native no-argument SADP call shape."""
    api: str

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the no-argument SADP call name."""
        if self.api not in {_owner.SADP_GET_LAST_ERROR, _owner.SADP_GET_VERSION, _owner.SADP_STOP, _owner.SADP_CLEARUP, _owner.SADP_SEND_INQUIRY}:
            raise _owner.PyEzvizError('SADP no-argument API is unsupported')
        return {'api': self.api}

@_owner.dataclass(frozen=True)
class SadpStartRequest:
    """Native ``SADP_Start_V30`` / ``V40`` call shape."""
    version: int = 40
    install_npf: int | bool = 0
    callback: str | None = None
    user_data: str | None = None

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return native argument names for starting SADP discovery."""
        if self.version not in {30, 40}:
            raise _owner.PyEzvizError('SADP start version must be 30 or 40')
        install_npf = _owner._byte_value('SADP install NPF flag', int(self.install_npf))
        if self.version == 30:
            return {'api': _owner.SADP_START_V30, 'pDeviceFindCallBack': self.callback or '<DeviceFindCallBack>', 'bInstallNPF': install_npf, 'pUserData': self.user_data or '<Pointer.NULL>'}
        return {'api': _owner.SADP_START_V40, 'pDeviceFindCallBack_v40': self.callback or '<DeviceFindCallBack_V40>', 'bInstallNPF': install_npf, 'pUserData': self.user_data or '<Pointer.NULL>'}

@_owner.dataclass(frozen=True)
class SadpSetLogToFileRequest:
    """Native ``SADP_SetLogToFile`` call shape."""
    log_level: int
    log_dir: str | bytes
    auto_delete: int | bool = True
    api: str = _owner.SADP_SET_LOG_TO_FILE

    def to_native_args_hint(self, *, include_buffer: bool=False) -> dict[str, _owner.Any]:
        """Return native argument names for SADP file logging."""
        if self.api != _owner.SADP_SET_LOG_TO_FILE:
            raise _owner.PyEzvizError('SADP log API is unsupported')
        if self.log_level < 0:
            raise _owner.PyEzvizError('SADP log level must be non-negative')
        log_dir = _owner._sadp_string_bytes('log directory', self.log_dir, 4096)
        if _owner.SADP_NUL_BYTE in log_dir:
            raise _owner.PyEzvizError('SADP log directory cannot contain NUL bytes')
        return {'api': self.api, 'nLogLevel': self.log_level, 'strLogDir': log_dir + _owner.SADP_NUL_BYTE if include_buffer else log_dir.decode('utf-8', errors='replace'), 'bAutoDel': _owner._byte_value('SADP auto-delete flag', int(self.auto_delete))}

@_owner.dataclass(frozen=True)
class SadpBatchResult:
    """RN-style batch operation result for SADP activation/network edits."""
    identifier: str
    password: str
    code: int
    error: int
    identifier_key: str

    def to_rn_dict(self, *, include_password: bool=True) -> dict[str, _owner.Any]:
        """Return the map pushed into the React Native result array."""
        if self.identifier_key not in {'serial', 'mac'}:
            raise _owner.PyEzvizError('SADP batch result identifier key is unsupported')
        identifier = self.identifier.strip()
        if not identifier:
            raise _owner.PyEzvizError('SADP batch result identifier cannot be empty')
        if not self.password:
            raise _owner.PyEzvizError('SADP batch result password cannot be empty')
        return {self.identifier_key: identifier, 'password': self.password if include_password else '<password>', 'code': self.code, 'error': self.error}
