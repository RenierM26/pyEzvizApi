# Runtime hooks deliberately resolve through their legacy owner.
# ruff: noqa: SLF001
# Model defaults depend only on the SDK constants leaf.
# ruff: noqa: E402, I001, SLF001
from __future__ import annotations
from pyezvizapi.streaming.local.hcnetsdk import constants as _constants
"""models configuration implementation; legacy runtime hooks remain on the owner module.

Access through _owner is deliberate: callers that patch the compatibility
module must still affect dependent operations. No copied hook snapshots.
"""

@_constants.dataclass(frozen=True)
class HcNetSdkStdXmlConfigRequest:
    """Python model of ``NET_DVR_STDXMLConfig`` request/output allocation.

    EZVIZ's Android helpers put the full ISAPI method/path/body text in
    ``lpRequestUrl`` and leave ``lpInBuffer`` empty. This model keeps that
    native boundary explicit while avoiding a hard dependency on host-native
    bindings.
    """
    request: str | bytes
    in_buffer: str | bytes = b''
    recv_timeout: int = 0
    force_encrypt: int = 0
    num_of_multi_part: int = 0
    output_buffer_size: int = _constants.HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
    status_buffer_size: int = _constants.HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE

    def __post_init__(self) -> None:
        for name, value in (('recv_timeout', self.recv_timeout), ('output_buffer_size', self.output_buffer_size), ('status_buffer_size', self.status_buffer_size)):
            if value < 0:
                raise _owner.PyEzvizError(f'HCNetSDK STDXML {name} must be non-negative')
        for name, value in (('force_encrypt', self.force_encrypt), ('num_of_multi_part', self.num_of_multi_part)):
            if not 0 <= value <= 255:
                raise _owner.PyEzvizError(f'HCNetSDK STDXML {name} must fit in one byte')

    @property
    def request_bytes(self) -> bytes:
        """Return bytes assigned to native ``lpRequestUrl``."""
        return _owner._stdxml_bytes('request', self.request)

    @property
    def in_buffer_bytes(self) -> bytes:
        """Return bytes assigned to native ``lpInBuffer``."""
        return _owner._stdxml_bytes('input buffer', self.in_buffer)

    @property
    def android_helper_compatible(self) -> bool:
        """Return whether this request fits EZVIZ's 1024-byte Java buffer."""
        return len(self.request_bytes) <= _owner.HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE and (not self.in_buffer_bytes)

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the JNA field shape used by EZVIZ's STDXML helpers.

        By default the byte buffers are represented by placeholders so callers
        can log the shape without exposing request bodies. Pass
        ``include_buffers=True`` when handing data to a local native bridge.
        """
        request_bytes = self.request_bytes
        in_buffer = self.in_buffer_bytes
        return {'api': 'NET_DVR_STDXMLConfig', 'input': {'field_order': _owner.HCNETSDK_STDXML_INPUT_FIELD_ORDER, 'dwSize': 'sizeof(NET_DVR_XML_CONFIG_INPUT)', 'lpRequestUrl': request_bytes if include_buffers else '<request-url-buffer>', 'dwRequestUrlLen': len(request_bytes), 'lpInBuffer': in_buffer if include_buffers and in_buffer else '<input-buffer>' if in_buffer else None, 'dwInBufferSize': len(in_buffer), 'dwRecvTimeOut': self.recv_timeout, 'byForceEncrpt': self.force_encrypt, 'byNumOfMultiPart': self.num_of_multi_part, 'byResLength': 30}, 'output': {'field_order': _owner.HCNETSDK_STDXML_OUTPUT_FIELD_ORDER, 'dwSize': 'sizeof(NET_DVR_XML_CONFIG_OUTPUT)', 'lpOutBuffer': '<output-buffer>', 'dwOutBufferSize': self.output_buffer_size, 'dwReturnedXMLSize': '<returned-xml-size>', 'lpStatusBuffer': '<status-buffer>', 'dwStatusSize': self.status_buffer_size, 'byResLength': 32}, 'android_helper_compatible': self.android_helper_compatible}

@_constants.dataclass(frozen=True)
class HcNetSdkStdXmlConfigResponse:
    """Result returned by a native ``NET_DVR_STDXMLConfig`` call."""
    succeeded: bool
    output: bytes
    status: bytes = b''
    returned_xml_size: int = 0
    last_error: int | None = None

    @property
    def text(self) -> str:
        """Decode the output buffer as UTF-8."""
        return self.output.decode('utf-8')

    @property
    def status_text(self) -> str:
        """Decode the status buffer as UTF-8."""
        return self.status.decode('utf-8')

    def json(self) -> dict[str, _owner.Any]:
        """Parse the output buffer as a JSON object."""
        return _owner.hcnetsdk_stdxml_response_json(self.output)

@_constants.dataclass(frozen=True)
class EzvizLanServicesSwitchState:
    """Parsed ``servicesSwitch`` values returned by EZVIZ local ISAPI."""
    hiksdk: int | None = None
    web: int | None = None
    rtsp: int | None = None
    raw: _owner.Mapping[str, _owner.Any] | None = None

    @property
    def hiksdk_enabled(self) -> bool | None:
        """Return the local HCNetSDK switch as a boolean when present."""
        return None if self.hiksdk is None else bool(self.hiksdk)

    @property
    def web_enabled(self) -> bool | None:
        """Return the local web switch as a boolean when present."""
        return None if self.web is None else bool(self.web)

@_constants.dataclass(frozen=True)
class EzvizLanWifiApInfo:
    """One Wi-Fi access point entry returned by ``NET_DVR_AP_INFO_LIST``."""
    ssid: str
    security: int
    channel: int
    signal_strength: int
    extra: int

@_constants.dataclass(frozen=True)
class EzvizLanHdDiskConfig:
    """One ``NET_DVR_SINGLE_HD`` entry from a traced storage config."""
    hd_no: int
    capacity: int
    free_space: int
    status: int
    attribute: int
    hd_type: int
    disk_driver: int
    group: int
    recycling: int
    storage_type: int
    picture_capacity: int
    free_picture_space: int

@_constants.dataclass(frozen=True)
class EzvizLanHdConfig:
    """Known fields from a traced ``NET_DVR_HDCFG`` response."""
    declared_size: int
    raw: bytes
    disk_count: int = 0
    disks: tuple[EzvizLanHdDiskConfig, ...] = ()

@_constants.dataclass(frozen=True)
class EzvizLanNtpConfig:
    """Known fields from a traced ``NET_DVR_NTPPARA`` response."""
    ntp_server: str
    interval_minutes: int
    enabled: int
    time_difference_hours: int
    time_difference_minutes: int
    ntp_port: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanNetInterfaceConfig:
    """One Ethernet interface entry from ``NET_DVR_NETCFG_V30``."""
    ip_address: str
    subnet_mask: str
    net_interface: int
    port: int
    mtu: int
    mac_address: str

@_constants.dataclass(frozen=True)
class EzvizLanNetConfigV30:
    """Known non-secret fields from a traced ``NET_DVR_NETCFG_V30`` response."""
    declared_size: int
    ethernet: tuple[EzvizLanNetInterfaceConfig, ...]
    manage_host_ip: str
    manage_host_port: int
    ip_server_ip: str
    multicast_ip: str
    gateway_ip: str
    nfs_ip: str
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanDvrConfigSummary:
    """Non-secret summary for sensitive traced ``NET_DVR_GetDVRConfig`` buffers."""
    command: int
    structure: str
    declared_size: int
    effective_size: int
    raw_length: int
    trailing_bytes: int
    nonzero_bytes: int

@_constants.dataclass(frozen=True)
class EzvizLanEzvizAccessConfig:
    """Redacted fields from ``NET_DVR_EZVIZ_ACCESS_CFG``.

    The native structure also contains a verification-code byte array. This
    model intentionally exposes only whether that field is populated.
    """
    declared_size: int
    enabled: int
    device_status: int
    allow_redirect: int
    domain_name: str
    verification_code_present: bool
    net_mode: int
    raw_length: int
    trailing_bytes: int

@_constants.dataclass(frozen=True)
class EzvizLanUserConfigV30Entry:
    """One decoded ``NET_DVR_USER_INFO_V30`` entry.

    Password and reserved bytes are hidden from ``repr(...)`` because this
    structure can contain real device credentials.
    """
    index: int
    username: str
    password: str = _constants.field(repr=False)
    password_bytes: bytes = _constants.field(repr=False)
    local_rights: tuple[int, ...]
    remote_rights: tuple[int, ...]
    net_preview_rights: tuple[int, ...]
    local_playback_rights: tuple[int, ...]
    net_playback_rights: tuple[int, ...]
    local_record_rights: tuple[int, ...]
    net_record_rights: tuple[int, ...]
    local_ptz_rights: tuple[int, ...]
    net_ptz_rights: tuple[int, ...]
    local_backup_rights: tuple[int, ...]
    user_ipv4: str
    user_ipv6: str
    mac_address: str
    priority: int
    reserved: bytes = _constants.field(repr=False)

    @property
    def is_active(self) -> bool:
        """Return whether the entry carries any configured user data."""
        return bool(self.username or self.password_bytes or self.priority or self.user_ipv4 or self.user_ipv6 or self.mac_address or any(self.local_rights) or any(self.remote_rights) or any(self.net_preview_rights) or any(self.local_playback_rights) or any(self.net_playback_rights) or any(self.local_record_rights) or any(self.net_record_rights) or any(self.local_ptz_rights) or any(self.net_ptz_rights) or any(self.local_backup_rights))

@_constants.dataclass(frozen=True)
class EzvizLanUserConfigV30:
    """Decoded ``NET_DVR_USER_V30`` user table."""
    declared_size: int
    users: tuple[EzvizLanUserConfigV30Entry, ...]
    raw_length: int
    trailing_bytes: int

    @property
    def active_users(self) -> tuple[_owner.EzvizLanUserConfigV30Entry, ...]:
        """Return configured entries, leaving empty user slots out."""
        return tuple(user for user in self.users if user.is_active)

@_constants.dataclass(frozen=True)
class EzvizLanDeviceConfigV40:
    """Known fields from a traced ``NET_DVR_DEVICECFG_V40`` response."""
    declared_size: int
    device_name: str
    dvr_id: int
    recycle_record: int
    serial_number: str
    software_version: int
    software_build_date: int
    dsp_software_version: int
    dsp_software_build_date: int
    panel_version: int
    hardware_version: int
    alarm_in_port_count: int
    alarm_out_port_count: int
    rs232_count: int
    rs485_count: int
    network_port_count: int
    disk_control_count: int
    disk_count: int
    dvr_type: int
    channel_count: int
    start_channel: int
    audio_count: int
    ip_channel_count: int
    device_type: int
    device_type_name: str
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanRecordDayConfig:
    """One all-day entry from ``NET_DVR_RECORD_V30``."""
    day_index: int
    all_day_record: int
    record_type: int

@_constants.dataclass(frozen=True)
class EzvizLanRecordScheduleSegment:
    """One timed schedule segment from ``NET_DVR_RECORD_V30``."""
    day_index: int
    segment_index: int
    start_hour: int
    start_minute: int
    stop_hour: int
    stop_minute: int
    record_type: int

@_constants.dataclass(frozen=True)
class EzvizLanRecordConfigV30:
    """Known fields from a traced ``NET_DVR_RECORD_V30`` response."""
    declared_size: int
    record_enabled: int
    all_day: tuple[EzvizLanRecordDayConfig, ...]
    schedule: tuple[tuple[EzvizLanRecordScheduleSegment, ...], ...]
    record_time: int
    pre_record_time: int
    recorder_duration: int
    redundancy_record: int
    audio_record: int
    stream_type: int
    passback_record: int
    lock_duration: int
    record_backup: int
    svc_level: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanCameraParamConfig:
    """Known fields from a ``NET_DVR_CAMERAPARAMCFG`` response."""
    declared_size: int
    brightness: int
    contrast: int
    sharpness: int
    saturation: int
    hue: int
    video_effect_enabled: int
    light_inhibit_level: int
    gray_level: int
    raw: bytes

    @property
    def wdr_enabled(self) -> int | None:
        """Return ``struWdr.byWDREnabled`` when the native buffer includes it."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET)

    @property
    def wdr_level_1(self) -> int | None:
        """Return ``struWdr.byWDRLevel1`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 1)

    @property
    def wdr_level_2(self) -> int | None:
        """Return ``struWdr.byWDRLevel2`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 2)

    @property
    def wdr_contrast_level(self) -> int | None:
        """Return ``struWdr.byWDRContrastLevel`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 3)

    @property
    def day_night_filter_type(self) -> int | None:
        """Return ``struDayNight.byDayNightFilterType`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET)

    @property
    def day_night_schedule_enabled(self) -> int | None:
        """Return ``struDayNight.bySwitchScheduleEnabled`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 1)

    @property
    def day_night_begin_time(self) -> tuple[int, int, int] | None:
        """Return the day/night begin time tuple when present."""
        return _owner._optional_raw_byte_triplet(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 2, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 7, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 8)

    @property
    def day_night_end_time(self) -> tuple[int, int, int] | None:
        """Return the day/night end time tuple when present."""
        return _owner._optional_raw_byte_triplet(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 3, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 9, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 10)

    @property
    def day_to_night_filter_level(self) -> int | None:
        """Return ``struDayNight.byDayToNightFilterLevel`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 4)

    @property
    def night_to_day_filter_level(self) -> int | None:
        """Return ``struDayNight.byNightToDayFilterLevel`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 5)

    @property
    def day_night_filter_time(self) -> int | None:
        """Return ``struDayNight.byDayNightFilterTime`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 6)

    @property
    def day_night_alarm_trigger_state(self) -> int | None:
        """Return ``struDayNight.byAlarmTrigState`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 11)

    @property
    def backlight_mode(self) -> int | None:
        """Return ``struBackLight.byBacklightMode`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET)

    @property
    def backlight_level(self) -> int | None:
        """Return ``struBackLight.byBacklightLevel`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET + 1)

@_constants.dataclass(frozen=True)
class EzvizLanWifiConnectStatus:
    """Known fields from a ``NET_DVR_WIFI_CONNECT_STATUS`` response."""
    declared_size: int
    current_status: int
    error_code: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanAudioInputParam:
    """Known fields from a ``NET_DVR_AUDIO_INPUT_PARAM`` response."""
    audio_input_type: int
    volume: int
    noise_filter_enabled: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanAudioOutputVolume:
    """Known fields from a ``NET_DVR_AUDIOOUT_VOLUME`` response."""
    declared_size: int
    volume: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanCompressionInfoV30:
    """Known fields from one ``NET_DVR_COMPRESSION_INFO_V30`` block."""
    stream_type: int
    resolution: int
    bitrate_type: int
    picture_quality: int
    video_bitrate: int
    video_frame_rate: int
    i_frame_interval: int
    interval_bp_frame: int
    reserved1: int
    video_encoding_type: int
    audio_encoding_type: int
    video_encoding_complexity: int
    svc_enabled: int
    format_type: int
    audio_bitrate: int
    stream_smoothing: int
    audio_sampling_rate: int
    smart_codec: int
    depth_map_enabled: int
    average_video_bitrate: int
    raw: bytes

@_constants.dataclass(frozen=True)
class EzvizLanCompressionConfig:
    """Known fields from a ``NET_DVR_COMPRESSIONCFG_V30`` response."""
    declared_size: int
    stream_type: int
    resolution: int
    bitrate_type: int
    picture_quality: int
    video_bitrate: int
    video_frame_rate: int
    i_frame_interval: int
    video_encoding_type: int
    raw: bytes

    @property
    def normal_record(self) -> _owner.EzvizLanCompressionInfoV30:
        """Return ``struNormHighRecordPara`` when present."""
        info = _owner._hcnetsdk_compression_info_v30(self.raw, _owner.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET)
        if info is None:
            raise _owner.PyEzvizError('EZVIZ LAN compression normal block is missing')
        return info

    @property
    def reserved(self) -> _owner.EzvizLanCompressionInfoV30 | None:
        """Return ``struRes`` when present."""
        return _owner._hcnetsdk_compression_info_v30(self.raw, _owner.HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET)

    @property
    def event_record(self) -> _owner.EzvizLanCompressionInfoV30 | None:
        """Return ``struEventRecordPara`` when present."""
        return _owner._hcnetsdk_compression_info_v30(self.raw, _owner.HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET)

    @property
    def network(self) -> _owner.EzvizLanCompressionInfoV30 | None:
        """Return ``struNetPara`` when present."""
        return _owner._hcnetsdk_compression_info_v30(self.raw, _owner.HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET)

@_constants.dataclass(frozen=True)
class EzvizLanPictureConfig:
    """Known fields from a ``NET_DVR_PICCFG_V40`` response."""
    declared_size: int
    channel_name: str
    raw: bytes

    @property
    def video_format(self) -> int | None:
        """Return ``dwVideoFormat`` when present."""
        return _owner._optional_raw_u32_be(self.raw, _owner.HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET)

    @property
    def brightness(self) -> int | None:
        """Return ``byBrightness`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET)

    @property
    def contrast(self) -> int | None:
        """Return ``byContrast`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 1)

    @property
    def saturation(self) -> int | None:
        """Return ``bySaturation`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 2)

    @property
    def hue(self) -> int | None:
        """Return ``byHue`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 3)

    @property
    def show_channel_name(self) -> int | None:
        """Return ``dwShowChanName`` when present."""
        return _owner._optional_raw_u32_be(self.raw, _owner.HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET)

    @property
    def channel_name_position(self) -> tuple[int, int] | None:
        """Return ``wShowNameTopLeftX`` and ``wShowNameTopLeftY`` when present."""
        return _owner._optional_raw_u16_be_pair(self.raw, _owner.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET, _owner.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET + 2)

    @property
    def hide_enabled(self) -> int | None:
        """Return ``dwEnableHide`` when present."""
        return _owner._optional_raw_u32_be(self.raw, _owner.HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET)

    @property
    def show_osd(self) -> int | None:
        """Return ``dwShowOsd`` when present."""
        return _owner._optional_raw_u32_be(self.raw, _owner.HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET)

    @property
    def osd_position(self) -> tuple[int, int] | None:
        """Return ``wOSDTopLeftX`` and ``wOSDTopLeftY`` when present."""
        return _owner._optional_raw_u16_be_pair(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET, _owner.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET + 2)

    @property
    def osd_type(self) -> int | None:
        """Return ``byOSDType`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET)

    @property
    def display_week(self) -> int | None:
        """Return ``byDispWeek`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 1)

    @property
    def osd_attribute(self) -> int | None:
        """Return ``byOSDAttrib`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 2)

    @property
    def hour_osd_type(self) -> int | None:
        """Return ``byHourOSDType`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 3)

    @property
    def font_size(self) -> int | None:
        """Return ``byFontSize`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 4)

    @property
    def osd_color_type(self) -> int | None:
        """Return ``byOSDColorType`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 5)

    @property
    def alignment(self) -> int | None:
        """Return ``byAlignment`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 6)

    @property
    def osd_millisecond_enabled(self) -> int | None:
        """Return ``byOSDMilliSecondEnable`` when present."""
        return _owner._optional_raw_byte(self.raw, _owner.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 7)

@_constants.dataclass(frozen=True)
class HcNetSdkDvrConfigRequest:
    """Native ``NET_DVR_GetDVRConfig`` / ``NET_DVR_SetDVRConfig`` shape."""
    login_id: int
    command: int
    channel: int
    structure: str
    api: str
    structure_size: int | None = None
    field_updates: _owner.Mapping[str, _owner.Any] | None = None
    read_before_write: bool = False

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK DVR config requires a successful login id')
        if self.command < 0:
            raise _owner.PyEzvizError('HCNetSDK DVR config command must be non-negative')
        if self.channel < -1:
            raise _owner.PyEzvizError('HCNetSDK DVR config channel must be -1 or greater')
        if not self.structure or any(char.isspace() for char in self.structure):
            raise _owner.PyEzvizError('HCNetSDK DVR config structure name is invalid')
        if self.structure_size is not None and self.structure_size < 0:
            raise _owner.PyEzvizError('HCNetSDK DVR config structure size is invalid')
        if self.api not in {_owner.HCNETSDK_GET_DVR_CONFIG, _owner.HCNETSDK_SET_DVR_CONFIG}:
            raise _owner.PyEzvizError('HCNetSDK DVR config API is unsupported')
        structure_size: int | str = self.structure_size if self.structure_size is not None else f'sizeof({self.structure})'
        hint: dict[str, _owner.Any] = {'api': self.api, 'lUserID': self.login_id, 'dwCommand': int(self.command), 'lChannel': self.channel, 'structure': self.structure}
        if self.api == _owner.HCNETSDK_GET_DVR_CONFIG:
            hint.update({'lpOutBuffer': f'<{self.structure}>', 'dwOutBufferSize': structure_size, 'lpBytesReturned': '<bytes-returned>'})
            return hint
        hint.update({'lpInBuffer': f'<{self.structure}>', 'dwInBufferSize': structure_size, 'fieldUpdates': dict(self.field_updates or {}), 'readBeforeWrite': self.read_before_write})
        return hint

@_constants.dataclass(frozen=True)
class HcNetSdkFormatDiskRequest:
    """Native ``NET_DVR_FormatDisk`` call shape."""
    login_id: int
    disk_number: int
    api: str = _constants.HCNETSDK_FORMAT_DISK

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the native argument names for starting local SD formatting."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK format requires a successful login id')
        if self.disk_number < 0:
            raise _owner.PyEzvizError('HCNetSDK format disk number must be non-negative')
        if self.api != _owner.HCNETSDK_FORMAT_DISK:
            raise _owner.PyEzvizError('HCNetSDK format API is unsupported')
        return {'api': self.api, 'lUserID': self.login_id, 'lDiskNumber': self.disk_number, 'failureHandle': -1}

@_constants.dataclass(frozen=True)
class HcNetSdkFormatProgressRequest:
    """Native ``NET_DVR_GetFormatProgress`` call shape."""
    format_handle: int
    api: str = _constants.HCNETSDK_GET_FORMAT_PROGRESS

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the native argument names for polling SD format progress."""
        if self.format_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK format handle must be non-negative')
        if self.api != _owner.HCNETSDK_GET_FORMAT_PROGRESS:
            raise _owner.PyEzvizError('HCNetSDK format-progress API is unsupported')
        return {'api': self.api, 'lFormatHandle': self.format_handle, 'pCurrentFormatDisk': '<IntByReference>', 'pCurrentDiskPos': '<IntByReference>', 'pFormatStatic': '<IntByReference>'}

@_constants.dataclass(frozen=True)
class HcNetSdkCloseFormatHandleRequest:
    """Native ``NET_DVR_CloseFormatHandle`` call shape."""
    format_handle: int
    api: str = _constants.HCNETSDK_CLOSE_FORMAT_HANDLE

    def to_native_args_hint(self) -> dict[str, _owner.Any]:
        """Return the native argument names for closing an SD format handle."""
        if self.format_handle < 0:
            raise _owner.PyEzvizError('HCNetSDK format handle must be non-negative')
        if self.api != _owner.HCNETSDK_CLOSE_FORMAT_HANDLE:
            raise _owner.PyEzvizError('HCNetSDK close-format API is unsupported')
        return {'api': self.api, 'lFormatHandle': self.format_handle}

@_constants.dataclass(frozen=True)
class HcNetSdkSetupAlarmParam:
    """Native ``NET_DVR_SETUPALARM_PARAM`` shape used by alarm V41 setup."""
    level: int = 0
    alarm_info_type: int = 0
    ret_alarm_type_v40: int = 0
    ret_dev_info_version: int = 0
    ret_vqd_alarm_type: int = 0
    face_alarm_detection: int = 0
    support: int = 0
    broken_net_http: int = 0
    task_no: int = 0

    def to_native_dict(self) -> dict[str, _owner.Any]:
        """Return the JNA field names and values for V41 alarm setup."""
        return {'structure': 'NET_DVR_SETUPALARM_PARAM', 'fieldOrder': _owner.HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER, 'dwSize': 'sizeof(NET_DVR_SETUPALARM_PARAM)', 'byLevel': _owner._byte_value('alarm level', self.level), 'byAlarmInfoType': _owner._byte_value('alarm info type', self.alarm_info_type), 'byRetAlarmTypeV40': _owner._byte_value('alarm V40 return type', self.ret_alarm_type_v40), 'byRetDevInfoVersion': _owner._byte_value('alarm device-info version', self.ret_dev_info_version), 'byRetVQDAlarmType': _owner._byte_value('alarm VQD return type', self.ret_vqd_alarm_type), 'byFaceAlarmDetection': _owner._byte_value('face alarm detection', self.face_alarm_detection), 'bySupport': _owner._byte_value('alarm support', self.support), 'byBrokenNetHttp': _owner._byte_value('broken-net HTTP', self.broken_net_http), 'wTaskNo': _owner._word_value('alarm task number', self.task_no), 'byRes1Length': 6}

@_constants.dataclass(frozen=True)
class EzvizLanSdFormatProgress:
    """RN-style result mapping for ``NET_DVR_GetFormatProgress`` values."""
    code: int
    current_disk: int
    progress: int | None
    status: int
    done: bool

@_constants.dataclass(frozen=True)
class HcNetSdkDeviceAbilityRequest:
    """Native ``NET_DVR_GetDeviceAbility`` call shape."""
    login_id: int
    ability_type: int
    in_buffer: str | bytes | None = None
    output_buffer_size: int = _constants.HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
    retry_output_buffer_size: int | None = _constants.HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
    api: str = _constants.HCNETSDK_GET_DEVICE_ABILITY

    @property
    def in_buffer_bytes(self) -> bytes:
        """Return bytes assigned to native ``pInBuf``."""
        if self.in_buffer is None:
            return b''
        return _owner._device_ability_bytes('input buffer', self.in_buffer)

    def to_native_args_hint(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise _owner.PyEzvizError('HCNetSDK device ability requires a successful login id')
        if self.ability_type < 0:
            raise _owner.PyEzvizError('HCNetSDK device ability type must be non-negative')
        if self.output_buffer_size < 0:
            raise _owner.PyEzvizError('HCNetSDK device ability output buffer size must be non-negative')
        if self.retry_output_buffer_size is not None and self.retry_output_buffer_size < self.output_buffer_size:
            raise _owner.PyEzvizError('HCNetSDK device ability retry buffer must be at least output size')
        in_buffer = self.in_buffer_bytes
        return {'api': self.api, 'lUserID': self.login_id, 'dwAbilityType': self.ability_type, 'pInBuf': in_buffer if include_buffers and in_buffer else '<input-buffer>' if in_buffer else None, 'dwInLength': len(in_buffer), 'pOutBuf': '<output-buffer>', 'dwOutLength': self.output_buffer_size, 'retryOnError': _owner.HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR if self.retry_output_buffer_size is not None else None, 'retryDwOutLength': self.retry_output_buffer_size}

@_constants.dataclass(frozen=True)
class EzvizLanPtzAbility:
    """Parsed PTZ ability values returned by local HCNetSDK ability XML."""
    control_types: str | None = None
    park_action_types: str | None = None
    schedule_task_types: str | None = None
    privacy_mask_enable: bool | None = None
    mirror_range: str | None = None

    @property
    def control_type_options(self) -> tuple[str, ...]:
        """Return comma-separated PTZ control options as a tuple."""
        return _owner._ability_option_tuple(self.control_types)

@_constants.dataclass(frozen=True)
class EzvizLanAccessProtocolAbility:
    """Parsed safe fields from ``AccessProtocolAbility`` XML."""
    channel_no: str | None = None
    enable_options: str | None = None
    device_status_options: str | None = None
    allow_redirect_options: str | None = None
    domain_length_min: int = 0
    domain_length_max: int = 0
    has_ezviz_param: bool = False

    @property
    def success(self) -> bool:
        """Return whether the EZVIZ parameter section was present."""
        return self.has_ezviz_param

    @property
    def enable_option_list(self) -> tuple[str, ...]:
        """Return comma-separated enable options as a tuple."""
        return _owner._ability_option_tuple(self.enable_options)

    @property
    def device_status_option_list(self) -> tuple[str, ...]:
        """Return comma-separated device-status options as a tuple."""
        return _owner._ability_option_tuple(self.device_status_options)

    @property
    def allow_redirect_option_list(self) -> tuple[str, ...]:
        """Return comma-separated redirect options as a tuple."""
        return _owner._ability_option_tuple(self.allow_redirect_options)

@_constants.dataclass(frozen=True)
class EzvizLanVideoPicAbility:
    """Parsed safe fields from ``VideoPicAbility`` XML."""
    channel_no: str | None = None
    channel_name_enabled: bool = False
    week_enabled: bool = False
    osd_type_options: str | None = None
    osd_attribute_options: str | None = None
    osd_hour_type_options: str | None = None
    motion_region_type_options: str | None = None
    motion_grid_row_granularity: int = 0
    motion_grid_column_granularity: int = 0

    @property
    def osd_type_option_list(self) -> tuple[str, ...]:
        """Return comma-separated OSD type options as a tuple."""
        return _owner._ability_option_tuple(self.osd_type_options)

    @property
    def osd_attribute_option_list(self) -> tuple[str, ...]:
        """Return comma-separated OSD attribute options as a tuple."""
        return _owner._ability_option_tuple(self.osd_attribute_options)

    @property
    def osd_hour_type_option_list(self) -> tuple[str, ...]:
        """Return comma-separated OSD hour-type options as a tuple."""
        return _owner._ability_option_tuple(self.osd_hour_type_options)

    @property
    def motion_region_type_option_list(self) -> tuple[str, ...]:
        """Return comma-separated motion region-type options as a tuple."""
        return _owner._ability_option_tuple(self.motion_region_type_options)

@_constants.dataclass(frozen=True)
class EzvizLanIpcFrontParameterRange:
    """One integer range advertised by ``CAMERAPARA`` ability XML."""
    minimum: int = 0
    maximum: int = 0
    default: int | None = None

    @property
    def supported(self) -> bool:
        """Return whether the range has a non-empty max/min span."""
        return self.maximum > self.minimum

@_constants.dataclass(frozen=True)
class EzvizLanIpcFrontParameterAbility:
    """Parsed safe image/front-parameter ranges from ``CAMERAPARA`` XML."""
    has_camera_para: bool = False
    power_line_frequency_mode_range: str | None = None
    white_balance_mode_range: str | None = None
    exposure_mode_range: str | None = None
    exposure_set_range: str | None = None
    exposure_user_set: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    gain_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    brightness_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    contrast_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    sharpness_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    saturation_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    day_night_filter_type_range: str | None = None
    switch_schedule_enabled_range: str | None = None
    day_to_night_filter_level_range: str | None = None
    night_to_day_filter_level_range: str | None = None
    day_night_filter_time: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    backlight_mode_range: str | None = None
    mirror_range: str | None = None
    digital_noise_reduction_enable_range: str | None = None
    digital_noise_reduction_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    digital_noise_spectral_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)
    digital_noise_temporal_level: EzvizLanIpcFrontParameterRange = _constants.field(default_factory=EzvizLanIpcFrontParameterRange)

    @property
    def success(self) -> bool:
        """Return whether a camera-parameter ability root was parsed."""
        return self.has_camera_para

    @property
    def mirror_options(self) -> tuple[str, ...]:
        """Return comma-separated mirror options as a tuple."""
        return _owner._ability_option_tuple(self.mirror_range)

    @property
    def backlight_mode_options(self) -> tuple[str, ...]:
        """Return comma-separated backlight mode options as a tuple."""
        return _owner._ability_option_tuple(self.backlight_mode_range)

    @property
    def day_night_filter_type_options(self) -> tuple[str, ...]:
        """Return comma-separated day/night filter type options as a tuple."""
        return _owner._ability_option_tuple(self.day_night_filter_type_range)

@_constants.dataclass(frozen=True)
class EzvizLanAudioVideoCompressStream:
    """One video stream profile from ``AudioVideoCompressInfo`` XML."""
    index: int | None = None
    video_encode_type_range: str | None = None
    video_encode_efficiency_range: str | None = None
    interval_bp_frame_range: str | None = None
    e_frame: int = 0
    resolution_indexes: tuple[int, ...] = ()
    frame_rates: tuple[int, ...] = ()
    bitrate_min: int = 0
    bitrate_max: int = 0
    resolutions: tuple[_owner.EzvizLanVideoResolution, ...] = _constants.field(default=(), kw_only=True)
    bitrate_codes: tuple[int, ...] = _constants.field(default=(), kw_only=True)

    @property
    def resolution_count(self) -> int:
        """Return the number of advertised video resolutions."""
        return len(self.resolution_indexes)

@_constants.dataclass(frozen=True)
class EzvizLanAudioVideoCompressVideoChannel:
    """One video channel from ``AudioVideoCompressInfo`` XML."""
    channel_number: int = 0
    main_stream: EzvizLanAudioVideoCompressStream | None = None
    sub_streams: tuple[EzvizLanAudioVideoCompressStream, ...] = ()

    @property
    def supports_sub_stream(self) -> bool:
        """Return whether at least one sub-stream profile was advertised."""
        return bool(self.sub_streams)

@_constants.dataclass(frozen=True)
class EzvizLanAudioVideoCompressAudioChannel:
    """One audio channel from ``AudioVideoCompressInfo`` XML."""
    channel_number: int = 0
    main_audio_encode_type_range: str | None = None
    sub_audio_encode_type_range: str | None = None
    audio_in_type_range: str | None = None
    audio_in_volume_min: int = 0
    audio_in_volume_max: int = 0

@_constants.dataclass(frozen=True)
class EzvizLanAudioVideoCompressVoiceTalkChannel:
    """One voice-talk channel from ``AudioVideoCompressInfo`` XML."""
    channel_number: int = 0
    voice_talk_encode_type_range: str | None = None
    voice_talk_in_type_range: str | None = None

@_constants.dataclass(frozen=True)
class EzvizLanAudioVideoCompressInfo:
    """Parsed safe fields from ``AudioVideoCompressInfo`` XML."""
    video_channels: tuple[EzvizLanAudioVideoCompressVideoChannel, ...] = ()
    audio_channels: tuple[EzvizLanAudioVideoCompressAudioChannel, ...] = ()
    voice_talk_channels: tuple[EzvizLanAudioVideoCompressVoiceTalkChannel, ...] = ()
    has_video_compress_info: bool = False
    has_audio_compress_info: bool = False

    @property
    def success(self) -> bool:
        """Return whether any advertised audio or video ability section was parsed."""
        return self.has_video_compress_info or self.has_audio_compress_info

    @property
    def supports_sub_stream(self) -> bool:
        """Return whether any video channel advertises sub-stream support."""
        return any(channel.supports_sub_stream for channel in self.video_channels)

@_constants.dataclass(frozen=True)
class EzvizLanDeviceSoftHardwareAbility:
    """Parsed software/hardware ability values used by ``DeviceAbilityHelper``."""
    max_preview_num: int = 0
    ptz_support: int = 0
    support_timing: bool = False
    sd_num: int = 0
    hard_disk_num: int = 0
    has_software_capability: bool = False
    has_hardware_capability: bool = False

    @property
    def success(self) -> bool:
        """Return whether both capability sections were present."""
        return self.has_software_capability and self.has_hardware_capability

    @property
    def ptz_supported(self) -> bool:
        """Return the app's PTZ support boolean interpretation."""
        return self.ptz_support == 1

@_constants.dataclass(frozen=True)
class EzvizLanPlaybackConvertAbility:
    """Parsed playback conversion ability values used by the Android app."""
    resolutions: tuple[_owner.EzvizLanPlaybackConvertResolution, ...] = ()

    @property
    def success(self) -> bool:
        """Return whether any conversion resolution was parsed."""
        return bool(self.resolutions)

@_constants.dataclass(frozen=True)
class EzvizLanLiveViewParams:
    """Relevant EZVIZ player init fields for ``PlayerDataType.LAN`` live view."""
    serial: str
    channel_number: int
    channel_serial: str | None = None
    channel_index: str | None = None
    channel_count: int | None = None
    stream_source: int = _constants.EZVIZ_STREAM_SOURCE_LIVE_MINE
    stream_type: int = 1
    video_level: int = _constants.EZVIZ_LAN_MAIN_VIDEO_LEVEL
    stream_inhibit: int = _constants.EZVIZ_STREAM_INHIBIT_LAN
    stream_timeout_ms: int = _constants.EZVIZ_STREAM_TIMEOUT_MS
    preplay_sps_type: int = _constants.EZVIZ_PREPLAY_SPS_TYPE
    device_ip: str | None = None
    device_local_ip: str | None = None
    device_cmd_port: int | None = None
    device_cmd_local_port: int | None = None
    device_stream_local_port: int | None = None
    device_stream_port: int | None = None
    netsdk_login_id: int = -1
    netsdk_channel_number: int | None = None

    def to_init_param_dict(self) -> dict[str, int | str]:
        """Return the native ``InitParam`` field names observed in the APK."""
        data: dict[str, int | str] = {'szDevSerial': self.serial, 'szChnlSerial': self.channel_serial or self.serial, 'szChnlIndex': self.channel_index or '', 'szDevIP': self.device_ip or '', 'szDevLocalIP': self.device_local_ip or '', 'iDevCmdPort': self.device_cmd_port or 0, 'iDevCmdLocalPort': self.device_cmd_local_port or 0, 'iDevStreamPort': self.device_stream_port or 0, 'iDevStreamLocalPort': self.device_stream_local_port or 0, 'iChannelCount': self.channel_count or 0, 'iP2PSPS': self.preplay_sps_type, 'iStreamInhibit': self.stream_inhibit, 'iStreamSource': self.stream_source, 'iStreamType': self.stream_type, 'iStreamTimeOut': self.stream_timeout_ms, 'iVideoLevel': _owner.ezviz_native_video_level(self.video_level), 'iChannelNumber': self.channel_number, 'iNetSDKUserId': self.netsdk_login_id}
        if self.netsdk_channel_number is not None:
            data['iNetSDKChannelNumber'] = self.netsdk_channel_number
        return data

    def to_real_play_request(self, *, link_mode: int=0, blocked: bool=False, multicast_ip: str='') -> _owner.HcNetSdkRealPlayRequest:
        """Return the direct HCNetSDK ``RealPlay_V30`` request shape."""
        return _owner.hcnetsdk_real_play_request(self.netsdk_login_id, channel_number=self.netsdk_channel_number or self.channel_number, link_mode=link_mode, blocked=blocked, multicast_ip=multicast_ip)

@_constants.dataclass(frozen=True)
class HcNetSdkTcpShapeLogRecord:
    """One secret-safe HCNetSDK command-port shape log line."""
    direction: str
    fd: int
    host: str
    port: int
    shape: _owner.HcNetSdkTcpPayloadShape
    captured_length: int | None = None
    fingerprint: str | None = None
    length_candidates: _owner.Mapping[str, int] | None = None

@_constants.dataclass(frozen=True)
class SadpDeviceNetParam:
    """Android ``SADP_DEV_NET_PARAM`` field updates used by the RN module."""
    ipv4_address: str
    ipv4_subnet_mask: str
    ipv4_gateway: str
    dhcp_enabled: int | bool
    http_port: int
    command_port: int
    ipv6_address: str = ''
    ipv6_gateway: str = ''
    ipv6_mask_len: int = 0

    def to_native_dict(self, *, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the Android SADP_DEV_NET_PARAM field values."""
        ipv4_address = _owner._sadp_string_bytes('IPv4 address', self.ipv4_address, 16)
        ipv4_subnet_mask = _owner._sadp_string_bytes('IPv4 subnet mask', self.ipv4_subnet_mask, 16)
        ipv4_gateway = _owner._sadp_string_bytes('IPv4 gateway', self.ipv4_gateway, 16)
        ipv6_address = _owner._sadp_string_bytes('IPv6 address', self.ipv6_address, 128, allow_empty=True)
        ipv6_gateway = _owner._sadp_string_bytes('IPv6 gateway', self.ipv6_gateway, 128, allow_empty=True)
        return {'structure': 'SADP_DEV_NET_PARAM', 'androidFields': _owner.SADP_DEV_NET_PARAM_ANDROID_FIELDS, 'jnaFieldOrder': _owner.SADP_DEV_NET_PARAM_JNA_FIELD_ORDER, 'szIPv4Address': ipv4_address if include_buffers else self.ipv4_address, 'szIPv4SubnetMask': ipv4_subnet_mask if include_buffers else self.ipv4_subnet_mask, 'szIPv4Gateway': ipv4_gateway if include_buffers else self.ipv4_gateway, 'szIPv6Address': ipv6_address if include_buffers else self.ipv6_address, 'szIPv6Gateway': ipv6_gateway if include_buffers else self.ipv6_gateway, 'byDhcpEnabled': _owner._byte_value('SADP DHCP enabled', int(self.dhcp_enabled)), 'byIPv6MaskLen': _owner._byte_value('SADP IPv6 mask length', self.ipv6_mask_len), 'wHttpPort': _owner._port_value('SADP HTTP port', self.http_port), 'wPort': _owner._port_value('SADP command port', self.command_port)}

@_constants.dataclass(frozen=True)
class SadpModifyDeviceNetParamRequest:
    """Android ``SADP_ModifyDeviceNetParam`` call shape."""
    mac: str
    password: str
    net_param: SadpDeviceNetParam
    api: str = _constants.SADP_MODIFY_DEVICE_NET_PARAM

    def to_native_args_hint(self, *, include_password: bool=False, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise _owner.PyEzvizError('SADP MAC address cannot be empty')
        if not self.password:
            raise _owner.PyEzvizError('SADP network password cannot be empty')
        return {'api': self.api, 'mac': mac, 'password': self.password if include_password else '<password>', 'passwordLength': len(self.password.encode('utf-8')), 'netParam': self.net_param.to_native_dict(include_buffers=include_buffers), 'lastErrorApi': _owner.SADP_GET_LAST_ERROR}

@_constants.dataclass(frozen=True)
class SadpDeviceRetNetParam:
    """Native ``SADP_DEV_RET_NET_PARAM`` output-buffer shape."""
    retry_modify_time: int | None = None
    surplus_lock_time: int | None = None

    def to_native_dict(self) -> dict[str, _owner.Any]:
        """Return the JNA field names for V40 network-edit failure detail."""
        result: dict[str, _owner.Any] = {'structure': 'SADP_DEV_RET_NET_PARAM', 'fieldOrder': _owner.SADP_DEV_RET_NET_PARAM_FIELD_ORDER, 'dwSize': 'sizeof(SADP_DEV_RET_NET_PARAM)', 'byResLength': 126}
        if self.retry_modify_time is not None:
            result['byRetryModifyTime'] = _owner._byte_value('SADP retry modify time', self.retry_modify_time)
        if self.surplus_lock_time is not None:
            result['bySurplusLockTime'] = _owner._byte_value('SADP surplus lock time', self.surplus_lock_time)
        return result

@_constants.dataclass(frozen=True)
class SadpModifyDeviceNetParamV40Request:
    """Android ``SADP_ModifyDeviceNetParam_V40`` call shape."""
    mac: str
    password: str
    net_param: SadpDeviceNetParam
    ret_net_param: SadpDeviceRetNetParam | None = None
    api: str = _constants.SADP_MODIFY_DEVICE_NET_PARAM_V40

    def to_native_args_hint(self, *, include_password: bool=False, include_buffers: bool=False) -> dict[str, _owner.Any]:
        """Return the V40 native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise _owner.PyEzvizError('SADP MAC address cannot be empty')
        if not self.password:
            raise _owner.PyEzvizError('SADP network password cannot be empty')
        if self.api != _owner.SADP_MODIFY_DEVICE_NET_PARAM_V40:
            raise _owner.PyEzvizError('SADP V40 network-param API is unsupported')
        ret_net_param = self.ret_net_param or _owner.SadpDeviceRetNetParam()
        return {'api': self.api, 'mac': mac, 'password': self.password if include_password else '<password>', 'passwordLength': len(self.password.encode('utf-8')), 'netParam': self.net_param.to_native_dict(include_buffers=include_buffers), 'lpRetNetParam': ret_net_param.to_native_dict(), 'dwOutBuffSize': _owner.SADP_DEV_RET_NET_PARAM_BUFFER_SIZE, 'lastErrorApi': _owner.SADP_GET_LAST_ERROR}

# Late owner reference preserves legacy model hook and annotation resolution.
import pyezvizapi.streaming.local.hcnetsdk.protocol as _owner
