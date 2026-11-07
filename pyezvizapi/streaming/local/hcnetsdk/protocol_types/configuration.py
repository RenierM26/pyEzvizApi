"""configuration protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET,
    HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET,
    HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET,
    HCNETSDK_CLOSE_FORMAT_HANDLE,
    HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET,
    HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET,
    HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET,
    HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET,
    HCNETSDK_COMPRESSION_INFO_V30_SIZE,
    HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR,
    HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE,
    HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE,
    HCNETSDK_FORMAT_DISK,
    HCNETSDK_GET_DEVICE_ABILITY,
    HCNETSDK_GET_DVR_CONFIG,
    HCNETSDK_GET_FORMAT_PROGRESS,
    HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET,
    HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET,
    HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET,
    HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET,
    HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET,
    HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET,
    HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET,
    HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET,
    HCNETSDK_SET_DVR_CONFIG,
    HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE,
    HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE,
    HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE,
    HCNETSDK_STDXML_INPUT_FIELD_ORDER,
    HCNETSDK_STDXML_OUTPUT_FIELD_ORDER,
    Any,
    HcNetSdkConfiguredMedia,
    Mapping,
    PyEzvizError,
    asdict,
    dataclass,
    field,
    json,
    normalize_hcnetsdk_parameters,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.playback import (
    EzvizLanPlaybackConvertResolution,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.sdk_requests import (
    EzvizLanIpcFrontParameterRange,
)
from pyezvizapi.streaming.local.hcnetsdk.protocol_types.values import (
    _ability_option_tuple,
    _device_ability_bytes,
    _optional_raw_byte,
    _optional_raw_byte_triplet,
    _optional_raw_u16_be_pair,
    _optional_raw_u32_be,
    _stdxml_bytes,
)


@dataclass(frozen=True)
class HcNetSdkStdXmlConfigRequest:
    """Python model of ``NET_DVR_STDXMLConfig`` request/output allocation.

    EZVIZ's Android helpers put the full ISAPI method/path/body text in
    ``lpRequestUrl`` and leave ``lpInBuffer`` empty. This model keeps that
    native boundary explicit while avoiding a hard dependency on host-native
    bindings.
    """

    request: str | bytes
    in_buffer: str | bytes = b""
    recv_timeout: int = 0
    force_encrypt: int = 0
    num_of_multi_part: int = 0
    output_buffer_size: int = HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
    status_buffer_size: int = HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE

    def __post_init__(self) -> None:
        for name, value in (
            ("recv_timeout", self.recv_timeout),
            ("output_buffer_size", self.output_buffer_size),
            ("status_buffer_size", self.status_buffer_size),
        ):
            if value < 0:
                raise PyEzvizError(f"HCNetSDK STDXML {name} must be non-negative")
        for name, value in (
            ("force_encrypt", self.force_encrypt),
            ("num_of_multi_part", self.num_of_multi_part),
        ):
            if not 0 <= value <= 0xFF:
                raise PyEzvizError(f"HCNetSDK STDXML {name} must fit in one byte")

    @property
    def request_bytes(self) -> bytes:
        """Return bytes assigned to native ``lpRequestUrl``."""
        return _stdxml_bytes("request", self.request)

    @property
    def in_buffer_bytes(self) -> bytes:
        """Return bytes assigned to native ``lpInBuffer``."""
        return _stdxml_bytes("input buffer", self.in_buffer)

    @property
    def android_helper_compatible(self) -> bool:
        """Return whether this request fits EZVIZ's 1024-byte Java buffer."""
        return (
            len(self.request_bytes) <= HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE
            and not self.in_buffer_bytes
        )

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the JNA field shape used by EZVIZ's STDXML helpers.

        By default the byte buffers are represented by placeholders so callers
        can log the shape without exposing request bodies. Pass
        ``include_buffers=True`` when handing data to a local native bridge.
        """
        request_bytes = self.request_bytes
        in_buffer = self.in_buffer_bytes
        return {
            "api": "NET_DVR_STDXMLConfig",
            "input": {
                "field_order": HCNETSDK_STDXML_INPUT_FIELD_ORDER,
                "dwSize": "sizeof(NET_DVR_XML_CONFIG_INPUT)",
                "lpRequestUrl": (request_bytes if include_buffers else "<request-url-buffer>"),
                "dwRequestUrlLen": len(request_bytes),
                "lpInBuffer": (
                    in_buffer
                    if include_buffers and in_buffer
                    else ("<input-buffer>" if in_buffer else None)
                ),
                "dwInBufferSize": len(in_buffer),
                "dwRecvTimeOut": self.recv_timeout,
                "byForceEncrpt": self.force_encrypt,
                "byNumOfMultiPart": self.num_of_multi_part,
                "byResLength": 30,
            },
            "output": {
                "field_order": HCNETSDK_STDXML_OUTPUT_FIELD_ORDER,
                "dwSize": "sizeof(NET_DVR_XML_CONFIG_OUTPUT)",
                "lpOutBuffer": "<output-buffer>",
                "dwOutBufferSize": self.output_buffer_size,
                "dwReturnedXMLSize": "<returned-xml-size>",
                "lpStatusBuffer": "<status-buffer>",
                "dwStatusSize": self.status_buffer_size,
                "byResLength": 32,
            },
            "android_helper_compatible": self.android_helper_compatible,
        }


def hcnetsdk_stdxml_response_json(
    response: Mapping[str, Any] | str | bytes,
) -> dict[str, Any]:
    """Parse a JSON response returned by EZVIZ local STDXML helpers."""
    if isinstance(response, Mapping):
        return dict(response)
    try:
        if isinstance(response, bytes):
            response = response.split(b"\x00", 1)[0]
            text = response.decode("utf-8")
        else:
            text = response.split("\x00", 1)[0]
        parsed = json.loads(text)
    except (UnicodeDecodeError, ValueError) as err:
        raise PyEzvizError("Invalid HCNetSDK STDXML response JSON") from err
    if not isinstance(parsed, dict):
        raise PyEzvizError("HCNetSDK STDXML response JSON must be an object")
    return parsed


@dataclass(frozen=True)
class HcNetSdkStdXmlConfigResponse:
    """Result returned by a native ``NET_DVR_STDXMLConfig`` call."""

    succeeded: bool
    output: bytes
    status: bytes = b""
    returned_xml_size: int = 0
    last_error: int | None = None

    @property
    def text(self) -> str:
        """Decode the output buffer as UTF-8."""
        return self.output.decode("utf-8")

    @property
    def status_text(self) -> str:
        """Decode the status buffer as UTF-8."""
        return self.status.decode("utf-8")

    def json(self) -> dict[str, Any]:
        """Parse the output buffer as a JSON object."""
        return hcnetsdk_stdxml_response_json(self.output)


@dataclass(frozen=True)
class EzvizLanServicesSwitchState:
    """Parsed ``servicesSwitch`` values returned by EZVIZ local ISAPI."""

    hiksdk: int | None = None
    web: int | None = None
    rtsp: int | None = None
    raw: Mapping[str, Any] | None = None

    @property
    def hiksdk_enabled(self) -> bool | None:
        """Return the local HCNetSDK switch as a boolean when present."""
        return None if self.hiksdk is None else bool(self.hiksdk)

    @property
    def web_enabled(self) -> bool | None:
        """Return the local web switch as a boolean when present."""
        return None if self.web is None else bool(self.web)


@dataclass(frozen=True)
class EzvizLanWifiApInfo:
    """One Wi-Fi access point entry returned by ``NET_DVR_AP_INFO_LIST``."""

    ssid: str
    security: int
    channel: int
    signal_strength: int
    extra: int


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLanHdConfig:
    """Known fields from a traced ``NET_DVR_HDCFG`` response."""

    declared_size: int
    raw: bytes
    disk_count: int = 0
    disks: tuple[EzvizLanHdDiskConfig, ...] = ()


@dataclass(frozen=True)
class EzvizLanNtpConfig:
    """Known fields from a traced ``NET_DVR_NTPPARA`` response."""

    ntp_server: str
    interval_minutes: int
    enabled: int
    time_difference_hours: int
    time_difference_minutes: int
    ntp_port: int
    raw: bytes


@dataclass(frozen=True)
class EzvizLanNetInterfaceConfig:
    """One Ethernet interface entry from ``NET_DVR_NETCFG_V30``."""

    ip_address: str
    subnet_mask: str
    net_interface: int
    port: int
    mtu: int
    mac_address: str


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLanDvrConfigSummary:
    """Non-secret summary for sensitive traced ``NET_DVR_GetDVRConfig`` buffers."""

    command: int
    structure: str
    declared_size: int
    effective_size: int
    raw_length: int
    trailing_bytes: int
    nonzero_bytes: int


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLanUserConfigV30Entry:
    """One decoded ``NET_DVR_USER_INFO_V30`` entry.

    Password and reserved bytes are hidden from ``repr(...)`` because this
    structure can contain real device credentials.
    """

    index: int
    username: str
    password: str = field(repr=False)
    password_bytes: bytes = field(repr=False)
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
    reserved: bytes = field(repr=False)

    @property
    def is_active(self) -> bool:
        """Return whether the entry carries any configured user data."""
        return bool(
            self.username
            or self.password_bytes
            or self.priority
            or self.user_ipv4
            or self.user_ipv6
            or self.mac_address
            or any(self.local_rights)
            or any(self.remote_rights)
            or any(self.net_preview_rights)
            or any(self.local_playback_rights)
            or any(self.net_playback_rights)
            or any(self.local_record_rights)
            or any(self.net_record_rights)
            or any(self.local_ptz_rights)
            or any(self.net_ptz_rights)
            or any(self.local_backup_rights)
        )


@dataclass(frozen=True)
class EzvizLanUserConfigV30:
    """Decoded ``NET_DVR_USER_V30`` user table."""

    declared_size: int
    users: tuple[EzvizLanUserConfigV30Entry, ...]
    raw_length: int
    trailing_bytes: int

    @property
    def active_users(self) -> tuple[EzvizLanUserConfigV30Entry, ...]:
        """Return configured entries, leaving empty user slots out."""
        return tuple(user for user in self.users if user.is_active)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLanRecordDayConfig:
    """One all-day entry from ``NET_DVR_RECORD_V30``."""

    day_index: int
    all_day_record: int
    record_type: int


@dataclass(frozen=True)
class EzvizLanRecordScheduleSegment:
    """One timed schedule segment from ``NET_DVR_RECORD_V30``."""

    day_index: int
    segment_index: int
    start_hour: int
    start_minute: int
    stop_hour: int
    stop_minute: int
    record_type: int


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET)

    @property
    def wdr_level_1(self) -> int | None:
        """Return ``struWdr.byWDRLevel1`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 1)

    @property
    def wdr_level_2(self) -> int | None:
        """Return ``struWdr.byWDRLevel2`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 2)

    @property
    def wdr_contrast_level(self) -> int | None:
        """Return ``struWdr.byWDRContrastLevel`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET + 3)

    @property
    def day_night_filter_type(self) -> int | None:
        """Return ``struDayNight.byDayNightFilterType`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET)

    @property
    def day_night_schedule_enabled(self) -> int | None:
        """Return ``struDayNight.bySwitchScheduleEnabled`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 1)

    @property
    def day_night_begin_time(self) -> tuple[int, int, int] | None:
        """Return the day/night begin time tuple when present."""
        return _optional_raw_byte_triplet(
            self.raw,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 2,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 7,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 8,
        )

    @property
    def day_night_end_time(self) -> tuple[int, int, int] | None:
        """Return the day/night end time tuple when present."""
        return _optional_raw_byte_triplet(
            self.raw,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 3,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 9,
            HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 10,
        )

    @property
    def day_to_night_filter_level(self) -> int | None:
        """Return ``struDayNight.byDayToNightFilterLevel`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 4)

    @property
    def night_to_day_filter_level(self) -> int | None:
        """Return ``struDayNight.byNightToDayFilterLevel`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 5)

    @property
    def day_night_filter_time(self) -> int | None:
        """Return ``struDayNight.byDayNightFilterTime`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 6)

    @property
    def day_night_alarm_trigger_state(self) -> int | None:
        """Return ``struDayNight.byAlarmTrigState`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET + 11)

    @property
    def backlight_mode(self) -> int | None:
        """Return ``struBackLight.byBacklightMode`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET)

    @property
    def backlight_level(self) -> int | None:
        """Return ``struBackLight.byBacklightLevel`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET + 1)


@dataclass(frozen=True)
class EzvizLanWifiConnectStatus:
    """Known fields from a ``NET_DVR_WIFI_CONNECT_STATUS`` response."""

    declared_size: int
    current_status: int
    error_code: int
    raw: bytes


@dataclass(frozen=True)
class EzvizLanAudioInputParam:
    """Known fields from a ``NET_DVR_AUDIO_INPUT_PARAM`` response."""

    audio_input_type: int
    volume: int
    noise_filter_enabled: int
    raw: bytes


@dataclass(frozen=True)
class EzvizLanAudioOutputVolume:
    """Known fields from a ``NET_DVR_AUDIOOUT_VOLUME`` response."""

    declared_size: int
    volume: int
    raw: bytes


@dataclass(frozen=True)
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


def _hcnetsdk_compression_info_v30(
    raw: bytes,
    offset: int,
) -> EzvizLanCompressionInfoV30 | None:
    if len(raw) < offset + HCNETSDK_COMPRESSION_INFO_V30_SIZE:
        return None
    block = raw[offset : offset + HCNETSDK_COMPRESSION_INFO_V30_SIZE]
    return EzvizLanCompressionInfoV30(
        stream_type=block[0],
        resolution=block[1],
        bitrate_type=block[2],
        picture_quality=block[3],
        video_bitrate=int.from_bytes(block[4:8], "big"),
        video_frame_rate=int.from_bytes(block[8:12], "big"),
        i_frame_interval=int.from_bytes(block[12:14], "big"),
        interval_bp_frame=block[14],
        reserved1=block[15],
        video_encoding_type=block[16],
        audio_encoding_type=block[17],
        video_encoding_complexity=block[18],
        svc_enabled=block[19],
        format_type=block[20],
        audio_bitrate=block[21],
        stream_smoothing=block[22],
        audio_sampling_rate=block[23],
        smart_codec=block[24],
        depth_map_enabled=block[25],
        average_video_bitrate=int.from_bytes(block[26:28], "big"),
        raw=block,
    )


@dataclass(frozen=True)
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
    def normal_record(self) -> EzvizLanCompressionInfoV30:
        """Return ``struNormHighRecordPara`` when present."""
        info = _hcnetsdk_compression_info_v30(self.raw, HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET)
        if info is None:
            raise PyEzvizError("EZVIZ LAN compression normal block is missing")
        return info

    @property
    def reserved(self) -> EzvizLanCompressionInfoV30 | None:
        """Return ``struRes`` when present."""
        return _hcnetsdk_compression_info_v30(self.raw, HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET)

    @property
    def event_record(self) -> EzvizLanCompressionInfoV30 | None:
        """Return ``struEventRecordPara`` when present."""
        return _hcnetsdk_compression_info_v30(self.raw, HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET)

    @property
    def network(self) -> EzvizLanCompressionInfoV30 | None:
        """Return ``struNetPara`` when present."""
        return _hcnetsdk_compression_info_v30(self.raw, HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET)


@dataclass(frozen=True)
class EzvizLanPictureConfig:
    """Known fields from a ``NET_DVR_PICCFG_V40`` response."""

    declared_size: int
    channel_name: str
    raw: bytes

    @property
    def video_format(self) -> int | None:
        """Return ``dwVideoFormat`` when present."""
        return _optional_raw_u32_be(self.raw, HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET)

    @property
    def brightness(self) -> int | None:
        """Return ``byBrightness`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET)

    @property
    def contrast(self) -> int | None:
        """Return ``byContrast`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 1)

    @property
    def saturation(self) -> int | None:
        """Return ``bySaturation`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 2)

    @property
    def hue(self) -> int | None:
        """Return ``byHue`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET + 3)

    @property
    def show_channel_name(self) -> int | None:
        """Return ``dwShowChanName`` when present."""
        return _optional_raw_u32_be(self.raw, HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET)

    @property
    def channel_name_position(self) -> tuple[int, int] | None:
        """Return ``wShowNameTopLeftX`` and ``wShowNameTopLeftY`` when present."""
        return _optional_raw_u16_be_pair(
            self.raw,
            HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET,
            HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET + 2,
        )

    @property
    def hide_enabled(self) -> int | None:
        """Return ``dwEnableHide`` when present."""
        return _optional_raw_u32_be(self.raw, HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET)

    @property
    def show_osd(self) -> int | None:
        """Return ``dwShowOsd`` when present."""
        return _optional_raw_u32_be(self.raw, HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET)

    @property
    def osd_position(self) -> tuple[int, int] | None:
        """Return ``wOSDTopLeftX`` and ``wOSDTopLeftY`` when present."""
        return _optional_raw_u16_be_pair(
            self.raw,
            HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET,
            HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET + 2,
        )

    @property
    def osd_type(self) -> int | None:
        """Return ``byOSDType`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET)

    @property
    def display_week(self) -> int | None:
        """Return ``byDispWeek`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 1)

    @property
    def osd_attribute(self) -> int | None:
        """Return ``byOSDAttrib`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 2)

    @property
    def hour_osd_type(self) -> int | None:
        """Return ``byHourOSDType`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 3)

    @property
    def font_size(self) -> int | None:
        """Return ``byFontSize`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 4)

    @property
    def osd_color_type(self) -> int | None:
        """Return ``byOSDColorType`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 5)

    @property
    def alignment(self) -> int | None:
        """Return ``byAlignment`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 6)

    @property
    def osd_millisecond_enabled(self) -> int | None:
        """Return ``byOSDMilliSecondEnable`` when present."""
        return _optional_raw_byte(self.raw, HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET + 7)


@dataclass(frozen=True)
class HcNetSdkDvrConfigRequest:
    """Native ``NET_DVR_GetDVRConfig`` / ``NET_DVR_SetDVRConfig`` shape."""

    login_id: int
    command: int
    channel: int
    structure: str
    api: str
    structure_size: int | None = None
    field_updates: Mapping[str, Any] | None = None
    read_before_write: bool = False

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK DVR config requires a successful login id")
        if self.command < 0:
            raise PyEzvizError("HCNetSDK DVR config command must be non-negative")
        if self.channel < -1:
            raise PyEzvizError("HCNetSDK DVR config channel must be -1 or greater")
        if not self.structure or any(char.isspace() for char in self.structure):
            raise PyEzvizError("HCNetSDK DVR config structure name is invalid")
        if self.structure_size is not None and self.structure_size < 0:
            raise PyEzvizError("HCNetSDK DVR config structure size is invalid")
        if self.api not in {HCNETSDK_GET_DVR_CONFIG, HCNETSDK_SET_DVR_CONFIG}:
            raise PyEzvizError("HCNetSDK DVR config API is unsupported")

        structure_size: int | str = (
            self.structure_size if self.structure_size is not None else f"sizeof({self.structure})"
        )
        hint: dict[str, Any] = {
            "api": self.api,
            "lUserID": self.login_id,
            "dwCommand": int(self.command),
            "lChannel": self.channel,
            "structure": self.structure,
        }
        if self.api == HCNETSDK_GET_DVR_CONFIG:
            hint.update(
                {
                    "lpOutBuffer": f"<{self.structure}>",
                    "dwOutBufferSize": structure_size,
                    "lpBytesReturned": "<bytes-returned>",
                }
            )
            return hint

        hint.update(
            {
                "lpInBuffer": f"<{self.structure}>",
                "dwInBufferSize": structure_size,
                "fieldUpdates": dict(self.field_updates or {}),
                "readBeforeWrite": self.read_before_write,
            }
        )
        return hint


@dataclass(frozen=True)
class HcNetSdkFormatDiskRequest:
    """Native ``NET_DVR_FormatDisk`` call shape."""

    login_id: int
    disk_number: int
    api: str = HCNETSDK_FORMAT_DISK

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the native argument names for starting local SD formatting."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK format requires a successful login id")
        if self.disk_number < 0:
            raise PyEzvizError("HCNetSDK format disk number must be non-negative")
        if self.api != HCNETSDK_FORMAT_DISK:
            raise PyEzvizError("HCNetSDK format API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lDiskNumber": self.disk_number,
            "failureHandle": -1,
        }


@dataclass(frozen=True)
class HcNetSdkFormatProgressRequest:
    """Native ``NET_DVR_GetFormatProgress`` call shape."""

    format_handle: int
    api: str = HCNETSDK_GET_FORMAT_PROGRESS

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the native argument names for polling SD format progress."""
        if self.format_handle < 0:
            raise PyEzvizError("HCNetSDK format handle must be non-negative")
        if self.api != HCNETSDK_GET_FORMAT_PROGRESS:
            raise PyEzvizError("HCNetSDK format-progress API is unsupported")
        return {
            "api": self.api,
            "lFormatHandle": self.format_handle,
            "pCurrentFormatDisk": "<IntByReference>",
            "pCurrentDiskPos": "<IntByReference>",
            "pFormatStatic": "<IntByReference>",
        }


@dataclass(frozen=True)
class HcNetSdkCloseFormatHandleRequest:
    """Native ``NET_DVR_CloseFormatHandle`` call shape."""

    format_handle: int
    api: str = HCNETSDK_CLOSE_FORMAT_HANDLE

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the native argument names for closing an SD format handle."""
        if self.format_handle < 0:
            raise PyEzvizError("HCNetSDK format handle must be non-negative")
        if self.api != HCNETSDK_CLOSE_FORMAT_HANDLE:
            raise PyEzvizError("HCNetSDK close-format API is unsupported")
        return {
            "api": self.api,
            "lFormatHandle": self.format_handle,
        }


@dataclass(frozen=True)
class EzvizLanSdFormatProgress:
    """RN-style result mapping for ``NET_DVR_GetFormatProgress`` values."""

    code: int
    current_disk: int
    progress: int | None
    status: int
    done: bool


@dataclass(frozen=True)
class HcNetSdkDeviceAbilityRequest:
    """Native ``NET_DVR_GetDeviceAbility`` call shape."""

    login_id: int
    ability_type: int
    in_buffer: str | bytes | None = None
    output_buffer_size: int = HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
    retry_output_buffer_size: int | None = HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
    api: str = HCNETSDK_GET_DEVICE_ABILITY

    @property
    def in_buffer_bytes(self) -> bytes:
        """Return bytes assigned to native ``pInBuf``."""
        if self.in_buffer is None:
            return b""
        return _device_ability_bytes("input buffer", self.in_buffer)

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK device ability requires a successful login id")
        if self.ability_type < 0:
            raise PyEzvizError("HCNetSDK device ability type must be non-negative")
        if self.output_buffer_size < 0:
            raise PyEzvizError("HCNetSDK device ability output buffer size must be non-negative")
        if self.retry_output_buffer_size is not None and (
            self.retry_output_buffer_size < self.output_buffer_size
        ):
            raise PyEzvizError("HCNetSDK device ability retry buffer must be at least output size")
        in_buffer = self.in_buffer_bytes
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "dwAbilityType": self.ability_type,
            "pInBuf": (
                in_buffer
                if include_buffers and in_buffer
                else ("<input-buffer>" if in_buffer else None)
            ),
            "dwInLength": len(in_buffer),
            "pOutBuf": "<output-buffer>",
            "dwOutLength": self.output_buffer_size,
            "retryOnError": HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR
            if self.retry_output_buffer_size is not None
            else None,
            "retryDwOutLength": self.retry_output_buffer_size,
        }


@dataclass(frozen=True)
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
        return _ability_option_tuple(self.enable_options)

    @property
    def device_status_option_list(self) -> tuple[str, ...]:
        """Return comma-separated device-status options as a tuple."""
        return _ability_option_tuple(self.device_status_options)

    @property
    def allow_redirect_option_list(self) -> tuple[str, ...]:
        """Return comma-separated redirect options as a tuple."""
        return _ability_option_tuple(self.allow_redirect_options)


@dataclass(frozen=True)
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
        return _ability_option_tuple(self.osd_type_options)

    @property
    def osd_attribute_option_list(self) -> tuple[str, ...]:
        """Return comma-separated OSD attribute options as a tuple."""
        return _ability_option_tuple(self.osd_attribute_options)

    @property
    def osd_hour_type_option_list(self) -> tuple[str, ...]:
        """Return comma-separated OSD hour-type options as a tuple."""
        return _ability_option_tuple(self.osd_hour_type_options)

    @property
    def motion_region_type_option_list(self) -> tuple[str, ...]:
        """Return comma-separated motion region-type options as a tuple."""
        return _ability_option_tuple(self.motion_region_type_options)


@dataclass(frozen=True)
class EzvizLanIpcFrontParameterAbility:
    """Parsed safe image/front-parameter ranges from ``CAMERAPARA`` XML."""

    has_camera_para: bool = False
    power_line_frequency_mode_range: str | None = None
    white_balance_mode_range: str | None = None
    exposure_mode_range: str | None = None
    exposure_set_range: str | None = None
    exposure_user_set: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    gain_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    brightness_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    contrast_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    sharpness_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    saturation_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    day_night_filter_type_range: str | None = None
    switch_schedule_enabled_range: str | None = None
    day_to_night_filter_level_range: str | None = None
    night_to_day_filter_level_range: str | None = None
    day_night_filter_time: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    backlight_mode_range: str | None = None
    mirror_range: str | None = None
    digital_noise_reduction_enable_range: str | None = None
    digital_noise_reduction_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    digital_noise_spectral_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )
    digital_noise_temporal_level: EzvizLanIpcFrontParameterRange = field(
        default_factory=EzvizLanIpcFrontParameterRange
    )

    @property
    def success(self) -> bool:
        """Return whether a camera-parameter ability root was parsed."""
        return self.has_camera_para

    @property
    def mirror_options(self) -> tuple[str, ...]:
        """Return comma-separated mirror options as a tuple."""
        return _ability_option_tuple(self.mirror_range)

    @property
    def backlight_mode_options(self) -> tuple[str, ...]:
        """Return comma-separated backlight mode options as a tuple."""
        return _ability_option_tuple(self.backlight_mode_range)

    @property
    def day_night_filter_type_options(self) -> tuple[str, ...]:
        """Return comma-separated day/night filter type options as a tuple."""
        return _ability_option_tuple(self.day_night_filter_type_range)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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
    resolutions: tuple[EzvizLanVideoResolution, ...] = field(default=(), kw_only=True)
    bitrate_codes: tuple[int, ...] = field(default=(), kw_only=True)

    @property
    def resolution_count(self) -> int:
        """Return the number of advertised video resolutions."""
        return len(self.resolution_indexes)


@dataclass(frozen=True)
class EzvizLanAudioVideoCompressVideoChannel:
    """One video channel from ``AudioVideoCompressInfo`` XML."""

    channel_number: int = 0
    main_stream: EzvizLanAudioVideoCompressStream | None = None
    sub_streams: tuple[EzvizLanAudioVideoCompressStream, ...] = ()

    @property
    def supports_sub_stream(self) -> bool:
        """Return whether at least one sub-stream profile was advertised."""
        return bool(self.sub_streams)


@dataclass(frozen=True)
class EzvizLanAudioVideoCompressAudioChannel:
    """One audio channel from ``AudioVideoCompressInfo`` XML."""

    channel_number: int = 0
    main_audio_encode_type_range: str | None = None
    sub_audio_encode_type_range: str | None = None
    audio_in_type_range: str | None = None
    audio_in_volume_min: int = 0
    audio_in_volume_max: int = 0


@dataclass(frozen=True)
class EzvizLanAudioVideoCompressVoiceTalkChannel:
    """One voice-talk channel from ``AudioVideoCompressInfo`` XML."""

    channel_number: int = 0
    voice_talk_encode_type_range: str | None = None
    voice_talk_in_type_range: str | None = None


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class HcNetSdkStreamDetails:
    """One fresh camera snapshot: current configuration is not observed media."""

    channel: int
    configuration: EzvizLanCompressionConfig = field(repr=False)
    capabilities: EzvizLanAudioVideoCompressInfo
    reported_login_serial: str = field(default="", repr=False)
    capabilities_error: int | None = None

    def configured_media(self, *, sub_stream: bool = False) -> HcNetSdkConfiguredMedia | None:
        """Translate configured SDK codes; this is not a negotiated media profile."""
        block = self.configuration.network if sub_stream else self.configuration.normal_record
        if block is None:
            return None
        resolution = self.configured_resolution(sub_stream=sub_stream)
        return normalize_hcnetsdk_parameters(
            video_encoding_type=block.video_encoding_type,
            audio_encoding_type=block.audio_encoding_type,
            video_frame_rate=block.video_frame_rate,
            video_bitrate=block.video_bitrate,
            audio_sampling_rate=block.audio_sampling_rate,
            format_type=block.format_type,
            width=resolution.width if resolution else None,
            height=resolution.height if resolution else None,
        )

    def configured_resolution(self, *, sub_stream: bool = False) -> EzvizLanVideoResolution | None:
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

    def as_dict(self) -> dict[str, Any]:
        """Return configuration and capability fields without raw replies/auth data."""

        def configured(block: EzvizLanCompressionInfoV30 | None) -> dict[str, Any] | None:
            if block is None:
                return None
            return {key: value for key, value in asdict(block).items() if key != "raw"}

        return {
            "channel": self.channel,
            "reported_login_serial": self.reported_login_serial,
            "source": "hcnetsdk_command_port",
            "observed_media": False,
            "transport_protocol": None,
            "main": configured(self.configuration.normal_record),
            "sub": configured(self.configuration.network),
            "main_configured_media": asdict(p)
            if (p := self.configured_media()) is not None
            else None,
            "sub_configured_media": asdict(p)
            if (p := self.configured_media(sub_stream=True)) is not None
            else None,
            "main_resolution": asdict(r)
            if (r := self.configured_resolution()) is not None
            else None,
            "sub_resolution": asdict(r)
            if (r := self.configured_resolution(sub_stream=True)) is not None
            else None,
            "capabilities": asdict(self.capabilities),
            "capabilities_error": self.capabilities_error,
        }


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class EzvizLanPlaybackConvertAbility:
    """Parsed playback conversion ability values used by the Android app."""

    resolutions: tuple[EzvizLanPlaybackConvertResolution, ...] = ()

    @property
    def success(self) -> bool:
        """Return whether any conversion resolution was parsed."""
        return bool(self.resolutions)
