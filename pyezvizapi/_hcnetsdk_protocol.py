"""HCNetSDK value models and pure protocol serialization; no socket ownership."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from enum import IntEnum
import ipaddress
import json
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk_parameters import HcNetSdkConfiguredMedia, normalize_hcnetsdk_parameters
from pyezvizapi.stream_header import EzvizStreamHeader, stream_header_from_preview

HCNETSDK_DEFAULT_SERVER_PORT = 8000


HCNETSDK_DEFAULT_TLS_PORT = 8443


HCNETSDK_DEFAULT_RTSP_PORT = 554


HCNETSDK_STDXML_INPUT_FIELD_ORDER = (
    "dwSize",
    "lpRequestUrl",
    "dwRequestUrlLen",
    "lpInBuffer",
    "dwInBufferSize",
    "dwRecvTimeOut",
    "byForceEncrpt",
    "byNumOfMultiPart",
    "byRes",
)


HCNETSDK_STDXML_OUTPUT_FIELD_ORDER = (
    "dwSize",
    "lpOutBuffer",
    "dwOutBufferSize",
    "dwReturnedXMLSize",
    "lpStatusBuffer",
    "dwStatusSize",
    "byRes",
)


HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE = 1024


HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE = 10_485_760


HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE = 16_384


HCNETSDK_XML_MARKER = b"<"


HCNETSDK_INIT = "NET_DVR_Init"


HCNETSDK_CLEANUP = "NET_DVR_Cleanup"


HCNETSDK_SET_CONNECT_TIME = "NET_DVR_SetConnectTime"


HCNETSDK_GET_LAST_ERROR = "NET_DVR_GetLastError"


HCNETSDK_GET_ERROR_MSG = "NET_DVR_GetErrorMsg"


HCNETSDK_GET_SDK_VERSION = "NET_DVR_GetSDKVersion"


HCNETSDK_GET_SDK_BUILD_VERSION = "NET_DVR_GetSDKBuildVersion"


HCNETSDK_LOGOUT_V30 = "NET_DVR_Logout_V30"


HCNETSDK_FIND_FILE_V30 = "NET_DVR_FindFile_V30"


HCNETSDK_FIND_NEXT_FILE_V30 = "NET_DVR_FindNextFile_V30"


HCNETSDK_FIND_CLOSE_V30 = "NET_DVR_FindClose_V30"


HCNETSDK_PLAYBACK_BY_TIME_V40 = "NET_DVR_PlayBackByTime_V40"


HCNETSDK_PLAYBACK_CONTROL_V40 = "NET_DVR_PlayBackControl_V40"


HCNETSDK_STOP_PLAYBACK = "NET_DVR_StopPlayBack"


HCNETSDK_PLAYBACK_CAPTURE_FILE = "NET_DVR_PlayBackCaptureFile"


HCNETSDK_SET_PLAY_DATA_CALLBACK = "NET_DVR_SetPlayDataCallBack"


HCNETSDK_SET_PLAY_DATA_CALLBACK_V40 = "NET_DVR_SetPlayDataCallBack_V40"


HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK = "NET_DVR_SetPlaybackResponseCallBack"


HCNETSDK_SET_PLAYBACK_ES_CALLBACK = "NET_DVR_SetPlayBackESCallBack"


HCNETSDK_SET_PLAYBACK_SECRET_KEY = "NET_DVR_SetPlayBackSecretKey"


HCNETSDK_GET_FILE_BY_NAME = "NET_DVR_GetFileByName"


HCNETSDK_GET_FILE_BY_TIME = "NET_DVR_GetFileByTime"


HCNETSDK_STOP_GET_FILE = "NET_DVR_StopGetFile"


HCNETSDK_GET_DOWNLOAD_POS = "NET_DVR_GetDownloadPos"


HCNETSDK_FIND_FILE_FAILED = -1


HCNETSDK_PLAYBACK_FAILED = -1


HCNETSDK_GET_FILE_FAILED = -1


HCNETSDK_PLAYBACK_FILE_TYPE_ALL = 0xFF


HCNETSDK_PLAYBACK_LOCK_STATE_ALL = 0xFF


HCNETSDK_TIME_FIELD_ORDER = (
    "dwYear",
    "dwMonth",
    "dwDay",
    "dwHour",
    "dwMinute",
    "dwSecond",
)


HCNETSDK_FILECOND_FIELD_ORDER = (
    "lChannel",
    "dwFileType",
    "dwIsLocked",
    "dwUseCardNo",
    "sCardNumber",
    "struStartTime",
    "struStopTime",
)


HCNETSDK_FINDDATA_V30_FIELD_ORDER = (
    "sFileName",
    "struStartTime",
    "struStopTime",
    "dwFileSize",
    "sCardNum",
    "byLocked",
    "byFileType",
    "byRes",
)


HCNETSDK_PLAYCOND_FIELD_ORDER = (
    "dwChannel",
    "struStartTime",
    "struStopTime",
    "byDrawFrame",
    "byStreamType",
    "byStreamID",
    "byRes",
)


HCNETSDK_SECRET_KEY_TYPE_AES = 1


HCNETSDK_MAKE_KEYFRAME_MAIN = "NET_DVR_MakeKeyFrame"


HCNETSDK_MAKE_KEYFRAME_SUB = "NET_DVR_MakeKeyFrameSub"


HCNETSDK_GET_DVR_CONFIG = "NET_DVR_GetDVRConfig"


HCNETSDK_SET_DVR_CONFIG = "NET_DVR_SetDVRConfig"


HCNETSDK_FORMAT_DISK = "NET_DVR_FormatDisk"


HCNETSDK_GET_FORMAT_PROGRESS = "NET_DVR_GetFormatProgress"


HCNETSDK_CLOSE_FORMAT_HANDLE = "NET_DVR_CloseFormatHandle"


HCNETSDK_GET_DEVICE_ABILITY = "NET_DVR_GetDeviceAbility"


HCNETSDK_SETUP_ALARM_CHAN_V30 = "NET_DVR_SetupAlarmChan_V30"


HCNETSDK_SETUP_ALARM_CHAN_V41 = "NET_DVR_SetupAlarmChan_V41"


HCNETSDK_CLOSE_ALARM_CHAN_V30 = "NET_DVR_CloseAlarmChan_V30"


HCNETSDK_SET_SDK_LOCAL_CFG = "NET_DVR_SetSDKLocalCfg"


HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER = (
    "dwSize",
    "byLevel",
    "byAlarmInfoType",
    "byRetAlarmTypeV40",
    "byRetDevInfoVersion",
    "byRetVQDAlarmType",
    "byFaceAlarmDetection",
    "bySupport",
    "byBrokenNetHttp",
    "wTaskNo",
    "byRes1",
)


HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE = 65_536


HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE = 524_288


HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR = 331_001


HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER = "NET_DVR_PTZControlWithSpeed_Other"


HCNETSDK_PTZ_PRESET_OTHER = "NET_DVR_PTZPreset_Other"


SADP_ACTIVATE_DEVICE = "SADP_ActivateDevice"


SADP_MODIFY_DEVICE_NET_PARAM = "SADP_ModifyDeviceNetParam"


SADP_MODIFY_DEVICE_NET_PARAM_V40 = "SADP_ModifyDeviceNetParam_V40"


SADP_GET_LAST_ERROR = "SADP_GetLastError"


SADP_GET_VERSION = "SADP_GetSadpVersion"


SADP_SET_LOG_TO_FILE = "SADP_SetLogToFile"


SADP_START_V30 = "SADP_Start_V30"


SADP_START_V40 = "SADP_Start_V40"


SADP_STOP = "SADP_Stop"


SADP_CLEARUP = "SADP_Clearup"


SADP_SEND_INQUIRY = "SADP_SendInquiry"


SADP_NUL_BYTE = b"\x00"


SADP_DEV_NET_PARAM_ANDROID_FIELDS = (
    "szIPv4Address",
    "szIPv4SubnetMask",
    "szIPv4Gateway",
    "szIPv6Address",
    "szIPv6Gateway",
    "byDhcpEnabled",
    "byIPv6MaskLen",
    "wHttpPort",
    "wPort",
    "byRes",
)


SADP_DEV_NET_PARAM_JNA_FIELD_ORDER = (
    "szIPv4Address",
    "szIPv4SubNetMask",
    "szIPv4Gateway",
    "szIPv6Address",
    "szIPv6Gateway",
    "wPort",
    "byIPv6MaskLen",
    "byDhcpEnable",
    "wHttpPort",
    "dwSDKOverTLSPort",
    "byRes",
)


SADP_DEV_RET_NET_PARAM_FIELD_ORDER = (
    "byRetryModifyTime",
    "bySurplusLockTime",
    "byRes",
)


SADP_DEV_RET_NET_PARAM_BUFFER_SIZE = 128


EZVIZ_HCNETUTIL_LOGIN_V40 = "HCNETUtil.s"


EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF = "LanDeviceListActivity.z0"


EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY = "PreviewBackNavigation.startLanVideoPlay"


EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE = "DeviceInfoEx.loginPlayDevice"


EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE = "IPlayDataInfo.loginPlayDevice"


EZVIZ_NATIVE_CREATE_CLIENT = "NativeApi.createClient"


EZVIZ_NATIVE_START_PREVIEW = "NativeApi.startPreview"


HCNETSDK_REALPLAY_V30 = "EZ_NET_DVR_RealPlay_V30"


HCNETSDK_REALDATA_CALLBACK_V30 = "HCNetSDKClient.sRealDataCallBack_V30"


EZVIZ_PLAYER_EXTRA_DEVICE_ID = "com.ezviz.EXTRA_DEVICE_ID"


EZVIZ_PLAYER_EXTRA_CHANNEL_NO = "com.ezviz.EXTRA_CHANNEL_NO"


EZVIZ_PLAYER_EXTRA_LAN_FLAG = "com.ezviz.EXTRA_LAN_FLAG"


EZVIZ_PLAYER_EXTRA_LAN_USERID = "com.ezviz.EXTRA_LAN_USERID"


EZVIZ_PLAYER_EXTRA_WIFI_SSID = "com.ezviz.EXTRA_WIFI_SSID"


EZVIZ_PLAYER_LAN_FLAG_HCNETSDK = 1


EZVIZ_STREAM_SOURCE_LIVE_MINE = 0


EZVIZ_STREAM_INHIBIT_LAN = 0x1F


EZVIZ_STREAM_TIMEOUT_MS = 30_000


EZVIZ_PREPLAY_SPS_TYPE = 9


EZVIZ_LAN_MAIN_VIDEO_LEVEL = 2


EZVIZ_LAN_PTZ_SPEED_DEFAULT = 5


EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE = 16


HCNETSDK_MPEG_PS_PACK_HEADER = b"\x00\x00\x01\xba"


HCNETSDK_MPEG_START_CODE_PREFIX = b"\x00\x00\x01"


HCNETSDK_MPEG_TS_SYNC_BYTE = 0x47


HCNETSDK_HIK_PRIVATE_PREFIX = b"@@@@"


HCNETSDK_HKMI_PREFIX = b"HKMI"


HCNETSDK_TCP_HEADER_LENGTH = 16


HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN = 90


HCNETSDK_COMMAND_CANDIDATE_CONTROL = 99


HCNETSDK_COMMAND_PORT_CONTROL_FAMILY = 0x63000000


HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH = 16


HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH = 6


HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM = "play_login_today"


_AES_SBOX = (
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
)


_AES_RCON = (0x01, 0x02, 0x04, 0x08)


HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET = 52


HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET = 72


HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET = 84


HCNETSDK_COMPRESSION_INFO_V30_SIZE = 28


HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET = 4


HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET = 32


HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET = 60


HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET = 88


HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET = 36


HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET = 40


HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET = 104


HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET = 108


HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET = 112


HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET = 148


HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET = 152


HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET = 156


class HcNetSdkRealDataType(IntEnum):
    """HCNetSDK real-play callback data types used by ``RealDataCallBack``."""

    SYSTEM_HEADER = 1
    STREAM_DATA = 2
    AUDIO_STREAM_DATA = 3
    PRIVATE_DATA = 112


@dataclass(frozen=True)
class HcNetSdkLanEndpoint:
    """LAN endpoint metadata derived from EZVIZ pagelist ``CONNECTION``."""

    serial: str
    host: str
    net_host: str | None = None
    command_port: int = HCNETSDK_DEFAULT_SERVER_PORT
    net_command_port: int | None = None
    stream_port: int | None = None
    net_stream_port: int | None = None
    rtsp_port: int | None = None
    sdk_tls_port: int = HCNETSDK_DEFAULT_TLS_PORT

    @classmethod
    def from_connection(
        cls,
        serial: str,
        connection: Mapping[str, Any] | None,
    ) -> HcNetSdkLanEndpoint:
        """Build LAN endpoint metadata from a pagelist ``CONNECTION`` mapping."""
        if not connection:
            raise PyEzvizError(f"Missing CONNECTION metadata for {serial}")

        host = connection.get("localIp")
        if not isinstance(host, str) or not host.strip():
            raise PyEzvizError(f"Missing localIp in CONNECTION metadata for {serial}")

        return cls(
            serial=serial,
            host=host.strip(),
            net_host=_mapping_str(connection, "netIp"),
            command_port=_mapping_int(
                connection,
                "localCmdPort",
                default=HCNETSDK_DEFAULT_SERVER_PORT,
            )
            or HCNETSDK_DEFAULT_SERVER_PORT,
            net_command_port=_mapping_int(connection, "netCmdPort", default=None),
            stream_port=_mapping_int(connection, "localStreamPort", default=None),
            net_stream_port=_mapping_int(connection, "netStreamPort", default=None),
            rtsp_port=_mapping_int(
                connection,
                "localRtspPort",
                default=HCNETSDK_DEFAULT_RTSP_PORT,
                zero_is_missing=True,
            ),
        )


@dataclass(frozen=True)
class HcNetSdkLoginCandidate:
    """One LAN login mode observed in the EZVIZ Android app."""

    username: str
    password: str = field(repr=False)
    port: int
    api: str
    https: bool = False


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

    def to_native_dict(self) -> dict[str, Any]:
        """Return the JNA field names and values for V41 alarm setup."""
        return {
            "structure": "NET_DVR_SETUPALARM_PARAM",
            "fieldOrder": HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
            "dwSize": "sizeof(NET_DVR_SETUPALARM_PARAM)",
            "byLevel": _byte_value("alarm level", self.level),
            "byAlarmInfoType": _byte_value("alarm info type", self.alarm_info_type),
            "byRetAlarmTypeV40": _byte_value("alarm V40 return type", self.ret_alarm_type_v40),
            "byRetDevInfoVersion": _byte_value(
                "alarm device-info version", self.ret_dev_info_version
            ),
            "byRetVQDAlarmType": _byte_value("alarm VQD return type", self.ret_vqd_alarm_type),
            "byFaceAlarmDetection": _byte_value("face alarm detection", self.face_alarm_detection),
            "bySupport": _byte_value("alarm support", self.support),
            "byBrokenNetHttp": _byte_value("broken-net HTTP", self.broken_net_http),
            "wTaskNo": _word_value("alarm task number", self.task_no),
            "byRes1Length": 6,
        }


@dataclass(frozen=True)
class HcNetSdkSetupAlarmRequest:
    """Native ``NET_DVR_SetupAlarmChan_V30`` / ``V41`` call shape."""

    login_id: int
    setup_param: HcNetSdkSetupAlarmParam | None = None

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for setting up an alarm channel."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK alarm setup requires a successful login id")
        if self.setup_param is None:
            return {
                "api": HCNETSDK_SETUP_ALARM_CHAN_V30,
                "lUserID": self.login_id,
                "failureHandle": -1,
            }
        return {
            "api": HCNETSDK_SETUP_ALARM_CHAN_V41,
            "lUserID": self.login_id,
            "lpSetupParam": self.setup_param.to_native_dict(),
            "failureHandle": -1,
        }


@dataclass(frozen=True)
class HcNetSdkCloseAlarmRequest:
    """Native ``NET_DVR_CloseAlarmChan_V30`` call shape."""

    alarm_handle: int
    api: str = HCNETSDK_CLOSE_ALARM_CHAN_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for closing an alarm channel."""
        if self.alarm_handle < 0:
            raise PyEzvizError("HCNetSDK alarm handle must be non-negative")
        if self.api != HCNETSDK_CLOSE_ALARM_CHAN_V30:
            raise PyEzvizError("HCNetSDK close-alarm API is unsupported")
        return {
            "api": self.api,
            "lAlarmHandle": self.alarm_handle,
        }


@dataclass(frozen=True)
class HcNetSdkSetSdkLocalCfgRequest:
    """Native ``NET_DVR_SetSDKLocalCfg`` request shape."""

    cfg_type: int
    structure: str
    field_updates: Mapping[str, Any] | None = None
    field_order: tuple[str, ...] | None = None
    api: str = HCNETSDK_SET_SDK_LOCAL_CFG

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for SDK-process local config."""
        if self.cfg_type < 0:
            raise PyEzvizError("HCNetSDK local config type must be non-negative")
        if not self.structure or any(char.isspace() for char in self.structure):
            raise PyEzvizError("HCNetSDK local config structure name is invalid")
        if self.api != HCNETSDK_SET_SDK_LOCAL_CFG:
            raise PyEzvizError("HCNetSDK local config API is unsupported")
        hint: dict[str, Any] = {
            "api": self.api,
            "enumType": int(self.cfg_type),
            "lpInBuff": f"<{self.structure}>",
            "structure": self.structure,
            "fieldUpdates": dict(self.field_updates or {}),
        }
        if self.field_order is not None:
            hint["fieldOrder"] = self.field_order
        return hint


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
        return _ability_option_tuple(self.control_types)


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
class EzvizLanIpcFrontParameterRange:
    """One integer range advertised by ``CAMERAPARA`` ability XML."""

    minimum: int = 0
    maximum: int = 0
    default: int | None = None

    @property
    def supported(self) -> bool:
        """Return whether the range has a non-empty max/min span."""
        return self.maximum > self.minimum


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
class EzvizLanPlaybackConvertResolution:
    """One playback conversion resolution entry from ``RecordAbility`` XML."""

    index: int
    frame_rates: tuple[int, ...] = ()
    bitrates: tuple[int, ...] = ()


@dataclass(frozen=True)
class EzvizLanPlaybackConvertAbility:
    """Parsed playback conversion ability values used by the Android app."""

    resolutions: tuple[EzvizLanPlaybackConvertResolution, ...] = ()

    @property
    def success(self) -> bool:
        """Return whether any conversion resolution was parsed."""
        return bool(self.resolutions)


@dataclass(frozen=True)
class HcNetSdkPtzControlRequest:
    """Native ``NET_DVR_PTZControlWithSpeed_Other`` call shape."""

    login_id: int
    channel: int
    command: int
    stop: int
    speed: int = EZVIZ_LAN_PTZ_SPEED_DEFAULT
    api: str = HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK PTZ control requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK PTZ control channel must be non-negative")
        if self.command < 0:
            raise PyEzvizError("HCNetSDK PTZ control command must be non-negative")
        if self.stop not in {0, 1}:
            raise PyEzvizError("HCNetSDK PTZ control stop flag must be 0 or 1")
        if self.speed < 0:
            raise PyEzvizError("HCNetSDK PTZ control speed must be non-negative")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "dwPTZCommand": self.command,
            "dwStop": self.stop,
            "dwSpeed": self.speed,
        }


@dataclass(frozen=True)
class HcNetSdkPtzPresetRequest:
    """Native ``NET_DVR_PTZPreset_Other`` call shape."""

    login_id: int
    channel: int
    command: int
    preset_index: int = 0
    api: str = HCNETSDK_PTZ_PRESET_OTHER

    def to_native_args_hint(self) -> dict[str, int | str]:
        """Return the native argument names for a local HCNetSDK bridge."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK PTZ preset requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK PTZ preset channel must be non-negative")
        if self.command not in {8, 9, 39}:
            raise PyEzvizError("HCNetSDK PTZ preset command is unsupported")
        if self.preset_index < 0:
            raise PyEzvizError("HCNetSDK PTZ preset index must be non-negative")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "dwPTZPresetCmd": self.command,
            "dwPresetIndex": self.preset_index,
        }


@dataclass(frozen=True)
class EzvizLanPlaybackIntent:
    """Intent extras used to hand a LAN HCNetSDK login to the player UI."""

    serial: str
    channel_number: int
    lan_user_id: int = -1
    ssid: str = ""
    lan_flag: int = EZVIZ_PLAYER_LAN_FLAG_HCNETSDK

    def to_extra_dict(self) -> dict[str, int | str]:
        """Return the exact extras written by startLanVideoPlay(...)."""
        return {
            EZVIZ_PLAYER_EXTRA_DEVICE_ID: self.serial,
            EZVIZ_PLAYER_EXTRA_CHANNEL_NO: self.channel_number,
            EZVIZ_PLAYER_EXTRA_LAN_FLAG: self.lan_flag,
            EZVIZ_PLAYER_EXTRA_LAN_USERID: self.lan_user_id,
            EZVIZ_PLAYER_EXTRA_WIFI_SSID: self.ssid,
        }


@dataclass(frozen=True)
class EzvizLanVideoQuality:
    """LAN quality pair exposed by ``LanItemDataHolder.getVideoQualityInfo()``."""

    stream_type: int
    video_level: int

    @property
    def native_video_level(self) -> int:
        """Return the value written to ``InitParam.iVideoLevel`` by the player."""
        return ezviz_native_video_level(self.video_level)


@dataclass(frozen=True)
class EzvizLanLiveViewParams:
    """Relevant EZVIZ player init fields for ``PlayerDataType.LAN`` live view."""

    serial: str
    channel_number: int
    channel_serial: str | None = None
    channel_index: str | None = None
    channel_count: int | None = None
    stream_source: int = EZVIZ_STREAM_SOURCE_LIVE_MINE
    stream_type: int = 1
    video_level: int = EZVIZ_LAN_MAIN_VIDEO_LEVEL
    stream_inhibit: int = EZVIZ_STREAM_INHIBIT_LAN
    stream_timeout_ms: int = EZVIZ_STREAM_TIMEOUT_MS
    preplay_sps_type: int = EZVIZ_PREPLAY_SPS_TYPE
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
        data: dict[str, int | str] = {
            "szDevSerial": self.serial,
            "szChnlSerial": self.channel_serial or self.serial,
            "szChnlIndex": self.channel_index or "",
            "szDevIP": self.device_ip or "",
            "szDevLocalIP": self.device_local_ip or "",
            "iDevCmdPort": self.device_cmd_port or 0,
            "iDevCmdLocalPort": self.device_cmd_local_port or 0,
            "iDevStreamPort": self.device_stream_port or 0,
            "iDevStreamLocalPort": self.device_stream_local_port or 0,
            "iChannelCount": self.channel_count or 0,
            "iP2PSPS": self.preplay_sps_type,
            "iStreamInhibit": self.stream_inhibit,
            "iStreamSource": self.stream_source,
            "iStreamType": self.stream_type,
            "iStreamTimeOut": self.stream_timeout_ms,
            "iVideoLevel": ezviz_native_video_level(self.video_level),
            "iChannelNumber": self.channel_number,
            "iNetSDKUserId": self.netsdk_login_id,
        }
        if self.netsdk_channel_number is not None:
            data["iNetSDKChannelNumber"] = self.netsdk_channel_number
        return data

    def to_real_play_request(
        self,
        *,
        link_mode: int = 0,
        blocked: bool = False,
        multicast_ip: str = "",
    ) -> HcNetSdkRealPlayRequest:
        """Return the direct HCNetSDK ``RealPlay_V30`` request shape."""
        return hcnetsdk_real_play_request(
            self.netsdk_login_id,
            channel_number=self.netsdk_channel_number or self.channel_number,
            link_mode=link_mode,
            blocked=blocked,
            multicast_ip=multicast_ip,
        )


@dataclass(frozen=True)
class EzvizLanKeyframeRequest:
    """HCNetSDK I-frame request made after LAN native preview starts."""

    api: str
    netsdk_login_id: int
    netsdk_channel_number: int


@dataclass(frozen=True)
class HcNetSdkRealDataPacket:
    """One packet emitted by an HCNetSDK real-play data callback."""

    real_handle: int
    data_type: int
    body: bytes

    @property
    def is_media(self) -> bool:
        """Return whether this callback packet can carry remuxable media."""
        return hcnetsdk_real_data_type_is_media(self.data_type)

    @property
    def payload_kind(self) -> str:
        """Return a small, non-secret classification of the callback body."""
        return classify_hcnetsdk_real_data_payload(self.body)


@dataclass(frozen=True)
class HcNetSdkTcpPayloadShape:
    """Secret-safe classification for raw HCNetSDK command-port bytes."""

    kind: str
    length: int
    printable_ratio: float
    null_ratio: float
    high_bit_ratio: float
    entropy_bits_per_byte: float
    u32be_0: int | None = None
    u32le_0: int | None = None
    u32be_4: int | None = None
    u32le_4: int | None = None
    u32be_8: int | None = None
    u32le_8: int | None = None
    u32be_12: int | None = None
    u32le_12: int | None = None
    u16be_0: int | None = None
    u16le_0: int | None = None
    declared_length_offset: int | None = None
    declared_length: int | None = None
    xml_offset: int | None = None
    xml_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class HcNetSdkTcpShapeLogRecord:
    """One secret-safe HCNetSDK command-port shape log line."""

    direction: str
    fd: int
    host: str
    port: int
    shape: HcNetSdkTcpPayloadShape
    captured_length: int | None = None
    fingerprint: str | None = None
    length_candidates: Mapping[str, int] | None = None


@dataclass(frozen=True)
class HcNetSdkSemanticLogEvent:
    """One secret-safe semantic HCNetSDK event."""

    name: str
    phase: str | None = None
    fields: Mapping[str, str] | None = None


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class HcNetSdkTcpFrameHeader:
    """Observed 16-byte HCNetSDK command-port packet header.

    A direct-local trace showed command replies arriving as a 16-byte header with
    the first big-endian word equal to the total frame length, followed by a
    body read of ``total_length - 16`` bytes. The remaining words are kept as
    opaque fields until more traces prove their semantics.
    """

    total_length: int
    field_4: int
    field_8: int
    field_12: int

    @property
    def body_length(self) -> int:
        """Return body length implied by the observed total-length word."""
        return self.total_length - HCNETSDK_TCP_HEADER_LENGTH

    def to_bytes(self) -> bytes:
        """Serialize the non-secret header fields using observed endianness."""
        return b"".join(
            (
                self.total_length.to_bytes(4, "big"),
                self.field_4.to_bytes(4, "big"),
                self.field_8.to_bytes(4, "big"),
                self.field_12.to_bytes(4, "big"),
            )
        )


@dataclass(frozen=True)
class HcNetSdkTcpFrame:
    """One complete HCNetSDK command-port frame."""

    header: HcNetSdkTcpFrameHeader
    body: bytes = b""

    def to_bytes(self) -> bytes:
        """Serialize the observed frame header and body."""
        if self.header.body_length != len(self.body):
            raise PyEzvizError("HCNetSDK TCP frame header/body length mismatch")
        return self.header.to_bytes() + self.body


@dataclass(frozen=True)
class HcNetSdkCommandPortExchange:
    """One command-port request and its optional response."""

    request: bytes
    response: HcNetSdkTcpFrame | None = None


@dataclass(frozen=True)
class HcNetSdkCommandPortStreamBootstrap:
    """Result of a command-port stream bootstrap."""

    exchanges: tuple[HcNetSdkCommandPortExchange, ...]
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None


@dataclass(frozen=True)
class HcNetSdkCommandPortLoginChallenge:
    """Decoded first-stage command-port login challenge."""

    response: HcNetSdkTcpFrame
    challenge: bytes
    password_seed: bytes


@dataclass(frozen=True)
class HcNetSdkCommandPortLoginSession:
    """Successful generated port-8000 login session."""

    session_id: bytes
    auth_seed: int
    serial: str
    first_response: HcNetSdkTcpFrame
    second_response: HcNetSdkTcpFrame
    challenge: bytes = b""
    password_seed: bytes = b""


@dataclass(frozen=True)
class HcNetSdkCommandPortControlResponse:
    """Pure-Python response from one generated command-port control request."""

    login_session: HcNetSdkCommandPortLoginSession
    request: bytes
    response: HcNetSdkTcpFrame

    @property
    def output(self) -> bytes:
        """Return the textual payload carried by the command-port response."""
        return hcnetsdk_command_port_response_payload(self.response)

    @property
    def text(self) -> str:
        """Decode the textual response payload as UTF-8."""
        return self.output.decode("utf-8")


@dataclass(frozen=True)
class HcNetSdkCommandPortControlTemplate:
    """Reusable post-login command-port control frame template."""

    command_id: int
    body_tail: bytes = b""
    addend: int | None = None
    addend_delta: int | None = None
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
    body_tail_transform: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.addend is not None and self.addend_delta is not None:
            raise PyEzvizError("HCNetSDK command-port template cannot set addend and addend_delta")
        if (
            self.body_tail_transform is not None
            and self.body_tail_transform != HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
        ):
            raise PyEzvizError(
                f"Unsupported HCNetSDK command-port body_tail_transform: {self.body_tail_transform}"
            )

    def to_frame(
        self,
        *,
        session_id: bytes,
        auth_seed: int,
        key: bytes,
        local_ip: str,
        addend: int | None = None,
    ) -> bytes:
        """Build this template with fresh login/session values."""
        template_addend = self.addend
        if template_addend is None and self.addend_delta is not None:
            template_addend = (int.from_bytes(session_id, "big") + self.addend_delta) & 0xFFFFFFFF
        body_tail = self.body_tail
        if self.body_tail_transform == HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM:
            body_tail = hcnetsdk_command_port_play_login_body_tail_for_today(body_tail)
        return hcnetsdk_command_port_control_frame(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=self.command_id,
            key=key,
            local_ip=local_ip,
            body_tail=body_tail,
            addend=template_addend if addend is None else addend,
            mask_seed=self.mask_seed,
        )


@dataclass(frozen=True)
class HcNetSdkTcpFrameShape:
    """One HCNetSDK command-port frame reconstructed from redacted log shapes."""

    direction: str
    fd: int
    host: str
    port: int
    total_length: int
    header_shape: HcNetSdkTcpPayloadShape
    body_shape: HcNetSdkTcpPayloadShape | None = None

    @property
    def body_length(self) -> int:
        """Return body length implied by the observed 16-byte header."""
        return self.total_length - HCNETSDK_TCP_HEADER_LENGTH

    @property
    def write_command_candidate(self) -> int | None:
        """Return the observed client-write command candidate when present.

        Fresh direct-local traces show HCNetSDK client writes with a big-endian total
        length at offset 0 and a small little-endian word at offset 4. That word
        was 90 for the initial encrypted login exchange and 99 for several
        follow-up capability/control requests. Keep it as a candidate until
        more devices prove the semantics.
        """
        if self.direction not in {"send", "write"}:
            return None
        return self.header_shape.u32le_4

    @property
    def write_command_role(self) -> str | None:
        """Return the current semantic label for an observed write candidate."""
        return hcnetsdk_command_candidate_role(self.write_command_candidate)


@dataclass(frozen=True)
class HcNetSdkClientInfo:
    """Python model of the Java/native ``NET_DVR_CLIENTINFO`` preview input."""

    channel: int = 1
    link_mode: int = 0
    multicast_ip: str = ""

    def to_native_dict(self) -> dict[str, int | str]:
        """Return the field names from the APK's ``NET_DVR_CLIENTINFO`` class."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK client channel must be non-negative")
        if self.link_mode < 0:
            raise PyEzvizError("HCNetSDK client link mode must be non-negative")
        return {
            "lChannel": self.channel,
            "lLinkMode": self.link_mode,
            "sMultiCastIP": self.multicast_ip,
        }


@dataclass(frozen=True)
class HcNetSdkRealPlayRequest:
    """Arguments needed for ``EZ_NET_DVR_RealPlay_V30`` plus callback metadata."""

    login_id: int
    client_info: HcNetSdkClientInfo
    blocked: bool = False
    callback_api: str = HCNETSDK_REALDATA_CALLBACK_V30
    api: str = HCNETSDK_REALPLAY_V30

    def to_native_args_hint(self) -> dict[str, int | str | dict[str, int | str]]:
        """Return a serializable hint for HCNetSDK-compatible real-play calls."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK real-play requires a successful login id")
        return {
            "api": self.api,
            "login_id": self.login_id,
            "client_info": self.client_info.to_native_dict(),
            "callback": self.callback_api,
            "blocked": int(self.blocked),
        }


@dataclass(frozen=True)
class EzvizLanPlayDeviceLogin:
    """Player-owned HCNetSDK login step used before LAN native preview starts."""

    endpoint: HcNetSdkLanEndpoint
    check_last_login_status: bool = False
    api: str = EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    facade_api: str = EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE

    def to_device_param_hint(self) -> dict[str, int | str]:
        """Return the non-secret DeviceParam fields relevant to this login."""
        return {
            "serial": self.endpoint.serial,
            "deviceLocalIp": self.endpoint.host,
            "localCmdPort": self.endpoint.command_port,
            "localStreamPort": self.endpoint.stream_port or 0,
        }


@dataclass(frozen=True)
class EzvizLanPreviewPlan:
    """APK-observed LAN preview flow around HCNetSDK login and EZ stream start."""

    login_candidates: tuple[HcNetSdkLoginCandidate, ...]
    live_view: EzvizLanLiveViewParams
    play_device_login: EzvizLanPlayDeviceLogin | None = None
    create_client_api: str = EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = EZVIZ_NATIVE_START_PREVIEW

    @property
    def real_play_request(self) -> HcNetSdkRealPlayRequest | None:
        """Return the HCNetSDK real-play call shape once login is available."""
        if self.live_view.netsdk_login_id < 0:
            return None
        return self.live_view.to_real_play_request()

    @property
    def post_start_keyframe_request(self) -> EzvizLanKeyframeRequest | None:
        """Return the HCNetSDK keyframe request made after native preview start."""
        if self.live_view.netsdk_login_id < 0:
            return None
        channel_number = self.live_view.netsdk_channel_number
        if channel_number is None:
            return None
        if self.live_view.stream_type == 2:
            api = HCNETSDK_MAKE_KEYFRAME_SUB
        else:
            api = HCNETSDK_MAKE_KEYFRAME_MAIN
        return EzvizLanKeyframeRequest(
            api=api,
            netsdk_login_id=self.live_view.netsdk_login_id,
            netsdk_channel_number=channel_number,
        )

    @property
    def post_start_keyframe_api(self) -> str | None:
        """Return the HCNetSDK keyframe API name made after preview start."""
        request = self.post_start_keyframe_request
        return None if request is None else request.api

    def native_call_sequence(self) -> tuple[str, ...]:
        """Return the native call sequence observed for LAN live preview."""
        calls = []
        if self.play_device_login is not None:
            calls.append(self.play_device_login.api)
        calls.extend([self.create_client_api, self.start_preview_api])
        if self.post_start_keyframe_request:
            calls.append(self.post_start_keyframe_request.api)
        return tuple(calls)


@dataclass(frozen=True)
class EzvizLanPlaybackPath:
    """Complete LAN Live View path observed in the EZVIZ Android app."""

    settings_login_candidates: tuple[HcNetSdkLoginCandidate, ...]
    settings_login_id: int
    channel_number: int
    playback_intent: EzvizLanPlaybackIntent
    play_device_login: EzvizLanPlayDeviceLogin
    play_device_login_id: int
    live_view: EzvizLanLiveViewParams
    create_client_api: str = EZVIZ_NATIVE_CREATE_CLIENT
    start_preview_api: str = EZVIZ_NATIVE_START_PREVIEW

    @property
    def post_start_keyframe_request(self) -> EzvizLanKeyframeRequest | None:
        """Return the keyframe request made after native preview starts."""
        return EzvizLanPreviewPlan(
            login_candidates=self.settings_login_candidates,
            live_view=self.live_view,
            play_device_login=self.play_device_login,
            create_client_api=self.create_client_api,
            start_preview_api=self.start_preview_api,
        ).post_start_keyframe_request

    def call_sequence(self) -> tuple[str, ...]:
        """Return the app-level calls needed for a complete LAN playback start."""
        calls = [
            EZVIZ_HCNETUTIL_LOGIN_V40,
            EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
            EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
            self.play_device_login.api,
            self.create_client_api,
            self.start_preview_api,
        ]
        if self.post_start_keyframe_request is not None:
            calls.append(self.post_start_keyframe_request.api)
        return tuple(calls)


@dataclass(frozen=True)
class EzvizLocalDeviceContent:
    """Decoded ``deviceContent`` for app-managed EZVIZ LAN devices."""

    device_ip: str | None = None
    device_type: int | None = None
    device_enc_type: int | None = None
    is_low_power: int | None = None
    device_max_act_limit: int | None = None
    device_sdk_version: int | None = None
    device_rand: str | None = None
    device_role_type: int | None = None


@dataclass(frozen=True)
class EzvizLocalDevice:
    """Local-device record shape used by the EZVIZ app and cloud API."""

    serial: str
    name: str | None = None
    model: str | None = None
    category: str | None = None
    device_category: str | None = None
    group_id: int | None = None
    content: EzvizLocalDeviceContent | None = None
    raw: Mapping[str, Any] | None = None

    @property
    def endpoint(self) -> HcNetSdkLanEndpoint | None:
        """Return a minimal HCNetSDK endpoint if the local payload has an IP."""
        if self.content is None or not self.content.device_ip:
            return None
        return HcNetSdkLanEndpoint(serial=self.serial, host=self.content.device_ip)


@dataclass(frozen=True)
class EzvizCasDeviceInfo:
    """CAS device-info tuple used by the EZVIZ native direct-local path.

    APK/native tracing showed CasDeviceInfo.key is copied into EZ_DEV_INFO.szKey
    and ultimately used as the AES-128 key for local SDK control frames. The
    direct-local ``9010/9020`` path uses the app-shaped local SDK SSL-like
    IV for control-frame encryption and appends a 32-byte lowercase MD5 hex
    digest of the ciphertext. ``deviceSerial + operationCode`` remains exposed
    for older CAS helpers and compatibility checks.
    """

    serial: str
    operation_code: str
    key: str
    encrypt_type: int | None = None

    @property
    def key_bytes(self) -> bytes:
        """Return the local-control AES key bytes, validating its size."""
        return _local_sdk_aes_bytes("key", self.key)

    @property
    def iv_bytes(self) -> bytes:
        """Return the local-control AES IV bytes derived from CAS metadata."""
        return ezviz_local_sdk_iv(self.serial, self.operation_code)


@dataclass(frozen=True)
class HcNetSdkPortProbe:
    """Non-authenticated classification result for one LAN port."""

    port: int
    tcp_open: bool
    tls_accepted: bool | None = None
    passive_bytes: bytes = b""
    error: str | None = None
    tls_error: str | None = None


@dataclass(frozen=True)
class EzvizLocalSdkFrameHeader:
    """Header for EZVIZ local SDK XML/framed control messages."""

    magic: bytes
    version: int
    sequence: int
    marker: int
    command: int
    status: int
    body_length: int
    reserved: int


@dataclass(frozen=True)
class EzvizLocalSdkFrame:
    """One EZVIZ local SDK control frame with an optional XML body."""

    header: EzvizLocalSdkFrameHeader
    body: bytes = b""
    trailer: bytes = b""


@dataclass(frozen=True)
class EzvizLocalSdkBodyShape:
    """Secret-safe body classification for EZVIZ local SDK frames."""

    kind: str
    length: int
    printable_ratio: float
    null_ratio: float
    high_bit_ratio: float
    entropy_bits_per_byte: float
    xml_offset: int | None = None
    xml_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class EzvizInterleavedRtpFrameHeader:
    """RTSP-style interleaved RTP frame prefix used on the EZVIZ stream port."""

    channel: int
    payload_length: int


@dataclass(frozen=True)
class EzvizInterleavedRtpFrame:
    """One interleaved RTP frame read from an EZVIZ local stream socket."""

    header: EzvizInterleavedRtpFrameHeader
    payload: bytes


@dataclass(frozen=True)
class EzvizInterleavedRtpFrameWithPrefix:
    """First RTP frame plus any binary preface emitted before it."""

    prefix: bytes
    frame: EzvizInterleavedRtpFrame


@dataclass(frozen=True)
class EzvizLocalSdkExchange:
    """One encrypted local SDK request and parsed response frame."""

    request: bytes
    response: EzvizLocalSdkFrame


@dataclass(frozen=True)
class EzvizLocalSdkStreamBootstrap:
    """Result of the direct-local preview setup sequence."""

    preview: EzvizLocalSdkExchange
    stream_setup: EzvizLocalSdkExchange
    pre_start: EzvizLocalSdkExchange | None = None
    first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

    @property
    def stream_header(self) -> EzvizStreamHeader | None:
        """Return camera-negotiated media fields without session/auth data."""
        return stream_header_from_preview(self.preview.response.body)


@dataclass(frozen=True)
class EzvizLocalReceiverInfo:
    """Structured receiver fields for the native local preview setup request."""

    nat_address: str = ""
    nat_port: int = 0
    upnp_address: str = ""
    upnp_port: int = 0
    inner_address: str = ""
    inner_port: int = 0
    stream_type: str = "MAIN"

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the nested ``ReceiverInfo`` XML lines."""
        for name, port_value in (
            ("nat_port", self.nat_port),
            ("upnp_port", self.upnp_port),
            ("inner_port", self.inner_port),
        ):
            if port_value < 0:
                raise PyEzvizError(f"EZVIZ local receiver {name} must be non-negative")
        fields: tuple[tuple[str, str | int | None], ...] = (
            ("NatAddress", self.nat_address),
            ("NatPort", self.nat_port),
            ("UPnPAddress", self.upnp_address),
            ("UPnPPort", self.upnp_port),
            ("InnerAddress", self.inner_address),
            ("InnerPort", self.inner_port),
            ("StreamType", self.stream_type),
        )
        lines = [f"{indent}<ReceiverInfo>"]
        for tag, value in fields:
            lines.append(f"{indent}\t<{tag}>{_xml_escape(str(value))}</{tag}>")
        lines.append(f"{indent}</ReceiverInfo>")
        return tuple(lines)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoEx:
    """Structured extended receiver-auth fields for the local preview request."""

    uuid: str | None = None
    timestamp: str | int | None = None

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the nested ``ReceiverInfoEx`` XML lines."""
        lines = [f"{indent}<ReceiverInfoEx>"]
        if self.uuid is not None or self.timestamp is not None:
            lines.append(f"{indent}\t<Authentication>")
            for tag, value in (("Uuid", self.uuid), ("Timestamp", self.timestamp)):
                if value is not None:
                    lines.append(f"{indent}\t\t<{tag}>{_xml_escape(str(value))}</{tag}>")
            lines.append(f"{indent}\t</Authentication>")
        lines.append(f"{indent}</ReceiverInfoEx>")
        return tuple(lines)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoAttrs:
    """App-shaped ``ReceiverInfo`` attributes for direct-local preview setup."""

    address: str = ""
    port: int = 10101
    server_type: int = 1
    stream_type: str = "MAIN"
    new_stream_type: int = 1
    trans_proto: str = "TCP"

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfo`` tag."""
        if self.port < 0:
            raise PyEzvizError("EZVIZ local receiver port must be non-negative")
        attrs = (
            ("Address", self.address),
            ("Port", self.port),
            ("ServerType", self.server_type),
            ("StreamType", self.stream_type),
            ("NewStreamType", self.new_stream_type),
            ("TransProto", self.trans_proto),
        )
        return (f"{indent}<ReceiverInfo {_xml_attrs(attrs)} />",)


@dataclass(frozen=True)
class EzvizLocalReceiverInfoExAttrs:
    """App-shaped ``ReceiverInfoEx`` attributes for direct-local preview setup."""

    session_id: str = ""
    port: int = 10101

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``ReceiverInfoEx`` tag."""
        if self.port < 0:
            raise PyEzvizError("EZVIZ local receiver ex port must be non-negative")
        return (
            f"{indent}<ReceiverInfoEx "
            f"{_xml_attrs((('SessionID', self.session_id), ('Port', self.port)))} />",
        )


@dataclass(frozen=True)
class EzvizLocalAuthenticationAttrs:
    """App-shaped authentication attributes for direct-local preview setup."""

    ticket: str = ""
    biz_code: str = "biz=1"
    interval: int = 180

    def xml_lines(self, *, indent: str = "\t") -> tuple[str, ...]:
        """Build the observed self-closing app ``Authentication`` tag."""
        if self.interval < 0:
            raise PyEzvizError("EZVIZ local authentication interval must be non-negative")
        attrs = (
            ("Ticket", self.ticket),
            ("BizCode", self.biz_code),
            ("Interval", self.interval),
        )
        return (f"{indent}<Authentication {_xml_attrs(attrs)} />",)


@dataclass(frozen=True)
class EzvizLocalPreviewRequest:
    """Plaintext field set for the observed 0x2011 preview request."""

    operation_code: str
    channel: int
    receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs
    receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs
    identifier: str | None = None
    is_encrypt: str | int = "TRUE"
    udt: int | None = None
    nat: int | None = None
    port_guess_type: int | None = None
    timeout: int | None = None
    heartbeat_interval: int | None = None
    authentication: str | EzvizLocalAuthenticationAttrs | None = None
    uuid: str | None = None
    timestamp: str | int | None = None
    public_key: str | None = None

    def to_xml(self) -> bytes:
        """Build a caller-owned XML body for the encrypted preview request."""
        return build_ezviz_local_preview_request_body(
            operation_code=self.operation_code,
            channel=self.channel,
            receiver_info=self.receiver_info,
            receiver_info_ex=self.receiver_info_ex,
            identifier=self.identifier,
            is_encrypt=self.is_encrypt,
            udt=self.udt,
            nat=self.nat,
            port_guess_type=self.port_guess_type,
            timeout=self.timeout,
            heartbeat_interval=self.heartbeat_interval,
            authentication=self.authentication,
            uuid=self.uuid,
            timestamp=self.timestamp,
            public_key=self.public_key,
        )


@dataclass(frozen=True)
class HcNetSdkNoArgRequest:
    """Native no-argument HCNetSDK call shape."""

    api: str

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the no-argument native call name."""
        if self.api not in {
            HCNETSDK_CLEANUP,
            HCNETSDK_GET_LAST_ERROR,
            HCNETSDK_GET_SDK_VERSION,
            HCNETSDK_GET_SDK_BUILD_VERSION,
        }:
            raise PyEzvizError("HCNetSDK no-argument API is unsupported")
        return {"api": self.api}


@dataclass(frozen=True)
class HcNetSdkInitRequest:
    """Native ``NET_DVR_Init`` call shape."""

    playctrl_library: str | None = "libPlayCtrl.so"
    api: str = HCNETSDK_INIT

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for SDK initialization."""
        if self.api != HCNETSDK_INIT:
            raise PyEzvizError("HCNetSDK init API is unsupported")
        if self.playctrl_library is None:
            return {
                "api": self.api,
                "overload": "android-default-playctrl-library",
            }
        playctrl_library = self.playctrl_library.strip()
        if not playctrl_library or "\x00" in playctrl_library:
            raise PyEzvizError("HCNetSDK PlayCtrl library name is invalid")
        return {
            "api": self.api,
            "sPlayCtrlPath": playctrl_library,
        }


@dataclass(frozen=True)
class HcNetSdkSetConnectTimeRequest:
    """Native ``NET_DVR_SetConnectTime`` call shape used by the APK."""

    connect_time_ms: int = 5000
    retry_count: int = 3
    api: str = HCNETSDK_SET_CONNECT_TIME

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for setting SDK connect timeout."""
        if self.connect_time_ms < 0:
            raise PyEzvizError("HCNetSDK connect time must be non-negative")
        if self.retry_count < 0:
            raise PyEzvizError("HCNetSDK connect retry count must be non-negative")
        if self.api != HCNETSDK_SET_CONNECT_TIME:
            raise PyEzvizError("HCNetSDK connect-time API is unsupported")
        return {
            "api": self.api,
            "dwWaitTime": self.connect_time_ms,
            "dwTryTimes": self.retry_count,
        }


@dataclass(frozen=True)
class HcNetSdkGetErrorMsgRequest:
    """Native ``NET_DVR_GetErrorMsg`` call shape."""

    error_code: int | None = None
    api: str = HCNETSDK_GET_ERROR_MSG

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for resolving an HCNetSDK error."""
        if self.api != HCNETSDK_GET_ERROR_MSG:
            raise PyEzvizError("HCNetSDK error-message API is unsupported")
        hint: dict[str, Any] = {
            "api": self.api,
            "pErrorNo": "<INT_PTR>",
        }
        if self.error_code is not None:
            if self.error_code < 0:
                raise PyEzvizError("HCNetSDK error code must be non-negative")
            hint["intPointerValue"] = self.error_code
        return hint


@dataclass(frozen=True)
class HcNetSdkLogoutRequest:
    """Native ``NET_DVR_Logout_V30`` call shape."""

    login_id: int
    api: str = HCNETSDK_LOGOUT_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for logging out a local SDK session."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK logout requires a successful login id")
        if self.api != HCNETSDK_LOGOUT_V30:
            raise PyEzvizError("HCNetSDK logout API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
        }


@dataclass(frozen=True)
class HcNetSdkTime:
    """Native ``NET_DVR_TIME`` field set."""

    year: int
    month: int
    day: int
    hour: int = 0
    minute: int = 0
    second: int = 0

    @classmethod
    def from_datetime(cls, value: datetime) -> HcNetSdkTime:
        """Build a native time from a Python ``datetime``."""
        return cls(
            year=value.year,
            month=value.month,
            day=value.day,
            hour=value.hour,
            minute=value.minute,
            second=value.second,
        )

    @classmethod
    def from_date(cls, value: date, *, end_of_day: bool = False) -> HcNetSdkTime:
        """Build a native day boundary from a Python ``date``."""
        return cls(
            year=value.year,
            month=value.month,
            day=value.day,
            hour=23 if end_of_day else 0,
            minute=59 if end_of_day else 0,
            second=59 if end_of_day else 0,
        )

    def to_native_dict(self) -> dict[str, Any]:
        """Return the Java ``NET_DVR_TIME`` field names and values."""
        if self.year < 0:
            raise PyEzvizError("HCNetSDK time year must be non-negative")
        if not 1 <= self.month <= 12:
            raise PyEzvizError("HCNetSDK time month must be between 1 and 12")
        if not 1 <= self.day <= 31:
            raise PyEzvizError("HCNetSDK time day must be between 1 and 31")
        if not 0 <= self.hour <= 23:
            raise PyEzvizError("HCNetSDK time hour must be between 0 and 23")
        if not 0 <= self.minute <= 59:
            raise PyEzvizError("HCNetSDK time minute must be between 0 and 59")
        if not 0 <= self.second <= 59:
            raise PyEzvizError("HCNetSDK time second must be between 0 and 59")
        return {
            "structure": "NET_DVR_TIME",
            "fieldOrder": HCNETSDK_TIME_FIELD_ORDER,
            "dwYear": self.year,
            "dwMonth": self.month,
            "dwDay": self.day,
            "dwHour": self.hour,
            "dwMinute": self.minute,
            "dwSecond": self.second,
        }


@dataclass(frozen=True)
class HcNetSdkFileCond:
    """Native ``NET_DVR_FILECOND`` search condition used by LAN playback."""

    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    file_type: int = HCNETSDK_PLAYBACK_FILE_TYPE_ALL
    is_locked: int = HCNETSDK_PLAYBACK_LOCK_STATE_ALL
    use_card_no: int = 0
    card_number: str | bytes = b""

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_FILECOND`` field shape."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK file search channel must be non-negative")
        if self.file_type < 0:
            raise PyEzvizError("HCNetSDK file search file type must be non-negative")
        if self.is_locked < 0:
            raise PyEzvizError("HCNetSDK file search lock state must be non-negative")
        if self.use_card_no < 0:
            raise PyEzvizError("HCNetSDK file search card flag must be non-negative")
        card_number = _bounded_bytes(
            "HCNetSDK file search card number",
            self.card_number,
            32,
        )
        return {
            "structure": "NET_DVR_FILECOND",
            "fieldOrder": HCNETSDK_FILECOND_FIELD_ORDER,
            "lChannel": self.channel,
            "dwFileType": self.file_type,
            "dwIsLocked": self.is_locked,
            "dwUseCardNo": self.use_card_no,
            "sCardNumber": (card_number if include_buffers else _nul_stripped_text(card_number)),
            "sCardNumberBufferSize": 32,
            "struStartTime": self.start_time.to_native_dict(),
            "struStopTime": self.stop_time.to_native_dict(),
        }


@dataclass(frozen=True)
class HcNetSdkFindFileRequest:
    """Native ``NET_DVR_FindFile_V30`` call shape."""

    login_id: int
    file_cond: HcNetSdkFileCond
    api: str = HCNETSDK_FIND_FILE_V30

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for starting playback file search."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file search requires a successful login id")
        if self.api != HCNETSDK_FIND_FILE_V30:
            raise PyEzvizError("HCNetSDK find-file API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lpFindCond": self.file_cond.to_native_dict(include_buffers=include_buffers),
            "failureHandle": HCNETSDK_FIND_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkFindDataV30:
    """Native ``NET_DVR_FINDDATA_V30`` output-buffer shape."""

    file_name: str | bytes = b""
    start_time: HcNetSdkTime | None = None
    stop_time: HcNetSdkTime | None = None
    file_size: int = 0
    card_number: str | bytes = b""
    locked: int = 0
    file_type: int = 0

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_FINDDATA_V30`` field shape."""
        if self.file_size < 0:
            raise PyEzvizError("HCNetSDK find data file size must be non-negative")
        file_name = _bounded_bytes(
            "HCNetSDK find data file name",
            self.file_name,
            100,
        )
        card_number = _bounded_bytes(
            "HCNetSDK find data card number",
            self.card_number,
            32,
        )
        return {
            "structure": "NET_DVR_FINDDATA_V30",
            "fieldOrder": HCNETSDK_FINDDATA_V30_FIELD_ORDER,
            "sFileName": (file_name if include_buffers else _nul_stripped_text(file_name)),
            "sFileNameBufferSize": 100,
            "struStartTime": (self.start_time or HcNetSdkTime(0, 1, 1)).to_native_dict(),
            "struStopTime": (self.stop_time or HcNetSdkTime(0, 1, 1)).to_native_dict(),
            "dwFileSize": self.file_size,
            "sCardNum": (card_number if include_buffers else _nul_stripped_text(card_number)),
            "sCardNumBufferSize": 32,
            "byLocked": _byte_value("find data locked", self.locked),
            "byFileType": _byte_value("find data file type", self.file_type),
            "byResLength": 2,
        }


@dataclass(frozen=True)
class HcNetSdkFindNextFileRequest:
    """Native ``NET_DVR_FindNextFile_V30`` call shape."""

    find_handle: int
    find_data: HcNetSdkFindDataV30 | None = None
    api: str = HCNETSDK_FIND_NEXT_FILE_V30

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for polling playback file search."""
        if self.find_handle < 0:
            raise PyEzvizError("HCNetSDK find handle must be non-negative")
        if self.api != HCNETSDK_FIND_NEXT_FILE_V30:
            raise PyEzvizError("HCNetSDK find-next-file API is unsupported")
        find_data = self.find_data or HcNetSdkFindDataV30()
        return {
            "api": self.api,
            "lFindHandle": self.find_handle,
            "lpFindData": find_data.to_native_dict(include_buffers=include_buffers),
        }


@dataclass(frozen=True)
class HcNetSdkFindCloseRequest:
    """Native ``NET_DVR_FindClose_V30`` call shape."""

    find_handle: int
    api: str = HCNETSDK_FIND_CLOSE_V30

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for closing a playback file search."""
        if self.find_handle < 0:
            raise PyEzvizError("HCNetSDK find handle must be non-negative")
        if self.api != HCNETSDK_FIND_CLOSE_V30:
            raise PyEzvizError("HCNetSDK find-close API is unsupported")
        return {
            "api": self.api,
            "lFindHandle": self.find_handle,
        }


@dataclass(frozen=True)
class HcNetSdkPlayCond:
    """Native ``NET_DVR_PLAYCOND`` time-playback condition."""

    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    draw_frame: int = 0
    stream_type: int = 0
    stream_id: str | bytes = b""

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Java ``NET_DVR_PLAYCOND`` field shape."""
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK playback channel must be non-negative")
        stream_id = _bounded_bytes(
            "HCNetSDK playback stream id",
            self.stream_id,
            32,
        )
        return {
            "structure": "NET_DVR_PLAYCOND",
            "fieldOrder": HCNETSDK_PLAYCOND_FIELD_ORDER,
            "dwChannel": self.channel,
            "struStartTime": self.start_time.to_native_dict(),
            "struStopTime": self.stop_time.to_native_dict(),
            "byDrawFrame": _byte_value("playback draw-frame flag", self.draw_frame),
            "byStreamType": _byte_value("playback stream type", self.stream_type),
            "byStreamID": (stream_id if include_buffers else _nul_stripped_text(stream_id)),
            "byStreamIDBufferSize": 32,
            "byResLength": 30,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackByTimeRequest:
    """Native ``NET_DVR_PlayBackByTime_V40`` call shape."""

    login_id: int
    play_cond: HcNetSdkPlayCond
    api: str = HCNETSDK_PLAYBACK_BY_TIME_V40

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for time-based playback start."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK playback requires a successful login id")
        if self.api != HCNETSDK_PLAYBACK_BY_TIME_V40:
            raise PyEzvizError("HCNetSDK playback-by-time API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lpPlayCond": self.play_cond.to_native_dict(include_buffers=include_buffers),
            "failureHandle": HCNETSDK_PLAYBACK_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackControlRequest:
    """Native ``NET_DVR_PlayBackControl_V40`` call shape."""

    play_handle: int
    command: int
    in_buffer: str | bytes | None = None
    out_buffer_size: int = 0
    api: str = HCNETSDK_PLAYBACK_CONTROL_V40

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for playback control."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.command < 0:
            raise PyEzvizError("HCNetSDK playback control command must be non-negative")
        if self.out_buffer_size < 0:
            raise PyEzvizError("HCNetSDK playback output size must be non-negative")
        if self.api != HCNETSDK_PLAYBACK_CONTROL_V40:
            raise PyEzvizError("HCNetSDK playback-control API is unsupported")
        in_buffer = _optional_native_bytes(
            "HCNetSDK playback control input buffer",
            self.in_buffer,
        )
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "dwControlCode": int(self.command),
            "lpInBuffer": (
                in_buffer
                if include_buffers and in_buffer
                else ("<input-buffer>" if in_buffer else None)
            ),
            "dwInLen": len(in_buffer),
            "lpOutBuffer": "<output-buffer>" if self.out_buffer_size else None,
            "dwOutLen": self.out_buffer_size,
            "lpOutLen": "<DWORD_PTR>" if self.out_buffer_size else None,
        }


@dataclass(frozen=True)
class HcNetSdkStopPlayBackRequest:
    """Native ``NET_DVR_StopPlayBack`` call shape."""

    play_handle: int
    api: str = HCNETSDK_STOP_PLAYBACK

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for stopping playback."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api != HCNETSDK_STOP_PLAYBACK:
            raise PyEzvizError("HCNetSDK stop-playback API is unsupported")
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackCaptureFileRequest:
    """Native ``NET_DVR_PlayBackCaptureFile`` call shape."""

    play_handle: int
    saved_file_name: str | bytes
    api: str = HCNETSDK_PLAYBACK_CAPTURE_FILE

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for a playback snapshot."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api != HCNETSDK_PLAYBACK_CAPTURE_FILE:
            raise PyEzvizError("HCNetSDK playback-capture API is unsupported")
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "sFileName": _native_path_value(
                "playback capture file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
        }


@dataclass(frozen=True)
class HcNetSdkPlayDataCallbackRequest:
    """Native ``NET_DVR_SetPlayDataCallBack`` / ``V40`` call shape."""

    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = HCNETSDK_SET_PLAY_DATA_CALLBACK

    @property
    def is_v40(self) -> bool:
        """Return whether this is the V40 callback setter variant."""
        return self.api == HCNETSDK_SET_PLAY_DATA_CALLBACK_V40

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for registering playback data callbacks."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.api not in {
            HCNETSDK_SET_PLAY_DATA_CALLBACK,
            HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
        }:
            raise PyEzvizError("HCNetSDK playback data callback API is unsupported")
        if self.is_v40:
            return {
                "api": self.api,
                "lPlayHandle": self.play_handle,
                "fPlayDataCallBack_V40": self.callback or "<PlayDataCallBack_V40>",
                "pUser": self.user_data if self.user_data is not None else None,
                "callbackSignature": (
                    "void(int playHandle, int dataType, byte* buffer, uint length, void* user)"
                ),
            }
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "fPlayDataCallBack": self.callback or "<PlayDataCallBack>",
            "dwUser": self.user_data if self.user_data is not None else 0,
            "callbackSignature": (
                "void(int playHandle, uint dataType, byte* buffer, uint length, uint user)"
            ),
        }


@dataclass(frozen=True)
class HcNetSdkPlaybackCallbackRequest:
    """Native playback response / elementary-stream callback setter shape."""

    play_handle: int
    callback: str | None = None
    user_data: str | int | None = None
    api: str = HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for playback callback registration."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        callback_names = {
            HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK: (
                "fPlaybackResponseCallBack",
                "<PlaybackResponseCallBack>",
            ),
            HCNETSDK_SET_PLAYBACK_ES_CALLBACK: (
                "fPlayBackESCallBack",
                "<PlayBackESCallBack>",
            ),
        }
        if self.api not in callback_names:
            raise PyEzvizError("HCNetSDK playback callback API is unsupported")
        arg_name, placeholder = callback_names[self.api]
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            arg_name: self.callback or placeholder,
            "pUser": self.user_data if self.user_data is not None else None,
        }


@dataclass(frozen=True)
class HcNetSdkPlayBackSecretKeyRequest:
    """Native ``NET_DVR_SetPlayBackSecretKey`` call shape."""

    play_handle: int
    secret_key: str | bytes
    secret_key_type: int = HCNETSDK_SECRET_KEY_TYPE_AES
    api: str = HCNETSDK_SET_PLAYBACK_SECRET_KEY

    def to_native_args_hint(
        self,
        *,
        include_secret: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for setting a playback stream key."""
        if self.play_handle < 0:
            raise PyEzvizError("HCNetSDK playback handle must be non-negative")
        if self.secret_key_type < 0:
            raise PyEzvizError("HCNetSDK playback secret-key type must be non-negative")
        if self.api != HCNETSDK_SET_PLAYBACK_SECRET_KEY:
            raise PyEzvizError("HCNetSDK playback secret-key API is unsupported")
        secret_key = _native_secret_key_bytes(
            "HCNetSDK playback secret key",
            self.secret_key,
        )
        return {
            "api": self.api,
            "lPlayHandle": self.play_handle,
            "dwSecretKeyType": self.secret_key_type,
            "pSecretKey": secret_key if include_secret else "<secret-key>",
            "dwSecretKeyLen": len(secret_key),
        }


@dataclass(frozen=True)
class HcNetSdkGetFileByNameRequest:
    """Native ``NET_DVR_GetFileByName`` download-start call shape."""

    login_id: int
    dvr_file_name: str | bytes
    saved_file_name: str | bytes
    api: str = HCNETSDK_GET_FILE_BY_NAME

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for file-name based download."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file download requires a successful login id")
        if self.api != HCNETSDK_GET_FILE_BY_NAME:
            raise PyEzvizError("HCNetSDK get-file-by-name API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "sDVRFileName": _native_path_value(
                "DVR file name",
                self.dvr_file_name,
                include_buffers=include_buffers,
            ),
            "sSavedFileName": _native_path_value(
                "saved file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
            "failureHandle": HCNETSDK_GET_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkGetFileByTimeRequest:
    """Native ``NET_DVR_GetFileByTime`` download-start call shape."""

    login_id: int
    channel: int
    start_time: HcNetSdkTime
    stop_time: HcNetSdkTime
    saved_file_name: str | bytes
    api: str = HCNETSDK_GET_FILE_BY_TIME

    def to_native_args_hint(
        self,
        *,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return native argument names for time-based download."""
        if self.login_id < 0:
            raise PyEzvizError("HCNetSDK file download requires a successful login id")
        if self.channel < 0:
            raise PyEzvizError("HCNetSDK file download channel must be non-negative")
        if self.api != HCNETSDK_GET_FILE_BY_TIME:
            raise PyEzvizError("HCNetSDK get-file-by-time API is unsupported")
        return {
            "api": self.api,
            "lUserID": self.login_id,
            "lChannel": self.channel,
            "lpStartTime": self.start_time.to_native_dict(),
            "lpStopTime": self.stop_time.to_native_dict(),
            "sSavedFileName": _native_path_value(
                "saved file name",
                self.saved_file_name,
                include_buffers=include_buffers,
            ),
            "failureHandle": HCNETSDK_GET_FILE_FAILED,
        }


@dataclass(frozen=True)
class HcNetSdkStopGetFileRequest:
    """Native ``NET_DVR_StopGetFile`` call shape."""

    file_handle: int
    api: str = HCNETSDK_STOP_GET_FILE

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for stopping a file download."""
        if self.file_handle < 0:
            raise PyEzvizError("HCNetSDK file handle must be non-negative")
        if self.api != HCNETSDK_STOP_GET_FILE:
            raise PyEzvizError("HCNetSDK stop-get-file API is unsupported")
        return {
            "api": self.api,
            "lFileHandle": self.file_handle,
        }


@dataclass(frozen=True)
class HcNetSdkGetDownloadPosRequest:
    """Native ``NET_DVR_GetDownloadPos`` call shape."""

    file_handle: int
    api: str = HCNETSDK_GET_DOWNLOAD_POS

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for polling download progress."""
        if self.file_handle < 0:
            raise PyEzvizError("HCNetSDK file handle must be non-negative")
        if self.api != HCNETSDK_GET_DOWNLOAD_POS:
            raise PyEzvizError("HCNetSDK get-download-position API is unsupported")
        return {
            "api": self.api,
            "lFileHandle": self.file_handle,
        }


@dataclass(frozen=True)
class SadpDeviceInfo:
    """Parsed SADP response fields."""

    fields: Mapping[str, str]

    @property
    def serial(self) -> str | None:
        """Return a likely device serial field if present."""
        return self.fields.get("DeviceSN") or self.fields.get("SerialNO")

    @property
    def ipv4_address(self) -> str | None:
        """Return the SADP IPv4 address field if present."""
        return self.fields.get("IPv4Address") or self.fields.get("IPAddress")

    @property
    def command_port(self) -> int | None:
        """Return the SDK command/server port if SADP reported one."""
        value = (
            self.fields.get("CommandPort")
            or self.fields.get("DevicePort")
            or self.fields.get("Port")
        )
        return int(value) if value and value.isdigit() else None


@dataclass(frozen=True)
class SadpActivateDeviceRequest:
    """Android ``SADP_ActivateDevice`` call shape."""

    serial: str
    password: str
    api: str = SADP_ACTIVATE_DEVICE

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
    ) -> dict[str, Any]:
        """Return the native argument names for a local SADP bridge."""
        serial = self.serial.strip()
        if not serial:
            raise PyEzvizError("SADP activation serial cannot be empty")
        password = self.password
        if not password:
            raise PyEzvizError("SADP activation password cannot be empty")
        return {
            "api": self.api,
            "serial": serial,
            "password": password if include_password else "<password>",
            "passwordLength": len(password.encode("utf-8")),
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


@dataclass(frozen=True)
class SadpDeviceNetParam:
    """Android ``SADP_DEV_NET_PARAM`` field updates used by the RN module."""

    ipv4_address: str
    ipv4_subnet_mask: str
    ipv4_gateway: str
    dhcp_enabled: int | bool
    http_port: int
    command_port: int
    ipv6_address: str = ""
    ipv6_gateway: str = ""
    ipv6_mask_len: int = 0

    def to_native_dict(self, *, include_buffers: bool = False) -> dict[str, Any]:
        """Return the Android SADP_DEV_NET_PARAM field values."""
        ipv4_address = _sadp_string_bytes("IPv4 address", self.ipv4_address, 16)
        ipv4_subnet_mask = _sadp_string_bytes("IPv4 subnet mask", self.ipv4_subnet_mask, 16)
        ipv4_gateway = _sadp_string_bytes("IPv4 gateway", self.ipv4_gateway, 16)
        ipv6_address = _sadp_string_bytes("IPv6 address", self.ipv6_address, 128, allow_empty=True)
        ipv6_gateway = _sadp_string_bytes("IPv6 gateway", self.ipv6_gateway, 128, allow_empty=True)
        return {
            "structure": "SADP_DEV_NET_PARAM",
            "androidFields": SADP_DEV_NET_PARAM_ANDROID_FIELDS,
            "jnaFieldOrder": SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
            "szIPv4Address": (ipv4_address if include_buffers else self.ipv4_address),
            "szIPv4SubnetMask": (ipv4_subnet_mask if include_buffers else self.ipv4_subnet_mask),
            "szIPv4Gateway": (ipv4_gateway if include_buffers else self.ipv4_gateway),
            "szIPv6Address": (ipv6_address if include_buffers else self.ipv6_address),
            "szIPv6Gateway": (ipv6_gateway if include_buffers else self.ipv6_gateway),
            "byDhcpEnabled": _byte_value("SADP DHCP enabled", int(self.dhcp_enabled)),
            "byIPv6MaskLen": _byte_value("SADP IPv6 mask length", self.ipv6_mask_len),
            "wHttpPort": _port_value("SADP HTTP port", self.http_port),
            "wPort": _port_value("SADP command port", self.command_port),
        }


@dataclass(frozen=True)
class SadpModifyDeviceNetParamRequest:
    """Android ``SADP_ModifyDeviceNetParam`` call shape."""

    mac: str
    password: str
    net_param: SadpDeviceNetParam
    api: str = SADP_MODIFY_DEVICE_NET_PARAM

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise PyEzvizError("SADP MAC address cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP network password cannot be empty")
        return {
            "api": self.api,
            "mac": mac,
            "password": self.password if include_password else "<password>",
            "passwordLength": len(self.password.encode("utf-8")),
            "netParam": self.net_param.to_native_dict(include_buffers=include_buffers),
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


@dataclass(frozen=True)
class SadpDeviceRetNetParam:
    """Native ``SADP_DEV_RET_NET_PARAM`` output-buffer shape."""

    retry_modify_time: int | None = None
    surplus_lock_time: int | None = None

    def to_native_dict(self) -> dict[str, Any]:
        """Return the JNA field names for V40 network-edit failure detail."""
        result: dict[str, Any] = {
            "structure": "SADP_DEV_RET_NET_PARAM",
            "fieldOrder": SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
            "dwSize": "sizeof(SADP_DEV_RET_NET_PARAM)",
            "byResLength": 126,
        }
        if self.retry_modify_time is not None:
            result["byRetryModifyTime"] = _byte_value(
                "SADP retry modify time", self.retry_modify_time
            )
        if self.surplus_lock_time is not None:
            result["bySurplusLockTime"] = _byte_value(
                "SADP surplus lock time", self.surplus_lock_time
            )
        return result


@dataclass(frozen=True)
class SadpModifyDeviceNetParamV40Request:
    """Android ``SADP_ModifyDeviceNetParam_V40`` call shape."""

    mac: str
    password: str
    net_param: SadpDeviceNetParam
    ret_net_param: SadpDeviceRetNetParam | None = None
    api: str = SADP_MODIFY_DEVICE_NET_PARAM_V40

    def to_native_args_hint(
        self,
        *,
        include_password: bool = False,
        include_buffers: bool = False,
    ) -> dict[str, Any]:
        """Return the V40 native argument names for a local SADP bridge."""
        mac = self.mac.strip()
        if not mac:
            raise PyEzvizError("SADP MAC address cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP network password cannot be empty")
        if self.api != SADP_MODIFY_DEVICE_NET_PARAM_V40:
            raise PyEzvizError("SADP V40 network-param API is unsupported")
        ret_net_param = self.ret_net_param or SadpDeviceRetNetParam()
        return {
            "api": self.api,
            "mac": mac,
            "password": self.password if include_password else "<password>",
            "passwordLength": len(self.password.encode("utf-8")),
            "netParam": self.net_param.to_native_dict(include_buffers=include_buffers),
            "lpRetNetParam": ret_net_param.to_native_dict(),
            "dwOutBuffSize": SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
            "lastErrorApi": SADP_GET_LAST_ERROR,
        }


@dataclass(frozen=True)
class SadpNoArgRequest:
    """Native no-argument SADP call shape."""

    api: str

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return the no-argument SADP call name."""
        if self.api not in {
            SADP_GET_LAST_ERROR,
            SADP_GET_VERSION,
            SADP_STOP,
            SADP_CLEARUP,
            SADP_SEND_INQUIRY,
        }:
            raise PyEzvizError("SADP no-argument API is unsupported")
        return {"api": self.api}


@dataclass(frozen=True)
class SadpStartRequest:
    """Native ``SADP_Start_V30`` / ``V40`` call shape."""

    version: int = 40
    install_npf: int | bool = 0
    callback: str | None = None
    user_data: str | None = None

    def to_native_args_hint(self) -> dict[str, Any]:
        """Return native argument names for starting SADP discovery."""
        if self.version not in {30, 40}:
            raise PyEzvizError("SADP start version must be 30 or 40")
        install_npf = _byte_value("SADP install NPF flag", int(self.install_npf))
        if self.version == 30:
            return {
                "api": SADP_START_V30,
                "pDeviceFindCallBack": self.callback or "<DeviceFindCallBack>",
                "bInstallNPF": install_npf,
                "pUserData": self.user_data or "<Pointer.NULL>",
            }
        return {
            "api": SADP_START_V40,
            "pDeviceFindCallBack_v40": (self.callback or "<DeviceFindCallBack_V40>"),
            "bInstallNPF": install_npf,
            "pUserData": self.user_data or "<Pointer.NULL>",
        }


@dataclass(frozen=True)
class SadpSetLogToFileRequest:
    """Native ``SADP_SetLogToFile`` call shape."""

    log_level: int
    log_dir: str | bytes
    auto_delete: int | bool = True
    api: str = SADP_SET_LOG_TO_FILE

    def to_native_args_hint(self, *, include_buffer: bool = False) -> dict[str, Any]:
        """Return native argument names for SADP file logging."""
        if self.api != SADP_SET_LOG_TO_FILE:
            raise PyEzvizError("SADP log API is unsupported")
        if self.log_level < 0:
            raise PyEzvizError("SADP log level must be non-negative")
        log_dir = _sadp_string_bytes("log directory", self.log_dir, 4096)
        if SADP_NUL_BYTE in log_dir:
            raise PyEzvizError("SADP log directory cannot contain NUL bytes")
        return {
            "api": self.api,
            "nLogLevel": self.log_level,
            "strLogDir": (
                log_dir + SADP_NUL_BYTE
                if include_buffer
                else log_dir.decode("utf-8", errors="replace")
            ),
            "bAutoDel": _byte_value("SADP auto-delete flag", int(self.auto_delete)),
        }


@dataclass(frozen=True)
class SadpBatchResult:
    """RN-style batch operation result for SADP activation/network edits."""

    identifier: str
    password: str
    code: int
    error: int
    identifier_key: str

    def to_rn_dict(self, *, include_password: bool = True) -> dict[str, Any]:
        """Return the map pushed into the React Native result array."""
        if self.identifier_key not in {"serial", "mac"}:
            raise PyEzvizError("SADP batch result identifier key is unsupported")
        identifier = self.identifier.strip()
        if not identifier:
            raise PyEzvizError("SADP batch result identifier cannot be empty")
        if not self.password:
            raise PyEzvizError("SADP batch result password cannot be empty")
        return {
            self.identifier_key: identifier,
            "password": self.password if include_password else "<password>",
            "code": self.code,
            "error": self.error,
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


def hcnetsdk_real_data_type_is_media(data_type: int) -> bool:
    """Return whether a real-play callback type can carry media payloads."""
    return data_type in (
        HcNetSdkRealDataType.STREAM_DATA,
        HcNetSdkRealDataType.AUDIO_STREAM_DATA,
        HcNetSdkRealDataType.PRIVATE_DATA,
    )


def hcnetsdk_real_play_request(
    login_id: int,
    *,
    channel_number: int = 1,
    link_mode: int = 0,
    blocked: bool = False,
    multicast_ip: str = "",
) -> HcNetSdkRealPlayRequest:
    """Build the APK-observed ``EZ_NET_DVR_RealPlay_V30`` argument model."""
    return HcNetSdkRealPlayRequest(
        login_id=login_id,
        client_info=HcNetSdkClientInfo(
            channel=channel_number,
            link_mode=link_mode,
            multicast_ip=multicast_ip,
        ),
        blocked=blocked,
    )


def classify_hcnetsdk_real_data_payload(data: bytes) -> str:
    """Classify HCNetSDK callback bytes without decoding or exposing content."""
    if not data:
        return "empty"
    prefixes = (
        (HCNETSDK_MPEG_PS_PACK_HEADER, "mpeg_ps"),
        (HCNETSDK_MPEG_START_CODE_PREFIX, "mpeg_ps_start"),
        (bytes((HCNETSDK_MPEG_TS_SYNC_BYTE,)), "mpeg_ts"),
        (HCNETSDK_HKMI_PREFIX, "hik_hkmi"),
        (HCNETSDK_HIK_PRIVATE_PREFIX, "hik_private"),
    )
    for prefix, kind in prefixes:
        if data.startswith(prefix):
            return kind
    return "unknown"


def build_hcnetsdk_tcp_frame(
    body: bytes = b"",
    *,
    field_4: int = 0,
    field_8: int = 0,
    field_12: int = 0,
) -> bytes:
    """Build the generic observed HCNetSDK command-port frame wrapper."""
    header = HcNetSdkTcpFrameHeader(
        total_length=HCNETSDK_TCP_HEADER_LENGTH + len(body),
        field_4=field_4,
        field_8=field_8,
        field_12=field_12,
    )
    return HcNetSdkTcpFrame(header=header, body=body).to_bytes()


def hcnetsdk_command_port_auth_word(
    *,
    session_id: bytes,
    auth_seed: int,
    command_id: int,
    key: bytes,
    addend: int | None = None,
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
) -> int:
    """Return the native HCNetSDK port-8000 post-login command auth word.

    ``session_id`` is the network-order four-byte id returned in the login
    response and reused in command bodies. Native ``libHCCore.so`` reverses it
    into a host-order word before the auth routine, uses the first 16 challenge
    bytes as a four-round AES-128 key, folds the 16-byte result down to one
    little-endian word, then adds the session-derived time/addend word used in
    the command header.
    """
    if len(session_id) != 4:
        raise PyEzvizError("HCNetSDK command-port session id must be 4 bytes")
    if len(key) < HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth key must be at least 16 bytes")
    if len(mask_seed) < HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth mask seed must be 6 bytes")
    session_word = int.from_bytes(session_id, "big")
    input_word = (
        auth_seed + (command_id * 2) + _hcnetsdk_command_port_auth_mask(session_word, mask_seed)
    ) & 0xFFFFFFFF
    transformed = _hcnetsdk_command_port_four_round_aes(
        input_word.to_bytes(4, "little") + (b"\x00" * 12),
        key[:HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH],
    )
    folded = bytes(
        transformed[index]
        ^ transformed[index + 4]
        ^ transformed[index + 8]
        ^ transformed[index + 12]
        for index in range(4)
    )
    return (
        int.from_bytes(folded, "little") + (session_word if addend is None else addend)
    ) & 0xFFFFFFFF


def hcnetsdk_command_port_control_frame(
    *,
    session_id: bytes,
    auth_seed: int,
    command_id: int,
    key: bytes,
    local_ip: str,
    body_tail: bytes = b"",
    addend: int | None = None,
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
) -> bytes:
    """Build one generated post-login HCNetSDK port-8000 control frame.

    The frame body format observed in native traces is the client LAN IPv4 word
    in little-endian byte order, the four-byte network-order login session id,
    eight reserved zero bytes, and then the command-specific tail. The auth word
    uses the same network-order session id returned by login.
    """
    if len(session_id) != 4:
        raise PyEzvizError("HCNetSDK command-port session id must be 4 bytes")
    body = _hcnetsdk_command_port_local_ip_word(local_ip) + session_id + (b"\x00" * 8) + body_tail
    return build_hcnetsdk_tcp_frame(
        body,
        field_4=HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
        field_8=hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=command_id,
            key=key,
            addend=addend,
            mask_seed=mask_seed,
        ),
        field_12=command_id,
    )


def hcnetsdk_command_port_play_login_body_tail_for_today(
    body_tail: bytes,
    *,
    today: date | None = None,
) -> bytes:
    """Refresh native play-login date words in a captured ``0x111040`` tail."""
    if len(body_tail) != 148:
        raise PyEzvizError("HCNetSDK play-login body tail transform requires a 148-byte tail")
    current = today or date.today()
    patched = bytearray(body_tail)
    values = {
        36: current.year,
        40: current.month,
        44: current.day,
        60: current.year,
        64: current.month,
        68: current.day,
        72: 23,
        76: 59,
        80: 59,
    }
    for offset, value in values.items():
        patched[offset : offset + 4] = value.to_bytes(4, "big")
    return bytes(patched)


def hcnetsdk_command_candidate_role(candidate: int | None) -> str | None:
    """Return the current role label for an observed command candidate.

    The names are trace-derived labels, not a complete HCNetSDK command table.
    They are useful for reducing redacted captures while the underlying
    encrypted request format is still being mapped.
    """
    if candidate == HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN:
        return "settings_login"
    if candidate == HCNETSDK_COMMAND_CANDIDATE_CONTROL:
        return "control"
    return None


def ezviz_native_video_level(video_level: int) -> int:
    """Mirror ``Utils.convertVideoLevel()`` before writing ``iVideoLevel``."""
    if video_level == -1:
        return 3
    if video_level == 0:
        return 2
    if video_level == 1:
        return 1
    if video_level == 2:
        return 0
    if video_level == 3:
        return 4
    return 5


def build_ezviz_local_preview_request_body(  # noqa: PLR0913
    *,
    operation_code: str,
    channel: int,
    receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs,
    receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs,
    identifier: str | None = None,
    is_encrypt: str | int = "TRUE",
    udt: int | None = None,
    nat: int | None = None,
    port_guess_type: int | None = None,
    timeout: int | None = None,
    heartbeat_interval: int | None = None,
    authentication: str | EzvizLocalAuthenticationAttrs | None = None,
    uuid: str | None = None,
    timestamp: str | int | None = None,
    public_key: str | None = None,
) -> bytes:
    """Build the plaintext XML body for the observed 0x2011 request.

    The caller must supply values obtained through their own credential/source
    path. This helper only gives the confirmed tag order and escaping.
    """
    if channel < 0:
        raise PyEzvizError("EZVIZ local preview channel must be non-negative")
    return _build_local_sdk_request_xml(
        (
            ("OperationCode", operation_code),
            ("Channel", channel),
            ("Identifier", identifier),
            ("ReceiverInfo", receiver_info),
            ("IsEncrypt", is_encrypt),
            ("Udt", udt),
            ("Nat", nat),
            ("PortGuessType", port_guess_type),
            ("Timeout", timeout),
            ("HeartbeatInterval", heartbeat_interval),
            ("ReceiverInfoEx", receiver_info_ex),
            ("Authentication", authentication),
            ("Uuid", uuid),
            ("Timestamp", timestamp),
            ("PublicKey", public_key),
        )
    )


def ezviz_local_sdk_iv(serial: str, operation_code: str) -> bytes:
    """Build the AES-CBC IV used by EZVIZ local-control CAS frames."""
    iv = f"{serial}{operation_code}".encode("latin1")
    if len(iv) != EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError("EZVIZ local SDK IV must be 16 bytes from serial + operation code")
    return iv


def hcnetsdk_command_port_response_payload(
    response: HcNetSdkTcpFrame | bytes,
) -> bytes:
    """Return a textual JSON/XML payload from a command-port response.

    Native command-port responses may include leading binary or NUL padding
    before the string output buffer. Keep the rule intentionally narrow so
    binary command responses remain available to lower-level callers.
    """
    body = response.body if isinstance(response, HcNetSdkTcpFrame) else response
    if not body:
        return b""
    candidates: list[tuple[int, bytes]] = []
    for marker in (b"<?xml", b"{", b"[", HCNETSDK_XML_MARKER):
        offset = body.find(marker)
        if offset >= 0:
            candidates.append((offset, body[offset:].split(b"\x00", 1)[0].strip()))
    for _offset, candidate in sorted(candidates, key=lambda item: item[0]):
        if not candidate:
            continue
        if candidate[:1] in {b"{", b"["}:
            try:
                json.loads(candidate.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                continue
            return candidate
        if candidate.startswith(b"<?xml") or (
            candidate[:1] == HCNETSDK_XML_MARKER and len(candidate) > 1 and candidate[1:2].isalpha()
        ):
            return candidate
    return body.split(b"\x00", 1)[0].strip()


def _mapping_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _mapping_int(
    data: Mapping[str, Any],
    key: str,
    *,
    default: int | None,
    zero_is_missing: bool = False,
) -> int | None:
    value = data.get(key)
    if value is None:
        return default
    if isinstance(value, int):
        return default if zero_is_missing and value == 0 else value
    if isinstance(value, str):
        try:
            int_value = int(value)
        except ValueError:
            return default
        return default if zero_is_missing and int_value == 0 else int_value
    return default


def _stdxml_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise PyEzvizError(f"HCNetSDK STDXML {label} must be bytes or string")
    return value.encode("utf-8")


def _optional_native_bytes(label: str, value: str | bytes | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise PyEzvizError(f"{label} must be bytes or string")


def _native_secret_key_bytes(label: str, value: str | bytes) -> bytes:
    raw = _optional_native_bytes(label, value)
    if not raw:
        raise PyEzvizError(f"{label} cannot be empty")
    if len(raw) > 4096:
        raise PyEzvizError(f"{label} must be at most 4096 bytes")
    return raw


def _native_path_value(
    label: str,
    value: str | bytes,
    *,
    include_buffers: bool = False,
) -> str | bytes:
    raw = _optional_native_bytes(f"HCNetSDK {label}", value)
    if not raw:
        raise PyEzvizError(f"HCNetSDK {label} cannot be empty")
    if SADP_NUL_BYTE in raw:
        raise PyEzvizError(f"HCNetSDK {label} cannot contain NUL bytes")
    if include_buffers:
        return raw
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise PyEzvizError(f"HCNetSDK {label} must be UTF-8") from err


def _bounded_bytes(
    label: str,
    value: str | bytes,
    limit: int,
    *,
    truncate: bool = False,
) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise PyEzvizError(f"EZVIZ LAN {label} must be bytes or string")
    if len(raw) <= limit:
        return raw
    if truncate:
        return raw[:limit]
    raise PyEzvizError(f"EZVIZ LAN {label} must be at most {limit} bytes")


def _sadp_string_bytes(
    label: str,
    value: str | bytes,
    limit: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise PyEzvizError(f"SADP {label} must be bytes or string")
    if not raw and not allow_empty:
        raise PyEzvizError(f"SADP {label} cannot be empty")
    if len(raw) > limit:
        raise PyEzvizError(f"SADP {label} must be at most {limit} bytes")
    return raw


def _optional_raw_byte(raw: bytes, offset: int) -> int | None:
    return raw[offset] if len(raw) > offset else None


def _optional_raw_u16_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 2:
        return None
    return int.from_bytes(raw[offset : offset + 2], "big")


def _optional_raw_u32_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 4:
        return None
    return int.from_bytes(raw[offset : offset + 4], "big")


def _optional_raw_u16_be_pair(
    raw: bytes,
    first_offset: int,
    second_offset: int,
) -> tuple[int, int] | None:
    first = _optional_raw_u16_be(raw, first_offset)
    second = _optional_raw_u16_be(raw, second_offset)
    if first is None or second is None:
        return None
    return first, second


def _optional_raw_byte_triplet(
    raw: bytes,
    first_offset: int,
    second_offset: int,
    third_offset: int,
) -> tuple[int, int, int] | None:
    if len(raw) <= max(first_offset, second_offset, third_offset):
        return None
    return raw[first_offset], raw[second_offset], raw[third_offset]


def _byte_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFF:
        raise PyEzvizError(f"EZVIZ LAN {label} must fit in one byte")
    return value


def _word_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFFFF:
        raise PyEzvizError(f"EZVIZ LAN {label} must fit in one unsigned word")
    return value


def _port_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFFFF:
        raise PyEzvizError(f"{label} must be between 0 and 65535")
    return value


def _nul_stripped_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8") if isinstance(value, bytes) else value
    return text.replace("\x00", "").strip()


def _device_ability_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise PyEzvizError(f"HCNetSDK device ability {label} must be bytes or string")
    return value.encode("utf-8")


def _ability_option_tuple(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(option.strip() for option in value.split(",") if option.strip())


def _hcnetsdk_command_port_local_ip_word(local_ip: str) -> bytes:
    try:
        return ipaddress.IPv4Address(local_ip).packed[::-1]
    except ipaddress.AddressValueError as err:
        raise PyEzvizError("HCNetSDK command-port local IP must be an IPv4 address") from err


def _hcnetsdk_command_port_auth_mask(session_word: int, mask_seed: bytes) -> int:
    """Return the small native mask term mixed into command auth input."""
    return sum(
        mask_seed[index] & ((session_word >> (5 * index)) & 0xFF)
        for index in range(HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH)
    )


def _hcnetsdk_command_port_four_round_aes(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block with the SDK's four-round AES-128 variant."""
    if len(block) != 16:
        raise PyEzvizError("HCNetSDK command-port auth block must be 16 bytes")
    if len(key) != HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH:
        raise PyEzvizError("HCNetSDK command-port auth key must be 16 bytes")

    round_keys = _hcnetsdk_aes128_round_keys(key, rounds=4)
    state = _hcnetsdk_aes_add_round_key(block, round_keys[0])
    for round_index in range(1, 4):
        state = _hcnetsdk_aes_sub_bytes(state)
        state = _hcnetsdk_aes_shift_rows(state)
        state = _hcnetsdk_aes_mix_columns(state)
        state = _hcnetsdk_aes_add_round_key(state, round_keys[round_index])
    state = _hcnetsdk_aes_sub_bytes(state)
    state = _hcnetsdk_aes_shift_rows(state)
    return _hcnetsdk_aes_add_round_key(state, round_keys[4])


def _hcnetsdk_aes128_round_keys(key: bytes, *, rounds: int) -> tuple[bytes, ...]:
    """Return AES-128 round keys, truncated to the native command-auth rounds."""
    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    while len(words) < 4 * (rounds + 1):
        word = words[-1][:]
        if len(words) % 4 == 0:
            word = word[1:] + word[:1]
            word = [_AES_SBOX[item] for item in word]
            word[0] ^= _AES_RCON[(len(words) // 4) - 1]
        words.append([left ^ right for left, right in zip(words[-4], word, strict=True)])
    expanded = bytes(item for word in words for item in word)
    return tuple(expanded[index : index + 16] for index in range(0, 16 * (rounds + 1), 16))


def _hcnetsdk_aes_add_round_key(state: bytes, round_key: bytes) -> bytes:
    return bytes(left ^ right for left, right in zip(state, round_key, strict=True))


def _hcnetsdk_aes_sub_bytes(state: bytes) -> bytes:
    return bytes(_AES_SBOX[item] for item in state)


def _hcnetsdk_aes_shift_rows(state: bytes) -> bytes:
    return bytes(
        (
            state[0],
            state[5],
            state[10],
            state[15],
            state[4],
            state[9],
            state[14],
            state[3],
            state[8],
            state[13],
            state[2],
            state[7],
            state[12],
            state[1],
            state[6],
            state[11],
        )
    )


def _hcnetsdk_aes_xtime(value: int) -> int:
    shifted = value << 1
    if value & 0x80:
        shifted ^= 0x1B
    return shifted & 0xFF


def _hcnetsdk_aes_mix_columns(state: bytes) -> bytes:
    mixed = bytearray()
    for column_index in range(0, 16, 4):
        column = state[column_index : column_index + 4]
        doubled = [_hcnetsdk_aes_xtime(item) for item in column]
        mixed.extend(
            (
                doubled[0] ^ column[3] ^ column[2] ^ doubled[1] ^ column[1],
                doubled[1] ^ column[0] ^ column[3] ^ doubled[2] ^ column[2],
                doubled[2] ^ column[1] ^ column[0] ^ doubled[3] ^ column[3],
                doubled[3] ^ column[2] ^ column[1] ^ doubled[0] ^ column[0],
            )
        )
    return bytes(mixed)


def _build_local_sdk_request_xml(
    fields: tuple[
        tuple[
            str,
            str
            | int
            | EzvizLocalReceiverInfo
            | EzvizLocalReceiverInfoAttrs
            | EzvizLocalReceiverInfoEx
            | EzvizLocalReceiverInfoExAttrs
            | EzvizLocalAuthenticationAttrs
            | None,
        ],
        ...,
    ],
) -> bytes:
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Request>"]
    for tag, value in fields:
        if value is None:
            continue
        if isinstance(value, (EzvizLocalReceiverInfo, EzvizLocalReceiverInfoAttrs)):
            if tag != "ReceiverInfo":
                raise PyEzvizError("Structured receiver info must use ReceiverInfo tag")
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, (EzvizLocalReceiverInfoEx, EzvizLocalReceiverInfoExAttrs)):
            if tag != "ReceiverInfoEx":
                raise PyEzvizError("Structured receiver info ex must use ReceiverInfoEx tag")
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, EzvizLocalAuthenticationAttrs):
            if tag != "Authentication":
                raise PyEzvizError("Structured authentication must use Authentication tag")
            lines.extend(value.xml_lines())
            continue
        lines.append(f"\t<{tag}>{_xml_escape(str(value))}</{tag}>")
    lines.append("</Request>")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _xml_attrs(fields: Iterable[tuple[str, str | int]]) -> str:
    return " ".join(f'{tag}="{_xml_escape(str(value))}"' for tag, value in fields)


def _local_sdk_aes_bytes(label: str, value: bytes | str) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else value
    if len(data) == EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        return data
    if isinstance(value, str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except binascii.Error:
            decoded = b""
        if len(decoded) == EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
            return decoded
    raise PyEzvizError(f"EZVIZ local SDK AES {label} must be 16 bytes")
