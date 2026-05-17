"""Experimental helpers for Hikvision HCNetSDK-style LAN paths.

The EZVIZ Android app uses two different device-control families:

* CAS cloud commands for app-style operations such as defence/PTZ/switch.
* Hikvision HCNetSDK LAN operations for local device management.

This module intentionally starts with the parts that are known from APK
inspection and safe to exercise: endpoint metadata, read-oriented SDK command
IDs, light port classification, and SADP XML response parsing. It does not
attempt to brute-force credentials or send state-changing device commands.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import json
import math
import re
import socket
import ssl
from typing import Any, cast
import xml.etree.ElementTree as ET

from Crypto.Cipher import AES

from .exceptions import PyEzvizError

HCNETSDK_DEFAULT_SERVER_PORT = 8000
HCNETSDK_DEFAULT_TLS_PORT = 8443
HCNETSDK_DEFAULT_RTSP_PORT = 554
HCNETSDK_EZVIZ_DEFAULT_USERNAME = "admin"
HCNETSDK_EZVIZ_LOCAL_USERNAME = "EZ_LOCAL_USER"
HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX = "_lan_device_space-"
HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX = "lan_device_space-"
HCNETSDK_EZVIZ_SERVICES_SWITCH_GET = (
    "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
)
HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT = (
    "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
)
HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE = 0x50910
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR = 0x50911
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR = 0x50D5C
HCNETSDK_MAKE_KEYFRAME_MAIN = "NET_DVR_MakeKeyFrame"
HCNETSDK_MAKE_KEYFRAME_SUB = "NET_DVR_MakeKeyFrameSub"
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
EZVIZ_PLAYER_LAN_FLAG_EZLINK = 2
EZVIZ_STREAM_SOURCE_LIVE_MINE = 0
EZVIZ_STREAM_INHIBIT_LAN = 0x1F
EZVIZ_STREAM_TIMEOUT_MS = 30_000
EZVIZ_PREPLAY_SPS_TYPE = 9
EZVIZ_LAN_MAIN_STREAM_TYPE = 1
EZVIZ_LAN_MAIN_VIDEO_LEVEL = 2
EZVIZ_LAN_SUB_STREAM_TYPE = 2
EZVIZ_LAN_SUB_VIDEO_LEVEL = 0
EZVIZ_LOCAL_SDK_MAGIC = b"\x9e\xba\xac\xe9"
EZVIZ_LOCAL_SDK_HEADER_LENGTH = 32
EZVIZ_RTP_INTERLEAVED_MAGIC = 0x24
EZVIZ_XML_DETECT_PREFIX_LIMIT = 64
EZVIZ_XML_START_BYTE = b"<"
EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD = 0.25
EZVIZ_BODY_PRINTABLE_THRESHOLD = 0.75
EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE = 16
EZVIZ_LOCAL_SDK_SSL_IV_PREFIX = b"01234567"
EZVIZ_LOCAL_SDK_PRE_START_COMMAND = 0x2013
EZVIZ_LOCAL_SDK_PRE_START_RESPONSE = 0x2014
EZVIZ_LOCAL_SDK_PREVIEW_COMMAND = 0x2011
EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE = 0x2012
EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND = 0x3105
EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE = 0x3106
EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH = 32
HCNETSDK_MPEG_PS_PACK_HEADER = b"\x00\x00\x01\xba"
HCNETSDK_MPEG_START_CODE_PREFIX = b"\x00\x00\x01"
HCNETSDK_MPEG_TS_SYNC_BYTE = 0x47
HCNETSDK_HIK_PRIVATE_PREFIX = b"@@@@"
HCNETSDK_HKMI_PREFIX = b"HKMI"
HCNETSDK_TCP_COMMAND_PORTS = (HCNETSDK_DEFAULT_SERVER_PORT, HCNETSDK_DEFAULT_TLS_PORT)
HCNETSDK_TCP_HEADER_LENGTH = 16
HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN = 90
HCNETSDK_COMMAND_CANDIDATE_CONTROL = 99


class HcNetSdkDvrCommand(IntEnum):
    """HCNetSDK ``NET_DVR_Get/SetDVRConfig`` command IDs seen in the APK."""

    GET_DEVICE_CFG = 100
    GET_NET_CFG = 1000
    GET_PIC_CFG_V30 = 1002
    GET_RECORD_CFG_V30 = 1004
    GET_USER_CFG_V30 = 1006
    SET_USER_CFG_V30 = 1007
    GET_COMPRESSION_CFG_V30 = 1040
    SET_COMPRESSION_CFG_V30 = 1041
    GET_HD_CFG = 1054
    GET_CAMERA_PARAM_CFG = 1067
    SET_CAMERA_PARAM_CFG = 1068
    GET_AP_INFO_LIST = 305
    SET_WIFI_CFG = 306
    GET_WIFI_CFG = 307
    GET_WIFI_CONNECT_STATUS = 310
    GET_AUDIO_INPUT_PARAM = 3201
    SET_AUDIO_INPUT_PARAM = 3202
    GET_AUDIOOUT_VOLUME = 3237
    SET_AUDIOOUT_VOLUME = 3238
    GET_PIC_CFG_V40 = 6179
    SET_PIC_CFG_V40 = 6180


class HcNetSdkAbility(IntEnum):
    """HCNetSDK ``NET_DVR_GetDeviceAbility`` IDs used by the app."""

    DEVICE_ENCODE_ALL = 3
    DEVICE_JPEG_CAPTURE = 15
    DEVICE_NETWORK = 2
    DEVICE_SERIAL = 16
    DEVICE_USER = 12
    IPC_FRONT_PARAMETER = 5
    DEVICE_ABILITY_INFO = 17


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
    password: str
    port: int
    api: str
    https: bool = False


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
    """One secret-safe HCNetSDK command-port shape line from Frida logs."""

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
    """One secret-safe semantic HCNetSDK event emitted by the Frida hook."""

    name: str
    phase: str | None = None
    fields: Mapping[str, str] | None = None


@dataclass(frozen=True)
class HcNetSdkCommandTraceSummary:
    """Secret-safe summary of one mixed HCNetSDK command-port trace.

    The Frida command-shape hook intentionally avoids raw payloads. This
    summary preserves only the useful correlation: which command candidates
    were sent during the settings login call, which follow-up command
    candidates appeared afterward, and whether playback/media/keyframe
    boundaries were observed.
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
        """Return a serializable hint for a future ctypes/native backend."""
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
    """APK-obser…36120 tokens truncated…23456"
    )


@pytest.mark.parametrize(
    ("func", "value"),
    (
        (ezviz_lan_password_store_name, " "),
        (ezviz_lan_password_store_key, ""),
    ),
)
def test_ezviz_lan_password_store_rejects_empty_values(
    func: Callable[[str], str], value: str
) -> None:
    with pytest.raises(PyEzvizError):
        func(value)


def test_ezviz_lan_services_switch_payload_matches_settings_checkbox() -> None:
    payload = ezviz_lan_services_switch_payload(
        {"servicesSwitch": {"hiksdk": 0, "web": 0, "rtsp": 1}, "other": 2},
        enabled=True,
    )

    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_GET == (
        "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
    )
    assert payload == {
        "servicesSwitch": {"hiksdk": 1, "web": 1, "rtsp": 1},
        "other": 2,
    }


def test_ezviz_lan_services_switch_payload_can_disable_missing_block() -> None:
    assert ezviz_lan_services_switch_payload(None, enabled=False) == {
        "servicesSwitch": {"hiksdk": 0, "web": 0},
    }


def test_ezviz_lan_services_switch_put_request_matches_hcnetutil() -> None:
    payload = {"servicesSwitch": {"hiksdk": 1, "web": 1}, "other": 2}

    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT == (
        "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
    )
    assert ezviz_lan_services_switch_put_request(payload) == (
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + '{"servicesSwitch":{"hiksdk":1,"web":1},"other":2}'
        + "\\r\\n"
    )


@pytest.mark.parametrize(
    ("response", "succeeded"),
    (
        ({"statusCode": 1}, True),
        ({"statusCode": 0}, False),
        ('{"statusCode":1}', True),
    ),
)
def test_ezviz_lan_services_switch_succeeded_matches_hcnetutil(
    response: dict[str, int] | str, succeeded: bool
) -> None:
    assert ezviz_lan_services_switch_succeeded(response) is succeeded


def test_ezviz_lan_services_switch_succeeded_rejects_invalid_json() -> None:
    with pytest.raises(PyEzvizError):
        ezviz_lan_services_switch_succeeded("not-json")


def test_ezviz_lan_settings_error_code_matches_presenter_offset() -> None:
    assert HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE == 0x50910
    assert ezviz_lan_settings_error_code(1) == 0x50911
    assert ezviz_lan_settings_error_code(1100) == 0x50D5C


def test_ezviz_lan_settings_error_clears_password_for_account_errors() -> None:
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR
        )
        is True
    )
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR
        )
        is True
    )
    assert ezviz_lan_settings_error_clears_password(0x50912) is False


def test_ezviz_lan_settings_login_succeeded_accepts_zero_login_id() -> None:
    assert ezviz_lan_settings_login_succeeded(0) is True
    assert ezviz_lan_settings_login_succeeded(42) is True
    assert ezviz_lan_settings_login_succeeded(-1) is False


def test_ezviz_lan_play_device_login_models_player_owned_login() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=8000,
        stream_port=9020,
    )

    login = ezviz_lan_play_device_login(endpoint)

    assert login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert login.facade_api == EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
    assert login.check_last_login_status is False
    assert login.to_device_param_hint() == {
        "serial": "CAM123",
        "deviceLocalIp": "192.0.2.10",
        "localCmdPort": 8000,
        "localStreamPort": 9020,
    }
    assert ezviz_lan_play_device_login_succeeded(0) is True
    assert ezviz_lan_play_device_login_succeeded(-1) is False


def test_hcnetsdk_real_data_payload_classification() -> None:
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xbaabc") == "mpeg_ps"
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xe0abc") == "mpeg_ps_start"
    assert classify_hcnetsdk_real_data_payload(b"Gabc") == "mpeg_ts"
    assert classify_hcnetsdk_real_data_payload(b"HKMIabc") == "hik_hkmi"
    assert classify_hcnetsdk_real_data_payload(b"@@@@abc") == "hik_private"
    assert classify_hcnetsdk_real_data_payload(b"") == "empty"
    assert classify_hcnetsdk_real_data_payload(b"abc") == "unknown"


def test_hcnetsdk_real_data_media_type_detection() -> None:
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.STREAM_DATA) is True
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.SYSTEM_HEADER) is False


def test_hcnetsdk_real_play_request_matches_v30_client_info_shape() -> None:
    request = hcnetsdk_real_play_request(
        7,
        channel_number=2,
        link_mode=1,
        blocked=True,
        multicast_ip="239.0.0.1",
    )

    assert request.api == HCNETSDK_REALPLAY_V30
    assert request.callback_api == HCNETSDK_REALDATA_CALLBACK_V30
    assert request.client_info.to_native_dict() == {
        "lChannel": 2,
        "lLinkMode": 1,
        "sMultiCastIP": "239.0.0.1",
    }
    assert request.to_native_args_hint() == {
        "api": HCNETSDK_REALPLAY_V30,
        "login_id": 7,
        "client_info": {
            "lChannel": 2,
            "lLinkMode": 1,
            "sMultiCastIP": "239.0.0.1",
        },
        "callback": HCNETSDK_REALDATA_CALLBACK_V30,
        "blocked": 1,
    }


def test_hcnetsdk_real_play_request_rejects_failed_login() -> None:
    request = hcnetsdk_real_play_request(-1)

    with pytest.raises(PyEzvizError, match="successful login id"):
        request.to_native_args_hint()


def test_hcnetsdk_client_info_rejects_negative_channel() -> None:
    with pytest.raises(PyEzvizError, match="channel"):
        HcNetSdkClientInfo(channel=-1).to_native_dict()


def test_iter_hcnetsdk_real_data_mpegps_filters_callback_packets() -> None:
    packets = [
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"syshead"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"\x00\x00\x01\xbaabc"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.AUDIO_STREAM_DATA, b"opaque"),
        HcNetSdkRealDataPacket(1, 999, b"\x00\x00\x01\xbadef"),
    ]

    assert list(iter_hcnetsdk_real_data_mpegps(packets)) == [b"\x00\x00\x01\xbaabc"]


def test_ezviz_lan_settings_channel_number_matches_activity_handoff() -> None:
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 1
    )
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=0,
            digital_channel_count=1,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 33
    )


@pytest.mark.parametrize(
    ("analog_channel_count", "digital_channel_count"),
    (
        (0, 0),
        (1, 1),
    ),
)
def test_ezviz_lan_settings_channel_number_rejects_non_single_preview(
    analog_channel_count: int, digital_channel_count: int
) -> None:
    with pytest.raises(PyEzvizError, match="one channel"):
        ezviz_lan_settings_channel_number(
            analog_channel_count=analog_channel_count,
            digital_channel_count=digital_channel_count,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_playback_intent_matches_preview_back_navigation() -> None:
    intent = ezviz_lan_playback_intent(
        " CS-CV310-A0-1B2WFR0120200927CCRRTEST123456 ",
        channel_number=1,
        netsdk_login_id=0,
        ssid=None,
    )

    assert intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }


def test_ezviz_lan_playback_intent_can_forward_explicit_lan_user_id() -> None:
    intent = ezviz_lan_playback_intent(
        "CAM123",
        channel_number=1,
        netsdk_login_id=0,
        ssid="123",
    )

    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_LAN_USERID] == 123
    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_WIFI_SSID] == "123"


def test_ezviz_lan_playback_intent_rejects_failed_login_id() -> None:
    with pytest.raises(PyEzvizError, match="successful login id"):
        ezviz_lan_playback_intent("CAM123", channel_number=1, netsdk_login_id=-1)


def test_parse_ezviz_local_device_decodes_device_content() -> None:
    device = parse_ezviz_local_device(
        {
            "deviceSerial": "CAM123",
            "deviceName": "Test Camera",
            "deviceModel": "C8C",
            "category": "IPC",
            "deviceCategory": "IPC",
            "groupId": "-1",
            "deviceContent": (
                '{"deviceIP":"192.0.2.44","deviceType":1,'
                '"deviceEncType":2,"isLowPower":0,'
                '"deviceMaxActLimit":30,"deviceSdkVersion":4,'
                '"deviceRand":"abc","deviceRoleType":5}'
            ),
        }
    )

    assert device.serial == "CAM123"
    assert device.name == "Test Camera"
    assert device.group_id == -1
    assert device.content is not None
    assert device.content.device_ip == "192.0.2.44"
    assert device.content.device_enc_type == 2
    assert device.endpoint is not None
    assert device.endpoint.host == "192.0.2.44"


def test_ezviz_lan_live_view_params_match_player_lan_shape() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        net_host="203.0.113.10",
        command_port=9010,
        net_command_port=8010,
        stream_port=9020,
        net_stream_port=9030,
    )

    params = ezviz_lan_live_view_params(
        endpoint,
        channel_number=2,
        channel_serial="CAM123-CH2",
        channel_index="2",
        channel_count=4,
        netsdk_login_id=42,
    )

    assert params.channel_serial == "CAM123-CH2"
    assert params.channel_index == "2"
    assert params.channel_count == 4
    assert params.preplay_sps_type == EZVIZ_PREPLAY_SPS_TYPE
    assert params.stream_source == EZVIZ_STREAM_SOURCE_LIVE_MINE
    assert params.stream_inhibit == EZVIZ_STREAM_INHIBIT_LAN
    assert params.stream_timeout_ms == EZVIZ_STREAM_TIMEOUT_MS
    assert params.stream_type == 1
    assert params.video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert params.device_ip == "203.0.113.10"
    assert params.device_local_ip == "192.0.2.10"
    assert params.device_cmd_port == 8010
    assert params.device_cmd_local_port == 9010
    assert params.device_stream_local_port == 9020
    assert params.device_stream_port == 9030
    assert params.netsdk_login_id == 42
    assert params.netsdk_channel_number == 2
    assert params.to_init_param_dict() == {
        "szDevSerial": "CAM123",
        "szChnlSerial": "CAM123-CH2",
        "szChnlIndex": "2",
        "szDevIP": "203.0.113.10",
        "szDevLocalIP": "192.0.2.10",
        "iDevCmdPort": 8010,
        "iDevCmdLocalPort": 9010,
        "iDevStreamPort": 9030,
        "iDevStreamLocalPort": 9020,
        "iChannelCount": 4,
        "iP2PSPS": EZVIZ_PREPLAY_SPS_TYPE,
        "iStreamInhibit": EZVIZ_STREAM_INHIBIT_LAN,
        "iStreamSource": EZVIZ_STREAM_SOURCE_LIVE_MINE,
        "iStreamType": 1,
        "iStreamTimeOut": EZVIZ_STREAM_TIMEOUT_MS,
        "iVideoLevel": 0,
        "iChannelNumber": 2,
        "iNetSDKUserId": 42,
        "iNetSDKChannelNumber": 2,
    }


def test_ezviz_lan_preview_plan_matches_native_call_sequence() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=1,
        stream_type=1,
        netsdk_login_id=7,
    )

    assert plan.login_candidates[0].api == "NET_DVR_Login_V40"
    assert plan.login_candidates[0].port == HCNETSDK_DEFAULT_TLS_PORT
    assert plan.login_candidates[1].port == 9010
    assert plan.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.real_play_request is not None
    assert plan.real_play_request.to_native_args_hint()["login_id"] == 7
    assert plan.real_play_request.client_info.to_native_dict()["lChannel"] == 1
    assert plan.play_device_login is not None
    assert plan.play_device_login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_models_app_flow() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        host="192.0.2.10",
        command_port=8000,
        stream_port=0,
    )

    path = ezviz_lan_complete_playback_path(
        endpoint,
        "ABCDEF",
        settings_login_id=0,
        play_device_login_id=7,
        analog_channel_count=1,
        digital_channel_count=0,
        analog_start_channel=1,
        digital_start_channel=33,
        stream_type=EZVIZ_LAN_MAIN_STREAM_TYPE,
    )

    assert path.settings_login_candidates[0].api == "NET_DVR_Login_V40"
    assert path.settings_login_candidates[0].https is True
    assert path.settings_login_candidates[1].port == 8000
    assert path.settings_login_id == 0
    assert path.channel_number == 1
    assert path.playback_intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }
    assert path.play_device_login_id == 7
    assert path.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert path.live_view.to_init_param_dict()["iNetSDKChannelNumber"] == 1
    assert path.post_start_keyframe_request is not None
    assert path.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert path.call_sequence() == (
        EZVIZ_HCNETUTIL_LOGIN_V40,
        EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
        EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_requires_play_device_login() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    with pytest.raises(PyEzvizError, match="play-device login"):
        ezviz_lan_complete_playback_path(
            endpoint,
            "ABCDEF",
            settings_login_id=0,
            play_device_login_id=-1,
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_preview_plan_forwards_channel_identity() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=3,
        channel_serial="CAM123-CH3",
        channel_index="3",
        channel_count=4,
    )

    init_param = plan.live_view.to_init_param_dict()
    assert init_param["szChnlSerial"] == "CAM123-CH3"
    assert init_param["szChnlIndex"] == "3"
    assert init_param["iChannelCount"] == 4
    assert init_param["iP2PSPS"] == EZVIZ_PREPLAY_SPS_TYPE


def test_ezviz_lan_video_qualities_match_lan_item_holder() -> None:
    qualities = ezviz_lan_video_qualities()

    assert qualities[0].stream_type == EZVIZ_LAN_MAIN_STREAM_TYPE
    assert qualities[0].video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert qualities[0].native_video_level == 0
    assert qualities[1].stream_type == EZVIZ_LAN_SUB_STREAM_TYPE
    assert qualities[1].video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert qualities[1].native_video_level == 2


def test_ezviz_native_video_level_matches_player_conversion() -> None:
    assert ezviz_native_video_level(-1) == 3
    assert ezviz_native_video_level(0) == 2
    assert ezviz_native_video_level(1) == 1
    assert ezviz_native_video_level(2) == 0
    assert ezviz_native_video_level(3) == 4
    assert ezviz_native_video_level(4) == 5


def test_ezviz_lan_preview_plan_uses_sub_keyframe_for_sub_stream() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        netsdk_login_id=7,
    )

    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_SUB
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.live_view.video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 2


def test_ezviz_lan_preview_plan_allows_explicit_video_level() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        video_level=3,
    )

    assert plan.live_view.video_level == 3
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 4


def test_ezviz_lan_preview_plan_skips_keyframe_without_login_id() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(endpoint, "ABCDEF")

    assert plan.post_start_keyframe_api is None
    assert plan.real_play_request is None
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
    )


class _FragmentedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._buffer = b"".join(chunks)

    def recv(self, length: int) -> bytes:
        chunk = self._buffer[:length]
        self._buffer = self._buffer[length:]
        return chunk


class _FakeSocket(_FragmentedSocket):
    def __init__(self, chunks: list[bytes]) -> None:
        super().__init__(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
