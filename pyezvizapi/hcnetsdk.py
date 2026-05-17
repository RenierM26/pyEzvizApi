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
                    lines.append(
                        f"{indent}\t\t<{tag}>{_xml_escape(str(value))}</{tag}>"
                    )
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
        )


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


SocketSourceAddress = tuple[str, int] | None
SocketFactory = Callable[[tuple[str, int], float | None], Any]
SourceAddressSocketFactory = Callable[
    [tuple[str, int], float | None, SocketSourceAddress],
    Any,
]
LocalSdkIvFactory = Callable[[int], bytes]


def ezviz_local_sdk_ssl_iv(
    size: int = EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE,
    *,
    seed: bytes = EZVIZ_LOCAL_SDK_SSL_IV_PREFIX,
) -> bytes:
    """Return the app-shaped IV used for local SDK SSL-like frames.

    EZVIZ traces show the direct-local stack creates one IV per preview setup
    context and reuses it for the ``0x2011`` and ``0x3105`` encrypted frames.
    The IV prefix observed in the app is the ASCII bytes ``01234567`` and the
    remaining AES block bytes are zero. The 32-byte frame trailer is a
    lowercase MD5 hex digest of the encrypted body.
    """
    if size != EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError("EZVIZ local SDK SSL IV must be 16 bytes")
    if len(seed) != len(EZVIZ_LOCAL_SDK_SSL_IV_PREFIX):
        raise PyEzvizError("EZVIZ local SDK SSL IV seed must be 8 bytes")
    return seed + bytes(size - len(seed))


def classify_lan_ports(
    endpoint: HcNetSdkLanEndpoint,
    *,
    timeout: float | None = 2.0,
    socket_factory: SocketFactory = socket.create_connection,
) -> list[HcNetSdkPortProbe]:
    """Probe advertised LAN ports without authenticating or changing state."""
    ports = [
        endpoint.sdk_tls_port,
        endpoint.command_port,
        endpoint.stream_port,
        endpoint.rtsp_port,
    ]
    seen: set[int] = set()
    results: list[HcNetSdkPortProbe] = []
    for port in ports:
        if port is None or port <= 0 or port in seen:
            continue
        seen.add(port)
        results.append(
            _probe_port(
                endpoint.host,
                port,
                timeout=timeout,
                socket_factory=socket_factory,
            )
        )
    return results


def ezviz_lan_login_candidates(
    verification_code: str,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    command_port: int = HCNETSDK_DEFAULT_SERVER_PORT,
    tls_port: int = HCNETSDK_DEFAULT_TLS_PORT,
) -> list[HcNetSdkLoginCandidate]:
    """Return EZVIZ app-style HCNetSDK LAN login attempts.

    APK inspection shows LAN login tries HCNetSDK V40 over HTTPS first, then
    classic V30 on the SDK command port, and finally V30 with ``EZ_LOCAL_USER``
    plus the middle 16 hex characters of the MD5 hash of the same device
    verification/activation code.
    """
    code = verification_code.strip()
    if not code:
        raise PyEzvizError("Missing EZVIZ LAN verification or activation code")

    local_password = ezviz_lan_local_user_password(code)
    return [
        HcNetSdkLoginCandidate(
            username=username,
            password=code,
            port=tls_port,
            api="NET_DVR_Login_V40",
            https=True,
        ),
        HcNetSdkLoginCandidate(
            username=username,
            password=code,
            port=command_port,
            api="NET_DVR_Login_V30",
        ),
        HcNetSdkLoginCandidate(
            username=HCNETSDK_EZVIZ_LOCAL_USERNAME,
            password=local_password,
            port=command_port,
            api="NET_DVR_Login_V30",
        ),
    ]


def ezviz_lan_local_user_password(password: str) -> str:
    """Return the EZ_LOCAL_USER password derived by AddMD5Util.a(...)."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()[8:24].lower()


def ezviz_lan_password_store_name(user_id: str) -> str:
    """Return the SharedPreferences name used for LAN Live View passwords."""
    user = user_id.strip()
    if not user:
        raise PyEzvizError("Missing EZVIZ user id for LAN password store")
    return f"{user}{HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX}"


def ezviz_lan_password_store_key(serial: str) -> str:
    """Return the SharedPreferences key used for one LAN device password."""
    device_serial = serial.strip()
    if not device_serial:
        raise PyEzvizError("Missing EZVIZ device serial for LAN password store")
    return f"{HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX}{device_serial}"


def ezviz_lan_settings_login_candidates(
    verification_code: str,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    command_port: int = HCNETSDK_DEFAULT_SERVER_PORT,
    tls_port: int = HCNETSDK_DEFAULT_TLS_PORT,
    login_with_8443: bool | None = None,
) -> list[HcNetSdkLoginCandidate]:
    """Return the LAN Live View settings-screen login attempts.

    LanDeviceListPresenter.o(...) differs slightly from the older
    DeviceInfoEx.loginLanDevice() helper:

    * scanned devices pass login_with_8443=True when SDK-over-TLS is
      advertised on port 8443, and that path does not fall back to the command
      port after a TLS login failure;
    * manual-add and React Native IP-login paths pass None and try TLS first,
      then the command port, then the EZVIZ local-user MD5 fallback;
    * compatibility mode passes False and skips the TLS attempt.

    The settings presenter calls ``HCNETUtil.s(...)`` for every attempt, so all
    attempts use the V40 login wrapper. Only the 8443 attempt sets the native
    ``byHttps`` flag.
    """
    code = verification_code.strip()
    if not code:
        raise PyEzvizError("Missing EZVIZ LAN settings password")

    candidates = [
        HcNetSdkLoginCandidate(
            username=username,
            password=code,
            port=tls_port,
            api="NET_DVR_Login_V40",
            https=True,
        ),
        HcNetSdkLoginCandidate(
            username=username,
            password=code,
            port=command_port,
            api="NET_DVR_Login_V40",
        ),
        HcNetSdkLoginCandidate(
            username=HCNETSDK_EZVIZ_LOCAL_USERNAME,
            password=ezviz_lan_local_user_password(code),
            port=command_port,
            api="NET_DVR_Login_V40",
        ),
    ]
    if login_with_8443 is True:
        return candidates[:1]
    if login_with_8443 is False:
        return candidates[1:]
    return candidates


def ezviz_lan_settings_updates_services_switch(
    *,
    login_with_8443: bool | None,
    login_port: int,
    open_8000: bool | None,
    tls_port: int = HCNETSDK_DEFAULT_TLS_PORT,
) -> bool:
    """Return whether the settings presenter writes ``servicesSwitch``.

    Smali inspection shows the compatibility checkbox update runs only after a
    successful SDK-over-TLS login attempt. If the TLS attempt is skipped, or if
    the flow falls back to the command-port login, the app does not send the
    ``GET``/``PUT`` servicesSwitch requests.
    """
    return (
        open_8000 is not None
        and login_with_8443 is not False
        and login_port == tls_port
    )


def ezviz_lan_services_switch_payload(
    payload: Mapping[str, Any] | None,
    *,
    enabled: bool,
) -> dict[str, Any]:
    """Return the LAN settings servicesSwitch update payload.

    The APK reads GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json,
    mutates servicesSwitch.hiksdk and servicesSwitch.web to the same checkbox
    value, then sends the whole JSON object back through HCNetSDK.
    """
    result: dict[str, Any] = dict(payload or {})
    services = result.get("servicesSwitch")
    services_switch = dict(services) if isinstance(services, Mapping) else {}
    checkbox_value = 1 if enabled else 0
    services_switch["hiksdk"] = checkbox_value
    services_switch["web"] = checkbox_value
    result["servicesSwitch"] = services_switch
    return result


def ezviz_lan_services_switch_put_request(payload: Mapping[str, Any]) -> str:
    """Return the raw ISAPI request string sent by HCNETUtil.c(...)."""
    return (
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + json.dumps(dict(payload), separators=(",", ":"))
        + "\\r\\n"
    )


def ezviz_lan_services_switch_succeeded(response: Mapping[str, Any] | str) -> bool:
    """Return whether HCNETUtil.c(...) would treat a servicesSwitch PUT as OK."""
    if isinstance(response, str):
        try:
            data = json.loads(response)
        except ValueError as err:
            raise PyEzvizError("Invalid EZVIZ servicesSwitch response JSON") from err
    else:
        data = response
    return data.get("statusCode") == 1


def ezviz_lan_settings_error_code(hcnetsdk_error: int) -> int:
    """Return the LAN settings UI error code for an HCNetSDK error."""
    return HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE + hcnetsdk_error


def ezviz_lan_settings_error_clears_password(error_code: int) -> bool:
    """Return whether LanDeviceListActivity.q(...) clears the LAN password."""
    return error_code in (
        HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR,
        HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR,
    )


def ezviz_lan_settings_login_succeeded(login_id: int) -> bool:
    """Return whether the settings presenter treats an HCNetSDK login as OK."""
    return login_id >= 0


def ezviz_lan_play_device_login_succeeded(login_id: int) -> bool:
    """Return whether DeviceInfoEx.loginPlayDevice(...) returned a login id."""
    return login_id >= 0


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


def classify_hcnetsdk_tcp_payload(data: bytes) -> HcNetSdkTcpPayloadShape:
    """Classify raw HCNetSDK command-port bytes without decoding secrets.

    Port 8000 traffic is still proprietary. This helper gives future live
    captures a stable Python target by recording byte-shape facts only:
    framing candidates, aggregate byte ratios, XML tag names when present, and
    common length-prefix guesses. It intentionally does not parse credentials.
    """
    length = len(data)
    if length == 0:
        return HcNetSdkTcpPayloadShape(
            kind="empty",
            length=0,
            printable_ratio=0.0,
            null_ratio=0.0,
            high_bit_ratio=0.0,
            entropy_bits_per_byte=0.0,
        )

    printable = sum(1 for byte in data if 0x20 <= byte <= 0x7E)
    nulls = data.count(0)
    high_bit = sum(1 for byte in data if byte >= 0x80)
    xml_offset = _xml_offset(data)
    xml_tags = _xml_tag_names(data[xml_offset:]) if xml_offset is not None else ()
    declared_offset, declared_length = _hcnetsdk_declared_length(data)
    u32be_0 = int.from_bytes(data[:4], "big") if length >= 4 else None
    u32le_0 = int.from_bytes(data[:4], "little") if length >= 4 else None
    u32be_4 = int.from_bytes(data[4:8], "big") if length >= 8 else None
    u32le_4 = int.from_bytes(data[4:8], "little") if length >= 8 else None
    u32be_8 = int.from_bytes(data[8:12], "big") if length >= 12 else None
    u32le_8 = int.from_bytes(data[8:12], "little") if length >= 12 else None
    u32be_12 = int.from_bytes(data[12:16], "big") if length >= 16 else None
    u32le_12 = int.from_bytes(data[12:16], "little") if length >= 16 else None
    u16be_0 = int.from_bytes(data[:2], "big") if length >= 2 else None
    u16le_0 = int.from_bytes(data[:2], "little") if length >= 2 else None

    return HcNetSdkTcpPayloadShape(
        kind=_hcnetsdk_tcp_payload_kind(
            data,
            printable_ratio=printable / length,
            high_bit_ratio=high_bit / length,
            xml_offset=xml_offset,
            xml_tags=xml_tags,
            declared_length_offset=declared_offset,
        ),
        length=length,
        printable_ratio=printable / length,
        null_ratio=nulls / length,
        high_bit_ratio=high_bit / length,
        entropy_bits_per_byte=_entropy_bits_per_byte(data),
        u32be_0=u32be_0,
        u32le_0=u32le_0,
        u32be_4=u32be_4,
        u32le_4=u32le_4,
        u32be_8=u32be_8,
        u32le_8=u32le_8,
        u32be_12=u32be_12,
        u32le_12=u32le_12,
        u16be_0=u16be_0,
        u16le_0=u16le_0,
        declared_length_offset=declared_offset,
        declared_length=declared_length,
        xml_offset=xml_offset,
        xml_tags=xml_tags,
    )


def parse_hcnetsdk_tcp_shape_log_line(
    line: str,
) -> HcNetSdkTcpShapeLogRecord | None:
    """Parse one secret-safe Frida HCNetSDK TCP shape log line.

    The narrow command-port hook intentionally prints only metadata, not raw
    bytes. This parser turns those metadata lines into the same Python shape
    model used by direct byte classification, so captured traces can drive the
    next packet-builder tests without copying secrets into fixtures.
    """
    match = re.search(
        r"\[(?:hcnetsdk|native)-(?P<direction>send|recv|read|write)\]\s+"
        r"fd=(?P<fd>-?\d+)\s+"
        r"(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\s+"
        r"(?P<fields>.*)$",
        line.strip(),
    )
    if not match:
        return None

    fields = _parse_shape_fields(match.group("fields"))
    kind = fields.get("tcpKind")
    length = _parse_int(fields.get("tcpLen"))
    if not kind or length is None:
        return None

    length_candidates = _parse_length_candidates(fields.get("lengthCandidates"))
    declared_offset: int | None = None
    declared_length: int | None = None
    if length_candidates:
        first_name, declared_length = next(iter(length_candidates.items()))
        declared_offset = _parse_length_candidate_offset(first_name)

    return HcNetSdkTcpShapeLogRecord(
        direction=match.group("direction"),
        fd=int(match.group("fd")),
        host=match.group("host"),
        port=int(match.group("port")),
        shape=HcNetSdkTcpPayloadShape(
            kind=kind,
            length=length,
            printable_ratio=_parse_float(fields.get("printable")) or 0.0,
            null_ratio=_parse_float(fields.get("nulls")) or 0.0,
            high_bit_ratio=_parse_float(fields.get("high")) or 0.0,
            entropy_bits_per_byte=0.0,
            u32be_0=_parse_int(fields.get("u32be0")),
            u32le_0=_parse_int(fields.get("u32le0")),
            u32be_4=_parse_int(fields.get("u32be4")),
            u32le_4=_parse_int(fields.get("u32le4")),
            u32be_8=_parse_int(fields.get("u32be8")),
            u32le_8=_parse_int(fields.get("u32le8")),
            u32be_12=_parse_int(fields.get("u32be12")),
            u32le_12=_parse_int(fields.get("u32le12")),
            u16be_0=_parse_int(fields.get("u16be0")),
            u16le_0=_parse_int(fields.get("u16le0")),
            declared_length_offset=declared_offset,
            declared_length=declared_length,
        ),
        captured_length=_parse_int(fields.get("captured")),
        fingerprint=fields.get("fp128"),
        length_candidates=length_candidates,
    )


def parse_hcnetsdk_semantic_log_line(line: str) -> HcNetSdkSemanticLogEvent | None:
    """Parse one secret-safe HCNetSDK semantic event line from Frida logs."""
    match = re.search(r"\[hcnetsdk-semantic\]\s+(?P<body>.*)$", line.strip())
    if not match:
        return None

    body = match.group("body")
    if body.startswith(("waiting for ", "hooked ", "native hooks installed ")) or (
        " hook unavailable " in body or " hooks unavailable " in body
    ):
        return None

    tokens = body.split()
    if not tokens:
        return None

    field_index = next(
        (index for index, token in enumerate(tokens) if "=" in token),
        len(tokens),
    )
    head = tokens[:field_index]
    fields = _parse_shape_fields(" ".join(tokens[field_index:]))
    phase = head[-1] if head and head[-1] in {"enter", "leave"} else None
    name_tokens = head[:-1] if phase else head
    if not name_tokens:
        return None

    return HcNetSdkSemanticLogEvent(
        name=" ".join(name_tokens),
        phase=phase,
        fields=fields,
    )


def summarize_hcnetsdk_command_trace(
    lines: Iterable[str],
) -> HcNetSdkCommandTraceSummary:
    """Summarize one mixed HCNetSDK command-shape/semantic Frida trace.

    This reducer is deliberately conservative: it uses semantic enter/leave
    boundaries to associate redacted write command candidates with
    HCNETUtil.s(...) settings login, leaves all later command candidates in
    followup_commands, and records only boolean proof points for playback
    login, keyframe request, and command-socket media.
    """
    login_commands: list[int] = []
    followup_commands: list[int] = []
    in_settings_login = False
    settings_login_success = False
    play_device_login_success = False
    keyframe_requested = False
    media_on_command_socket = False

    for line in lines:
        record = parse_hcnetsdk_tcp_shape_log_line(line)
        if record is not None:
            if record.shape.kind == "interleaved_media":
                media_on_command_socket = True
            command = _hcnetsdk_shape_command_candidate(record)
            if command is not None:
                if in_settings_login:
                    login_commands.append(command)
                else:
                    followup_commands.append(command)

        event = parse_hcnetsdk_semantic_log_line(line)
        if event is None:
            continue

        if event.name == EZVIZ_HCNETUTIL_LOGIN_V40:
            if event.phase == "enter":
                in_settings_login = True
            elif event.phase == "leave":
                in_settings_login = False
                ret = _event_field_int(event, "ret")
                settings_login_success = ret is not None and ret >= 0
            continue

        if event.name in {
            EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
            EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE,
        } and event.phase == "leave":
            ret = _event_field_int(event, "ret")
            play_device_login_success = ret is not None and ret >= 0
            continue

        if event.name.endswith("NET_DVR_MakeKeyFrame") and event.phase == "leave":
            keyframe_requested = _event_field_bool(event, "ret")

    return HcNetSdkCommandTraceSummary(
        settings_login_commands=tuple(login_commands),
        followup_commands=tuple(followup_commands),
        settings_login_success=settings_login_success,
        play_device_login_success=play_device_login_success,
        keyframe_requested=keyframe_requested,
        media_on_command_socket=media_on_command_socket,
    )


def parse_hcnetsdk_tcp_frame_header(data: bytes) -> HcNetSdkTcpFrameHeader:
    """Parse the observed 16-byte HCNetSDK command-port frame header."""
    if len(data) < HCNETSDK_TCP_HEADER_LENGTH:
        raise PyEzvizError("HCNetSDK TCP frame header is truncated")
    total_length = int.from_bytes(data[0:4], "big")
    if total_length < HCNETSDK_TCP_HEADER_LENGTH:
        raise PyEzvizError("HCNetSDK TCP frame total length is too small")
    return HcNetSdkTcpFrameHeader(
        total_length=total_length,
        field_4=int.from_bytes(data[4:8], "big"),
        field_8=int.from_bytes(data[8:12], "big"),
        field_12=int.from_bytes(data[12:16], "big"),
    )


def parse_hcnetsdk_tcp_frame(data: bytes) -> HcNetSdkTcpFrame:
    """Parse one complete observed HCNetSDK command-port frame."""
    header = parse_hcnetsdk_tcp_frame_header(data)
    if len(data) < header.total_length:
        raise PyEzvizError("HCNetSDK TCP frame is truncated")
    return HcNetSdkTcpFrame(
        header=header,
        body=data[HCNETSDK_TCP_HEADER_LENGTH : header.total_length],
    )


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


def hcnetsdk_command_candidate_role(candidate: int | None) -> str | None:
    """Return the current role label for an observed command candidate.

    The names are trace-derived labels, not a complete HCNetSDK command table.
    They are useful for reducing redacted Frida captures while the underlying
    encrypted request format is still being mapped.
    """
    if candidate == HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN:
        return "settings_login"
    if candidate == HCNETSDK_COMMAND_CANDIDATE_CONTROL:
        return "control"
    return None


def iter_hcnetsdk_tcp_frame_shapes(
    records: Iterable[HcNetSdkTcpShapeLogRecord],
) -> Iterator[HcNetSdkTcpFrameShape]:
    """Yield command frames reconstructed from secret-safe socket shape logs.

    The narrow Frida hook logs response headers and bodies as separate reads
    when the app asks libc for 16 bytes first and then the implied body length.
    This reducer pairs those adjacent records without needing payload bytes.
    Whole-frame writes are yielded as header-only shapes because their body
    content remains intentionally redacted.
    """
    pending = list(records)
    index = 0
    while index < len(pending):
        record = pending[index]
        total_length = record.shape.declared_length
        if record.shape.length == HCNETSDK_TCP_HEADER_LENGTH:
            total_length = record.shape.u32be_0
        if (
            total_length is None
            or (
                record.shape.declared_length_offset != 0
                and record.shape.length != HCNETSDK_TCP_HEADER_LENGTH
            )
            or total_length < HCNETSDK_TCP_HEADER_LENGTH
        ):
            index += 1
            continue
        is_split_header = record.shape.length == HCNETSDK_TCP_HEADER_LENGTH
        is_whole_write = (
            record.direction in {"send", "write"}
            and record.shape.length == total_length
        )
        if not is_split_header and not is_whole_write:
            index += 1
            continue

        body_shape: HcNetSdkTcpPayloadShape | None = None
        if is_split_header:
            next_index = index + 1
            if next_index < len(pending):
                candidate = pending[next_index]
                same_stream = (
                    candidate.direction == record.direction
                    and candidate.fd == record.fd
                    and candidate.host == record.host
                    and candidate.port == record.port
                )
                if (
                    same_stream
                    and candidate.shape.length
                    == total_length - HCNETSDK_TCP_HEADER_LENGTH
                ):
                    body_shape = candidate.shape
                    index += 1

        yield HcNetSdkTcpFrameShape(
            direction=record.direction,
            fd=record.fd,
            host=record.host,
            port=record.port,
            total_length=total_length,
            header_shape=record.shape,
            body_shape=body_shape,
        )
        index += 1


def iter_hcnetsdk_real_data_mpegps(
    packets: Iterable[HcNetSdkRealDataPacket],
    *,
    include_system_header: bool = False,
) -> Iterator[bytes]:
    """Yield MPEG-PS-like payloads from HCNetSDK real-play callback packets."""
    for packet in packets:
        if packet.data_type == HcNetSdkRealDataType.SYSTEM_HEADER:
            if include_system_header and packet.body:
                yield packet.body
            continue
        if not packet.is_media:
            continue
        if packet.payload_kind in {"mpeg_ps", "mpeg_ps_start"}:
            yield packet.body


def ezviz_lan_play_device_login(
    endpoint: HcNetSdkLanEndpoint,
    *,
    check_last_login_status: bool = False,
) -> EzvizLanPlayDeviceLogin:
    """Build the player-side LAN HCNetSDK login step observed in the APK.

    The settings screen's login id is only a gate for opening the player. The
    player path then calls IPlayDataInfo.loginPlayDevice(...) /
    DeviceInfoEx.loginPlayDevice(...) and uses that returned NetSDK id for
    InitParam.iNetSDKUserId and the later keyframe request.
    """
    if not endpoint.host.strip():
        raise PyEzvizError("Missing EZVIZ LAN play-device host")
    return EzvizLanPlayDeviceLogin(
        endpoint=endpoint,
        check_last_login_status=check_last_login_status,
    )


def ezviz_lan_settings_channel_number(
    *,
    analog_channel_count: int,
    digital_channel_count: int,
    analog_start_channel: int,
    digital_start_channel: int,
) -> int:
    """Return the channel selected by LanDeviceListActivity.z0(...)."""
    total_channels = analog_channel_count + digital_channel_count
    if total_channels != 1:
        raise PyEzvizError("EZVIZ LAN single-preview handoff requires one channel")
    if analog_channel_count > 0:
        return analog_start_channel
    return digital_start_channel


def ezviz_lan_playback_intent(
    serial: str,
    *,
    channel_number: int,
    netsdk_login_id: int,
    ssid: str | None = None,
    lan_user_id: int | None = None,
) -> EzvizLanPlaybackIntent:
    """Build the LAN playback extras passed into VideoPlayActivity.

    netsdk_login_id is validated because the settings screen only opens
    playback after HCNetSDK login succeeds. The intent EXTRA_LAN_USERID is
    separate: ActivityUtil.b(...) parses it from the optional SSID string and
    otherwise sends -1. The stream core performs/uses its own NetSDK login
    when creating the native init params.
    """
    device_serial = serial.strip()
    if not device_serial:
        raise PyEzvizError("Missing EZVIZ LAN playback device serial")
    if channel_number < 0:
        raise PyEzvizError("EZVIZ LAN playback channel number must be non-negative")
    if not ezviz_lan_settings_login_succeeded(netsdk_login_id):
        raise PyEzvizError("EZVIZ LAN playback requires a successful login id")
    wifi_ssid = ssid or ""
    extra_lan_user_id = -1
    if lan_user_id is not None:
        extra_lan_user_id = lan_user_id
    elif wifi_ssid:
        try:
            extra_lan_user_id = int(wifi_ssid)
        except ValueError:
            extra_lan_user_id = -1
    return EzvizLanPlaybackIntent(
        serial=device_serial,
        channel_number=channel_number,
        lan_user_id=extra_lan_user_id,
        ssid=wifi_ssid,
    )


def ezviz_lan_video_qualities() -> tuple[EzvizLanVideoQuality, ...]:
    """Return the two LAN quality entries exposed by the EZVIZ app."""
    return (
        EzvizLanVideoQuality(
            stream_type=EZVIZ_LAN_MAIN_STREAM_TYPE,
            video_level=EZVIZ_LAN_MAIN_VIDEO_LEVEL,
        ),
        EzvizLanVideoQuality(
            stream_type=EZVIZ_LAN_SUB_STREAM_TYPE,
            video_level=EZVIZ_LAN_SUB_VIDEO_LEVEL,
        ),
    )


def ezviz_lan_video_level_for_stream_type(stream_type: int) -> int:
    """Return the app's default LAN video level for a main/sub stream type."""
    if stream_type == EZVIZ_LAN_SUB_STREAM_TYPE:
        return EZVIZ_LAN_SUB_VIDEO_LEVEL
    return EZVIZ_LAN_MAIN_VIDEO_LEVEL


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


def ezviz_lan_live_view_params(
    endpoint: HcNetSdkLanEndpoint,
    *,
    channel_number: int = 1,
    channel_serial: str | None = None,
    channel_index: str | None = None,
    channel_count: int | None = None,
    stream_type: int = 1,
    video_level: int | None = None,
    netsdk_login_id: int = -1,
) -> EzvizLanLiveViewParams:
    """Build the LAN fields the EZVIZ player passes into its stream SDK.

    The Android app still uses ``LivePlaySource`` for LAN preview. The key
    difference is that the converted device param has ``isLocal()`` true and
    carries local IP/command/stream ports; when HCNetSDK login succeeds, the
    stream core also forwards the NetSDK login id and channel number.
    """
    if channel_number < 0:
        raise PyEzvizError("LAN live-view channel number must be non-negative")
    if stream_type < 1:
        raise PyEzvizError("LAN live-view stream type must be positive")

    return EzvizLanLiveViewParams(
        serial=endpoint.serial,
        channel_number=channel_number,
        channel_serial=channel_serial,
        channel_index=channel_index,
        channel_count=channel_count,
        stream_type=max(1, min(stream_type, 2)),
        video_level=(
            ezviz_lan_video_level_for_stream_type(stream_type)
            if video_level is None
            else video_level
        ),
        device_ip=endpoint.net_host,
        device_local_ip=endpoint.host,
        device_cmd_port=endpoint.net_command_port,
        device_cmd_local_port=endpoint.command_port,
        device_stream_local_port=endpoint.stream_port,
        device_stream_port=endpoint.net_stream_port,
        netsdk_login_id=netsdk_login_id,
        netsdk_channel_number=channel_number if netsdk_login_id > -1 else None,
    )


def ezviz_lan_preview_plan(
    endpoint: HcNetSdkLanEndpoint,
    verification_code: str,
    *,
    channel_number: int = 1,
    channel_serial: str | None = None,
    channel_index: str | None = None,
    channel_count: int | None = None,
    stream_type: int = 1,
    video_level: int | None = None,
    netsdk_login_id: int = -1,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
) -> EzvizLanPreviewPlan:
    """Build the APK-observed LAN preview setup sequence.

    The Java layer logs in through HCNetSDK first, passes the resulting login
    id into EZ stream ``InitParam``, starts native preview through
    ``NativeApi.startPreview()``, then asks HCNetSDK to force an I-frame for
    the selected channel and stream type.
    """
    live_view = ezviz_lan_live_view_params(
        endpoint,
        channel_number=channel_number,
        channel_serial=channel_serial,
        channel_index=channel_index,
        channel_count=channel_count,
        stream_type=stream_type,
        video_level=video_level,
        netsdk_login_id=netsdk_login_id,
    )
    return EzvizLanPreviewPlan(
        login_candidates=tuple(
            ezviz_lan_login_candidates(
                verification_code,
                username=username,
                command_port=endpoint.command_port,
                tls_port=endpoint.sdk_tls_port,
            )
        ),
        live_view=live_view,
        play_device_login=ezviz_lan_play_device_login(endpoint),
    )


def ezviz_lan_complete_playback_path(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    verification_code: str,
    *,
    settings_login_id: int,
    play_device_login_id: int,
    analog_channel_count: int,
    digital_channel_count: int,
    analog_start_channel: int,
    digital_start_channel: int,
    channel_serial: str | None = None,
    channel_index: str | None = None,
    channel_count: int | None = None,
    stream_type: int = EZVIZ_LAN_MAIN_STREAM_TYPE,
    video_level: int | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    ssid: str | None = None,
    lan_user_id: int | None = None,
) -> EzvizLanPlaybackPath:
    """Build the full APK-observed LAN Live View playback path.

    The settings-screen login id and the player-owned NetSDK login id are
    intentionally separate. The app first uses the settings login to allow the
    handoff into the player, then the player obtains/reuses a NetSDK id through
    DeviceInfoEx.loginPlayDevice(...) and passes that id into native preview
    and the post-start keyframe request.
    """
    if not ezviz_lan_settings_login_succeeded(settings_login_id):
        raise PyEzvizError("EZVIZ LAN playback requires successful settings login")
    if not ezviz_lan_play_device_login_succeeded(play_device_login_id):
        raise PyEzvizError("EZVIZ LAN playback requires successful play-device login")

    channel_number = ezviz_lan_settings_channel_number(
        analog_channel_count=analog_channel_count,
        digital_channel_count=digital_channel_count,
        analog_start_channel=analog_start_channel,
        digital_start_channel=digital_start_channel,
    )
    playback_intent = ezviz_lan_playback_intent(
        endpoint.serial,
        channel_number=channel_number,
        netsdk_login_id=settings_login_id,
        ssid=ssid,
        lan_user_id=lan_user_id,
    )
    play_device_login = ezviz_lan_play_device_login(endpoint)
    live_view = ezviz_lan_live_view_params(
        endpoint,
        channel_number=channel_number,
        channel_serial=channel_serial,
        channel_index=channel_index,
        channel_count=channel_count,
        stream_type=stream_type,
        video_level=video_level,
        netsdk_login_id=play_device_login_id,
    )
    return EzvizLanPlaybackPath(
        settings_login_candidates=tuple(
            ezviz_lan_settings_login_candidates(
                verification_code,
                username=username,
                command_port=endpoint.command_port,
                tls_port=endpoint.sdk_tls_port,
            )
        ),
        settings_login_id=settings_login_id,
        channel_number=channel_number,
        playback_intent=playback_intent,
        play_device_login=play_device_login,
        play_device_login_id=play_device_login_id,
        live_view=live_view,
    )


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
        )
    )


def build_ezviz_local_stream_setup_request_body(
    *,
    session: str | int,
    rate: str | int = 0,
    mode: str | int = 0,
) -> bytes:
    """Build the plaintext XML body for the observed 0x3105 request."""
    return _build_local_sdk_request_xml(
        (
            ("Session", session),
            ("Rate", rate),
            ("Mode", mode),
        )
    )


class EzvizLocalSdkClient:
    """Socket client for the EZVIZ direct-local SDK frame layer.

    Callers provide the classified plaintext setup fields. The client handles
    the confirmed envelope, AES-CBC/PKCS#5 wrapping, ciphertext MD5 trailer,
    socket split between command and stream ports, and interleaved RTP reads.
    """

    def __init__(
        self,
        endpoint: HcNetSdkLanEndpoint,
        device_info: EzvizCasDeviceInfo,
        *,
        timeout: float | None = 5.0,
        socket_factory: SocketFactory = socket.create_connection,
        iv_factory: LocalSdkIvFactory = ezviz_local_sdk_ssl_iv,
        response_trailer_length: int = EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH,
        command_source_port: int | None = None,
        command_source_host: str = "",
    ) -> None:
        if endpoint.stream_port is None:
            raise PyEzvizError("Missing EZVIZ local stream port")
        self.endpoint = endpoint
        self.device_info = device_info
        self.timeout = timeout
        self.socket_factory = socket_factory
        self.iv_factory = iv_factory
        self._request_iv = iv_factory(EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE)
        self.response_trailer_length = response_trailer_length
        if command_source_port is not None and command_source_port < 0:
            raise PyEzvizError("EZVIZ local SDK command source port must be non-negative")
        self.command_source_port = command_source_port
        self.command_source_host = command_source_host
        self._command_sock: Any | None = None
        self._stream_sock: Any | None = None

    def __enter__(self) -> EzvizLocalSdkClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close any opened local sockets."""
        for sock in (self._command_sock, self._stream_sock):
            if sock is not None:
                sock.close()
        self._command_sock = None
        self._stream_sock = None

    def send_encrypted_command(
        self,
        command: int,
        body: bytes | str,
        *,
        sequence: int = 0,
        stream_socket: bool = False,
    ) -> EzvizLocalSdkExchange:
        """Send one encrypted local SDK frame and read its response frame."""
        sock = self._stream() if stream_socket else self._command()
        request = build_ezviz_cas_ssl_local_sdk_frame(
            command=command,
            body=body,
            device_info=self.device_info,
            iv=self._request_iv,
            sequence=sequence,
        )
        _send_all(sock, request)
        return EzvizLocalSdkExchange(
            request=request,
            response=read_ezviz_local_sdk_frame(
                sock,
                trailer_length=self.response_trailer_length,
            ),
        )

    def bootstrap_preview(
        self,
        *,
        preview_body: bytes | str,
        stream_setup_body: bytes | str,
        pre_start_body: bytes | str | None = None,
        pre_start_sequence: int = 0,
        preview_sequence: int = 0,
        stream_setup_sequence: int = 0,
        read_first_media: bool = False,
        max_prefix_bytes: int = 4096,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Run the confirmed direct-local setup shape.

        Some app flows send an encrypted 0x2013 pre-start command before the
        0x2011 preview setup. The body source is still caller-owned, so this
        method supports it as an optional supplied frame without trying to
        synthesize unknown fields.
        """
        pre_start = None
        if pre_start_body is not None:
            pre_start = self.send_encrypted_command(
                EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
                pre_start_body,
                sequence=pre_start_sequence,
            )
            if pre_start.response.header.command != EZVIZ_LOCAL_SDK_PRE_START_RESPONSE:
                raise PyEzvizError("EZVIZ local pre-start returned unexpected command")

        preview = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
            preview_body,
            sequence=preview_sequence,
        )
        if preview.response.header.command != EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE:
            raise PyEzvizError("EZVIZ local preview setup returned unexpected command")

        stream_setup = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
            stream_setup_body,
            sequence=stream_setup_sequence,
            stream_socket=True,
        )
        if stream_setup.response.header.command != EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE:
            raise PyEzvizError("EZVIZ local stream setup returned unexpected command")

        first_media = (
            self.read_first_stream_frame(max_prefix_bytes=max_prefix_bytes)
            if read_first_media
            else None
        )
        return EzvizLocalSdkStreamBootstrap(
            preview=preview,
            stream_setup=stream_setup,
            pre_start=pre_start,
            first_media=first_media,
        )

    def bootstrap_preview_from_fields(
        self,
        *,
        preview_request: EzvizLocalPreviewRequest,
        pre_start_body: bytes | str | None = None,
        pre_start_sequence: int = 0,
        preview_sequence: int = 0,
        stream_setup_sequence: int = 0,
        stream_rate: str | int = 0,
        stream_mode: str | int = 0,
        read_first_media: bool = False,
        max_prefix_bytes: int = 4096,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap preview and build 0x3105 from the 0x2012 Session."""
        pre_start = None
        if pre_start_body is not None:
            pre_start = self.send_encrypted_command(
                EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
                pre_start_body,
                sequence=pre_start_sequence,
            )
            if pre_start.response.header.command != EZVIZ_LOCAL_SDK_PRE_START_RESPONSE:
                raise PyEzvizError("EZVIZ local pre-start returned unexpected command")

        preview = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
            preview_request.to_xml(),
            sequence=preview_sequence,
        )
        if preview.response.header.command != EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE:
            raise PyEzvizError("EZVIZ local preview setup returned unexpected command")

        session = parse_ezviz_local_sdk_xml_fields(preview.response).get("Session")
        if not session:
            fields = parse_ezviz_local_sdk_xml_fields(preview.response)
            result = fields.get("Result")
            suffix = f" (Result={result})" if result else ""
            raise PyEzvizError(
                "EZVIZ local preview response is missing Session" + suffix
            )

        stream_setup = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
            build_ezviz_local_stream_setup_request_body(
                session=session,
                rate=stream_rate,
                mode=stream_mode,
            ),
            sequence=stream_setup_sequence,
            stream_socket=True,
        )
        if stream_setup.response.header.command != EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE:
            raise PyEzvizError("EZVIZ local stream setup returned unexpected command")

        first_media = (
            self.read_first_stream_frame(max_prefix_bytes=max_prefix_bytes)
            if read_first_media
            else None
        )
        return EzvizLocalSdkStreamBootstrap(
            preview=preview,
            stream_setup=stream_setup,
            pre_start=pre_start,
            first_media=first_media,
        )

    def read_first_stream_frame(
        self,
        *,
        max_prefix_bytes: int = 4096,
    ) -> EzvizInterleavedRtpFrameWithPrefix:
        """Read the first media frame after the local stream setup response."""
        return read_ezviz_interleaved_rtp_frame_after_prefix(
            self._stream(),
            max_prefix_bytes=max_prefix_bytes,
        )

    def read_stream_frame_after_prefix(
        self,
        *,
        max_prefix_bytes: int = 4096,
    ) -> EzvizInterleavedRtpFrameWithPrefix:
        """Read the next local stream frame, tolerating any binary preface."""
        return read_ezviz_interleaved_rtp_frame_after_prefix(
            self._stream(),
            max_prefix_bytes=max_prefix_bytes,
        )

    def _command(self) -> Any:
        if self._command_sock is None:
            source_address = (
                (self.command_source_host, self.command_source_port)
                if self.command_source_port is not None
                else None
            )
            self._command_sock = _connect_with_optional_source_address(
                self.socket_factory,
                (self.endpoint.host, self.endpoint.command_port),
                self.timeout,
                source_address=source_address,
            )
        return self._command_sock

    def _stream(self) -> Any:
        if self._stream_sock is None:
            self._stream_sock = self.socket_factory(
                (self.endpoint.host, self.endpoint.stream_port or 0),
                self.timeout,
            )
        return self._stream_sock


def _connect_with_optional_source_address(
    socket_factory: SocketFactory,
    address: tuple[str, int],
    timeout: float | None,
    *,
    source_address: SocketSourceAddress = None,
) -> Any:
    if source_address is None:
        return socket_factory(address, timeout)
    try:
        source_socket_factory = cast(SourceAddressSocketFactory, socket_factory)
        return source_socket_factory(address, timeout, source_address)
    except TypeError:
        if socket_factory is socket.create_connection:
            return socket.create_connection(
                address,
                timeout=timeout,
                source_address=source_address,
            )
        raise


def parse_ezviz_local_device(data: Mapping[str, Any]) -> EzvizLocalDevice:
    """Parse one EZVIZ ``/v3/devices/loc/list`` local-device record."""
    serial = _mapping_str(data, "deviceSerial")
    if not serial:
        raise PyEzvizError("Missing deviceSerial in EZVIZ local-device record")

    content = _parse_local_device_content(data.get("deviceContent"))
    return EzvizLocalDevice(
        serial=serial,
        name=_mapping_str(data, "deviceName"),
        model=_mapping_str(data, "deviceModel"),
        category=_mapping_str(data, "category"),
        device_category=_mapping_str(data, "deviceCategory"),
        group_id=_mapping_int(data, "groupId", default=None),
        content=content,
        raw=data,
    )


def parse_sadp_response(data: bytes | str) -> SadpDeviceInfo:
    """Parse an XML SADP response body into a small field mapping."""
    text = data.decode("utf-8", "ignore") if isinstance(data, bytes) else data
    start = text.find("<")
    end = text.rfind(">")
    if start == -1 or end == -1 or end <= start:
        raise PyEzvizError("SADP response does not contain XML")

    root = ET.fromstring(text[start : end + 1])
    fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        value = (element.text or "").strip()
        if value:
            fields[tag] = value
    return SadpDeviceInfo(fields=fields)


def parse_ezviz_local_sdk_frame_header(data: bytes) -> EzvizLocalSdkFrameHeader:
    """Parse the 32-byte EZVIZ local SDK control header.

    Normal app traces against a directly-owned camera showed this
    framing on both the command port and the stream setup port before XML
    bodies. The helper only parses the non-secret header; callers can decide
    whether retaining any body bytes is appropriate for their workflow.
    """
    if len(data) < EZVIZ_LOCAL_SDK_HEADER_LENGTH:
        raise PyEzvizError("EZVIZ local SDK frame header is truncated")
    magic = data[:4]
    if magic != EZVIZ_LOCAL_SDK_MAGIC:
        raise PyEzvizError("EZVIZ local SDK frame header has invalid magic")

    return EzvizLocalSdkFrameHeader(
        magic=magic,
        version=int.from_bytes(data[4:8], "big"),
        sequence=int.from_bytes(data[8:12], "big"),
        marker=int.from_bytes(data[12:16], "big"),
        command=int.from_bytes(data[18:20], "big"),
        status=int.from_bytes(data[20:24], "big"),
        body_length=int.from_bytes(data[24:28], "big"),
        reserved=int.from_bytes(data[28:32], "big"),
    )


def build_ezviz_local_sdk_frame_header(
    *,
    command: int,
    body_length: int = 0,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build the 32-byte EZVIZ local SDK header observed in app traces.

    This helper intentionally handles only the non-secret binary envelope. The
    body is caller-supplied because the XML fields still need classification
    before they are safe to persist or synthesize from app captures.
    """
    if not 0 <= command <= 0xFFFF:
        raise PyEzvizError("EZVIZ local SDK command must fit in 16 bits")
    if body_length < 0:
        raise PyEzvizError("EZVIZ local SDK body length must be non-negative")
    if not 0 <= status <= 0xFFFFFFFF:
        raise PyEzvizError("EZVIZ local SDK status must fit in 32 bits")

    return b"".join(
        (
            EZVIZ_LOCAL_SDK_MAGIC,
            version.to_bytes(4, "big"),
            sequence.to_bytes(4, "big"),
            marker.to_bytes(4, "big"),
            b"\x00\x00",
            command.to_bytes(2, "big"),
            status.to_bytes(4, "big"),
            body_length.to_bytes(4, "big"),
            reserved.to_bytes(4, "big"),
        )
    )


def build_ezviz_local_sdk_frame(
    *,
    command: int,
    body: bytes | str = b"",
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build an EZVIZ local SDK frame from a command and caller-owned body."""
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    return (
        build_ezviz_local_sdk_frame_header(
            command=command,
            body_length=len(body_bytes),
            sequence=sequence,
            version=version,
            marker=marker,
            status=status,
            reserved=reserved,
        )
        + body_bytes
    )


def encrypt_ezviz_local_sdk_body_aes_cbc(
    body: bytes | str,
    *,
    key: bytes | str,
    iv: bytes | str,
) -> bytes:
    """Encrypt a local SDK control body with AES-CBC/PKCS#5 padding.

    The EZVIZ app's local control frames use AES-CBC with 16-byte block
    padding before wrapping the encrypted bytes in the local SDK frame
    envelope. This helper does not derive or store device secrets; callers
    must supply key and IV bytes from their own credential source.
    """
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    return AES.new(
        _local_sdk_aes_bytes("key", key),
        AES.MODE_CBC,
        _local_sdk_aes_bytes("IV", iv),
    ).encrypt(_pkcs5_pad(body_bytes))


def decrypt_ezviz_local_sdk_body_aes_cbc(
    body: bytes,
    *,
    key: bytes | str,
    iv: bytes | str,
) -> bytes:
    """Decrypt a local SDK AES-CBC/PKCS#5 control body."""
    plain = AES.new(
        _local_sdk_aes_bytes("key", key),
        AES.MODE_CBC,
        _local_sdk_aes_bytes("IV", iv),
    ).decrypt(body)
    return _pkcs5_unpad(plain)


def build_encrypted_ezviz_local_sdk_frame(
    *,
    command: int,
    body: bytes | str,
    key: bytes | str,
    iv: bytes | str,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build an encrypted EZVIZ local SDK control frame.

    This is the reusable piece needed by the standalone reproducer after
    a caller has resolved the local CAS device-info key and IV source.
    """
    return build_ezviz_local_sdk_frame(
        command=command,
        body=encrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv),
        sequence=sequence,
        version=version,
        marker=marker,
        status=status,
        reserved=reserved,
    )


def build_ezviz_local_sdk_ssl_frame(
    *,
    command: int,
    body: bytes | str,
    key: bytes | str,
    iv: bytes | str,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build the app-observed local SDK SSL-like frame.

    Normal EZVIZ live view sends local control frames as a 32-byte local SDK
    header, AES-CBC/PKCS#5 ciphertext, and a 32-byte lowercase ASCII MD5 hex
    trailer over that ciphertext. The header body length covers only the
    ciphertext, matching the observed ``0x2011`` and ``0x3105`` sends.
    """
    iv_bytes = _local_sdk_aes_bytes("IV", iv)
    frame = build_encrypted_ezviz_local_sdk_frame(
        command=command,
        body=body,
        key=key,
        iv=iv_bytes,
        sequence=sequence,
        version=version,
        marker=marker,
        status=status,
        reserved=reserved,
    )
    parsed = parse_ezviz_local_sdk_frame(frame)
    trailer = hashlib.md5(parsed.body, usedforsecurity=False).hexdigest().encode(
        "ascii"
    )
    return frame + trailer


def ezviz_local_sdk_iv(serial: str, operation_code: str) -> bytes:
    """Build the AES-CBC IV used by EZVIZ local-control CAS frames."""
    iv = f"{serial}{operation_code}".encode("latin1")
    if len(iv) != EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError(
            "EZVIZ local SDK IV must be 16 bytes from serial + operation code"
        )
    return iv


def build_ezviz_cas_encrypted_local_sdk_frame(
    *,
    command: int,
    body: bytes | str,
    device_info: EzvizCasDeviceInfo,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build a local SDK frame using the app-observed CAS device-info tuple."""
    return build_encrypted_ezviz_local_sdk_frame(
        command=command,
        body=body,
        key=device_info.key_bytes,
        iv=device_info.iv_bytes,
        sequence=sequence,
        version=version,
        marker=marker,
        status=status,
        reserved=reserved,
    )


def build_ezviz_cas_ssl_local_sdk_frame(
    *,
    command: int,
    body: bytes | str,
    device_info: EzvizCasDeviceInfo,
    iv: bytes | str,
    sequence: int = 0,
    version: int = 0x01000000,
    marker: int = 0,
    status: int = 0xFFFFFFFF,
    reserved: int = 0,
) -> bytes:
    """Build a direct-local SDK frame with CAS key and ciphertext MD5 trailer."""
    return build_ezviz_local_sdk_ssl_frame(
        command=command,
        body=body,
        key=device_info.key_bytes,
        iv=iv,
        sequence=sequence,
        version=version,
        marker=marker,
        status=status,
        reserved=reserved,
    )


def parse_ezviz_local_sdk_frame(data: bytes) -> EzvizLocalSdkFrame:
    """Parse an EZVIZ local SDK frame and validate its declared body length."""
    header = parse_ezviz_local_sdk_frame_header(data)
    frame_length = EZVIZ_LOCAL_SDK_HEADER_LENGTH + header.body_length
    if len(data) < frame_length:
        raise PyEzvizError("EZVIZ local SDK frame body is truncated")
    return EzvizLocalSdkFrame(
        header=header,
        body=data[EZVIZ_LOCAL_SDK_HEADER_LENGTH:frame_length],
        trailer=data[frame_length:],
    )


def parse_ezviz_local_sdk_xml_fields(
    data: bytes | str | EzvizLocalSdkFrame,
) -> dict[str, str]:
    """Parse a local SDK XML body into simple tag text fields."""
    if isinstance(data, EzvizLocalSdkFrame):
        body: bytes | str = data.body
    else:
        body = data
    text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else body
    start = text.find("<")
    end = text.rfind(">")
    if start == -1 or end == -1 or end <= start:
        raise PyEzvizError("EZVIZ local SDK body does not contain XML")

    root = ET.fromstring(text[start : end + 1])
    fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        value = (element.text or "").strip()
        if value:
            fields[tag] = value
    return fields


def classify_ezviz_local_sdk_body(data: bytes) -> EzvizLocalSdkBodyShape:
    """Classify frame body shape without exposing body contents.

    The app trace showed plain XML response bodies, but request bodies
    did not surface XML tags under redacted instrumentation. This helper keeps
    only aggregate properties and tag names, so it is safe to store in notes.
    """
    length = len(data)
    if length == 0:
        return EzvizLocalSdkBodyShape(
            kind="empty",
            length=0,
            printable_ratio=0.0,
            null_ratio=0.0,
            high_bit_ratio=0.0,
            entropy_bits_per_byte=0.0,
        )

    printable = sum(1 for byte in data if 0x20 <= byte <= 0x7E)
    nulls = data.count(0)
    high_bit = sum(1 for byte in data if byte >= 0x80)
    xml_offset = _xml_offset(data)
    xml_tags = _xml_tag_names(data[xml_offset:]) if xml_offset is not None else ()

    if xml_tags and xml_offset == 0:
        kind = "xml"
    elif xml_tags:
        kind = "prefixed_xml"
    elif high_bit / length > EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD:
        kind = "opaque_binary"
    elif printable / length > EZVIZ_BODY_PRINTABLE_THRESHOLD:
        kind = "printable_non_xml"
    else:
        kind = "binary"

    return EzvizLocalSdkBodyShape(
        kind=kind,
        length=length,
        printable_ratio=printable / length,
        null_ratio=nulls / length,
        high_bit_ratio=high_bit / length,
        entropy_bits_per_byte=_entropy_bits_per_byte(data),
        xml_offset=xml_offset,
        xml_tags=xml_tags,
    )


def read_ezviz_local_sdk_frame(
    sock: Any,
    *,
    trailer_length: int = 0,
) -> EzvizLocalSdkFrame:
    """Read one complete EZVIZ local SDK frame from a socket-like object."""
    if trailer_length < 0:
        raise PyEzvizError("EZVIZ local SDK trailer length must be non-negative")
    header_bytes = _recv_exact(sock, EZVIZ_LOCAL_SDK_HEADER_LENGTH)
    header = parse_ezviz_local_sdk_frame_header(header_bytes)
    return EzvizLocalSdkFrame(
        header=header,
        body=_recv_exact(sock, header.body_length),
        trailer=_recv_exact(sock, trailer_length) if trailer_length else b"",
    )


def parse_ezviz_interleaved_rtp_frame_header(
    data: bytes,
) -> EzvizInterleavedRtpFrameHeader:
    """Parse the 4-byte interleaved RTP prefix from EZVIZ local media.

    The local stream port emits dollar + channel + big-endian length before an
    RTP payload. The RTP payload then carries MPEG-PS data, often beginning
    with an RTP header followed by the MPEG-PS pack header.
    """
    if len(data) < 4:
        raise PyEzvizError("EZVIZ interleaved RTP header is truncated")
    if data[0] != EZVIZ_RTP_INTERLEAVED_MAGIC:
        raise PyEzvizError("EZVIZ interleaved RTP header has invalid magic")
    return EzvizInterleavedRtpFrameHeader(
        channel=data[1],
        payload_length=int.from_bytes(data[2:4], "big"),
    )


def build_ezviz_interleaved_rtp_frame_header(
    *,
    channel: int,
    payload_length: int,
) -> bytes:
    """Build a 4-byte interleaved RTP header."""
    if not 0 <= channel <= 0xFF:
        raise PyEzvizError("EZVIZ interleaved RTP channel must fit in 8 bits")
    if not 0 <= payload_length <= 0xFFFF:
        raise PyEzvizError("EZVIZ interleaved RTP payload length must fit in 16 bits")
    return bytes(
        (
            EZVIZ_RTP_INTERLEAVED_MAGIC,
            channel,
            *payload_length.to_bytes(2, "big"),
        )
    )


def read_ezviz_interleaved_rtp_frame(sock: Any) -> EzvizInterleavedRtpFrame:
    """Read one complete interleaved RTP frame from a socket-like object."""
    header = parse_ezviz_interleaved_rtp_frame_header(_recv_exact(sock, 4))
    return EzvizInterleavedRtpFrame(
        header=header,
        payload=_recv_exact(sock, header.payload_length),
    )


def read_ezviz_interleaved_rtp_frame_after_prefix(
    sock: Any,
    *,
    max_prefix_bytes: int = 4096,
) -> EzvizInterleavedRtpFrameWithPrefix:
    """Read the first interleaved RTP frame, preserving any binary preface.

    The local stream port sends a short binary preface after the encrypted
    ``0x3105`` setup succeeds, then switches to ``$`` interleaved RTP frames.
    A standalone reproducer needs to tolerate that preface without discarding
    it silently.
    """
    if max_prefix_bytes < 0:
        raise PyEzvizError("EZVIZ RTP prefix limit must be non-negative")

    prefix = bytearray()
    while True:
        byte = _recv_exact(sock, 1)
        if byte[0] == EZVIZ_RTP_INTERLEAVED_MAGIC:
            header_tail = _recv_exact(sock, 3)
            header = parse_ezviz_interleaved_rtp_frame_header(byte + header_tail)
            return EzvizInterleavedRtpFrameWithPrefix(
                prefix=bytes(prefix),
                frame=EzvizInterleavedRtpFrame(
                    header=header,
                    payload=_recv_exact(sock, header.payload_length),
                ),
            )

        prefix.extend(byte)
        if len(prefix) > max_prefix_bytes:
            raise PyEzvizError("EZVIZ RTP prefix exceeded limit before frame magic")


def _parse_local_device_content(value: Any) -> EzvizLocalDeviceContent | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            data = json.loads(value)
        except ValueError as err:
            raise PyEzvizError("Invalid EZVIZ local deviceContent JSON") from err
    elif isinstance(value, Mapping):
        data = value
    else:
        return None

    return EzvizLocalDeviceContent(
        device_ip=_mapping_str(data, "deviceIP"),
        device_type=_mapping_int(data, "deviceType", default=None),
        device_enc_type=_mapping_int(data, "deviceEncType", default=None),
        is_low_power=_mapping_int(data, "isLowPower", default=None),
        device_max_act_limit=_mapping_int(data, "deviceMaxActLimit", default=None),
        device_sdk_version=_mapping_int(data, "deviceSdkVersion", default=None),
        device_rand=_mapping_str(data, "deviceRand"),
        device_role_type=_mapping_int(data, "deviceRoleType", default=None),
    )


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


def _looks_tls_record(data: bytes) -> bool:
    if len(data) < 5:
        return False
    content_type = data[0]
    major = data[1]
    minor = data[2]
    record_length = int.from_bytes(data[3:5], "big")
    return (
        content_type in {20, 21, 22, 23}
        and major == 3
        and 0 <= minor <= 4
        and record_length <= max(0, len(data) - 5)
    )


def _hcnetsdk_tcp_payload_kind(
    data: bytes,
    *,
    printable_ratio: float,
    high_bit_ratio: float,
    xml_offset: int | None,
    xml_tags: tuple[str, ...],
    declared_length_offset: int | None,
) -> str:
    known_kind = _hcnetsdk_known_prefix_kind(data)
    if known_kind is not None:
        kind = known_kind
    elif xml_tags and xml_offset == 0:
        kind = "xml"
    elif xml_tags:
        kind = "prefixed_xml"
    elif declared_length_offset is not None:
        kind = "length_prefixed_binary"
    elif high_bit_ratio > EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD:
        kind = "opaque_binary"
    elif printable_ratio > EZVIZ_BODY_PRINTABLE_THRESHOLD:
        kind = "printable_non_xml"
    else:
        kind = "binary"
    return kind


def _hcnetsdk_known_prefix_kind(data: bytes) -> str | None:
    if data.startswith(bytes((EZVIZ_RTP_INTERLEAVED_MAGIC,))):
        return "interleaved_media"
    if _looks_tls_record(data):
        return "tls_record"
    for prefix, kind in (
        (EZVIZ_LOCAL_SDK_MAGIC, "ezviz_local_sdk_frame"),
        (b"HTTP/", "http"),
        (b"GET ", "http"),
        (b"POST ", "http"),
        (b"PUT ", "http"),
        (HCNETSDK_HKMI_PREFIX, "hik_hkmi"),
        (HCNETSDK_HIK_PRIVATE_PREFIX, "hik_private"),
        (HCNETSDK_MPEG_PS_PACK_HEADER, "mpeg_ps"),
    ):
        if data.startswith(prefix):
            return kind
    return None


def _hcnetsdk_declared_length(data: bytes) -> tuple[int | None, int | None]:
    """Return a plausible embedded length field if one matches captured bytes."""
    candidates: list[tuple[int, int]] = []
    for offset in (0, 2, 4, 8, 12, 16, 20, 24):
        if len(data) >= offset + 4:
            candidates.append((offset, int.from_bytes(data[offset : offset + 4], "big")))
            candidates.append(
                (offset, int.from_bytes(data[offset : offset + 4], "little"))
            )
        if len(data) >= offset + 2:
            candidates.append((offset, int.from_bytes(data[offset : offset + 2], "big")))
            candidates.append(
                (offset, int.from_bytes(data[offset : offset + 2], "little"))
            )

    for offset, value in candidates:
        if value in {len(data), len(data) - offset, len(data) - offset - 4}:
            return offset, value
    return None, None


def _parse_shape_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in text.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value.rstrip(",")
    return fields


def _parse_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None


def _parse_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _event_field_int(event: HcNetSdkSemanticLogEvent, name: str) -> int | None:
    fields = event.fields or {}
    return _parse_int(fields.get(name))


def _event_field_bool(event: HcNetSdkSemanticLogEvent, name: str) -> bool:
    fields = event.fields or {}
    return fields.get(name, "").lower() == "true"


def _hcnetsdk_shape_command_candidate(
    record: HcNetSdkTcpShapeLogRecord,
) -> int | None:
    if record.direction not in {"send", "write"}:
        return None
    candidate = record.shape.u32le_4
    if hcnetsdk_command_candidate_role(candidate) is None:
        return None
    return candidate


def _parse_length_candidates(value: str | None) -> dict[str, int]:
    if not value:
        return {}
    candidates: dict[str, int] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        name, raw = part.split("=", 1)
        parsed = _parse_int(raw)
        if parsed is not None:
            candidates[name] = parsed
    return candidates


def _parse_length_candidate_offset(name: str) -> int | None:
    match = re.search(r"@(\d+)$", name)
    return int(match.group(1)) if match else None


def _recv_exact(sock: Any, length: int) -> bytes:
    if length < 0:
        raise PyEzvizError("Cannot read a negative byte count")
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise PyEzvizError("Socket closed before expected EZVIZ frame bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_all(sock: Any, data: bytes) -> None:
    sendall = getattr(sock, "sendall", None)
    if callable(sendall):
        sendall(data)
        return

    sent = 0
    while sent < len(data):
        count = sock.send(data[sent:])
        if count <= 0:
            raise PyEzvizError("Socket closed before EZVIZ frame was sent")
        sent += count


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
                raise PyEzvizError(
                    "Structured receiver info ex must use ReceiverInfoEx tag"
                )
            lines.extend(value.xml_lines())
            continue
        if isinstance(value, EzvizLocalAuthenticationAttrs):
            if tag != "Authentication":
                raise PyEzvizError(
                    "Structured authentication must use Authentication tag"
                )
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
    if len(data) != EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError(f"EZVIZ local SDK AES {label} must be 16 bytes")
    return data


def _pkcs5_pad(data: bytes) -> bytes:
    pad_len = EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE - (
        len(data) % EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
    )
    return data + (bytes((pad_len,)) * pad_len)


def _pkcs5_unpad(data: bytes) -> bytes:
    if not data or len(data) % EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError("EZVIZ local SDK AES body has invalid padded length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE:
        raise PyEzvizError("EZVIZ local SDK AES body has invalid padding")
    if data[-pad_len:] != bytes((pad_len,)) * pad_len:
        raise PyEzvizError("EZVIZ local SDK AES body has inconsistent padding")
    return data[:-pad_len]


def _entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for byte in set(data):
        probability = data.count(byte) / length
        entropy -= probability * math.log2(probability)
    return entropy


def _xml_offset(data: bytes) -> int | None:
    limit = min(len(data), EZVIZ_XML_DETECT_PREFIX_LIMIT)
    for offset in range(limit):
        if data[offset : offset + 1] != EZVIZ_XML_START_BYTE:
            continue
        if _xml_tag_names(data[offset:]):
            return offset
    return None


def _xml_tag_names(data: bytes) -> tuple[str, ...]:
    text = data.decode("utf-8", "ignore")
    tags: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r"</?([A-Za-z_][A-Za-z0-9_.:-]*)\b[^>]*>", text):
        tag = match.group(1)
        if tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tuple(tags)


def _probe_port(
    host: str,
    port: int,
    *,
    timeout: float | None,
    socket_factory: SocketFactory,
) -> HcNetSdkPortProbe:
    try:
        sock = socket_factory((host, port), timeout)
    except OSError as err:
        return HcNetSdkPortProbe(
            port=port,
            tcp_open=False,
            error=f"{type(err).__name__}: {err}",
        )

    passive_bytes = b""
    try:
        if timeout is not None:
            sock.settimeout(min(timeout, 1.0))
        try:
            passive_bytes = sock.recv(32)
        except TimeoutError:
            passive_bytes = b""
    finally:
        sock.close()

    tls_accepted: bool | None = None
    tls_error: str | None = None
    try:
        raw_sock = socket_factory((host, port), timeout)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            if timeout is not None:
                raw_sock.settimeout(timeout)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            tls_accepted = True
            tls_sock.close()
        except (OSError, ssl.SSLError) as err:
            raw_sock.close()
            tls_accepted = False
            tls_error = f"{type(err).__name__}: {err}"
    except OSError as err:
        tls_accepted = False
        tls_error = f"{type(err).__name__}: {err}"

    return HcNetSdkPortProbe(
        port=port,
        tcp_open=True,
        tls_accepted=tls_accepted,
        passive_bytes=passive_bytes,
        tls_error=tls_error,
    )
