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
from pyezvizapi.streaming.local.hcnetsdk.parameters import HcNetSdkConfiguredMedia, normalize_hcnetsdk_parameters
from pyezvizapi.streaming.media.header import EzvizStreamHeader, stream_header_from_preview

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


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkRealDataType as HcNetSdkRealDataType


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkLanEndpoint as HcNetSdkLanEndpoint


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkLoginCandidate as HcNetSdkLoginCandidate


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkStdXmlConfigRequest as HcNetSdkStdXmlConfigRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkStdXmlConfigResponse as HcNetSdkStdXmlConfigResponse


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanServicesSwitchState as EzvizLanServicesSwitchState


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanWifiApInfo as EzvizLanWifiApInfo


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanHdDiskConfig as EzvizLanHdDiskConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanHdConfig as EzvizLanHdConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanNtpConfig as EzvizLanNtpConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanNetInterfaceConfig as EzvizLanNetInterfaceConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanNetConfigV30 as EzvizLanNetConfigV30


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanDvrConfigSummary as EzvizLanDvrConfigSummary


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanEzvizAccessConfig as EzvizLanEzvizAccessConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanUserConfigV30Entry as EzvizLanUserConfigV30Entry


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanUserConfigV30 as EzvizLanUserConfigV30


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanDeviceConfigV40 as EzvizLanDeviceConfigV40


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanRecordDayConfig as EzvizLanRecordDayConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanRecordScheduleSegment as EzvizLanRecordScheduleSegment


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanRecordConfigV30 as EzvizLanRecordConfigV30


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanCameraParamConfig as EzvizLanCameraParamConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanWifiConnectStatus as EzvizLanWifiConnectStatus


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioInputParam as EzvizLanAudioInputParam


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioOutputVolume as EzvizLanAudioOutputVolume


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanCompressionInfoV30 as EzvizLanCompressionInfoV30


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanCompressionConfig as EzvizLanCompressionConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanPictureConfig as EzvizLanPictureConfig


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkDvrConfigRequest as HcNetSdkDvrConfigRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkFormatDiskRequest as HcNetSdkFormatDiskRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkFormatProgressRequest as HcNetSdkFormatProgressRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkCloseFormatHandleRequest as HcNetSdkCloseFormatHandleRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkSetupAlarmParam as HcNetSdkSetupAlarmParam


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkSetupAlarmRequest as HcNetSdkSetupAlarmRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkCloseAlarmRequest as HcNetSdkCloseAlarmRequest


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkSetSdkLocalCfgRequest as HcNetSdkSetSdkLocalCfgRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanSdFormatProgress as EzvizLanSdFormatProgress


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkDeviceAbilityRequest as HcNetSdkDeviceAbilityRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanPtzAbility as EzvizLanPtzAbility


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAccessProtocolAbility as EzvizLanAccessProtocolAbility


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanVideoPicAbility as EzvizLanVideoPicAbility


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanIpcFrontParameterRange as EzvizLanIpcFrontParameterRange


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanIpcFrontParameterAbility as EzvizLanIpcFrontParameterAbility


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanVideoResolution as EzvizLanVideoResolution


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioVideoCompressStream as EzvizLanAudioVideoCompressStream


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioVideoCompressVideoChannel as EzvizLanAudioVideoCompressVideoChannel


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioVideoCompressAudioChannel as EzvizLanAudioVideoCompressAudioChannel


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioVideoCompressVoiceTalkChannel as EzvizLanAudioVideoCompressVoiceTalkChannel


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanAudioVideoCompressInfo as EzvizLanAudioVideoCompressInfo


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkStreamDetails as HcNetSdkStreamDetails


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanDeviceSoftHardwareAbility as EzvizLanDeviceSoftHardwareAbility


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanPlaybackConvertResolution as EzvizLanPlaybackConvertResolution


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanPlaybackConvertAbility as EzvizLanPlaybackConvertAbility


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPtzControlRequest as HcNetSdkPtzControlRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPtzPresetRequest as HcNetSdkPtzPresetRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanPlaybackIntent as EzvizLanPlaybackIntent


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanVideoQuality as EzvizLanVideoQuality


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import EzvizLanLiveViewParams as EzvizLanLiveViewParams


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanKeyframeRequest as EzvizLanKeyframeRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkRealDataPacket as HcNetSdkRealDataPacket


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkTcpPayloadShape as HcNetSdkTcpPayloadShape


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import HcNetSdkTcpShapeLogRecord as HcNetSdkTcpShapeLogRecord


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkSemanticLogEvent as HcNetSdkSemanticLogEvent


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkCommandTraceSummary as HcNetSdkCommandTraceSummary


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkTcpFrameHeader as HcNetSdkTcpFrameHeader


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkTcpFrame as HcNetSdkTcpFrame


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortExchange as HcNetSdkCommandPortExchange


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortStreamBootstrap as HcNetSdkCommandPortStreamBootstrap


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortLoginChallenge as HcNetSdkCommandPortLoginChallenge


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortLoginSession as HcNetSdkCommandPortLoginSession


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortControlResponse as HcNetSdkCommandPortControlResponse


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkCommandPortControlTemplate as HcNetSdkCommandPortControlTemplate


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkTcpFrameShape as HcNetSdkTcpFrameShape


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkClientInfo as HcNetSdkClientInfo


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkRealPlayRequest as HcNetSdkRealPlayRequest


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLanPlayDeviceLogin as EzvizLanPlayDeviceLogin


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLanPreviewPlan as EzvizLanPreviewPlan


from pyezvizapi.streaming.local.hcnetsdk.models_playback import EzvizLanPlaybackPath as EzvizLanPlaybackPath


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalDeviceContent as EzvizLocalDeviceContent


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalDevice as EzvizLocalDevice


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizCasDeviceInfo as EzvizCasDeviceInfo


from pyezvizapi.streaming.local.hcnetsdk.models_session import HcNetSdkPortProbe as HcNetSdkPortProbe


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalSdkFrameHeader as EzvizLocalSdkFrameHeader


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalSdkFrame as EzvizLocalSdkFrame


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalSdkBodyShape as EzvizLocalSdkBodyShape


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizInterleavedRtpFrameHeader as EzvizInterleavedRtpFrameHeader


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizInterleavedRtpFrame as EzvizInterleavedRtpFrame


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizInterleavedRtpFrameWithPrefix as EzvizInterleavedRtpFrameWithPrefix


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalSdkExchange as EzvizLocalSdkExchange


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalSdkStreamBootstrap as EzvizLocalSdkStreamBootstrap


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalReceiverInfo as EzvizLocalReceiverInfo


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalReceiverInfoEx as EzvizLocalReceiverInfoEx


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalReceiverInfoAttrs as EzvizLocalReceiverInfoAttrs


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalReceiverInfoExAttrs as EzvizLocalReceiverInfoExAttrs


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalAuthenticationAttrs as EzvizLocalAuthenticationAttrs


from pyezvizapi.streaming.local.hcnetsdk.models_session import EzvizLocalPreviewRequest as EzvizLocalPreviewRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkNoArgRequest as HcNetSdkNoArgRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkInitRequest as HcNetSdkInitRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkSetConnectTimeRequest as HcNetSdkSetConnectTimeRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkGetErrorMsgRequest as HcNetSdkGetErrorMsgRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkLogoutRequest as HcNetSdkLogoutRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkTime as HcNetSdkTime


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkFileCond as HcNetSdkFileCond


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkFindFileRequest as HcNetSdkFindFileRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkFindDataV30 as HcNetSdkFindDataV30


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkFindNextFileRequest as HcNetSdkFindNextFileRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkFindCloseRequest as HcNetSdkFindCloseRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayCond as HcNetSdkPlayCond


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayBackByTimeRequest as HcNetSdkPlayBackByTimeRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayBackControlRequest as HcNetSdkPlayBackControlRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkStopPlayBackRequest as HcNetSdkStopPlayBackRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayBackCaptureFileRequest as HcNetSdkPlayBackCaptureFileRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayDataCallbackRequest as HcNetSdkPlayDataCallbackRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlaybackCallbackRequest as HcNetSdkPlaybackCallbackRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkPlayBackSecretKeyRequest as HcNetSdkPlayBackSecretKeyRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkGetFileByNameRequest as HcNetSdkGetFileByNameRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkGetFileByTimeRequest as HcNetSdkGetFileByTimeRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkStopGetFileRequest as HcNetSdkStopGetFileRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import HcNetSdkGetDownloadPosRequest as HcNetSdkGetDownloadPosRequest


from pyezvizapi.streaming.local.hcnetsdk.models_session import SadpDeviceInfo as SadpDeviceInfo


from pyezvizapi.streaming.local.hcnetsdk.models_playback import SadpActivateDeviceRequest as SadpActivateDeviceRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import SadpDeviceNetParam as SadpDeviceNetParam


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import SadpModifyDeviceNetParamRequest as SadpModifyDeviceNetParamRequest


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import SadpDeviceRetNetParam as SadpDeviceRetNetParam


from pyezvizapi.streaming.local.hcnetsdk.models_configuration import SadpModifyDeviceNetParamV40Request as SadpModifyDeviceNetParamV40Request


from pyezvizapi.streaming.local.hcnetsdk.models_playback import SadpNoArgRequest as SadpNoArgRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import SadpStartRequest as SadpStartRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import SadpSetLogToFileRequest as SadpSetLogToFileRequest


from pyezvizapi.streaming.local.hcnetsdk.models_playback import SadpBatchResult as SadpBatchResult


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_stdxml_response_json as hcnetsdk_stdxml_response_json


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_compression_info_v30 as _hcnetsdk_compression_info_v30


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_real_data_type_is_media as hcnetsdk_real_data_type_is_media


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_real_play_request as hcnetsdk_real_play_request


from pyezvizapi.streaming.local.hcnetsdk.serialization import classify_hcnetsdk_real_data_payload as classify_hcnetsdk_real_data_payload


from pyezvizapi.streaming.local.hcnetsdk.serialization import build_hcnetsdk_tcp_frame as build_hcnetsdk_tcp_frame


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_command_port_auth_word as hcnetsdk_command_port_auth_word


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_command_port_control_frame as hcnetsdk_command_port_control_frame


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_command_port_play_login_body_tail_for_today as hcnetsdk_command_port_play_login_body_tail_for_today


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_command_candidate_role as hcnetsdk_command_candidate_role


from pyezvizapi.streaming.local.hcnetsdk.serialization import ezviz_native_video_level as ezviz_native_video_level


from pyezvizapi.streaming.local.hcnetsdk.serialization import build_ezviz_local_preview_request_body as build_ezviz_local_preview_request_body


from pyezvizapi.streaming.local.hcnetsdk.serialization import ezviz_local_sdk_iv as ezviz_local_sdk_iv


from pyezvizapi.streaming.local.hcnetsdk.serialization import hcnetsdk_command_port_response_payload as hcnetsdk_command_port_response_payload


from pyezvizapi.streaming.local.hcnetsdk.serialization import _mapping_str as _mapping_str


from pyezvizapi.streaming.local.hcnetsdk.serialization import _mapping_int as _mapping_int


from pyezvizapi.streaming.local.hcnetsdk.serialization import _stdxml_bytes as _stdxml_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_native_bytes as _optional_native_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _native_secret_key_bytes as _native_secret_key_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _native_path_value as _native_path_value


from pyezvizapi.streaming.local.hcnetsdk.serialization import _bounded_bytes as _bounded_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _sadp_string_bytes as _sadp_string_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_raw_byte as _optional_raw_byte


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_raw_u16_be as _optional_raw_u16_be


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_raw_u32_be as _optional_raw_u32_be


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_raw_u16_be_pair as _optional_raw_u16_be_pair


from pyezvizapi.streaming.local.hcnetsdk.serialization import _optional_raw_byte_triplet as _optional_raw_byte_triplet


from pyezvizapi.streaming.local.hcnetsdk.serialization import _byte_value as _byte_value


from pyezvizapi.streaming.local.hcnetsdk.serialization import _word_value as _word_value


from pyezvizapi.streaming.local.hcnetsdk.serialization import _port_value as _port_value


from pyezvizapi.streaming.local.hcnetsdk.serialization import _nul_stripped_text as _nul_stripped_text


from pyezvizapi.streaming.local.hcnetsdk.serialization import _device_ability_bytes as _device_ability_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _ability_option_tuple as _ability_option_tuple


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_command_port_local_ip_word as _hcnetsdk_command_port_local_ip_word


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_command_port_auth_mask as _hcnetsdk_command_port_auth_mask


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_command_port_four_round_aes as _hcnetsdk_command_port_four_round_aes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes128_round_keys as _hcnetsdk_aes128_round_keys


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes_add_round_key as _hcnetsdk_aes_add_round_key


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes_sub_bytes as _hcnetsdk_aes_sub_bytes


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes_shift_rows as _hcnetsdk_aes_shift_rows


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes_xtime as _hcnetsdk_aes_xtime


from pyezvizapi.streaming.local.hcnetsdk.serialization import _hcnetsdk_aes_mix_columns as _hcnetsdk_aes_mix_columns


from pyezvizapi.streaming.local.hcnetsdk.serialization import _build_local_sdk_request_xml as _build_local_sdk_request_xml


from pyezvizapi.streaming.local.hcnetsdk.serialization import _xml_escape as _xml_escape


from pyezvizapi.streaming.local.hcnetsdk.serialization import _xml_attrs as _xml_attrs


from pyezvizapi.streaming.local.hcnetsdk.serialization import _local_sdk_aes_bytes as _local_sdk_aes_bytes
