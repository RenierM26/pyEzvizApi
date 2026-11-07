"""SDK model and serialization compatibility composition root."""
# Initialization order follows the retained public model surface.
from __future__ import annotations
import pyezvizapi.streaming.local.hcnetsdk as _compat_module_0
import pyezvizapi.streaming.local.hcnetsdk.constants as _constants
_sys = _constants._sys
base64 = _constants.base64
binascii = _constants.binascii
Iterable = _constants.Iterable
Mapping = _constants.Mapping
asdict = _constants.asdict
dataclass = _constants.dataclass
field = _constants.field
date = _constants.date
datetime = _constants.datetime
IntEnum = _constants.IntEnum
ipaddress = _constants.ipaddress
json = _constants.json
Any = _constants.Any
PyEzvizError = _constants.PyEzvizError
HcNetSdkConfiguredMedia = _constants.HcNetSdkConfiguredMedia
normalize_hcnetsdk_parameters = _constants.normalize_hcnetsdk_parameters
EzvizStreamHeader = _constants.EzvizStreamHeader
stream_header_from_preview = _constants.stream_header_from_preview
HCNETSDK_DEFAULT_SERVER_PORT = _constants.HCNETSDK_DEFAULT_SERVER_PORT
HCNETSDK_DEFAULT_TLS_PORT = _constants.HCNETSDK_DEFAULT_TLS_PORT
HCNETSDK_DEFAULT_RTSP_PORT = _constants.HCNETSDK_DEFAULT_RTSP_PORT
HCNETSDK_STDXML_INPUT_FIELD_ORDER = _constants.HCNETSDK_STDXML_INPUT_FIELD_ORDER
HCNETSDK_STDXML_OUTPUT_FIELD_ORDER = _constants.HCNETSDK_STDXML_OUTPUT_FIELD_ORDER
HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE = _constants.HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE = _constants.HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE = _constants.HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE
HCNETSDK_XML_MARKER = _constants.HCNETSDK_XML_MARKER
HCNETSDK_INIT = _constants.HCNETSDK_INIT
HCNETSDK_CLEANUP = _constants.HCNETSDK_CLEANUP
HCNETSDK_SET_CONNECT_TIME = _constants.HCNETSDK_SET_CONNECT_TIME
HCNETSDK_GET_LAST_ERROR = _constants.HCNETSDK_GET_LAST_ERROR
HCNETSDK_GET_ERROR_MSG = _constants.HCNETSDK_GET_ERROR_MSG
HCNETSDK_GET_SDK_VERSION = _constants.HCNETSDK_GET_SDK_VERSION
HCNETSDK_GET_SDK_BUILD_VERSION = _constants.HCNETSDK_GET_SDK_BUILD_VERSION
HCNETSDK_LOGOUT_V30 = _constants.HCNETSDK_LOGOUT_V30
HCNETSDK_FIND_FILE_V30 = _constants.HCNETSDK_FIND_FILE_V30
HCNETSDK_FIND_NEXT_FILE_V30 = _constants.HCNETSDK_FIND_NEXT_FILE_V30
HCNETSDK_FIND_CLOSE_V30 = _constants.HCNETSDK_FIND_CLOSE_V30
HCNETSDK_PLAYBACK_BY_TIME_V40 = _constants.HCNETSDK_PLAYBACK_BY_TIME_V40
HCNETSDK_PLAYBACK_CONTROL_V40 = _constants.HCNETSDK_PLAYBACK_CONTROL_V40
HCNETSDK_STOP_PLAYBACK = _constants.HCNETSDK_STOP_PLAYBACK
HCNETSDK_PLAYBACK_CAPTURE_FILE = _constants.HCNETSDK_PLAYBACK_CAPTURE_FILE
HCNETSDK_SET_PLAY_DATA_CALLBACK = _constants.HCNETSDK_SET_PLAY_DATA_CALLBACK
HCNETSDK_SET_PLAY_DATA_CALLBACK_V40 = _constants.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40
HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK = _constants.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK
HCNETSDK_SET_PLAYBACK_ES_CALLBACK = _constants.HCNETSDK_SET_PLAYBACK_ES_CALLBACK
HCNETSDK_SET_PLAYBACK_SECRET_KEY = _constants.HCNETSDK_SET_PLAYBACK_SECRET_KEY
HCNETSDK_GET_FILE_BY_NAME = _constants.HCNETSDK_GET_FILE_BY_NAME
HCNETSDK_GET_FILE_BY_TIME = _constants.HCNETSDK_GET_FILE_BY_TIME
HCNETSDK_STOP_GET_FILE = _constants.HCNETSDK_STOP_GET_FILE
HCNETSDK_GET_DOWNLOAD_POS = _constants.HCNETSDK_GET_DOWNLOAD_POS
HCNETSDK_FIND_FILE_FAILED = _constants.HCNETSDK_FIND_FILE_FAILED
HCNETSDK_PLAYBACK_FAILED = _constants.HCNETSDK_PLAYBACK_FAILED
HCNETSDK_GET_FILE_FAILED = _constants.HCNETSDK_GET_FILE_FAILED
HCNETSDK_PLAYBACK_FILE_TYPE_ALL = _constants.HCNETSDK_PLAYBACK_FILE_TYPE_ALL
HCNETSDK_PLAYBACK_LOCK_STATE_ALL = _constants.HCNETSDK_PLAYBACK_LOCK_STATE_ALL
HCNETSDK_TIME_FIELD_ORDER = _constants.HCNETSDK_TIME_FIELD_ORDER
HCNETSDK_FILECOND_FIELD_ORDER = _constants.HCNETSDK_FILECOND_FIELD_ORDER
HCNETSDK_FINDDATA_V30_FIELD_ORDER = _constants.HCNETSDK_FINDDATA_V30_FIELD_ORDER
HCNETSDK_PLAYCOND_FIELD_ORDER = _constants.HCNETSDK_PLAYCOND_FIELD_ORDER
HCNETSDK_SECRET_KEY_TYPE_AES = _constants.HCNETSDK_SECRET_KEY_TYPE_AES
HCNETSDK_MAKE_KEYFRAME_MAIN = _constants.HCNETSDK_MAKE_KEYFRAME_MAIN
HCNETSDK_MAKE_KEYFRAME_SUB = _constants.HCNETSDK_MAKE_KEYFRAME_SUB
HCNETSDK_GET_DVR_CONFIG = _constants.HCNETSDK_GET_DVR_CONFIG
HCNETSDK_SET_DVR_CONFIG = _constants.HCNETSDK_SET_DVR_CONFIG
HCNETSDK_FORMAT_DISK = _constants.HCNETSDK_FORMAT_DISK
HCNETSDK_GET_FORMAT_PROGRESS = _constants.HCNETSDK_GET_FORMAT_PROGRESS
HCNETSDK_CLOSE_FORMAT_HANDLE = _constants.HCNETSDK_CLOSE_FORMAT_HANDLE
HCNETSDK_GET_DEVICE_ABILITY = _constants.HCNETSDK_GET_DEVICE_ABILITY
HCNETSDK_SETUP_ALARM_CHAN_V30 = _constants.HCNETSDK_SETUP_ALARM_CHAN_V30
HCNETSDK_SETUP_ALARM_CHAN_V41 = _constants.HCNETSDK_SETUP_ALARM_CHAN_V41
HCNETSDK_CLOSE_ALARM_CHAN_V30 = _constants.HCNETSDK_CLOSE_ALARM_CHAN_V30
HCNETSDK_SET_SDK_LOCAL_CFG = _constants.HCNETSDK_SET_SDK_LOCAL_CFG
HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER = _constants.HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER
HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE = _constants.HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE = _constants.HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR = _constants.HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR
HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER = _constants.HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER
HCNETSDK_PTZ_PRESET_OTHER = _constants.HCNETSDK_PTZ_PRESET_OTHER
SADP_ACTIVATE_DEVICE = _constants.SADP_ACTIVATE_DEVICE
SADP_MODIFY_DEVICE_NET_PARAM = _constants.SADP_MODIFY_DEVICE_NET_PARAM
SADP_MODIFY_DEVICE_NET_PARAM_V40 = _constants.SADP_MODIFY_DEVICE_NET_PARAM_V40
SADP_GET_LAST_ERROR = _constants.SADP_GET_LAST_ERROR
SADP_GET_VERSION = _constants.SADP_GET_VERSION
SADP_SET_LOG_TO_FILE = _constants.SADP_SET_LOG_TO_FILE
SADP_START_V30 = _constants.SADP_START_V30
SADP_START_V40 = _constants.SADP_START_V40
SADP_STOP = _constants.SADP_STOP
SADP_CLEARUP = _constants.SADP_CLEARUP
SADP_SEND_INQUIRY = _constants.SADP_SEND_INQUIRY
SADP_NUL_BYTE = _constants.SADP_NUL_BYTE
SADP_DEV_NET_PARAM_ANDROID_FIELDS = _constants.SADP_DEV_NET_PARAM_ANDROID_FIELDS
SADP_DEV_NET_PARAM_JNA_FIELD_ORDER = _constants.SADP_DEV_NET_PARAM_JNA_FIELD_ORDER
SADP_DEV_RET_NET_PARAM_FIELD_ORDER = _constants.SADP_DEV_RET_NET_PARAM_FIELD_ORDER
SADP_DEV_RET_NET_PARAM_BUFFER_SIZE = _constants.SADP_DEV_RET_NET_PARAM_BUFFER_SIZE
EZVIZ_HCNETUTIL_LOGIN_V40 = _constants.EZVIZ_HCNETUTIL_LOGIN_V40
EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF = _constants.EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF
EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY = _constants.EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY
EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE = _constants.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE = _constants.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
EZVIZ_NATIVE_CREATE_CLIENT = _constants.EZVIZ_NATIVE_CREATE_CLIENT
EZVIZ_NATIVE_START_PREVIEW = _constants.EZVIZ_NATIVE_START_PREVIEW
HCNETSDK_REALPLAY_V30 = _constants.HCNETSDK_REALPLAY_V30
HCNETSDK_REALDATA_CALLBACK_V30 = _constants.HCNETSDK_REALDATA_CALLBACK_V30
EZVIZ_PLAYER_EXTRA_DEVICE_ID = _constants.EZVIZ_PLAYER_EXTRA_DEVICE_ID
EZVIZ_PLAYER_EXTRA_CHANNEL_NO = _constants.EZVIZ_PLAYER_EXTRA_CHANNEL_NO
EZVIZ_PLAYER_EXTRA_LAN_FLAG = _constants.EZVIZ_PLAYER_EXTRA_LAN_FLAG
EZVIZ_PLAYER_EXTRA_LAN_USERID = _constants.EZVIZ_PLAYER_EXTRA_LAN_USERID
EZVIZ_PLAYER_EXTRA_WIFI_SSID = _constants.EZVIZ_PLAYER_EXTRA_WIFI_SSID
EZVIZ_PLAYER_LAN_FLAG_HCNETSDK = _constants.EZVIZ_PLAYER_LAN_FLAG_HCNETSDK
EZVIZ_STREAM_SOURCE_LIVE_MINE = _constants.EZVIZ_STREAM_SOURCE_LIVE_MINE
EZVIZ_STREAM_INHIBIT_LAN = _constants.EZVIZ_STREAM_INHIBIT_LAN
EZVIZ_STREAM_TIMEOUT_MS = _constants.EZVIZ_STREAM_TIMEOUT_MS
EZVIZ_PREPLAY_SPS_TYPE = _constants.EZVIZ_PREPLAY_SPS_TYPE
EZVIZ_LAN_MAIN_VIDEO_LEVEL = _constants.EZVIZ_LAN_MAIN_VIDEO_LEVEL
EZVIZ_LAN_PTZ_SPEED_DEFAULT = _constants.EZVIZ_LAN_PTZ_SPEED_DEFAULT
EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE = _constants.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
HCNETSDK_MPEG_PS_PACK_HEADER = _constants.HCNETSDK_MPEG_PS_PACK_HEADER
HCNETSDK_MPEG_START_CODE_PREFIX = _constants.HCNETSDK_MPEG_START_CODE_PREFIX
HCNETSDK_MPEG_TS_SYNC_BYTE = _constants.HCNETSDK_MPEG_TS_SYNC_BYTE
HCNETSDK_HIK_PRIVATE_PREFIX = _constants.HCNETSDK_HIK_PRIVATE_PREFIX
HCNETSDK_HKMI_PREFIX = _constants.HCNETSDK_HKMI_PREFIX
HCNETSDK_TCP_HEADER_LENGTH = _constants.HCNETSDK_TCP_HEADER_LENGTH
HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN = _constants.HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN
HCNETSDK_COMMAND_CANDIDATE_CONTROL = _constants.HCNETSDK_COMMAND_CANDIDATE_CONTROL
HCNETSDK_COMMAND_PORT_CONTROL_FAMILY = _constants.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH = _constants.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH
HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH = _constants.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM = _constants.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
_AES_SBOX = _constants._AES_SBOX
_AES_RCON = _constants._AES_RCON
HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET = _constants.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET = _constants.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET = _constants.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET
HCNETSDK_COMPRESSION_INFO_V30_SIZE = _constants.HCNETSDK_COMPRESSION_INFO_V30_SIZE
HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET = _constants.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET
HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET = _constants.HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET
HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET = _constants.HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET
HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET = _constants.HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET
HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET = _constants.HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET
HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET = _constants.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET
HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET = _constants.HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET
HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET = _constants.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET
HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET = _constants.HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET
HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET = _constants.HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET
HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET = _constants.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET
HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET = _constants.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET

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
from pyezvizapi.streaming.local.hcnetsdk import serialization as _impl_serialization

def hcnetsdk_stdxml_response_json(response: Mapping[str, Any] | str | bytes) -> dict[str, Any]:
    """Parse a JSON response returned by EZVIZ local STDXML helpers."""
    return _impl_serialization.hcnetsdk_stdxml_response_json(response, _owner=_sys.modules[__name__])

def _hcnetsdk_compression_info_v30(raw: bytes, offset: int) -> EzvizLanCompressionInfoV30 | None:
    return _impl_serialization._hcnetsdk_compression_info_v30(raw, offset, _owner=_sys.modules[__name__])

def hcnetsdk_real_data_type_is_media(data_type: int) -> bool:
    """Return whether a real-play callback type can carry media payloads."""
    return _impl_serialization.hcnetsdk_real_data_type_is_media(data_type, _owner=_sys.modules[__name__])

def hcnetsdk_real_play_request(login_id: int, *, channel_number: int=1, link_mode: int=0, blocked: bool=False, multicast_ip: str='') -> HcNetSdkRealPlayRequest:
    """Build the APK-observed ``EZ_NET_DVR_RealPlay_V30`` argument model."""
    return _impl_serialization.hcnetsdk_real_play_request(login_id, channel_number=channel_number, link_mode=link_mode, blocked=blocked, multicast_ip=multicast_ip, _owner=_sys.modules[__name__])

def classify_hcnetsdk_real_data_payload(data: bytes) -> str:
    """Classify HCNetSDK callback bytes without decoding or exposing content."""
    return _impl_serialization.classify_hcnetsdk_real_data_payload(data, _owner=_sys.modules[__name__])

def build_hcnetsdk_tcp_frame(body: bytes=b'', *, field_4: int=0, field_8: int=0, field_12: int=0) -> bytes:
    """Build the generic observed HCNetSDK command-port frame wrapper."""
    return _impl_serialization.build_hcnetsdk_tcp_frame(body, field_4=field_4, field_8=field_8, field_12=field_12, _owner=_sys.modules[__name__])

def hcnetsdk_command_port_auth_word(*, session_id: bytes, auth_seed: int, command_id: int, key: bytes, addend: int | None=None, mask_seed: bytes=b'\x00' * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH) -> int:
    """Return the native HCNetSDK port-8000 post-login command auth word.

    ``session_id`` is the network-order four-byte id returned in the login
    response and reused in command bodies. Native ``libHCCore.so`` reverses it
    into a host-order word before the auth routine, uses the first 16 challenge
    bytes as a four-round AES-128 key, folds the 16-byte result down to one
    little-endian word, then adds the session-derived time/addend word used in
    the command header.
    """
    return _impl_serialization.hcnetsdk_command_port_auth_word(session_id=session_id, auth_seed=auth_seed, command_id=command_id, key=key, addend=addend, mask_seed=mask_seed, _owner=_sys.modules[__name__])

def hcnetsdk_command_port_control_frame(*, session_id: bytes, auth_seed: int, command_id: int, key: bytes, local_ip: str, body_tail: bytes=b'', addend: int | None=None, mask_seed: bytes=b'\x00' * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH) -> bytes:
    """Build one generated post-login HCNetSDK port-8000 control frame.

    The frame body format observed in native traces is the client LAN IPv4 word
    in little-endian byte order, the four-byte network-order login session id,
    eight reserved zero bytes, and then the command-specific tail. The auth word
    uses the same network-order session id returned by login.
    """
    return _impl_serialization.hcnetsdk_command_port_control_frame(session_id=session_id, auth_seed=auth_seed, command_id=command_id, key=key, local_ip=local_ip, body_tail=body_tail, addend=addend, mask_seed=mask_seed, _owner=_sys.modules[__name__])

def hcnetsdk_command_port_play_login_body_tail_for_today(body_tail: bytes, *, today: date | None=None) -> bytes:
    """Refresh native play-login date words in a captured ``0x111040`` tail."""
    return _impl_serialization.hcnetsdk_command_port_play_login_body_tail_for_today(body_tail, today=today, _owner=_sys.modules[__name__])

def hcnetsdk_command_candidate_role(candidate: int | None) -> str | None:
    """Return the current role label for an observed command candidate.

    The names are trace-derived labels, not a complete HCNetSDK command table.
    They are useful for reducing redacted captures while the underlying
    encrypted request format is still being mapped.
    """
    return _impl_serialization.hcnetsdk_command_candidate_role(candidate, _owner=_sys.modules[__name__])

def ezviz_native_video_level(video_level: int) -> int:
    """Mirror ``Utils.convertVideoLevel()`` before writing ``iVideoLevel``."""
    return _impl_serialization.ezviz_native_video_level(video_level, _owner=_sys.modules[__name__])

def build_ezviz_local_preview_request_body(*, operation_code: str, channel: int, receiver_info: str | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs, receiver_info_ex: str | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs, identifier: str | None=None, is_encrypt: str | int='TRUE', udt: int | None=None, nat: int | None=None, port_guess_type: int | None=None, timeout: int | None=None, heartbeat_interval: int | None=None, authentication: str | EzvizLocalAuthenticationAttrs | None=None, uuid: str | None=None, timestamp: str | int | None=None, public_key: str | None=None) -> bytes:  # noqa: PLR0913
    """Build the plaintext XML body for the observed 0x2011 request.

    The caller must supply values obtained through their own credential/source
    path. This helper only gives the confirmed tag order and escaping.
    """
    return _impl_serialization.build_ezviz_local_preview_request_body(operation_code=operation_code, channel=channel, receiver_info=receiver_info, receiver_info_ex=receiver_info_ex, identifier=identifier, is_encrypt=is_encrypt, udt=udt, nat=nat, port_guess_type=port_guess_type, timeout=timeout, heartbeat_interval=heartbeat_interval, authentication=authentication, uuid=uuid, timestamp=timestamp, public_key=public_key, _owner=_sys.modules[__name__])

def ezviz_local_sdk_iv(serial: str, operation_code: str) -> bytes:
    """Build the AES-CBC IV used by EZVIZ local-control CAS frames."""
    return _impl_serialization.ezviz_local_sdk_iv(serial, operation_code, _owner=_sys.modules[__name__])

def hcnetsdk_command_port_response_payload(response: HcNetSdkTcpFrame | bytes) -> bytes:
    """Return a textual JSON/XML payload from a command-port response.

    Native command-port responses may include leading binary or NUL padding
    before the string output buffer. Keep the rule intentionally narrow so
    binary command responses remain available to lower-level callers.
    """
    return _impl_serialization.hcnetsdk_command_port_response_payload(response, _owner=_sys.modules[__name__])

def _mapping_str(data: Mapping[str, Any], key: str) -> str | None:
    return _impl_serialization._mapping_str(data, key, _owner=_sys.modules[__name__])

def _mapping_int(data: Mapping[str, Any], key: str, *, default: int | None, zero_is_missing: bool=False) -> int | None:
    return _impl_serialization._mapping_int(data, key, default=default, zero_is_missing=zero_is_missing, _owner=_sys.modules[__name__])

def _stdxml_bytes(label: str, value: str | bytes) -> bytes:
    return _impl_serialization._stdxml_bytes(label, value, _owner=_sys.modules[__name__])

def _optional_native_bytes(label: str, value: str | bytes | None) -> bytes:
    return _impl_serialization._optional_native_bytes(label, value, _owner=_sys.modules[__name__])

def _native_secret_key_bytes(label: str, value: str | bytes) -> bytes:
    return _impl_serialization._native_secret_key_bytes(label, value, _owner=_sys.modules[__name__])

def _native_path_value(label: str, value: str | bytes, *, include_buffers: bool=False) -> str | bytes:
    return _impl_serialization._native_path_value(label, value, include_buffers=include_buffers, _owner=_sys.modules[__name__])

def _bounded_bytes(label: str, value: str | bytes, limit: int, *, truncate: bool=False) -> bytes:
    return _impl_serialization._bounded_bytes(label, value, limit, truncate=truncate, _owner=_sys.modules[__name__])

def _sadp_string_bytes(label: str, value: str | bytes, limit: int, *, allow_empty: bool=False) -> bytes:
    return _impl_serialization._sadp_string_bytes(label, value, limit, allow_empty=allow_empty, _owner=_sys.modules[__name__])

def _optional_raw_byte(raw: bytes, offset: int) -> int | None:
    return _impl_serialization._optional_raw_byte(raw, offset, _owner=_sys.modules[__name__])

def _optional_raw_u16_be(raw: bytes, offset: int) -> int | None:
    return _impl_serialization._optional_raw_u16_be(raw, offset, _owner=_sys.modules[__name__])

def _optional_raw_u32_be(raw: bytes, offset: int) -> int | None:
    return _impl_serialization._optional_raw_u32_be(raw, offset, _owner=_sys.modules[__name__])

def _optional_raw_u16_be_pair(raw: bytes, first_offset: int, second_offset: int) -> tuple[int, int] | None:
    return _impl_serialization._optional_raw_u16_be_pair(raw, first_offset, second_offset, _owner=_sys.modules[__name__])

def _optional_raw_byte_triplet(raw: bytes, first_offset: int, second_offset: int, third_offset: int) -> tuple[int, int, int] | None:
    return _impl_serialization._optional_raw_byte_triplet(raw, first_offset, second_offset, third_offset, _owner=_sys.modules[__name__])

def _byte_value(label: str, value: int) -> int:
    return _impl_serialization._byte_value(label, value, _owner=_sys.modules[__name__])

def _word_value(label: str, value: int) -> int:
    return _impl_serialization._word_value(label, value, _owner=_sys.modules[__name__])

def _port_value(label: str, value: int) -> int:
    return _impl_serialization._port_value(label, value, _owner=_sys.modules[__name__])

def _nul_stripped_text(value: str | bytes | None) -> str:
    return _impl_serialization._nul_stripped_text(value, _owner=_sys.modules[__name__])

def _device_ability_bytes(label: str, value: str | bytes) -> bytes:
    return _impl_serialization._device_ability_bytes(label, value, _owner=_sys.modules[__name__])

def _ability_option_tuple(value: str | None) -> tuple[str, ...]:
    return _impl_serialization._ability_option_tuple(value, _owner=_sys.modules[__name__])

def _hcnetsdk_command_port_local_ip_word(local_ip: str) -> bytes:
    return _impl_serialization._hcnetsdk_command_port_local_ip_word(local_ip, _owner=_sys.modules[__name__])

def _hcnetsdk_command_port_auth_mask(session_word: int, mask_seed: bytes) -> int:
    """Return the small native mask term mixed into command auth input."""
    return _impl_serialization._hcnetsdk_command_port_auth_mask(session_word, mask_seed, _owner=_sys.modules[__name__])

def _hcnetsdk_command_port_four_round_aes(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block with the SDK's four-round AES-128 variant."""
    return _impl_serialization._hcnetsdk_command_port_four_round_aes(block, key, _owner=_sys.modules[__name__])

def _hcnetsdk_aes128_round_keys(key: bytes, *, rounds: int) -> tuple[bytes, ...]:
    """Return AES-128 round keys, truncated to the native command-auth rounds."""
    return _impl_serialization._hcnetsdk_aes128_round_keys(key, rounds=rounds, _owner=_sys.modules[__name__])

def _hcnetsdk_aes_add_round_key(state: bytes, round_key: bytes) -> bytes:
    return _impl_serialization._hcnetsdk_aes_add_round_key(state, round_key, _owner=_sys.modules[__name__])

def _hcnetsdk_aes_sub_bytes(state: bytes) -> bytes:
    return _impl_serialization._hcnetsdk_aes_sub_bytes(state, _owner=_sys.modules[__name__])

def _hcnetsdk_aes_shift_rows(state: bytes) -> bytes:
    return _impl_serialization._hcnetsdk_aes_shift_rows(state, _owner=_sys.modules[__name__])

def _hcnetsdk_aes_xtime(value: int) -> int:
    return _impl_serialization._hcnetsdk_aes_xtime(value, _owner=_sys.modules[__name__])

def _hcnetsdk_aes_mix_columns(state: bytes) -> bytes:
    return _impl_serialization._hcnetsdk_aes_mix_columns(state, _owner=_sys.modules[__name__])

def _build_local_sdk_request_xml(fields: tuple[tuple[str, str | int | EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs | EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs | EzvizLocalAuthenticationAttrs | None], ...]) -> bytes:
    return _impl_serialization._build_local_sdk_request_xml(fields, _owner=_sys.modules[__name__])

def _xml_escape(value: str) -> str:
    return _impl_serialization._xml_escape(value, _owner=_sys.modules[__name__])

def _xml_attrs(fields: Iterable[tuple[str, str | int]]) -> str:
    return _impl_serialization._xml_attrs(fields, _owner=_sys.modules[__name__])

def _local_sdk_aes_bytes(label: str, value: bytes | str) -> bytes:
    return _impl_serialization._local_sdk_aes_bytes(label, value, _owner=_sys.modules[__name__])
