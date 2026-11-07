# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.hcnetsdk.api`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local.hcnetsdk import api as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher.AES as _compat_typed_AES

    AES = _compat_typed_AES
    import Crypto.Cipher.PKCS1_v1_5 as _compat_typed_PKCS1_v1_5

    PKCS1_v1_5 = _compat_typed_PKCS1_v1_5
    import Crypto.PublicKey.RSA as _compat_typed_RSA

    RSA = _compat_typed_RSA
    import Crypto.Util.asn1 as _compat_module_2

    DerSequence = _compat_module_2.DerSequence

    import pyezvizapi.streaming.local.hcnetsdk.api as _compat_module_3

    _AES_RCON = _compat_module_3._AES_RCON
    _AES_SBOX = _compat_module_3._AES_SBOX
    _WINDOWS_EXCLUSIVE_SOURCE_BIND = _compat_module_3._WINDOWS_EXCLUSIVE_SOURCE_BIND
    DEFAULT_RESOLVER = _compat_module_3.DEFAULT_RESOLVER
    ET = _compat_module_3.ET
    EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD = _compat_module_3.EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD
    EZVIZ_BODY_PRINTABLE_THRESHOLD = _compat_module_3.EZVIZ_BODY_PRINTABLE_THRESHOLD
    EZVIZ_CAS_PTZ_COMMAND_MAP = _compat_module_3.EZVIZ_CAS_PTZ_COMMAND_MAP
    EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE = _compat_module_3.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    EZVIZ_HCNETUTIL_LOGIN_V40 = _compat_module_3.EZVIZ_HCNETUTIL_LOGIN_V40
    EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF = _compat_module_3.EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF
    EZVIZ_LAN_MAIN_STREAM_TYPE = _compat_module_3.EZVIZ_LAN_MAIN_STREAM_TYPE
    EZVIZ_LAN_MAIN_VIDEO_LEVEL = _compat_module_3.EZVIZ_LAN_MAIN_VIDEO_LEVEL
    EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP = _compat_module_3.EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP
    EZVIZ_LAN_PTZ_ACTION_RESET = _compat_module_3.EZVIZ_LAN_PTZ_ACTION_RESET
    EZVIZ_LAN_PTZ_ACTION_START = _compat_module_3.EZVIZ_LAN_PTZ_ACTION_START
    EZVIZ_LAN_PTZ_ACTION_STOP = _compat_module_3.EZVIZ_LAN_PTZ_ACTION_STOP
    EZVIZ_LAN_PTZ_COMMAND_MAP = _compat_module_3.EZVIZ_LAN_PTZ_COMMAND_MAP
    EZVIZ_LAN_PTZ_PRESET_COMMANDS = _compat_module_3.EZVIZ_LAN_PTZ_PRESET_COMMANDS
    EZVIZ_LAN_PTZ_SPEED_DEFAULT = _compat_module_3.EZVIZ_LAN_PTZ_SPEED_DEFAULT
    EZVIZ_LAN_SUB_STREAM_TYPE = _compat_module_3.EZVIZ_LAN_SUB_STREAM_TYPE
    EZVIZ_LAN_SUB_VIDEO_LEVEL = _compat_module_3.EZVIZ_LAN_SUB_VIDEO_LEVEL
    EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE = _compat_module_3.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
    EZVIZ_LOCAL_SDK_HEADER_LENGTH = _compat_module_3.EZVIZ_LOCAL_SDK_HEADER_LENGTH
    EZVIZ_LOCAL_SDK_MAGIC = _compat_module_3.EZVIZ_LOCAL_SDK_MAGIC
    EZVIZ_LOCAL_SDK_PRE_START_COMMAND = _compat_module_3.EZVIZ_LOCAL_SDK_PRE_START_COMMAND
    EZVIZ_LOCAL_SDK_PRE_START_RESPONSE = _compat_module_3.EZVIZ_LOCAL_SDK_PRE_START_RESPONSE
    EZVIZ_LOCAL_SDK_PREVIEW_COMMAND = _compat_module_3.EZVIZ_LOCAL_SDK_PREVIEW_COMMAND
    EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE = _compat_module_3.EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE
    EZVIZ_LOCAL_SDK_SSL_IV_PREFIX = _compat_module_3.EZVIZ_LOCAL_SDK_SSL_IV_PREFIX
    EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH = _compat_module_3.EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH
    EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES = _compat_module_3.EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES
    EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND = _compat_module_3.EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND
    EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE = _compat_module_3.EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE
    EZVIZ_LOCAL_SDK_STOP_TIMEOUT = _compat_module_3.EZVIZ_LOCAL_SDK_STOP_TIMEOUT
    EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND = _compat_module_3.EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE = _compat_module_3.EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE
    EZVIZ_NATIVE_CREATE_CLIENT = _compat_module_3.EZVIZ_NATIVE_CREATE_CLIENT
    EZVIZ_NATIVE_START_PREVIEW = _compat_module_3.EZVIZ_NATIVE_START_PREVIEW
    EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE = _compat_module_3.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
    EZVIZ_PLAYER_EXTRA_CHANNEL_NO = _compat_module_3.EZVIZ_PLAYER_EXTRA_CHANNEL_NO
    EZVIZ_PLAYER_EXTRA_DEVICE_ID = _compat_module_3.EZVIZ_PLAYER_EXTRA_DEVICE_ID
    EZVIZ_PLAYER_EXTRA_LAN_FLAG = _compat_module_3.EZVIZ_PLAYER_EXTRA_LAN_FLAG
    EZVIZ_PLAYER_EXTRA_LAN_USERID = _compat_module_3.EZVIZ_PLAYER_EXTRA_LAN_USERID
    EZVIZ_PLAYER_EXTRA_WIFI_SSID = _compat_module_3.EZVIZ_PLAYER_EXTRA_WIFI_SSID
    EZVIZ_PLAYER_LAN_FLAG_EZLINK = _compat_module_3.EZVIZ_PLAYER_LAN_FLAG_EZLINK
    EZVIZ_PLAYER_LAN_FLAG_HCNETSDK = _compat_module_3.EZVIZ_PLAYER_LAN_FLAG_HCNETSDK
    EZVIZ_PREPLAY_SPS_TYPE = _compat_module_3.EZVIZ_PREPLAY_SPS_TYPE
    EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY = (
        _compat_module_3.EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY
    )
    EZVIZ_RTP_INTERLEAVED_MAGIC = _compat_module_3.EZVIZ_RTP_INTERLEAVED_MAGIC
    EZVIZ_STREAM_INHIBIT_LAN = _compat_module_3.EZVIZ_STREAM_INHIBIT_LAN
    EZVIZ_STREAM_SOURCE_LIVE_MINE = _compat_module_3.EZVIZ_STREAM_SOURCE_LIVE_MINE
    EZVIZ_STREAM_TIMEOUT_MS = _compat_module_3.EZVIZ_STREAM_TIMEOUT_MS
    EZVIZ_XML_DETECT_PREFIX_LIMIT = _compat_module_3.EZVIZ_XML_DETECT_PREFIX_LIMIT
    EZVIZ_XML_START_BYTE = _compat_module_3.EZVIZ_XML_START_BYTE
    HCNETSDK_AUDIO_INPUT_PARAM_SIZE = _compat_module_3.HCNETSDK_AUDIO_INPUT_PARAM_SIZE
    HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE = _compat_module_3.HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE
    HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET = (
        _compat_module_3.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET
    )
    HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET = (
        _compat_module_3.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET
    )
    HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE = _compat_module_3.HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE
    HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET = _compat_module_3.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET
    HCNETSDK_CLEANUP = _compat_module_3.HCNETSDK_CLEANUP
    HCNETSDK_CLOSE_ALARM_CHAN_V30 = _compat_module_3.HCNETSDK_CLOSE_ALARM_CHAN_V30
    HCNETSDK_CLOSE_FORMAT_HANDLE = _compat_module_3.HCNETSDK_CLOSE_FORMAT_HANDLE
    HCNETSDK_COMMAND_CANDIDATE_CONTROL = _compat_module_3.HCNETSDK_COMMAND_CANDIDATE_CONTROL
    HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN = (
        _compat_module_3.HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN
    )
    HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH = _compat_module_3.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH
    HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH = _compat_module_3.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
    HCNETSDK_COMMAND_PORT_CONTROL_FAMILY = _compat_module_3.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
    HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID = _compat_module_3.HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID
    HCNETSDK_COMMAND_PORT_LOGIN_FAMILY = _compat_module_3.HCNETSDK_COMMAND_PORT_LOGIN_FAMILY
    HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12 = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12
    )
    HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX
    )
    HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX
    )
    HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH
    )
    HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
    )
    HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH
    )
    HCNETSDK_COMMAND_PORT_RSA_BITS = _compat_module_3.HCNETSDK_COMMAND_PORT_RSA_BITS
    HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH = _compat_module_3.HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH
    HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH = (
        _compat_module_3.HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH
    )
    HCNETSDK_COMMAND_PORT_USERNAME_LENGTH = _compat_module_3.HCNETSDK_COMMAND_PORT_USERNAME_LENGTH
    HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET = _compat_module_3.HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET
    HCNETSDK_COMPRESSION_CFG_MIN_SIZE = _compat_module_3.HCNETSDK_COMPRESSION_CFG_MIN_SIZE
    HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET = (
        _compat_module_3.HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET
    )
    HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET = _compat_module_3.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET
    HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET = (
        _compat_module_3.HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET
    )
    HCNETSDK_COMPRESSION_INFO_V30_SIZE = _compat_module_3.HCNETSDK_COMPRESSION_INFO_V30_SIZE
    HCNETSDK_DEFAULT_RTSP_PORT = _compat_module_3.HCNETSDK_DEFAULT_RTSP_PORT
    HCNETSDK_DEFAULT_SERVER_PORT = _compat_module_3.HCNETSDK_DEFAULT_SERVER_PORT
    HCNETSDK_DEFAULT_TLS_PORT = _compat_module_3.HCNETSDK_DEFAULT_TLS_PORT
    HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR = (
        _compat_module_3.HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR
    )
    HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
    )
    HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
    )
    HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE
    )
    HCNETSDK_DEVICE_CFG_V40_MIN_SIZE = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_MIN_SIZE
    HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET
    HCNETSDK_DEVICE_CFG_V40_NAME_SIZE = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_NAME_SIZE
    HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET
    HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE
    HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET = (
        _compat_module_3.HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET
    )
    HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE = _compat_module_3.HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE
    HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS = (
        _compat_module_3.HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS
    )
    HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS = (
        _compat_module_3.HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE = _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE
    HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_SIZE = _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_SIZE
    HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET
    )
    HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE = (
        _compat_module_3.HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE
    )
    HCNETSDK_EZVIZ_CONNECT_MODE_PUT = _compat_module_3.HCNETSDK_EZVIZ_CONNECT_MODE_PUT
    HCNETSDK_EZVIZ_DEFAULT_USERNAME = _compat_module_3.HCNETSDK_EZVIZ_DEFAULT_USERNAME
    HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX = _compat_module_3.HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX
    HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX = (
        _compat_module_3.HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX
    )
    HCNETSDK_EZVIZ_LOCAL_USERNAME = _compat_module_3.HCNETSDK_EZVIZ_LOCAL_USERNAME
    HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT = _compat_module_3.HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT
    HCNETSDK_EZVIZ_SERVICES_SWITCH_GET = _compat_module_3.HCNETSDK_EZVIZ_SERVICES_SWITCH_GET
    HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT = _compat_module_3.HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR = (
        _compat_module_3.HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR
    )
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR = (
        _compat_module_3.HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR
    )
    HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE = _compat_module_3.HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE
    HCNETSDK_FILECOND_FIELD_ORDER = _compat_module_3.HCNETSDK_FILECOND_FIELD_ORDER
    HCNETSDK_FIND_CLOSE_V30 = _compat_module_3.HCNETSDK_FIND_CLOSE_V30
    HCNETSDK_FIND_FILE_FAILED = _compat_module_3.HCNETSDK_FIND_FILE_FAILED
    HCNETSDK_FIND_FILE_V30 = _compat_module_3.HCNETSDK_FIND_FILE_V30
    HCNETSDK_FIND_NEXT_FILE_EXCEPTION = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_EXCEPTION
    HCNETSDK_FIND_NEXT_FILE_IS_FINDING = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_IS_FINDING
    HCNETSDK_FIND_NEXT_FILE_NO_FILE = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_NO_FILE
    HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE
    HCNETSDK_FIND_NEXT_FILE_SUCCESS = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_SUCCESS
    HCNETSDK_FIND_NEXT_FILE_V30 = _compat_module_3.HCNETSDK_FIND_NEXT_FILE_V30
    HCNETSDK_FINDDATA_V30_FIELD_ORDER = _compat_module_3.HCNETSDK_FINDDATA_V30_FIELD_ORDER
    HCNETSDK_FORMAT_DISK = _compat_module_3.HCNETSDK_FORMAT_DISK
    HCNETSDK_GET_DEVICE_ABILITY = _compat_module_3.HCNETSDK_GET_DEVICE_ABILITY
    HCNETSDK_GET_DOWNLOAD_POS = _compat_module_3.HCNETSDK_GET_DOWNLOAD_POS
    HCNETSDK_GET_DVR_CONFIG = _compat_module_3.HCNETSDK_GET_DVR_CONFIG
    HCNETSDK_GET_ERROR_MSG = _compat_module_3.HCNETSDK_GET_ERROR_MSG
    HCNETSDK_GET_FILE_BY_NAME = _compat_module_3.HCNETSDK_GET_FILE_BY_NAME
    HCNETSDK_GET_FILE_BY_TIME = _compat_module_3.HCNETSDK_GET_FILE_BY_TIME
    HCNETSDK_GET_FILE_FAILED = _compat_module_3.HCNETSDK_GET_FILE_FAILED
    HCNETSDK_GET_FORMAT_PROGRESS = _compat_module_3.HCNETSDK_GET_FORMAT_PROGRESS
    HCNETSDK_GET_LAST_ERROR = _compat_module_3.HCNETSDK_GET_LAST_ERROR
    HCNETSDK_GET_SDK_BUILD_VERSION = _compat_module_3.HCNETSDK_GET_SDK_BUILD_VERSION
    HCNETSDK_GET_SDK_VERSION = _compat_module_3.HCNETSDK_GET_SDK_VERSION
    HCNETSDK_HD_CFG_DISK_ATTR_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_ATTR_OFFSET
    HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET
    HCNETSDK_HD_CFG_DISK_COUNT = _compat_module_3.HCNETSDK_HD_CFG_DISK_COUNT
    HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET
    HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET = (
        _compat_module_3.HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET
    )
    HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET
    HCNETSDK_HD_CFG_DISK_GROUP_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_GROUP_OFFSET
    HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET
    HCNETSDK_HD_CFG_DISK_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_OFFSET
    HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET = (
        _compat_module_3.HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET
    )
    HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET
    HCNETSDK_HD_CFG_DISK_SIZE = _compat_module_3.HCNETSDK_HD_CFG_DISK_SIZE
    HCNETSDK_HD_CFG_DISK_STATUS_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_STATUS_OFFSET
    HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET = (
        _compat_module_3.HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET
    )
    HCNETSDK_HD_CFG_DISK_TYPE_OFFSET = _compat_module_3.HCNETSDK_HD_CFG_DISK_TYPE_OFFSET
    HCNETSDK_HD_CFG_HEADER_SIZE = _compat_module_3.HCNETSDK_HD_CFG_HEADER_SIZE
    HCNETSDK_HD_CFG_MIN_SIZE = _compat_module_3.HCNETSDK_HD_CFG_MIN_SIZE
    HCNETSDK_HIK_PRIVATE_PREFIX = _compat_module_3.HCNETSDK_HIK_PRIVATE_PREFIX
    HCNETSDK_HKMI_PREFIX = _compat_module_3.HCNETSDK_HKMI_PREFIX
    HCNETSDK_INIT = _compat_module_3.HCNETSDK_INIT
    HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER = (
        _compat_module_3.HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER
    )
    HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER = _compat_module_3.HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER
    HCNETSDK_LOGIN_V40 = _compat_module_3.HCNETSDK_LOGIN_V40
    HCNETSDK_LOGOUT_V30 = _compat_module_3.HCNETSDK_LOGOUT_V30
    HCNETSDK_MAKE_KEYFRAME_MAIN = _compat_module_3.HCNETSDK_MAKE_KEYFRAME_MAIN
    HCNETSDK_MAKE_KEYFRAME_SUB = _compat_module_3.HCNETSDK_MAKE_KEYFRAME_SUB
    HCNETSDK_MPEG_PS_PACK_HEADER = _compat_module_3.HCNETSDK_MPEG_PS_PACK_HEADER
    HCNETSDK_MPEG_START_CODE_PREFIX = _compat_module_3.HCNETSDK_MPEG_START_CODE_PREFIX
    HCNETSDK_MPEG_TS_SYNC_BYTE = _compat_module_3.HCNETSDK_MPEG_TS_SYNC_BYTE
    HCNETSDK_NETCFG_V30_ETHERNET_COUNT = _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_COUNT
    HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET
    )
    HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET
    )
    HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET
    )
    HCNETSDK_NETCFG_V30_ETHERNET_OFFSET = _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_OFFSET
    HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET
    )
    HCNETSDK_NETCFG_V30_ETHERNET_SIZE = _compat_module_3.HCNETSDK_NETCFG_V30_ETHERNET_SIZE
    HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET = _compat_module_3.HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET
    HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET = _compat_module_3.HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET
    HCNETSDK_NETCFG_V30_IP_SIZE = _compat_module_3.HCNETSDK_NETCFG_V30_IP_SIZE
    HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET
    )
    HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET
    )
    HCNETSDK_NETCFG_V30_MIN_SIZE = _compat_module_3.HCNETSDK_NETCFG_V30_MIN_SIZE
    HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET = (
        _compat_module_3.HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET
    )
    HCNETSDK_NETCFG_V30_NFS_IP_OFFSET = _compat_module_3.HCNETSDK_NETCFG_V30_NFS_IP_OFFSET
    HCNETSDK_NTP_CFG_SIZE = _compat_module_3.HCNETSDK_NTP_CFG_SIZE
    HCNETSDK_NTP_ENABLE_OFFSET = _compat_module_3.HCNETSDK_NTP_ENABLE_OFFSET
    HCNETSDK_NTP_INTERVAL_OFFSET = _compat_module_3.HCNETSDK_NTP_INTERVAL_OFFSET
    HCNETSDK_NTP_PORT_OFFSET = _compat_module_3.HCNETSDK_NTP_PORT_OFFSET
    HCNETSDK_NTP_SERVER_SIZE = _compat_module_3.HCNETSDK_NTP_SERVER_SIZE
    HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET = (
        _compat_module_3.HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET
    )
    HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET = (
        _compat_module_3.HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET
    )
    HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET
    HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE = _compat_module_3.HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE
    HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET
    HCNETSDK_PIC_CFG_MIN_SIZE = _compat_module_3.HCNETSDK_PIC_CFG_MIN_SIZE
    HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET
    HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET
    HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET
    HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET = (
        _compat_module_3.HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET
    )
    HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET
    HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET = _compat_module_3.HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET
    HCNETSDK_PLAY_CONVERT = _compat_module_3.HCNETSDK_PLAY_CONVERT
    HCNETSDK_PLAYAUDIOVOLUME = _compat_module_3.HCNETSDK_PLAYAUDIOVOLUME
    HCNETSDK_PLAYBACK_BY_TIME_V40 = _compat_module_3.HCNETSDK_PLAYBACK_BY_TIME_V40
    HCNETSDK_PLAYBACK_CAPTURE_FILE = _compat_module_3.HCNETSDK_PLAYBACK_CAPTURE_FILE
    HCNETSDK_PLAYBACK_CONTROL_V40 = _compat_module_3.HCNETSDK_PLAYBACK_CONTROL_V40
    HCNETSDK_PLAYBACK_FAILED = _compat_module_3.HCNETSDK_PLAYBACK_FAILED
    HCNETSDK_PLAYBACK_FILE_TYPE_ALL = _compat_module_3.HCNETSDK_PLAYBACK_FILE_TYPE_ALL
    HCNETSDK_PLAYBACK_LOCK_STATE_ALL = _compat_module_3.HCNETSDK_PLAYBACK_LOCK_STATE_ALL
    HCNETSDK_PLAYCOND_FIELD_ORDER = _compat_module_3.HCNETSDK_PLAYCOND_FIELD_ORDER
    HCNETSDK_PLAYFAST = _compat_module_3.HCNETSDK_PLAYFAST
    HCNETSDK_PLAYPAUSE = _compat_module_3.HCNETSDK_PLAYPAUSE
    HCNETSDK_PLAYRESTART = _compat_module_3.HCNETSDK_PLAYRESTART
    HCNETSDK_PLAYSLOW = _compat_module_3.HCNETSDK_PLAYSLOW
    HCNETSDK_PLAYSTART = _compat_module_3.HCNETSDK_PLAYSTART
    HCNETSDK_PLAYSTARTAUDIO = _compat_module_3.HCNETSDK_PLAYSTARTAUDIO
    HCNETSDK_PLAYSTOPAUDIO = _compat_module_3.HCNETSDK_PLAYSTOPAUDIO
    HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER = _compat_module_3.HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER
    HCNETSDK_PTZ_PRESET_OTHER = _compat_module_3.HCNETSDK_PTZ_PRESET_OTHER
    HCNETSDK_REALDATA_CALLBACK_V30 = _compat_module_3.HCNETSDK_REALDATA_CALLBACK_V30
    HCNETSDK_REALPLAY_V30 = _compat_module_3.HCNETSDK_REALPLAY_V30
    HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET = _compat_module_3.HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET
    HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE = _compat_module_3.HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE
    HCNETSDK_RECORD_CFG_V30_DAY_COUNT = _compat_module_3.HCNETSDK_RECORD_CFG_V30_DAY_COUNT
    HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET = (
        _compat_module_3.HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET
    )
    HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE = _compat_module_3.HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE
    HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY = (
        _compat_module_3.HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY
    )
    HCNETSDK_RECORD_CFG_V30_SIZE = _compat_module_3.HCNETSDK_RECORD_CFG_V30_SIZE
    HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET = _compat_module_3.HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET
    HCNETSDK_SECRET_KEY_TYPE_AES = _compat_module_3.HCNETSDK_SECRET_KEY_TYPE_AES
    HCNETSDK_SET_CONNECT_TIME = _compat_module_3.HCNETSDK_SET_CONNECT_TIME
    HCNETSDK_SET_DVR_CONFIG = _compat_module_3.HCNETSDK_SET_DVR_CONFIG
    HCNETSDK_SET_PLAY_DATA_CALLBACK = _compat_module_3.HCNETSDK_SET_PLAY_DATA_CALLBACK
    HCNETSDK_SET_PLAY_DATA_CALLBACK_V40 = _compat_module_3.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40
    HCNETSDK_SET_PLAYBACK_ES_CALLBACK = _compat_module_3.HCNETSDK_SET_PLAYBACK_ES_CALLBACK
    HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK = (
        _compat_module_3.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK
    )
    HCNETSDK_SET_PLAYBACK_SECRET_KEY = _compat_module_3.HCNETSDK_SET_PLAYBACK_SECRET_KEY
    HCNETSDK_SET_SDK_LOCAL_CFG = _compat_module_3.HCNETSDK_SET_SDK_LOCAL_CFG
    HCNETSDK_SET_TRANS_TYPE = _compat_module_3.HCNETSDK_SET_TRANS_TYPE
    HCNETSDK_SETUP_ALARM_CHAN_V30 = _compat_module_3.HCNETSDK_SETUP_ALARM_CHAN_V30
    HCNETSDK_SETUP_ALARM_CHAN_V41 = _compat_module_3.HCNETSDK_SETUP_ALARM_CHAN_V41
    HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER = _compat_module_3.HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER
    HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX = _compat_module_3.HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX
    HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE
    )
    HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID = (
        _compat_module_3.HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID
    )
    HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE = (
        _compat_module_3.HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE
    )
    HCNETSDK_STDXML_COMMAND_PORT_FLAGS = _compat_module_3.HCNETSDK_STDXML_COMMAND_PORT_FLAGS
    HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE = (
        _compat_module_3.HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE
    )
    HCNETSDK_STDXML_CONFIG = _compat_module_3.HCNETSDK_STDXML_CONFIG
    HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
    )
    HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE = (
        _compat_module_3.HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE
    )
    HCNETSDK_STDXML_INPUT_FIELD_ORDER = _compat_module_3.HCNETSDK_STDXML_INPUT_FIELD_ORDER
    HCNETSDK_STDXML_OUTPUT_FIELD_ORDER = _compat_module_3.HCNETSDK_STDXML_OUTPUT_FIELD_ORDER
    HCNETSDK_STOP_GET_FILE = _compat_module_3.HCNETSDK_STOP_GET_FILE
    HCNETSDK_STOP_PLAYBACK = _compat_module_3.HCNETSDK_STOP_PLAYBACK
    HCNETSDK_TCP_COMMAND_PORTS = _compat_module_3.HCNETSDK_TCP_COMMAND_PORTS
    HCNETSDK_TCP_HEADER_LENGTH = _compat_module_3.HCNETSDK_TCP_HEADER_LENGTH
    HCNETSDK_TIME_CFG_SIZE = _compat_module_3.HCNETSDK_TIME_CFG_SIZE
    HCNETSDK_TIME_FIELD_ORDER = _compat_module_3.HCNETSDK_TIME_FIELD_ORDER
    HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE = (
        _compat_module_3.HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE
    )
    HCNETSDK_USER_CFG_V30_ENTRY_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_ENTRY_SIZE
    HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE
    HCNETSDK_USER_CFG_V30_MAC_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_MAC_SIZE
    HCNETSDK_USER_CFG_V30_MAX_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_MAX_SIZE
    HCNETSDK_USER_CFG_V30_MIN_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_MIN_SIZE
    HCNETSDK_USER_CFG_V30_PASSWORD_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_PASSWORD_SIZE
    HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE = (
        _compat_module_3.HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE
    )
    HCNETSDK_USER_CFG_V30_RESERVED_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_RESERVED_SIZE
    HCNETSDK_USER_CFG_V30_USER_COUNT = _compat_module_3.HCNETSDK_USER_CFG_V30_USER_COUNT
    HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE
    HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE
    HCNETSDK_USER_CFG_V30_USERNAME_SIZE = _compat_module_3.HCNETSDK_USER_CFG_V30_USERNAME_SIZE
    HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE = _compat_module_3.HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE
    HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE = _compat_module_3.HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE
    HCNETSDK_WIFI_AP_INFO_SSID_SIZE = _compat_module_3.HCNETSDK_WIFI_AP_INFO_SSID_SIZE
    HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE = _compat_module_3.HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE
    HCNETSDK_XML_MARKER = _compat_module_3.HCNETSDK_XML_MARKER
    SADP_ACTIVATE_DEVICE = _compat_module_3.SADP_ACTIVATE_DEVICE
    SADP_CLEARUP = _compat_module_3.SADP_CLEARUP
    SADP_DEV_NET_PARAM_ANDROID_FIELDS = _compat_module_3.SADP_DEV_NET_PARAM_ANDROID_FIELDS
    SADP_DEV_NET_PARAM_JNA_FIELD_ORDER = _compat_module_3.SADP_DEV_NET_PARAM_JNA_FIELD_ORDER
    SADP_DEV_RET_NET_PARAM_BUFFER_SIZE = _compat_module_3.SADP_DEV_RET_NET_PARAM_BUFFER_SIZE
    SADP_DEV_RET_NET_PARAM_FIELD_ORDER = _compat_module_3.SADP_DEV_RET_NET_PARAM_FIELD_ORDER
    SADP_GET_LAST_ERROR = _compat_module_3.SADP_GET_LAST_ERROR
    SADP_GET_VERSION = _compat_module_3.SADP_GET_VERSION
    SADP_MODIFY_DEVICE_NET_PARAM = _compat_module_3.SADP_MODIFY_DEVICE_NET_PARAM
    SADP_MODIFY_DEVICE_NET_PARAM_V40 = _compat_module_3.SADP_MODIFY_DEVICE_NET_PARAM_V40
    SADP_NUL_BYTE = _compat_module_3.SADP_NUL_BYTE
    SADP_SEND_INQUIRY = _compat_module_3.SADP_SEND_INQUIRY
    SADP_SET_LOG_TO_FILE = _compat_module_3.SADP_SET_LOG_TO_FILE
    SADP_START_V30 = _compat_module_3.SADP_START_V30
    SADP_START_V40 = _compat_module_3.SADP_START_V40
    SADP_STOP = _compat_module_3.SADP_STOP
    Any = _compat_module_3.Any
    BoundedResolver = _compat_module_3.BoundedResolver
    Callable = _compat_module_3.Callable
    DeviceException = _compat_module_3.DeviceException
    Empty = _compat_module_3.Empty
    EzvizCasDeviceInfo = _compat_module_3.EzvizCasDeviceInfo
    EzvizInterleavedRtpFrame = _compat_module_3.EzvizInterleavedRtpFrame
    EzvizInterleavedRtpFrameHeader = _compat_module_3.EzvizInterleavedRtpFrameHeader
    EzvizInterleavedRtpFrameWithPrefix = _compat_module_3.EzvizInterleavedRtpFrameWithPrefix
    EzvizLanAccessProtocolAbility = _compat_module_3.EzvizLanAccessProtocolAbility
    EzvizLanAudioInputParam = _compat_module_3.EzvizLanAudioInputParam
    EzvizLanAudioOutputVolume = _compat_module_3.EzvizLanAudioOutputVolume
    EzvizLanAudioVideoCompressAudioChannel = _compat_module_3.EzvizLanAudioVideoCompressAudioChannel
    EzvizLanAudioVideoCompressInfo = _compat_module_3.EzvizLanAudioVideoCompressInfo
    EzvizLanAudioVideoCompressStream = _compat_module_3.EzvizLanAudioVideoCompressStream
    EzvizLanAudioVideoCompressVideoChannel = _compat_module_3.EzvizLanAudioVideoCompressVideoChannel
    EzvizLanAudioVideoCompressVoiceTalkChannel = (
        _compat_module_3.EzvizLanAudioVideoCompressVoiceTalkChannel
    )
    EzvizLanCameraParamConfig = _compat_module_3.EzvizLanCameraParamConfig
    EzvizLanCompressionConfig = _compat_module_3.EzvizLanCompressionConfig
    EzvizLanCompressionInfoV30 = _compat_module_3.EzvizLanCompressionInfoV30
    EzvizLanDeviceConfigV40 = _compat_module_3.EzvizLanDeviceConfigV40
    EzvizLanDeviceSoftHardwareAbility = _compat_module_3.EzvizLanDeviceSoftHardwareAbility
    EzvizLanDvrConfigSummary = _compat_module_3.EzvizLanDvrConfigSummary
    EzvizLanEzvizAccessConfig = _compat_module_3.EzvizLanEzvizAccessConfig
    EzvizLanHdConfig = _compat_module_3.EzvizLanHdConfig
    EzvizLanHdDiskConfig = _compat_module_3.EzvizLanHdDiskConfig
    EzvizLanIpcFrontParameterAbility = _compat_module_3.EzvizLanIpcFrontParameterAbility
    EzvizLanIpcFrontParameterRange = _compat_module_3.EzvizLanIpcFrontParameterRange
    EzvizLanKeyframeRequest = _compat_module_3.EzvizLanKeyframeRequest
    EzvizLanLiveViewParams = _compat_module_3.EzvizLanLiveViewParams
    EzvizLanNetConfigV30 = _compat_module_3.EzvizLanNetConfigV30
    EzvizLanNetInterfaceConfig = _compat_module_3.EzvizLanNetInterfaceConfig
    EzvizLanNtpConfig = _compat_module_3.EzvizLanNtpConfig
    EzvizLanPictureConfig = _compat_module_3.EzvizLanPictureConfig
    EzvizLanPlaybackConvertAbility = _compat_module_3.EzvizLanPlaybackConvertAbility
    EzvizLanPlaybackConvertResolution = _compat_module_3.EzvizLanPlaybackConvertResolution
    EzvizLanPlaybackIntent = _compat_module_3.EzvizLanPlaybackIntent
    EzvizLanPlaybackPath = _compat_module_3.EzvizLanPlaybackPath
    EzvizLanPlayDeviceLogin = _compat_module_3.EzvizLanPlayDeviceLogin
    EzvizLanPreviewPlan = _compat_module_3.EzvizLanPreviewPlan
    EzvizLanPtzAbility = _compat_module_3.EzvizLanPtzAbility
    EzvizLanRecordConfigV30 = _compat_module_3.EzvizLanRecordConfigV30
    EzvizLanRecordDayConfig = _compat_module_3.EzvizLanRecordDayConfig
    EzvizLanRecordScheduleSegment = _compat_module_3.EzvizLanRecordScheduleSegment
    EzvizLanSdFormatProgress = _compat_module_3.EzvizLanSdFormatProgress
    EzvizLanServicesSwitchState = _compat_module_3.EzvizLanServicesSwitchState
    EzvizLanUserConfigV30 = _compat_module_3.EzvizLanUserConfigV30
    EzvizLanUserConfigV30Entry = _compat_module_3.EzvizLanUserConfigV30Entry
    EzvizLanVideoPicAbility = _compat_module_3.EzvizLanVideoPicAbility
    EzvizLanVideoQuality = _compat_module_3.EzvizLanVideoQuality
    EzvizLanVideoResolution = _compat_module_3.EzvizLanVideoResolution
    EzvizLanWifiApInfo = _compat_module_3.EzvizLanWifiApInfo
    EzvizLanWifiConnectStatus = _compat_module_3.EzvizLanWifiConnectStatus
    EzvizLocalAuthenticationAttrs = _compat_module_3.EzvizLocalAuthenticationAttrs
    EzvizLocalDevice = _compat_module_3.EzvizLocalDevice
    EzvizLocalDeviceContent = _compat_module_3.EzvizLocalDeviceContent
    EzvizLocalPreviewRequest = _compat_module_3.EzvizLocalPreviewRequest
    EzvizLocalReceiverInfo = _compat_module_3.EzvizLocalReceiverInfo
    EzvizLocalReceiverInfoAttrs = _compat_module_3.EzvizLocalReceiverInfoAttrs
    EzvizLocalReceiverInfoEx = _compat_module_3.EzvizLocalReceiverInfoEx
    EzvizLocalReceiverInfoExAttrs = _compat_module_3.EzvizLocalReceiverInfoExAttrs
    EzvizLocalSdkBodyShape = _compat_module_3.EzvizLocalSdkBodyShape
    EzvizLocalSdkClient = _compat_module_3.EzvizLocalSdkClient
    EzvizLocalSdkDeadlineExpired = _compat_module_3.EzvizLocalSdkDeadlineExpired
    EzvizLocalSdkExchange = _compat_module_3.EzvizLocalSdkExchange
    EzvizLocalSdkFrame = _compat_module_3.EzvizLocalSdkFrame
    EzvizLocalSdkFrameHeader = _compat_module_3.EzvizLocalSdkFrameHeader
    EzvizLocalSdkStreamBootstrap = _compat_module_3.EzvizLocalSdkStreamBootstrap
    EzvizLocalSdkStreamClosed = _compat_module_3.EzvizLocalSdkStreamClosed
    EzvizPtzCommand = _compat_module_3.EzvizPtzCommand
    EzvizStreamHeader = _compat_module_3.EzvizStreamHeader
    Full = _compat_module_3.Full
    HcNetSdkAbility = _compat_module_3.HcNetSdkAbility
    HcNetSdkClientInfo = _compat_module_3.HcNetSdkClientInfo
    HcNetSdkCloseAlarmRequest = _compat_module_3.HcNetSdkCloseAlarmRequest
    HcNetSdkCloseFormatHandleRequest = _compat_module_3.HcNetSdkCloseFormatHandleRequest
    HcNetSdkCommandPortClient = _compat_module_3.HcNetSdkCommandPortClient
    HcNetSdkCommandPortControlResponse = _compat_module_3.HcNetSdkCommandPortControlResponse
    HcNetSdkCommandPortControlTemplate = _compat_module_3.HcNetSdkCommandPortControlTemplate
    HcNetSdkCommandPortExchange = _compat_module_3.HcNetSdkCommandPortExchange
    HcNetSdkCommandPortLoginChallenge = _compat_module_3.HcNetSdkCommandPortLoginChallenge
    HcNetSdkCommandPortLoginSession = _compat_module_3.HcNetSdkCommandPortLoginSession
    HcNetSdkCommandPortStreamBootstrap = _compat_module_3.HcNetSdkCommandPortStreamBootstrap
    HcNetSdkCommandTraceSummary = _compat_module_3.HcNetSdkCommandTraceSummary
    HcNetSdkConfiguredMedia = _compat_module_3.HcNetSdkConfiguredMedia
    HcNetSdkDeviceAbilityRequest = _compat_module_3.HcNetSdkDeviceAbilityRequest
    HcNetSdkDvrCommand = _compat_module_3.HcNetSdkDvrCommand
    HcNetSdkDvrConfigRequest = _compat_module_3.HcNetSdkDvrConfigRequest
    HcNetSdkFileCond = _compat_module_3.HcNetSdkFileCond
    HcNetSdkFindCloseRequest = _compat_module_3.HcNetSdkFindCloseRequest
    HcNetSdkFindDataV30 = _compat_module_3.HcNetSdkFindDataV30
    HcNetSdkFindFileRequest = _compat_module_3.HcNetSdkFindFileRequest
    HcNetSdkFindNextFileRequest = _compat_module_3.HcNetSdkFindNextFileRequest
    HcNetSdkFormatDiskRequest = _compat_module_3.HcNetSdkFormatDiskRequest
    HcNetSdkFormatProgressRequest = _compat_module_3.HcNetSdkFormatProgressRequest
    HcNetSdkGetDownloadPosRequest = _compat_module_3.HcNetSdkGetDownloadPosRequest
    HcNetSdkGetErrorMsgRequest = _compat_module_3.HcNetSdkGetErrorMsgRequest
    HcNetSdkGetFileByNameRequest = _compat_module_3.HcNetSdkGetFileByNameRequest
    HcNetSdkGetFileByTimeRequest = _compat_module_3.HcNetSdkGetFileByTimeRequest
    HcNetSdkInitRequest = _compat_module_3.HcNetSdkInitRequest
    HcNetSdkLanEndpoint = _compat_module_3.HcNetSdkLanEndpoint
    HcNetSdkLocalCfgType = _compat_module_3.HcNetSdkLocalCfgType
    HcNetSdkLoginCandidate = _compat_module_3.HcNetSdkLoginCandidate
    HcNetSdkLogoutRequest = _compat_module_3.HcNetSdkLogoutRequest
    HcNetSdkNoArgRequest = _compat_module_3.HcNetSdkNoArgRequest
    HcNetSdkPlayBackByTimeRequest = _compat_module_3.HcNetSdkPlayBackByTimeRequest
    HcNetSdkPlaybackCallbackRequest = _compat_module_3.HcNetSdkPlaybackCallbackRequest
    HcNetSdkPlayBackCaptureFileRequest = _compat_module_3.HcNetSdkPlayBackCaptureFileRequest
    HcNetSdkPlaybackControlCommand = _compat_module_3.HcNetSdkPlaybackControlCommand
    HcNetSdkPlayBackControlRequest = _compat_module_3.HcNetSdkPlayBackControlRequest
    HcNetSdkPlayBackSecretKeyRequest = _compat_module_3.HcNetSdkPlayBackSecretKeyRequest
    HcNetSdkPlayCond = _compat_module_3.HcNetSdkPlayCond
    HcNetSdkPlayDataCallbackRequest = _compat_module_3.HcNetSdkPlayDataCallbackRequest
    HcNetSdkPortProbe = _compat_module_3.HcNetSdkPortProbe
    HcNetSdkPtzCommand = _compat_module_3.HcNetSdkPtzCommand
    HcNetSdkPtzControlRequest = _compat_module_3.HcNetSdkPtzControlRequest
    HcNetSdkPtzPresetCommand = _compat_module_3.HcNetSdkPtzPresetCommand
    HcNetSdkPtzPresetRequest = _compat_module_3.HcNetSdkPtzPresetRequest
    HcNetSdkPurePythonClient = _compat_module_3.HcNetSdkPurePythonClient
    HcNetSdkRealDataPacket = _compat_module_3.HcNetSdkRealDataPacket
    HcNetSdkRealDataType = _compat_module_3.HcNetSdkRealDataType
    HcNetSdkRealPlayRequest = _compat_module_3.HcNetSdkRealPlayRequest
    HcNetSdkSemanticLogEvent = _compat_module_3.HcNetSdkSemanticLogEvent
    HcNetSdkSetConnectTimeRequest = _compat_module_3.HcNetSdkSetConnectTimeRequest
    HcNetSdkSetSdkLocalCfgRequest = _compat_module_3.HcNetSdkSetSdkLocalCfgRequest
    HcNetSdkSetupAlarmParam = _compat_module_3.HcNetSdkSetupAlarmParam
    HcNetSdkSetupAlarmRequest = _compat_module_3.HcNetSdkSetupAlarmRequest
    HcNetSdkStdXmlConfigRequest = _compat_module_3.HcNetSdkStdXmlConfigRequest
    HcNetSdkStdXmlConfigResponse = _compat_module_3.HcNetSdkStdXmlConfigResponse
    HcNetSdkStopGetFileRequest = _compat_module_3.HcNetSdkStopGetFileRequest
    HcNetSdkStopPlayBackRequest = _compat_module_3.HcNetSdkStopPlayBackRequest
    HcNetSdkStreamDetails = _compat_module_3.HcNetSdkStreamDetails
    HcNetSdkTcpFrame = _compat_module_3.HcNetSdkTcpFrame
    HcNetSdkTcpFrameHeader = _compat_module_3.HcNetSdkTcpFrameHeader
    HcNetSdkTcpFrameShape = _compat_module_3.HcNetSdkTcpFrameShape
    HcNetSdkTcpPayloadShape = _compat_module_3.HcNetSdkTcpPayloadShape
    HcNetSdkTcpShapeLogRecord = _compat_module_3.HcNetSdkTcpShapeLogRecord
    HcNetSdkTime = _compat_module_3.HcNetSdkTime
    IntEnum = _compat_module_3.IntEnum
    Iterable = _compat_module_3.Iterable
    IterableMediaPacketSource = _compat_module_3.IterableMediaPacketSource
    Iterator = _compat_module_3.Iterator
    LocalSdkIvFactory = _compat_module_3.LocalSdkIvFactory
    Lock = _compat_module_3.Lock
    Mapping = _compat_module_3.Mapping
    MediaPacket = _compat_module_3.MediaPacket
    MediaPacketMetadata = _compat_module_3.MediaPacketMetadata
    PyEzvizError = _compat_module_3.PyEzvizError
    Queue = _compat_module_3.Queue
    ResolverBusy = _compat_module_3.ResolverBusy
    SadpActivateDeviceRequest = _compat_module_3.SadpActivateDeviceRequest
    SadpBatchResult = _compat_module_3.SadpBatchResult
    SadpDeviceInfo = _compat_module_3.SadpDeviceInfo
    SadpDeviceNetParam = _compat_module_3.SadpDeviceNetParam
    SadpDeviceRetNetParam = _compat_module_3.SadpDeviceRetNetParam
    SadpModifyDeviceNetParamRequest = _compat_module_3.SadpModifyDeviceNetParamRequest
    SadpModifyDeviceNetParamV40Request = _compat_module_3.SadpModifyDeviceNetParamV40Request
    SadpNoArgRequest = _compat_module_3.SadpNoArgRequest
    SadpSetLogToFileRequest = _compat_module_3.SadpSetLogToFileRequest
    SadpStartRequest = _compat_module_3.SadpStartRequest
    SocketBindAddress = _compat_module_3.SocketBindAddress
    SocketFactory = _compat_module_3.SocketFactory
    SocketSourceAddress = _compat_module_3.SocketSourceAddress
    SourceAddressSocketFactory = _compat_module_3.SourceAddressSocketFactory
    Thread = _compat_module_3.Thread
    _ability_option_tuple = _compat_module_3._ability_option_tuple
    _audio_video_compress_audio_channels = _compat_module_3._audio_video_compress_audio_channels
    _audio_video_compress_stream = _compat_module_3._audio_video_compress_stream
    _audio_video_compress_video_channels = _compat_module_3._audio_video_compress_video_channels
    _audio_video_compress_voice_talk_channels = (
        _compat_module_3._audio_video_compress_voice_talk_channels
    )
    _bounded_bytes = _compat_module_3._bounded_bytes
    _build_local_sdk_request_xml = _compat_module_3._build_local_sdk_request_xml
    _byte_tuple = _compat_module_3._byte_tuple
    _byte_value = _compat_module_3._byte_value
    _connect_attempt_settings = _compat_module_3._connect_attempt_settings
    _connect_bound_source_socket = _compat_module_3._connect_bound_source_socket
    _connect_with_optional_source_address = _compat_module_3._connect_with_optional_source_address
    _create_deadline_connection = _compat_module_3._create_deadline_connection
    _create_reusable_source_connection = _compat_module_3._create_reusable_source_connection
    _DeadlineBoundRecvSocket = _compat_module_3._DeadlineBoundRecvSocket
    _device_ability_bytes = _compat_module_3._device_ability_bytes
    _device_ability_response_text = _compat_module_3._device_ability_response_text
    _device_ability_xml_name = _compat_module_3._device_ability_xml_name
    _dword_value = _compat_module_3._dword_value
    _entropy_bits_per_byte = _compat_module_3._entropy_bits_per_byte
    _event_field_bool = _compat_module_3._event_field_bool
    _event_field_int = _compat_module_3._event_field_int
    _ezviz_lan_hd_disk_config = _compat_module_3._ezviz_lan_hd_disk_config
    _ezviz_lan_user_config_v30_entry = _compat_module_3._ezviz_lan_user_config_v30_entry
    _fixed_ipv4_text = _compat_module_3._fixed_ipv4_text
    _fixed_secret_bytes = _compat_module_3._fixed_secret_bytes
    _fixed_secret_text = _compat_module_3._fixed_secret_text
    _getaddrinfo_before_deadline = _compat_module_3._getaddrinfo_before_deadline
    _hcnetsdk_aes128_round_keys = _compat_module_3._hcnetsdk_aes128_round_keys
    _hcnetsdk_aes_add_round_key = _compat_module_3._hcnetsdk_aes_add_round_key
    _hcnetsdk_aes_mix_columns = _compat_module_3._hcnetsdk_aes_mix_columns
    _hcnetsdk_aes_shift_rows = _compat_module_3._hcnetsdk_aes_shift_rows
    _hcnetsdk_aes_sub_bytes = _compat_module_3._hcnetsdk_aes_sub_bytes
    _hcnetsdk_aes_xtime = _compat_module_3._hcnetsdk_aes_xtime
    _hcnetsdk_command_port_auth_mask = _compat_module_3._hcnetsdk_command_port_auth_mask
    _hcnetsdk_command_port_four_round_aes = _compat_module_3._hcnetsdk_command_port_four_round_aes
    _hcnetsdk_command_port_local_ip_word = _compat_module_3._hcnetsdk_command_port_local_ip_word
    _hcnetsdk_command_port_login_prefix = _compat_module_3._hcnetsdk_command_port_login_prefix
    _hcnetsdk_command_port_md5_digest = _compat_module_3._hcnetsdk_command_port_md5_digest
    _hcnetsdk_command_port_md5_hmac = _compat_module_3._hcnetsdk_command_port_md5_hmac
    _hcnetsdk_command_port_username = _compat_module_3._hcnetsdk_command_port_username
    _hcnetsdk_compression_info_v30 = _compat_module_3._hcnetsdk_compression_info_v30
    _hcnetsdk_config_declared_size = _compat_module_3._hcnetsdk_config_declared_size
    _hcnetsdk_declared_length = _compat_module_3._hcnetsdk_declared_length
    _hcnetsdk_known_prefix_kind = _compat_module_3._hcnetsdk_known_prefix_kind
    _hcnetsdk_protocol = _compat_module_3._hcnetsdk_protocol
    _hcnetsdk_shape_command_candidate = _compat_module_3._hcnetsdk_shape_command_candidate
    _hcnetsdk_stream_details_query = _compat_module_3._hcnetsdk_stream_details_query
    _hcnetsdk_tcp_payload_kind = _compat_module_3._hcnetsdk_tcp_payload_kind
    _hcnetsdk_time_value = _compat_module_3._hcnetsdk_time_value
    _ipc_front_parameter_field_root = _compat_module_3._ipc_front_parameter_field_root
    _local_sdk_aes_bytes = _compat_module_3._local_sdk_aes_bytes
    _looks_tls_record = _compat_module_3._looks_tls_record
    _mac_address_bytes = _compat_module_3._mac_address_bytes
    _mac_address_text = _compat_module_3._mac_address_text
    _mapping_int = _compat_module_3._mapping_int
    _mapping_str = _compat_module_3._mapping_str
    _native_path_value = _compat_module_3._native_path_value
    _native_secret_key_bytes = _compat_module_3._native_secret_key_bytes
    _native_string_bytes = _compat_module_3._native_string_bytes
    _nul_stripped_text = _compat_module_3._nul_stripped_text
    _optional_native_bytes = _compat_module_3._optional_native_bytes
    _optional_raw_byte = _compat_module_3._optional_raw_byte
    _optional_raw_byte_triplet = _compat_module_3._optional_raw_byte_triplet
    _optional_raw_u16_be = _compat_module_3._optional_raw_u16_be
    _optional_raw_u16_be_pair = _compat_module_3._optional_raw_u16_be_pair
    _optional_raw_u32_be = _compat_module_3._optional_raw_u32_be
    _parse_float = _compat_module_3._parse_float
    _parse_int = _compat_module_3._parse_int
    _parse_length_candidate_offset = _compat_module_3._parse_length_candidate_offset
    _parse_length_candidates = _compat_module_3._parse_length_candidates
    _parse_local_device_content = _compat_module_3._parse_local_device_content
    _parse_shape_fields = _compat_module_3._parse_shape_fields
    _pkcs5_pad = _compat_module_3._pkcs5_pad
    _pkcs5_unpad = _compat_module_3._pkcs5_unpad
    _port_value = _compat_module_3._port_value
    _probe_port = _compat_module_3._probe_port
    _ptz_int = _compat_module_3._ptz_int
    _recv_exact = _compat_module_3._recv_exact
    _remaining_timeout = _compat_module_3._remaining_timeout
    _resolver = _compat_module_3._resolver
    _sadp_string_bytes = _compat_module_3._sadp_string_bytes
    _send_all = _compat_module_3._send_all
    _send_all_before_deadline = _compat_module_3._send_all_before_deadline
    _send_all_with_timeout = _compat_module_3._send_all_with_timeout
    _services_switch_value = _compat_module_3._services_switch_value
    _SourcePortConflictError = _compat_module_3._SourcePortConflictError
    _stdxml_bytes = _compat_module_3._stdxml_bytes
    _wait_for_socket_io = _compat_module_3._wait_for_socket_io
    _windows_concrete_source_address = _compat_module_3._windows_concrete_source_address
    _word_value = _compat_module_3._word_value
    _xml_attr = _compat_module_3._xml_attr
    _xml_attr_int = _compat_module_3._xml_attr_int
    _xml_attrs = _compat_module_3._xml_attrs
    _xml_bool_opt_attr = _compat_module_3._xml_bool_opt_attr
    _xml_child_int = _compat_module_3._xml_child_int
    _xml_child_int_csv_with_prefix = _compat_module_3._xml_child_int_csv_with_prefix
    _xml_child_int_range = _compat_module_3._xml_child_int_range
    _xml_child_optional_int = _compat_module_3._xml_child_optional_int
    _xml_child_text = _compat_module_3._xml_child_text
    _xml_children = _compat_module_3._xml_children
    _xml_descendant_bool_text = _compat_module_3._xml_descendant_bool_text
    _xml_descendant_int = _compat_module_3._xml_descendant_int
    _xml_descendant_text = _compat_module_3._xml_descendant_text
    _xml_escape = _compat_module_3._xml_escape
    _xml_first_child = _compat_module_3._xml_first_child
    _xml_has_descendant = _compat_module_3._xml_has_descendant
    _xml_has_parent = _compat_module_3._xml_has_parent
    _xml_int_csv = _compat_module_3._xml_int_csv
    _xml_local_name = _compat_module_3._xml_local_name
    _xml_offset = _compat_module_3._xml_offset
    _xml_opt_attr = _compat_module_3._xml_opt_attr
    _xml_tag_names = _compat_module_3._xml_tag_names
    annotations = _compat_module_3.annotations
    asdict = _compat_module_3.asdict
    base64 = _compat_module_3.base64
    binascii = _compat_module_3.binascii
    build_encrypted_ezviz_local_sdk_frame = _compat_module_3.build_encrypted_ezviz_local_sdk_frame
    build_ezviz_cas_encrypted_local_sdk_frame = (
        _compat_module_3.build_ezviz_cas_encrypted_local_sdk_frame
    )
    build_ezviz_cas_ssl_local_sdk_frame = _compat_module_3.build_ezviz_cas_ssl_local_sdk_frame
    build_ezviz_interleaved_rtp_frame_header = (
        _compat_module_3.build_ezviz_interleaved_rtp_frame_header
    )
    build_ezviz_local_preview_request_body = _compat_module_3.build_ezviz_local_preview_request_body
    build_ezviz_local_sdk_frame = _compat_module_3.build_ezviz_local_sdk_frame
    build_ezviz_local_sdk_frame_header = _compat_module_3.build_ezviz_local_sdk_frame_header
    build_ezviz_local_sdk_ssl_frame = _compat_module_3.build_ezviz_local_sdk_ssl_frame
    build_ezviz_local_stop_preview_request_body = (
        _compat_module_3.build_ezviz_local_stop_preview_request_body
    )
    build_ezviz_local_stream_setup_request_body = (
        _compat_module_3.build_ezviz_local_stream_setup_request_body
    )
    build_hcnetsdk_tcp_frame = _compat_module_3.build_hcnetsdk_tcp_frame
    cast = _compat_module_3.cast
    classify_ezviz_local_sdk_body = _compat_module_3.classify_ezviz_local_sdk_body
    classify_hcnetsdk_real_data_payload = _compat_module_3.classify_hcnetsdk_real_data_payload
    classify_hcnetsdk_tcp_payload = _compat_module_3.classify_hcnetsdk_tcp_payload
    classify_lan_ports = _compat_module_3.classify_lan_ports
    closing = _compat_module_3.closing
    dataclass = _compat_module_3.dataclass
    date = _compat_module_3.date
    datetime = _compat_module_3.datetime
    decode_hcnetsdk_command_port_login_challenge = (
        _compat_module_3.decode_hcnetsdk_command_port_login_challenge
    )
    decrypt_ezviz_local_sdk_body_aes_cbc = _compat_module_3.decrypt_ezviz_local_sdk_body_aes_cbc
    discover_hcnetsdk_stream_details = _compat_module_3.discover_hcnetsdk_stream_details
    discover_hcnetsdk_stream_details_for_login = (
        _compat_module_3.discover_hcnetsdk_stream_details_for_login
    )
    encrypt_ezviz_local_sdk_body_aes_cbc = _compat_module_3.encrypt_ezviz_local_sdk_body_aes_cbc
    errno = _compat_module_3.errno
    ezviz_cas_ptz_command = _compat_module_3.ezviz_cas_ptz_command
    ezviz_hcnetsdk_local_ability_parse_request = (
        _compat_module_3.ezviz_hcnetsdk_local_ability_parse_request
    )
    ezviz_hcnetsdk_local_ptz_without_recv_request = (
        _compat_module_3.ezviz_hcnetsdk_local_ptz_without_recv_request
    )
    ezviz_lan_access_protocol_ability = _compat_module_3.ezviz_lan_access_protocol_ability
    ezviz_lan_access_protocol_ability_input = (
        _compat_module_3.ezviz_lan_access_protocol_ability_input
    )
    ezviz_lan_access_protocol_ability_request = (
        _compat_module_3.ezviz_lan_access_protocol_ability_request
    )
    ezviz_lan_audio_input_get_config_request = (
        _compat_module_3.ezviz_lan_audio_input_get_config_request
    )
    ezviz_lan_audio_input_param = _compat_module_3.ezviz_lan_audio_input_param
    ezviz_lan_audio_output_volume = _compat_module_3.ezviz_lan_audio_output_volume
    ezviz_lan_audio_video_compress_info = _compat_module_3.ezviz_lan_audio_video_compress_info
    ezviz_lan_audio_video_compress_info_ability_request = (
        _compat_module_3.ezviz_lan_audio_video_compress_info_ability_request
    )
    ezviz_lan_audio_video_compress_info_input = (
        _compat_module_3.ezviz_lan_audio_video_compress_info_input
    )
    ezviz_lan_audio_volume_update_requests = _compat_module_3.ezviz_lan_audio_volume_update_requests
    ezviz_lan_audioout_volume_get_config_request = (
        _compat_module_3.ezviz_lan_audioout_volume_get_config_request
    )
    ezviz_lan_backlight_wdr_get_config_request = (
        _compat_module_3.ezviz_lan_backlight_wdr_get_config_request
    )
    ezviz_lan_backlight_wdr_update_request = _compat_module_3.ezviz_lan_backlight_wdr_update_request
    ezviz_lan_camera_param_config = _compat_module_3.ezviz_lan_camera_param_config
    ezviz_lan_complete_playback_path = _compat_module_3.ezviz_lan_complete_playback_path
    ezviz_lan_compression_config = _compat_module_3.ezviz_lan_compression_config
    ezviz_lan_connect_mode_payload = _compat_module_3.ezviz_lan_connect_mode_payload
    ezviz_lan_connect_mode_put_config = _compat_module_3.ezviz_lan_connect_mode_put_config
    ezviz_lan_connect_mode_put_request = _compat_module_3.ezviz_lan_connect_mode_put_request
    ezviz_lan_day_night_get_config_request = _compat_module_3.ezviz_lan_day_night_get_config_request
    ezviz_lan_day_night_update_request = _compat_module_3.ezviz_lan_day_night_update_request
    ezviz_lan_device_config_v40 = _compat_module_3.ezviz_lan_device_config_v40
    ezviz_lan_device_config_v40_request = _compat_module_3.ezviz_lan_device_config_v40_request
    ezviz_lan_dvr_config_summary = _compat_module_3.ezviz_lan_dvr_config_summary
    ezviz_lan_ezviz_access_config = _compat_module_3.ezviz_lan_ezviz_access_config
    ezviz_lan_ezviz_access_config_summary = _compat_module_3.ezviz_lan_ezviz_access_config_summary
    ezviz_lan_ezviz_access_get_config_request = (
        _compat_module_3.ezviz_lan_ezviz_access_get_config_request
    )
    ezviz_lan_ezviz_access_replacement_domain = (
        _compat_module_3.ezviz_lan_ezviz_access_replacement_domain
    )
    ezviz_lan_ezviz_access_replacement_domain_request = (
        _compat_module_3.ezviz_lan_ezviz_access_replacement_domain_request
    )
    ezviz_lan_ezviz_access_set_domain_request = (
        _compat_module_3.ezviz_lan_ezviz_access_set_domain_request
    )
    ezviz_lan_hd_config = _compat_module_3.ezviz_lan_hd_config
    ezviz_lan_hd_config_request = _compat_module_3.ezviz_lan_hd_config_request
    ezviz_lan_image_display_param_ability_input = (
        _compat_module_3.ezviz_lan_image_display_param_ability_input
    )
    ezviz_lan_image_display_param_ability_request = (
        _compat_module_3.ezviz_lan_image_display_param_ability_request
    )
    ezviz_lan_ipc_front_parameter_ability = _compat_module_3.ezviz_lan_ipc_front_parameter_ability
    ezviz_lan_ipc_front_parameter_ability_request = (
        _compat_module_3.ezviz_lan_ipc_front_parameter_ability_request
    )
    ezviz_lan_live_view_params = _compat_module_3.ezviz_lan_live_view_params
    ezviz_lan_local_user_password = _compat_module_3.ezviz_lan_local_user_password
    ezviz_lan_login_candidates = _compat_module_3.ezviz_lan_login_candidates
    ezviz_lan_net_config_and_voice_upload_payload = (
        _compat_module_3.ezviz_lan_net_config_and_voice_upload_payload
    )
    ezviz_lan_net_config_and_voice_upload_put_config = (
        _compat_module_3.ezviz_lan_net_config_and_voice_upload_put_config
    )
    ezviz_lan_net_config_and_voice_upload_put_request = (
        _compat_module_3.ezviz_lan_net_config_and_voice_upload_put_request
    )
    ezviz_lan_net_config_v30 = _compat_module_3.ezviz_lan_net_config_v30
    ezviz_lan_net_config_v30_request = _compat_module_3.ezviz_lan_net_config_v30_request
    ezviz_lan_ntp_config = _compat_module_3.ezviz_lan_ntp_config
    ezviz_lan_ntp_get_config_request = _compat_module_3.ezviz_lan_ntp_get_config_request
    ezviz_lan_password_store_key = _compat_module_3.ezviz_lan_password_store_key
    ezviz_lan_password_store_name = _compat_module_3.ezviz_lan_password_store_name
    ezviz_lan_pic_config_get_request = _compat_module_3.ezviz_lan_pic_config_get_request
    ezviz_lan_pic_config_update_request = _compat_module_3.ezviz_lan_pic_config_update_request
    ezviz_lan_pic_config_v30_get_request = _compat_module_3.ezviz_lan_pic_config_v30_get_request
    ezviz_lan_picture_config = _compat_module_3.ezviz_lan_picture_config
    ezviz_lan_play_device_login = _compat_module_3.ezviz_lan_play_device_login
    ezviz_lan_play_device_login_succeeded = _compat_module_3.ezviz_lan_play_device_login_succeeded
    ezviz_lan_playback_condition = _compat_module_3.ezviz_lan_playback_condition
    ezviz_lan_playback_convert_ability = _compat_module_3.ezviz_lan_playback_convert_ability
    ezviz_lan_playback_file_search_condition = (
        _compat_module_3.ezviz_lan_playback_file_search_condition
    )
    ezviz_lan_playback_intent = _compat_module_3.ezviz_lan_playback_intent
    ezviz_lan_playback_video_type = _compat_module_3.ezviz_lan_playback_video_type
    ezviz_lan_preview_plan = _compat_module_3.ezviz_lan_preview_plan
    ezviz_lan_ptz_ability = _compat_module_3.ezviz_lan_ptz_ability
    ezviz_lan_ptz_ability_input = _compat_module_3.ezviz_lan_ptz_ability_input
    ezviz_lan_ptz_ability_request = _compat_module_3.ezviz_lan_ptz_ability_request
    ezviz_lan_ptz_control_request = _compat_module_3.ezviz_lan_ptz_control_request
    ezviz_lan_ptz_is_preset_command = _compat_module_3.ezviz_lan_ptz_is_preset_command
    ezviz_lan_ptz_native_command = _compat_module_3.ezviz_lan_ptz_native_command
    ezviz_lan_ptz_preset_request = _compat_module_3.ezviz_lan_ptz_preset_request
    ezviz_lan_ptz_request = _compat_module_3.ezviz_lan_ptz_request
    ezviz_lan_record_ability_input = _compat_module_3.ezviz_lan_record_ability_input
    ezviz_lan_record_ability_request = _compat_module_3.ezviz_lan_record_ability_request
    ezviz_lan_record_config_v30 = _compat_module_3.ezviz_lan_record_config_v30
    ezviz_lan_record_config_v30_request = _compat_module_3.ezviz_lan_record_config_v30_request
    ezviz_lan_rn_device_ability_request = _compat_module_3.ezviz_lan_rn_device_ability_request
    ezviz_lan_sadp_activate_batch_result = _compat_module_3.ezviz_lan_sadp_activate_batch_result
    ezviz_lan_sadp_edit_net_param_batch_result = (
        _compat_module_3.ezviz_lan_sadp_edit_net_param_batch_result
    )
    ezviz_lan_sd_format_close_request = _compat_module_3.ezviz_lan_sd_format_close_request
    ezviz_lan_sd_format_progress_request = _compat_module_3.ezviz_lan_sd_format_progress_request
    ezviz_lan_sd_format_progress_result = _compat_module_3.ezviz_lan_sd_format_progress_result
    ezviz_lan_sd_format_start_request = _compat_module_3.ezviz_lan_sd_format_start_request
    ezviz_lan_services_switch_get_command_port = (
        _compat_module_3.ezviz_lan_services_switch_get_command_port
    )
    ezviz_lan_services_switch_get_config = _compat_module_3.ezviz_lan_services_switch_get_config
    ezviz_lan_services_switch_get_request = _compat_module_3.ezviz_lan_services_switch_get_request
    ezviz_lan_services_switch_payload = _compat_module_3.ezviz_lan_services_switch_payload
    ezviz_lan_services_switch_put_config = _compat_module_3.ezviz_lan_services_switch_put_config
    ezviz_lan_services_switch_put_request = _compat_module_3.ezviz_lan_services_switch_put_request
    ezviz_lan_services_switch_set_command_port = (
        _compat_module_3.ezviz_lan_services_switch_set_command_port
    )
    ezviz_lan_services_switch_set_config = _compat_module_3.ezviz_lan_services_switch_set_config
    ezviz_lan_services_switch_set_payload = _compat_module_3.ezviz_lan_services_switch_set_payload
    ezviz_lan_services_switch_state = _compat_module_3.ezviz_lan_services_switch_state
    ezviz_lan_services_switch_state_command_port = (
        _compat_module_3.ezviz_lan_services_switch_state_command_port
    )
    ezviz_lan_services_switch_succeeded = _compat_module_3.ezviz_lan_services_switch_succeeded
    ezviz_lan_services_switch_update_config = (
        _compat_module_3.ezviz_lan_services_switch_update_config
    )
    ezviz_lan_settings_channel_number = _compat_module_3.ezviz_lan_settings_channel_number
    ezviz_lan_settings_error_clears_password = (
        _compat_module_3.ezviz_lan_settings_error_clears_password
    )
    ezviz_lan_settings_error_code = _compat_module_3.ezviz_lan_settings_error_code
    ezviz_lan_settings_login_candidates = _compat_module_3.ezviz_lan_settings_login_candidates
    ezviz_lan_settings_login_succeeded = _compat_module_3.ezviz_lan_settings_login_succeeded
    ezviz_lan_settings_updates_services_switch = (
        _compat_module_3.ezviz_lan_settings_updates_services_switch
    )
    ezviz_lan_soft_hardware_ability = _compat_module_3.ezviz_lan_soft_hardware_ability
    ezviz_lan_soft_hardware_ability_request = (
        _compat_module_3.ezviz_lan_soft_hardware_ability_request
    )
    ezviz_lan_time_config = _compat_module_3.ezviz_lan_time_config
    ezviz_lan_time_get_config_request = _compat_module_3.ezviz_lan_time_get_config_request
    ezviz_lan_user_config_v30 = _compat_module_3.ezviz_lan_user_config_v30
    ezviz_lan_user_config_v30_summary = _compat_module_3.ezviz_lan_user_config_v30_summary
    ezviz_lan_user_password_get_config_request = (
        _compat_module_3.ezviz_lan_user_password_get_config_request
    )
    ezviz_lan_user_password_update_request = _compat_module_3.ezviz_lan_user_password_update_request
    ezviz_lan_video_coding_get_config_request = (
        _compat_module_3.ezviz_lan_video_coding_get_config_request
    )
    ezviz_lan_video_coding_update_request = _compat_module_3.ezviz_lan_video_coding_update_request
    ezviz_lan_video_effect_get_config_request = (
        _compat_module_3.ezviz_lan_video_effect_get_config_request
    )
    ezviz_lan_video_effect_update_request = _compat_module_3.ezviz_lan_video_effect_update_request
    ezviz_lan_video_level_for_stream_type = _compat_module_3.ezviz_lan_video_level_for_stream_type
    ezviz_lan_video_pic_ability = _compat_module_3.ezviz_lan_video_pic_ability
    ezviz_lan_video_pic_ability_input = _compat_module_3.ezviz_lan_video_pic_ability_input
    ezviz_lan_video_pic_ability_request = _compat_module_3.ezviz_lan_video_pic_ability_request
    ezviz_lan_video_qualities = _compat_module_3.ezviz_lan_video_qualities
    ezviz_lan_wifi_ap_info_list = _compat_module_3.ezviz_lan_wifi_ap_info_list
    ezviz_lan_wifi_ap_info_list_request = _compat_module_3.ezviz_lan_wifi_ap_info_list_request
    ezviz_lan_wifi_config_summary = _compat_module_3.ezviz_lan_wifi_config_summary
    ezviz_lan_wifi_connect_status = _compat_module_3.ezviz_lan_wifi_connect_status
    ezviz_lan_wifi_connect_status_request = _compat_module_3.ezviz_lan_wifi_connect_status_request
    ezviz_lan_wifi_get_config_request = _compat_module_3.ezviz_lan_wifi_get_config_request
    ezviz_lan_wifi_set_config_request = _compat_module_3.ezviz_lan_wifi_set_config_request
    ezviz_lan_wifi_station_patch = _compat_module_3.ezviz_lan_wifi_station_patch
    ezviz_lan_wifi_work_mode_update_request = (
        _compat_module_3.ezviz_lan_wifi_work_mode_update_request
    )
    ezviz_local_sdk_iv = _compat_module_3.ezviz_local_sdk_iv
    ezviz_local_sdk_ssl_iv = _compat_module_3.ezviz_local_sdk_ssl_iv
    ezviz_native_video_level = _compat_module_3.ezviz_native_video_level
    field = _compat_module_3.field
    hashlib = _compat_module_3.hashlib
    hcnetsdk_cleanup_request = _compat_module_3.hcnetsdk_cleanup_request
    hcnetsdk_close_alarm_request = _compat_module_3.hcnetsdk_close_alarm_request
    hcnetsdk_command_candidate_role = _compat_module_3.hcnetsdk_command_candidate_role
    hcnetsdk_command_port_auth_word = _compat_module_3.hcnetsdk_command_port_auth_word
    hcnetsdk_command_port_control_frame = _compat_module_3.hcnetsdk_command_port_control_frame
    hcnetsdk_command_port_control_template_from_frame = (
        _compat_module_3.hcnetsdk_command_port_control_template_from_frame
    )
    hcnetsdk_command_port_execute_template = _compat_module_3.hcnetsdk_command_port_execute_template
    hcnetsdk_command_port_login_proof = _compat_module_3.hcnetsdk_command_port_login_proof
    hcnetsdk_command_port_login_proof_frame = (
        _compat_module_3.hcnetsdk_command_port_login_proof_frame
    )
    hcnetsdk_command_port_login_request_frame = (
        _compat_module_3.hcnetsdk_command_port_login_request_frame
    )
    hcnetsdk_command_port_password_digest = _compat_module_3.hcnetsdk_command_port_password_digest
    hcnetsdk_command_port_play_login_body_tail_for_today = (
        _compat_module_3.hcnetsdk_command_port_play_login_body_tail_for_today
    )
    hcnetsdk_command_port_public_key_der = _compat_module_3.hcnetsdk_command_port_public_key_der
    hcnetsdk_command_port_response_payload = _compat_module_3.hcnetsdk_command_port_response_payload
    hcnetsdk_command_port_rsa_key = _compat_module_3.hcnetsdk_command_port_rsa_key
    hcnetsdk_device_ability_command_port_body_tail = (
        _compat_module_3.hcnetsdk_device_ability_command_port_body_tail
    )
    hcnetsdk_device_ability_command_port_template = (
        _compat_module_3.hcnetsdk_device_ability_command_port_template
    )
    hcnetsdk_device_ability_request = _compat_module_3.hcnetsdk_device_ability_request
    hcnetsdk_device_ability_xml = _compat_module_3.hcnetsdk_device_ability_xml
    hcnetsdk_dvr_config_command_port_body_tail = (
        _compat_module_3.hcnetsdk_dvr_config_command_port_body_tail
    )
    hcnetsdk_dvr_config_command_port_template = (
        _compat_module_3.hcnetsdk_dvr_config_command_port_template
    )
    hcnetsdk_dvr_config_get_request = _compat_module_3.hcnetsdk_dvr_config_get_request
    hcnetsdk_dvr_config_set_request = _compat_module_3.hcnetsdk_dvr_config_set_request
    hcnetsdk_file_search_condition = _compat_module_3.hcnetsdk_file_search_condition
    hcnetsdk_find_close_v30_request = _compat_module_3.hcnetsdk_find_close_v30_request
    hcnetsdk_find_file_v30_request = _compat_module_3.hcnetsdk_find_file_v30_request
    hcnetsdk_find_next_file_status = _compat_module_3.hcnetsdk_find_next_file_status
    hcnetsdk_find_next_file_v30_request = _compat_module_3.hcnetsdk_find_next_file_v30_request
    hcnetsdk_get_device_ability_command_port = (
        _compat_module_3.hcnetsdk_get_device_ability_command_port
    )
    hcnetsdk_get_download_pos_request = _compat_module_3.hcnetsdk_get_download_pos_request
    hcnetsdk_get_dvr_config_command_port = _compat_module_3.hcnetsdk_get_dvr_config_command_port
    hcnetsdk_get_error_msg_request = _compat_module_3.hcnetsdk_get_error_msg_request
    hcnetsdk_get_file_by_name_request = _compat_module_3.hcnetsdk_get_file_by_name_request
    hcnetsdk_get_file_by_time_request = _compat_module_3.hcnetsdk_get_file_by_time_request
    hcnetsdk_get_last_error_request = _compat_module_3.hcnetsdk_get_last_error_request
    hcnetsdk_get_sdk_build_version_request = _compat_module_3.hcnetsdk_get_sdk_build_version_request
    hcnetsdk_get_sdk_version_request = _compat_module_3.hcnetsdk_get_sdk_version_request
    hcnetsdk_init_request = _compat_module_3.hcnetsdk_init_request
    hcnetsdk_logout_v30_request = _compat_module_3.hcnetsdk_logout_v30_request
    hcnetsdk_media_packet_source = _compat_module_3.hcnetsdk_media_packet_source
    hcnetsdk_playback_by_time_v40_request = _compat_module_3.hcnetsdk_playback_by_time_v40_request
    hcnetsdk_playback_capture_file_request = _compat_module_3.hcnetsdk_playback_capture_file_request
    hcnetsdk_playback_condition = _compat_module_3.hcnetsdk_playback_condition
    hcnetsdk_playback_control_v40_request = _compat_module_3.hcnetsdk_playback_control_v40_request
    hcnetsdk_real_data_to_media_packet = _compat_module_3.hcnetsdk_real_data_to_media_packet
    hcnetsdk_real_data_type_is_media = _compat_module_3.hcnetsdk_real_data_type_is_media
    hcnetsdk_real_play_request = _compat_module_3.hcnetsdk_real_play_request
    hcnetsdk_set_connect_time_request = _compat_module_3.hcnetsdk_set_connect_time_request
    hcnetsdk_set_play_data_callback_request = (
        _compat_module_3.hcnetsdk_set_play_data_callback_request
    )
    hcnetsdk_set_play_data_callback_v40_request = (
        _compat_module_3.hcnetsdk_set_play_data_callback_v40_request
    )
    hcnetsdk_set_playback_es_callback_request = (
        _compat_module_3.hcnetsdk_set_playback_es_callback_request
    )
    hcnetsdk_set_playback_response_callback_request = (
        _compat_module_3.hcnetsdk_set_playback_response_callback_request
    )
    hcnetsdk_set_playback_secret_key_request = (
        _compat_module_3.hcnetsdk_set_playback_secret_key_request
    )
    hcnetsdk_set_sdk_local_cfg_request = _compat_module_3.hcnetsdk_set_sdk_local_cfg_request
    hcnetsdk_setup_alarm_v30_request = _compat_module_3.hcnetsdk_setup_alarm_v30_request
    hcnetsdk_setup_alarm_v41_request = _compat_module_3.hcnetsdk_setup_alarm_v41_request
    hcnetsdk_stdxml_config_command_port = _compat_module_3.hcnetsdk_stdxml_config_command_port
    hcnetsdk_stdxml_config_command_port_body_tail = (
        _compat_module_3.hcnetsdk_stdxml_config_command_port_body_tail
    )
    hcnetsdk_stdxml_config_command_port_from_trace = (
        _compat_module_3.hcnetsdk_stdxml_config_command_port_from_trace
    )
    hcnetsdk_stdxml_config_command_port_template = (
        _compat_module_3.hcnetsdk_stdxml_config_command_port_template
    )
    hcnetsdk_stdxml_config_request = _compat_module_3.hcnetsdk_stdxml_config_request
    hcnetsdk_stdxml_isapi_command_port = _compat_module_3.hcnetsdk_stdxml_isapi_command_port
    hcnetsdk_stdxml_isapi_request = _compat_module_3.hcnetsdk_stdxml_isapi_request
    hcnetsdk_stdxml_response_json = _compat_module_3.hcnetsdk_stdxml_response_json
    hcnetsdk_stop_get_file_request = _compat_module_3.hcnetsdk_stop_get_file_request
    hcnetsdk_stop_playback_request = _compat_module_3.hcnetsdk_stop_playback_request
    hcnetsdk_time = _compat_module_3.hcnetsdk_time
    hcnetsdk_time_from_datetime = _compat_module_3.hcnetsdk_time_from_datetime
    hmac = _compat_module_3.hmac
    ipaddress = _compat_module_3.ipaddress
    iter_hcnetsdk_real_data_mpegps = _compat_module_3.iter_hcnetsdk_real_data_mpegps
    iter_hcnetsdk_tcp_frame_shapes = _compat_module_3.iter_hcnetsdk_tcp_frame_shapes
    json = _compat_module_3.json
    math = _compat_module_3.math
    normalize_hcnetsdk_parameters = _compat_module_3.normalize_hcnetsdk_parameters
    parse_ezviz_interleaved_rtp_frame_header = (
        _compat_module_3.parse_ezviz_interleaved_rtp_frame_header
    )
    parse_ezviz_local_device = _compat_module_3.parse_ezviz_local_device
    parse_ezviz_local_sdk_frame = _compat_module_3.parse_ezviz_local_sdk_frame
    parse_ezviz_local_sdk_frame_header = _compat_module_3.parse_ezviz_local_sdk_frame_header
    parse_ezviz_local_sdk_xml_fields = _compat_module_3.parse_ezviz_local_sdk_xml_fields
    parse_hcnetsdk_command_port_login_session = (
        _compat_module_3.parse_hcnetsdk_command_port_login_session
    )
    parse_hcnetsdk_semantic_log_line = _compat_module_3.parse_hcnetsdk_semantic_log_line
    parse_hcnetsdk_tcp_frame = _compat_module_3.parse_hcnetsdk_tcp_frame
    parse_hcnetsdk_tcp_frame_header = _compat_module_3.parse_hcnetsdk_tcp_frame_header
    parse_hcnetsdk_tcp_shape_log_line = _compat_module_3.parse_hcnetsdk_tcp_shape_log_line
    parse_sadp_response = _compat_module_3.parse_sadp_response
    re = _compat_module_3.re
    read_ezviz_interleaved_rtp_frame = _compat_module_3.read_ezviz_interleaved_rtp_frame
    read_ezviz_interleaved_rtp_frame_after_prefix = (
        _compat_module_3.read_ezviz_interleaved_rtp_frame_after_prefix
    )
    read_ezviz_local_sdk_frame = _compat_module_3.read_ezviz_local_sdk_frame
    read_hcnetsdk_command_port_interleaved_frame_after_prefix = (
        _compat_module_3.read_hcnetsdk_command_port_interleaved_frame_after_prefix
    )
    read_hcnetsdk_tcp_frame = _compat_module_3.read_hcnetsdk_tcp_frame
    replace = _compat_module_3.replace
    sadp_activate_device_request = _compat_module_3.sadp_activate_device_request
    sadp_clearup_request = _compat_module_3.sadp_clearup_request
    sadp_device_net_param = _compat_module_3.sadp_device_net_param
    sadp_get_last_error_request = _compat_module_3.sadp_get_last_error_request
    sadp_get_sadp_version_request = _compat_module_3.sadp_get_sadp_version_request
    sadp_modify_device_net_param_request = _compat_module_3.sadp_modify_device_net_param_request
    sadp_modify_device_net_param_v40_request = (
        _compat_module_3.sadp_modify_device_net_param_v40_request
    )
    sadp_send_inquiry_request = _compat_module_3.sadp_send_inquiry_request
    sadp_set_log_to_file_request = _compat_module_3.sadp_set_log_to_file_request
    sadp_start_v30_request = _compat_module_3.sadp_start_v30_request
    sadp_start_v40_request = _compat_module_3.sadp_start_v40_request
    sadp_stop_request = _compat_module_3.sadp_stop_request
    select = _compat_module_3.select
    socket = _compat_module_3.socket
    ssl = _compat_module_3.ssl
    stream_header_from_preview = _compat_module_3.stream_header_from_preview
    summarize_hcnetsdk_command_trace = _compat_module_3.summarize_hcnetsdk_command_trace
    suppress = _compat_module_3.suppress
    sys = _compat_module_3.sys
    time = _compat_module_3.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        AES,
        PKCS1_v1_5,
        RSA,
        DerSequence,
        _AES_RCON,
        _AES_SBOX,
        _WINDOWS_EXCLUSIVE_SOURCE_BIND,
        DEFAULT_RESOLVER,
        ET,
        EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD,
        EZVIZ_BODY_PRINTABLE_THRESHOLD,
        EZVIZ_CAS_PTZ_COMMAND_MAP,
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        EZVIZ_HCNETUTIL_LOGIN_V40,
        EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
        EZVIZ_LAN_MAIN_STREAM_TYPE,
        EZVIZ_LAN_MAIN_VIDEO_LEVEL,
        EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP,
        EZVIZ_LAN_PTZ_ACTION_RESET,
        EZVIZ_LAN_PTZ_ACTION_START,
        EZVIZ_LAN_PTZ_ACTION_STOP,
        EZVIZ_LAN_PTZ_COMMAND_MAP,
        EZVIZ_LAN_PTZ_PRESET_COMMANDS,
        EZVIZ_LAN_PTZ_SPEED_DEFAULT,
        EZVIZ_LAN_SUB_STREAM_TYPE,
        EZVIZ_LAN_SUB_VIDEO_LEVEL,
        EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE,
        EZVIZ_LOCAL_SDK_HEADER_LENGTH,
        EZVIZ_LOCAL_SDK_MAGIC,
        EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
        EZVIZ_LOCAL_SDK_PRE_START_RESPONSE,
        EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
        EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE,
        EZVIZ_LOCAL_SDK_SSL_IV_PREFIX,
        EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH,
        EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES,
        EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND,
        EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE,
        EZVIZ_LOCAL_SDK_STOP_TIMEOUT,
        EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
        EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE,
        EZVIZ_NATIVE_CREATE_CLIENT,
        EZVIZ_NATIVE_START_PREVIEW,
        EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE,
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO,
        EZVIZ_PLAYER_EXTRA_DEVICE_ID,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG,
        EZVIZ_PLAYER_EXTRA_LAN_USERID,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID,
        EZVIZ_PLAYER_LAN_FLAG_EZLINK,
        EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PREPLAY_SPS_TYPE,
        EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
        EZVIZ_RTP_INTERLEAVED_MAGIC,
        EZVIZ_STREAM_INHIBIT_LAN,
        EZVIZ_STREAM_SOURCE_LIVE_MINE,
        EZVIZ_STREAM_TIMEOUT_MS,
        EZVIZ_XML_DETECT_PREFIX_LIMIT,
        EZVIZ_XML_START_BYTE,
        HCNETSDK_AUDIO_INPUT_PARAM_SIZE,
        HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE,
        HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET,
        HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET,
        HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE,
        HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET,
        HCNETSDK_CLEANUP,
        HCNETSDK_CLOSE_ALARM_CHAN_V30,
        HCNETSDK_CLOSE_FORMAT_HANDLE,
        HCNETSDK_COMMAND_CANDIDATE_CONTROL,
        HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN,
        HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH,
        HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
        HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
        HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID,
        HCNETSDK_COMMAND_PORT_LOGIN_FAMILY,
        HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12,
        HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX,
        HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX,
        HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH,
        HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM,
        HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH,
        HCNETSDK_COMMAND_PORT_RSA_BITS,
        HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH,
        HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH,
        HCNETSDK_COMMAND_PORT_USERNAME_LENGTH,
        HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET,
        HCNETSDK_COMPRESSION_CFG_MIN_SIZE,
        HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET,
        HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET,
        HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET,
        HCNETSDK_COMPRESSION_INFO_V30_SIZE,
        HCNETSDK_DEFAULT_RTSP_PORT,
        HCNETSDK_DEFAULT_SERVER_PORT,
        HCNETSDK_DEFAULT_TLS_PORT,
        HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR,
        HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE,
        HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE,
        HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE,
        HCNETSDK_DEVICE_CFG_V40_MIN_SIZE,
        HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET,
        HCNETSDK_DEVICE_CFG_V40_NAME_SIZE,
        HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET,
        HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE,
        HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET,
        HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE,
        HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS,
        HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS,
        HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE,
        HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_SIZE,
        HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET,
        HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE,
        HCNETSDK_EZVIZ_CONNECT_MODE_PUT,
        HCNETSDK_EZVIZ_DEFAULT_USERNAME,
        HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX,
        HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX,
        HCNETSDK_EZVIZ_LOCAL_USERNAME,
        HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT,
        HCNETSDK_EZVIZ_SERVICES_SWITCH_GET,
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT,
        HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR,
        HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR,
        HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE,
        HCNETSDK_FILECOND_FIELD_ORDER,
        HCNETSDK_FIND_CLOSE_V30,
        HCNETSDK_FIND_FILE_FAILED,
        HCNETSDK_FIND_FILE_V30,
        HCNETSDK_FIND_NEXT_FILE_EXCEPTION,
        HCNETSDK_FIND_NEXT_FILE_IS_FINDING,
        HCNETSDK_FIND_NEXT_FILE_NO_FILE,
        HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE,
        HCNETSDK_FIND_NEXT_FILE_SUCCESS,
        HCNETSDK_FIND_NEXT_FILE_V30,
        HCNETSDK_FINDDATA_V30_FIELD_ORDER,
        HCNETSDK_FORMAT_DISK,
        HCNETSDK_GET_DEVICE_ABILITY,
        HCNETSDK_GET_DOWNLOAD_POS,
        HCNETSDK_GET_DVR_CONFIG,
        HCNETSDK_GET_ERROR_MSG,
        HCNETSDK_GET_FILE_BY_NAME,
        HCNETSDK_GET_FILE_BY_TIME,
        HCNETSDK_GET_FILE_FAILED,
        HCNETSDK_GET_FORMAT_PROGRESS,
        HCNETSDK_GET_LAST_ERROR,
        HCNETSDK_GET_SDK_BUILD_VERSION,
        HCNETSDK_GET_SDK_VERSION,
        HCNETSDK_HD_CFG_DISK_ATTR_OFFSET,
        HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET,
        HCNETSDK_HD_CFG_DISK_COUNT,
        HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET,
        HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET,
        HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET,
        HCNETSDK_HD_CFG_DISK_GROUP_OFFSET,
        HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET,
        HCNETSDK_HD_CFG_DISK_OFFSET,
        HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET,
        HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET,
        HCNETSDK_HD_CFG_DISK_SIZE,
        HCNETSDK_HD_CFG_DISK_STATUS_OFFSET,
        HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET,
        HCNETSDK_HD_CFG_DISK_TYPE_OFFSET,
        HCNETSDK_HD_CFG_HEADER_SIZE,
        HCNETSDK_HD_CFG_MIN_SIZE,
        HCNETSDK_HIK_PRIVATE_PREFIX,
        HCNETSDK_HKMI_PREFIX,
        HCNETSDK_INIT,
        HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER,
        HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER,
        HCNETSDK_LOGIN_V40,
        HCNETSDK_LOGOUT_V30,
        HCNETSDK_MAKE_KEYFRAME_MAIN,
        HCNETSDK_MAKE_KEYFRAME_SUB,
        HCNETSDK_MPEG_PS_PACK_HEADER,
        HCNETSDK_MPEG_START_CODE_PREFIX,
        HCNETSDK_MPEG_TS_SYNC_BYTE,
        HCNETSDK_NETCFG_V30_ETHERNET_COUNT,
        HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET,
        HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET,
        HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET,
        HCNETSDK_NETCFG_V30_ETHERNET_OFFSET,
        HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET,
        HCNETSDK_NETCFG_V30_ETHERNET_SIZE,
        HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET,
        HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET,
        HCNETSDK_NETCFG_V30_IP_SIZE,
        HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET,
        HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET,
        HCNETSDK_NETCFG_V30_MIN_SIZE,
        HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET,
        HCNETSDK_NETCFG_V30_NFS_IP_OFFSET,
        HCNETSDK_NTP_CFG_SIZE,
        HCNETSDK_NTP_ENABLE_OFFSET,
        HCNETSDK_NTP_INTERVAL_OFFSET,
        HCNETSDK_NTP_PORT_OFFSET,
        HCNETSDK_NTP_SERVER_SIZE,
        HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET,
        HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET,
        HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET,
        HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE,
        HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET,
        HCNETSDK_PIC_CFG_MIN_SIZE,
        HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET,
        HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET,
        HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET,
        HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET,
        HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET,
        HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET,
        HCNETSDK_PLAY_CONVERT,
        HCNETSDK_PLAYAUDIOVOLUME,
        HCNETSDK_PLAYBACK_BY_TIME_V40,
        HCNETSDK_PLAYBACK_CAPTURE_FILE,
        HCNETSDK_PLAYBACK_CONTROL_V40,
        HCNETSDK_PLAYBACK_FAILED,
        HCNETSDK_PLAYBACK_FILE_TYPE_ALL,
        HCNETSDK_PLAYBACK_LOCK_STATE_ALL,
        HCNETSDK_PLAYCOND_FIELD_ORDER,
        HCNETSDK_PLAYFAST,
        HCNETSDK_PLAYPAUSE,
        HCNETSDK_PLAYRESTART,
        HCNETSDK_PLAYSLOW,
        HCNETSDK_PLAYSTART,
        HCNETSDK_PLAYSTARTAUDIO,
        HCNETSDK_PLAYSTOPAUDIO,
        HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER,
        HCNETSDK_PTZ_PRESET_OTHER,
        HCNETSDK_REALDATA_CALLBACK_V30,
        HCNETSDK_REALPLAY_V30,
        HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET,
        HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE,
        HCNETSDK_RECORD_CFG_V30_DAY_COUNT,
        HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET,
        HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE,
        HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY,
        HCNETSDK_RECORD_CFG_V30_SIZE,
        HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET,
        HCNETSDK_SECRET_KEY_TYPE_AES,
        HCNETSDK_SET_CONNECT_TIME,
        HCNETSDK_SET_DVR_CONFIG,
        HCNETSDK_SET_PLAY_DATA_CALLBACK,
        HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
        HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
        HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK,
        HCNETSDK_SET_PLAYBACK_SECRET_KEY,
        HCNETSDK_SET_SDK_LOCAL_CFG,
        HCNETSDK_SET_TRANS_TYPE,
        HCNETSDK_SETUP_ALARM_CHAN_V30,
        HCNETSDK_SETUP_ALARM_CHAN_V41,
        HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER,
        HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX,
        HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE,
        HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE,
        HCNETSDK_STDXML_COMMAND_PORT_FLAGS,
        HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE,
        HCNETSDK_STDXML_CONFIG,
        HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE,
        HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE,
        HCNETSDK_STDXML_INPUT_FIELD_ORDER,
        HCNETSDK_STDXML_OUTPUT_FIELD_ORDER,
        HCNETSDK_STOP_GET_FILE,
        HCNETSDK_STOP_PLAYBACK,
        HCNETSDK_TCP_COMMAND_PORTS,
        HCNETSDK_TCP_HEADER_LENGTH,
        HCNETSDK_TIME_CFG_SIZE,
        HCNETSDK_TIME_FIELD_ORDER,
        HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE,
        HCNETSDK_USER_CFG_V30_ENTRY_SIZE,
        HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE,
        HCNETSDK_USER_CFG_V30_MAC_SIZE,
        HCNETSDK_USER_CFG_V30_MAX_SIZE,
        HCNETSDK_USER_CFG_V30_MIN_SIZE,
        HCNETSDK_USER_CFG_V30_PASSWORD_SIZE,
        HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE,
        HCNETSDK_USER_CFG_V30_RESERVED_SIZE,
        HCNETSDK_USER_CFG_V30_USER_COUNT,
        HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE,
        HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE,
        HCNETSDK_USER_CFG_V30_USERNAME_SIZE,
        HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE,
        HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE,
        HCNETSDK_WIFI_AP_INFO_SSID_SIZE,
        HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE,
        HCNETSDK_XML_MARKER,
        SADP_ACTIVATE_DEVICE,
        SADP_CLEARUP,
        SADP_DEV_NET_PARAM_ANDROID_FIELDS,
        SADP_DEV_NET_PARAM_JNA_FIELD_ORDER,
        SADP_DEV_RET_NET_PARAM_BUFFER_SIZE,
        SADP_DEV_RET_NET_PARAM_FIELD_ORDER,
        SADP_GET_LAST_ERROR,
        SADP_GET_VERSION,
        SADP_MODIFY_DEVICE_NET_PARAM,
        SADP_MODIFY_DEVICE_NET_PARAM_V40,
        SADP_NUL_BYTE,
        SADP_SEND_INQUIRY,
        SADP_SET_LOG_TO_FILE,
        SADP_START_V30,
        SADP_START_V40,
        SADP_STOP,
        Any,
        BoundedResolver,
        Callable,
        DeviceException,
        Empty,
        EzvizCasDeviceInfo,
        EzvizInterleavedRtpFrame,
        EzvizInterleavedRtpFrameHeader,
        EzvizInterleavedRtpFrameWithPrefix,
        EzvizLanAccessProtocolAbility,
        EzvizLanAudioInputParam,
        EzvizLanAudioOutputVolume,
        EzvizLanAudioVideoCompressAudioChannel,
        EzvizLanAudioVideoCompressInfo,
        EzvizLanAudioVideoCompressStream,
        EzvizLanAudioVideoCompressVideoChannel,
        EzvizLanAudioVideoCompressVoiceTalkChannel,
        EzvizLanCameraParamConfig,
        EzvizLanCompressionConfig,
        EzvizLanCompressionInfoV30,
        EzvizLanDeviceConfigV40,
        EzvizLanDeviceSoftHardwareAbility,
        EzvizLanDvrConfigSummary,
        EzvizLanEzvizAccessConfig,
        EzvizLanHdConfig,
        EzvizLanHdDiskConfig,
        EzvizLanIpcFrontParameterAbility,
        EzvizLanIpcFrontParameterRange,
        EzvizLanKeyframeRequest,
        EzvizLanLiveViewParams,
        EzvizLanNetConfigV30,
        EzvizLanNetInterfaceConfig,
        EzvizLanNtpConfig,
        EzvizLanPictureConfig,
        EzvizLanPlaybackConvertAbility,
        EzvizLanPlaybackConvertResolution,
        EzvizLanPlaybackIntent,
        EzvizLanPlaybackPath,
        EzvizLanPlayDeviceLogin,
        EzvizLanPreviewPlan,
        EzvizLanPtzAbility,
        EzvizLanRecordConfigV30,
        EzvizLanRecordDayConfig,
        EzvizLanRecordScheduleSegment,
        EzvizLanSdFormatProgress,
        EzvizLanServicesSwitchState,
        EzvizLanUserConfigV30,
        EzvizLanUserConfigV30Entry,
        EzvizLanVideoPicAbility,
        EzvizLanVideoQuality,
        EzvizLanVideoResolution,
        EzvizLanWifiApInfo,
        EzvizLanWifiConnectStatus,
        EzvizLocalAuthenticationAttrs,
        EzvizLocalDevice,
        EzvizLocalDeviceContent,
        EzvizLocalPreviewRequest,
        EzvizLocalReceiverInfo,
        EzvizLocalReceiverInfoAttrs,
        EzvizLocalReceiverInfoEx,
        EzvizLocalReceiverInfoExAttrs,
        EzvizLocalSdkBodyShape,
        EzvizLocalSdkClient,
        EzvizLocalSdkDeadlineExpired,
        EzvizLocalSdkExchange,
        EzvizLocalSdkFrame,
        EzvizLocalSdkFrameHeader,
        EzvizLocalSdkStreamBootstrap,
        EzvizLocalSdkStreamClosed,
        EzvizPtzCommand,
        EzvizStreamHeader,
        Full,
        HcNetSdkAbility,
        HcNetSdkClientInfo,
        HcNetSdkCloseAlarmRequest,
        HcNetSdkCloseFormatHandleRequest,
        HcNetSdkCommandPortClient,
        HcNetSdkCommandPortControlResponse,
        HcNetSdkCommandPortControlTemplate,
        HcNetSdkCommandPortExchange,
        HcNetSdkCommandPortLoginChallenge,
        HcNetSdkCommandPortLoginSession,
        HcNetSdkCommandPortStreamBootstrap,
        HcNetSdkCommandTraceSummary,
        HcNetSdkConfiguredMedia,
        HcNetSdkDeviceAbilityRequest,
        HcNetSdkDvrCommand,
        HcNetSdkDvrConfigRequest,
        HcNetSdkFileCond,
        HcNetSdkFindCloseRequest,
        HcNetSdkFindDataV30,
        HcNetSdkFindFileRequest,
        HcNetSdkFindNextFileRequest,
        HcNetSdkFormatDiskRequest,
        HcNetSdkFormatProgressRequest,
        HcNetSdkGetDownloadPosRequest,
        HcNetSdkGetErrorMsgRequest,
        HcNetSdkGetFileByNameRequest,
        HcNetSdkGetFileByTimeRequest,
        HcNetSdkInitRequest,
        HcNetSdkLanEndpoint,
        HcNetSdkLocalCfgType,
        HcNetSdkLoginCandidate,
        HcNetSdkLogoutRequest,
        HcNetSdkNoArgRequest,
        HcNetSdkPlayBackByTimeRequest,
        HcNetSdkPlaybackCallbackRequest,
        HcNetSdkPlayBackCaptureFileRequest,
        HcNetSdkPlaybackControlCommand,
        HcNetSdkPlayBackControlRequest,
        HcNetSdkPlayBackSecretKeyRequest,
        HcNetSdkPlayCond,
        HcNetSdkPlayDataCallbackRequest,
        HcNetSdkPortProbe,
        HcNetSdkPtzCommand,
        HcNetSdkPtzControlRequest,
        HcNetSdkPtzPresetCommand,
        HcNetSdkPtzPresetRequest,
        HcNetSdkPurePythonClient,
        HcNetSdkRealDataPacket,
        HcNetSdkRealDataType,
        HcNetSdkRealPlayRequest,
        HcNetSdkSemanticLogEvent,
        HcNetSdkSetConnectTimeRequest,
        HcNetSdkSetSdkLocalCfgRequest,
        HcNetSdkSetupAlarmParam,
        HcNetSdkSetupAlarmRequest,
        HcNetSdkStdXmlConfigRequest,
        HcNetSdkStdXmlConfigResponse,
        HcNetSdkStopGetFileRequest,
        HcNetSdkStopPlayBackRequest,
        HcNetSdkStreamDetails,
        HcNetSdkTcpFrame,
        HcNetSdkTcpFrameHeader,
        HcNetSdkTcpFrameShape,
        HcNetSdkTcpPayloadShape,
        HcNetSdkTcpShapeLogRecord,
        HcNetSdkTime,
        IntEnum,
        Iterable,
        IterableMediaPacketSource,
        Iterator,
        LocalSdkIvFactory,
        Lock,
        Mapping,
        MediaPacket,
        MediaPacketMetadata,
        PyEzvizError,
        Queue,
        ResolverBusy,
        SadpActivateDeviceRequest,
        SadpBatchResult,
        SadpDeviceInfo,
        SadpDeviceNetParam,
        SadpDeviceRetNetParam,
        SadpModifyDeviceNetParamRequest,
        SadpModifyDeviceNetParamV40Request,
        SadpNoArgRequest,
        SadpSetLogToFileRequest,
        SadpStartRequest,
        SocketBindAddress,
        SocketFactory,
        SocketSourceAddress,
        SourceAddressSocketFactory,
        Thread,
        _ability_option_tuple,
        _audio_video_compress_audio_channels,
        _audio_video_compress_stream,
        _audio_video_compress_video_channels,
        _audio_video_compress_voice_talk_channels,
        _bounded_bytes,
        _build_local_sdk_request_xml,
        _byte_tuple,
        _byte_value,
        _connect_attempt_settings,
        _connect_bound_source_socket,
        _connect_with_optional_source_address,
        _create_deadline_connection,
        _create_reusable_source_connection,
        _DeadlineBoundRecvSocket,
        _device_ability_bytes,
        _device_ability_response_text,
        _device_ability_xml_name,
        _dword_value,
        _entropy_bits_per_byte,
        _event_field_bool,
        _event_field_int,
        _ezviz_lan_hd_disk_config,
        _ezviz_lan_user_config_v30_entry,
        _fixed_ipv4_text,
        _fixed_secret_bytes,
        _fixed_secret_text,
        _getaddrinfo_before_deadline,
        _hcnetsdk_aes128_round_keys,
        _hcnetsdk_aes_add_round_key,
        _hcnetsdk_aes_mix_columns,
        _hcnetsdk_aes_shift_rows,
        _hcnetsdk_aes_sub_bytes,
        _hcnetsdk_aes_xtime,
        _hcnetsdk_command_port_auth_mask,
        _hcnetsdk_command_port_four_round_aes,
        _hcnetsdk_command_port_local_ip_word,
        _hcnetsdk_command_port_login_prefix,
        _hcnetsdk_command_port_md5_digest,
        _hcnetsdk_command_port_md5_hmac,
        _hcnetsdk_command_port_username,
        _hcnetsdk_compression_info_v30,
        _hcnetsdk_config_declared_size,
        _hcnetsdk_declared_length,
        _hcnetsdk_known_prefix_kind,
        _hcnetsdk_protocol,
        _hcnetsdk_shape_command_candidate,
        _hcnetsdk_stream_details_query,
        _hcnetsdk_tcp_payload_kind,
        _hcnetsdk_time_value,
        _ipc_front_parameter_field_root,
        _local_sdk_aes_bytes,
        _looks_tls_record,
        _mac_address_bytes,
        _mac_address_text,
        _mapping_int,
        _mapping_str,
        _native_path_value,
        _native_secret_key_bytes,
        _native_string_bytes,
        _nul_stripped_text,
        _optional_native_bytes,
        _optional_raw_byte,
        _optional_raw_byte_triplet,
        _optional_raw_u16_be,
        _optional_raw_u16_be_pair,
        _optional_raw_u32_be,
        _parse_float,
        _parse_int,
        _parse_length_candidate_offset,
        _parse_length_candidates,
        _parse_local_device_content,
        _parse_shape_fields,
        _pkcs5_pad,
        _pkcs5_unpad,
        _port_value,
        _probe_port,
        _ptz_int,
        _recv_exact,
        _remaining_timeout,
        _resolver,
        _sadp_string_bytes,
        _send_all,
        _send_all_before_deadline,
        _send_all_with_timeout,
        _services_switch_value,
        _SourcePortConflictError,
        _stdxml_bytes,
        _wait_for_socket_io,
        _windows_concrete_source_address,
        _word_value,
        _xml_attr,
        _xml_attr_int,
        _xml_attrs,
        _xml_bool_opt_attr,
        _xml_child_int,
        _xml_child_int_csv_with_prefix,
        _xml_child_int_range,
        _xml_child_optional_int,
        _xml_child_text,
        _xml_children,
        _xml_descendant_bool_text,
        _xml_descendant_int,
        _xml_descendant_text,
        _xml_escape,
        _xml_first_child,
        _xml_has_descendant,
        _xml_has_parent,
        _xml_int_csv,
        _xml_local_name,
        _xml_offset,
        _xml_opt_attr,
        _xml_tag_names,
        annotations,
        asdict,
        base64,
        binascii,
        build_encrypted_ezviz_local_sdk_frame,
        build_ezviz_cas_encrypted_local_sdk_frame,
        build_ezviz_cas_ssl_local_sdk_frame,
        build_ezviz_interleaved_rtp_frame_header,
        build_ezviz_local_preview_request_body,
        build_ezviz_local_sdk_frame,
        build_ezviz_local_sdk_frame_header,
        build_ezviz_local_sdk_ssl_frame,
        build_ezviz_local_stop_preview_request_body,
        build_ezviz_local_stream_setup_request_body,
        build_hcnetsdk_tcp_frame,
        cast,
        classify_ezviz_local_sdk_body,
        classify_hcnetsdk_real_data_payload,
        classify_hcnetsdk_tcp_payload,
        classify_lan_ports,
        closing,
        dataclass,
        date,
        datetime,
        decode_hcnetsdk_command_port_login_challenge,
        decrypt_ezviz_local_sdk_body_aes_cbc,
        discover_hcnetsdk_stream_details,
        discover_hcnetsdk_stream_details_for_login,
        encrypt_ezviz_local_sdk_body_aes_cbc,
        errno,
        ezviz_cas_ptz_command,
        ezviz_hcnetsdk_local_ability_parse_request,
        ezviz_hcnetsdk_local_ptz_without_recv_request,
        ezviz_lan_access_protocol_ability,
        ezviz_lan_access_protocol_ability_input,
        ezviz_lan_access_protocol_ability_request,
        ezviz_lan_audio_input_get_config_request,
        ezviz_lan_audio_input_param,
        ezviz_lan_audio_output_volume,
        ezviz_lan_audio_video_compress_info,
        ezviz_lan_audio_video_compress_info_ability_request,
        ezviz_lan_audio_video_compress_info_input,
        ezviz_lan_audio_volume_update_requests,
        ezviz_lan_audioout_volume_get_config_request,
        ezviz_lan_backlight_wdr_get_config_request,
        ezviz_lan_backlight_wdr_update_request,
        ezviz_lan_camera_param_config,
        ezviz_lan_complete_playback_path,
        ezviz_lan_compression_config,
        ezviz_lan_connect_mode_payload,
        ezviz_lan_connect_mode_put_config,
        ezviz_lan_connect_mode_put_request,
        ezviz_lan_day_night_get_config_request,
        ezviz_lan_day_night_update_request,
        ezviz_lan_device_config_v40,
        ezviz_lan_device_config_v40_request,
        ezviz_lan_dvr_config_summary,
        ezviz_lan_ezviz_access_config,
        ezviz_lan_ezviz_access_config_summary,
        ezviz_lan_ezviz_access_get_config_request,
        ezviz_lan_ezviz_access_replacement_domain,
        ezviz_lan_ezviz_access_replacement_domain_request,
        ezviz_lan_ezviz_access_set_domain_request,
        ezviz_lan_hd_config,
        ezviz_lan_hd_config_request,
        ezviz_lan_image_display_param_ability_input,
        ezviz_lan_image_display_param_ability_request,
        ezviz_lan_ipc_front_parameter_ability,
        ezviz_lan_ipc_front_parameter_ability_request,
        ezviz_lan_live_view_params,
        ezviz_lan_local_user_password,
        ezviz_lan_login_candidates,
        ezviz_lan_net_config_and_voice_upload_payload,
        ezviz_lan_net_config_and_voice_upload_put_config,
        ezviz_lan_net_config_and_voice_upload_put_request,
        ezviz_lan_net_config_v30,
        ezviz_lan_net_config_v30_request,
        ezviz_lan_ntp_config,
        ezviz_lan_ntp_get_config_request,
        ezviz_lan_password_store_key,
        ezviz_lan_password_store_name,
        ezviz_lan_pic_config_get_request,
        ezviz_lan_pic_config_update_request,
        ezviz_lan_pic_config_v30_get_request,
        ezviz_lan_picture_config,
        ezviz_lan_play_device_login,
        ezviz_lan_play_device_login_succeeded,
        ezviz_lan_playback_condition,
        ezviz_lan_playback_convert_ability,
        ezviz_lan_playback_file_search_condition,
        ezviz_lan_playback_intent,
        ezviz_lan_playback_video_type,
        ezviz_lan_preview_plan,
        ezviz_lan_ptz_ability,
        ezviz_lan_ptz_ability_input,
        ezviz_lan_ptz_ability_request,
        ezviz_lan_ptz_control_request,
        ezviz_lan_ptz_is_preset_command,
        ezviz_lan_ptz_native_command,
        ezviz_lan_ptz_preset_request,
        ezviz_lan_ptz_request,
        ezviz_lan_record_ability_input,
        ezviz_lan_record_ability_request,
        ezviz_lan_record_config_v30,
        ezviz_lan_record_config_v30_request,
        ezviz_lan_rn_device_ability_request,
        ezviz_lan_sadp_activate_batch_result,
        ezviz_lan_sadp_edit_net_param_batch_result,
        ezviz_lan_sd_format_close_request,
        ezviz_lan_sd_format_progress_request,
        ezviz_lan_sd_format_progress_result,
        ezviz_lan_sd_format_start_request,
        ezviz_lan_services_switch_get_command_port,
        ezviz_lan_services_switch_get_config,
        ezviz_lan_services_switch_get_request,
        ezviz_lan_services_switch_payload,
        ezviz_lan_services_switch_put_config,
        ezviz_lan_services_switch_put_request,
        ezviz_lan_services_switch_set_command_port,
        ezviz_lan_services_switch_set_config,
        ezviz_lan_services_switch_set_payload,
        ezviz_lan_services_switch_state,
        ezviz_lan_services_switch_state_command_port,
        ezviz_lan_services_switch_succeeded,
        ezviz_lan_services_switch_update_config,
        ezviz_lan_settings_channel_number,
        ezviz_lan_settings_error_clears_password,
        ezviz_lan_settings_error_code,
        ezviz_lan_settings_login_candidates,
        ezviz_lan_settings_login_succeeded,
        ezviz_lan_settings_updates_services_switch,
        ezviz_lan_soft_hardware_ability,
        ezviz_lan_soft_hardware_ability_request,
        ezviz_lan_time_config,
        ezviz_lan_time_get_config_request,
        ezviz_lan_user_config_v30,
        ezviz_lan_user_config_v30_summary,
        ezviz_lan_user_password_get_config_request,
        ezviz_lan_user_password_update_request,
        ezviz_lan_video_coding_get_config_request,
        ezviz_lan_video_coding_update_request,
        ezviz_lan_video_effect_get_config_request,
        ezviz_lan_video_effect_update_request,
        ezviz_lan_video_level_for_stream_type,
        ezviz_lan_video_pic_ability,
        ezviz_lan_video_pic_ability_input,
        ezviz_lan_video_pic_ability_request,
        ezviz_lan_video_qualities,
        ezviz_lan_wifi_ap_info_list,
        ezviz_lan_wifi_ap_info_list_request,
        ezviz_lan_wifi_config_summary,
        ezviz_lan_wifi_connect_status,
        ezviz_lan_wifi_connect_status_request,
        ezviz_lan_wifi_get_config_request,
        ezviz_lan_wifi_set_config_request,
        ezviz_lan_wifi_station_patch,
        ezviz_lan_wifi_work_mode_update_request,
        ezviz_local_sdk_iv,
        ezviz_local_sdk_ssl_iv,
        ezviz_native_video_level,
        field,
        hashlib,
        hcnetsdk_cleanup_request,
        hcnetsdk_close_alarm_request,
        hcnetsdk_command_candidate_role,
        hcnetsdk_command_port_auth_word,
        hcnetsdk_command_port_control_frame,
        hcnetsdk_command_port_control_template_from_frame,
        hcnetsdk_command_port_execute_template,
        hcnetsdk_command_port_login_proof,
        hcnetsdk_command_port_login_proof_frame,
        hcnetsdk_command_port_login_request_frame,
        hcnetsdk_command_port_password_digest,
        hcnetsdk_command_port_play_login_body_tail_for_today,
        hcnetsdk_command_port_public_key_der,
        hcnetsdk_command_port_response_payload,
        hcnetsdk_command_port_rsa_key,
        hcnetsdk_device_ability_command_port_body_tail,
        hcnetsdk_device_ability_command_port_template,
        hcnetsdk_device_ability_request,
        hcnetsdk_device_ability_xml,
        hcnetsdk_dvr_config_command_port_body_tail,
        hcnetsdk_dvr_config_command_port_template,
        hcnetsdk_dvr_config_get_request,
        hcnetsdk_dvr_config_set_request,
        hcnetsdk_file_search_condition,
        hcnetsdk_find_close_v30_request,
        hcnetsdk_find_file_v30_request,
        hcnetsdk_find_next_file_status,
        hcnetsdk_find_next_file_v30_request,
        hcnetsdk_get_device_ability_command_port,
        hcnetsdk_get_download_pos_request,
        hcnetsdk_get_dvr_config_command_port,
        hcnetsdk_get_error_msg_request,
        hcnetsdk_get_file_by_name_request,
        hcnetsdk_get_file_by_time_request,
        hcnetsdk_get_last_error_request,
        hcnetsdk_get_sdk_build_version_request,
        hcnetsdk_get_sdk_version_request,
        hcnetsdk_init_request,
        hcnetsdk_logout_v30_request,
        hcnetsdk_media_packet_source,
        hcnetsdk_playback_by_time_v40_request,
        hcnetsdk_playback_capture_file_request,
        hcnetsdk_playback_condition,
        hcnetsdk_playback_control_v40_request,
        hcnetsdk_real_data_to_media_packet,
        hcnetsdk_real_data_type_is_media,
        hcnetsdk_real_play_request,
        hcnetsdk_set_connect_time_request,
        hcnetsdk_set_play_data_callback_request,
        hcnetsdk_set_play_data_callback_v40_request,
        hcnetsdk_set_playback_es_callback_request,
        hcnetsdk_set_playback_response_callback_request,
        hcnetsdk_set_playback_secret_key_request,
        hcnetsdk_set_sdk_local_cfg_request,
        hcnetsdk_setup_alarm_v30_request,
        hcnetsdk_setup_alarm_v41_request,
        hcnetsdk_stdxml_config_command_port,
        hcnetsdk_stdxml_config_command_port_body_tail,
        hcnetsdk_stdxml_config_command_port_from_trace,
        hcnetsdk_stdxml_config_command_port_template,
        hcnetsdk_stdxml_config_request,
        hcnetsdk_stdxml_isapi_command_port,
        hcnetsdk_stdxml_isapi_request,
        hcnetsdk_stdxml_response_json,
        hcnetsdk_stop_get_file_request,
        hcnetsdk_stop_playback_request,
        hcnetsdk_time,
        hcnetsdk_time_from_datetime,
        hmac,
        ipaddress,
        iter_hcnetsdk_real_data_mpegps,
        iter_hcnetsdk_tcp_frame_shapes,
        json,
        math,
        normalize_hcnetsdk_parameters,
        parse_ezviz_interleaved_rtp_frame_header,
        parse_ezviz_local_device,
        parse_ezviz_local_sdk_frame,
        parse_ezviz_local_sdk_frame_header,
        parse_ezviz_local_sdk_xml_fields,
        parse_hcnetsdk_command_port_login_session,
        parse_hcnetsdk_semantic_log_line,
        parse_hcnetsdk_tcp_frame,
        parse_hcnetsdk_tcp_frame_header,
        parse_hcnetsdk_tcp_shape_log_line,
        parse_sadp_response,
        re,
        read_ezviz_interleaved_rtp_frame,
        read_ezviz_interleaved_rtp_frame_after_prefix,
        read_ezviz_local_sdk_frame,
        read_hcnetsdk_command_port_interleaved_frame_after_prefix,
        read_hcnetsdk_tcp_frame,
        replace,
        sadp_activate_device_request,
        sadp_clearup_request,
        sadp_device_net_param,
        sadp_get_last_error_request,
        sadp_get_sadp_version_request,
        sadp_modify_device_net_param_request,
        sadp_modify_device_net_param_v40_request,
        sadp_send_inquiry_request,
        sadp_set_log_to_file_request,
        sadp_start_v30_request,
        sadp_start_v40_request,
        sadp_stop_request,
        select,
        socket,
        ssl,
        stream_header_from_preview,
        summarize_hcnetsdk_command_trace,
        suppress,
        sys,
        time,
    )

sys.modules[__name__] = _implementation
