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
from contextlib import closing, suppress
from dataclasses import replace
from datetime import date, datetime
from enum import IntEnum
import errno
import hashlib
import hmac
import ipaddress
import json
import math
import re
import select
import socket
import ssl
import sys
from threading import Lock
import time
from typing import Any, cast
import xml.etree.ElementTree as ET

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence

from pyezvizapi import _hcnetsdk_protocol
from pyezvizapi import _resolver
from pyezvizapi._resolver import DEFAULT_RESOLVER, BoundedResolver, ResolverBusy
from pyezvizapi.exceptions import DeviceException, EzvizLocalSdkDeadlineExpired, EzvizLocalSdkStreamClosed, PyEzvizError
from pyezvizapi.media import IterableMediaPacketSource, MediaPacket, MediaPacketMetadata

# Explicit aliases retain historical public/private module attributes.
_AES_RCON = _hcnetsdk_protocol._AES_RCON  # noqa: SLF001 -- compatibility alias
_AES_SBOX = _hcnetsdk_protocol._AES_SBOX  # noqa: SLF001 -- compatibility alias
EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE = _hcnetsdk_protocol.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
EZVIZ_HCNETUTIL_LOGIN_V40 = _hcnetsdk_protocol.EZVIZ_HCNETUTIL_LOGIN_V40
EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF = _hcnetsdk_protocol.EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF
EZVIZ_LAN_MAIN_VIDEO_LEVEL = _hcnetsdk_protocol.EZVIZ_LAN_MAIN_VIDEO_LEVEL
EZVIZ_LAN_PTZ_SPEED_DEFAULT = _hcnetsdk_protocol.EZVIZ_LAN_PTZ_SPEED_DEFAULT
EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE = _hcnetsdk_protocol.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
EZVIZ_NATIVE_CREATE_CLIENT = _hcnetsdk_protocol.EZVIZ_NATIVE_CREATE_CLIENT
EZVIZ_NATIVE_START_PREVIEW = _hcnetsdk_protocol.EZVIZ_NATIVE_START_PREVIEW
EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE = _hcnetsdk_protocol.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
EZVIZ_PLAYER_EXTRA_CHANNEL_NO = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_CHANNEL_NO
EZVIZ_PLAYER_EXTRA_DEVICE_ID = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_DEVICE_ID
EZVIZ_PLAYER_EXTRA_LAN_FLAG = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_LAN_FLAG
EZVIZ_PLAYER_EXTRA_LAN_USERID = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_LAN_USERID
EZVIZ_PLAYER_EXTRA_WIFI_SSID = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_WIFI_SSID
EZVIZ_PLAYER_LAN_FLAG_HCNETSDK = _hcnetsdk_protocol.EZVIZ_PLAYER_LAN_FLAG_HCNETSDK
EZVIZ_PREPLAY_SPS_TYPE = _hcnetsdk_protocol.EZVIZ_PREPLAY_SPS_TYPE
EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY = _hcnetsdk_protocol.EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY
EZVIZ_STREAM_INHIBIT_LAN = _hcnetsdk_protocol.EZVIZ_STREAM_INHIBIT_LAN
EZVIZ_STREAM_SOURCE_LIVE_MINE = _hcnetsdk_protocol.EZVIZ_STREAM_SOURCE_LIVE_MINE
EZVIZ_STREAM_TIMEOUT_MS = _hcnetsdk_protocol.EZVIZ_STREAM_TIMEOUT_MS
HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET
HCNETSDK_CLEANUP = _hcnetsdk_protocol.HCNETSDK_CLEANUP
HCNETSDK_CLOSE_ALARM_CHAN_V30 = _hcnetsdk_protocol.HCNETSDK_CLOSE_ALARM_CHAN_V30
HCNETSDK_CLOSE_FORMAT_HANDLE = _hcnetsdk_protocol.HCNETSDK_CLOSE_FORMAT_HANDLE
HCNETSDK_COMMAND_CANDIDATE_CONTROL = _hcnetsdk_protocol.HCNETSDK_COMMAND_CANDIDATE_CONTROL
HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN = _hcnetsdk_protocol.HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN
HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH
HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
HCNETSDK_COMMAND_PORT_CONTROL_FAMILY = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET
HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET
HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET
HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET
HCNETSDK_COMPRESSION_INFO_V30_SIZE = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_INFO_V30_SIZE
HCNETSDK_DEFAULT_RTSP_PORT = _hcnetsdk_protocol.HCNETSDK_DEFAULT_RTSP_PORT
HCNETSDK_DEFAULT_SERVER_PORT = _hcnetsdk_protocol.HCNETSDK_DEFAULT_SERVER_PORT
HCNETSDK_DEFAULT_TLS_PORT = _hcnetsdk_protocol.HCNETSDK_DEFAULT_TLS_PORT
HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR
HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
HCNETSDK_FILECOND_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_FILECOND_FIELD_ORDER
HCNETSDK_FIND_CLOSE_V30 = _hcnetsdk_protocol.HCNETSDK_FIND_CLOSE_V30
HCNETSDK_FIND_FILE_FAILED = _hcnetsdk_protocol.HCNETSDK_FIND_FILE_FAILED
HCNETSDK_FIND_FILE_V30 = _hcnetsdk_protocol.HCNETSDK_FIND_FILE_V30
HCNETSDK_FIND_NEXT_FILE_V30 = _hcnetsdk_protocol.HCNETSDK_FIND_NEXT_FILE_V30
HCNETSDK_FINDDATA_V30_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_FINDDATA_V30_FIELD_ORDER
HCNETSDK_FORMAT_DISK = _hcnetsdk_protocol.HCNETSDK_FORMAT_DISK
HCNETSDK_GET_DEVICE_ABILITY = _hcnetsdk_protocol.HCNETSDK_GET_DEVICE_ABILITY
HCNETSDK_GET_DOWNLOAD_POS = _hcnetsdk_protocol.HCNETSDK_GET_DOWNLOAD_POS
HCNETSDK_GET_DVR_CONFIG = _hcnetsdk_protocol.HCNETSDK_GET_DVR_CONFIG
HCNETSDK_GET_ERROR_MSG = _hcnetsdk_protocol.HCNETSDK_GET_ERROR_MSG
HCNETSDK_GET_FILE_BY_NAME = _hcnetsdk_protocol.HCNETSDK_GET_FILE_BY_NAME
HCNETSDK_GET_FILE_BY_TIME = _hcnetsdk_protocol.HCNETSDK_GET_FILE_BY_TIME
HCNETSDK_GET_FILE_FAILED = _hcnetsdk_protocol.HCNETSDK_GET_FILE_FAILED
HCNETSDK_GET_FORMAT_PROGRESS = _hcnetsdk_protocol.HCNETSDK_GET_FORMAT_PROGRESS
HCNETSDK_GET_LAST_ERROR = _hcnetsdk_protocol.HCNETSDK_GET_LAST_ERROR
HCNETSDK_GET_SDK_BUILD_VERSION = _hcnetsdk_protocol.HCNETSDK_GET_SDK_BUILD_VERSION
HCNETSDK_GET_SDK_VERSION = _hcnetsdk_protocol.HCNETSDK_GET_SDK_VERSION
HCNETSDK_HIK_PRIVATE_PREFIX = _hcnetsdk_protocol.HCNETSDK_HIK_PRIVATE_PREFIX
HCNETSDK_HKMI_PREFIX = _hcnetsdk_protocol.HCNETSDK_HKMI_PREFIX
HCNETSDK_INIT = _hcnetsdk_protocol.HCNETSDK_INIT
HCNETSDK_LOGOUT_V30 = _hcnetsdk_protocol.HCNETSDK_LOGOUT_V30
HCNETSDK_MAKE_KEYFRAME_MAIN = _hcnetsdk_protocol.HCNETSDK_MAKE_KEYFRAME_MAIN
HCNETSDK_MAKE_KEYFRAME_SUB = _hcnetsdk_protocol.HCNETSDK_MAKE_KEYFRAME_SUB
HCNETSDK_MPEG_PS_PACK_HEADER = _hcnetsdk_protocol.HCNETSDK_MPEG_PS_PACK_HEADER
HCNETSDK_MPEG_START_CODE_PREFIX = _hcnetsdk_protocol.HCNETSDK_MPEG_START_CODE_PREFIX
HCNETSDK_MPEG_TS_SYNC_BYTE = _hcnetsdk_protocol.HCNETSDK_MPEG_TS_SYNC_BYTE
HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET
HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET
HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET
HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET
HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET
HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET
HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET
HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET
HCNETSDK_PLAYBACK_BY_TIME_V40 = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_BY_TIME_V40
HCNETSDK_PLAYBACK_CAPTURE_FILE = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_CAPTURE_FILE
HCNETSDK_PLAYBACK_CONTROL_V40 = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_CONTROL_V40
HCNETSDK_PLAYBACK_FAILED = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_FAILED
HCNETSDK_PLAYBACK_FILE_TYPE_ALL = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_FILE_TYPE_ALL
HCNETSDK_PLAYBACK_LOCK_STATE_ALL = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_LOCK_STATE_ALL
HCNETSDK_PLAYCOND_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_PLAYCOND_FIELD_ORDER
HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER = _hcnetsdk_protocol.HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER
HCNETSDK_PTZ_PRESET_OTHER = _hcnetsdk_protocol.HCNETSDK_PTZ_PRESET_OTHER
HCNETSDK_REALDATA_CALLBACK_V30 = _hcnetsdk_protocol.HCNETSDK_REALDATA_CALLBACK_V30
HCNETSDK_REALPLAY_V30 = _hcnetsdk_protocol.HCNETSDK_REALPLAY_V30
HCNETSDK_SECRET_KEY_TYPE_AES = _hcnetsdk_protocol.HCNETSDK_SECRET_KEY_TYPE_AES
HCNETSDK_SET_CONNECT_TIME = _hcnetsdk_protocol.HCNETSDK_SET_CONNECT_TIME
HCNETSDK_SET_DVR_CONFIG = _hcnetsdk_protocol.HCNETSDK_SET_DVR_CONFIG
HCNETSDK_SET_PLAY_DATA_CALLBACK = _hcnetsdk_protocol.HCNETSDK_SET_PLAY_DATA_CALLBACK
HCNETSDK_SET_PLAY_DATA_CALLBACK_V40 = _hcnetsdk_protocol.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40
HCNETSDK_SET_PLAYBACK_ES_CALLBACK = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_ES_CALLBACK
HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK
HCNETSDK_SET_PLAYBACK_SECRET_KEY = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_SECRET_KEY
HCNETSDK_SET_SDK_LOCAL_CFG = _hcnetsdk_protocol.HCNETSDK_SET_SDK_LOCAL_CFG
HCNETSDK_SETUP_ALARM_CHAN_V30 = _hcnetsdk_protocol.HCNETSDK_SETUP_ALARM_CHAN_V30
HCNETSDK_SETUP_ALARM_CHAN_V41 = _hcnetsdk_protocol.HCNETSDK_SETUP_ALARM_CHAN_V41
HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER
HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE = _hcnetsdk_protocol.HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE = _hcnetsdk_protocol.HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE = _hcnetsdk_protocol.HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE
HCNETSDK_STDXML_INPUT_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_STDXML_INPUT_FIELD_ORDER
HCNETSDK_STDXML_OUTPUT_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_STDXML_OUTPUT_FIELD_ORDER
HCNETSDK_STOP_GET_FILE = _hcnetsdk_protocol.HCNETSDK_STOP_GET_FILE
HCNETSDK_STOP_PLAYBACK = _hcnetsdk_protocol.HCNETSDK_STOP_PLAYBACK
HCNETSDK_TCP_HEADER_LENGTH = _hcnetsdk_protocol.HCNETSDK_TCP_HEADER_LENGTH
HCNETSDK_TIME_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_TIME_FIELD_ORDER
HCNETSDK_XML_MARKER = _hcnetsdk_protocol.HCNETSDK_XML_MARKER
SADP_ACTIVATE_DEVICE = _hcnetsdk_protocol.SADP_ACTIVATE_DEVICE
SADP_CLEARUP = _hcnetsdk_protocol.SADP_CLEARUP
SADP_DEV_NET_PARAM_ANDROID_FIELDS = _hcnetsdk_protocol.SADP_DEV_NET_PARAM_ANDROID_FIELDS
SADP_DEV_NET_PARAM_JNA_FIELD_ORDER = _hcnetsdk_protocol.SADP_DEV_NET_PARAM_JNA_FIELD_ORDER
SADP_DEV_RET_NET_PARAM_BUFFER_SIZE = _hcnetsdk_protocol.SADP_DEV_RET_NET_PARAM_BUFFER_SIZE
SADP_DEV_RET_NET_PARAM_FIELD_ORDER = _hcnetsdk_protocol.SADP_DEV_RET_NET_PARAM_FIELD_ORDER
SADP_GET_LAST_ERROR = _hcnetsdk_protocol.SADP_GET_LAST_ERROR
SADP_GET_VERSION = _hcnetsdk_protocol.SADP_GET_VERSION
SADP_MODIFY_DEVICE_NET_PARAM = _hcnetsdk_protocol.SADP_MODIFY_DEVICE_NET_PARAM
SADP_MODIFY_DEVICE_NET_PARAM_V40 = _hcnetsdk_protocol.SADP_MODIFY_DEVICE_NET_PARAM_V40
SADP_NUL_BYTE = _hcnetsdk_protocol.SADP_NUL_BYTE
SADP_SEND_INQUIRY = _hcnetsdk_protocol.SADP_SEND_INQUIRY
SADP_SET_LOG_TO_FILE = _hcnetsdk_protocol.SADP_SET_LOG_TO_FILE
SADP_START_V30 = _hcnetsdk_protocol.SADP_START_V30
SADP_START_V40 = _hcnetsdk_protocol.SADP_START_V40
SADP_STOP = _hcnetsdk_protocol.SADP_STOP
EzvizCasDeviceInfo = _hcnetsdk_protocol.EzvizCasDeviceInfo
EzvizInterleavedRtpFrame = _hcnetsdk_protocol.EzvizInterleavedRtpFrame
EzvizInterleavedRtpFrameHeader = _hcnetsdk_protocol.EzvizInterleavedRtpFrameHeader
EzvizInterleavedRtpFrameWithPrefix = _hcnetsdk_protocol.EzvizInterleavedRtpFrameWithPrefix
EzvizLanAccessProtocolAbility = _hcnetsdk_protocol.EzvizLanAccessProtocolAbility
EzvizLanAudioInputParam = _hcnetsdk_protocol.EzvizLanAudioInputParam
EzvizLanAudioOutputVolume = _hcnetsdk_protocol.EzvizLanAudioOutputVolume
EzvizLanAudioVideoCompressAudioChannel = _hcnetsdk_protocol.EzvizLanAudioVideoCompressAudioChannel
EzvizLanAudioVideoCompressInfo = _hcnetsdk_protocol.EzvizLanAudioVideoCompressInfo
EzvizLanAudioVideoCompressStream = _hcnetsdk_protocol.EzvizLanAudioVideoCompressStream
EzvizLanAudioVideoCompressVideoChannel = _hcnetsdk_protocol.EzvizLanAudioVideoCompressVideoChannel
EzvizLanAudioVideoCompressVoiceTalkChannel = _hcnetsdk_protocol.EzvizLanAudioVideoCompressVoiceTalkChannel
EzvizLanCameraParamConfig = _hcnetsdk_protocol.EzvizLanCameraParamConfig
EzvizLanCompressionConfig = _hcnetsdk_protocol.EzvizLanCompressionConfig
EzvizLanCompressionInfoV30 = _hcnetsdk_protocol.EzvizLanCompressionInfoV30
EzvizLanDeviceConfigV40 = _hcnetsdk_protocol.EzvizLanDeviceConfigV40
EzvizLanDeviceSoftHardwareAbility = _hcnetsdk_protocol.EzvizLanDeviceSoftHardwareAbility
EzvizLanDvrConfigSummary = _hcnetsdk_protocol.EzvizLanDvrConfigSummary
EzvizLanEzvizAccessConfig = _hcnetsdk_protocol.EzvizLanEzvizAccessConfig
EzvizLanHdConfig = _hcnetsdk_protocol.EzvizLanHdConfig
EzvizLanHdDiskConfig = _hcnetsdk_protocol.EzvizLanHdDiskConfig
EzvizLanIpcFrontParameterAbility = _hcnetsdk_protocol.EzvizLanIpcFrontParameterAbility
EzvizLanIpcFrontParameterRange = _hcnetsdk_protocol.EzvizLanIpcFrontParameterRange
EzvizLanKeyframeRequest = _hcnetsdk_protocol.EzvizLanKeyframeRequest
EzvizLanLiveViewParams = _hcnetsdk_protocol.EzvizLanLiveViewParams
EzvizLanNetConfigV30 = _hcnetsdk_protocol.EzvizLanNetConfigV30
EzvizLanNetInterfaceConfig = _hcnetsdk_protocol.EzvizLanNetInterfaceConfig
EzvizLanNtpConfig = _hcnetsdk_protocol.EzvizLanNtpConfig
EzvizLanPictureConfig = _hcnetsdk_protocol.EzvizLanPictureConfig
EzvizLanPlaybackConvertAbility = _hcnetsdk_protocol.EzvizLanPlaybackConvertAbility
EzvizLanPlaybackConvertResolution = _hcnetsdk_protocol.EzvizLanPlaybackConvertResolution
EzvizLanPlaybackIntent = _hcnetsdk_protocol.EzvizLanPlaybackIntent
EzvizLanPlaybackPath = _hcnetsdk_protocol.EzvizLanPlaybackPath
EzvizLanPlayDeviceLogin = _hcnetsdk_protocol.EzvizLanPlayDeviceLogin
EzvizLanPreviewPlan = _hcnetsdk_protocol.EzvizLanPreviewPlan
EzvizLanPtzAbility = _hcnetsdk_protocol.EzvizLanPtzAbility
EzvizLanRecordConfigV30 = _hcnetsdk_protocol.EzvizLanRecordConfigV30
EzvizLanRecordDayConfig = _hcnetsdk_protocol.EzvizLanRecordDayConfig
EzvizLanRecordScheduleSegment = _hcnetsdk_protocol.EzvizLanRecordScheduleSegment
EzvizLanSdFormatProgress = _hcnetsdk_protocol.EzvizLanSdFormatProgress
EzvizLanServicesSwitchState = _hcnetsdk_protocol.EzvizLanServicesSwitchState
EzvizLanUserConfigV30 = _hcnetsdk_protocol.EzvizLanUserConfigV30
EzvizLanUserConfigV30Entry = _hcnetsdk_protocol.EzvizLanUserConfigV30Entry
EzvizLanVideoPicAbility = _hcnetsdk_protocol.EzvizLanVideoPicAbility
EzvizLanVideoQuality = _hcnetsdk_protocol.EzvizLanVideoQuality
EzvizLanVideoResolution = _hcnetsdk_protocol.EzvizLanVideoResolution
EzvizLanWifiApInfo = _hcnetsdk_protocol.EzvizLanWifiApInfo
EzvizLanWifiConnectStatus = _hcnetsdk_protocol.EzvizLanWifiConnectStatus
EzvizLocalAuthenticationAttrs = _hcnetsdk_protocol.EzvizLocalAuthenticationAttrs
EzvizLocalDevice = _hcnetsdk_protocol.EzvizLocalDevice
EzvizLocalDeviceContent = _hcnetsdk_protocol.EzvizLocalDeviceContent
EzvizLocalPreviewRequest = _hcnetsdk_protocol.EzvizLocalPreviewRequest
EzvizLocalReceiverInfo = _hcnetsdk_protocol.EzvizLocalReceiverInfo
EzvizLocalReceiverInfoAttrs = _hcnetsdk_protocol.EzvizLocalReceiverInfoAttrs
EzvizLocalReceiverInfoEx = _hcnetsdk_protocol.EzvizLocalReceiverInfoEx
EzvizLocalReceiverInfoExAttrs = _hcnetsdk_protocol.EzvizLocalReceiverInfoExAttrs
EzvizLocalSdkBodyShape = _hcnetsdk_protocol.EzvizLocalSdkBodyShape
EzvizLocalSdkExchange = _hcnetsdk_protocol.EzvizLocalSdkExchange
EzvizLocalSdkFrame = _hcnetsdk_protocol.EzvizLocalSdkFrame
EzvizLocalSdkFrameHeader = _hcnetsdk_protocol.EzvizLocalSdkFrameHeader
EzvizLocalSdkStreamBootstrap = _hcnetsdk_protocol.EzvizLocalSdkStreamBootstrap
HcNetSdkClientInfo = _hcnetsdk_protocol.HcNetSdkClientInfo
HcNetSdkCloseAlarmRequest = _hcnetsdk_protocol.HcNetSdkCloseAlarmRequest
HcNetSdkCloseFormatHandleRequest = _hcnetsdk_protocol.HcNetSdkCloseFormatHandleRequest
HcNetSdkCommandPortControlResponse = _hcnetsdk_protocol.HcNetSdkCommandPortControlResponse
HcNetSdkCommandPortControlTemplate = _hcnetsdk_protocol.HcNetSdkCommandPortControlTemplate
HcNetSdkCommandPortExchange = _hcnetsdk_protocol.HcNetSdkCommandPortExchange
HcNetSdkCommandPortLoginChallenge = _hcnetsdk_protocol.HcNetSdkCommandPortLoginChallenge
HcNetSdkCommandPortLoginSession = _hcnetsdk_protocol.HcNetSdkCommandPortLoginSession
HcNetSdkCommandPortStreamBootstrap = _hcnetsdk_protocol.HcNetSdkCommandPortStreamBootstrap
HcNetSdkCommandTraceSummary = _hcnetsdk_protocol.HcNetSdkCommandTraceSummary
HcNetSdkDeviceAbilityRequest = _hcnetsdk_protocol.HcNetSdkDeviceAbilityRequest
HcNetSdkDvrConfigRequest = _hcnetsdk_protocol.HcNetSdkDvrConfigRequest
HcNetSdkFileCond = _hcnetsdk_protocol.HcNetSdkFileCond
HcNetSdkFindCloseRequest = _hcnetsdk_protocol.HcNetSdkFindCloseRequest
HcNetSdkFindDataV30 = _hcnetsdk_protocol.HcNetSdkFindDataV30
HcNetSdkFindFileRequest = _hcnetsdk_protocol.HcNetSdkFindFileRequest
HcNetSdkFindNextFileRequest = _hcnetsdk_protocol.HcNetSdkFindNextFileRequest
HcNetSdkFormatDiskRequest = _hcnetsdk_protocol.HcNetSdkFormatDiskRequest
HcNetSdkFormatProgressRequest = _hcnetsdk_protocol.HcNetSdkFormatProgressRequest
HcNetSdkGetDownloadPosRequest = _hcnetsdk_protocol.HcNetSdkGetDownloadPosRequest
HcNetSdkGetErrorMsgRequest = _hcnetsdk_protocol.HcNetSdkGetErrorMsgRequest
HcNetSdkGetFileByNameRequest = _hcnetsdk_protocol.HcNetSdkGetFileByNameRequest
HcNetSdkGetFileByTimeRequest = _hcnetsdk_protocol.HcNetSdkGetFileByTimeRequest
HcNetSdkInitRequest = _hcnetsdk_protocol.HcNetSdkInitRequest
HcNetSdkLanEndpoint = _hcnetsdk_protocol.HcNetSdkLanEndpoint
HcNetSdkLoginCandidate = _hcnetsdk_protocol.HcNetSdkLoginCandidate
HcNetSdkLogoutRequest = _hcnetsdk_protocol.HcNetSdkLogoutRequest
HcNetSdkNoArgRequest = _hcnetsdk_protocol.HcNetSdkNoArgRequest
HcNetSdkPlayBackByTimeRequest = _hcnetsdk_protocol.HcNetSdkPlayBackByTimeRequest
HcNetSdkPlaybackCallbackRequest = _hcnetsdk_protocol.HcNetSdkPlaybackCallbackRequest
HcNetSdkPlayBackCaptureFileRequest = _hcnetsdk_protocol.HcNetSdkPlayBackCaptureFileRequest
HcNetSdkPlayBackControlRequest = _hcnetsdk_protocol.HcNetSdkPlayBackControlRequest
HcNetSdkPlayBackSecretKeyRequest = _hcnetsdk_protocol.HcNetSdkPlayBackSecretKeyRequest
HcNetSdkPlayCond = _hcnetsdk_protocol.HcNetSdkPlayCond
HcNetSdkPlayDataCallbackRequest = _hcnetsdk_protocol.HcNetSdkPlayDataCallbackRequest
HcNetSdkPortProbe = _hcnetsdk_protocol.HcNetSdkPortProbe
HcNetSdkPtzControlRequest = _hcnetsdk_protocol.HcNetSdkPtzControlRequest
HcNetSdkPtzPresetRequest = _hcnetsdk_protocol.HcNetSdkPtzPresetRequest
HcNetSdkRealDataPacket = _hcnetsdk_protocol.HcNetSdkRealDataPacket
HcNetSdkRealDataType = _hcnetsdk_protocol.HcNetSdkRealDataType
HcNetSdkRealPlayRequest = _hcnetsdk_protocol.HcNetSdkRealPlayRequest
HcNetSdkSemanticLogEvent = _hcnetsdk_protocol.HcNetSdkSemanticLogEvent
HcNetSdkSetConnectTimeRequest = _hcnetsdk_protocol.HcNetSdkSetConnectTimeRequest
HcNetSdkSetSdkLocalCfgRequest = _hcnetsdk_protocol.HcNetSdkSetSdkLocalCfgRequest
HcNetSdkSetupAlarmParam = _hcnetsdk_protocol.HcNetSdkSetupAlarmParam
HcNetSdkSetupAlarmRequest = _hcnetsdk_protocol.HcNetSdkSetupAlarmRequest
HcNetSdkStdXmlConfigRequest = _hcnetsdk_protocol.HcNetSdkStdXmlConfigRequest
HcNetSdkStdXmlConfigResponse = _hcnetsdk_protocol.HcNetSdkStdXmlConfigResponse
HcNetSdkStopGetFileRequest = _hcnetsdk_protocol.HcNetSdkStopGetFileRequest
HcNetSdkStopPlayBackRequest = _hcnetsdk_protocol.HcNetSdkStopPlayBackRequest
HcNetSdkStreamDetails = _hcnetsdk_protocol.HcNetSdkStreamDetails
HcNetSdkTcpFrame = _hcnetsdk_protocol.HcNetSdkTcpFrame
HcNetSdkTcpFrameHeader = _hcnetsdk_protocol.HcNetSdkTcpFrameHeader
HcNetSdkTcpFrameShape = _hcnetsdk_protocol.HcNetSdkTcpFrameShape
HcNetSdkTcpPayloadShape = _hcnetsdk_protocol.HcNetSdkTcpPayloadShape
HcNetSdkTcpShapeLogRecord = _hcnetsdk_protocol.HcNetSdkTcpShapeLogRecord
HcNetSdkTime = _hcnetsdk_protocol.HcNetSdkTime
SadpActivateDeviceRequest = _hcnetsdk_protocol.SadpActivateDeviceRequest
SadpBatchResult = _hcnetsdk_protocol.SadpBatchResult
SadpDeviceInfo = _hcnetsdk_protocol.SadpDeviceInfo
SadpDeviceNetParam = _hcnetsdk_protocol.SadpDeviceNetParam
SadpDeviceRetNetParam = _hcnetsdk_protocol.SadpDeviceRetNetParam
SadpModifyDeviceNetParamRequest = _hcnetsdk_protocol.SadpModifyDeviceNetParamRequest
SadpModifyDeviceNetParamV40Request = _hcnetsdk_protocol.SadpModifyDeviceNetParamV40Request
SadpNoArgRequest = _hcnetsdk_protocol.SadpNoArgRequest
SadpSetLogToFileRequest = _hcnetsdk_protocol.SadpSetLogToFileRequest
SadpStartRequest = _hcnetsdk_protocol.SadpStartRequest
_ability_option_tuple = _hcnetsdk_protocol._ability_option_tuple  # noqa: SLF001 -- compatibility alias
_bounded_bytes = _hcnetsdk_protocol._bounded_bytes  # noqa: SLF001 -- compatibility alias
_build_local_sdk_request_xml = _hcnetsdk_protocol._build_local_sdk_request_xml  # noqa: SLF001 -- compatibility alias
_byte_value = _hcnetsdk_protocol._byte_value  # noqa: SLF001 -- compatibility alias
_device_ability_bytes = _hcnetsdk_protocol._device_ability_bytes  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes128_round_keys = _hcnetsdk_protocol._hcnetsdk_aes128_round_keys  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes_add_round_key = _hcnetsdk_protocol._hcnetsdk_aes_add_round_key  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes_mix_columns = _hcnetsdk_protocol._hcnetsdk_aes_mix_columns  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes_shift_rows = _hcnetsdk_protocol._hcnetsdk_aes_shift_rows  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes_sub_bytes = _hcnetsdk_protocol._hcnetsdk_aes_sub_bytes  # noqa: SLF001 -- compatibility alias
_hcnetsdk_aes_xtime = _hcnetsdk_protocol._hcnetsdk_aes_xtime  # noqa: SLF001 -- compatibility alias
_hcnetsdk_command_port_auth_mask = _hcnetsdk_protocol._hcnetsdk_command_port_auth_mask  # noqa: SLF001 -- compatibility alias
_hcnetsdk_command_port_four_round_aes = _hcnetsdk_protocol._hcnetsdk_command_port_four_round_aes  # noqa: SLF001 -- compatibility alias
_hcnetsdk_command_port_local_ip_word = _hcnetsdk_protocol._hcnetsdk_command_port_local_ip_word  # noqa: SLF001 -- compatibility alias
_hcnetsdk_compression_info_v30 = _hcnetsdk_protocol._hcnetsdk_compression_info_v30  # noqa: SLF001 -- compatibility alias
_local_sdk_aes_bytes = _hcnetsdk_protocol._local_sdk_aes_bytes  # noqa: SLF001 -- compatibility alias
_mapping_int = _hcnetsdk_protocol._mapping_int  # noqa: SLF001 -- compatibility alias
_mapping_str = _hcnetsdk_protocol._mapping_str  # noqa: SLF001 -- compatibility alias
_native_path_value = _hcnetsdk_protocol._native_path_value  # noqa: SLF001 -- compatibility alias
_native_secret_key_bytes = _hcnetsdk_protocol._native_secret_key_bytes  # noqa: SLF001 -- compatibility alias
_nul_stripped_text = _hcnetsdk_protocol._nul_stripped_text  # noqa: SLF001 -- compatibility alias
_optional_native_bytes = _hcnetsdk_protocol._optional_native_bytes  # noqa: SLF001 -- compatibility alias
_optional_raw_byte = _hcnetsdk_protocol._optional_raw_byte  # noqa: SLF001 -- compatibility alias
_optional_raw_byte_triplet = _hcnetsdk_protocol._optional_raw_byte_triplet  # noqa: SLF001 -- compatibility alias
_optional_raw_u16_be = _hcnetsdk_protocol._optional_raw_u16_be  # noqa: SLF001 -- compatibility alias
_optional_raw_u16_be_pair = _hcnetsdk_protocol._optional_raw_u16_be_pair  # noqa: SLF001 -- compatibility alias
_optional_raw_u32_be = _hcnetsdk_protocol._optional_raw_u32_be  # noqa: SLF001 -- compatibility alias
_port_value = _hcnetsdk_protocol._port_value  # noqa: SLF001 -- compatibility alias
_sadp_string_bytes = _hcnetsdk_protocol._sadp_string_bytes  # noqa: SLF001 -- compatibility alias
_stdxml_bytes = _hcnetsdk_protocol._stdxml_bytes  # noqa: SLF001 -- compatibility alias
_word_value = _hcnetsdk_protocol._word_value  # noqa: SLF001 -- compatibility alias
_xml_attrs = _hcnetsdk_protocol._xml_attrs  # noqa: SLF001 -- compatibility alias
_xml_escape = _hcnetsdk_protocol._xml_escape  # noqa: SLF001 -- compatibility alias
build_ezviz_local_preview_request_body = _hcnetsdk_protocol.build_ezviz_local_preview_request_body
build_hcnetsdk_tcp_frame = _hcnetsdk_protocol.build_hcnetsdk_tcp_frame
classify_hcnetsdk_real_data_payload = _hcnetsdk_protocol.classify_hcnetsdk_real_data_payload
ezviz_local_sdk_iv = _hcnetsdk_protocol.ezviz_local_sdk_iv
ezviz_native_video_level = _hcnetsdk_protocol.ezviz_native_video_level
hcnetsdk_command_candidate_role = _hcnetsdk_protocol.hcnetsdk_command_candidate_role
hcnetsdk_command_port_auth_word = _hcnetsdk_protocol.hcnetsdk_command_port_auth_word
hcnetsdk_command_port_control_frame = _hcnetsdk_protocol.hcnetsdk_command_port_control_frame
hcnetsdk_command_port_play_login_body_tail_for_today = _hcnetsdk_protocol.hcnetsdk_command_port_play_login_body_tail_for_today
hcnetsdk_command_port_response_payload = _hcnetsdk_protocol.hcnetsdk_command_port_response_payload
hcnetsdk_real_data_type_is_media = _hcnetsdk_protocol.hcnetsdk_real_data_type_is_media
hcnetsdk_real_play_request = _hcnetsdk_protocol.hcnetsdk_real_play_request
hcnetsdk_stdxml_response_json = _hcnetsdk_protocol.hcnetsdk_stdxml_response_json


# Preserve earlier imported support symbols as well as locally defined SDK values.
Empty = _resolver.Empty
EzvizStreamHeader = _hcnetsdk_protocol.EzvizStreamHeader
Full = _resolver.Full
HcNetSdkConfiguredMedia = _hcnetsdk_protocol.HcNetSdkConfiguredMedia
Queue = _resolver.Queue
Thread = _resolver.Thread
asdict = _hcnetsdk_protocol.asdict
base64 = _hcnetsdk_protocol.base64
binascii = _hcnetsdk_protocol.binascii
dataclass = _hcnetsdk_protocol.dataclass
field = _hcnetsdk_protocol.field
normalize_hcnetsdk_parameters = _hcnetsdk_protocol.normalize_hcnetsdk_parameters
stream_header_from_preview = _hcnetsdk_protocol.stream_header_from_preview

_WINDOWS_EXCLUSIVE_SOURCE_BIND = sys.platform == "win32"

HCNETSDK_EZVIZ_DEFAULT_USERNAME = "admin"
HCNETSDK_EZVIZ_LOCAL_USERNAME = "EZ_LOCAL_USER"
HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX = "_lan_device_space-"
HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX = "lan_device_space-"
HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID = 0x117000
HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE = 8
HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE = 12
HCNETSDK_STDXML_COMMAND_PORT_FLAGS = b"\x01\x00\x00\x00"
HCNETSDK_EZVIZ_SERVICES_SWITCH_GET = (
    "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
)
HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT = (
    "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
)
HCNETSDK_EZVIZ_CONNECT_MODE_PUT = (
    "PUT /ISAPI/EZVIZ/IPC/System/Network/connectMode?format=json\r\n"
)
HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT = (
    "PUT /ISAPI/EZVIZ/IPC/System/netConfigAndVoiceFileUpload?format=json\r\n"
)
HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE = 0x50910
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR = 0x50911
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR = 0x50D5C
HCNETSDK_LOGIN_V40 = "NET_DVR_Login_V40"
HCNETSDK_STDXML_CONFIG = "NET_DVR_STDXMLConfig"
HCNETSDK_FIND_NEXT_FILE_SUCCESS = 1000
HCNETSDK_FIND_NEXT_FILE_NO_FILE = 1001
HCNETSDK_FIND_NEXT_FILE_IS_FINDING = 1002
HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE = 1003
HCNETSDK_FIND_NEXT_FILE_EXCEPTION = 1004
HCNETSDK_PLAYSTART = 1
HCNETSDK_PLAYPAUSE = 3
HCNETSDK_PLAYRESTART = 4
HCNETSDK_PLAYFAST = 5
HCNETSDK_PLAYSLOW = 6
HCNETSDK_PLAYSTARTAUDIO = 9
HCNETSDK_PLAYSTOPAUDIO = 10
HCNETSDK_PLAYAUDIOVOLUME = 11
HCNETSDK_SET_TRANS_TYPE = 32
HCNETSDK_PLAY_CONVERT = 33
HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER = ("byEnableAbilityParse", "byRes")
HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER = ("byWithoutRecv", "byRes")
HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE = 2_097_152
EZVIZ_PLAYER_LAN_FLAG_EZLINK = 2
EZVIZ_LAN_MAIN_STREAM_TYPE = 1
EZVIZ_LAN_SUB_STREAM_TYPE = 2
EZVIZ_LAN_SUB_VIDEO_LEVEL = 0
EZVIZ_LAN_PTZ_ACTION_START = 10
EZVIZ_LAN_PTZ_ACTION_STOP = 11
EZVIZ_LAN_PTZ_ACTION_RESET = 101
EZVIZ_LOCAL_SDK_MAGIC = b"\x9e\xba\xac\xe9"
EZVIZ_LOCAL_SDK_HEADER_LENGTH = 32
EZVIZ_RTP_INTERLEAVED_MAGIC = 0x24
EZVIZ_XML_DETECT_PREFIX_LIMIT = 64
EZVIZ_XML_START_BYTE = b"<"
EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD = 0.25
EZVIZ_BODY_PRINTABLE_THRESHOLD = 0.75
EZVIZ_LOCAL_SDK_SSL_IV_PREFIX = b"01234567"
EZVIZ_LOCAL_SDK_PRE_START_COMMAND = 0x2013
EZVIZ_LOCAL_SDK_PRE_START_RESPONSE = 0x2014
# Native SendByeStream uses the same envelope ID with an owned Session.
EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND = 0x2013
EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE = 0x2014
EZVIZ_LOCAL_SDK_STOP_TIMEOUT = 2.0
EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES = 4 * 1024 * 1024
EZVIZ_LOCAL_SDK_PREVIEW_COMMAND = 0x2011
EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE = 0x2012
EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND = 0x3105
EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE = 0x3106
EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH = 32
HCNETSDK_TCP_COMMAND_PORTS = (HCNETSDK_DEFAULT_SERVER_PORT, HCNETSDK_DEFAULT_TLS_PORT)
HCNETSDK_COMMAND_PORT_LOGIN_FAMILY = 0x5A000000
HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12 = 0x00010000
HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX = bytes.fromhex("05013d4b00000001")
HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX = bytes.fromhex("0000000000006f00")
HCNETSDK_COMMAND_PORT_USERNAME_LENGTH = 48
HCNETSDK_COMMAND_PORT_RSA_BITS = 1024
HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH = 128
HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH = 64
HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH = 32
HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH = 16
HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID = b"\x00\x00\x00\x00"
EZVIZ_CAS_PTZ_COMMAND_MAP = {
    0: "UP",
    1: "DOWN",
    2: "LEFT",
    3: "RIGHT",
    5: "ZOOMIN",
    6: "ZOOMOUT",
    7: "SET_PRESET",
    8: "CLE_PRESET",
    9: "GOTO_PRESET",
    10: "START",
    11: "STOP",
    12: "CENTER",
    13: "UPLEFT",
    14: "DOWNLEFT",
    15: "UPRIGHT",
    16: "DOWNRIGHT",
}
EZVIZ_LAN_PTZ_COMMAND_MAP = {
    0: 21,
    1: 22,
    2: 23,
    3: 24,
    5: 11,
    6: 12,
    7: 8,
    8: 9,
    9: 39,
    10: 0,
    11: 1,
}
EZVIZ_LAN_PTZ_PRESET_COMMANDS = frozenset({7, 8, 9})
EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP = {
    0x00: 1,
    0x1D: 8,
    0x20: 9,
    0x21: 10,
}


class HcNetSdkDvrCommand(IntEnum):
    """HCNetSDK ``NET_DVR_Get/SetDVRConfig`` command IDs seen in the APK."""

    GET_DEVICE_CFG = 100
    GET_TIME_CFG = 118
    GET_NTP_CFG = 224
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
    GET_DEVICE_CFG_V40 = 1100
    GET_AP_INFO_LIST = 305
    SET_WIFI_CFG = 306
    GET_WIFI_CFG = 307
    GET_WIFI_CONNECT_STATUS = 310
    GET_AUDIO_INPUT_PARAM = 3201
    SET_AUDIO_INPUT_PARAM = 3202
    GET_AUDIOOUT_VOLUME = 3237
    SET_AUDIOOUT_VOLUME = 3238
    GET_EZVIZ_ACCESS_CFG = 3398
    SET_EZVIZ_ACCESS_CFG = 3399
    GET_PIC_CFG_V40 = 6179
    SET_PIC_CFG_V40 = 6180


HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS: Mapping[int, int] = {
    # Native trace: NET_DVR_GetDVRConfig(login, 1054, -1, NET_DVR_HDCFG)
    # dispatches through Core_SimpleCommandToDvr as an empty 0x111050 command.
    HcNetSdkDvrCommand.GET_HD_CFG: 0x111050,
    # Native trace: NET_DVR_GetDVRConfig(login, 305, -1, NET_DVR_AP_INFO_LIST)
    # dispatches as an empty 0x20140 command and returns NET_DVR_AP_INFO_LIST.
    HcNetSdkDvrCommand.GET_AP_INFO_LIST: 0x20140,
    # Native trace: NET_DVR_GetDVRConfig(login, 307, -1, NET_DVR_WIFI_CFG)
    # dispatches as an empty 0x20141 command and returns NET_DVR_WIFI_CFG.
    # This may contain station credentials, so no typed convenience parser is exposed.
    HcNetSdkDvrCommand.GET_WIFI_CFG: 0x20141,
    # Native trace: NET_DVR_GetDVRConfig(login, 1000, -1, NET_DVR_NETCFG_V30)
    # dispatches as an empty 0x110000 command.
    HcNetSdkDvrCommand.GET_NET_CFG: 0x110000,
    # Native trace: NET_DVR_GetDVRConfig(login, 1004, 1, NET_DVR_RECORD_V30)
    # dispatches as 0x110020 with a channel tail.
    HcNetSdkDvrCommand.GET_RECORD_CFG_V30: 0x110020,
    # Native binary dispatch: libHCGeneralCfgMgr ConfigUserCfg and
    # libHCCoreDevCfg DetermineCompatibleInfo carry the GET/SET user-config
    # pair as 0x110030/0x110031. Available live devices rejected the read
    # before returning a body, so parser coverage uses synthetic fixtures.
    HcNetSdkDvrCommand.GET_USER_CFG_V30: 0x110030,
    # Native trace: NET_DVR_GetDVRConfig(login, 118, -1, NET_DVR_TIME)
    # dispatches as an empty 0x20500 command.
    HcNetSdkDvrCommand.GET_TIME_CFG: 0x20500,
    # Native trace: NET_DVR_GetDVRConfig(login, 224, -1, NET_DVR_NTPPARA)
    # dispatches as an empty 0x20112 command.
    HcNetSdkDvrCommand.GET_NTP_CFG: 0x20112,
    # Native trace: NET_DVR_GetDVRConfig(login, 1100, -1, NET_DVR_DEVICECFG_V40)
    # dispatches as an empty 0x1110c2 command.
    HcNetSdkDvrCommand.GET_DEVICE_CFG_V40: 0x1110C2,
    # Native trace: NET_DVR_GetDVRConfig(login, 1067, 1, NET_DVR_CAMERAPARAMCFG)
    # dispatches as an empty 0x111096 command and returns NET_DVR_CAMERAPARAMCFG.
    HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG: 0x111096,
    # Native trace: NET_DVR_GetDVRConfig(login, 310, 0,
    # NET_DVR_WIFI_CONNECT_STATUS) dispatches as 0x20145 with a channel tail.
    HcNetSdkDvrCommand.GET_WIFI_CONNECT_STATUS: 0x20145,
    # Native trace: NET_DVR_GetDVRConfig(login, 3201, 1,
    # NET_DVR_AUDIO_INPUT_PARAM) dispatches as 0x113201 with a channel tail.
    HcNetSdkDvrCommand.GET_AUDIO_INPUT_PARAM: 0x113201,
    # Native trace: NET_DVR_GetDVRConfig(login, 3237, 1,
    # NET_DVR_AUDIOOUT_VOLUME) dispatches as 0x113026 with a channel tail.
    HcNetSdkDvrCommand.GET_AUDIOOUT_VOLUME: 0x113026,
    # Native trace: NET_DVR_GetDVRConfig(login, 1040, 1,
    # NET_DVR_COMPRESSIONCFG_V30) dispatches as 0x110040 with a channel tail.
    HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30: 0x110040,
    # Native sidecar trace: NET_DVR_GetDVRConfig(login, 1002, 1,
    # NET_DVR_PICCFG_V30) dispatches through the same 0x110010 channel-tailed
    # command as the app's V40 picture-config path; some device firmware still
    # rejects the public V30 command while accepting V40.
    HcNetSdkDvrCommand.GET_PIC_CFG_V30: 0x110010,
    # Native trace: NET_DVR_GetDVRConfig(login, 6179, 1, NET_DVR_PICCFG_V40)
    # dispatches as 0x110010 with a channel tail.
    HcNetSdkDvrCommand.GET_PIC_CFG_V40: 0x110010,
    # Native trace: NET_DVR_GetDVRConfig(login, 3398, 1,
    # NET_DVR_EZVIZ_ACCESS_CFG) dispatches as 0x113420. Native app traces carry
    # a volatile 16-byte tail, but pure-Python empty-tail live smoke succeeds.
    # The response may contain access/security config, so no typed parser is exposed.
    HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG: 0x113420,
}

HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS: frozenset[int] = frozenset(
    {
        HcNetSdkDvrCommand.GET_WIFI_CONNECT_STATUS,
        HcNetSdkDvrCommand.GET_AUDIO_INPUT_PARAM,
        HcNetSdkDvrCommand.GET_AUDIOOUT_VOLUME,
        HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30,
        HcNetSdkDvrCommand.GET_PIC_CFG_V30,
        HcNetSdkDvrCommand.GET_PIC_CFG_V40,
        HcNetSdkDvrCommand.GET_RECORD_CFG_V30,
    }
)
HCNETSDK_HD_CFG_MIN_SIZE = 4
HCNETSDK_HD_CFG_HEADER_SIZE = 8
HCNETSDK_HD_CFG_DISK_COUNT = 33
HCNETSDK_HD_CFG_DISK_OFFSET = 8
HCNETSDK_HD_CFG_DISK_SIZE = 144
HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET = 0
HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET = 4
HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET = 8
HCNETSDK_HD_CFG_DISK_STATUS_OFFSET = 12
HCNETSDK_HD_CFG_DISK_ATTR_OFFSET = 16
HCNETSDK_HD_CFG_DISK_TYPE_OFFSET = 17
HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET = 18
HCNETSDK_HD_CFG_DISK_GROUP_OFFSET = 20
HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET = 24
HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET = 28
HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET = 32
HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET = 36
HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE = 8
HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE = 52
HCNETSDK_WIFI_AP_INFO_SSID_SIZE = 36
HCNETSDK_TIME_CFG_SIZE = 24
HCNETSDK_NTP_CFG_SIZE = 80
HCNETSDK_NTP_SERVER_SIZE = 64
HCNETSDK_NTP_INTERVAL_OFFSET = 64
HCNETSDK_NTP_ENABLE_OFFSET = 66
HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET = 67
HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET = 68
HCNETSDK_NTP_PORT_OFFSET = 70
HCNETSDK_NETCFG_V30_MIN_SIZE = 184
HCNETSDK_NETCFG_V30_ETHERNET_COUNT = 2
HCNETSDK_NETCFG_V30_ETHERNET_OFFSET = 4
HCNETSDK_NETCFG_V30_ETHERNET_SIZE = 48
HCNETSDK_NETCFG_V30_IP_SIZE = 16
HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET = 32
HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET = 36
HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET = 38
HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET = 40
HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET = (
    HCNETSDK_NETCFG_V30_ETHERNET_OFFSET
    + HCNETSDK_NETCFG_V30_ETHERNET_COUNT * HCNETSDK_NETCFG_V30_ETHERNET_SIZE
)
HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET = (
    HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET + HCNETSDK_NETCFG_V30_IP_SIZE
)
HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET = (
    HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET + 4
)
HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET = (
    HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET + HCNETSDK_NETCFG_V30_IP_SIZE
)
HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET = (
    HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET + HCNETSDK_NETCFG_V30_IP_SIZE
)
HCNETSDK_NETCFG_V30_NFS_IP_OFFSET = (
    HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET + HCNETSDK_NETCFG_V30_IP_SIZE
)
HCNETSDK_DEVICE_CFG_V40_MIN_SIZE = 164
HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET = 4
HCNETSDK_DEVICE_CFG_V40_NAME_SIZE = 32
HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET = 44
HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE = 48
HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET = 140
HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE = 24
HCNETSDK_RECORD_CFG_V30_SIZE = 508
HCNETSDK_RECORD_CFG_V30_DAY_COUNT = 7
HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY = 8
HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET = 8
HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE = 4
HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET = (
    HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET
    + HCNETSDK_RECORD_CFG_V30_DAY_COUNT * HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE
)
HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE = 8
HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET = (
    HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET
    + HCNETSDK_RECORD_CFG_V30_DAY_COUNT
    * HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY
    * HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE
)
HCNETSDK_USER_CFG_V30_USER_COUNT = 32
HCNETSDK_USER_CFG_V30_ENTRY_SIZE = 792
HCNETSDK_USER_CFG_V30_USERNAME_SIZE = 32
HCNETSDK_USER_CFG_V30_PASSWORD_SIZE = 16
HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE = 32
HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE = 32
HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE = 64
HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE = 16
HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE = 128
HCNETSDK_USER_CFG_V30_MAC_SIZE = 6
HCNETSDK_USER_CFG_V30_RESERVED_SIZE = 17
HCNETSDK_USER_CFG_V30_MIN_SIZE = 4 + HCNETSDK_USER_CFG_V30_ENTRY_SIZE
HCNETSDK_USER_CFG_V30_MAX_SIZE = (
    4 + HCNETSDK_USER_CFG_V30_USER_COUNT * HCNETSDK_USER_CFG_V30_ENTRY_SIZE
)
HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE = 12
HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE = 8
HCNETSDK_AUDIO_INPUT_PARAM_SIZE = 8
HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE = 5
HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX = b"\x00\x00"
HCNETSDK_COMPRESSION_CFG_MIN_SIZE = 32
HCNETSDK_PIC_CFG_MIN_SIZE = 36
HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE = 32
HCNETSDK_EZVIZ_ACCESS_CFG_SIZE = 516
HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET = 4
HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET = 5
HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET = 6
HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET = 7
HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE = 64
HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET = 72
HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE = 32
HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET = 104


class HcNetSdkAbility(IntEnum):
    """HCNetSDK ``NET_DVR_GetDeviceAbility`` IDs used by the app."""

    DEVICE_SOFT_HARDWARE = 1
    DEVICE_ENCODE_ALL = 3
    DEVICE_ENCODE_ALL_V20 = 8
    DEVICE_JPEG_CAPTURE = 15
    DEVICE_NETWORK = 2
    DEVICE_SERIAL = 16
    DEVICE_USER = 12
    IPC_FRONT_PARAMETER = 5
    DEVICE_ABILITY_INFO = 17
    DEVICE_VIDEOPIC = 14


class HcNetSdkLocalCfgType(IntEnum):
    """HCNetSDK ``NET_DVR_SetSDKLocalCfg`` enum values from the APK."""

    TCP_PORT_BIND = 0
    UDP_PORT_BIND = 1
    MEM_POOL = 2
    MODULE_RECV_TIMEOUT = 3
    ABILITY_PARSE = 4
    TALK_MODE = 5
    PROTECT_KEY = 6
    CFG_VERSION = 7
    RTSP_PARAMS = 8
    SIMXML_LOGIN = 9
    CHECK_DEV = 10
    SECURITY = 11
    EZVIZLIB_PATH = 12
    CHAR_ENCODE = 13
    PROXYS = 14
    LOG = 15
    STREAM_CALLBACK = 16
    GENERAL = 17
    PTZ = 18


class HcNetSdkPlaybackControlCommand(IntEnum):
    """HCNetSDK playback-control IDs from ``PlaybackControlCommand``."""

    START = HCNETSDK_PLAYSTART
    PAUSE = HCNETSDK_PLAYPAUSE
    RESTART = HCNETSDK_PLAYRESTART
    FAST = HCNETSDK_PLAYFAST
    SLOW = HCNETSDK_PLAYSLOW
    START_AUDIO = HCNETSDK_PLAYSTARTAUDIO
    STOP_AUDIO = HCNETSDK_PLAYSTOPAUDIO
    AUDIO_VOLUME = HCNETSDK_PLAYAUDIOVOLUME
    SET_TRANS_TYPE = HCNETSDK_SET_TRANS_TYPE
    PLAY_CONVERT = HCNETSDK_PLAY_CONVERT


class EzvizPtzCommand(IntEnum):
    """EZVIZ app PTZ command IDs from ``PlayerConstants``/``PlayUtils``."""

    UP = 0
    DOWN = 1
    LEFT = 2
    RIGHT = 3
    FLIP = 4
    ZOOM_IN = 5
    ZOOM_OUT = 6
    SET_PRESET = 7
    CLEAR_PRESET = 8
    CLE_PRESET = 8
    GOTO_PRESET = 9
    ACTION_START = EZVIZ_LAN_PTZ_ACTION_START
    ACTION_STOP = EZVIZ_LAN_PTZ_ACTION_STOP
    CENTER = 12
    UP_LEFT = 13
    DOWN_LEFT = 14
    UP_RIGHT = 15
    DOWN_RIGHT = 16
    ACTION_RESET = EZVIZ_LAN_PTZ_ACTION_RESET


class HcNetSdkPtzCommand(IntEnum):
    """HCNetSDK PTZ command IDs from ``com.neutral.netsdk.PTZCommand``."""

    LIGHT_PWRON = 2
    WIPER_PWRON = 3
    FAN_PWRON = 4
    HEATER_PWRON = 5
    AUX_PWRON1 = 6
    AUX_PWRON2 = 7
    ZOOM_IN = 11
    ZOOM_OUT = 12
    FOCUS_NEAR = 13
    FOCUS_FAR = 14
    IRIS_OPEN = 15
    IRIS_CLOSE = 16
    TILT_UP = 21
    TILT_DOWN = 22
    PAN_LEFT = 23
    PAN_RIGHT = 24
    UP_LEFT = 25
    UP_RIGHT = 26
    DOWN_LEFT = 27
    DOWN_RIGHT = 28
    PAN_AUTO = 29
    RUN_CRUISE = 36
    RUN_SEQ = 37
    STOP_SEQ = 38
    GOTO_PRESET = 39


class HcNetSdkPtzPresetCommand(IntEnum):
    """HCNetSDK preset command IDs from ``PTZPresetCmd``."""

    SET_PRESET = 8
    CLEAR_PRESET = 9
    CLE_PRESET = 9
    GOTO_PRESET = 39


def hcnetsdk_real_data_to_media_packet(
    packet: HcNetSdkRealDataPacket,
) -> MediaPacket:
    """Normalize an HCNetSDK callback packet without changing its SDK model."""

    return MediaPacket(
        body=packet.body,
        metadata=MediaPacketMetadata(
            source="hcnetsdk",
            data_type=packet.data_type,
            attributes={
                "real_handle": packet.real_handle,
                "payload_kind": packet.payload_kind,
            },
        ),
    )


def hcnetsdk_media_packet_source(
    packets: Iterable[HcNetSdkRealDataPacket],
    *,
    cancel: Callable[[], None] | None = None,
) -> IterableMediaPacketSource[HcNetSdkRealDataPacket]:
    """Adapt HCNetSDK callback media packets to the shared packet contract."""

    return IterableMediaPacketSource(
        packets,
        hcnetsdk_real_data_to_media_packet,
        predicate=lambda packet: packet.is_media,
        cancel=cancel,
    )


SocketSourceAddress = tuple[str, int] | None
SocketBindAddress = tuple[str, int] | tuple[str, int, int, int]
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


def hcnetsdk_time(
    year: int,
    month: int,
    day: int,
    *,
    hour: int = 0,
    minute: int = 0,
    second: int = 0,
) -> HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` field model."""
    return HcNetSdkTime(
        year=year,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
    )


def hcnetsdk_time_from_datetime(value: datetime) -> HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` model from a Python ``datetime``."""
    return HcNetSdkTime.from_datetime(value)


def hcnetsdk_file_search_condition(
    channel: int,
    start_time: HcNetSdkTime | datetime | date,
    stop_time: HcNetSdkTime | datetime | date,
    *,
    file_type: int = HCNETSDK_PLAYBACK_FILE_TYPE_ALL,
    is_locked: int = HCNETSDK_PLAYBACK_LOCK_STATE_ALL,
    use_card_no: int = 0,
    card_number: str | bytes = b"",
) -> HcNetSdkFileCond:
    """Return a generic ``NET_DVR_FILECOND`` playback search condition."""
    return HcNetSdkFileCond(
        channel=channel,
        start_time=_hcnetsdk_time_value(start_time),
        stop_time=_hcnetsdk_time_value(stop_time, end_of_day=True),
        file_type=file_type,
        is_locked=is_locked,
        use_card_no=use_card_no,
        card_number=card_number,
    )


def ezviz_lan_playback_file_search_condition(
    channel: int,
    start_time: HcNetSdkTime | datetime | date,
    stop_time: HcNetSdkTime | datetime | date,
) -> HcNetSdkFileCond:
    """Return the APK-observed LAN playback file-search condition."""
    return hcnetsdk_file_search_condition(
        channel,
        start_time,
        stop_time,
        file_type=HCNETSDK_PLAYBACK_FILE_TYPE_ALL,
        is_locked=HCNETSDK_PLAYBACK_LOCK_STATE_ALL,
        use_card_no=0,
    )


def hcnetsdk_playback_condition(
    channel: int,
    start_time: HcNetSdkTime | datetime | date,
    stop_time: HcNetSdkTime | datetime | date,
    *,
    draw_frame: int = 0,
    stream_type: int = 0,
    stream_id: str | bytes = b"",
) -> HcNetSdkPlayCond:
    """Return a generic ``NET_DVR_PLAYCOND`` time-playback condition."""
    return HcNetSdkPlayCond(
        channel=channel,
        start_time=_hcnetsdk_time_value(start_time),
        stop_time=_hcnetsdk_time_value(stop_time, end_of_day=True),
        draw_frame=draw_frame,
        stream_type=stream_type,
        stream_id=stream_id,
    )


def ezviz_lan_playback_condition(
    channel: int,
    start_time: HcNetSdkTime | datetime | date,
    stop_time: HcNetSdkTime | datetime | date,
    *,
    stream_type: int = 0,
) -> HcNetSdkPlayCond:
    """Return the APK-compatible LAN playback-by-time condition."""
    return hcnetsdk_playback_condition(
        channel,
        start_time,
        stop_time,
        draw_frame=0,
        stream_type=stream_type,
    )


def hcnetsdk_init_request(
    playctrl_library: str | None = "libPlayCtrl.so",
) -> HcNetSdkInitRequest:
    """Return the ``NET_DVR_Init`` request shape used before LAN SDK calls."""
    return HcNetSdkInitRequest(playctrl_library=playctrl_library)


def hcnetsdk_cleanup_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_Cleanup`` request shape."""
    return HcNetSdkNoArgRequest(api=HCNETSDK_CLEANUP)


def hcnetsdk_set_connect_time_request(
    connect_time_ms: int = 5000,
    retry_count: int = 3,
) -> HcNetSdkSetConnectTimeRequest:
    """Return the APK-style ``NET_DVR_SetConnectTime`` request shape."""
    return HcNetSdkSetConnectTimeRequest(
        connect_time_ms=connect_time_ms,
        retry_count=retry_count,
    )


def hcnetsdk_get_last_error_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetLastError`` request shape."""
    return HcNetSdkNoArgRequest(api=HCNETSDK_GET_LAST_ERROR)


def hcnetsdk_get_error_msg_request(
    error_code: int | None = None,
) -> HcNetSdkGetErrorMsgRequest:
    """Return the ``NET_DVR_GetErrorMsg`` request shape."""
    return HcNetSdkGetErrorMsgRequest(error_code=error_code)


def hcnetsdk_get_sdk_version_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKVersion`` request shape."""
    return HcNetSdkNoArgRequest(api=HCNETSDK_GET_SDK_VERSION)


def hcnetsdk_get_sdk_build_version_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKBuildVersion`` request shape."""
    return HcNetSdkNoArgRequest(api=HCNETSDK_GET_SDK_BUILD_VERSION)


def hcnetsdk_logout_v30_request(login_id: int) -> HcNetSdkLogoutRequest:
    """Return the ``NET_DVR_Logout_V30`` request shape."""
    return HcNetSdkLogoutRequest(login_id=login_id)


def hcnetsdk_find_file_v30_request(
    login_id: int,
    file_cond: HcNetSdkFileCond,
) -> HcNetSdkFindFileRequest:
    """Return the ``NET_DVR_FindFile_V30`` request shape."""
    return HcNetSdkFindFileRequest(login_id=login_id, file_cond=file_cond)


def hcnetsdk_find_next_file_v30_request(
    find_handle: int,
    *,
    find_data: HcNetSdkFindDataV30 | None = None,
) -> HcNetSdkFindNextFileRequest:
    """Return the ``NET_DVR_FindNextFile_V30`` request shape."""
    return HcNetSdkFindNextFileRequest(
        find_handle=find_handle,
        find_data=find_data,
    )


def hcnetsdk_find_close_v30_request(
    find_handle: int,
) -> HcNetSdkFindCloseRequest:
    """Return the ``NET_DVR_FindClose_V30`` request shape."""
    return HcNetSdkFindCloseRequest(find_handle=find_handle)


def hcnetsdk_playback_by_time_v40_request(
    login_id: int,
    play_cond: HcNetSdkPlayCond,
) -> HcNetSdkPlayBackByTimeRequest:
    """Return the ``NET_DVR_PlayBackByTime_V40`` request shape."""
    return HcNetSdkPlayBackByTimeRequest(login_id=login_id, play_cond=play_cond)


def hcnetsdk_playback_control_v40_request(
    play_handle: int,
    command: int | HcNetSdkPlaybackControlCommand,
    *,
    in_buffer: str | bytes | None = None,
    out_buffer_size: int = 0,
) -> HcNetSdkPlayBackControlRequest:
    """Return the ``NET_DVR_PlayBackControl_V40`` request shape."""
    return HcNetSdkPlayBackControlRequest(
        play_handle=play_handle,
        command=int(command),
        in_buffer=in_buffer,
        out_buffer_size=out_buffer_size,
    )


def hcnetsdk_stop_playback_request(
    play_handle: int,
) -> HcNetSdkStopPlayBackRequest:
    """Return the ``NET_DVR_StopPlayBack`` request shape."""
    return HcNetSdkStopPlayBackRequest(play_handle=play_handle)


def hcnetsdk_playback_capture_file_request(
    play_handle: int,
    saved_file_name: str | bytes,
) -> HcNetSdkPlayBackCaptureFileRequest:
    """Return the ``NET_DVR_PlayBackCaptureFile`` request shape."""
    return HcNetSdkPlayBackCaptureFileRequest(
        play_handle=play_handle,
        saved_file_name=saved_file_name,
    )


def hcnetsdk_set_play_data_callback_request(
    play_handle: int,
    *,
    callback: str | None = None,
    user_data: str | int | None = None,
) -> HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack`` request shape."""
    return HcNetSdkPlayDataCallbackRequest(
        play_handle=play_handle,
        callback=callback,
        user_data=user_data,
    )


def hcnetsdk_set_play_data_callback_v40_request(
    play_handle: int,
    *,
    callback: str | None = None,
    user_data: str | int | None = None,
) -> HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack_V40`` request shape."""
    return HcNetSdkPlayDataCallbackRequest(
        play_handle=play_handle,
        callback=callback,
        user_data=user_data,
        api=HCNETSDK_SET_PLAY_DATA_CALLBACK_V40,
    )


def hcnetsdk_set_playback_response_callback_request(
    play_handle: int,
    *,
    callback: str | None = None,
    user_data: str | int | None = None,
) -> HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlaybackResponseCallBack`` request shape."""
    return HcNetSdkPlaybackCallbackRequest(
        play_handle=play_handle,
        callback=callback,
        user_data=user_data,
    )


def hcnetsdk_set_playback_es_callback_request(
    play_handle: int,
    *,
    callback: str | None = None,
    user_data: str | int | None = None,
) -> HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlayBackESCallBack`` request shape."""
    return HcNetSdkPlaybackCallbackRequest(
        play_handle=play_handle,
        callback=callback,
        user_data=user_data,
        api=HCNETSDK_SET_PLAYBACK_ES_CALLBACK,
    )


def hcnetsdk_set_playback_secret_key_request(
    play_handle: int,
    secret_key: str | bytes,
    *,
    secret_key_type: int = HCNETSDK_SECRET_KEY_TYPE_AES,
) -> HcNetSdkPlayBackSecretKeyRequest:
    """Return the ``NET_DVR_SetPlayBackSecretKey`` request shape."""
    return HcNetSdkPlayBackSecretKeyRequest(
        play_handle=play_handle,
        secret_key=secret_key,
        secret_key_type=secret_key_type,
    )


def hcnetsdk_get_file_by_name_request(
    login_id: int,
    dvr_file_name: str | bytes,
    saved_file_name: str | bytes,
) -> HcNetSdkGetFileByNameRequest:
    """Return the ``NET_DVR_GetFileByName`` request shape."""
    return HcNetSdkGetFileByNameRequest(
        login_id=login_id,
        dvr_file_name=dvr_file_name,
        saved_file_name=saved_file_name,
    )


def hcnetsdk_get_file_by_time_request(
    login_id: int,
    channel: int,
    start_time: HcNetSdkTime | datetime | date,
    stop_time: HcNetSdkTime | datetime | date,
    saved_file_name: str | bytes,
) -> HcNetSdkGetFileByTimeRequest:
    """Return the ``NET_DVR_GetFileByTime`` request shape."""
    return HcNetSdkGetFileByTimeRequest(
        login_id=login_id,
        channel=channel,
        start_time=_hcnetsdk_time_value(start_time),
        stop_time=_hcnetsdk_time_value(stop_time, end_of_day=True),
        saved_file_name=saved_file_name,
    )


def hcnetsdk_stop_get_file_request(file_handle: int) -> HcNetSdkStopGetFileRequest:
    """Return the ``NET_DVR_StopGetFile`` request shape."""
    return HcNetSdkStopGetFileRequest(file_handle=file_handle)


def hcnetsdk_get_download_pos_request(
    file_handle: int,
) -> HcNetSdkGetDownloadPosRequest:
    """Return the ``NET_DVR_GetDownloadPos`` request shape."""
    return HcNetSdkGetDownloadPosRequest(file_handle=file_handle)


def hcnetsdk_find_next_file_status(native_result: int) -> str:
    """Return the app-observed meaning of ``NET_DVR_FindNextFile_V30``."""
    if native_result == HCNETSDK_FIND_NEXT_FILE_SUCCESS:
        return "file"
    if native_result == HCNETSDK_FIND_NEXT_FILE_NO_FILE:
        return "no_file"
    if native_result == HCNETSDK_FIND_NEXT_FILE_IS_FINDING:
        return "finding"
    if native_result == HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE:
        return "no_more_file"
    if native_result == HCNETSDK_FIND_NEXT_FILE_EXCEPTION:
        return "exception"
    return "unknown"


def ezviz_lan_playback_video_type(native_file_type: int) -> int:
    """Map native file type to the EZVIZ ``CloudFile.videoType`` value."""
    return EZVIZ_LAN_PLAYBACK_VIDEO_TYPE_MAP.get(native_file_type, 0)


def sadp_activate_device_request(
    serial: str,
    password: str,
) -> SadpActivateDeviceRequest:
    """Return the local SADP device activation request shape."""
    return SadpActivateDeviceRequest(serial=serial, password=password)


def sadp_device_net_param(
    *,
    ipv4_address: str,
    ipv4_subnet_mask: str,
    ipv4_gateway: str,
    dhcp_enabled: int | bool,
    http_port: int,
    command_port: int,
    ipv6_address: str = "",
    ipv6_gateway: str = "",
    ipv6_mask_len: int = 0,
) -> SadpDeviceNetParam:
    """Return the Android ``SADP_DEV_NET_PARAM`` field-update model."""
    return SadpDeviceNetParam(
        ipv4_address=ipv4_address,
        ipv4_subnet_mask=ipv4_subnet_mask,
        ipv4_gateway=ipv4_gateway,
        dhcp_enabled=dhcp_enabled,
        http_port=http_port,
        command_port=command_port,
        ipv6_address=ipv6_address,
        ipv6_gateway=ipv6_gateway,
        ipv6_mask_len=ipv6_mask_len,
    )


def sadp_modify_device_net_param_request(
    mac: str,
    password: str,
    net_param: SadpDeviceNetParam,
) -> SadpModifyDeviceNetParamRequest:
    """Return the local SADP network-parameter update request shape."""
    return SadpModifyDeviceNetParamRequest(
        mac=mac,
        password=password,
        net_param=net_param,
    )


def sadp_modify_device_net_param_v40_request(
    mac: str,
    password: str,
    net_param: SadpDeviceNetParam,
    *,
    ret_net_param: SadpDeviceRetNetParam | None = None,
) -> SadpModifyDeviceNetParamV40Request:
    """Return the local SADP V40 network-parameter update request shape."""
    return SadpModifyDeviceNetParamV40Request(
        mac=mac,
        password=password,
        net_param=net_param,
        ret_net_param=ret_net_param,
    )


def sadp_get_last_error_request() -> SadpNoArgRequest:
    """Return the ``SADP_GetLastError`` request shape."""
    return SadpNoArgRequest(api=SADP_GET_LAST_ERROR)


def sadp_get_sadp_version_request() -> SadpNoArgRequest:
    """Return the ``SADP_GetSadpVersion`` request shape."""
    return SadpNoArgRequest(api=SADP_GET_VERSION)


def sadp_set_log_to_file_request(
    log_level: int,
    log_dir: str | bytes,
    *,
    auto_delete: int | bool = True,
) -> SadpSetLogToFileRequest:
    """Return the ``SADP_SetLogToFile`` request shape."""
    return SadpSetLogToFileRequest(
        log_level=log_level,
        log_dir=log_dir,
        auto_delete=auto_delete,
    )


def sadp_start_v30_request(
    *,
    install_npf: int | bool = 0,
    callback: str | None = None,
    user_data: str | None = None,
) -> SadpStartRequest:
    """Return the ``SADP_Start_V30`` request shape."""
    return SadpStartRequest(
        version=30,
        install_npf=install_npf,
        callback=callback,
        user_data=user_data,
    )


def sadp_start_v40_request(
    *,
    install_npf: int | bool = 0,
    callback: str | None = None,
    user_data: str | None = None,
) -> SadpStartRequest:
    """Return the ``SADP_Start_V40`` request shape."""
    return SadpStartRequest(
        version=40,
        install_npf=install_npf,
        callback=callback,
        user_data=user_data,
    )


def sadp_stop_request() -> SadpNoArgRequest:
    """Return the ``SADP_Stop`` request shape."""
    return SadpNoArgRequest(api=SADP_STOP)


def sadp_clearup_request() -> SadpNoArgRequest:
    """Return the ``SADP_Clearup`` request shape."""
    return SadpNoArgRequest(api=SADP_CLEARUP)


def sadp_send_inquiry_request() -> SadpNoArgRequest:
    """Return the ``SADP_SendInquiry`` request shape."""
    return SadpNoArgRequest(api=SADP_SEND_INQUIRY)


def ezviz_lan_sadp_activate_batch_result(
    serial: str,
    password: str,
    *,
    code: int,
    error: int,
) -> SadpBatchResult:
    """Return the RN-style result map model for batch SADP activation."""
    return SadpBatchResult(
        identifier=serial,
        password=password,
        code=code,
        error=error,
        identifier_key="serial",
    )


def ezviz_lan_sadp_edit_net_param_batch_result(
    mac: str,
    password: str,
    *,
    code: int,
    error: int,
) -> SadpBatchResult:
    """Return the RN-style result map model for batch SADP network edits."""
    return SadpBatchResult(
        identifier=mac,
        password=password,
        code=code,
        error=error,
        identifier_key="mac",
    )


def hcnetsdk_stdxml_config_request(
    request: str | bytes,
    *,
    in_buffer: str | bytes = b"",
    recv_timeout: int = 0,
    force_encrypt: int = 0,
    num_of_multi_part: int = 0,
    output_buffer_size: int = HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE,
    status_buffer_size: int = HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE,
) -> HcNetSdkStdXmlConfigRequest:
    """Return a ``NET_DVR_STDXMLConfig`` request model."""
    return HcNetSdkStdXmlConfigRequest(
        request=request,
        in_buffer=in_buffer,
        recv_timeout=recv_timeout,
        force_encrypt=force_encrypt,
        num_of_multi_part=num_of_multi_part,
        output_buffer_size=output_buffer_size,
        status_buffer_size=status_buffer_size,
    )


def hcnetsdk_stdxml_isapi_request(
    method: str,
    path: str,
    body: Mapping[str, Any] | str | bytes | None = None,
) -> str:
    """Return the ISAPI request text passed to ``NET_DVR_STDXMLConfig``."""
    method_name = method.strip().upper()
    if not method_name or any(char in method_name for char in " \r\n\t"):
        raise PyEzvizError("HCNetSDK STDXML method is invalid")
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise PyEzvizError("HCNetSDK STDXML path is invalid")

    request = f"{method_name} {path}\r\n"
    if body is None:
        return request
    if isinstance(body, Mapping):
        body_text = json.dumps(dict(body), separators=(",", ":"))
    elif isinstance(body, bytes):
        body_text = body.decode("utf-8")
    else:
        body_text = body
    return request + body_text + "\r\n"


def ezviz_lan_services_switch_get_request() -> str:
    """Return the local ISAPI request used to read ``servicesSwitch``."""
    return HCNETSDK_EZVIZ_SERVICES_SWITCH_GET


def ezviz_lan_services_switch_get_config() -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for reading ``servicesSwitch``."""
    return hcnetsdk_stdxml_config_request(ezviz_lan_services_switch_get_request())


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


def ezviz_lan_services_switch_set_payload(
    payload: Mapping[str, Any] | None,
    *,
    hiksdk: int | bool | None = None,
    web: int | bool | None = None,
    rtsp: int | bool | None = None,
    upnp: int | bool | None = None,
) -> dict[str, Any]:
    """Return a ``servicesSwitch`` payload with only named switches changed."""
    result: dict[str, Any] = dict(payload or {})
    services = result.get("servicesSwitch")
    services_switch = dict(services) if isinstance(services, Mapping) else {}
    for key, value in (
        ("hiksdk", hiksdk),
        ("web", web),
        ("rtsp", rtsp),
        ("upnp", upnp),
    ):
        if value is not None:
            services_switch[key] = _services_switch_value(key, value)
    result["servicesSwitch"] = services_switch
    return result


def ezviz_lan_services_switch_put_request(payload: Mapping[str, Any]) -> str:
    """Return the raw ISAPI request string sent by HCNETUtil.c(...)."""
    return hcnetsdk_stdxml_isapi_request(
        "PUT",
        "/ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json",
        payload,
    )


def ezviz_lan_services_switch_put_config(
    payload: Mapping[str, Any],
) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing ``servicesSwitch``."""
    return hcnetsdk_stdxml_config_request(ezviz_lan_services_switch_put_request(payload))


def ezviz_lan_services_switch_update_config(
    payload: Mapping[str, Any] | None,
    *,
    enabled: bool,
) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for the app's checkbox update."""
    return ezviz_lan_services_switch_put_config(
        ezviz_lan_services_switch_payload(payload, enabled=enabled)
    )


def ezviz_lan_services_switch_set_config(
    payload: Mapping[str, Any] | None,
    *,
    hiksdk: int | bool | None = None,
    web: int | bool | None = None,
    rtsp: int | bool | None = None,
    upnp: int | bool | None = None,
) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for direct ``servicesSwitch`` updates."""
    return ezviz_lan_services_switch_put_config(
        ezviz_lan_services_switch_set_payload(
            payload,
            hiksdk=hiksdk,
            web=web,
            rtsp=rtsp,
            upnp=upnp,
        )
    )


def ezviz_lan_services_switch_state(
    response: Mapping[str, Any] | str | bytes,
) -> EzvizLanServicesSwitchState:
    """Parse ``servicesSwitch`` values from a local ISAPI response."""
    data = hcnetsdk_stdxml_response_json(response)
    services = data.get("servicesSwitch")
    values = services if isinstance(services, Mapping) else {}
    return EzvizLanServicesSwitchState(
        hiksdk=_mapping_int(values, "hiksdk", default=None),
        web=_mapping_int(values, "web", default=None),
        rtsp=_mapping_int(values, "rtsp", default=None),
        raw=data,
    )


def ezviz_lan_services_switch_succeeded(
    response: Mapping[str, Any] | str | bytes,
) -> bool:
    """Return whether HCNETUtil.c(...) would treat a servicesSwitch PUT as OK."""
    data = hcnetsdk_stdxml_response_json(response)
    return data.get("statusCode") == 1


def ezviz_lan_services_switch_get_command_port(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> HcNetSdkStdXmlConfigResponse:
    """Read ``servicesSwitch`` through traced pure-Python command-port STDXML."""
    return hcnetsdk_stdxml_config_command_port_from_trace(
        endpoint,
        password,
        ezviz_lan_services_switch_get_config(),
        command_id=command_id,
        body_prefix=body_prefix,
        addend_delta=addend_delta,
        addend=addend,
        name="servicesSwitch GET",
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )


def ezviz_lan_services_switch_state_command_port(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> EzvizLanServicesSwitchState:
    """Read and parse ``servicesSwitch`` through pure command-port STDXML."""
    response = ezviz_lan_services_switch_get_command_port(
        endpoint,
        password,
        command_id=command_id,
        body_prefix=body_prefix,
        addend_delta=addend_delta,
        addend=addend,
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    if not response.succeeded:
        raise PyEzvizError("HCNetSDK command-port servicesSwitch GET failed")
    return ezviz_lan_services_switch_state(response.output)


def ezviz_lan_services_switch_set_command_port(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    current_payload: Mapping[str, Any] | None = None,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
    hiksdk: int | bool | None = None,
    web: int | bool | None = None,
    rtsp: int | bool | None = None,
    upnp: int | bool | None = None,
) -> HcNetSdkStdXmlConfigResponse:
    """Set named ``servicesSwitch`` values through pure command-port STDXML.

    When ``current_payload`` is omitted, the device is read first so unspecified
    switches are preserved before the PUT request is sent.
    """
    payload = current_payload
    if payload is None:
        get_response = ezviz_lan_services_switch_get_command_port(
            endpoint,
            password,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            username=username,
            local_ip=local_ip,
            timeout=timeout,
            socket_factory=socket_factory,
            rsa_key=rsa_key,
        )
        if not get_response.succeeded:
            raise PyEzvizError("HCNetSDK command-port servicesSwitch GET failed")
        payload = hcnetsdk_stdxml_response_json(get_response.output)

    return hcnetsdk_stdxml_config_command_port_from_trace(
        endpoint,
        password,
        ezviz_lan_services_switch_set_config(
            payload,
            hiksdk=hiksdk,
            web=web,
            rtsp=rtsp,
            upnp=upnp,
        ),
        command_id=command_id,
        body_prefix=body_prefix,
        addend_delta=addend_delta,
        addend=addend,
        name="servicesSwitch PUT",
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )


def ezviz_lan_connect_mode_payload(mode: int = 1) -> dict[str, Any]:
    """Return the local ``connectMode`` payload used when leaving AP mode."""
    if mode < 0:
        raise PyEzvizError("EZVIZ LAN connect mode must be non-negative")
    return {"ConnectMode": {"mode": mode}}


def ezviz_lan_connect_mode_put_request(mode: int = 1) -> str:
    """Return the raw local ISAPI ``connectMode`` PUT request."""
    return hcnetsdk_stdxml_isapi_request(
        "PUT",
        "/ISAPI/EZVIZ/IPC/System/Network/connectMode?format=json",
        ezviz_lan_connect_mode_payload(mode),
    )


def ezviz_lan_connect_mode_put_config(
    mode: int = 1,
) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing local ``connectMode``."""
    return hcnetsdk_stdxml_config_request(ezviz_lan_connect_mode_put_request(mode))


def ezviz_lan_net_config_and_voice_upload_payload(
    *,
    ip: str,
    port: int,
    bssid: str,
    ssid: str,
    passwd: str,
    security: int,
) -> dict[str, Any]:
    """Return the local add-device Wi-Fi upload payload used by the APK."""
    if port < 0:
        raise PyEzvizError("EZVIZ LAN net-config port must be non-negative")
    if security < 0:
        raise PyEzvizError("EZVIZ LAN net-config security must be non-negative")
    return {
        "NetConfigAndVoiceFileUpload": {
            "ip": ip,
            "port": port,
            "bssid": bssid,
            "ssid": ssid,
            "passwd": passwd,
            "security": security,
        }
    }


def ezviz_lan_net_config_and_voice_upload_put_request(
    *,
    ip: str,
    port: int,
    bssid: str,
    ssid: str,
    passwd: str,
    security: int,
) -> str:
    """Return the raw local ISAPI net-config upload PUT request."""
    return hcnetsdk_stdxml_isapi_request(
        "PUT",
        "/ISAPI/EZVIZ/IPC/System/netConfigAndVoiceFileUpload?format=json",
        ezviz_lan_net_config_and_voice_upload_payload(
            ip=ip,
            port=port,
            bssid=bssid,
            ssid=ssid,
            passwd=passwd,
            security=security,
        ),
    )


def ezviz_lan_net_config_and_voice_upload_put_config(
    *,
    ip: str,
    port: int,
    bssid: str,
    ssid: str,
    passwd: str,
    security: int,
) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for local net-config upload."""
    return hcnetsdk_stdxml_config_request(
        ezviz_lan_net_config_and_voice_upload_put_request(
            ip=ip,
            port=port,
            bssid=bssid,
            ssid=ssid,
            passwd=passwd,
            security=security,
        )
    )


def hcnetsdk_dvr_config_get_request(
    login_id: int,
    command: int,
    *,
    channel: int = -1,
    structure: str,
    structure_size: int | None = None,
) -> HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_GetDVRConfig`` request model."""
    return HcNetSdkDvrConfigRequest(
        login_id=login_id,
        command=int(command),
        channel=channel,
        structure=structure,
        structure_size=structure_size,
        api=HCNETSDK_GET_DVR_CONFIG,
    )


def hcnetsdk_dvr_config_set_request(
    login_id: int,
    command: int,
    *,
    channel: int = -1,
    structure: str,
    structure_size: int | None = None,
    field_updates: Mapping[str, Any] | None = None,
    read_before_write: bool = False,
) -> HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_SetDVRConfig`` request model."""
    return HcNetSdkDvrConfigRequest(
        login_id=login_id,
        command=int(command),
        channel=channel,
        structure=structure,
        structure_size=structure_size,
        field_updates=field_updates,
        read_before_write=read_before_write,
        api=HCNETSDK_SET_DVR_CONFIG,
    )


def ezviz_lan_wifi_station_patch(
    *,
    ssid: str | bytes,
    password: str | bytes = b"",
    mac: str | bytes | None = None,
    mode: int = 0,
    security: int | None = None,
) -> dict[str, Any]:
    """Return APK-observed ``NET_DVR_WIFI_CFG`` field updates for station Wi-Fi."""
    if mode < 0:
        raise PyEzvizError("EZVIZ LAN Wi-Fi mode must be non-negative")
    ssid_bytes = _bounded_bytes("Wi-Fi SSID", ssid, 32, truncate=True)
    password_bytes = _bounded_bytes("Wi-Fi password", password, 63)
    wifi_security = (4 if password_bytes else 0) if security is None else security
    if wifi_security < 0:
        raise PyEzvizError("EZVIZ LAN Wi-Fi security must be non-negative")

    patch: dict[str, Any] = {
        "dwMode": mode,
        "sEssid": ssid_bytes,
        "sEssidLength": len(ssid_bytes),
        "dwSecurity": wifi_security,
    }
    if mac is not None:
        patch["struEtherNet.byMACAddr"] = _mac_address_bytes(mac)
    if password_bytes:
        patch.update(
            {
                "wpa_psk.dwKeyLength": len(password_bytes),
                "wpa_psk.byKeyType": 0,
                "wpa_psk.sKeyInfo": "<password-bytes>",
                "wpa_psk.sKeyInfoLength": len(password_bytes),
            }
        )
    return patch


def ezviz_lan_wifi_get_config_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the app's ``NET_DVR_WIFI_CFG`` read request."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
    )


def ezviz_lan_wifi_set_config_request(
    login_id: int,
    *,
    ssid: str | bytes,
    password: str | bytes = b"",
    mac: str | bytes | None = None,
    mode: int = 0,
    security: int | None = None,
) -> HcNetSdkDvrConfigRequest:
    """Return the APK-observed ``NET_DVR_WIFI_CFG`` station update request."""
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
        field_updates=ezviz_lan_wifi_station_patch(
            ssid=ssid,
            password=password,
            mac=mac,
            mode=mode,
            security=security,
        ),
        read_before_write=True,
    )


def ezviz_lan_wifi_work_mode_update_request(
    login_id: int,
    mode: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN ``apiSetApWorkModeWithHandle`` request shape."""
    if mode < 0:
        raise PyEzvizError("EZVIZ LAN Wi-Fi work mode must be non-negative")
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
        field_updates={"dwMode": mode},
        read_before_write=True,
    )


def ezviz_lan_wifi_ap_info_list_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi scan ``NET_DVR_AP_INFO_LIST`` request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_AP_INFO_LIST,
        structure="NET_DVR_AP_INFO_LIST",
    )


def ezviz_lan_time_get_config_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_TIME`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_TIME_CFG,
        structure="NET_DVR_TIME",
    )


def ezviz_lan_ntp_get_config_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NTPPARA`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_NTP_CFG,
        structure="NET_DVR_NTPPARA",
    )


def ezviz_lan_device_config_v40_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_DEVICECFG_V40`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_DEVICE_CFG_V40,
        structure="NET_DVR_DEVICECFG_V40",
    )


def ezviz_lan_net_config_v30_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NETCFG_V30`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_NET_CFG,
        structure="NET_DVR_NETCFG_V30",
    )


def ezviz_lan_record_config_v30_request(
    login_id: int,
    *,
    channel: int = 1,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_RECORD_V30`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_RECORD_CFG_V30,
        channel=channel,
        structure="NET_DVR_RECORD_V30",
    )


def ezviz_lan_wifi_ap_info_list(
    data: bytes | bytearray | memoryview,
) -> tuple[EzvizLanWifiApInfo, ...]:
    """Parse a ``NET_DVR_AP_INFO_LIST`` buffer returned by the command port."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE:
        raise PyEzvizError("EZVIZ LAN Wi-Fi AP list response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "Wi-Fi AP list"
    )
    count = int.from_bytes(raw[4:8], "big")
    required_size = (
        HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE
        + count * HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE
    )
    if required_size > effective_size:
        raise PyEzvizError("EZVIZ LAN Wi-Fi AP list count exceeds response size")
    raw = raw[:effective_size]

    entries: list[EzvizLanWifiApInfo] = []
    offset = HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE
    for _ in range(count):
        end = offset + HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE
        if end > len(raw):
            raise PyEzvizError("EZVIZ LAN Wi-Fi AP entry is truncated")
        entry = raw[offset:end]
        entries.append(
            EzvizLanWifiApInfo(
                ssid=_nul_stripped_text(
                    entry[:HCNETSDK_WIFI_AP_INFO_SSID_SIZE]
                ),
                security=int.from_bytes(
                    entry[
                        HCNETSDK_WIFI_AP_INFO_SSID_SIZE
                        : HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 4
                    ],
                    "big",
                ),
                channel=int.from_bytes(
                    entry[
                        HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 4
                        : HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 8
                    ],
                    "big",
                ),
                signal_strength=int.from_bytes(
                    entry[
                        HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 8
                        : HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 12
                    ],
                    "big",
                ),
                extra=int.from_bytes(
                    entry[
                        HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 12
                        : HCNETSDK_WIFI_AP_INFO_SSID_SIZE + 16
                    ],
                    "big",
                ),
            )
        )
        offset = end
    return tuple(entries)


def ezviz_lan_time_config(data: bytes | bytearray | memoryview) -> HcNetSdkTime:
    """Parse a traced ``NET_DVR_TIME`` buffer from command-port output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_TIME_CFG_SIZE:
        raise PyEzvizError("EZVIZ LAN time config response is too short")
    fields = tuple(
        int.from_bytes(raw[offset : offset + 4], "big")
        for offset in range(0, HCNETSDK_TIME_CFG_SIZE, 4)
    )
    parsed = HcNetSdkTime(*fields)
    parsed.to_native_dict()
    return parsed


def ezviz_lan_ntp_config(data: bytes | bytearray | memoryview) -> EzvizLanNtpConfig:
    """Parse known ``NET_DVR_NTPPARA`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_NTP_CFG_SIZE:
        raise PyEzvizError("EZVIZ LAN NTP config response is too short")
    raw = raw[:HCNETSDK_NTP_CFG_SIZE]
    return EzvizLanNtpConfig(
        ntp_server=_nul_stripped_text(raw[:HCNETSDK_NTP_SERVER_SIZE]),
        interval_minutes=int.from_bytes(
            raw[
                HCNETSDK_NTP_INTERVAL_OFFSET
                : HCNETSDK_NTP_INTERVAL_OFFSET + 2
            ],
            "big",
        ),
        enabled=raw[HCNETSDK_NTP_ENABLE_OFFSET],
        time_difference_hours=int.from_bytes(
            raw[
                HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET
                : HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET + 1
            ],
            "little",
            signed=True,
        ),
        time_difference_minutes=int.from_bytes(
            raw[
                HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET
                : HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET + 1
            ],
            "little",
            signed=True,
        ),
        ntp_port=int.from_bytes(
            raw[HCNETSDK_NTP_PORT_OFFSET : HCNETSDK_NTP_PORT_OFFSET + 2],
            "big",
        ),
        raw=raw,
    )


def ezviz_lan_net_config_v30(
    data: bytes | bytearray | memoryview,
) -> EzvizLanNetConfigV30:
    """Parse non-secret ``NET_DVR_NETCFG_V30`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN net config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "net config"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_NETCFG_V30_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN net config declared size is too small")

    ethernet: list[EzvizLanNetInterfaceConfig] = []
    offset = HCNETSDK_NETCFG_V30_ETHERNET_OFFSET
    for _ in range(HCNETSDK_NETCFG_V30_ETHERNET_COUNT):
        entry = raw[offset : offset + HCNETSDK_NETCFG_V30_ETHERNET_SIZE]
        ethernet.append(
            EzvizLanNetInterfaceConfig(
                ip_address=_fixed_ipv4_text(
                    entry[:HCNETSDK_NETCFG_V30_IP_SIZE]
                ),
                subnet_mask=_fixed_ipv4_text(
                    entry[
                        HCNETSDK_NETCFG_V30_IP_SIZE
                        : HCNETSDK_NETCFG_V30_IP_SIZE * 2
                    ]
                ),
                net_interface=int.from_bytes(
                    entry[
                        HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET
                        : HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET + 4
                    ],
                    "big",
                ),
                port=int.from_bytes(
                    entry[
                        HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET
                        : HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET + 2
                    ],
                    "big",
                ),
                mtu=int.from_bytes(
                    entry[
                        HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET
                        : HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET + 2
                    ],
                    "big",
                ),
                mac_address=_mac_address_text(
                    entry[
                        HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET
                        : HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET + 6
                    ]
                ),
            )
        )
        offset += HCNETSDK_NETCFG_V30_ETHERNET_SIZE

    return EzvizLanNetConfigV30(
        declared_size=effective_size,
        ethernet=tuple(ethernet),
        manage_host_ip=_fixed_ipv4_text(
            raw[
                HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET
                : HCNETSDK_NETCFG_V30_MANAGE_HOST_IP_OFFSET
                + HCNETSDK_NETCFG_V30_IP_SIZE
            ]
        ),
        manage_host_port=int.from_bytes(
            raw[
                HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET
                : HCNETSDK_NETCFG_V30_MANAGE_HOST_PORT_OFFSET + 2
            ],
            "big",
        ),
        ip_server_ip=_fixed_ipv4_text(
            raw[
                HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET
                : HCNETSDK_NETCFG_V30_IP_SERVER_OFFSET
                + HCNETSDK_NETCFG_V30_IP_SIZE
            ]
        ),
        multicast_ip=_fixed_ipv4_text(
            raw[
                HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET
                : HCNETSDK_NETCFG_V30_MULTICAST_IP_OFFSET
                + HCNETSDK_NETCFG_V30_IP_SIZE
            ]
        ),
        gateway_ip=_fixed_ipv4_text(
            raw[
                HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET
                : HCNETSDK_NETCFG_V30_GATEWAY_IP_OFFSET
                + HCNETSDK_NETCFG_V30_IP_SIZE
            ]
        ),
        nfs_ip=_fixed_ipv4_text(
            raw[
                HCNETSDK_NETCFG_V30_NFS_IP_OFFSET
                : HCNETSDK_NETCFG_V30_NFS_IP_OFFSET
                + HCNETSDK_NETCFG_V30_IP_SIZE
            ]
        ),
        raw=raw,
    )


def _hcnetsdk_config_declared_size(raw: bytes, label: str) -> tuple[int, int]:
    """Return declared/effective size for traced DVR config body variants."""
    declared_size = int.from_bytes(raw[0:4], "big")
    if declared_size == 0:
        return declared_size, len(raw)
    if declared_size <= len(raw):
        return declared_size, declared_size

    shifted_size = int.from_bytes(raw[0:2], "big")
    if raw[2:4] == HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX and 0 < shifted_size <= len(
        raw
    ):
        return shifted_size, shifted_size

    raise PyEzvizError(f"EZVIZ LAN {label} response is truncated")


def ezviz_lan_dvr_config_summary(
    data: bytes | bytearray | memoryview,
    *,
    command: int,
    structure: str,
) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary for a binary DVR config response."""
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN DVR config response is too short")
    declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "DVR config"
    )
    if effective_size < 4:
        raise PyEzvizError("EZVIZ LAN DVR config declared size is too small")
    effective_raw = raw[:effective_size]
    return EzvizLanDvrConfigSummary(
        command=int(command),
        structure=structure,
        declared_size=declared_size,
        effective_size=effective_size,
        raw_length=len(raw),
        trailing_bytes=len(raw) - effective_size,
        nonzero_bytes=sum(1 for value in effective_raw if value),
    )


def ezviz_lan_wifi_config_summary(
    data: bytes | bytearray | memoryview,
) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_WIFI_CFG`` buffer."""
    return ezviz_lan_dvr_config_summary(
        data,
        command=HcNetSdkDvrCommand.GET_WIFI_CFG,
        structure="NET_DVR_WIFI_CFG",
    )


def ezviz_lan_ezviz_access_config_summary(
    data: bytes | bytearray | memoryview,
) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_EZVIZ_ACCESS_CFG``."""
    return ezviz_lan_dvr_config_summary(
        data,
        command=HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG,
        structure="NET_DVR_EZVIZ_ACCESS_CFG",
    )


def ezviz_lan_ezviz_access_config(
    data: bytes | bytearray | memoryview,
) -> EzvizLanEzvizAccessConfig:
    """Parse redacted ``NET_DVR_EZVIZ_ACCESS_CFG`` fields from command output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN access config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "EZVIZ access config"
    )
    if effective_size < HCNETSDK_EZVIZ_ACCESS_CFG_SIZE:
        raise PyEzvizError("EZVIZ LAN access config declared size is too small")
    effective_raw = raw[:effective_size]
    verification = effective_raw[
        HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET
        : HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET
        + HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE
    ]
    return EzvizLanEzvizAccessConfig(
        declared_size=effective_size,
        enabled=effective_raw[HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET],
        device_status=effective_raw[
            HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET
        ],
        allow_redirect=effective_raw[
            HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET
        ],
        domain_name=_nul_stripped_text(
            effective_raw[
                HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET
                : HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET
                + HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE
            ]
        ),
        verification_code_present=any(verification),
        net_mode=effective_raw[HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET],
        raw_length=len(raw),
        trailing_bytes=len(raw) - effective_size,
    )


def ezviz_lan_user_config_v30_summary(
    data: bytes | bytearray | memoryview,
) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of ``NET_DVR_USER_V30`` config output."""
    return ezviz_lan_dvr_config_summary(
        data,
        command=HcNetSdkDvrCommand.GET_USER_CFG_V30,
        structure="NET_DVR_USER_V30",
    )


def ezviz_lan_user_config_v30(
    data: bytes | bytearray | memoryview,
) -> EzvizLanUserConfigV30:
    """Decode a ``NET_DVR_USER_V30`` command-port response.

    The returned object contains usernames, passwords, and rights. Keep live
    outputs local and use synthetic fixtures in public tests/docs.
    """
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN user config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "user config"
    )
    if effective_size < HCNETSDK_USER_CFG_V30_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN user config declared size is too small")
    if effective_size > HCNETSDK_USER_CFG_V30_MAX_SIZE:
        raise PyEzvizError("EZVIZ LAN user config declared size is too large")
    payload_size = effective_size - 4
    if payload_size % HCNETSDK_USER_CFG_V30_ENTRY_SIZE:
        raise PyEzvizError("EZVIZ LAN user config entry table is misaligned")

    users = tuple(
        _ezviz_lan_user_config_v30_entry(
            raw[
                4 + index * HCNETSDK_USER_CFG_V30_ENTRY_SIZE
                : 4 + (index + 1) * HCNETSDK_USER_CFG_V30_ENTRY_SIZE
            ],
            index,
        )
        for index in range(payload_size // HCNETSDK_USER_CFG_V30_ENTRY_SIZE)
    )
    return EzvizLanUserConfigV30(
        declared_size=effective_size,
        users=users,
        raw_length=len(raw),
        trailing_bytes=len(raw) - effective_size,
    )


def _ezviz_lan_user_config_v30_entry(
    entry: bytes,
    index: int,
) -> EzvizLanUserConfigV30Entry:
    """Parse one fixed-size ``NET_DVR_USER_INFO_V30`` record."""
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        value = entry[offset : offset + size]
        offset += size
        return value

    username = _nul_stripped_text(take(HCNETSDK_USER_CFG_V30_USERNAME_SIZE))
    password_bytes = _fixed_secret_bytes(
        take(HCNETSDK_USER_CFG_V30_PASSWORD_SIZE)
    )
    password = _fixed_secret_text(password_bytes)
    local_rights = _byte_tuple(take(HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE))
    remote_rights = _byte_tuple(take(HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE))
    net_preview_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    local_playback_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    net_playback_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    local_record_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    net_record_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    local_ptz_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    net_ptz_rights = _byte_tuple(take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE))
    local_backup_rights = _byte_tuple(
        take(HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE)
    )
    user_ipv4 = _fixed_ipv4_text(take(HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE))
    user_ipv6 = _fixed_ipv4_text(take(HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE))
    mac_address = _mac_address_text(take(HCNETSDK_USER_CFG_V30_MAC_SIZE))
    priority = take(1)[0]
    reserved = take(HCNETSDK_USER_CFG_V30_RESERVED_SIZE)

    return EzvizLanUserConfigV30Entry(
        index=index,
        username=username,
        password=password,
        password_bytes=password_bytes,
        local_rights=local_rights,
        remote_rights=remote_rights,
        net_preview_rights=net_preview_rights,
        local_playback_rights=local_playback_rights,
        net_playback_rights=net_playback_rights,
        local_record_rights=local_record_rights,
        net_record_rights=net_record_rights,
        local_ptz_rights=local_ptz_rights,
        net_ptz_rights=net_ptz_rights,
        local_backup_rights=local_backup_rights,
        user_ipv4=user_ipv4,
        user_ipv6=user_ipv6,
        mac_address=mac_address,
        priority=priority,
        reserved=reserved,
    )


def ezviz_lan_device_config_v40(
    data: bytes | bytearray | memoryview,
) -> EzvizLanDeviceConfigV40:
    """Parse known ``NET_DVR_DEVICECFG_V40`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN device V40 config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "device V40 config"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_DEVICE_CFG_V40_MIN_SIZE:
        raise PyEzvizError(
            "EZVIZ LAN device V40 config declared size is too small"
        )

    def u32(offset: int) -> int:
        return int.from_bytes(raw[offset : offset + 4], "big")

    return EzvizLanDeviceConfigV40(
        declared_size=effective_size,
        device_name=_nul_stripped_text(
            raw[
                HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET
                : HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET
                + HCNETSDK_DEVICE_CFG_V40_NAME_SIZE
            ]
        ),
        dvr_id=u32(36),
        recycle_record=u32(40),
        serial_number=_nul_stripped_text(
            raw[
                HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET
                : HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET
                + HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE
            ]
        ),
        software_version=u32(92),
        software_build_date=u32(96),
        dsp_software_version=u32(100),
        dsp_software_build_date=u32(104),
        panel_version=u32(108),
        hardware_version=u32(112),
        alarm_in_port_count=raw[116],
        alarm_out_port_count=raw[117],
        rs232_count=raw[118],
        rs485_count=raw[119],
        network_port_count=raw[120],
        disk_control_count=raw[121],
        disk_count=raw[122],
        dvr_type=raw[123],
        channel_count=raw[124],
        start_channel=raw[125],
        audio_count=raw[130],
        ip_channel_count=raw[131],
        device_type=int.from_bytes(raw[138:140], "big"),
        device_type_name=_nul_stripped_text(
            raw[
                HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET
                : HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET
                + HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE
            ]
        ),
        raw=raw,
    )


def ezviz_lan_record_config_v30(
    data: bytes | bytearray | memoryview,
) -> EzvizLanRecordConfigV30:
    """Parse known ``NET_DVR_RECORD_V30`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < 4:
        raise PyEzvizError("EZVIZ LAN record config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "record config"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_RECORD_CFG_V30_SIZE:
        raise PyEzvizError("EZVIZ LAN record config declared size is too small")

    all_day: list[EzvizLanRecordDayConfig] = []
    offset = HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET
    for day_index in range(HCNETSDK_RECORD_CFG_V30_DAY_COUNT):
        entry = raw[offset : offset + HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE]
        all_day.append(
            EzvizLanRecordDayConfig(
                day_index=day_index,
                all_day_record=int.from_bytes(entry[0:2], "big"),
                record_type=entry[2],
            )
        )
        offset += HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE

    schedule: list[tuple[EzvizLanRecordScheduleSegment, ...]] = []
    offset = HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET
    for day_index in range(HCNETSDK_RECORD_CFG_V30_DAY_COUNT):
        day_segments: list[EzvizLanRecordScheduleSegment] = []
        for segment_index in range(HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY):
            entry = raw[offset : offset + HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE]
            day_segments.append(
                EzvizLanRecordScheduleSegment(
                    day_index=day_index,
                    segment_index=segment_index,
                    start_hour=entry[0],
                    start_minute=entry[1],
                    stop_hour=entry[2],
                    stop_minute=entry[3],
                    record_type=entry[4],
                )
            )
            offset += HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE
        schedule.append(tuple(day_segments))

    trailer = HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET
    return EzvizLanRecordConfigV30(
        declared_size=effective_size,
        record_enabled=int.from_bytes(raw[4:8], "big"),
        all_day=tuple(all_day),
        schedule=tuple(schedule),
        record_time=int.from_bytes(raw[trailer : trailer + 4], "big"),
        pre_record_time=int.from_bytes(raw[trailer + 4 : trailer + 8], "big"),
        recorder_duration=int.from_bytes(raw[trailer + 8 : trailer + 12], "big"),
        redundancy_record=raw[trailer + 12],
        audio_record=raw[trailer + 13],
        stream_type=raw[trailer + 14],
        passback_record=raw[trailer + 15],
        lock_duration=int.from_bytes(raw[trailer + 16 : trailer + 18], "big"),
        record_backup=raw[trailer + 18],
        svc_level=raw[trailer + 19],
        raw=raw,
    )


def ezviz_lan_hd_config(
    data: bytes | bytearray | memoryview,
) -> EzvizLanHdConfig:
    """Parse known ``NET_DVR_HDCFG`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_HD_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN HD config response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "HD config"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_HD_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN HD config declared size is too small")
    if len(raw) < HCNETSDK_HD_CFG_HEADER_SIZE:
        return EzvizLanHdConfig(declared_size=effective_size, raw=raw)

    disk_count = int.from_bytes(raw[4:8], "big")
    if disk_count > HCNETSDK_HD_CFG_DISK_COUNT:
        raise PyEzvizError("EZVIZ LAN HD config disk count exceeds response capacity")
    required_size = (
        HCNETSDK_HD_CFG_DISK_OFFSET + disk_count * HCNETSDK_HD_CFG_DISK_SIZE
    )
    if required_size > len(raw):
        raise PyEzvizError("EZVIZ LAN HD config disk table is truncated")

    disks = tuple(
        _ezviz_lan_hd_disk_config(
            raw[
                HCNETSDK_HD_CFG_DISK_OFFSET
                + index * HCNETSDK_HD_CFG_DISK_SIZE
                : HCNETSDK_HD_CFG_DISK_OFFSET
                + (index + 1) * HCNETSDK_HD_CFG_DISK_SIZE
            ]
        )
        for index in range(disk_count)
    )
    return EzvizLanHdConfig(
        declared_size=effective_size,
        raw=raw,
        disk_count=disk_count,
        disks=disks,
    )


def _ezviz_lan_hd_disk_config(entry: bytes) -> EzvizLanHdDiskConfig:
    """Parse one fixed-size ``NET_DVR_SINGLE_HD`` record."""

    def u32(offset: int) -> int:
        return int.from_bytes(entry[offset : offset + 4], "big")

    return EzvizLanHdDiskConfig(
        hd_no=u32(HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET),
        capacity=u32(HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET),
        free_space=u32(HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET),
        status=u32(HCNETSDK_HD_CFG_DISK_STATUS_OFFSET),
        attribute=entry[HCNETSDK_HD_CFG_DISK_ATTR_OFFSET],
        hd_type=entry[HCNETSDK_HD_CFG_DISK_TYPE_OFFSET],
        disk_driver=entry[HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET],
        group=u32(HCNETSDK_HD_CFG_DISK_GROUP_OFFSET),
        recycling=entry[HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET],
        storage_type=u32(HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET),
        picture_capacity=u32(HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET),
        free_picture_space=u32(HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET),
    )


def ezviz_lan_camera_param_config(
    data: bytes | bytearray | memoryview,
) -> EzvizLanCameraParamConfig:
    """Parse known ``NET_DVR_CAMERAPARAMCFG`` fields from command-port output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN camera-param response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "camera-param"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN camera-param declared size is too small")

    return EzvizLanCameraParamConfig(
        declared_size=effective_size,
        brightness=raw[4],
        contrast=raw[5],
        sharpness=raw[6],
        saturation=raw[7],
        hue=raw[8],
        video_effect_enabled=raw[9],
        light_inhibit_level=raw[10],
        gray_level=raw[11],
        raw=raw,
    )


def ezviz_lan_wifi_connect_status(
    data: bytes | bytearray | memoryview,
) -> EzvizLanWifiConnectStatus:
    """Parse known ``NET_DVR_WIFI_CONNECT_STATUS`` fields from command output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN Wi-Fi status response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "Wi-Fi status"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN Wi-Fi status declared size is too small")
    return EzvizLanWifiConnectStatus(
        declared_size=effective_size,
        current_status=raw[4],
        error_code=int.from_bytes(raw[8:12], "big") if len(raw) >= 12 else 0,
        raw=raw,
    )


def ezviz_lan_audio_input_param(
    data: bytes | bytearray | memoryview,
) -> EzvizLanAudioInputParam:
    """Parse known ``NET_DVR_AUDIO_INPUT_PARAM`` fields from command output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_AUDIO_INPUT_PARAM_SIZE:
        raise PyEzvizError("EZVIZ LAN audio-input response is too short")
    return EzvizLanAudioInputParam(
        audio_input_type=raw[0],
        volume=raw[1],
        noise_filter_enabled=raw[2],
        raw=raw[:HCNETSDK_AUDIO_INPUT_PARAM_SIZE],
    )


def ezviz_lan_audio_output_volume(
    data: bytes | bytearray | memoryview,
) -> EzvizLanAudioOutputVolume:
    """Parse known ``NET_DVR_AUDIOOUT_VOLUME`` fields from command output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN audio-output response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "audio-output"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN audio-output declared size is too small")
    return EzvizLanAudioOutputVolume(
        declared_size=effective_size,
        volume=raw[4],
        raw=raw,
    )


def ezviz_lan_compression_config(
    data: bytes | bytearray | memoryview,
) -> EzvizLanCompressionConfig:
    """Parse known ``NET_DVR_COMPRESSIONCFG_V30`` fields from command output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_COMPRESSION_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN compression response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "compression"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_COMPRESSION_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN compression declared size is too small")
    normal_record = _hcnetsdk_compression_info_v30(
        raw, HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET
    )
    if normal_record is None:
        raise PyEzvizError("EZVIZ LAN compression normal block is missing")
    return EzvizLanCompressionConfig(
        declared_size=effective_size,
        stream_type=normal_record.stream_type,
        resolution=normal_record.resolution,
        bitrate_type=normal_record.bitrate_type,
        picture_quality=normal_record.picture_quality,
        video_bitrate=normal_record.video_bitrate,
        video_frame_rate=normal_record.video_frame_rate,
        i_frame_interval=normal_record.i_frame_interval,
        video_encoding_type=normal_record.video_encoding_type,
        raw=raw,
    )


def ezviz_lan_picture_config(
    data: bytes | bytearray | memoryview,
) -> EzvizLanPictureConfig:
    """Parse known ``NET_DVR_PICCFG_V40`` fields from command output."""
    raw = bytes(data)
    if len(raw) < HCNETSDK_PIC_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN picture response is too short")
    _declared_size, effective_size = _hcnetsdk_config_declared_size(
        raw, "picture"
    )
    raw = raw[:effective_size]
    if len(raw) < HCNETSDK_PIC_CFG_MIN_SIZE:
        raise PyEzvizError("EZVIZ LAN picture declared size is too small")
    return EzvizLanPictureConfig(
        declared_size=effective_size,
        channel_name=_nul_stripped_text(
            raw[4 : 4 + HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE]
        ),
        raw=raw,
    )


def ezviz_lan_wifi_connect_status_request(
    login_id: int,
    *,
    channel: int = 0,
) -> HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi connection status request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_WIFI_CONNECT_STATUS,
        channel=channel,
        structure="NET_DVR_WIFI_CONNECT_STATUS",
    )


def ezviz_lan_ezviz_access_replacement_domain(
    domain: str | bytes | None,
    *,
    fallback: str = "dev.ezvizru.com",
) -> str:
    """Return the domain rewrite performed by ``HCNETUtil.g``."""
    text = _nul_stripped_text(domain)
    return text.replace("ezvizlife", "ezvizru") if text else fallback


def ezviz_lan_ezviz_access_get_config_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_EZVIZ_ACCESS_CFG,
        channel=1,
        structure="NET_DVR_EZVIZ_ACCESS_CFG",
    )


def ezviz_lan_ezviz_access_set_domain_request(
    login_id: int,
    domain: str | bytes,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` domain update shape."""
    domain_bytes = _bounded_bytes("EZVIZ access domain", domain, 64)
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_EZVIZ_ACCESS_CFG,
        channel=1,
        structure="NET_DVR_EZVIZ_ACCESS_CFG",
        field_updates={
            "byDomainName": domain_bytes,
            "byDomainNameLength": len(domain_bytes),
        },
        read_before_write=True,
    )


def ezviz_lan_ezviz_access_replacement_domain_request(
    login_id: int,
    current_domain: str | bytes | None,
) -> HcNetSdkDvrConfigRequest:
    """Return the local-add domain rewrite request used on RU accounts."""
    return ezviz_lan_ezviz_access_set_domain_request(
        login_id,
        ezviz_lan_ezviz_access_replacement_domain(current_domain),
    )


def ezviz_lan_audio_input_get_config_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local audio-input config read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_AUDIO_INPUT_PARAM,
        channel=channel,
        structure="NET_DVR_AUDIO_INPUT_PARAM",
    )


def ezviz_lan_audioout_volume_get_config_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local audio-output volume read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_AUDIOOUT_VOLUME,
        channel=channel,
        structure="NET_DVR_AUDIOOUT_VOLUME",
    )


def ezviz_lan_audio_volume_update_requests(
    login_id: int,
    channel: int,
    *,
    input_volume: int,
    output_volume: int,
) -> tuple[HcNetSdkDvrConfigRequest, HcNetSdkDvrConfigRequest]:
    """Return the two local audio-volume set calls made by the RN wrapper."""
    return (
        hcnetsdk_dvr_config_set_request(
            login_id,
            HcNetSdkDvrCommand.SET_AUDIO_INPUT_PARAM,
            channel=channel,
            structure="NET_DVR_AUDIO_INPUT_PARAM",
            field_updates={"byVolume": _byte_value("audio input volume", input_volume)},
            read_before_write=True,
        ),
        hcnetsdk_dvr_config_set_request(
            login_id,
            HcNetSdkDvrCommand.SET_AUDIOOUT_VOLUME,
            channel=channel,
            structure="NET_DVR_AUDIOOUT_VOLUME",
            field_updates={
                "byAudioOutVolume": _byte_value(
                    "audio output volume", output_volume
                )
            },
            read_before_write=True,
        ),
    )


def ezviz_lan_video_coding_get_config_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local video-coding config read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30,
        channel=channel,
        structure="NET_DVR_COMPRESSIONCFG_V30",
    )


def ezviz_lan_video_coding_update_request(
    login_id: int,
    channel: int,
    *,
    video_encoding_type: int,
    video_frame_rate: int,
    video_bitrate: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN video-coding update request shape."""
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_COMPRESSION_CFG_V30,
        channel=channel,
        structure="NET_DVR_COMPRESSIONCFG_V30",
        field_updates={
            "struNormHighRecordPara.byVideoEncType": _byte_value(
                "video encoding type", video_encoding_type
            ),
            "struNormHighRecordPara.dwVideoFrameRate": _byte_value(
                "video frame rate", video_frame_rate
            ),
            "struNormHighRecordPara.dwVideoBitrate": _dword_value(
                "video bitrate", video_bitrate
            ),
        },
        read_before_write=True,
    )


def ezviz_lan_pic_config_get_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local image/OSD config read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_PIC_CFG_V40,
        channel=channel,
        structure="NET_DVR_PICCFG_V40",
    )


def ezviz_lan_pic_config_v30_get_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the traced legacy ``NET_DVR_PICCFG_V30`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_PIC_CFG_V30,
        channel=channel,
        structure="NET_DVR_PICCFG_V30",
    )


def ezviz_lan_pic_config_update_request(
    login_id: int,
    channel: int,
    *,
    show_osd: int | None = None,
    channel_name: str | bytes | None = None,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN image/OSD update request shape."""
    updates: dict[str, Any] = {}
    if show_osd is not None:
        if show_osd < 0:
            raise PyEzvizError("EZVIZ LAN show_osd must be non-negative")
        updates["dwShowOsd"] = show_osd
    if channel_name is not None:
        name_bytes = _bounded_bytes("channel name", channel_name, 32, truncate=True)
        updates["sChanName"] = name_bytes
        updates["sChanNameLength"] = len(name_bytes)
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_PIC_CFG_V40,
        channel=channel,
        structure="NET_DVR_PICCFG_V40",
        field_updates=updates,
        read_before_write=True,
    )


def ezviz_lan_hd_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local storage ``NET_DVR_HDCFG`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_HD_CFG,
        structure="NET_DVR_HDCFG",
    )


def ezviz_lan_sd_format_start_request(
    login_id: int,
    disk_number: int,
) -> HcNetSdkFormatDiskRequest:
    """Return the local SD-card format start request shape."""
    return HcNetSdkFormatDiskRequest(login_id=login_id, disk_number=disk_number)


def ezviz_lan_sd_format_progress_request(
    format_handle: int,
) -> HcNetSdkFormatProgressRequest:
    """Return the local SD-card format progress request shape."""
    return HcNetSdkFormatProgressRequest(format_handle=format_handle)


def ezviz_lan_sd_format_close_request(
    format_handle: int,
) -> HcNetSdkCloseFormatHandleRequest:
    """Return the local SD-card format close request shape."""
    return HcNetSdkCloseFormatHandleRequest(format_handle=format_handle)


def ezviz_lan_sd_format_progress_result(
    *,
    native_succeeded: bool,
    current_disk: int = -1,
    current_disk_position: int = -1,
    status: int = -1,
    last_error: int = 0,
) -> EzvizLanSdFormatProgress:
    """Map native SD format progress references to the RN result semantics."""
    if not native_succeeded:
        return EzvizLanSdFormatProgress(
            code=last_error,
            current_disk=current_disk,
            progress=None,
            status=status,
            done=False,
        )
    if status == 0:
        return EzvizLanSdFormatProgress(
            code=0,
            current_disk=current_disk,
            progress=current_disk_position,
            status=status,
            done=False,
        )
    if status == 1:
        return EzvizLanSdFormatProgress(
            code=0,
            current_disk=current_disk,
            progress=100,
            status=status,
            done=True,
        )
    return EzvizLanSdFormatProgress(
        code=last_error or -1,
        current_disk=current_disk,
        progress=None,
        status=status,
        done=False,
    )


def hcnetsdk_setup_alarm_v30_request(login_id: int) -> HcNetSdkSetupAlarmRequest:
    """Return the legacy ``NET_DVR_SetupAlarmChan_V30`` request shape."""
    return HcNetSdkSetupAlarmRequest(login_id=login_id)


def hcnetsdk_setup_alarm_v41_request(
    login_id: int,
    *,
    level: int = 0,
    alarm_info_type: int = 0,
    ret_alarm_type_v40: int = 0,
    ret_dev_info_version: int = 0,
    ret_vqd_alarm_type: int = 0,
    face_alarm_detection: int = 0,
    support: int = 0,
    broken_net_http: int = 0,
    task_no: int = 0,
) -> HcNetSdkSetupAlarmRequest:
    """Return a ``NET_DVR_SetupAlarmChan_V41`` request model."""
    return HcNetSdkSetupAlarmRequest(
        login_id=login_id,
        setup_param=HcNetSdkSetupAlarmParam(
            level=level,
            alarm_info_type=alarm_info_type,
            ret_alarm_type_v40=ret_alarm_type_v40,
            ret_dev_info_version=ret_dev_info_version,
            ret_vqd_alarm_type=ret_vqd_alarm_type,
            face_alarm_detection=face_alarm_detection,
            support=support,
            broken_net_http=broken_net_http,
            task_no=task_no,
        ),
    )


def hcnetsdk_close_alarm_request(alarm_handle: int) -> HcNetSdkCloseAlarmRequest:
    """Return the ``NET_DVR_CloseAlarmChan_V30`` request shape."""
    return HcNetSdkCloseAlarmRequest(alarm_handle=alarm_handle)


def hcnetsdk_set_sdk_local_cfg_request(
    cfg_type: int,
    *,
    structure: str,
    field_updates: Mapping[str, Any] | None = None,
    field_order: tuple[str, ...] | None = None,
) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return a generic ``NET_DVR_SetSDKLocalCfg`` request model."""
    return HcNetSdkSetSdkLocalCfgRequest(
        cfg_type=int(cfg_type),
        structure=structure,
        field_updates=field_updates,
        field_order=field_order,
    )


def ezviz_hcnetsdk_local_ability_parse_request(
    *,
    enabled: int | bool = True,
) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local ability parser toggle exposed by the APK."""
    return hcnetsdk_set_sdk_local_cfg_request(
        HcNetSdkLocalCfgType.ABILITY_PARSE,
        structure="NET_DVR_LOCAL_ABILITY_PARSE_CFG",
        field_updates={
            "byEnableAbilityParse": _byte_value(
                "ability parse enabled", int(enabled)
            )
        },
        field_order=HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER,
    )


def ezviz_hcnetsdk_local_ptz_without_recv_request(
    *,
    without_recv: int | bool = True,
) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local PTZ no-receive config exposed by the APK."""
    return hcnetsdk_set_sdk_local_cfg_request(
        HcNetSdkLocalCfgType.PTZ,
        structure="NET_DVR_LOCAL_PTZ_CFG",
        field_updates={
            "byWithoutRecv": _byte_value("PTZ without-receive", int(without_recv))
        },
        field_order=HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER,
    )


def ezviz_lan_user_password_get_config_request(
    login_id: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_USER_V30`` read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_USER_CFG_V30,
        structure="NET_DVR_USER_V30",
    )


def ezviz_lan_user_password_update_request(
    login_id: int,
    password: str | bytes,
) -> HcNetSdkDvrConfigRequest:
    """Return the local admin-user password update request shape."""
    password_bytes = _bounded_bytes("user password", password, 16)
    if not password_bytes:
        raise PyEzvizError("EZVIZ LAN user password cannot be empty")
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_USER_CFG_V30,
        structure="NET_DVR_USER_V30",
        field_updates={
            "struUser[0].sPassword": "<password-bytes>",
            "struUser[0].sPasswordLength": len(password_bytes),
            "struUser[0].sPasswordZeroFill": 16,
        },
        read_before_write=True,
    )


def ezviz_lan_video_effect_get_config_request(
    login_id: int,
    channel: int = 1,
) -> HcNetSdkDvrConfigRequest:
    """Return the local camera video-effect config read request shape."""
    return hcnetsdk_dvr_config_get_request(
        login_id,
        HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG,
        channel=channel,
        structure="NET_DVR_CAMERAPARAMCFG",
    )


def ezviz_lan_video_effect_update_request(
    login_id: int,
    *,
    brightness: int,
    contrast: int,
    saturation: int,
    sharpness: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN camera video-effect update request shape."""
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG,
        structure="NET_DVR_CAMERAPARAMCFG",
        field_updates={
            "struVideoEffect.byBrightnessLevel": _byte_value(
                "brightness level", brightness
            ),
            "struVideoEffect.byContrastLevel": _byte_value(
                "contrast level", contrast
            ),
            "struVideoEffect.bySaturationLevel": _byte_value(
                "saturation level", saturation
            ),
            "struVideoEffect.bySharpnessLevel": _byte_value(
                "sharpness level", sharpness
            ),
        },
        read_before_write=True,
    )


def ezviz_lan_backlight_wdr_get_config_request(
    login_id: int,
    channel: int = 1,
) -> HcNetSdkDvrConfigRequest:
    """Return the local WDR/backlight config read request shape."""
    return ezviz_lan_video_effect_get_config_request(login_id, channel=channel)


def ezviz_lan_backlight_wdr_update_request(
    login_id: int,
    *,
    wdr_enabled: int,
    backlight_mode: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN WDR/backlight update request shape."""
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG,
        structure="NET_DVR_CAMERAPARAMCFG",
        field_updates={
            "struWdr.byWDREnabled": _byte_value("WDR enabled", wdr_enabled),
            "struBackLight.byBacklightMode": _byte_value(
                "backlight mode", backlight_mode
            ),
        },
        read_before_write=True,
    )


def ezviz_lan_day_night_get_config_request(
    login_id: int,
    channel: int = 1,
) -> HcNetSdkDvrConfigRequest:
    """Return the local day/night config read request shape."""
    return ezviz_lan_video_effect_get_config_request(login_id, channel=channel)


def ezviz_lan_day_night_update_request(
    login_id: int,
    *,
    day_night_filter_type: int,
    begin_time: int,
    begin_time_min: int,
    begin_time_sec: int,
    end_time: int,
    end_time_min: int,
    end_time_sec: int,
    night_to_day_filter_level: int,
) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN day/night update request shape."""
    return hcnetsdk_dvr_config_set_request(
        login_id,
        HcNetSdkDvrCommand.SET_CAMERA_PARAM_CFG,
        structure="NET_DVR_CAMERAPARAMCFG",
        field_updates={
            "struDayNight.byDayNightFilterType": _byte_value(
                "day/night filter type", day_night_filter_type
            ),
            "struDayNight.byBeginTime": _byte_value("day/night begin hour", begin_time),
            "struDayNight.byBeginTimeMin": _byte_value(
                "day/night begin minute", begin_time_min
            ),
            "struDayNight.byBeginTimeSec": _byte_value(
                "day/night begin second", begin_time_sec
            ),
            "struDayNight.byEndTime": _byte_value("day/night end hour", end_time),
            "struDayNight.byEndTimeMin": _byte_value(
                "day/night end minute", end_time_min
            ),
            "struDayNight.byEndTimeSec": _byte_value(
                "day/night end second", end_time_sec
            ),
            "struDayNight.byNightToDayFilterLevel": _byte_value(
                "night-to-day filter level", night_to_day_filter_level
            ),
        },
        read_before_write=True,
    )


def hcnetsdk_device_ability_xml(
    root: str,
    *,
    channel: int | str | None = None,
    channel_tag: str = "channelNO",
    version: str | None = "2.0",
) -> bytes:
    """Return compact XML passed as ``NET_DVR_GetDeviceAbility`` input."""
    element = ET.Element(_device_ability_xml_name("root", root))
    if version is not None:
        element.set("version", version)
    if channel is not None:
        child = ET.SubElement(
            element,
            _device_ability_xml_name("channel tag", channel_tag),
        )
        child.text = str(channel)
    return ET.tostring(element, encoding="utf-8", short_empty_elements=True)


def hcnetsdk_device_ability_request(
    login_id: int,
    ability_type: int,
    *,
    in_buffer: str | bytes | None = None,
    output_buffer_size: int = HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE,
    retry_output_buffer_size: int | None = (
        HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
    ),
) -> HcNetSdkDeviceAbilityRequest:
    """Return a ``NET_DVR_GetDeviceAbility`` request model."""
    return HcNetSdkDeviceAbilityRequest(
        login_id=login_id,
        ability_type=int(ability_type),
        in_buffer=in_buffer,
        output_buffer_size=output_buffer_size,
        retry_output_buffer_size=retry_output_buffer_size,
    )


def ezviz_lan_record_ability_input() -> bytes:
    """Return the playback conversion ability XML used by ``DeviceAbilityHelper``."""
    return hcnetsdk_device_ability_xml("RecordAbility")


def ezviz_lan_audio_video_compress_info_input(channel: int) -> bytes:
    """Return the stream-config video ability XML used by the APK."""
    return hcnetsdk_device_ability_xml(
        "AudioVideoCompressInfo",
        channel=channel,
        channel_tag="VideoChannelNumber",
        version=None,
    )


def ezviz_lan_ptz_ability_input(channel: int) -> bytes:
    """Return the PTZ ability XML used by ``DeviceAbilityHelper.c``."""
    return hcnetsdk_device_ability_xml("PTZAbility", channel=channel)


def ezviz_lan_image_display_param_ability_input(channel: int) -> bytes:
    """Return the image-display ability XML used by the RN LAN wrapper.

    Live devices may acknowledge this request with an empty body. The image
    parameter ranges used by the app are available through ``IPC_FRONT_PARAMETER``.
    """
    return hcnetsdk_device_ability_xml("ImageDisplayParamAbility", channel=channel)


def ezviz_lan_video_pic_ability_input(channel: int) -> bytes:
    """Return the video-picture ability XML used by the RN LAN wrapper."""
    return hcnetsdk_device_ability_xml("VideoPicAbility", channel=channel)


def ezviz_lan_access_protocol_ability_input(
    channel: int | str = "0xff",
) -> bytes:
    """Return the access-protocol ability XML used by local-add setup."""
    return hcnetsdk_device_ability_xml("AccessProtocolAbility", channel=channel)


def ezviz_lan_rn_device_ability_request(
    login_id: int,
    ability_type: int,
    *,
    in_buffer: str | bytes | None = None,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the generic 2 MiB RN LAN ``NET_DVR_GetDeviceAbility`` shape."""
    return hcnetsdk_device_ability_request(
        login_id,
        ability_type,
        in_buffer=in_buffer,
        output_buffer_size=HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE,
        retry_output_buffer_size=None,
    )


def ezviz_lan_access_protocol_ability_request(
    login_id: int,
    channel: int | str = "0xff",
) -> HcNetSdkDeviceAbilityRequest:
    """Return the access-protocol ability request used by local-add setup."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=ezviz_lan_access_protocol_ability_input(channel),
    )


def ezviz_lan_image_display_param_ability_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN image-display ability request shape.

    Prefer ``ezviz_lan_ipc_front_parameter_ability_request`` for a live
    ``CAMERAPARA`` response containing image parameter ranges.
    """
    return ezviz_lan_rn_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=ezviz_lan_image_display_param_ability_input(channel),
    )


def ezviz_lan_video_pic_ability_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN video-picture ability request shape."""
    return ezviz_lan_rn_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_VIDEOPIC,
        in_buffer=ezviz_lan_video_pic_ability_input(channel),
    )


def ezviz_lan_audio_video_compress_info_ability_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the stream-config audio/video ability request shape."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_ENCODE_ALL_V20,
        in_buffer=ezviz_lan_audio_video_compress_info_input(channel),
    )


def ezviz_lan_soft_hardware_ability_request(
    login_id: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the device software/hardware ability request shape."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_SOFT_HARDWARE,
        in_buffer=None,
    )


def ezviz_lan_record_ability_request(
    login_id: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the record/playback conversion ability request shape."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=ezviz_lan_record_ability_input(),
    )


def ezviz_lan_ptz_ability_request(
    login_id: int,
    channel: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the local PTZ ability request shape used by the Android app."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.DEVICE_ABILITY_INFO,
        in_buffer=ezviz_lan_ptz_ability_input(channel),
    )


def ezviz_lan_ipc_front_parameter_ability_request(
    login_id: int,
) -> HcNetSdkDeviceAbilityRequest:
    """Return the local IPC-front-parameter request used for mirror ability."""
    return hcnetsdk_device_ability_request(
        login_id,
        HcNetSdkAbility.IPC_FRONT_PARAMETER,
        in_buffer=None,
    )


def ezviz_lan_ptz_ability(response: str | bytes) -> EzvizLanPtzAbility:
    """Parse the PTZ ability fields read by EZVIZ's ``PTZAbilityHandler``."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN PTZ ability XML") from err

    return EzvizLanPtzAbility(
        control_types=_xml_opt_attr(root, "controlType"),
        park_action_types=_xml_opt_attr(root, "actionType", parent="ParkAction"),
        schedule_task_types=_xml_opt_attr(root, "actionType", parent="SchduleTask")
        or _xml_opt_attr(root, "actionType", parent="ScheduleTask"),
        privacy_mask_enable=_xml_bool_opt_attr(root, "globalEnable"),
        mirror_range=_xml_child_text(root, ("Mirror", "Range")),
    )


def ezviz_lan_access_protocol_ability(
    response: str | bytes,
) -> EzvizLanAccessProtocolAbility:
    """Parse safe local-add fields from ``AccessProtocolAbility`` XML."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN access-protocol ability XML") from err

    return EzvizLanAccessProtocolAbility(
        channel_no=_xml_descendant_text(root, "channelNO"),
        enable_options=_xml_attr(root, "enable", "opt", parent="EzvizParam"),
        device_status_options=_xml_attr(
            root, "deviceStatus", "opt", parent="EzvizParam"
        ),
        allow_redirect_options=_xml_attr(
            root, "allowRedirect", "opt", parent="EzvizParam"
        ),
        domain_length_min=_xml_attr_int(root, "domainLen", "min", parent="EzvizParam"),
        domain_length_max=_xml_attr_int(root, "domainLen", "max", parent="EzvizParam"),
        has_ezviz_param=_xml_has_descendant(root, "EzvizParam"),
    )


def ezviz_lan_video_pic_ability(response: str | bytes) -> EzvizLanVideoPicAbility:
    """Parse safe OSD/motion fields from ``VideoPicAbility`` XML."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN video-picture ability XML") from err

    return EzvizLanVideoPicAbility(
        channel_no=_xml_descendant_text(root, "channelNO"),
        channel_name_enabled=_xml_descendant_bool_text(
            root, "enabled", parent="ChannelName", default=False
        ),
        week_enabled=_xml_descendant_bool_text(root, "enabled", parent="Week"),
        osd_type_options=_xml_attr(root, "OSDType", "opt", parent="OSD"),
        osd_attribute_options=_xml_attr(root, "OSDAttrib", "opt", parent="OSD"),
        osd_hour_type_options=_xml_attr(root, "OSDHourType", "opt", parent="OSD"),
        motion_region_type_options=_xml_attr(
            root, "regionType", "opt", parent="MotionDetection"
        ),
        motion_grid_row_granularity=_xml_descendant_int(
            root, "rowGranularity", parent="VideoFormatP"
        ),
        motion_grid_column_granularity=_xml_descendant_int(
            root, "columnGranularity", parent="VideoFormatP"
        ),
    )


def ezviz_lan_ipc_front_parameter_ability(
    response: str | bytes,
) -> EzvizLanIpcFrontParameterAbility:
    """Parse safe image/front-parameter ranges from ``CAMERAPARA`` XML."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN IPC front-parameter XML") from err

    field_root = _ipc_front_parameter_field_root(root)
    return EzvizLanIpcFrontParameterAbility(
        has_camera_para=_xml_local_name(root).lower() == "camerapara",
        power_line_frequency_mode_range=_xml_child_text(
            field_root, ("PowerLineFrequencyMode", "Range")
        ),
        white_balance_mode_range=_xml_child_text(
            field_root, ("WhiteBalance", "WhiteBalanceMode", "Range")
        ),
        exposure_mode_range=_xml_child_text(
            field_root, ("Exposure", "ExposureMode", "Range")
        ),
        exposure_set_range=_xml_child_text(
            field_root, ("Exposure", "ExposureSet", "Range")
        ),
        exposure_user_set=_xml_child_int_range(
            field_root, ("Exposure", "exposureUSERSET")
        ),
        gain_level=_xml_child_int_range(field_root, ("GainLevel",)),
        brightness_level=_xml_child_int_range(field_root, ("BrightnessLevel",)),
        contrast_level=_xml_child_int_range(field_root, ("ContrastLevel",)),
        sharpness_level=_xml_child_int_range(field_root, ("SharpnessLevel",)),
        saturation_level=_xml_child_int_range(field_root, ("SaturationLevel",)),
        day_night_filter_type_range=_xml_child_text(
            field_root, ("DayNightFilter", "DayNightFilterType", "Range")
        ),
        switch_schedule_enabled_range=_xml_child_text(
            field_root,
            (
                "DayNightFilter",
                "SwitchSchedule",
                "SwitchScheduleEnabled",
                "Range",
            ),
        ),
        day_to_night_filter_level_range=_xml_child_text(
            field_root,
            (
                "DayNightFilter",
                "SwitchSchedule",
                "DayToNightFilterLevel",
                "Range",
            ),
        ),
        night_to_day_filter_level_range=_xml_child_text(
            field_root,
            (
                "DayNightFilter",
                "SwitchSchedule",
                "NightToDayFilterLevel",
                "Range",
            ),
        ),
        day_night_filter_time=_xml_child_int_range(
            field_root, ("DayNightFilter", "SwitchSchedule", "DayNightFilterTime")
        ),
        backlight_mode_range=_xml_child_text(
            field_root, ("Backlight", "BacklightMode", "Range")
        ),
        mirror_range=_xml_child_text(field_root, ("Mirror", "Range")),
        digital_noise_reduction_enable_range=_xml_child_text(
            field_root,
            ("DigitalNoiseReduction", "DigitalNoiseReductionEnable", "Range"),
        ),
        digital_noise_reduction_level=_xml_child_int_range(
            field_root, ("DigitalNoiseReduction", "DigitalNoiseReductionLevel")
        ),
        digital_noise_spectral_level=_xml_child_int_range(
            field_root, ("DigitalNoiseReduction", "DigitalNoiseSpectralLevel")
        ),
        digital_noise_temporal_level=_xml_child_int_range(
            field_root, ("DigitalNoiseReduction", "DigitalNoiseTemporalLevel")
        ),
    )


def ezviz_lan_audio_video_compress_info(
    response: str | bytes,
) -> EzvizLanAudioVideoCompressInfo:
    """Parse safe stream/audio fields from ``AudioVideoCompressInfo`` XML."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN audio/video compress XML") from err

    video_root = _xml_first_child(root, "VideoCompressInfo")
    audio_root = _xml_first_child(root, "AudioCompressInfo")
    video_channels = (
        _audio_video_compress_video_channels(video_root)
        if video_root is not None
        else ()
    )
    audio_channels: tuple[EzvizLanAudioVideoCompressAudioChannel, ...] = ()
    voice_talk_channels: tuple[EzvizLanAudioVideoCompressVoiceTalkChannel, ...] = ()
    if audio_root is not None:
        audio_section = _xml_first_child(audio_root, "Audio")
        voice_talk_section = _xml_first_child(audio_root, "VoiceTalk")
        if audio_section is not None:
            audio_channels = _audio_video_compress_audio_channels(audio_section)
        if voice_talk_section is not None:
            voice_talk_channels = _audio_video_compress_voice_talk_channels(
                voice_talk_section
            )

    return EzvizLanAudioVideoCompressInfo(
        video_channels=video_channels,
        audio_channels=audio_channels,
        voice_talk_channels=voice_talk_channels,
        has_video_compress_info=video_root is not None,
        has_audio_compress_info=audio_root is not None,
    )


def ezviz_lan_soft_hardware_ability(
    response: str | bytes,
) -> EzvizLanDeviceSoftHardwareAbility:
    """Parse ``DEVICE_SOFTHARDWARE_ABILITY`` fields used by the app."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN soft/hardware ability XML") from err

    has_software = _xml_has_descendant(root, "SoftwareCapability")
    has_hardware = _xml_has_descendant(root, "HardwareCapability")
    return EzvizLanDeviceSoftHardwareAbility(
        max_preview_num=_xml_descendant_int(
            root, "MaxPreviewNum", parent="SoftwareCapability"
        ),
        ptz_support=_xml_descendant_int(root, "PtzSupport", parent="SoftwareCapability"),
        support_timing=_xml_descendant_bool_text(
            root, "isSupportLoginTiming", parent="SoftwareCapability"
        ),
        sd_num=_xml_descendant_int(root, "SDNum", parent="HardwareCapability"),
        hard_disk_num=_xml_descendant_int(
            root, "HardDiskNum", parent="HardwareCapability"
        ),
        has_software_capability=has_software,
        has_hardware_capability=has_hardware,
    )


def ezviz_lan_playback_convert_ability(
    response: str | bytes,
) -> EzvizLanPlaybackConvertAbility:
    """Parse playback conversion entries from ``RecordAbility`` XML."""
    try:
        root = ET.fromstring(_device_ability_response_text(response))
    except ET.ParseError as err:
        raise PyEzvizError("Invalid EZVIZ LAN playback ability XML") from err

    resolutions: list[EzvizLanPlaybackConvertResolution] = []
    for entry in root.iter():
        if _xml_local_name(entry).lower() != "videoresolutionentry":
            continue
        resolutions.append(
            EzvizLanPlaybackConvertResolution(
                index=_xml_descendant_int(entry, "Index"),
                frame_rates=_xml_int_csv(
                    _xml_child_text(entry, ("VideoFrameRate",))
                ),
                bitrates=_xml_int_csv(
                    _xml_child_text(entry, ("VideoBitrate", "Range"))
                ),
            )
        )
    return EzvizLanPlaybackConvertAbility(resolutions=tuple(resolutions))


def ezviz_cas_ptz_command(command: int) -> str:
    """Return the CAS/cloud PTZ command string used by the EZVIZ app."""
    command_id = _ptz_int("EZVIZ PTZ command", command)
    return EZVIZ_CAS_PTZ_COMMAND_MAP.get(command_id, "")


def ezviz_lan_ptz_native_command(command: int) -> int:
    """Return the HCNetSDK LAN PTZ value for an EZVIZ app command ID."""
    command_id = _ptz_int("EZVIZ LAN PTZ command", command)
    native = EZVIZ_LAN_PTZ_COMMAND_MAP.get(command_id)
    if native is None:
        raise PyEzvizError(f"Unsupported EZVIZ LAN PTZ command: {command_id}")
    return native


def ezviz_lan_ptz_is_preset_command(command: int) -> bool:
    """Return whether the app routes this PTZ command through the preset API."""
    command_id = _ptz_int("EZVIZ LAN PTZ command", command)
    return command_id in EZVIZ_LAN_PTZ_PRESET_COMMANDS


def ezviz_lan_ptz_control_request(
    login_id: int,
    channel: int,
    command: int,
    *,
    action: int = EZVIZ_LAN_PTZ_ACTION_START,
    speed: int = EZVIZ_LAN_PTZ_SPEED_DEFAULT,
) -> HcNetSdkPtzControlRequest:
    """Return the APK-observed local PTZ control call for non-preset commands."""
    if ezviz_lan_ptz_is_preset_command(command):
        raise PyEzvizError("Use ezviz_lan_ptz_preset_request for preset commands")
    return HcNetSdkPtzControlRequest(
        login_id=login_id,
        channel=channel,
        command=ezviz_lan_ptz_native_command(command),
        stop=ezviz_lan_ptz_native_command(action),
        speed=speed,
    )


def ezviz_lan_ptz_preset_request(
    login_id: int,
    channel: int,
    command: int,
    *,
    preset_index: int = 0,
) -> HcNetSdkPtzPresetRequest:
    """Return the APK-observed local PTZ preset call shape."""
    if not ezviz_lan_ptz_is_preset_command(command):
        raise PyEzvizError("EZVIZ LAN PTZ command is not a preset command")
    return HcNetSdkPtzPresetRequest(
        login_id=login_id,
        channel=channel,
        command=ezviz_lan_ptz_native_command(command),
        preset_index=preset_index,
    )


def ezviz_lan_ptz_request(
    login_id: int,
    channel: int,
    command: int,
    *,
    action: int = EZVIZ_LAN_PTZ_ACTION_START,
    speed: int = EZVIZ_LAN_PTZ_SPEED_DEFAULT,
    preset_index: int = 0,
) -> HcNetSdkPtzControlRequest | HcNetSdkPtzPresetRequest:
    """Return the same PTZ native-call branch used by ``ptzControlLan``."""
    if ezviz_lan_ptz_is_preset_command(command):
        return ezviz_lan_ptz_preset_request(
            login_id,
            channel,
            command,
            preset_index=preset_index,
        )
    return ezviz_lan_ptz_control_request(
        login_id,
        channel,
        command,
        action=action,
        speed=speed,
    )


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
    """Parse one secret-safe HCNetSDK TCP shape log line.

    These lines contain only metadata, not raw bytes. This parser turns that
    metadata into the same Python shape model used by direct byte
    classification, so captured traces can drive packet-builder tests without
    copying secrets into fixtures.
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
    """Parse one secret-safe HCNetSDK semantic event line."""
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
    """Summarize one mixed HCNetSDK command-shape/semantic trace.

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


def read_hcnetsdk_tcp_frame(sock: Any, *, max_frame_bytes: int | None = None, allow_short_ack: bool = True) -> HcNetSdkTcpFrame:
    """Read one complete HCNetSDK command-port frame from a socket-like object."""
    if max_frame_bytes is not None and max_frame_bytes < HCNETSDK_TCP_HEADER_LENGTH:
        raise PyEzvizError("HCNetSDK frame limit must include the 16-byte header")
    header_bytes = _recv_exact(sock, HCNETSDK_TCP_HEADER_LENGTH)
    total_length = int.from_bytes(header_bytes[0:4], "big")
    if max_frame_bytes is not None and total_length > max_frame_bytes:
        raise PyEzvizError("HCNetSDK response exceeds discovery frame limit")
    if total_length < HCNETSDK_TCP_HEADER_LENGTH:
        if not allow_short_ack:
            raise PyEzvizError("HCNetSDK TCP frame total length is too small")
        header = HcNetSdkTcpFrameHeader(
            total_length=HCNETSDK_TCP_HEADER_LENGTH,
            field_4=int.from_bytes(header_bytes[4:8], "big"),
            field_8=int.from_bytes(header_bytes[8:12], "big"),
            field_12=int.from_bytes(header_bytes[12:16], "big"),
        )
        return HcNetSdkTcpFrame(header=header, body=b"")
    header = parse_hcnetsdk_tcp_frame_header(header_bytes)
    return HcNetSdkTcpFrame(
        header=header,
        body=_recv_exact(sock, header.body_length),
    )


def hcnetsdk_command_port_login_request_frame(
    public_key_der: bytes,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str,
) -> bytes:
    """Build the first port-8000 RSA login frame.

    The native SDK sends a PKCS#1 ``RSAPublicKey`` DER blob, not the longer
    SubjectPublicKeyInfo form returned by many RSA exporters.
    """
    body = (
        _hcnetsdk_command_port_login_prefix(local_ip)
        + _hcnetsdk_command_port_username(username)
        + public_key_der
    )
    return build_hcnetsdk_tcp_frame(
        body,
        field_4=HCNETSDK_COMMAND_PORT_LOGIN_FAMILY,
        field_12=HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12,
    )


def hcnetsdk_command_port_password_digest(
    username: str,
    password: str | bytes,
    password_seed: bytes,
) -> bytes:
    """Return the native SDK SHA-256 password branch for command-port login.

    This is a device-protocol compatibility digest, not password storage.
    """
    password_bytes = password if isinstance(password, bytes) else password.encode()
    if len(password_seed) != HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH:
        raise PyEzvizError("HCNetSDK command-port password seed must be 64 bytes")
    # The command-port handshake requires this SHA-256 branch verbatim.
    digest = hashlib.new("sha256", usedforsecurity=False)
    digest.update(username.encode())
    digest.update(password_seed)
    digest.update(password_bytes)
    return digest.hexdigest().encode()


def _hcnetsdk_command_port_md5_digest(data: bytes = b"") -> Any:
    return hashlib.md5(  # codeql[py/weak-cryptographic-algorithm]
        data,
        usedforsecurity=False,
    )


def _hcnetsdk_command_port_md5_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, _hcnetsdk_command_port_md5_digest).digest()


def hcnetsdk_command_port_login_proof(
    username: str,
    password: str | bytes,
    challenge: bytes,
    password_seed: bytes,
) -> tuple[bytes, bytes]:
    """Return the two proof chunks for the second command-port login frame.

    The native device handshake uses MD5 HMAC branches here for compatibility;
    these values are not persisted password hashes.
    """
    challenge = challenge.rstrip(b"\x00")
    if not challenge:
        raise PyEzvizError("HCNetSDK command-port login challenge is empty")
    password_digest = hcnetsdk_command_port_password_digest(
        username,
        password,
        password_seed,
    )
    # The command-port handshake requires these MD5 HMAC branches verbatim.
    return (
        _hcnetsdk_command_port_md5_hmac(challenge, username.encode()),
        _hcnetsdk_command_port_md5_hmac(challenge, password_digest),
    )


def hcnetsdk_command_port_login_proof_frame(
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    password: str | bytes,
    challenge: bytes,
    password_seed: bytes,
    local_ip: str,
) -> bytes:
    """Build the second port-8000 login proof frame."""
    primary, secondary = hcnetsdk_command_port_login_proof(
        username,
        password,
        challenge,
        password_seed,
    )
    body = (
        _hcnetsdk_command_port_login_prefix(local_ip)
        + primary.ljust(HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH, b"\x00")
        + secondary[:HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH]
    )
    return build_hcnetsdk_tcp_frame(
        body,
        field_4=HCNETSDK_COMMAND_PORT_LOGIN_FAMILY,
        field_12=HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12,
    )


def hcnetsdk_command_port_control_template_from_frame(
    frame: bytes,
    *,
    addend: int | None = None,
    addend_delta: int | None = None,
    auth_seed: int | None = None,
    key: bytes | None = None,
    mask_seed: bytes = b"\x00" * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH,
    body_tail_transform: str | None = None,
    name: str | None = None,
) -> HcNetSdkCommandPortControlTemplate:
    """Extract the reusable command id and body tail from a ``0x63`` frame."""
    parsed = parse_hcnetsdk_tcp_frame(frame)
    if parsed.header.field_4 != HCNETSDK_COMMAND_PORT_CONTROL_FAMILY:
        raise PyEzvizError("HCNetSDK command-port template requires a 0x63 frame")
    if len(parsed.body) < 16:
        raise PyEzvizError("HCNetSDK command-port control body is truncated")
    if parsed.body[8:16] != b"\x00" * 8:
        raise PyEzvizError("HCNetSDK command-port control reserved bytes are invalid")
    if addend is not None and addend_delta is not None:
        raise PyEzvizError(
            "HCNetSDK command-port template cannot set addend and addend_delta"
        )
    if addend is None and addend_delta is None and auth_seed is not None and key is not None:
        session_id = parsed.body[4:8]
        folded = hcnetsdk_command_port_auth_word(
            session_id=session_id,
            auth_seed=auth_seed,
            command_id=parsed.header.field_12,
            key=key,
            addend=0,
            mask_seed=mask_seed,
        )
        inferred_addend = (parsed.header.field_8 - folded) & 0xFFFFFFFF
        addend_delta = (
            inferred_addend - int.from_bytes(session_id, "big")
        ) & 0xFFFFFFFF
    return HcNetSdkCommandPortControlTemplate(
        command_id=parsed.header.field_12,
        body_tail=parsed.body[16:],
        addend=addend,
        addend_delta=addend_delta,
        mask_seed=mask_seed,
        body_tail_transform=body_tail_transform,
        name=name,
    )


def hcnetsdk_command_port_public_key_der(rsa_key: Any) -> bytes:
    """Return PKCS#1 ``RSAPublicKey`` DER for a PyCryptodome RSA key."""
    public_key = rsa_key.publickey() if rsa_key.has_private() else rsa_key
    return bytes(DerSequence([public_key.n, public_key.e]).encode())


def hcnetsdk_command_port_rsa_key() -> Any:
    """Generate the protocol-mandated RSA key for command-port login."""
    # The native SDK handshake requires 1024-bit RSA; larger generated keys are
    # rejected by the device-side command-port login framing.
    return RSA.generate(  # codeql[py/weak-crypto-key]
        HCNETSDK_COMMAND_PORT_RSA_BITS
    )


def decode_hcnetsdk_command_port_login_challenge(
    response: HcNetSdkTcpFrame,
    rsa_key: Any,
) -> HcNetSdkCommandPortLoginChallenge:
    """Decrypt the first command-port login response with the RSA private key."""
    if len(response.body) < (
        HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH
        + HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH
    ):
        raise PyEzvizError("HCNetSDK command-port login challenge response is truncated")
    challenge = PKCS1_v1_5.new(rsa_key).decrypt(
        response.body[:HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH],
        b"",
    )
    if not challenge:
        raise PyEzvizError("HCNetSDK command-port RSA challenge decrypt failed")
    return HcNetSdkCommandPortLoginChallenge(
        response=response,
        challenge=challenge.rstrip(b"\x00"),
        password_seed=response.body[
            HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH : (
                HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH
                + HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH
            )
        ],
    )


def parse_hcnetsdk_command_port_login_session(
    first_response: HcNetSdkTcpFrame,
    second_response: HcNetSdkTcpFrame,
    *,
    challenge: bytes = b"",
    password_seed: bytes = b"",
) -> HcNetSdkCommandPortLoginSession:
    """Parse the successful second command-port login response."""
    if (
        len(second_response.body) < 4
        or second_response.body[:4] == HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID
    ):
        raise PyEzvizError("HCNetSDK command-port login failed")
    return HcNetSdkCommandPortLoginSession(
        session_id=second_response.body[:4],
        auth_seed=second_response.header.field_4,
        serial=second_response.body[4:48].split(b"\x00", 1)[0].decode(
            "ascii",
            errors="ignore",
        ),
        first_response=first_response,
        second_response=second_response,
        challenge=challenge,
        password_seed=password_seed,
    )


def iter_hcnetsdk_tcp_frame_shapes(
    records: Iterable[HcNetSdkTcpShapeLogRecord],
) -> Iterator[HcNetSdkTcpFrameShape]:
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


def build_ezviz_local_stop_preview_request_body(
    *, operation_code: str, session: str | int
) -> bytes:
    """Build the native session-scoped bye; never generate wildcard stops."""
    if (
        isinstance(session, bool)
        or not str(session).isascii()
        or not str(session).isdigit()
        or len(str(session)) > 10
        or not 0 < int(session) <= 0x7FFFFFFF
    ):
        raise PyEzvizError("EZVIZ stop preview requires a positive owned session")
    if not operation_code:
        raise PyEzvizError("EZVIZ stop preview requires supplied operation code")
    return _build_local_sdk_request_xml((("OperationCode", operation_code), ("Session", session)))


class _DeadlineBoundRecvSocket:
    """Apply an absolute deadline and configured timeout to every receive."""

    def __init__(
        self,
        sock: Any,
        *,
        deadline: float,
        configured_timeout: float | None,
        monotonic: Callable[[], float],
    ) -> None:
        self._sock = sock
        self._deadline = deadline
        self._configured_timeout = configured_timeout
        self._monotonic = monotonic
        self.bytes_received = 0

    def recv(self, length: int) -> bytes:
        remaining = self._deadline - self._monotonic()
        if remaining <= 0:
            raise EzvizLocalSdkDeadlineExpired(
                "EZVIZ local SDK frame read exceeded its deadline"
            )
        deadline_limits_receive = (
            self._configured_timeout is None
            or remaining <= self._configured_timeout
        )
        effective_timeout = (
            remaining
            if self._configured_timeout is None
            else min(self._configured_timeout, remaining)
        )
        readable = _wait_for_socket_io(
            self._sock,
            readable=True,
            timeout=effective_timeout,
        )
        if readable is not None:
            if not readable:
                if deadline_limits_receive:
                    raise EzvizLocalSdkDeadlineExpired(
                        "EZVIZ local SDK frame read exceeded its deadline"
                    )
                raise TimeoutError("timed out")
            data = self._sock.recv(length)
            self.bytes_received += len(data)
            return data

        previous_timeout = self._sock.gettimeout()
        self._sock.settimeout(effective_timeout)
        try:
            data = self._sock.recv(length)
        except TimeoutError as err:
            if deadline_limits_receive:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK frame read exceeded its deadline"
                ) from err
            raise
        finally:
            self._sock.settimeout(previous_timeout)
        self.bytes_received += len(data)
        return data


def _wait_for_socket_io(
    sock: Any,
    *,
    readable: bool,
    timeout: float,
) -> bool | None:
    """Wait for real socket readiness without changing its shared timeout."""
    try:
        file_descriptor = sock.fileno()
    except (AttributeError, TypeError):
        return None
    if file_descriptor < 0:
        raise OSError(errno.EBADF, "Bad file descriptor")
    read_list = [sock] if readable else []
    write_list = [] if readable else [sock]
    ready_read, ready_write, _ = select.select(
        read_list,
        write_list,
        [],
        timeout,
    )
    return bool(ready_read if readable else ready_write)


def _remaining_timeout(
    deadline: float | None,
    monotonic: Callable[[], float],
) -> float | None:
    """Return time left before an absolute local-stream deadline."""
    if deadline is None:
        return None
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise EzvizLocalSdkDeadlineExpired(
            "EZVIZ local SDK operation exceeded its deadline"
        )
    return remaining


def _send_all_with_timeout(
    sock: Any,
    data: bytes,
    *,
    timeout: float | None,
    deadline: float | None,
    monotonic: Callable[[], float],
) -> None:
    """Send a frame without letting writes exceed an optional deadline."""
    effective_timeout = (
        _remaining_timeout(deadline, monotonic)
        if deadline is not None
        else timeout
    )
    if effective_timeout is None:
        _send_all(sock, data)
        return
    previous_timeout = sock.gettimeout()
    operation_deadline = (
        deadline if deadline is not None else monotonic() + effective_timeout
    )
    if callable(getattr(sock, "fileno", None)) and _send_all_before_deadline(
            sock,
            data,
            operation_deadline=operation_deadline,
            configured_timeout=previous_timeout,
            capture_deadline=deadline is not None,
            monotonic=monotonic,
        ):
        return

    write_timeout = (
        effective_timeout
        if previous_timeout is None
        else min(previous_timeout, effective_timeout)
    )
    deadline_limits_write = deadline is not None and (
        previous_timeout is None or effective_timeout <= previous_timeout
    )
    sock.settimeout(write_timeout)
    try:
        _send_all(sock, data)
    except TimeoutError as err:
        if deadline_limits_write:
            raise EzvizLocalSdkDeadlineExpired(
                "EZVIZ local SDK frame write exceeded its deadline"
            ) from err
        raise
    finally:
        sock.settimeout(previous_timeout)


def _send_all_before_deadline(
    sock: Any,
    data: bytes,
    *,
    operation_deadline: float,
    configured_timeout: float | None,
    capture_deadline: bool,
    monotonic: Callable[[], float],
) -> bool:
    """Partially send on a real socket while recomputing its deadline."""
    remaining_data = memoryview(data)
    while remaining_data:
        remaining = operation_deadline - monotonic()
        if remaining <= 0:
            if capture_deadline:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK frame write exceeded its deadline"
                )
            raise TimeoutError("timed out")
        write_timeout = (
            remaining
            if configured_timeout is None
            else min(configured_timeout, remaining)
        )
        deadline_limits_write = capture_deadline and (
            configured_timeout is None or remaining <= configured_timeout
        )
        writable = _wait_for_socket_io(
            sock,
            readable=False,
            timeout=write_timeout,
        )
        if writable is None:
            return False
        if not writable:
            if deadline_limits_write:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK frame write exceeded its deadline"
                )
            raise TimeoutError("timed out")
        try:
            sent = sock.send(remaining_data)
        except TimeoutError as err:
            if deadline_limits_write:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK frame write exceeded its deadline"
                ) from err
            raise
        if sent <= 0:
            raise PyEzvizError("Socket closed before EZVIZ frame was sent")
        remaining_data = remaining_data[sent:]
    return True


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
        if command_source_port is not None and not 1 <= command_source_port <= 65535:
            raise PyEzvizError(
                "EZVIZ local SDK command source port must be between 1 and 65535"
            )
        self.command_source_port = command_source_port
        self.command_source_host = command_source_host
        self._command_sock: Any | None = None
        self._stream_sock: Any | None = None
        self._owned_preview: tuple[str, str, int] | None = None
        self._retired_stream_sock: Any | None = None
        self._preview_stopped = False

    def __enter__(self) -> EzvizLocalSdkClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Release this preview best-effort, then close sockets (at most 2s cleanup)."""
        try:
            with suppress(OSError, PyEzvizError):
                self.stop_preview()
        finally:
            for sock in (self._command_sock, self._stream_sock, self._retired_stream_sock):
                if sock is not None:
                    with suppress(OSError):
                        sock.close()
            self._command_sock = None
            self._stream_sock = None
            self._retired_stream_sock = None
            self._preview_stopped = False

    def stop_preview(
        self,
        *,
        timeout: float = EZVIZ_LOCAL_SDK_STOP_TIMEOUT,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizLocalSdkExchange | None:
        """Release only a preview accepted on this client, once, without retries.

        Native SendByeStream uses a fresh command connection. After its ACK,
        drain the stopped media socket to EOF instead of resetting unread data.
        One finite deadline covers connect, send, response and bounded drain.
        """
        if not math.isfinite(timeout) or timeout <= 0:
            raise PyEzvizError("EZVIZ stop preview requires a finite positive timeout")
        owned = self._owned_preview
        self._owned_preview = None
        if owned is None:
            return None
        self._preview_stopped = True
        operation_code, session, sequence = owned
        body = build_ezviz_local_stop_preview_request_body(
            operation_code=operation_code, session=session
        )
        deadline = monotonic() + timeout
        # Do not reuse the preview connection or its bound source port: the
        # camera may already have closed it and the port may be in TIME_WAIT.
        with closing(
            EzvizLocalSdkClient(
                self.endpoint,
                self.device_info,
                timeout=timeout,
                socket_factory=self.socket_factory,
                iv_factory=self.iv_factory,
                response_trailer_length=self.response_trailer_length,
            )
        ) as stop_client:
            exchange = stop_client.send_encrypted_command(
                EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND,
                body,
                sequence=sequence,
                deadline=deadline,
                monotonic=monotonic,
            )
        if exchange.response.header.command != EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE:
            raise PyEzvizError("EZVIZ stop preview returned unexpected command")
        try:
            result = parse_ezviz_local_sdk_xml_fields(exchange.response).get("Result")
        except ET.ParseError as err:
            raise PyEzvizError("EZVIZ stop preview returned malformed XML") from err
        if result != "0":
            raise PyEzvizError("EZVIZ stop preview was not accepted")
        sock = self._stream_sock if self._stream_sock is not None else self._retired_stream_sock
        if sock is not None:
            sock.shutdown(socket.SHUT_WR)
            previous_timeout = sock.gettimeout()
            drained = 0
            try:
                while drained < EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES:
                    sock.settimeout(_remaining_timeout(deadline, monotonic))
                    try:
                        chunk = sock.recv(min(65536, EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES - drained))
                    except TimeoutError as err:
                        raise EzvizLocalSdkDeadlineExpired(
                            "EZVIZ stop preview drain exceeded its deadline"
                        ) from err
                    if not chunk:
                        break
                    drained += len(chunk)
            finally:
                sock.settimeout(previous_timeout)
        return exchange

    def _invalidate_socket(self, sock: Any) -> None:
        """Detach and close a socket whose protocol framing may be corrupt."""
        if self._command_sock is sock:
            self._command_sock = None
        if self._stream_sock is sock:
            self._stream_sock = None
            if self._owned_preview is not None and self._retired_stream_sock is None:
                # A partial frame cannot be parsed again, but closing unread
                # media before the owned stop ACK can strand the camera session.
                # Keep it only for bounded raw teardown, never further parsing.
                self._retired_stream_sock = sock
                return
        with suppress(Exception):
            sock.close()

    def send_encrypted_command(
        self,
        command: int,
        body: bytes | str,
        *,
        sequence: int = 0,
        stream_socket: bool = False,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizLocalSdkExchange:
        """Send one encrypted local SDK frame and read its response frame."""
        effective_timeout = (
            _remaining_timeout(deadline, monotonic)
            if deadline is not None
            else timeout
        )
        sock = (
            self._stream(
                timeout=effective_timeout,
                deadline_limited=deadline is not None,
                deadline=deadline,
                monotonic=monotonic,
            )
            if stream_socket
            else self._command(
                timeout=effective_timeout,
                deadline_limited=deadline is not None,
                deadline=deadline,
                monotonic=monotonic,
            )
        )
        request = build_ezviz_cas_ssl_local_sdk_frame(
            command=command,
            body=body,
            device_info=self.device_info,
            iv=self._request_iv,
            sequence=sequence,
        )
        try:
            _send_all_with_timeout(
                sock,
                request,
                timeout=timeout,
                deadline=deadline,
                monotonic=monotonic,
            )
        except EzvizLocalSdkDeadlineExpired:
            self._invalidate_socket(sock)
            raise
        read_socket = sock
        previous_timeout = None
        if effective_timeout is not None:
            previous_timeout = sock.gettimeout()
            read_socket = _DeadlineBoundRecvSocket(
                sock,
                deadline=(
                    deadline
                    if deadline is not None
                    else monotonic() + effective_timeout
                ),
                configured_timeout=previous_timeout,
                monotonic=monotonic,
            )
        try:
            response = read_ezviz_local_sdk_frame(
                read_socket,
                trailer_length=self.response_trailer_length,
            )
        except EzvizLocalSdkDeadlineExpired:
            self._invalidate_socket(sock)
            raise
        return EzvizLocalSdkExchange(request=request, response=response)

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
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Run the confirmed direct-local setup shape.

        Some app flows send an encrypted 0x2013 pre-start command before the
        0x2011 preview setup. The body source is still caller-owned, so this
        method supports it as an optional supplied frame without trying to
        synthesize unknown fields.
        """
        if (self._owned_preview is not None or self._retired_stream_sock is not None
                or self._preview_stopped):
            raise PyEzvizError("Close this client before starting another owned preview")
        pre_start = None
        if pre_start_body is not None:
            pre_start = self.send_encrypted_command(
                EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
                pre_start_body,
                sequence=pre_start_sequence,
                deadline=deadline,
                monotonic=monotonic,
            )
            if pre_start.response.header.command != EZVIZ_LOCAL_SDK_PRE_START_RESPONSE:
                raise PyEzvizError("EZVIZ local pre-start returned unexpected command")

        preview = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
            preview_body,
            sequence=preview_sequence,
            deadline=deadline,
            monotonic=monotonic,
        )
        if preview.response.header.command != EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE:
            raise PyEzvizError("EZVIZ local preview setup returned unexpected command")

        stream_setup = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
            stream_setup_body,
            sequence=stream_setup_sequence,
            stream_socket=True,
            deadline=deadline,
            monotonic=monotonic,
        )
        if stream_setup.response.header.command != EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE:
            raise PyEzvizError("EZVIZ local stream setup returned unexpected command")

        first_media = (
            self.read_stream_frame_after_prefix(
                max_prefix_bytes=max_prefix_bytes,
                deadline=deadline,
                monotonic=monotonic,
            )
            if read_first_media
            else None
        )
        return EzvizLocalSdkStreamBootstrap(
            preview=preview,
            stream_setup=stream_setup,
            pre_start=pre_start,
            first_media=first_media,
        )

    def bootstrap_preview_from_fields(  # noqa: PLR0913
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
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap preview and build 0x3105 from the 0x2012 Session."""
        if (self._owned_preview is not None or self._retired_stream_sock is not None
                or self._preview_stopped):
            raise PyEzvizError("Close this client before starting another owned preview")
        pre_start = None
        if pre_start_body is not None:
            pre_start = self.send_encrypted_command(
                EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
                pre_start_body,
                sequence=pre_start_sequence,
                deadline=deadline,
                monotonic=monotonic,
            )
            if pre_start.response.header.command != EZVIZ_LOCAL_SDK_PRE_START_RESPONSE:
                raise PyEzvizError("EZVIZ local pre-start returned unexpected command")

        preview = self.send_encrypted_command(
            EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
            preview_request.to_xml(),
            sequence=preview_sequence,
            deadline=deadline,
            monotonic=monotonic,
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

        # Remember only a positive accepted session generated by our structured
        # preview path. Raw caller-owned setup bodies never imply stop authority.
        fields = parse_ezviz_local_sdk_xml_fields(preview.response)
        if (
            fields.get("Result", "0") == "0"
            and session.isascii()
            and session.isdigit()
            and len(session) <= 10
            and 0 < int(session) <= 0x7FFFFFFF
        ):
            self._owned_preview = (
                preview_request.operation_code,
                session,
                (max(preview_sequence, stream_setup_sequence) + 1) & 0xFFFFFFFF,
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
            deadline=deadline,
            monotonic=monotonic,
        )
        if stream_setup.response.header.command != EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE:
            raise PyEzvizError("EZVIZ local stream setup returned unexpected command")

        first_media = (
            self.read_stream_frame_after_prefix(
                max_prefix_bytes=max_prefix_bytes,
                deadline=deadline,
                monotonic=monotonic,
            )
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
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizInterleavedRtpFrameWithPrefix:
        """Read the next local stream frame, tolerating any binary preface."""
        effective_timeout = (
            _remaining_timeout(deadline, monotonic)
            if deadline is not None
            else timeout
        )
        sock = self._stream(
            timeout=effective_timeout,
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        if effective_timeout is None:
            return read_ezviz_interleaved_rtp_frame_after_prefix(
                sock,
                max_prefix_bytes=max_prefix_bytes,
            )

        previous_timeout = sock.gettimeout()
        deadline_socket = _DeadlineBoundRecvSocket(
            sock,
            deadline=(
                deadline if deadline is not None else monotonic() + effective_timeout
            ),
            configured_timeout=previous_timeout,
            monotonic=monotonic,
        )
        try:
            return read_ezviz_interleaved_rtp_frame_after_prefix(
                deadline_socket,
                max_prefix_bytes=max_prefix_bytes,
            )
        except EzvizLocalSdkDeadlineExpired:
            self._invalidate_socket(sock)
            raise

    def _command(
        self,
        *,
        timeout: float | None = None,
        deadline_limited: bool = False,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Any:
        if self._command_sock is None:
            source_address = (
                (self.command_source_host, self.command_source_port)
                if self.command_source_port is not None
                else None
            )
            connect_timeout = self.timeout
            if timeout is not None:
                connect_timeout = (
                    timeout
                    if connect_timeout is None
                    else min(connect_timeout, timeout)
                )
            try:
                command_sock = _connect_with_optional_source_address(
                    self.socket_factory,
                    (self.endpoint.host, self.endpoint.command_port),
                    connect_timeout,
                    source_address=source_address,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except TimeoutError as err:
                if deadline_limited and (
                    self.timeout is None
                    or (timeout is not None and timeout <= self.timeout)
                ):
                    raise EzvizLocalSdkDeadlineExpired(
                        "EZVIZ local SDK command connect exceeded its deadline"
                    ) from err
                raise
            if timeout is not None:
                command_sock.settimeout(self.timeout)
            self._command_sock = command_sock
        return self._command_sock

    def _stream(
        self,
        *,
        timeout: float | None = None,
        deadline_limited: bool = False,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Any:
        if self._retired_stream_sock is not None or self._preview_stopped:
            raise PyEzvizError(
                "EZVIZ media socket was invalidated or stopped; close this client before reopening"
            )
        if self._stream_sock is None:
            connect_timeout = self.timeout
            if timeout is not None:
                connect_timeout = (
                    timeout
                    if connect_timeout is None
                    else min(connect_timeout, timeout)
                )
            try:
                stream_sock = _connect_with_optional_source_address(
                    self.socket_factory,
                    (self.endpoint.host, self.endpoint.stream_port or 0),
                    connect_timeout,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except TimeoutError as err:
                if deadline_limited and (
                    self.timeout is None
                    or (timeout is not None and timeout <= self.timeout)
                ):
                    raise EzvizLocalSdkDeadlineExpired(
                        "EZVIZ local SDK stream connect exceeded its deadline"
                    ) from err
                raise
            if timeout is not None:
                stream_sock.settimeout(self.timeout)
            self._stream_sock = stream_sock
        return self._stream_sock


class _SourcePortConflictError(OSError):
    """An address error known to have occurred after binding the source port."""


def _connect_with_optional_source_address(
    socket_factory: SocketFactory,
    address: tuple[str, int],
    timeout: float | None,
    *,
    source_address: SocketSourceAddress = None,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> Any:
    if source_address is None:
        if socket_factory is socket.create_connection and deadline is not None:
            return _create_deadline_connection(
                address,
                timeout,
                deadline=deadline,
                monotonic=monotonic,
            )
        return socket_factory(address, timeout)
    try:
        if socket_factory is socket.create_connection:
            return _create_reusable_source_connection(
                address,
                timeout,
                source_address=source_address,
                deadline=deadline,
                monotonic=monotonic,
            )
        source_socket_factory = cast(SourceAddressSocketFactory, socket_factory)
        return source_socket_factory(address, timeout, source_address)
    except OSError as err:
        if err.errno == errno.EADDRINUSE or isinstance(
            err,
            _SourcePortConflictError,
        ):
            raise PyEzvizError(
                f"EZVIZ local SDK receiver port {source_address[1]} is already in use"
            ) from err
        raise


def _create_reusable_source_connection(
    address: tuple[str, int],
    timeout: float | None,
    *,
    source_address: tuple[str, int],
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> socket.socket:
    """Connect from an exact source port with platform-safe ownership."""

    last_error: OSError | None = None
    host, port = address
    for family, sock_type, protocol, _, target in _getaddrinfo_before_deadline(
        host,
        port,
        deadline=deadline,
        monotonic=monotonic,
    ):
        try:
            attempt_timeout, deadline_limits_attempt = _connect_attempt_settings(
                timeout,
                deadline=deadline,
                monotonic=monotonic,
            )
            if _WINDOWS_EXCLUSIVE_SOURCE_BIND:
                try:
                    return _connect_bound_source_socket(
                        family,
                        sock_type,
                        protocol,
                        target,
                        attempt_timeout,
                        source_address=source_address,
                        exclusive=True,
                    )
                except OSError as err:
                    if err.errno != errno.EADDRINUSE:
                        raise
                    concrete_source_address = _windows_concrete_source_address(
                        source_address,
                        family,
                        target,
                    )
                    if concrete_source_address == source_address:
                        raise
                    (
                        concrete_timeout,
                        deadline_limits_attempt,
                    ) = _connect_attempt_settings(
                        timeout,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                    return _connect_bound_source_socket(
                        family,
                        sock_type,
                        protocol,
                        target,
                        concrete_timeout,
                        source_address=concrete_source_address,
                        exclusive=True,
                    )
            return _connect_bound_source_socket(
                family,
                sock_type,
                protocol,
                target,
                attempt_timeout,
                source_address=source_address,
                exclusive=False,
            )
        except OSError as err:
            if isinstance(err, TimeoutError) and deadline_limits_attempt:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK connect exceeded its deadline"
                ) from err
            last_error = err

    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo returned no addresses")


def _connect_attempt_settings(
    timeout: float | None,
    *,
    deadline: float | None,
    monotonic: Callable[[], float],
) -> tuple[float | None, bool]:
    """Return the timeout and whether the absolute deadline constrains it."""
    if deadline is None:
        return timeout, False
    remaining = _remaining_timeout(deadline, monotonic)
    assert remaining is not None
    return (
        remaining if timeout is None else min(timeout, remaining),
        timeout is None or remaining <= timeout,
    )


def _create_deadline_connection(
    address: tuple[str, int],
    timeout: float | None,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> socket.socket:
    """Connect to resolved addresses without renewing an absolute deadline."""
    last_error: OSError | None = None
    host, port = address
    for family, sock_type, protocol, _, target in _getaddrinfo_before_deadline(
        host,
        port,
        deadline=deadline,
        monotonic=monotonic,
    ):
        remaining = _remaining_timeout(deadline, monotonic)
        assert remaining is not None
        attempt_timeout = remaining if timeout is None else min(timeout, remaining)
        deadline_limits_attempt = timeout is None or remaining <= timeout
        sock = socket.socket(family, sock_type, protocol)
        try:
            sock.settimeout(attempt_timeout)
            sock.connect(target)
            return sock
        except OSError as err:
            last_error = err
            sock.close()
            if isinstance(err, TimeoutError) and deadline_limits_attempt:
                raise EzvizLocalSdkDeadlineExpired(
                    "EZVIZ local SDK connect exceeded its deadline"
                ) from err
    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo returned no addresses")


def _getaddrinfo_before_deadline(
    host: str, port: int, *, deadline: float | None,
    monotonic: Callable[[], float], resolver: BoundedResolver | None = None,
) -> list[tuple[Any, ...]]:
    """Use the shared bounded resolver, or an explicitly owned injected service."""
    remaining = _remaining_timeout(deadline, monotonic)
    try:
        return (resolver or DEFAULT_RESOLVER).resolve(host, port, timeout=remaining)
    except ResolverBusy as err:
        raise EzvizLocalSdkDeadlineExpired("EZVIZ local SDK hostname resolver is still busy") from err
    except TimeoutError as err:
        raise EzvizLocalSdkDeadlineExpired("EZVIZ local SDK hostname resolution exceeded its deadline") from err


def _connect_bound_source_socket(
    family: int,
    sock_type: int,
    protocol: int,
    target: Any,
    timeout: float | None,
    *,
    source_address: SocketBindAddress,
    exclusive: bool,
) -> socket.socket:
    """Bind and connect one source socket with the requested ownership mode."""

    sock = socket.socket(family, sock_type, protocol)
    try:
        sock.settimeout(timeout)
        if exclusive:
            exclusive_option = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if exclusive_option is None:
                raise PyEzvizError(
                    "Windows does not expose exclusive source-port binding support"
                )
            sock.setsockopt(socket.SOL_SOCKET, exclusive_option, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(source_address)
        try:
            sock.connect(target)
        except OSError as err:
            if err.errno == errno.EADDRNOTAVAIL:
                raise _SourcePortConflictError(err.errno, str(err)) from err
            raise
        if sock.getsockname()[1] != source_address[1]:
            raise PyEzvizError(
                "EZVIZ local SDK receiver port changed while opening the socket"
            )
        return sock
    except Exception:
        sock.close()
        raise


def _windows_concrete_source_address(
    source_address: tuple[str, int],
    family: int,
    target: Any,
) -> SocketBindAddress:
    """Resolve a wildcard source to the interface selected for the target."""

    host, port = source_address
    wildcard_hosts = {"", "::"} if family == socket.AF_INET6 else {"", "0.0.0.0"}
    if host not in wildcard_hosts:
        return source_address
    route_probe = socket.socket(family, socket.SOCK_DGRAM)
    try:
        route_probe.connect(target)
        routed_address = route_probe.getsockname()
        routed_host = str(routed_address[0])
    finally:
        route_probe.close()
    if family == socket.AF_INET6:
        return routed_host, port, int(routed_address[2]), int(routed_address[3])
    return routed_host, port


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


def read_hcnetsdk_command_port_interleaved_frame_after_prefix(
    sock: Any,
    *,
    max_prefix_bytes: int = 4096,
) -> EzvizInterleavedRtpFrameWithPrefix:
    """Read one HCNetSDK command-port interleaved media frame.

    The local stream port uses ``$`` + channel + big-endian payload length.
    Port 8000 uses the same magic byte, but its two length bytes are a
    little-endian total frame length. Keeping this reader separate prevents the
    command-port path from coalescing adjacent media frames.
    """
    if max_prefix_bytes < 0:
        raise PyEzvizError("HCNetSDK command-port prefix limit must be non-negative")

    prefix = bytearray()
    while True:
        byte = _recv_exact(sock, 1)
        if byte[0] == EZVIZ_RTP_INTERLEAVED_MAGIC:
            header_tail = _recv_exact(sock, 3)
            total_length = int.from_bytes(header_tail[1:3], "little")
            if total_length < 4:
                raise PyEzvizError(
                    "HCNetSDK command-port interleaved frame length is invalid"
                )
            payload_length = total_length - 4
            return EzvizInterleavedRtpFrameWithPrefix(
                prefix=bytes(prefix),
                frame=EzvizInterleavedRtpFrame(
                    header=EzvizInterleavedRtpFrameHeader(
                        channel=header_tail[0],
                        payload_length=payload_length,
                    ),
                    payload=_recv_exact(sock, payload_length),
                ),
            )

        prefix.extend(byte)
        if len(prefix) > max_prefix_bytes:
            raise PyEzvizError(
                "HCNetSDK command-port prefix exceeded limit before frame magic"
            )


class HcNetSdkCommandPortClient:
    """Small native-Python client for HCNetSDK command-port media framing."""

    def __init__(
        self,
        endpoint: HcNetSdkLanEndpoint,
        *,
        timeout: float | None = 10.0,
        socket_factory: SocketFactory = socket.create_connection,
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.socket_factory = socket_factory
        self._socket: Any | None = None
        self._state_lock = Lock()
        self._read_lock = Lock()
        self._write_lock = Lock()
        self._allow_reconnect = True

    def __enter__(self) -> HcNetSdkCommandPortClient:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def sock(self) -> Any:
        """Return the connected socket, opening it lazily."""
        return self.connect()

    @property
    def connected(self) -> bool:
        """Return whether a command-port socket is currently attached."""
        with self._state_lock:
            return self._socket is not None

    def connect(
        self,
        *,
        timeout: float | None = None,
        deadline_limited: bool = False,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Any:
        """Open the command-port TCP socket if needed."""
        with self._state_lock:
            existing_socket = self._socket
            if existing_socket is not None:
                return existing_socket
            if not self._allow_reconnect:
                raise PyEzvizError("HCNetSDK command-port client is shut down")
        if existing_socket is None:
            connect_timeout = self.timeout
            if timeout is not None:
                connect_timeout = (
                    timeout
                    if connect_timeout is None
                    else min(connect_timeout, timeout)
                )
            try:
                command_sock = _connect_with_optional_source_address(
                    self.socket_factory,
                    (self.endpoint.host, self.endpoint.command_port),
                    connect_timeout,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except TimeoutError as err:
                if deadline_limited and (
                    self.timeout is None
                    or (timeout is not None and timeout <= self.timeout)
                ):
                    raise EzvizLocalSdkDeadlineExpired(
                        "HCNetSDK command-port connect exceeded its deadline"
                    ) from err
                raise
            if timeout is not None:
                command_sock.settimeout(self.timeout)
            with self._state_lock:
                if not self._allow_reconnect:
                    with suppress(Exception):
                        command_sock.close()
                    raise PyEzvizError("HCNetSDK command-port client is shut down")
                if self._socket is None:
                    self._socket = command_sock
                    return command_sock
                existing_socket = self._socket
            with suppress(Exception):
                command_sock.close()
            return existing_socket
        raise AssertionError("unreachable command-port connection state")

    def close(self) -> None:
        """Close the command-port socket."""
        with self._state_lock:
            command_sock = self._socket
            self._socket = None
        if command_sock is None:
            return
        with suppress(Exception):
            command_sock.close()

    def shutdown(self) -> None:
        """Close the socket and permanently reject lazy reconnection."""
        with self._state_lock:
            self._allow_reconnect = False
            command_sock = self._socket
            self._socket = None
        if command_sock is not None:
            with suppress(Exception):
                command_sock.close()

    def _invalidate_socket(self, sock: Any) -> None:
        """Detach and close a socket whose protocol framing may be corrupt."""
        with self._state_lock:
            if self._socket is sock:
                self._socket = None
        with suppress(Exception):
            sock.close()

    def send_command_frame(
        self,
        frame: bytes,
        *,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Send one complete command-port frame."""
        with self._write_lock:
            self._send_command_frame_unlocked(
                frame,
                timeout=timeout,
                deadline=deadline,
                monotonic=monotonic,
            )

    def _send_command_frame_unlocked(
        self,
        frame: bytes,
        *,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        effective_timeout = (
            _remaining_timeout(deadline, monotonic)
            if deadline is not None
            else timeout
        )
        sock = self.connect(
            timeout=effective_timeout,
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        try:
            _send_all_with_timeout(
                sock,
                frame,
                timeout=timeout,
                deadline=deadline,
                monotonic=monotonic,
            )
        except EzvizLocalSdkDeadlineExpired:
            self._invalidate_socket(sock)
            raise

    def read_tcp_frame(
        self,
        *,
        max_frame_bytes: int | None = None,
        allow_short_ack: bool = True,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkTcpFrame:
        """Read one non-media command-port response frame."""
        with self._read_lock:
            return self._read_tcp_frame_unlocked(
                max_frame_bytes=max_frame_bytes,
                allow_short_ack=allow_short_ack,
                timeout=timeout,
                deadline=deadline,
                monotonic=monotonic,
            )

    def _read_tcp_frame_unlocked(
        self,
        *,
        max_frame_bytes: int | None = None,
        allow_short_ack: bool = True,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkTcpFrame:
        effective_timeout = (
            _remaining_timeout(deadline, monotonic)
            if deadline is not None
            else timeout
        )
        sock = self.connect(
            timeout=effective_timeout,
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        if effective_timeout is None:
            try:
                return read_hcnetsdk_tcp_frame(sock, max_frame_bytes=max_frame_bytes, allow_short_ack=allow_short_ack)
            except PyEzvizError:
                if max_frame_bytes is not None or not allow_short_ack:
                    self._invalidate_socket(sock)
                raise
        previous_timeout = sock.gettimeout()
        deadline_socket = _DeadlineBoundRecvSocket(
            sock,
            deadline=(
                deadline if deadline is not None else monotonic() + effective_timeout
            ),
            configured_timeout=previous_timeout,
            monotonic=monotonic,
        )
        try:
            return read_hcnetsdk_tcp_frame(deadline_socket, max_frame_bytes=max_frame_bytes, allow_short_ack=allow_short_ack)
        except EzvizLocalSdkDeadlineExpired:
            self._invalidate_socket(sock)
            raise
        except PyEzvizError:
            if max_frame_bytes is not None or not allow_short_ack:
                self._invalidate_socket(sock)
            raise

    def read_media_frame_after_prefix(
        self,
        *,
        max_prefix_bytes: int = 4096,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        invalidate_on_deadline: bool = True,
    ) -> EzvizInterleavedRtpFrameWithPrefix:
        """Read the next command-port media frame."""
        with self._read_lock:
            return self._read_media_frame_after_prefix_unlocked(
                max_prefix_bytes=max_prefix_bytes,
                timeout=timeout,
                deadline=deadline,
                monotonic=monotonic,
                invalidate_on_deadline=invalidate_on_deadline,
            )

    def _read_media_frame_after_prefix_unlocked(
        self,
        *,
        max_prefix_bytes: int = 4096,
        timeout: float | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        invalidate_on_deadline: bool = True,
    ) -> EzvizInterleavedRtpFrameWithPrefix:
        effective_timeout = (
            _remaining_timeout(deadline, monotonic)
            if deadline is not None
            else timeout
        )
        sock = self.connect(
            timeout=effective_timeout,
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        if effective_timeout is None:
            return read_hcnetsdk_command_port_interleaved_frame_after_prefix(
                sock,
                max_prefix_bytes=max_prefix_bytes,
            )

        previous_timeout = sock.gettimeout()
        deadline_socket = _DeadlineBoundRecvSocket(
            sock,
            deadline=(
                deadline if deadline is not None else monotonic() + effective_timeout
            ),
            configured_timeout=previous_timeout,
            monotonic=monotonic,
        )
        try:
            return read_hcnetsdk_command_port_interleaved_frame_after_prefix(
                deadline_socket,
                max_prefix_bytes=max_prefix_bytes,
            )
        except EzvizLocalSdkDeadlineExpired:
            if invalidate_on_deadline or deadline_socket.bytes_received:
                self._invalidate_socket(sock)
            raise

    def login(
        self,
        *,
        password: str | bytes,
        username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
        local_ip: str | None = None,
        rsa_key: Any | None = None,
        max_frame_bytes: int | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortLoginSession:
        """Run the generated RSA/challenge command-port login handshake."""
        if deadline is not None and rsa_key is None:
            raise PyEzvizError(
                "Deadline-aware HCNetSDK command-port login requires a "
                "pre-generated rsa_key"
            )
        sock = self.connect(
            timeout=_remaining_timeout(deadline, monotonic),
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        if local_ip is None:
            try:
                local_ip = str(sock.getsockname()[0])
            except (AttributeError, OSError, TypeError) as err:
                raise PyEzvizError(
                    "HCNetSDK command-port login requires local_ip when the "
                    "socket does not expose getsockname()"
                ) from err

        key = rsa_key if rsa_key is not None else hcnetsdk_command_port_rsa_key()
        self.send_command_frame(
            hcnetsdk_command_port_login_request_frame(
                hcnetsdk_command_port_public_key_der(key),
                username=username,
                local_ip=local_ip,
            ),
            deadline=deadline,
            monotonic=monotonic,
        )
        first_response = self.read_tcp_frame(
            max_frame_bytes=max_frame_bytes,
            deadline=deadline,
            monotonic=monotonic,
        )
        challenge = decode_hcnetsdk_command_port_login_challenge(first_response, key)
        self.send_command_frame(
            hcnetsdk_command_port_login_proof_frame(
                username=username,
                password=password,
                challenge=challenge.challenge,
                password_seed=challenge.password_seed,
                local_ip=local_ip,
            ),
            deadline=deadline,
            monotonic=monotonic,
        )
        second_response = self.read_tcp_frame(
            max_frame_bytes=max_frame_bytes,
            deadline=deadline,
            monotonic=monotonic,
        )
        return parse_hcnetsdk_command_port_login_session(
            first_response,
            second_response,
            challenge=challenge.challenge,
            password_seed=challenge.password_seed,
        )

    def bootstrap_media_stream(
        self,
        command_frames: Iterable[bytes],
        *,
        read_response_after_each: bool | Iterable[bool] = True,
        read_first_media: bool = True,
        max_prefix_bytes: int = 4096,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortStreamBootstrap:
        """Send command frames and optionally read the first media frame."""
        frames = tuple(command_frames)
        response_flags: tuple[bool, ...] | None
        if isinstance(read_response_after_each, bool):
            response_flags = None
        else:
            response_flags = tuple(read_response_after_each)
            if len(response_flags) != len(frames):
                raise PyEzvizError(
                    "HCNetSDK response-read policy length must match command frames"
                )

        exchanges: list[HcNetSdkCommandPortExchange] = []
        for index, frame in enumerate(frames):
            self.send_command_frame(
                frame,
                deadline=deadline,
                monotonic=monotonic,
            )
            should_read = (
                read_response_after_each if response_flags is None else response_flags[index]
            )
            response = (
                self.read_tcp_frame(
                    deadline=deadline,
                    monotonic=monotonic,
                )
                if should_read
                else None
            )
            exchanges.append(HcNetSdkCommandPortExchange(frame, response))

        first_media = (
            self.read_media_frame_after_prefix(
                max_prefix_bytes=max_prefix_bytes,
                deadline=deadline,
                monotonic=monotonic,
            )
            if read_first_media
            else None
        )
        return HcNetSdkCommandPortStreamBootstrap(
            exchanges=tuple(exchanges),
            first_media=first_media,
        )


def hcnetsdk_device_ability_command_port_body_tail(
    request: HcNetSdkDeviceAbilityRequest,
) -> bytes:
    """Return the pure command-port tail for ``NET_DVR_GetDeviceAbility``."""
    if request.ability_type < 0:
        raise PyEzvizError("HCNetSDK device ability type must be non-negative")
    return int(request.ability_type).to_bytes(4, "big") + request.in_buffer_bytes


def hcnetsdk_device_ability_command_port_template(
    request: HcNetSdkDeviceAbilityRequest,
    *,
    addend_delta: int | None = 0,
    addend: int | None = None,
    name: str | None = None,
) -> HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_GetDeviceAbility``."""
    return HcNetSdkCommandPortControlTemplate(
        command_id=0x11000,
        body_tail=hcnetsdk_device_ability_command_port_body_tail(request),
        addend=addend,
        addend_delta=addend_delta,
        name=name or HCNETSDK_GET_DEVICE_ABILITY,
    )


def hcnetsdk_dvr_config_command_port_template(
    request: HcNetSdkDvrConfigRequest,
    *,
    command_id: int | None = None,
    body_tail: bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    name: str | None = None,
) -> HcNetSdkCommandPortControlTemplate:
    """Return a traced command-port template for ``NET_DVR_GetDVRConfig``.

    ``NET_DVR_GetDVRConfig`` does not carry the public SDK ``dwCommand`` value
    directly on the wire. Native traces show each config surface dispatching to
    a device-protocol command id, so unknown config commands must be supplied
    explicitly until traced.
    """
    request.to_native_args_hint()
    if request.api != HCNETSDK_GET_DVR_CONFIG:
        raise PyEzvizError("Pure command-port DVR config currently supports GET only")
    protocol_command = command_id
    if protocol_command is None:
        protocol_command = HCNETSDK_DVR_CONFIG_COMMAND_PORT_COMMAND_IDS.get(
            int(request.command)
        )
    if protocol_command is None:
        raise PyEzvizError(
            "HCNetSDK DVR config command-port id is unknown for "
            f"dwCommand {int(request.command)}"
        )
    if protocol_command < 0:
        raise PyEzvizError("HCNetSDK DVR config command-port id must be non-negative")
    command_tail = body_tail
    if command_tail is None:
        command_tail = hcnetsdk_dvr_config_command_port_body_tail(request)

    return HcNetSdkCommandPortControlTemplate(
        command_id=protocol_command,
        body_tail=command_tail,
        addend=addend,
        addend_delta=addend_delta,
        name=name or f"{HCNETSDK_GET_DVR_CONFIG}:{int(request.command)}",
    )


def hcnetsdk_dvr_config_command_port_body_tail(
    request: HcNetSdkDvrConfigRequest,
) -> bytes:
    """Return the traced command-port body tail for a DVR config request."""
    if int(request.command) == HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG:
        if request.channel != 1:
            raise PyEzvizError(
                "HCNetSDK camera-param command-port read is traced for channel 1"
            )
        return b""
    if int(request.command) not in HCNETSDK_DVR_CONFIG_CHANNEL_TAIL_COMMANDS:
        return b""
    if request.channel < 0:
        raise PyEzvizError(
            "HCNetSDK DVR config command-port channel tail requires a channel"
        )
    if request.channel > 0xFFFFFFFF:
        raise PyEzvizError("HCNetSDK DVR config command-port channel is too large")
    return int(request.channel).to_bytes(4, "big")


def hcnetsdk_stdxml_config_command_port_body_tail(
    request: HcNetSdkStdXmlConfigRequest | str | bytes,
) -> bytes:
    """Return the traced command-port tail for ``NET_DVR_STDXMLConfig``.

    A live Android SDK trace showed STDXML using the generated command-port
    control frame with command ``0x117000``, eight extra reserved bytes, a
    twelve-byte request descriptor, and then the request/in-buffer bytes.
    """
    config = (
        request
        if isinstance(request, HcNetSdkStdXmlConfigRequest)
        else hcnetsdk_stdxml_config_request(request)
    )
    payload = config.request_bytes + config.in_buffer_bytes
    total_length = HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE + len(payload)
    return b"".join(
        (
            b"\x00" * HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE,
            total_length.to_bytes(4, "big"),
            len(config.request_bytes).to_bytes(4, "big"),
            HCNETSDK_STDXML_COMMAND_PORT_FLAGS,
            payload,
        )
    )


def hcnetsdk_stdxml_config_command_port_template(
    request: HcNetSdkStdXmlConfigRequest | str | bytes,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    name: str | None = None,
) -> HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_STDXMLConfig``."""
    config = (
        request
        if isinstance(request, HcNetSdkStdXmlConfigRequest)
        else hcnetsdk_stdxml_config_request(request)
    )
    if command_id < 0:
        raise PyEzvizError("HCNetSDK STDXML command id must be non-negative")
    if body_prefix is None:
        body_tail = hcnetsdk_stdxml_config_command_port_body_tail(config)
    else:
        body_tail = _stdxml_bytes("command-port body prefix", body_prefix)
        body_tail += config.request_bytes
        body_tail += config.in_buffer_bytes
    return HcNetSdkCommandPortControlTemplate(
        command_id=command_id,
        body_tail=body_tail,
        addend=addend,
        addend_delta=addend_delta,
        name=name or HCNETSDK_STDXML_CONFIG,
    )


def hcnetsdk_command_port_execute_template(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    template: HcNetSdkCommandPortControlTemplate,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> HcNetSdkCommandPortControlResponse:
    """Execute one generated command-port control template in pure Python.

    The EZVIZ devices tested so far accept this pattern for local capability
    reads: perform the RSA login on one socket, close it, then send the
    authenticated control command on a fresh command-port socket.
    """
    with HcNetSdkCommandPortClient(
        endpoint,
        timeout=timeout,
        socket_factory=socket_factory,
    ) as login_client:
        actual_local_ip = local_ip
        if actual_local_ip is None:
            try:
                actual_local_ip = str(login_client.sock.getsockname()[0])
            except (AttributeError, OSError, TypeError) as err:
                raise PyEzvizError(
                    "HCNetSDK command-port control requires local_ip when the "
                    "socket does not expose getsockname()"
                ) from err
        login_session = login_client.login(
            password=password,
            username=username,
            local_ip=actual_local_ip,
            rsa_key=rsa_key,
        )

    request = template.to_frame(
        session_id=login_session.session_id,
        auth_seed=login_session.auth_seed,
        key=login_session.challenge,
        local_ip=actual_local_ip,
    )
    with HcNetSdkCommandPortClient(
        endpoint,
        timeout=timeout,
        socket_factory=socket_factory,
    ) as control_client:
        control_client.send_command_frame(request)
        response = control_client.read_tcp_frame()
    return HcNetSdkCommandPortControlResponse(
        login_session=login_session,
        request=request,
        response=response,
    )


def hcnetsdk_get_device_ability_command_port(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    request: HcNetSdkDeviceAbilityRequest,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> bytes:
    """Read ``NET_DVR_GetDeviceAbility`` through the pure command-port path."""
    response = hcnetsdk_command_port_execute_template(
        endpoint,
        password,
        hcnetsdk_device_ability_command_port_template(request),
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    return response.output


def hcnetsdk_get_dvr_config_command_port(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    request: HcNetSdkDvrConfigRequest,
    *,
    command_id: int | None = None,
    body_tail: bytes | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> bytes:
    """Read a traced ``NET_DVR_GetDVRConfig`` output buffer in pure Python."""
    response = hcnetsdk_command_port_execute_template(
        endpoint,
        password,
        hcnetsdk_dvr_config_command_port_template(
            request,
            command_id=command_id,
            body_tail=body_tail,
        ),
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    return response.response.body


def hcnetsdk_stdxml_config_command_port(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    request: HcNetSdkStdXmlConfigRequest | str | bytes,
    template: HcNetSdkCommandPortControlTemplate,
    *,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> HcNetSdkStdXmlConfigResponse:
    """Execute a traced ``NET_DVR_STDXMLConfig`` command in pure Python."""
    config = (
        request
        if isinstance(request, HcNetSdkStdXmlConfigRequest)
        else hcnetsdk_stdxml_config_request(request)
    )
    if not config.request_bytes:
        raise PyEzvizError("HCNetSDK STDXML request must not be empty")
    response = hcnetsdk_command_port_execute_template(
        endpoint,
        password,
        template,
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )
    output = response.output
    return HcNetSdkStdXmlConfigResponse(
        succeeded=bool(output),
        output=output,
        returned_xml_size=len(output),
    )


def hcnetsdk_stdxml_config_command_port_from_trace(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    request: HcNetSdkStdXmlConfigRequest | str | bytes,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    name: str | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> HcNetSdkStdXmlConfigResponse:
    """Execute traced ``NET_DVR_STDXMLConfig`` through pure command-port IO."""
    config = (
        request
        if isinstance(request, HcNetSdkStdXmlConfigRequest)
        else hcnetsdk_stdxml_config_request(request)
    )
    template = hcnetsdk_stdxml_config_command_port_template(
        config,
        command_id=command_id,
        body_prefix=body_prefix,
        addend_delta=addend_delta,
        addend=addend,
        name=name,
    )
    return hcnetsdk_stdxml_config_command_port(
        endpoint,
        password,
        config,
        template,
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )


def hcnetsdk_stdxml_isapi_command_port(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    method: str,
    path: str,
    body: Mapping[str, Any] | str | bytes | None = None,
    *,
    command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
    body_prefix: str | bytes | None = None,
    addend_delta: int | None = 0,
    addend: int | None = None,
    name: str | None = None,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
) -> HcNetSdkStdXmlConfigResponse:
    """Execute a generic ISAPI request through pure command-port STDXML."""
    request = hcnetsdk_stdxml_isapi_request(method, path, body)
    return hcnetsdk_stdxml_config_command_port_from_trace(
        endpoint,
        password,
        request,
        command_id=command_id,
        body_prefix=body_prefix,
        addend_delta=addend_delta,
        addend=addend,
        name=name or f"{method.strip().upper()} {path}",
        username=username,
        local_ip=local_ip,
        timeout=timeout,
        socket_factory=socket_factory,
        rsa_key=rsa_key,
    )


class HcNetSdkPurePythonClient:
    """Pure command-port HCNetSDK-compatible client with no native SDK library."""

    def __init__(
        self,
        endpoint: HcNetSdkLanEndpoint,
        password: str | bytes,
        *,
        username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
        local_ip: str | None = None,
        timeout: float | None = 10.0,
        socket_factory: SocketFactory = socket.create_connection,
        rsa_key: Any | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.password = password
        self.username = username
        self.local_ip = local_ip
        self.timeout = timeout
        self.socket_factory = socket_factory
        self.rsa_key = rsa_key

    def execute_template(
        self,
        template: HcNetSdkCommandPortControlTemplate,
    ) -> HcNetSdkCommandPortControlResponse:
        """Execute one generated command-port template."""
        return hcnetsdk_command_port_execute_template(
            self.endpoint,
            self.password,
            template,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def device_ability(self, request: HcNetSdkDeviceAbilityRequest) -> bytes:
        """Read ``NET_DVR_GetDeviceAbility`` through pure Python command-port IO."""
        return hcnetsdk_get_device_ability_command_port(
            self.endpoint,
            self.password,
            request,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def access_protocol_ability(
        self,
        channel: int | str = "0xff",
    ) -> EzvizLanAccessProtocolAbility:
        """Read and parse local ``AccessProtocolAbility`` output."""
        return ezviz_lan_access_protocol_ability(
            self.device_ability(ezviz_lan_access_protocol_ability_request(1, channel))
        )

    def video_pic_ability(self, channel: int = 1) -> EzvizLanVideoPicAbility:
        """Read and parse local ``VideoPicAbility`` output."""
        return ezviz_lan_video_pic_ability(
            self.device_ability(ezviz_lan_video_pic_ability_request(1, channel))
        )

    def audio_video_compress_info(
        self,
        channel: int = 1,
    ) -> EzvizLanAudioVideoCompressInfo:
        """Read and parse local ``AudioVideoCompressInfo`` output."""
        return ezviz_lan_audio_video_compress_info(
            self.device_ability(
                ezviz_lan_audio_video_compress_info_ability_request(1, channel)
            )
        )

    def ipc_front_parameter_ability(self) -> EzvizLanIpcFrontParameterAbility:
        """Read and parse local ``IPC_FRONT_PARAMETER`` image ranges."""
        return ezviz_lan_ipc_front_parameter_ability(
            self.device_ability(ezviz_lan_ipc_front_parameter_ability_request(1))
        )

    def image_display_param_ability(self) -> EzvizLanIpcFrontParameterAbility:
        """Read image-display ranges through the live-backed front-parameter path."""
        return self.ipc_front_parameter_ability()

    def soft_hardware_ability(self) -> EzvizLanDeviceSoftHardwareAbility:
        """Read and parse local device software/hardware ability output."""
        return ezviz_lan_soft_hardware_ability(
            self.device_ability(ezviz_lan_soft_hardware_ability_request(1))
        )

    def playback_convert_ability(self) -> EzvizLanPlaybackConvertAbility:
        """Read and parse local playback conversion ability output."""
        return ezviz_lan_playback_convert_ability(
            self.device_ability(ezviz_lan_record_ability_request(1))
        )

    def ptz_ability(self, channel: int = 1) -> EzvizLanPtzAbility:
        """Read and parse local PTZ ability output."""
        return ezviz_lan_ptz_ability(
            self.device_ability(ezviz_lan_ptz_ability_request(1, channel))
        )

    def dvr_config(
        self,
        request: HcNetSdkDvrConfigRequest,
        *,
        command_id: int | None = None,
        body_tail: bytes | None = None,
    ) -> bytes:
        """Read a traced ``NET_DVR_GetDVRConfig`` buffer through command-port IO."""
        return hcnetsdk_get_dvr_config_command_port(
            self.endpoint,
            self.password,
            request,
            command_id=command_id,
            body_tail=body_tail,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def wifi_ap_info_list(self) -> tuple[EzvizLanWifiApInfo, ...]:
        """Read and parse traced ``NET_DVR_AP_INFO_LIST`` output."""
        return ezviz_lan_wifi_ap_info_list(
            self.dvr_config(ezviz_lan_wifi_ap_info_list_request(1))
        )

    def hd_config(self) -> EzvizLanHdConfig:
        """Read and parse traced ``NET_DVR_HDCFG`` output."""
        return ezviz_lan_hd_config(self.dvr_config(ezviz_lan_hd_config_request(1)))

    def time_config(self) -> HcNetSdkTime:
        """Read and parse traced ``NET_DVR_TIME`` output."""
        return ezviz_lan_time_config(
            self.dvr_config(ezviz_lan_time_get_config_request(1))
        )

    def ntp_config(self) -> EzvizLanNtpConfig:
        """Read and parse traced ``NET_DVR_NTPPARA`` output."""
        return ezviz_lan_ntp_config(
            self.dvr_config(ezviz_lan_ntp_get_config_request(1))
        )

    def device_config_v40(self) -> EzvizLanDeviceConfigV40:
        """Read and parse traced ``NET_DVR_DEVICECFG_V40`` output."""
        return ezviz_lan_device_config_v40(
            self.dvr_config(ezviz_lan_device_config_v40_request(1))
        )

    def net_config_v30(self) -> EzvizLanNetConfigV30:
        """Read and parse traced ``NET_DVR_NETCFG_V30`` output."""
        return ezviz_lan_net_config_v30(
            self.dvr_config(ezviz_lan_net_config_v30_request(1))
        )

    def record_config_v30(self, channel: int = 1) -> EzvizLanRecordConfigV30:
        """Read and parse traced ``NET_DVR_RECORD_V30`` output."""
        return ezviz_lan_record_config_v30(
            self.dvr_config(ezviz_lan_record_config_v30_request(1, channel=channel))
        )

    def camera_param_config(self, channel: int = 1) -> EzvizLanCameraParamConfig:
        """Read and parse traced ``NET_DVR_CAMERAPARAMCFG`` output."""
        if channel != 1:
            raise PyEzvizError(
                "EZVIZ LAN camera-param pure read is traced for channel 1"
            )
        return ezviz_lan_camera_param_config(
            self.dvr_config(ezviz_lan_video_effect_get_config_request(1, channel))
        )

    def wifi_connect_status(self, channel: int = 0) -> EzvizLanWifiConnectStatus:
        """Read and parse traced ``NET_DVR_WIFI_CONNECT_STATUS`` output."""
        return ezviz_lan_wifi_connect_status(
            self.dvr_config(ezviz_lan_wifi_connect_status_request(1, channel=channel))
        )

    def audio_input_param(self, channel: int = 1) -> EzvizLanAudioInputParam:
        """Read and parse traced ``NET_DVR_AUDIO_INPUT_PARAM`` output."""
        return ezviz_lan_audio_input_param(
            self.dvr_config(ezviz_lan_audio_input_get_config_request(1, channel))
        )

    def audioout_volume(self, channel: int = 1) -> EzvizLanAudioOutputVolume:
        """Read and parse traced ``NET_DVR_AUDIOOUT_VOLUME`` output."""
        return ezviz_lan_audio_output_volume(
            self.dvr_config(ezviz_lan_audioout_volume_get_config_request(1, channel))
        )

    def stream_details(self, channel: int = 1) -> HcNetSdkStreamDetails:
        """Read current compression and per-resolution abilities without cloud IO."""
        return discover_hcnetsdk_stream_details(
            self.endpoint, self.password, channel=channel, username=self.username,
            local_ip=self.local_ip, timeout=self.timeout, socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def compression_config(self, channel: int = 1) -> EzvizLanCompressionConfig:
        """Read and parse traced ``NET_DVR_COMPRESSIONCFG_V30`` output."""
        return ezviz_lan_compression_config(
            self.dvr_config(ezviz_lan_video_coding_get_config_request(1, channel))
        )

    def picture_config(self, channel: int = 1) -> EzvizLanPictureConfig:
        """Read and parse traced ``NET_DVR_PICCFG_V40`` output."""
        return ezviz_lan_picture_config(
            self.dvr_config(ezviz_lan_pic_config_get_request(1, channel))
        )

    def picture_config_v30(self, channel: int = 1) -> EzvizLanPictureConfig:
        """Read and parse traced legacy ``NET_DVR_PICCFG_V30`` output."""
        return ezviz_lan_picture_config(
            self.dvr_config(ezviz_lan_pic_config_v30_get_request(1, channel))
        )

    def wifi_config_summary(self) -> EzvizLanDvrConfigSummary:
        """Read a traced ``NET_DVR_WIFI_CFG`` buffer as a non-secret summary."""
        return ezviz_lan_wifi_config_summary(
            self.dvr_config(ezviz_lan_wifi_get_config_request(1))
        )

    def ezviz_access_config_summary(self) -> EzvizLanDvrConfigSummary:
        """Read traced EZVIZ access config as a non-secret summary."""
        return ezviz_lan_ezviz_access_config_summary(
            self.dvr_config(ezviz_lan_ezviz_access_get_config_request(1))
        )

    def ezviz_access_config(self) -> EzvizLanEzvizAccessConfig:
        """Read and parse redacted traced ``NET_DVR_EZVIZ_ACCESS_CFG`` output."""
        return ezviz_lan_ezviz_access_config(
            self.dvr_config(ezviz_lan_ezviz_access_get_config_request(1))
        )

    def user_config_v30_summary(self) -> EzvizLanDvrConfigSummary:
        """Read user config as a non-secret summary."""
        return ezviz_lan_user_config_v30_summary(
            self.dvr_config(ezviz_lan_user_password_get_config_request(1))
        )

    def user_config_v30(self) -> EzvizLanUserConfigV30:
        """Read and decode ``NET_DVR_USER_V30`` user config.

        The returned object can include usernames, passwords, and rights.
        """
        return ezviz_lan_user_config_v30(
            self.dvr_config(ezviz_lan_user_password_get_config_request(1))
        )

    def stdxml_config(
        self,
        request: HcNetSdkStdXmlConfigRequest | str | bytes,
        template: HcNetSdkCommandPortControlTemplate,
    ) -> HcNetSdkStdXmlConfigResponse:
        """Execute a traced STDXML command through pure Python command-port IO."""
        return hcnetsdk_stdxml_config_command_port(
            self.endpoint,
            self.password,
            request,
            template,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def stdxml_config_from_trace(
        self,
        request: HcNetSdkStdXmlConfigRequest | str | bytes,
        *,
        command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        body_prefix: str | bytes | None = None,
        addend_delta: int | None = 0,
        addend: int | None = None,
        name: str | None = None,
    ) -> HcNetSdkStdXmlConfigResponse:
        """Execute traced STDXML through pure Python command-port IO."""
        return hcnetsdk_stdxml_config_command_port_from_trace(
            self.endpoint,
            self.password,
            request,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            name=name,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def stdxml_isapi_request(
        self,
        method: str,
        path: str,
        body: Mapping[str, Any] | str | bytes | None = None,
        *,
        command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        body_prefix: str | bytes | None = None,
        addend_delta: int | None = 0,
        addend: int | None = None,
        name: str | None = None,
    ) -> HcNetSdkStdXmlConfigResponse:
        """Execute a generic ISAPI request through pure command-port STDXML."""
        return hcnetsdk_stdxml_isapi_command_port(
            self.endpoint,
            self.password,
            method,
            path,
            body,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            name=name,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def services_switch_get(
        self,
        *,
        command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        body_prefix: str | bytes | None = None,
        addend_delta: int | None = 0,
        addend: int | None = None,
    ) -> HcNetSdkStdXmlConfigResponse:
        """Read raw ``servicesSwitch`` JSON through pure command-port STDXML."""
        return ezviz_lan_services_switch_get_command_port(
            self.endpoint,
            self.password,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def services_switch_state(
        self,
        *,
        command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        body_prefix: str | bytes | None = None,
        addend_delta: int | None = 0,
        addend: int | None = None,
    ) -> EzvizLanServicesSwitchState:
        """Read and parse ``servicesSwitch`` through pure command-port STDXML."""
        return ezviz_lan_services_switch_state_command_port(
            self.endpoint,
            self.password,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
        )

    def services_switch_set(
        self,
        current_payload: Mapping[str, Any] | None = None,
        *,
        command_id: int = HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID,
        body_prefix: str | bytes | None = None,
        addend_delta: int | None = 0,
        addend: int | None = None,
        hiksdk: int | bool | None = None,
        web: int | bool | None = None,
        rtsp: int | bool | None = None,
        upnp: int | bool | None = None,
    ) -> HcNetSdkStdXmlConfigResponse:
        """Set named ``servicesSwitch`` values through pure command-port STDXML."""
        return ezviz_lan_services_switch_set_command_port(
            self.endpoint,
            self.password,
            current_payload,
            command_id=command_id,
            body_prefix=body_prefix,
            addend_delta=addend_delta,
            addend=addend,
            username=self.username,
            local_ip=self.local_ip,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            rsa_key=self.rsa_key,
            hiksdk=hiksdk,
            web=web,
            rtsp=rtsp,
            upnp=upnp,
        )


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


def _hcnetsdk_time_value(
    value: HcNetSdkTime | datetime | date,
    *,
    end_of_day: bool = False,
) -> HcNetSdkTime:
    if isinstance(value, HcNetSdkTime):
        return value
    if isinstance(value, datetime):
        return HcNetSdkTime.from_datetime(value)
    if isinstance(value, date):
        return HcNetSdkTime.from_date(value, end_of_day=end_of_day)
    raise PyEzvizError("HCNetSDK time value must be date, datetime, or HcNetSdkTime")


def _native_string_bytes(label: str, value: str) -> bytes:
    if not value:
        raise PyEzvizError(f"HCNetSDK {label} must not be empty")
    if "\x00" in value:
        raise PyEzvizError(f"HCNetSDK {label} must not contain NUL bytes")
    return value.encode("utf-8")


def _services_switch_value(label: str, value: int | bool) -> int:
    if not isinstance(value, (bool, int)):
        raise PyEzvizError(f"EZVIZ LAN servicesSwitch.{label} must be 0 or 1")
    int_value = int(value)
    if int_value not in (0, 1):
        raise PyEzvizError(f"EZVIZ LAN servicesSwitch.{label} must be 0 or 1")
    return int_value


def _fixed_ipv4_text(value: bytes | bytearray | memoryview) -> str:
    raw = bytes(value)
    with suppress(UnicodeDecodeError):
        text = _nul_stripped_text(raw)
        if text and text.isprintable():
            with suppress(ValueError):
                return str(ipaddress.ip_address(text))
            return text
    binary_ipv4 = raw[:4]
    if any(binary_ipv4) and not any(raw[4:]):
        return str(ipaddress.ip_address(bytes(reversed(binary_ipv4))))
    return ""


def _mac_address_text(value: bytes | bytearray | memoryview) -> str:
    raw = bytes(value)
    if len(raw) != 6 or not any(raw):
        return ""
    return ":".join(f"{byte:02x}" for byte in raw)


def _byte_tuple(value: bytes | bytearray | memoryview) -> tuple[int, ...]:
    return tuple(bytes(value))


def _fixed_secret_bytes(value: bytes | bytearray | memoryview) -> bytes:
    return bytes(value).split(SADP_NUL_BYTE, 1)[0]


def _fixed_secret_text(value: bytes | bytearray | memoryview) -> str:
    raw = bytes(value)
    if not raw:
        return ""
    with suppress(UnicodeDecodeError):
        return raw.decode("utf-8")
    return raw.decode("latin-1")


def _mac_address_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 6:
            raise PyEzvizError("EZVIZ LAN MAC address must be 6 bytes")
        return value
    parts = value.split(":")
    if len(parts) != 6:
        raise PyEzvizError("EZVIZ LAN MAC address must contain 6 octets")
    try:
        return bytes(int(part, 16) for part in parts)
    except ValueError as err:
        raise PyEzvizError("EZVIZ LAN MAC address has invalid hex") from err


def _dword_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFFFFFFFF:
        raise PyEzvizError(f"EZVIZ LAN {label} must fit in one unsigned dword")
    return value


def _device_ability_response_text(response: str | bytes) -> str:
    text = response.decode("utf-8") if isinstance(response, bytes) else response
    return text.replace("\x00", "").strip()


def _device_ability_xml_name(label: str, value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
        raise PyEzvizError(f"HCNetSDK device ability {label} XML name is invalid")
    return value


def _xml_local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _xml_opt_attr(
    root: ET.Element,
    name: str,
    *,
    parent: str | None = None,
) -> str | None:
    return _xml_attr(root, name, "opt", parent=parent)


def _xml_attr(
    root: ET.Element,
    name: str,
    attr: str,
    *,
    parent: str | None = None,
) -> str | None:
    for element in root.iter():
        if _xml_local_name(element).lower() != name.lower():
            continue
        if parent is not None and not _xml_has_parent(root, element, parent):
            continue
        value = element.attrib.get(attr)
        return value if value else None
    return None


def _xml_attr_int(
    root: ET.Element,
    name: str,
    attr: str,
    *,
    parent: str | None = None,
    default: int = 0,
) -> int:
    value = _xml_attr(root, name, attr, parent=parent)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _xml_bool_opt_attr(root: ET.Element, name: str) -> bool | None:
    value = _xml_opt_attr(root, name)
    if value is None:
        return None
    return value.lower() == "true"


def _xml_descendant_int(
    root: ET.Element,
    name: str,
    *,
    parent: str | None = None,
    default: int = 0,
) -> int:
    value = _xml_descendant_text(root, name, parent=parent)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _xml_descendant_bool_text(
    root: ET.Element,
    name: str,
    *,
    parent: str | None = None,
    default: bool = False,
) -> bool:
    value = _xml_descendant_text(root, name, parent=parent)
    return default if value is None else value.lower() == "true"


def _xml_descendant_text(
    root: ET.Element,
    name: str,
    *,
    parent: str | None = None,
) -> str | None:
    for element in root.iter():
        if _xml_local_name(element).lower() != name.lower():
            continue
        if parent is not None and not _xml_has_parent(root, element, parent):
            continue
        text = element.text
        return text.strip() if text and text.strip() else None
    return None


def _xml_has_descendant(root: ET.Element, name: str) -> bool:
    return any(_xml_local_name(element).lower() == name.lower() for element in root.iter())


def _xml_int_csv(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    parsed: list[int] = []
    for part in value.split(","):
        text = part.strip()
        if not text:
            continue
        with suppress(ValueError):
            parsed.append(int(text))
    return tuple(parsed)


def _xml_child_int_csv_with_prefix(root: ET.Element, prefix: str) -> tuple[int, ...]:
    parsed: list[int] = []
    prefix_lower = prefix.lower()
    for child in list(root):
        if not _xml_local_name(child).lower().startswith(prefix_lower):
            continue
        text = child.text.strip() if child.text and child.text.strip() else None
        parsed.extend(_xml_int_csv(text))
    return tuple(parsed)


def _xml_child_text(root: ET.Element, path: tuple[str, ...]) -> str | None:
    elements = [root]
    for name in path:
        next_elements: list[ET.Element] = []
        for element in elements:
            next_elements.extend(
                child
                for child in list(element)
                if _xml_local_name(child).lower() == name.lower()
            )
        elements = next_elements
        if not elements:
            return None
    text = elements[0].text
    return text.strip() if text and text.strip() else None


def _xml_children(root: ET.Element, name: str) -> tuple[ET.Element, ...]:
    return tuple(
        child
        for child in list(root)
        if _xml_local_name(child).lower() == name.lower()
    )


def _xml_first_child(root: ET.Element, name: str) -> ET.Element | None:
    children = _xml_children(root, name)
    return children[0] if children else None


def _ipc_front_parameter_field_root(root: ET.Element) -> ET.Element:
    channel_list = _xml_first_child(root, "ChannelList")
    if channel_list is None:
        return root
    channel_entry = _xml_first_child(channel_list, "ChannelEntry")
    return channel_entry if channel_entry is not None else root


def _xml_child_int(
    root: ET.Element,
    path: tuple[str, ...],
    *,
    default: int = 0,
) -> int:
    value = _xml_child_text(root, path)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _xml_child_optional_int(
    root: ET.Element,
    path: tuple[str, ...],
) -> int | None:
    value = _xml_child_text(root, path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _xml_child_int_range(
    root: ET.Element,
    path: tuple[str, ...],
) -> EzvizLanIpcFrontParameterRange:
    return EzvizLanIpcFrontParameterRange(
        minimum=_xml_child_int(root, (*path, "Min")),
        maximum=_xml_child_int(root, (*path, "Max")),
        default=_xml_child_optional_int(root, (*path, "Default")),
    )


def _audio_video_compress_stream(
    root: ET.Element,
    *,
    index: int | None = None,
) -> EzvizLanAudioVideoCompressStream:
    resolutions: list[EzvizLanVideoResolution] = []
    bitrate_mins: list[int] = []
    bitrate_maxes: list[int] = []
    resolution_indexes: list[int] = []
    frame_rates: list[int] = []
    frame_rates.extend(_xml_child_int_csv_with_prefix(root, "VideoFrameRate"))
    resolution_list = _xml_first_child(root, "VideoResolutionList")
    if resolution_list is not None:
        for entry in _xml_children(resolution_list, "VideoResolutionEntry"):
            dimensions = _xml_child_text(entry, ("Resolution",))
            size = re.fullmatch(r"([0-9]+)\s*[*xX]\s*([0-9]+)", dimensions or "")
            width = int(size[1]) if size and int(size[1]) > 0 else None
            height = int(size[2]) if size and int(size[2]) > 0 else None
            if width is None or height is None:
                width = height = None
            resolutions.append(EzvizLanVideoResolution(
                index=_xml_child_optional_int(entry, ("Index",)),
                name=_xml_child_text(entry, ("Name",)), dimensions=dimensions,
                width=width, height=height,
                frame_rate_codes=tuple(_xml_child_int_csv_with_prefix(entry, "VideoFrameRate")),
                bitrate_min=_xml_child_optional_int(entry, ("VideoBitrate", "Min")),
                bitrate_max=_xml_child_optional_int(entry, ("VideoBitrate", "Max")),
                bitrate_codes=_xml_int_csv(_xml_child_text(entry, ("VideoBitrate", "Range"))),
            ))
            resolution_indexes.append(_xml_child_int(entry, ("Index",)))
            frame_rates.extend(_xml_child_int_csv_with_prefix(entry, "VideoFrameRate"))
            bitrate_min = _xml_child_int(entry, ("VideoBitrate", "Min"))
            bitrate_max = _xml_child_int(entry, ("VideoBitrate", "Max"))
            if bitrate_min:
                bitrate_mins.append(bitrate_min)
            if bitrate_max:
                bitrate_maxes.append(bitrate_max)

    return EzvizLanAudioVideoCompressStream(
        index=index,
        video_encode_type_range=_xml_child_text(root, ("VideoEncodeType", "Range")),
        video_encode_efficiency_range=_xml_child_text(
            root, ("VideoEncodeEfficiency", "Range")
        ),
        interval_bp_frame_range=_xml_child_text(root, ("IntervalBPFrame", "Range")),
        e_frame=_xml_child_int(root, ("EFrame",)),
        resolution_indexes=tuple(resolution_indexes),
        frame_rates=tuple(dict.fromkeys(frame_rates)),
        bitrate_min=min(bitrate_mins) if bitrate_mins else 0,
        bitrate_max=max(bitrate_maxes) if bitrate_maxes else 0,
        resolutions=tuple(resolutions),
        bitrate_codes=_xml_int_csv(_xml_child_text(root, ("VideoBitrate", "Range"))),
    )


def _audio_video_compress_video_channels(
    root: ET.Element,
) -> tuple[EzvizLanAudioVideoCompressVideoChannel, ...]:
    channel_list = _xml_first_child(root, "ChannelList")
    if channel_list is None:
        return ()
    channels: list[EzvizLanAudioVideoCompressVideoChannel] = []
    for entry in _xml_children(channel_list, "ChannelEntry"):
        main = _xml_first_child(entry, "MainChannel")
        sub_list = _xml_first_child(entry, "SubChannelList")
        sub_streams: list[EzvizLanAudioVideoCompressStream] = []
        if sub_list is not None:
            for sub_entry in _xml_children(sub_list, "SubChannelEntry"):
                sub_streams.append(
                    _audio_video_compress_stream(
                        sub_entry,
                        index=_xml_child_optional_int(sub_entry, ("index",)),
                    )
                )
        channels.append(
            EzvizLanAudioVideoCompressVideoChannel(
                channel_number=_xml_child_int(entry, ("ChannelNumber",)),
                main_stream=(
                    _audio_video_compress_stream(main) if main is not None else None
                ),
                sub_streams=tuple(sub_streams),
            )
        )
    return tuple(channels)


def _audio_video_compress_audio_channels(
    root: ET.Element,
) -> tuple[EzvizLanAudioVideoCompressAudioChannel, ...]:
    channel_list = _xml_first_child(root, "ChannelList")
    if channel_list is None:
        return ()
    return tuple(
        EzvizLanAudioVideoCompressAudioChannel(
            channel_number=_xml_child_int(entry, ("ChannelNumber",)),
            main_audio_encode_type_range=_xml_child_text(
                entry, ("MainAudioEncodeType", "Range")
            ),
            sub_audio_encode_type_range=_xml_child_text(
                entry, ("SubAudioEncodeType", "Range")
            ),
            audio_in_type_range=_xml_child_text(entry, ("AudioInType", "Range")),
            audio_in_volume_min=_xml_child_int(entry, ("AudioInVolume", "Min")),
            audio_in_volume_max=_xml_child_int(entry, ("AudioInVolume", "Max")),
        )
        for entry in _xml_children(channel_list, "ChannelEntry")
    )


def _audio_video_compress_voice_talk_channels(
    root: ET.Element,
) -> tuple[EzvizLanAudioVideoCompressVoiceTalkChannel, ...]:
    channel_list = _xml_first_child(root, "ChannelList")
    if channel_list is None:
        return ()
    return tuple(
        EzvizLanAudioVideoCompressVoiceTalkChannel(
            channel_number=_xml_child_int(entry, ("ChannelNumber",)),
            voice_talk_encode_type_range=_xml_child_text(
                entry, ("VoiceTalkEncodeType", "Range")
            ),
            voice_talk_in_type_range=_xml_child_text(
                entry, ("VoiceTalkInType", "Range")
            ),
        )
        for entry in _xml_children(channel_list, "ChannelEntry")
    )


def _xml_has_parent(root: ET.Element, child: ET.Element, parent: str) -> bool:
    for candidate in root.iter():
        if _xml_local_name(candidate).lower() != parent.lower():
            continue
        if any(descendant is child for descendant in candidate.iter()):
            return True
    return False


def _ptz_int(label: str, value: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as err:
        raise PyEzvizError(f"{label} must be an integer") from err


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


def _hcnetsdk_command_port_login_prefix(local_ip: str) -> bytes:
    return (
        HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX
        + _hcnetsdk_command_port_local_ip_word(local_ip)
        + HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX
    )


def _hcnetsdk_command_port_username(username: str) -> bytes:
    username_bytes = username.encode()
    if len(username_bytes) > HCNETSDK_COMMAND_PORT_USERNAME_LENGTH:
        raise PyEzvizError("HCNetSDK command-port username is too long")
    return username_bytes.ljust(HCNETSDK_COMMAND_PORT_USERNAME_LENGTH, b"\x00")


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
        try:
            chunk = sock.recv(remaining)
        except TimeoutError as err:
            raise DeviceException(
                "Device offline or unreachable: timed out waiting for EZVIZ local SDK data"
            ) from err
        if not chunk:
            raise EzvizLocalSdkStreamClosed(
                "Socket closed before expected EZVIZ frame bytes"
            )
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


def discover_hcnetsdk_stream_details(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    *,
    channel: int = 1,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    max_response_bytes: int = 524_288,
) -> HcNetSdkStreamDetails:
    """Login once and issue native GET1040 and ability8 queries on fresh sockets.

    Supplied credentials only: never renew or retry authentication. The finite
    network deadline covers login and both reads; RSA generation precedes it.
    Native frame-rate/resolution/codec IDs are preserved, not guessed as FPS or
    encryption protocols. Explicit capability-query rejection retains configuration
    with its raw error code; malformed/authentication/network errors propagate.
    """
    if not isinstance(channel, int) or isinstance(channel, bool) or not 1 <= channel <= 255:
        raise PyEzvizError("Stream discovery channel must be between 1 and 255")
    if timeout is None or not math.isfinite(timeout) or timeout <= 0:
        raise PyEzvizError("Stream discovery requires a positive finite timeout")
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 16:
        raise PyEzvizError("Discovery response limit must include the 16-byte header")
    if not password:
        raise PyEzvizError("Stream discovery requires supplied local credentials")
    key = rsa_key if rsa_key is not None else hcnetsdk_command_port_rsa_key()
    deadline = monotonic() + timeout
    with closing(HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        sock = client.connect(deadline=deadline, monotonic=monotonic)
        address = local_ip if local_ip is not None else str(sock.getsockname()[0])
        session = client.login(password=password, username=username, local_ip=address,
                               rsa_key=key, max_frame_bytes=max_response_bytes, deadline=deadline, monotonic=monotonic)
        config_template = hcnetsdk_dvr_config_command_port_template(ezviz_lan_video_coding_get_config_request(1, channel))
        ability_template = hcnetsdk_device_ability_command_port_template(ezviz_lan_audio_video_compress_info_ability_request(1, channel))
        config = _hcnetsdk_stream_details_query(endpoint, config_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
        configuration = ezviz_lan_compression_config(config.body)
        ability = _hcnetsdk_stream_details_query(endpoint, ability_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
        # A complete header-only device rejection is distinct from empty success,
        # malformed XML or a network timeout. Retain the confirmed configuration
        # without pretending that the camera advertised no supported profiles.
        capabilities_error = None
        if not ability.body and ability.header.field_4 == ability.header.field_8 and ability.header.field_8 not in (0, 1):
            capabilities_error = ability.header.field_8
            capabilities = EzvizLanAudioVideoCompressInfo()
        else:
            capabilities = ezviz_lan_audio_video_compress_info(hcnetsdk_command_port_response_payload(ability))
            if not capabilities.success:
                raise PyEzvizError("Camera did not return audio/video compression capabilities")
        if monotonic() >= deadline:
            raise EzvizLocalSdkDeadlineExpired("Camera stream discovery exhausted its deadline")
        return HcNetSdkStreamDetails(channel, configuration, capabilities, session.serial, capabilities_error)


def _hcnetsdk_stream_details_query(
    endpoint: HcNetSdkLanEndpoint, template: HcNetSdkCommandPortControlTemplate,
    session: HcNetSdkCommandPortLoginSession, address: str, timeout: float,
    socket_factory: SocketFactory, deadline: float, monotonic: Callable[[], float],
    max_response_bytes: int,
) -> HcNetSdkTcpFrame:
    request = template.to_frame(session_id=session.session_id, auth_seed=session.auth_seed,
                                key=session.challenge, local_ip=address)
    with closing(HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        client.send_command_frame(request, deadline=deadline, monotonic=monotonic)
        return client.read_tcp_frame(deadline=deadline, monotonic=monotonic, max_frame_bytes=max_response_bytes, allow_short_ack=False)


def discover_hcnetsdk_stream_details_for_login(
    endpoint: HcNetSdkLanEndpoint,
    login: HcNetSdkLoginCandidate,
    *,
    tls_context: ssl.SSLContext | None = None,
    channel: int = 1,
    timeout: float = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    max_response_bytes: int = 524_288,
) -> HcNetSdkStreamDetails:
    """Query one explicit native login profile, never enumerate or renew secrets.

    HTTPSV40 means the native binary SDK over TLS, not HTTP/ISAPI. Default TLS
    verifies certificates; private CA/self-signed handling belongs to a supplied
    SSLContext. TCP and TLS handshake share each connection's remaining budget.
    Authentication rejection propagates without a second credential/profile.
    """
    if login.api not in {"NET_DVR_Login_V30", "NET_DVR_Login_V40"}:
        raise PyEzvizError("Unsupported native stream discovery login profile")
    if isinstance(login.port, bool) or not 1 <= login.port <= 65535:
        raise PyEzvizError("Native stream discovery login port is invalid")
    if login.https and login.api != "NET_DVR_Login_V40":
        raise PyEzvizError("TLS stream discovery requires the native V40 profile")
    selected_factory = socket_factory
    if login.https:
        context = tls_context if tls_context is not None else ssl.create_default_context()

        def connect_tls(address: tuple[str, int], budget: float | None) -> Any:
            started = monotonic()
            raw = socket_factory(address, budget)
            try:
                remaining = None if budget is None else budget - (monotonic() - started)
                if remaining is not None and remaining <= 0:
                    raise EzvizLocalSdkDeadlineExpired("Native discovery TLS deadline exhausted")
                raw.settimeout(remaining)
                return context.wrap_socket(raw, server_hostname=address[0])
            except BaseException:
                raw.close()
                raise

        selected_factory = connect_tls
    elif tls_context is not None:
        raise PyEzvizError("TLS context supplied for a plain native login profile")
    return discover_hcnetsdk_stream_details(
        replace(endpoint, command_port=login.port), login.password,
        username=login.username, channel=channel, timeout=timeout,
        socket_factory=selected_factory, rsa_key=rsa_key, monotonic=monotonic,
        max_response_bytes=max_response_bytes,
    )

# Match the earlier implicit wildcard surface; named private compatibility hooks remain available.
__all__ = [name for name in globals() if not name.startswith("_")]
