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

from pyezvizapi.streaming.local.hcnetsdk import protocol as _hcnetsdk_protocol
from pyezvizapi._shared import resolver as _resolver
from pyezvizapi._shared.resolver import DEFAULT_RESOLVER, BoundedResolver, ResolverBusy
from pyezvizapi.exceptions import DeviceException, EzvizLocalSdkDeadlineExpired, EzvizLocalSdkStreamClosed, PyEzvizError
from pyezvizapi.streaming.media.models import IterableMediaPacketSource, MediaPacket, MediaPacketMetadata

# Explicit aliases retain historical public/private module attributes.
_AES_RCON = _hcnetsdk_protocol._AES_RCON
_AES_SBOX = _hcnetsdk_protocol._AES_SBOX
EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE: str = _hcnetsdk_protocol.EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
EZVIZ_HCNETUTIL_LOGIN_V40: str = _hcnetsdk_protocol.EZVIZ_HCNETUTIL_LOGIN_V40
EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF: str = _hcnetsdk_protocol.EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF
EZVIZ_LAN_MAIN_VIDEO_LEVEL: int = _hcnetsdk_protocol.EZVIZ_LAN_MAIN_VIDEO_LEVEL
EZVIZ_LAN_PTZ_SPEED_DEFAULT: int = _hcnetsdk_protocol.EZVIZ_LAN_PTZ_SPEED_DEFAULT
EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE: int = _hcnetsdk_protocol.EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE
EZVIZ_NATIVE_CREATE_CLIENT: str = _hcnetsdk_protocol.EZVIZ_NATIVE_CREATE_CLIENT
EZVIZ_NATIVE_START_PREVIEW: str = _hcnetsdk_protocol.EZVIZ_NATIVE_START_PREVIEW
EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE: str = _hcnetsdk_protocol.EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
EZVIZ_PLAYER_EXTRA_CHANNEL_NO: str = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_CHANNEL_NO
EZVIZ_PLAYER_EXTRA_DEVICE_ID: str = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_DEVICE_ID
EZVIZ_PLAYER_EXTRA_LAN_FLAG: str = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_LAN_FLAG
EZVIZ_PLAYER_EXTRA_LAN_USERID: str = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_LAN_USERID
EZVIZ_PLAYER_EXTRA_WIFI_SSID: str = _hcnetsdk_protocol.EZVIZ_PLAYER_EXTRA_WIFI_SSID
EZVIZ_PLAYER_LAN_FLAG_HCNETSDK: int = _hcnetsdk_protocol.EZVIZ_PLAYER_LAN_FLAG_HCNETSDK
EZVIZ_PREPLAY_SPS_TYPE: int = _hcnetsdk_protocol.EZVIZ_PREPLAY_SPS_TYPE
EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY: str = _hcnetsdk_protocol.EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY
EZVIZ_STREAM_INHIBIT_LAN: int = _hcnetsdk_protocol.EZVIZ_STREAM_INHIBIT_LAN
EZVIZ_STREAM_SOURCE_LIVE_MINE: int = _hcnetsdk_protocol.EZVIZ_STREAM_SOURCE_LIVE_MINE
EZVIZ_STREAM_TIMEOUT_MS: int = _hcnetsdk_protocol.EZVIZ_STREAM_TIMEOUT_MS
HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_BACKLIGHT_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_DAY_NIGHT_OFFSET
HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_CAMERA_PARAM_CFG_WDR_OFFSET
HCNETSDK_CLEANUP: str = _hcnetsdk_protocol.HCNETSDK_CLEANUP
HCNETSDK_CLOSE_ALARM_CHAN_V30: str = _hcnetsdk_protocol.HCNETSDK_CLOSE_ALARM_CHAN_V30
HCNETSDK_CLOSE_FORMAT_HANDLE: str = _hcnetsdk_protocol.HCNETSDK_CLOSE_FORMAT_HANDLE
HCNETSDK_COMMAND_CANDIDATE_CONTROL: int = _hcnetsdk_protocol.HCNETSDK_COMMAND_CANDIDATE_CONTROL
HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN: int = _hcnetsdk_protocol.HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN
HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH: int = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_AUTH_KEY_LENGTH
HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH: int = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH
HCNETSDK_COMMAND_PORT_CONTROL_FAMILY: int = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM: str = _hcnetsdk_protocol.HCNETSDK_COMMAND_PORT_PLAY_LOGIN_TODAY_TRANSFORM
HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_EVENT_OFFSET
HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_NETWORK_OFFSET
HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_NORMAL_OFFSET
HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_CFG_RESERVED_OFFSET
HCNETSDK_COMPRESSION_INFO_V30_SIZE: int = _hcnetsdk_protocol.HCNETSDK_COMPRESSION_INFO_V30_SIZE
HCNETSDK_DEFAULT_RTSP_PORT: int = _hcnetsdk_protocol.HCNETSDK_DEFAULT_RTSP_PORT
HCNETSDK_DEFAULT_SERVER_PORT: int = _hcnetsdk_protocol.HCNETSDK_DEFAULT_SERVER_PORT
HCNETSDK_DEFAULT_TLS_PORT: int = _hcnetsdk_protocol.HCNETSDK_DEFAULT_TLS_PORT
HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR: int = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_BUFFER_TOO_SMALL_ERROR
HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE: int = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE: int = _hcnetsdk_protocol.HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE
HCNETSDK_FILECOND_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_FILECOND_FIELD_ORDER
HCNETSDK_FIND_CLOSE_V30: str = _hcnetsdk_protocol.HCNETSDK_FIND_CLOSE_V30
HCNETSDK_FIND_FILE_FAILED = _hcnetsdk_protocol.HCNETSDK_FIND_FILE_FAILED
HCNETSDK_FIND_FILE_V30: str = _hcnetsdk_protocol.HCNETSDK_FIND_FILE_V30
HCNETSDK_FIND_NEXT_FILE_V30: str = _hcnetsdk_protocol.HCNETSDK_FIND_NEXT_FILE_V30
HCNETSDK_FINDDATA_V30_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_FINDDATA_V30_FIELD_ORDER
HCNETSDK_FORMAT_DISK: str = _hcnetsdk_protocol.HCNETSDK_FORMAT_DISK
HCNETSDK_GET_DEVICE_ABILITY: str = _hcnetsdk_protocol.HCNETSDK_GET_DEVICE_ABILITY
HCNETSDK_GET_DOWNLOAD_POS: str = _hcnetsdk_protocol.HCNETSDK_GET_DOWNLOAD_POS
HCNETSDK_GET_DVR_CONFIG: str = _hcnetsdk_protocol.HCNETSDK_GET_DVR_CONFIG
HCNETSDK_GET_ERROR_MSG: str = _hcnetsdk_protocol.HCNETSDK_GET_ERROR_MSG
HCNETSDK_GET_FILE_BY_NAME: str = _hcnetsdk_protocol.HCNETSDK_GET_FILE_BY_NAME
HCNETSDK_GET_FILE_BY_TIME: str = _hcnetsdk_protocol.HCNETSDK_GET_FILE_BY_TIME
HCNETSDK_GET_FILE_FAILED = _hcnetsdk_protocol.HCNETSDK_GET_FILE_FAILED
HCNETSDK_GET_FORMAT_PROGRESS: str = _hcnetsdk_protocol.HCNETSDK_GET_FORMAT_PROGRESS
HCNETSDK_GET_LAST_ERROR: str = _hcnetsdk_protocol.HCNETSDK_GET_LAST_ERROR
HCNETSDK_GET_SDK_BUILD_VERSION: str = _hcnetsdk_protocol.HCNETSDK_GET_SDK_BUILD_VERSION
HCNETSDK_GET_SDK_VERSION: str = _hcnetsdk_protocol.HCNETSDK_GET_SDK_VERSION
HCNETSDK_HIK_PRIVATE_PREFIX: bytes = _hcnetsdk_protocol.HCNETSDK_HIK_PRIVATE_PREFIX
HCNETSDK_HKMI_PREFIX: bytes = _hcnetsdk_protocol.HCNETSDK_HKMI_PREFIX
HCNETSDK_INIT: str = _hcnetsdk_protocol.HCNETSDK_INIT
HCNETSDK_LOGOUT_V30: str = _hcnetsdk_protocol.HCNETSDK_LOGOUT_V30
HCNETSDK_MAKE_KEYFRAME_MAIN: str = _hcnetsdk_protocol.HCNETSDK_MAKE_KEYFRAME_MAIN
HCNETSDK_MAKE_KEYFRAME_SUB: str = _hcnetsdk_protocol.HCNETSDK_MAKE_KEYFRAME_SUB
HCNETSDK_MPEG_PS_PACK_HEADER: bytes = _hcnetsdk_protocol.HCNETSDK_MPEG_PS_PACK_HEADER
HCNETSDK_MPEG_START_CODE_PREFIX: bytes = _hcnetsdk_protocol.HCNETSDK_MPEG_START_CODE_PREFIX
HCNETSDK_MPEG_TS_SYNC_BYTE: int = _hcnetsdk_protocol.HCNETSDK_MPEG_TS_SYNC_BYTE
HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_BRIGHTNESS_OFFSET
HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_ENABLE_HIDE_OFFSET
HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_NAME_POSITION_OFFSET
HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_OSD_POSITION_OFFSET
HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_OSD_TYPE_OFFSET
HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_SHOW_CHANNEL_NAME_OFFSET
HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_SHOW_OSD_OFFSET
HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET: int = _hcnetsdk_protocol.HCNETSDK_PIC_CFG_VIDEO_FORMAT_OFFSET
HCNETSDK_PLAYBACK_BY_TIME_V40: str = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_BY_TIME_V40
HCNETSDK_PLAYBACK_CAPTURE_FILE: str = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_CAPTURE_FILE
HCNETSDK_PLAYBACK_CONTROL_V40: str = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_CONTROL_V40
HCNETSDK_PLAYBACK_FAILED = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_FAILED
HCNETSDK_PLAYBACK_FILE_TYPE_ALL: int = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_FILE_TYPE_ALL
HCNETSDK_PLAYBACK_LOCK_STATE_ALL: int = _hcnetsdk_protocol.HCNETSDK_PLAYBACK_LOCK_STATE_ALL
HCNETSDK_PLAYCOND_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_PLAYCOND_FIELD_ORDER
HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER: str = _hcnetsdk_protocol.HCNETSDK_PTZ_CONTROL_WITH_SPEED_OTHER
HCNETSDK_PTZ_PRESET_OTHER: str = _hcnetsdk_protocol.HCNETSDK_PTZ_PRESET_OTHER
HCNETSDK_REALDATA_CALLBACK_V30: str = _hcnetsdk_protocol.HCNETSDK_REALDATA_CALLBACK_V30
HCNETSDK_REALPLAY_V30: str = _hcnetsdk_protocol.HCNETSDK_REALPLAY_V30
HCNETSDK_SECRET_KEY_TYPE_AES: int = _hcnetsdk_protocol.HCNETSDK_SECRET_KEY_TYPE_AES
HCNETSDK_SET_CONNECT_TIME: str = _hcnetsdk_protocol.HCNETSDK_SET_CONNECT_TIME
HCNETSDK_SET_DVR_CONFIG: str = _hcnetsdk_protocol.HCNETSDK_SET_DVR_CONFIG
HCNETSDK_SET_PLAY_DATA_CALLBACK: str = _hcnetsdk_protocol.HCNETSDK_SET_PLAY_DATA_CALLBACK
HCNETSDK_SET_PLAY_DATA_CALLBACK_V40: str = _hcnetsdk_protocol.HCNETSDK_SET_PLAY_DATA_CALLBACK_V40
HCNETSDK_SET_PLAYBACK_ES_CALLBACK: str = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_ES_CALLBACK
HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK: str = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_RESPONSE_CALLBACK
HCNETSDK_SET_PLAYBACK_SECRET_KEY: str = _hcnetsdk_protocol.HCNETSDK_SET_PLAYBACK_SECRET_KEY
HCNETSDK_SET_SDK_LOCAL_CFG: str = _hcnetsdk_protocol.HCNETSDK_SET_SDK_LOCAL_CFG
HCNETSDK_SETUP_ALARM_CHAN_V30: str = _hcnetsdk_protocol.HCNETSDK_SETUP_ALARM_CHAN_V30
HCNETSDK_SETUP_ALARM_CHAN_V41: str = _hcnetsdk_protocol.HCNETSDK_SETUP_ALARM_CHAN_V41
HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_SETUPALARM_PARAM_FIELD_ORDER
HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE: int = _hcnetsdk_protocol.HCNETSDK_STDXML_ANDROID_REQUEST_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE: int = _hcnetsdk_protocol.HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE
HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE: int = _hcnetsdk_protocol.HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE
HCNETSDK_STDXML_INPUT_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_STDXML_INPUT_FIELD_ORDER
HCNETSDK_STDXML_OUTPUT_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_STDXML_OUTPUT_FIELD_ORDER
HCNETSDK_STOP_GET_FILE: str = _hcnetsdk_protocol.HCNETSDK_STOP_GET_FILE
HCNETSDK_STOP_PLAYBACK: str = _hcnetsdk_protocol.HCNETSDK_STOP_PLAYBACK
HCNETSDK_TCP_HEADER_LENGTH: int = _hcnetsdk_protocol.HCNETSDK_TCP_HEADER_LENGTH
HCNETSDK_TIME_FIELD_ORDER = _hcnetsdk_protocol.HCNETSDK_TIME_FIELD_ORDER
HCNETSDK_XML_MARKER: bytes = _hcnetsdk_protocol.HCNETSDK_XML_MARKER
SADP_ACTIVATE_DEVICE: str = _hcnetsdk_protocol.SADP_ACTIVATE_DEVICE
SADP_CLEARUP: str = _hcnetsdk_protocol.SADP_CLEARUP
SADP_DEV_NET_PARAM_ANDROID_FIELDS = _hcnetsdk_protocol.SADP_DEV_NET_PARAM_ANDROID_FIELDS
SADP_DEV_NET_PARAM_JNA_FIELD_ORDER = _hcnetsdk_protocol.SADP_DEV_NET_PARAM_JNA_FIELD_ORDER
SADP_DEV_RET_NET_PARAM_BUFFER_SIZE: int = _hcnetsdk_protocol.SADP_DEV_RET_NET_PARAM_BUFFER_SIZE
SADP_DEV_RET_NET_PARAM_FIELD_ORDER = _hcnetsdk_protocol.SADP_DEV_RET_NET_PARAM_FIELD_ORDER
SADP_GET_LAST_ERROR: str = _hcnetsdk_protocol.SADP_GET_LAST_ERROR
SADP_GET_VERSION: str = _hcnetsdk_protocol.SADP_GET_VERSION
SADP_MODIFY_DEVICE_NET_PARAM: str = _hcnetsdk_protocol.SADP_MODIFY_DEVICE_NET_PARAM
SADP_MODIFY_DEVICE_NET_PARAM_V40: str = _hcnetsdk_protocol.SADP_MODIFY_DEVICE_NET_PARAM_V40
SADP_NUL_BYTE: bytes = _hcnetsdk_protocol.SADP_NUL_BYTE
SADP_SEND_INQUIRY: str = _hcnetsdk_protocol.SADP_SEND_INQUIRY
SADP_SET_LOG_TO_FILE: str = _hcnetsdk_protocol.SADP_SET_LOG_TO_FILE
SADP_START_V30: str = _hcnetsdk_protocol.SADP_START_V30
SADP_START_V40: str = _hcnetsdk_protocol.SADP_START_V40
SADP_STOP: str = _hcnetsdk_protocol.SADP_STOP
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
_ability_option_tuple = _hcnetsdk_protocol._ability_option_tuple
_bounded_bytes = _hcnetsdk_protocol._bounded_bytes
_build_local_sdk_request_xml = _hcnetsdk_protocol._build_local_sdk_request_xml
_byte_value = _hcnetsdk_protocol._byte_value
_device_ability_bytes = _hcnetsdk_protocol._device_ability_bytes
_hcnetsdk_aes128_round_keys = _hcnetsdk_protocol._hcnetsdk_aes128_round_keys
_hcnetsdk_aes_add_round_key = _hcnetsdk_protocol._hcnetsdk_aes_add_round_key
_hcnetsdk_aes_mix_columns = _hcnetsdk_protocol._hcnetsdk_aes_mix_columns
_hcnetsdk_aes_shift_rows = _hcnetsdk_protocol._hcnetsdk_aes_shift_rows
_hcnetsdk_aes_sub_bytes = _hcnetsdk_protocol._hcnetsdk_aes_sub_bytes
_hcnetsdk_aes_xtime = _hcnetsdk_protocol._hcnetsdk_aes_xtime
_hcnetsdk_command_port_auth_mask = _hcnetsdk_protocol._hcnetsdk_command_port_auth_mask
_hcnetsdk_command_port_four_round_aes = _hcnetsdk_protocol._hcnetsdk_command_port_four_round_aes
_hcnetsdk_command_port_local_ip_word = _hcnetsdk_protocol._hcnetsdk_command_port_local_ip_word
_hcnetsdk_compression_info_v30 = _hcnetsdk_protocol._hcnetsdk_compression_info_v30
_local_sdk_aes_bytes = _hcnetsdk_protocol._local_sdk_aes_bytes
_mapping_int = _hcnetsdk_protocol._mapping_int
_mapping_str = _hcnetsdk_protocol._mapping_str
_native_path_value = _hcnetsdk_protocol._native_path_value
_native_secret_key_bytes = _hcnetsdk_protocol._native_secret_key_bytes
_nul_stripped_text = _hcnetsdk_protocol._nul_stripped_text
_optional_native_bytes = _hcnetsdk_protocol._optional_native_bytes
_optional_raw_byte = _hcnetsdk_protocol._optional_raw_byte
_optional_raw_byte_triplet = _hcnetsdk_protocol._optional_raw_byte_triplet
_optional_raw_u16_be = _hcnetsdk_protocol._optional_raw_u16_be
_optional_raw_u16_be_pair = _hcnetsdk_protocol._optional_raw_u16_be_pair
_optional_raw_u32_be = _hcnetsdk_protocol._optional_raw_u32_be
_port_value = _hcnetsdk_protocol._port_value
_sadp_string_bytes = _hcnetsdk_protocol._sadp_string_bytes
_stdxml_bytes = _hcnetsdk_protocol._stdxml_bytes
_word_value = _hcnetsdk_protocol._word_value
_xml_attrs = _hcnetsdk_protocol._xml_attrs
_xml_escape = _hcnetsdk_protocol._xml_escape
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

HCNETSDK_EZVIZ_DEFAULT_USERNAME: str = "admin"
HCNETSDK_EZVIZ_LOCAL_USERNAME: str = "EZ_LOCAL_USER"
HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX: str = "_lan_device_space-"
HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX: str = "lan_device_space-"
HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID: int = 0x117000
HCNETSDK_STDXML_COMMAND_PORT_EXTRA_RESERVED_SIZE: int = 8
HCNETSDK_STDXML_COMMAND_PORT_PREFIX_SIZE: int = 12
HCNETSDK_STDXML_COMMAND_PORT_FLAGS: bytes = b"\x01\x00\x00\x00"
HCNETSDK_EZVIZ_SERVICES_SWITCH_GET: str = (
    "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
)
HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT: str = (
    "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\r\n"
)
HCNETSDK_EZVIZ_CONNECT_MODE_PUT: str = (
    "PUT /ISAPI/EZVIZ/IPC/System/Network/connectMode?format=json\r\n"
)
HCNETSDK_EZVIZ_NET_CONFIG_UPLOAD_PUT: str = (
    "PUT /ISAPI/EZVIZ/IPC/System/netConfigAndVoiceFileUpload?format=json\r\n"
)
HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE: int = 0x50910
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR: int = 0x50911
HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR: int = 0x50D5C
HCNETSDK_LOGIN_V40: str = "NET_DVR_Login_V40"
HCNETSDK_STDXML_CONFIG: str = "NET_DVR_STDXMLConfig"
HCNETSDK_FIND_NEXT_FILE_SUCCESS: int = 1000
HCNETSDK_FIND_NEXT_FILE_NO_FILE: int = 1001
HCNETSDK_FIND_NEXT_FILE_IS_FINDING: int = 1002
HCNETSDK_FIND_NEXT_FILE_NO_MORE_FILE: int = 1003
HCNETSDK_FIND_NEXT_FILE_EXCEPTION: int = 1004
HCNETSDK_PLAYSTART: int = 1
HCNETSDK_PLAYPAUSE: int = 3
HCNETSDK_PLAYRESTART: int = 4
HCNETSDK_PLAYFAST: int = 5
HCNETSDK_PLAYSLOW: int = 6
HCNETSDK_PLAYSTARTAUDIO: int = 9
HCNETSDK_PLAYSTOPAUDIO: int = 10
HCNETSDK_PLAYAUDIOVOLUME: int = 11
HCNETSDK_SET_TRANS_TYPE: int = 32
HCNETSDK_PLAY_CONVERT: int = 33
HCNETSDK_LOCAL_ABILITY_PARSE_CFG_FIELD_ORDER = ("byEnableAbilityParse", "byRes")
HCNETSDK_LOCAL_PTZ_CFG_FIELD_ORDER = ("byWithoutRecv", "byRes")
HCNETSDK_DEVICE_ABILITY_RN_OUTPUT_BUFFER_SIZE: int = 2_097_152
EZVIZ_PLAYER_LAN_FLAG_EZLINK: int = 2
EZVIZ_LAN_MAIN_STREAM_TYPE: int = 1
EZVIZ_LAN_SUB_STREAM_TYPE: int = 2
EZVIZ_LAN_SUB_VIDEO_LEVEL: int = 0
EZVIZ_LAN_PTZ_ACTION_START: int = 10
EZVIZ_LAN_PTZ_ACTION_STOP: int = 11
EZVIZ_LAN_PTZ_ACTION_RESET: int = 101
EZVIZ_LOCAL_SDK_MAGIC: bytes = b"\x9e\xba\xac\xe9"
EZVIZ_LOCAL_SDK_HEADER_LENGTH: int = 32
EZVIZ_RTP_INTERLEAVED_MAGIC: int = 0x24
EZVIZ_XML_DETECT_PREFIX_LIMIT: int = 64
EZVIZ_XML_START_BYTE: bytes = b"<"
EZVIZ_BODY_OPAQUE_HIGH_BIT_THRESHOLD: float = 0.25
EZVIZ_BODY_PRINTABLE_THRESHOLD: float = 0.75
EZVIZ_LOCAL_SDK_SSL_IV_PREFIX: bytes = b"01234567"
EZVIZ_LOCAL_SDK_PRE_START_COMMAND: int = 0x2013
EZVIZ_LOCAL_SDK_PRE_START_RESPONSE: int = 0x2014
# Native SendByeStream uses the same envelope ID with an owned Session.
EZVIZ_LOCAL_SDK_STOP_PREVIEW_COMMAND: int = 0x2013
EZVIZ_LOCAL_SDK_STOP_PREVIEW_RESPONSE: int = 0x2014
EZVIZ_LOCAL_SDK_STOP_TIMEOUT: float = 2.0
EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES = 4 * 1024 * 1024
EZVIZ_LOCAL_SDK_PREVIEW_COMMAND: int = 0x2011
EZVIZ_LOCAL_SDK_PREVIEW_RESPONSE: int = 0x2012
EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND: int = 0x3105
EZVIZ_LOCAL_SDK_STREAM_SETUP_RESPONSE: int = 0x3106
EZVIZ_LOCAL_SDK_SSL_TRAILER_LENGTH: int = 32
HCNETSDK_TCP_COMMAND_PORTS = (HCNETSDK_DEFAULT_SERVER_PORT, HCNETSDK_DEFAULT_TLS_PORT)
HCNETSDK_COMMAND_PORT_LOGIN_FAMILY: int = 0x5A000000
HCNETSDK_COMMAND_PORT_LOGIN_HEADER_FIELD_12: int = 0x00010000
HCNETSDK_COMMAND_PORT_LOGIN_SEED_PREFIX = bytes.fromhex("05013d4b00000001")
HCNETSDK_COMMAND_PORT_LOGIN_SEED_SUFFIX = bytes.fromhex("0000000000006f00")
HCNETSDK_COMMAND_PORT_USERNAME_LENGTH: int = 48
HCNETSDK_COMMAND_PORT_RSA_BITS: int = 1024
HCNETSDK_COMMAND_PORT_RSA_BLOCK_LENGTH: int = 128
HCNETSDK_COMMAND_PORT_PASSWORD_SEED_LENGTH: int = 64
HCNETSDK_COMMAND_PORT_PRIMARY_PROOF_LENGTH: int = 32
HCNETSDK_COMMAND_PORT_SECONDARY_PROOF_LENGTH: int = 16
HCNETSDK_COMMAND_PORT_EMPTY_SESSION_ID: bytes = b"\x00\x00\x00\x00"
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
HCNETSDK_HD_CFG_MIN_SIZE: int = 4
HCNETSDK_HD_CFG_HEADER_SIZE: int = 8
HCNETSDK_HD_CFG_DISK_COUNT: int = 33
HCNETSDK_HD_CFG_DISK_OFFSET: int = 8
HCNETSDK_HD_CFG_DISK_SIZE: int = 144
HCNETSDK_HD_CFG_DISK_HD_NO_OFFSET: int = 0
HCNETSDK_HD_CFG_DISK_CAPACITY_OFFSET: int = 4
HCNETSDK_HD_CFG_DISK_FREE_SPACE_OFFSET: int = 8
HCNETSDK_HD_CFG_DISK_STATUS_OFFSET: int = 12
HCNETSDK_HD_CFG_DISK_ATTR_OFFSET: int = 16
HCNETSDK_HD_CFG_DISK_TYPE_OFFSET: int = 17
HCNETSDK_HD_CFG_DISK_DRIVER_OFFSET: int = 18
HCNETSDK_HD_CFG_DISK_GROUP_OFFSET: int = 20
HCNETSDK_HD_CFG_DISK_RECYCLING_OFFSET: int = 24
HCNETSDK_HD_CFG_DISK_STORAGE_TYPE_OFFSET: int = 28
HCNETSDK_HD_CFG_DISK_PICTURE_CAPACITY_OFFSET: int = 32
HCNETSDK_HD_CFG_DISK_FREE_PICTURE_SPACE_OFFSET: int = 36
HCNETSDK_WIFI_AP_INFO_LIST_HEADER_SIZE: int = 8
HCNETSDK_WIFI_AP_INFO_ENTRY_SIZE: int = 52
HCNETSDK_WIFI_AP_INFO_SSID_SIZE: int = 36
HCNETSDK_TIME_CFG_SIZE: int = 24
HCNETSDK_NTP_CFG_SIZE: int = 80
HCNETSDK_NTP_SERVER_SIZE: int = 64
HCNETSDK_NTP_INTERVAL_OFFSET: int = 64
HCNETSDK_NTP_ENABLE_OFFSET: int = 66
HCNETSDK_NTP_TIME_DIFFERENCE_HOURS_OFFSET: int = 67
HCNETSDK_NTP_TIME_DIFFERENCE_MINUTES_OFFSET: int = 68
HCNETSDK_NTP_PORT_OFFSET: int = 70
HCNETSDK_NETCFG_V30_MIN_SIZE: int = 184
HCNETSDK_NETCFG_V30_ETHERNET_COUNT: int = 2
HCNETSDK_NETCFG_V30_ETHERNET_OFFSET: int = 4
HCNETSDK_NETCFG_V30_ETHERNET_SIZE: int = 48
HCNETSDK_NETCFG_V30_IP_SIZE: int = 16
HCNETSDK_NETCFG_V30_ETHERNET_NET_INTERFACE_OFFSET: int = 32
HCNETSDK_NETCFG_V30_ETHERNET_PORT_OFFSET: int = 36
HCNETSDK_NETCFG_V30_ETHERNET_MTU_OFFSET: int = 38
HCNETSDK_NETCFG_V30_ETHERNET_MAC_OFFSET: int = 40
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
HCNETSDK_DEVICE_CFG_V40_MIN_SIZE: int = 164
HCNETSDK_DEVICE_CFG_V40_NAME_OFFSET: int = 4
HCNETSDK_DEVICE_CFG_V40_NAME_SIZE: int = 32
HCNETSDK_DEVICE_CFG_V40_SERIAL_OFFSET: int = 44
HCNETSDK_DEVICE_CFG_V40_SERIAL_SIZE: int = 48
HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_OFFSET: int = 140
HCNETSDK_DEVICE_CFG_V40_TYPE_NAME_SIZE: int = 24
HCNETSDK_RECORD_CFG_V30_SIZE: int = 508
HCNETSDK_RECORD_CFG_V30_DAY_COUNT: int = 7
HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY: int = 8
HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET: int = 8
HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE: int = 4
HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET = (
    HCNETSDK_RECORD_CFG_V30_ALL_DAY_OFFSET
    + HCNETSDK_RECORD_CFG_V30_DAY_COUNT * HCNETSDK_RECORD_CFG_V30_ALL_DAY_SIZE
)
HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE: int = 8
HCNETSDK_RECORD_CFG_V30_TRAILER_OFFSET = (
    HCNETSDK_RECORD_CFG_V30_SCHEDULE_OFFSET
    + HCNETSDK_RECORD_CFG_V30_DAY_COUNT
    * HCNETSDK_RECORD_CFG_V30_SEGMENTS_PER_DAY
    * HCNETSDK_RECORD_CFG_V30_SCHEDULE_SIZE
)
HCNETSDK_USER_CFG_V30_USER_COUNT: int = 32
HCNETSDK_USER_CFG_V30_ENTRY_SIZE: int = 792
HCNETSDK_USER_CFG_V30_USERNAME_SIZE: int = 32
HCNETSDK_USER_CFG_V30_PASSWORD_SIZE: int = 16
HCNETSDK_USER_CFG_V30_LOCAL_RIGHT_SIZE: int = 32
HCNETSDK_USER_CFG_V30_REMOTE_RIGHT_SIZE: int = 32
HCNETSDK_USER_CFG_V30_CHANNEL_RIGHT_SIZE: int = 64
HCNETSDK_USER_CFG_V30_USER_IP_V4_SIZE: int = 16
HCNETSDK_USER_CFG_V30_USER_IP_V6_SIZE: int = 128
HCNETSDK_USER_CFG_V30_MAC_SIZE: int = 6
HCNETSDK_USER_CFG_V30_RESERVED_SIZE: int = 17
HCNETSDK_USER_CFG_V30_MIN_SIZE = 4 + HCNETSDK_USER_CFG_V30_ENTRY_SIZE
HCNETSDK_USER_CFG_V30_MAX_SIZE = (
    4 + HCNETSDK_USER_CFG_V30_USER_COUNT * HCNETSDK_USER_CFG_V30_ENTRY_SIZE
)
HCNETSDK_CAMERA_PARAM_CFG_MIN_SIZE: int = 12
HCNETSDK_WIFI_CONNECT_STATUS_MIN_SIZE: int = 8
HCNETSDK_AUDIO_INPUT_PARAM_SIZE: int = 8
HCNETSDK_AUDIOOUT_VOLUME_MIN_SIZE: int = 5
HCNETSDK_SHIFTED_SIZE_ZERO_SUFFIX: bytes = b"\x00\x00"
HCNETSDK_COMPRESSION_CFG_MIN_SIZE: int = 32
HCNETSDK_PIC_CFG_MIN_SIZE: int = 36
HCNETSDK_PIC_CFG_CHANNEL_NAME_SIZE: int = 32
HCNETSDK_EZVIZ_ACCESS_CFG_SIZE: int = 516
HCNETSDK_EZVIZ_ACCESS_CFG_ENABLE_OFFSET: int = 4
HCNETSDK_EZVIZ_ACCESS_CFG_DEVICE_STATUS_OFFSET: int = 5
HCNETSDK_EZVIZ_ACCESS_CFG_ALLOW_REDIRECT_OFFSET: int = 6
HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_OFFSET: int = 7
HCNETSDK_EZVIZ_ACCESS_CFG_DOMAIN_SIZE: int = 64
HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_OFFSET: int = 72
HCNETSDK_EZVIZ_ACCESS_CFG_VERIFICATION_SIZE: int = 32
HCNETSDK_EZVIZ_ACCESS_CFG_NET_MODE_OFFSET: int = 104


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
from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_real_data_to_media_packet as hcnetsdk_real_data_to_media_packet


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_media_packet_source as hcnetsdk_media_packet_source


SocketSourceAddress = tuple[str, int] | None
SocketBindAddress = tuple[str, int] | tuple[str, int, int, int]
SocketFactory = Callable[[tuple[str, int], float | None], Any]
SourceAddressSocketFactory = Callable[
    [tuple[str, int], float | None, SocketSourceAddress],
    Any,
]
LocalSdkIvFactory = Callable[[int], bytes]


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_local_sdk_ssl_iv as ezviz_local_sdk_ssl_iv


from pyezvizapi.streaming.local.hcnetsdk.discovery import classify_lan_ports as classify_lan_ports


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_login_candidates as ezviz_lan_login_candidates


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_local_user_password as ezviz_lan_local_user_password


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_password_store_name as ezviz_lan_password_store_name


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_password_store_key as ezviz_lan_password_store_key


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_settings_login_candidates as ezviz_lan_settings_login_candidates


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_settings_updates_services_switch as ezviz_lan_settings_updates_services_switch


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_time as hcnetsdk_time


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_time_from_datetime as hcnetsdk_time_from_datetime


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_file_search_condition as hcnetsdk_file_search_condition


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_playback_file_search_condition as ezviz_lan_playback_file_search_condition


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_playback_condition as hcnetsdk_playback_condition


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_playback_condition as ezviz_lan_playback_condition


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_init_request as hcnetsdk_init_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_cleanup_request as hcnetsdk_cleanup_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_connect_time_request as hcnetsdk_set_connect_time_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_last_error_request as hcnetsdk_get_last_error_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_error_msg_request as hcnetsdk_get_error_msg_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_sdk_version_request as hcnetsdk_get_sdk_version_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_sdk_build_version_request as hcnetsdk_get_sdk_build_version_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_logout_v30_request as hcnetsdk_logout_v30_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_find_file_v30_request as hcnetsdk_find_file_v30_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_find_next_file_v30_request as hcnetsdk_find_next_file_v30_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_find_close_v30_request as hcnetsdk_find_close_v30_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_playback_by_time_v40_request as hcnetsdk_playback_by_time_v40_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_playback_control_v40_request as hcnetsdk_playback_control_v40_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_stop_playback_request as hcnetsdk_stop_playback_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_playback_capture_file_request as hcnetsdk_playback_capture_file_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_play_data_callback_request as hcnetsdk_set_play_data_callback_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_play_data_callback_v40_request as hcnetsdk_set_play_data_callback_v40_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_playback_response_callback_request as hcnetsdk_set_playback_response_callback_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_playback_es_callback_request as hcnetsdk_set_playback_es_callback_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_playback_secret_key_request as hcnetsdk_set_playback_secret_key_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_file_by_name_request as hcnetsdk_get_file_by_name_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_file_by_time_request as hcnetsdk_get_file_by_time_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_stop_get_file_request as hcnetsdk_stop_get_file_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_get_download_pos_request as hcnetsdk_get_download_pos_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_find_next_file_status as hcnetsdk_find_next_file_status


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_playback_video_type as ezviz_lan_playback_video_type


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_activate_device_request as sadp_activate_device_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_device_net_param as sadp_device_net_param


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_modify_device_net_param_request as sadp_modify_device_net_param_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_modify_device_net_param_v40_request as sadp_modify_device_net_param_v40_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_get_last_error_request as sadp_get_last_error_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_get_sadp_version_request as sadp_get_sadp_version_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_set_log_to_file_request as sadp_set_log_to_file_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_start_v30_request as sadp_start_v30_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_start_v40_request as sadp_start_v40_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_stop_request as sadp_stop_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_clearup_request as sadp_clearup_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import sadp_send_inquiry_request as sadp_send_inquiry_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import ezviz_lan_sadp_activate_batch_result as ezviz_lan_sadp_activate_batch_result


from pyezvizapi.streaming.local.hcnetsdk.discovery import ezviz_lan_sadp_edit_net_param_batch_result as ezviz_lan_sadp_edit_net_param_batch_result


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_stdxml_config_request as hcnetsdk_stdxml_config_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_stdxml_isapi_request as hcnetsdk_stdxml_isapi_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_get_request as ezviz_lan_services_switch_get_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_get_config as ezviz_lan_services_switch_get_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_payload as ezviz_lan_services_switch_payload


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_set_payload as ezviz_lan_services_switch_set_payload


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_put_request as ezviz_lan_services_switch_put_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_put_config as ezviz_lan_services_switch_put_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_update_config as ezviz_lan_services_switch_update_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_set_config as ezviz_lan_services_switch_set_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_state as ezviz_lan_services_switch_state


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_succeeded as ezviz_lan_services_switch_succeeded


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_get_command_port as ezviz_lan_services_switch_get_command_port


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_state_command_port as ezviz_lan_services_switch_state_command_port


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_services_switch_set_command_port as ezviz_lan_services_switch_set_command_port


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_connect_mode_payload as ezviz_lan_connect_mode_payload


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_connect_mode_put_request as ezviz_lan_connect_mode_put_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_connect_mode_put_config as ezviz_lan_connect_mode_put_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_net_config_and_voice_upload_payload as ezviz_lan_net_config_and_voice_upload_payload


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_net_config_and_voice_upload_put_request as ezviz_lan_net_config_and_voice_upload_put_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_net_config_and_voice_upload_put_config as ezviz_lan_net_config_and_voice_upload_put_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_dvr_config_get_request as hcnetsdk_dvr_config_get_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_dvr_config_set_request as hcnetsdk_dvr_config_set_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_station_patch as ezviz_lan_wifi_station_patch


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_get_config_request as ezviz_lan_wifi_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_set_config_request as ezviz_lan_wifi_set_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_work_mode_update_request as ezviz_lan_wifi_work_mode_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_ap_info_list_request as ezviz_lan_wifi_ap_info_list_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_time_get_config_request as ezviz_lan_time_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ntp_get_config_request as ezviz_lan_ntp_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_device_config_v40_request as ezviz_lan_device_config_v40_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_net_config_v30_request as ezviz_lan_net_config_v30_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_record_config_v30_request as ezviz_lan_record_config_v30_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_ap_info_list as ezviz_lan_wifi_ap_info_list


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_time_config as ezviz_lan_time_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ntp_config as ezviz_lan_ntp_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_net_config_v30 as ezviz_lan_net_config_v30


from pyezvizapi.streaming.local.hcnetsdk.configuration import _hcnetsdk_config_declared_size as _hcnetsdk_config_declared_size


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_dvr_config_summary as ezviz_lan_dvr_config_summary


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_config_summary as ezviz_lan_wifi_config_summary


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ezviz_access_config_summary as ezviz_lan_ezviz_access_config_summary


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ezviz_access_config as ezviz_lan_ezviz_access_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_user_config_v30_summary as ezviz_lan_user_config_v30_summary


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_user_config_v30 as ezviz_lan_user_config_v30


from pyezvizapi.streaming.local.hcnetsdk.configuration import _ezviz_lan_user_config_v30_entry as _ezviz_lan_user_config_v30_entry


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_device_config_v40 as ezviz_lan_device_config_v40


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_record_config_v30 as ezviz_lan_record_config_v30


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_hd_config as ezviz_lan_hd_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import _ezviz_lan_hd_disk_config as _ezviz_lan_hd_disk_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_camera_param_config as ezviz_lan_camera_param_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_connect_status as ezviz_lan_wifi_connect_status


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_audio_input_param as ezviz_lan_audio_input_param


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_audio_output_volume as ezviz_lan_audio_output_volume


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_compression_config as ezviz_lan_compression_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_picture_config as ezviz_lan_picture_config


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_wifi_connect_status_request as ezviz_lan_wifi_connect_status_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_ezviz_access_replacement_domain as ezviz_lan_ezviz_access_replacement_domain


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ezviz_access_get_config_request as ezviz_lan_ezviz_access_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_ezviz_access_set_domain_request as ezviz_lan_ezviz_access_set_domain_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_ezviz_access_replacement_domain_request as ezviz_lan_ezviz_access_replacement_domain_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_audio_input_get_config_request as ezviz_lan_audio_input_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_audioout_volume_get_config_request as ezviz_lan_audioout_volume_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_audio_volume_update_requests as ezviz_lan_audio_volume_update_requests


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_video_coding_get_config_request as ezviz_lan_video_coding_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_video_coding_update_request as ezviz_lan_video_coding_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_pic_config_get_request as ezviz_lan_pic_config_get_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_pic_config_v30_get_request as ezviz_lan_pic_config_v30_get_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_pic_config_update_request as ezviz_lan_pic_config_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_hd_config_request as ezviz_lan_hd_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_sd_format_start_request as ezviz_lan_sd_format_start_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_sd_format_progress_request as ezviz_lan_sd_format_progress_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_sd_format_close_request as ezviz_lan_sd_format_close_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_sd_format_progress_result as ezviz_lan_sd_format_progress_result


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_setup_alarm_v30_request as hcnetsdk_setup_alarm_v30_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_setup_alarm_v41_request as hcnetsdk_setup_alarm_v41_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_close_alarm_request as hcnetsdk_close_alarm_request


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_set_sdk_local_cfg_request as hcnetsdk_set_sdk_local_cfg_request


from pyezvizapi.streaming.local.hcnetsdk.discovery import ezviz_hcnetsdk_local_ability_parse_request as ezviz_hcnetsdk_local_ability_parse_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_hcnetsdk_local_ptz_without_recv_request as ezviz_hcnetsdk_local_ptz_without_recv_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_user_password_get_config_request as ezviz_lan_user_password_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_user_password_update_request as ezviz_lan_user_password_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_video_effect_get_config_request as ezviz_lan_video_effect_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_video_effect_update_request as ezviz_lan_video_effect_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_backlight_wdr_get_config_request as ezviz_lan_backlight_wdr_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_backlight_wdr_update_request as ezviz_lan_backlight_wdr_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_day_night_get_config_request as ezviz_lan_day_night_get_config_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_day_night_update_request as ezviz_lan_day_night_update_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_device_ability_xml as hcnetsdk_device_ability_xml


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_device_ability_request as hcnetsdk_device_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_record_ability_input as ezviz_lan_record_ability_input


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_audio_video_compress_info_input as ezviz_lan_audio_video_compress_info_input


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_ability_input as ezviz_lan_ptz_ability_input


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_image_display_param_ability_input as ezviz_lan_image_display_param_ability_input


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_video_pic_ability_input as ezviz_lan_video_pic_ability_input


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_access_protocol_ability_input as ezviz_lan_access_protocol_ability_input


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_rn_device_ability_request as ezviz_lan_rn_device_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_access_protocol_ability_request as ezviz_lan_access_protocol_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_image_display_param_ability_request as ezviz_lan_image_display_param_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_video_pic_ability_request as ezviz_lan_video_pic_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_audio_video_compress_info_ability_request as ezviz_lan_audio_video_compress_info_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_soft_hardware_ability_request as ezviz_lan_soft_hardware_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_record_ability_request as ezviz_lan_record_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_ability_request as ezviz_lan_ptz_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ipc_front_parameter_ability_request as ezviz_lan_ipc_front_parameter_ability_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_ability as ezviz_lan_ptz_ability


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_access_protocol_ability as ezviz_lan_access_protocol_ability


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_video_pic_ability as ezviz_lan_video_pic_ability


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ipc_front_parameter_ability as ezviz_lan_ipc_front_parameter_ability


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_audio_video_compress_info as ezviz_lan_audio_video_compress_info


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_soft_hardware_ability as ezviz_lan_soft_hardware_ability


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_playback_convert_ability as ezviz_lan_playback_convert_ability


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_cas_ptz_command as ezviz_cas_ptz_command


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_native_command as ezviz_lan_ptz_native_command


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_is_preset_command as ezviz_lan_ptz_is_preset_command


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_control_request as ezviz_lan_ptz_control_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_preset_request as ezviz_lan_ptz_preset_request


from pyezvizapi.streaming.local.hcnetsdk.configuration import ezviz_lan_ptz_request as ezviz_lan_ptz_request


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_settings_error_code as ezviz_lan_settings_error_code


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_settings_error_clears_password as ezviz_lan_settings_error_clears_password


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_settings_login_succeeded as ezviz_lan_settings_login_succeeded


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_play_device_login_succeeded as ezviz_lan_play_device_login_succeeded


from pyezvizapi.streaming.local.hcnetsdk.discovery import classify_hcnetsdk_tcp_payload as classify_hcnetsdk_tcp_payload


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_hcnetsdk_tcp_shape_log_line as parse_hcnetsdk_tcp_shape_log_line


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_hcnetsdk_semantic_log_line as parse_hcnetsdk_semantic_log_line


from pyezvizapi.streaming.local.hcnetsdk.discovery import summarize_hcnetsdk_command_trace as summarize_hcnetsdk_command_trace


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_hcnetsdk_tcp_frame_header as parse_hcnetsdk_tcp_frame_header


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_hcnetsdk_tcp_frame as parse_hcnetsdk_tcp_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import read_hcnetsdk_tcp_frame as read_hcnetsdk_tcp_frame


from pyezvizapi.streaming.local.hcnetsdk.authentication import hcnetsdk_command_port_login_request_frame as hcnetsdk_command_port_login_request_frame


from pyezvizapi.streaming.local.hcnetsdk.authentication import hcnetsdk_command_port_password_digest as hcnetsdk_command_port_password_digest


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_command_port_md5_digest as _hcnetsdk_command_port_md5_digest


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_command_port_md5_hmac as _hcnetsdk_command_port_md5_hmac


from pyezvizapi.streaming.local.hcnetsdk.authentication import hcnetsdk_command_port_login_proof as hcnetsdk_command_port_login_proof


from pyezvizapi.streaming.local.hcnetsdk.authentication import hcnetsdk_command_port_login_proof_frame as hcnetsdk_command_port_login_proof_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_command_port_control_template_from_frame as hcnetsdk_command_port_control_template_from_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_command_port_public_key_der as hcnetsdk_command_port_public_key_der


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_command_port_rsa_key as hcnetsdk_command_port_rsa_key


from pyezvizapi.streaming.local.hcnetsdk.authentication import decode_hcnetsdk_command_port_login_challenge as decode_hcnetsdk_command_port_login_challenge


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_hcnetsdk_command_port_login_session as parse_hcnetsdk_command_port_login_session


from pyezvizapi.streaming.local.hcnetsdk.requests import iter_hcnetsdk_tcp_frame_shapes as iter_hcnetsdk_tcp_frame_shapes


from pyezvizapi.streaming.local.hcnetsdk.requests import iter_hcnetsdk_real_data_mpegps as iter_hcnetsdk_real_data_mpegps


from pyezvizapi.streaming.local.hcnetsdk.authentication import ezviz_lan_play_device_login as ezviz_lan_play_device_login


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_settings_channel_number as ezviz_lan_settings_channel_number


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_playback_intent as ezviz_lan_playback_intent


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_video_qualities as ezviz_lan_video_qualities


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_video_level_for_stream_type as ezviz_lan_video_level_for_stream_type


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_live_view_params as ezviz_lan_live_view_params


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_preview_plan as ezviz_lan_preview_plan


from pyezvizapi.streaming.local.hcnetsdk.requests import ezviz_lan_complete_playback_path as ezviz_lan_complete_playback_path


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_local_stream_setup_request_body as build_ezviz_local_stream_setup_request_body


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_local_stop_preview_request_body as build_ezviz_local_stop_preview_request_body


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
from pyezvizapi.streaming.local.hcnetsdk.requests import _wait_for_socket_io as _wait_for_socket_io


from pyezvizapi.streaming.local.hcnetsdk.requests import _remaining_timeout as _remaining_timeout


from pyezvizapi.streaming.local.hcnetsdk.requests import _send_all_with_timeout as _send_all_with_timeout


from pyezvizapi.streaming.local.hcnetsdk.requests import _send_all_before_deadline as _send_all_before_deadline


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
from pyezvizapi.streaming.local.hcnetsdk.requests import _connect_with_optional_source_address as _connect_with_optional_source_address


from pyezvizapi.streaming.local.hcnetsdk.requests import _create_reusable_source_connection as _create_reusable_source_connection


from pyezvizapi.streaming.local.hcnetsdk.requests import _connect_attempt_settings as _connect_attempt_settings


from pyezvizapi.streaming.local.hcnetsdk.requests import _create_deadline_connection as _create_deadline_connection


from pyezvizapi.streaming.local.hcnetsdk.requests import _getaddrinfo_before_deadline as _getaddrinfo_before_deadline


from pyezvizapi.streaming.local.hcnetsdk.requests import _connect_bound_source_socket as _connect_bound_source_socket


from pyezvizapi.streaming.local.hcnetsdk.requests import _windows_concrete_source_address as _windows_concrete_source_address


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_ezviz_local_device as parse_ezviz_local_device


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_sadp_response as parse_sadp_response


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_ezviz_local_sdk_frame_header as parse_ezviz_local_sdk_frame_header


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_local_sdk_frame_header as build_ezviz_local_sdk_frame_header


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_local_sdk_frame as build_ezviz_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.authentication import encrypt_ezviz_local_sdk_body_aes_cbc as encrypt_ezviz_local_sdk_body_aes_cbc


from pyezvizapi.streaming.local.hcnetsdk.authentication import decrypt_ezviz_local_sdk_body_aes_cbc as decrypt_ezviz_local_sdk_body_aes_cbc


from pyezvizapi.streaming.local.hcnetsdk.requests import build_encrypted_ezviz_local_sdk_frame as build_encrypted_ezviz_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_local_sdk_ssl_frame as build_ezviz_local_sdk_ssl_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_cas_encrypted_local_sdk_frame as build_ezviz_cas_encrypted_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_cas_ssl_local_sdk_frame as build_ezviz_cas_ssl_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_ezviz_local_sdk_frame as parse_ezviz_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_ezviz_local_sdk_xml_fields as parse_ezviz_local_sdk_xml_fields


from pyezvizapi.streaming.local.hcnetsdk.discovery import classify_ezviz_local_sdk_body as classify_ezviz_local_sdk_body


from pyezvizapi.streaming.local.hcnetsdk.requests import read_ezviz_local_sdk_frame as read_ezviz_local_sdk_frame


from pyezvizapi.streaming.local.hcnetsdk.discovery import parse_ezviz_interleaved_rtp_frame_header as parse_ezviz_interleaved_rtp_frame_header


from pyezvizapi.streaming.local.hcnetsdk.requests import build_ezviz_interleaved_rtp_frame_header as build_ezviz_interleaved_rtp_frame_header


from pyezvizapi.streaming.local.hcnetsdk.requests import read_ezviz_interleaved_rtp_frame as read_ezviz_interleaved_rtp_frame


from pyezvizapi.streaming.local.hcnetsdk.requests import read_ezviz_interleaved_rtp_frame_after_prefix as read_ezviz_interleaved_rtp_frame_after_prefix


from pyezvizapi.streaming.local.hcnetsdk.requests import read_hcnetsdk_command_port_interleaved_frame_after_prefix as read_hcnetsdk_command_port_interleaved_frame_after_prefix


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
from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_device_ability_command_port_body_tail as hcnetsdk_device_ability_command_port_body_tail


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_device_ability_command_port_template as hcnetsdk_device_ability_command_port_template


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_dvr_config_command_port_template as hcnetsdk_dvr_config_command_port_template


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_dvr_config_command_port_body_tail as hcnetsdk_dvr_config_command_port_body_tail


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_stdxml_config_command_port_body_tail as hcnetsdk_stdxml_config_command_port_body_tail


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_stdxml_config_command_port_template as hcnetsdk_stdxml_config_command_port_template


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_command_port_execute_template as hcnetsdk_command_port_execute_template


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_get_device_ability_command_port as hcnetsdk_get_device_ability_command_port


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_get_dvr_config_command_port as hcnetsdk_get_dvr_config_command_port


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_stdxml_config_command_port as hcnetsdk_stdxml_config_command_port


from pyezvizapi.streaming.local.hcnetsdk.configuration import hcnetsdk_stdxml_config_command_port_from_trace as hcnetsdk_stdxml_config_command_port_from_trace


from pyezvizapi.streaming.local.hcnetsdk.requests import hcnetsdk_stdxml_isapi_command_port as hcnetsdk_stdxml_isapi_command_port


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
from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_local_device_content as _parse_local_device_content


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_time_value as _hcnetsdk_time_value


from pyezvizapi.streaming.local.hcnetsdk.requests import _native_string_bytes as _native_string_bytes


from pyezvizapi.streaming.local.hcnetsdk.configuration import _services_switch_value as _services_switch_value


from pyezvizapi.streaming.local.hcnetsdk.requests import _fixed_ipv4_text as _fixed_ipv4_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _mac_address_text as _mac_address_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _byte_tuple as _byte_tuple


from pyezvizapi.streaming.local.hcnetsdk.requests import _fixed_secret_bytes as _fixed_secret_bytes


from pyezvizapi.streaming.local.hcnetsdk.requests import _fixed_secret_text as _fixed_secret_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _mac_address_bytes as _mac_address_bytes


from pyezvizapi.streaming.local.hcnetsdk.requests import _dword_value as _dword_value


from pyezvizapi.streaming.local.hcnetsdk.configuration import _device_ability_response_text as _device_ability_response_text


from pyezvizapi.streaming.local.hcnetsdk.configuration import _device_ability_xml_name as _device_ability_xml_name


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_local_name as _xml_local_name


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_opt_attr as _xml_opt_attr


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_attr as _xml_attr


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_attr_int as _xml_attr_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_bool_opt_attr as _xml_bool_opt_attr


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_descendant_int as _xml_descendant_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_descendant_bool_text as _xml_descendant_bool_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_descendant_text as _xml_descendant_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_has_descendant as _xml_has_descendant


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_int_csv as _xml_int_csv


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_child_int_csv_with_prefix as _xml_child_int_csv_with_prefix


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_child_text as _xml_child_text


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_children as _xml_children


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_first_child as _xml_first_child


from pyezvizapi.streaming.local.hcnetsdk.requests import _ipc_front_parameter_field_root as _ipc_front_parameter_field_root


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_child_int as _xml_child_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_child_optional_int as _xml_child_optional_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_child_int_range as _xml_child_int_range


from pyezvizapi.streaming.local.hcnetsdk.requests import _audio_video_compress_stream as _audio_video_compress_stream


from pyezvizapi.streaming.local.hcnetsdk.requests import _audio_video_compress_video_channels as _audio_video_compress_video_channels


from pyezvizapi.streaming.local.hcnetsdk.requests import _audio_video_compress_audio_channels as _audio_video_compress_audio_channels


from pyezvizapi.streaming.local.hcnetsdk.requests import _audio_video_compress_voice_talk_channels as _audio_video_compress_voice_talk_channels


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_has_parent as _xml_has_parent


from pyezvizapi.streaming.local.hcnetsdk.configuration import _ptz_int as _ptz_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _looks_tls_record as _looks_tls_record


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_tcp_payload_kind as _hcnetsdk_tcp_payload_kind


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_known_prefix_kind as _hcnetsdk_known_prefix_kind


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_declared_length as _hcnetsdk_declared_length


from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_shape_fields as _parse_shape_fields


from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_int as _parse_int


from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_float as _parse_float


from pyezvizapi.streaming.local.hcnetsdk.requests import _event_field_int as _event_field_int


from pyezvizapi.streaming.local.hcnetsdk.requests import _event_field_bool as _event_field_bool


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_shape_command_candidate as _hcnetsdk_shape_command_candidate


from pyezvizapi.streaming.local.hcnetsdk.authentication import _hcnetsdk_command_port_login_prefix as _hcnetsdk_command_port_login_prefix


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_command_port_username as _hcnetsdk_command_port_username


from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_length_candidates as _parse_length_candidates


from pyezvizapi.streaming.local.hcnetsdk.discovery import _parse_length_candidate_offset as _parse_length_candidate_offset


from pyezvizapi.streaming.local.hcnetsdk.requests import _recv_exact as _recv_exact


from pyezvizapi.streaming.local.hcnetsdk.requests import _send_all as _send_all


from pyezvizapi.streaming.local.hcnetsdk.requests import _pkcs5_pad as _pkcs5_pad


from pyezvizapi.streaming.local.hcnetsdk.requests import _pkcs5_unpad as _pkcs5_unpad


from pyezvizapi.streaming.local.hcnetsdk.requests import _entropy_bits_per_byte as _entropy_bits_per_byte


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_offset as _xml_offset


from pyezvizapi.streaming.local.hcnetsdk.requests import _xml_tag_names as _xml_tag_names


from pyezvizapi.streaming.local.hcnetsdk.discovery import _probe_port as _probe_port


from pyezvizapi.streaming.local.hcnetsdk.discovery import discover_hcnetsdk_stream_details as discover_hcnetsdk_stream_details


from pyezvizapi.streaming.local.hcnetsdk.requests import _hcnetsdk_stream_details_query as _hcnetsdk_stream_details_query


from pyezvizapi.streaming.local.hcnetsdk.discovery import discover_hcnetsdk_stream_details_for_login as discover_hcnetsdk_stream_details_for_login

# Match the earlier implicit wildcard surface; named private compatibility hooks remain available.
__all__ = [name for name in globals() if not name.startswith("_")]
