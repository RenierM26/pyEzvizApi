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

import sys as _sys

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
# Define socket value-type aliases before the operations that annotate them.
SocketSourceAddress = tuple[str, int] | None
SocketBindAddress = tuple[str, int] | tuple[str, int, int, int]
SocketFactory = Callable[[tuple[str, int], float | None], Any]

from pyezvizapi.streaming.local.hcnetsdk import requests as _impl_requests

def hcnetsdk_real_data_to_media_packet(packet: HcNetSdkRealDataPacket) -> MediaPacket:
    """Normalize an HCNetSDK callback packet without changing its SDK model."""
    return _impl_requests.hcnetsdk_real_data_to_media_packet(packet, _owner=_sys.modules[__name__])


def hcnetsdk_media_packet_source(packets: Iterable[HcNetSdkRealDataPacket], *, cancel: Callable[[], None] | None=None) -> IterableMediaPacketSource[HcNetSdkRealDataPacket]:
    """Adapt HCNetSDK callback media packets to the shared packet contract."""
    return _impl_requests.hcnetsdk_media_packet_source(packets, cancel=cancel, _owner=_sys.modules[__name__])


SourceAddressSocketFactory = Callable[
    [tuple[str, int], float | None, SocketSourceAddress],
    Any,
]
LocalSdkIvFactory = Callable[[int], bytes]


from pyezvizapi.streaming.local.hcnetsdk import authentication as _impl_authentication

def ezviz_local_sdk_ssl_iv(size: int=EZVIZ_LOCAL_SDK_AES_BLOCK_SIZE, *, seed: bytes=EZVIZ_LOCAL_SDK_SSL_IV_PREFIX) -> bytes:
    """Return the app-shaped IV used for local SDK SSL-like frames.

    EZVIZ traces show the direct-local stack creates one IV per preview setup
    context and reuses it for the ``0x2011`` and ``0x3105`` encrypted frames.
    The IV prefix observed in the app is the ASCII bytes ``01234567`` and the
    remaining AES block bytes are zero. The 32-byte frame trailer is a
    lowercase MD5 hex digest of the encrypted body.
    """
    return _impl_authentication.ezviz_local_sdk_ssl_iv(size, seed=seed, _owner=_sys.modules[__name__])


from pyezvizapi.streaming.local.hcnetsdk import discovery as _impl_discovery

def classify_lan_ports(endpoint: HcNetSdkLanEndpoint, *, timeout: float | None=2.0, socket_factory: SocketFactory=socket.create_connection) -> list[HcNetSdkPortProbe]:
    """Probe advertised LAN ports without authenticating or changing state."""
    return _impl_discovery.classify_lan_ports(endpoint, timeout=timeout, socket_factory=socket_factory, _owner=_sys.modules[__name__])


def ezviz_lan_login_candidates(verification_code: str, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, command_port: int=HCNETSDK_DEFAULT_SERVER_PORT, tls_port: int=HCNETSDK_DEFAULT_TLS_PORT) -> list[HcNetSdkLoginCandidate]:
    """Return EZVIZ app-style HCNetSDK LAN login attempts.

    APK inspection shows LAN login tries HCNetSDK V40 over HTTPS first, then
    classic V30 on the SDK command port, and finally V30 with ``EZ_LOCAL_USER``
    plus the middle 16 hex characters of the MD5 hash of the same device
    verification/activation code.
    """
    return _impl_authentication.ezviz_lan_login_candidates(verification_code, username=username, command_port=command_port, tls_port=tls_port, _owner=_sys.modules[__name__])


def ezviz_lan_local_user_password(password: str) -> str:
    """Return the EZ_LOCAL_USER password derived by AddMD5Util.a(...)."""
    return _impl_authentication.ezviz_lan_local_user_password(password, _owner=_sys.modules[__name__])


def ezviz_lan_password_store_name(user_id: str) -> str:
    """Return the SharedPreferences name used for LAN Live View passwords."""
    return _impl_authentication.ezviz_lan_password_store_name(user_id, _owner=_sys.modules[__name__])


def ezviz_lan_password_store_key(serial: str) -> str:
    """Return the SharedPreferences key used for one LAN device password."""
    return _impl_authentication.ezviz_lan_password_store_key(serial, _owner=_sys.modules[__name__])


def ezviz_lan_settings_login_candidates(verification_code: str, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, command_port: int=HCNETSDK_DEFAULT_SERVER_PORT, tls_port: int=HCNETSDK_DEFAULT_TLS_PORT, login_with_8443: bool | None=None) -> list[HcNetSdkLoginCandidate]:
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
    return _impl_authentication.ezviz_lan_settings_login_candidates(verification_code, username=username, command_port=command_port, tls_port=tls_port, login_with_8443=login_with_8443, _owner=_sys.modules[__name__])


from pyezvizapi.streaming.local.hcnetsdk import configuration as _impl_configuration

def ezviz_lan_settings_updates_services_switch(*, login_with_8443: bool | None, login_port: int, open_8000: bool | None, tls_port: int=HCNETSDK_DEFAULT_TLS_PORT) -> bool:
    """Return whether the settings presenter writes ``servicesSwitch``.

    Smali inspection shows the compatibility checkbox update runs only after a
    successful SDK-over-TLS login attempt. If the TLS attempt is skipped, or if
    the flow falls back to the command-port login, the app does not send the
    ``GET``/``PUT`` servicesSwitch requests.
    """
    return _impl_configuration.ezviz_lan_settings_updates_services_switch(login_with_8443=login_with_8443, login_port=login_port, open_8000=open_8000, tls_port=tls_port, _owner=_sys.modules[__name__])


def hcnetsdk_time(year: int, month: int, day: int, *, hour: int=0, minute: int=0, second: int=0) -> HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` field model."""
    return _impl_requests.hcnetsdk_time(year, month, day, hour=hour, minute=minute, second=second, _owner=_sys.modules[__name__])


def hcnetsdk_time_from_datetime(value: datetime) -> HcNetSdkTime:
    """Return a ``NET_DVR_TIME`` model from a Python ``datetime``."""
    return _impl_requests.hcnetsdk_time_from_datetime(value, _owner=_sys.modules[__name__])


def hcnetsdk_file_search_condition(channel: int, start_time: HcNetSdkTime | datetime | date, stop_time: HcNetSdkTime | datetime | date, *, file_type: int=HCNETSDK_PLAYBACK_FILE_TYPE_ALL, is_locked: int=HCNETSDK_PLAYBACK_LOCK_STATE_ALL, use_card_no: int=0, card_number: str | bytes=b'') -> HcNetSdkFileCond:
    """Return a generic ``NET_DVR_FILECOND`` playback search condition."""
    return _impl_requests.hcnetsdk_file_search_condition(channel, start_time, stop_time, file_type=file_type, is_locked=is_locked, use_card_no=use_card_no, card_number=card_number, _owner=_sys.modules[__name__])


def ezviz_lan_playback_file_search_condition(channel: int, start_time: HcNetSdkTime | datetime | date, stop_time: HcNetSdkTime | datetime | date) -> HcNetSdkFileCond:
    """Return the APK-observed LAN playback file-search condition."""
    return _impl_requests.ezviz_lan_playback_file_search_condition(channel, start_time, stop_time, _owner=_sys.modules[__name__])


def hcnetsdk_playback_condition(channel: int, start_time: HcNetSdkTime | datetime | date, stop_time: HcNetSdkTime | datetime | date, *, draw_frame: int=0, stream_type: int=0, stream_id: str | bytes=b'') -> HcNetSdkPlayCond:
    """Return a generic ``NET_DVR_PLAYCOND`` time-playback condition."""
    return _impl_requests.hcnetsdk_playback_condition(channel, start_time, stop_time, draw_frame=draw_frame, stream_type=stream_type, stream_id=stream_id, _owner=_sys.modules[__name__])


def ezviz_lan_playback_condition(channel: int, start_time: HcNetSdkTime | datetime | date, stop_time: HcNetSdkTime | datetime | date, *, stream_type: int=0) -> HcNetSdkPlayCond:
    """Return the APK-compatible LAN playback-by-time condition."""
    return _impl_requests.ezviz_lan_playback_condition(channel, start_time, stop_time, stream_type=stream_type, _owner=_sys.modules[__name__])


def hcnetsdk_init_request(playctrl_library: str | None='libPlayCtrl.so') -> HcNetSdkInitRequest:
    """Return the ``NET_DVR_Init`` request shape used before LAN SDK calls."""
    return _impl_requests.hcnetsdk_init_request(playctrl_library, _owner=_sys.modules[__name__])


def hcnetsdk_cleanup_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_Cleanup`` request shape."""
    return _impl_requests.hcnetsdk_cleanup_request(_owner=_sys.modules[__name__])


def hcnetsdk_set_connect_time_request(connect_time_ms: int=5000, retry_count: int=3) -> HcNetSdkSetConnectTimeRequest:
    """Return the APK-style ``NET_DVR_SetConnectTime`` request shape."""
    return _impl_requests.hcnetsdk_set_connect_time_request(connect_time_ms, retry_count, _owner=_sys.modules[__name__])


def hcnetsdk_get_last_error_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetLastError`` request shape."""
    return _impl_requests.hcnetsdk_get_last_error_request(_owner=_sys.modules[__name__])


def hcnetsdk_get_error_msg_request(error_code: int | None=None) -> HcNetSdkGetErrorMsgRequest:
    """Return the ``NET_DVR_GetErrorMsg`` request shape."""
    return _impl_requests.hcnetsdk_get_error_msg_request(error_code, _owner=_sys.modules[__name__])


def hcnetsdk_get_sdk_version_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKVersion`` request shape."""
    return _impl_requests.hcnetsdk_get_sdk_version_request(_owner=_sys.modules[__name__])


def hcnetsdk_get_sdk_build_version_request() -> HcNetSdkNoArgRequest:
    """Return the ``NET_DVR_GetSDKBuildVersion`` request shape."""
    return _impl_requests.hcnetsdk_get_sdk_build_version_request(_owner=_sys.modules[__name__])


def hcnetsdk_logout_v30_request(login_id: int) -> HcNetSdkLogoutRequest:
    """Return the ``NET_DVR_Logout_V30`` request shape."""
    return _impl_requests.hcnetsdk_logout_v30_request(login_id, _owner=_sys.modules[__name__])


def hcnetsdk_find_file_v30_request(login_id: int, file_cond: HcNetSdkFileCond) -> HcNetSdkFindFileRequest:
    """Return the ``NET_DVR_FindFile_V30`` request shape."""
    return _impl_requests.hcnetsdk_find_file_v30_request(login_id, file_cond, _owner=_sys.modules[__name__])


def hcnetsdk_find_next_file_v30_request(find_handle: int, *, find_data: HcNetSdkFindDataV30 | None=None) -> HcNetSdkFindNextFileRequest:
    """Return the ``NET_DVR_FindNextFile_V30`` request shape."""
    return _impl_requests.hcnetsdk_find_next_file_v30_request(find_handle, find_data=find_data, _owner=_sys.modules[__name__])


def hcnetsdk_find_close_v30_request(find_handle: int) -> HcNetSdkFindCloseRequest:
    """Return the ``NET_DVR_FindClose_V30`` request shape."""
    return _impl_requests.hcnetsdk_find_close_v30_request(find_handle, _owner=_sys.modules[__name__])


def hcnetsdk_playback_by_time_v40_request(login_id: int, play_cond: HcNetSdkPlayCond) -> HcNetSdkPlayBackByTimeRequest:
    """Return the ``NET_DVR_PlayBackByTime_V40`` request shape."""
    return _impl_requests.hcnetsdk_playback_by_time_v40_request(login_id, play_cond, _owner=_sys.modules[__name__])


def hcnetsdk_playback_control_v40_request(play_handle: int, command: int | HcNetSdkPlaybackControlCommand, *, in_buffer: str | bytes | None=None, out_buffer_size: int=0) -> HcNetSdkPlayBackControlRequest:
    """Return the ``NET_DVR_PlayBackControl_V40`` request shape."""
    return _impl_requests.hcnetsdk_playback_control_v40_request(play_handle, command, in_buffer=in_buffer, out_buffer_size=out_buffer_size, _owner=_sys.modules[__name__])


def hcnetsdk_stop_playback_request(play_handle: int) -> HcNetSdkStopPlayBackRequest:
    """Return the ``NET_DVR_StopPlayBack`` request shape."""
    return _impl_requests.hcnetsdk_stop_playback_request(play_handle, _owner=_sys.modules[__name__])


def hcnetsdk_playback_capture_file_request(play_handle: int, saved_file_name: str | bytes) -> HcNetSdkPlayBackCaptureFileRequest:
    """Return the ``NET_DVR_PlayBackCaptureFile`` request shape."""
    return _impl_requests.hcnetsdk_playback_capture_file_request(play_handle, saved_file_name, _owner=_sys.modules[__name__])


def hcnetsdk_set_play_data_callback_request(play_handle: int, *, callback: str | None=None, user_data: str | int | None=None) -> HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack`` request shape."""
    return _impl_requests.hcnetsdk_set_play_data_callback_request(play_handle, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def hcnetsdk_set_play_data_callback_v40_request(play_handle: int, *, callback: str | None=None, user_data: str | int | None=None) -> HcNetSdkPlayDataCallbackRequest:
    """Return the ``NET_DVR_SetPlayDataCallBack_V40`` request shape."""
    return _impl_requests.hcnetsdk_set_play_data_callback_v40_request(play_handle, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def hcnetsdk_set_playback_response_callback_request(play_handle: int, *, callback: str | None=None, user_data: str | int | None=None) -> HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlaybackResponseCallBack`` request shape."""
    return _impl_requests.hcnetsdk_set_playback_response_callback_request(play_handle, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def hcnetsdk_set_playback_es_callback_request(play_handle: int, *, callback: str | None=None, user_data: str | int | None=None) -> HcNetSdkPlaybackCallbackRequest:
    """Return the ``NET_DVR_SetPlayBackESCallBack`` request shape."""
    return _impl_requests.hcnetsdk_set_playback_es_callback_request(play_handle, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def hcnetsdk_set_playback_secret_key_request(play_handle: int, secret_key: str | bytes, *, secret_key_type: int=HCNETSDK_SECRET_KEY_TYPE_AES) -> HcNetSdkPlayBackSecretKeyRequest:
    """Return the ``NET_DVR_SetPlayBackSecretKey`` request shape."""
    return _impl_requests.hcnetsdk_set_playback_secret_key_request(play_handle, secret_key, secret_key_type=secret_key_type, _owner=_sys.modules[__name__])


def hcnetsdk_get_file_by_name_request(login_id: int, dvr_file_name: str | bytes, saved_file_name: str | bytes) -> HcNetSdkGetFileByNameRequest:
    """Return the ``NET_DVR_GetFileByName`` request shape."""
    return _impl_requests.hcnetsdk_get_file_by_name_request(login_id, dvr_file_name, saved_file_name, _owner=_sys.modules[__name__])


def hcnetsdk_get_file_by_time_request(login_id: int, channel: int, start_time: HcNetSdkTime | datetime | date, stop_time: HcNetSdkTime | datetime | date, saved_file_name: str | bytes) -> HcNetSdkGetFileByTimeRequest:
    """Return the ``NET_DVR_GetFileByTime`` request shape."""
    return _impl_requests.hcnetsdk_get_file_by_time_request(login_id, channel, start_time, stop_time, saved_file_name, _owner=_sys.modules[__name__])


def hcnetsdk_stop_get_file_request(file_handle: int) -> HcNetSdkStopGetFileRequest:
    """Return the ``NET_DVR_StopGetFile`` request shape."""
    return _impl_requests.hcnetsdk_stop_get_file_request(file_handle, _owner=_sys.modules[__name__])


def hcnetsdk_get_download_pos_request(file_handle: int) -> HcNetSdkGetDownloadPosRequest:
    """Return the ``NET_DVR_GetDownloadPos`` request shape."""
    return _impl_requests.hcnetsdk_get_download_pos_request(file_handle, _owner=_sys.modules[__name__])


def hcnetsdk_find_next_file_status(native_result: int) -> str:
    """Return the app-observed meaning of ``NET_DVR_FindNextFile_V30``."""
    return _impl_requests.hcnetsdk_find_next_file_status(native_result, _owner=_sys.modules[__name__])


def ezviz_lan_playback_video_type(native_file_type: int) -> int:
    """Map native file type to the EZVIZ ``CloudFile.videoType`` value."""
    return _impl_requests.ezviz_lan_playback_video_type(native_file_type, _owner=_sys.modules[__name__])


def sadp_activate_device_request(serial: str, password: str) -> SadpActivateDeviceRequest:
    """Return the local SADP device activation request shape."""
    return _impl_discovery.sadp_activate_device_request(serial, password, _owner=_sys.modules[__name__])


def sadp_device_net_param(*, ipv4_address: str, ipv4_subnet_mask: str, ipv4_gateway: str, dhcp_enabled: int | bool, http_port: int, command_port: int, ipv6_address: str='', ipv6_gateway: str='', ipv6_mask_len: int=0) -> SadpDeviceNetParam:
    """Return the Android ``SADP_DEV_NET_PARAM`` field-update model."""
    return _impl_discovery.sadp_device_net_param(ipv4_address=ipv4_address, ipv4_subnet_mask=ipv4_subnet_mask, ipv4_gateway=ipv4_gateway, dhcp_enabled=dhcp_enabled, http_port=http_port, command_port=command_port, ipv6_address=ipv6_address, ipv6_gateway=ipv6_gateway, ipv6_mask_len=ipv6_mask_len, _owner=_sys.modules[__name__])


def sadp_modify_device_net_param_request(mac: str, password: str, net_param: SadpDeviceNetParam) -> SadpModifyDeviceNetParamRequest:
    """Return the local SADP network-parameter update request shape."""
    return _impl_discovery.sadp_modify_device_net_param_request(mac, password, net_param, _owner=_sys.modules[__name__])


def sadp_modify_device_net_param_v40_request(mac: str, password: str, net_param: SadpDeviceNetParam, *, ret_net_param: SadpDeviceRetNetParam | None=None) -> SadpModifyDeviceNetParamV40Request:
    """Return the local SADP V40 network-parameter update request shape."""
    return _impl_discovery.sadp_modify_device_net_param_v40_request(mac, password, net_param, ret_net_param=ret_net_param, _owner=_sys.modules[__name__])


def sadp_get_last_error_request() -> SadpNoArgRequest:
    """Return the ``SADP_GetLastError`` request shape."""
    return _impl_discovery.sadp_get_last_error_request(_owner=_sys.modules[__name__])


def sadp_get_sadp_version_request() -> SadpNoArgRequest:
    """Return the ``SADP_GetSadpVersion`` request shape."""
    return _impl_discovery.sadp_get_sadp_version_request(_owner=_sys.modules[__name__])


def sadp_set_log_to_file_request(log_level: int, log_dir: str | bytes, *, auto_delete: int | bool=True) -> SadpSetLogToFileRequest:
    """Return the ``SADP_SetLogToFile`` request shape."""
    return _impl_discovery.sadp_set_log_to_file_request(log_level, log_dir, auto_delete=auto_delete, _owner=_sys.modules[__name__])


def sadp_start_v30_request(*, install_npf: int | bool=0, callback: str | None=None, user_data: str | None=None) -> SadpStartRequest:
    """Return the ``SADP_Start_V30`` request shape."""
    return _impl_discovery.sadp_start_v30_request(install_npf=install_npf, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def sadp_start_v40_request(*, install_npf: int | bool=0, callback: str | None=None, user_data: str | None=None) -> SadpStartRequest:
    """Return the ``SADP_Start_V40`` request shape."""
    return _impl_discovery.sadp_start_v40_request(install_npf=install_npf, callback=callback, user_data=user_data, _owner=_sys.modules[__name__])


def sadp_stop_request() -> SadpNoArgRequest:
    """Return the ``SADP_Stop`` request shape."""
    return _impl_discovery.sadp_stop_request(_owner=_sys.modules[__name__])


def sadp_clearup_request() -> SadpNoArgRequest:
    """Return the ``SADP_Clearup`` request shape."""
    return _impl_discovery.sadp_clearup_request(_owner=_sys.modules[__name__])


def sadp_send_inquiry_request() -> SadpNoArgRequest:
    """Return the ``SADP_SendInquiry`` request shape."""
    return _impl_discovery.sadp_send_inquiry_request(_owner=_sys.modules[__name__])


def ezviz_lan_sadp_activate_batch_result(serial: str, password: str, *, code: int, error: int) -> SadpBatchResult:
    """Return the RN-style result map model for batch SADP activation."""
    return _impl_discovery.ezviz_lan_sadp_activate_batch_result(serial, password, code=code, error=error, _owner=_sys.modules[__name__])


def ezviz_lan_sadp_edit_net_param_batch_result(mac: str, password: str, *, code: int, error: int) -> SadpBatchResult:
    """Return the RN-style result map model for batch SADP network edits."""
    return _impl_discovery.ezviz_lan_sadp_edit_net_param_batch_result(mac, password, code=code, error=error, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_config_request(request: str | bytes, *, in_buffer: str | bytes=b'', recv_timeout: int=0, force_encrypt: int=0, num_of_multi_part: int=0, output_buffer_size: int=HCNETSDK_STDXML_DEFAULT_OUTPUT_BUFFER_SIZE, status_buffer_size: int=HCNETSDK_STDXML_DEFAULT_STATUS_BUFFER_SIZE) -> HcNetSdkStdXmlConfigRequest:
    """Return a ``NET_DVR_STDXMLConfig`` request model."""
    return _impl_configuration.hcnetsdk_stdxml_config_request(request, in_buffer=in_buffer, recv_timeout=recv_timeout, force_encrypt=force_encrypt, num_of_multi_part=num_of_multi_part, output_buffer_size=output_buffer_size, status_buffer_size=status_buffer_size, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_isapi_request(method: str, path: str, body: Mapping[str, Any] | str | bytes | None=None) -> str:
    """Return the ISAPI request text passed to ``NET_DVR_STDXMLConfig``."""
    return _impl_requests.hcnetsdk_stdxml_isapi_request(method, path, body, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_get_request() -> str:
    """Return the local ISAPI request used to read ``servicesSwitch``."""
    return _impl_configuration.ezviz_lan_services_switch_get_request(_owner=_sys.modules[__name__])


def ezviz_lan_services_switch_get_config() -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for reading ``servicesSwitch``."""
    return _impl_configuration.ezviz_lan_services_switch_get_config(_owner=_sys.modules[__name__])


def ezviz_lan_services_switch_payload(payload: Mapping[str, Any] | None, *, enabled: bool) -> dict[str, Any]:
    """Return the LAN settings servicesSwitch update payload.

    The APK reads GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json,
    mutates servicesSwitch.hiksdk and servicesSwitch.web to the same checkbox
    value, then sends the whole JSON object back through HCNetSDK.
    """
    return _impl_configuration.ezviz_lan_services_switch_payload(payload, enabled=enabled, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_set_payload(payload: Mapping[str, Any] | None, *, hiksdk: int | bool | None=None, web: int | bool | None=None, rtsp: int | bool | None=None, upnp: int | bool | None=None) -> dict[str, Any]:
    """Return a ``servicesSwitch`` payload with only named switches changed."""
    return _impl_configuration.ezviz_lan_services_switch_set_payload(payload, hiksdk=hiksdk, web=web, rtsp=rtsp, upnp=upnp, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_put_request(payload: Mapping[str, Any]) -> str:
    """Return the raw ISAPI request string sent by HCNETUtil.c(...)."""
    return _impl_configuration.ezviz_lan_services_switch_put_request(payload, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_put_config(payload: Mapping[str, Any]) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing ``servicesSwitch``."""
    return _impl_configuration.ezviz_lan_services_switch_put_config(payload, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_update_config(payload: Mapping[str, Any] | None, *, enabled: bool) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for the app's checkbox update."""
    return _impl_configuration.ezviz_lan_services_switch_update_config(payload, enabled=enabled, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_set_config(payload: Mapping[str, Any] | None, *, hiksdk: int | bool | None=None, web: int | bool | None=None, rtsp: int | bool | None=None, upnp: int | bool | None=None) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for direct ``servicesSwitch`` updates."""
    return _impl_configuration.ezviz_lan_services_switch_set_config(payload, hiksdk=hiksdk, web=web, rtsp=rtsp, upnp=upnp, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_state(response: Mapping[str, Any] | str | bytes) -> EzvizLanServicesSwitchState:
    """Parse ``servicesSwitch`` values from a local ISAPI response."""
    return _impl_configuration.ezviz_lan_services_switch_state(response, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_succeeded(response: Mapping[str, Any] | str | bytes) -> bool:
    """Return whether HCNETUtil.c(...) would treat a servicesSwitch PUT as OK."""
    return _impl_configuration.ezviz_lan_services_switch_succeeded(response, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_get_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913
    """Read ``servicesSwitch`` through traced pure-Python command-port STDXML."""
    return _impl_configuration.ezviz_lan_services_switch_get_command_port(endpoint, password, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_state_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> EzvizLanServicesSwitchState:  # noqa: PLR0913
    """Read and parse ``servicesSwitch`` through pure command-port STDXML."""
    return _impl_configuration.ezviz_lan_services_switch_state_command_port(endpoint, password, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def ezviz_lan_services_switch_set_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, current_payload: Mapping[str, Any] | None=None, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None, hiksdk: int | bool | None=None, web: int | bool | None=None, rtsp: int | bool | None=None, upnp: int | bool | None=None) -> HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913
    """Set named ``servicesSwitch`` values through pure command-port STDXML.

    When ``current_payload`` is omitted, the device is read first so unspecified
    switches are preserved before the PUT request is sent.
    """
    return _impl_configuration.ezviz_lan_services_switch_set_command_port(endpoint, password, current_payload, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, hiksdk=hiksdk, web=web, rtsp=rtsp, upnp=upnp, _owner=_sys.modules[__name__])


def ezviz_lan_connect_mode_payload(mode: int=1) -> dict[str, Any]:
    """Return the local ``connectMode`` payload used when leaving AP mode."""
    return _impl_requests.ezviz_lan_connect_mode_payload(mode, _owner=_sys.modules[__name__])


def ezviz_lan_connect_mode_put_request(mode: int=1) -> str:
    """Return the raw local ISAPI ``connectMode`` PUT request."""
    return _impl_requests.ezviz_lan_connect_mode_put_request(mode, _owner=_sys.modules[__name__])


def ezviz_lan_connect_mode_put_config(mode: int=1) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for writing local ``connectMode``."""
    return _impl_configuration.ezviz_lan_connect_mode_put_config(mode, _owner=_sys.modules[__name__])


def ezviz_lan_net_config_and_voice_upload_payload(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int) -> dict[str, Any]:
    """Return the local add-device Wi-Fi upload payload used by the APK."""
    return _impl_configuration.ezviz_lan_net_config_and_voice_upload_payload(ip=ip, port=port, bssid=bssid, ssid=ssid, passwd=passwd, security=security, _owner=_sys.modules[__name__])


def ezviz_lan_net_config_and_voice_upload_put_request(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int) -> str:
    """Return the raw local ISAPI net-config upload PUT request."""
    return _impl_configuration.ezviz_lan_net_config_and_voice_upload_put_request(ip=ip, port=port, bssid=bssid, ssid=ssid, passwd=passwd, security=security, _owner=_sys.modules[__name__])


def ezviz_lan_net_config_and_voice_upload_put_config(*, ip: str, port: int, bssid: str, ssid: str, passwd: str, security: int) -> HcNetSdkStdXmlConfigRequest:
    """Return a STDXML request model for local net-config upload."""
    return _impl_configuration.ezviz_lan_net_config_and_voice_upload_put_config(ip=ip, port=port, bssid=bssid, ssid=ssid, passwd=passwd, security=security, _owner=_sys.modules[__name__])


def hcnetsdk_dvr_config_get_request(login_id: int, command: int, *, channel: int=-1, structure: str, structure_size: int | None=None) -> HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_GetDVRConfig`` request model."""
    return _impl_configuration.hcnetsdk_dvr_config_get_request(login_id, command, channel=channel, structure=structure, structure_size=structure_size, _owner=_sys.modules[__name__])


def hcnetsdk_dvr_config_set_request(login_id: int, command: int, *, channel: int=-1, structure: str, structure_size: int | None=None, field_updates: Mapping[str, Any] | None=None, read_before_write: bool=False) -> HcNetSdkDvrConfigRequest:
    """Return a ``NET_DVR_SetDVRConfig`` request model."""
    return _impl_configuration.hcnetsdk_dvr_config_set_request(login_id, command, channel=channel, structure=structure, structure_size=structure_size, field_updates=field_updates, read_before_write=read_before_write, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_station_patch(*, ssid: str | bytes, password: str | bytes=b'', mac: str | bytes | None=None, mode: int=0, security: int | None=None) -> dict[str, Any]:
    """Return APK-observed ``NET_DVR_WIFI_CFG`` field updates for station Wi-Fi."""
    return _impl_configuration.ezviz_lan_wifi_station_patch(ssid=ssid, password=password, mac=mac, mode=mode, security=security, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_get_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the app's ``NET_DVR_WIFI_CFG`` read request."""
    return _impl_configuration.ezviz_lan_wifi_get_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_set_config_request(login_id: int, *, ssid: str | bytes, password: str | bytes=b'', mac: str | bytes | None=None, mode: int=0, security: int | None=None) -> HcNetSdkDvrConfigRequest:
    """Return the APK-observed ``NET_DVR_WIFI_CFG`` station update request."""
    return _impl_configuration.ezviz_lan_wifi_set_config_request(login_id, ssid=ssid, password=password, mac=mac, mode=mode, security=security, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_work_mode_update_request(login_id: int, mode: int) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN ``apiSetApWorkModeWithHandle`` request shape."""
    return _impl_configuration.ezviz_lan_wifi_work_mode_update_request(login_id, mode, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_ap_info_list_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi scan ``NET_DVR_AP_INFO_LIST`` request shape."""
    return _impl_configuration.ezviz_lan_wifi_ap_info_list_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_time_get_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_TIME`` read request shape."""
    return _impl_configuration.ezviz_lan_time_get_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_ntp_get_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NTPPARA`` read request shape."""
    return _impl_configuration.ezviz_lan_ntp_get_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_device_config_v40_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_DEVICECFG_V40`` read request shape."""
    return _impl_configuration.ezviz_lan_device_config_v40_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_net_config_v30_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_NETCFG_V30`` read request shape."""
    return _impl_configuration.ezviz_lan_net_config_v30_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_record_config_v30_request(login_id: int, *, channel: int=1) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_RECORD_V30`` read request shape."""
    return _impl_configuration.ezviz_lan_record_config_v30_request(login_id, channel=channel, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_ap_info_list(data: bytes | bytearray | memoryview) -> tuple[EzvizLanWifiApInfo, ...]:
    """Parse a ``NET_DVR_AP_INFO_LIST`` buffer returned by the command port."""
    return _impl_configuration.ezviz_lan_wifi_ap_info_list(data, _owner=_sys.modules[__name__])


def ezviz_lan_time_config(data: bytes | bytearray | memoryview) -> HcNetSdkTime:
    """Parse a traced ``NET_DVR_TIME`` buffer from command-port output."""
    return _impl_configuration.ezviz_lan_time_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_ntp_config(data: bytes | bytearray | memoryview) -> EzvizLanNtpConfig:
    """Parse known ``NET_DVR_NTPPARA`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_ntp_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_net_config_v30(data: bytes | bytearray | memoryview) -> EzvizLanNetConfigV30:
    """Parse non-secret ``NET_DVR_NETCFG_V30`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_net_config_v30(data, _owner=_sys.modules[__name__])


def _hcnetsdk_config_declared_size(raw: bytes, label: str) -> tuple[int, int]:
    """Return declared/effective size for traced DVR config body variants."""
    return _impl_configuration._hcnetsdk_config_declared_size(raw, label, _owner=_sys.modules[__name__])


def ezviz_lan_dvr_config_summary(data: bytes | bytearray | memoryview, *, command: int, structure: str) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary for a binary DVR config response."""
    return _impl_configuration.ezviz_lan_dvr_config_summary(data, command=command, structure=structure, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_config_summary(data: bytes | bytearray | memoryview) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_WIFI_CFG`` buffer."""
    return _impl_configuration.ezviz_lan_wifi_config_summary(data, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_config_summary(data: bytes | bytearray | memoryview) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of a traced ``NET_DVR_EZVIZ_ACCESS_CFG``."""
    return _impl_configuration.ezviz_lan_ezviz_access_config_summary(data, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_config(data: bytes | bytearray | memoryview) -> EzvizLanEzvizAccessConfig:
    """Parse redacted ``NET_DVR_EZVIZ_ACCESS_CFG`` fields from command output."""
    return _impl_configuration.ezviz_lan_ezviz_access_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_user_config_v30_summary(data: bytes | bytearray | memoryview) -> EzvizLanDvrConfigSummary:
    """Return a non-secret summary of ``NET_DVR_USER_V30`` config output."""
    return _impl_configuration.ezviz_lan_user_config_v30_summary(data, _owner=_sys.modules[__name__])


def ezviz_lan_user_config_v30(data: bytes | bytearray | memoryview) -> EzvizLanUserConfigV30:
    """Decode a ``NET_DVR_USER_V30`` command-port response.

    The returned object contains usernames, passwords, and rights. Keep live
    outputs local and use synthetic fixtures in public tests/docs.
    """
    return _impl_configuration.ezviz_lan_user_config_v30(data, _owner=_sys.modules[__name__])


def _ezviz_lan_user_config_v30_entry(entry: bytes, index: int) -> EzvizLanUserConfigV30Entry:
    """Parse one fixed-size ``NET_DVR_USER_INFO_V30`` record."""
    return _impl_configuration._ezviz_lan_user_config_v30_entry(entry, index, _owner=_sys.modules[__name__])


def ezviz_lan_device_config_v40(data: bytes | bytearray | memoryview) -> EzvizLanDeviceConfigV40:
    """Parse known ``NET_DVR_DEVICECFG_V40`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_device_config_v40(data, _owner=_sys.modules[__name__])


def ezviz_lan_record_config_v30(data: bytes | bytearray | memoryview) -> EzvizLanRecordConfigV30:
    """Parse known ``NET_DVR_RECORD_V30`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_record_config_v30(data, _owner=_sys.modules[__name__])


def ezviz_lan_hd_config(data: bytes | bytearray | memoryview) -> EzvizLanHdConfig:
    """Parse known ``NET_DVR_HDCFG`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_hd_config(data, _owner=_sys.modules[__name__])


def _ezviz_lan_hd_disk_config(entry: bytes) -> EzvizLanHdDiskConfig:
    """Parse one fixed-size ``NET_DVR_SINGLE_HD`` record."""
    return _impl_configuration._ezviz_lan_hd_disk_config(entry, _owner=_sys.modules[__name__])


def ezviz_lan_camera_param_config(data: bytes | bytearray | memoryview) -> EzvizLanCameraParamConfig:
    """Parse known ``NET_DVR_CAMERAPARAMCFG`` fields from command-port output."""
    return _impl_configuration.ezviz_lan_camera_param_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_connect_status(data: bytes | bytearray | memoryview) -> EzvizLanWifiConnectStatus:
    """Parse known ``NET_DVR_WIFI_CONNECT_STATUS`` fields from command output."""
    return _impl_configuration.ezviz_lan_wifi_connect_status(data, _owner=_sys.modules[__name__])


def ezviz_lan_audio_input_param(data: bytes | bytearray | memoryview) -> EzvizLanAudioInputParam:
    """Parse known ``NET_DVR_AUDIO_INPUT_PARAM`` fields from command output."""
    return _impl_requests.ezviz_lan_audio_input_param(data, _owner=_sys.modules[__name__])


def ezviz_lan_audio_output_volume(data: bytes | bytearray | memoryview) -> EzvizLanAudioOutputVolume:
    """Parse known ``NET_DVR_AUDIOOUT_VOLUME`` fields from command output."""
    return _impl_configuration.ezviz_lan_audio_output_volume(data, _owner=_sys.modules[__name__])


def ezviz_lan_compression_config(data: bytes | bytearray | memoryview) -> EzvizLanCompressionConfig:
    """Parse known ``NET_DVR_COMPRESSIONCFG_V30`` fields from command output."""
    return _impl_configuration.ezviz_lan_compression_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_picture_config(data: bytes | bytearray | memoryview) -> EzvizLanPictureConfig:
    """Parse known ``NET_DVR_PICCFG_V40`` fields from command output."""
    return _impl_configuration.ezviz_lan_picture_config(data, _owner=_sys.modules[__name__])


def ezviz_lan_wifi_connect_status_request(login_id: int, *, channel: int=0) -> HcNetSdkDvrConfigRequest:
    """Return the local Wi-Fi connection status request shape."""
    return _impl_configuration.ezviz_lan_wifi_connect_status_request(login_id, channel=channel, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_replacement_domain(domain: str | bytes | None, *, fallback: str='dev.ezvizru.com') -> str:
    """Return the domain rewrite performed by ``HCNETUtil.g``."""
    return _impl_requests.ezviz_lan_ezviz_access_replacement_domain(domain, fallback=fallback, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_get_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` read request shape."""
    return _impl_configuration.ezviz_lan_ezviz_access_get_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_set_domain_request(login_id: int, domain: str | bytes) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_EZVIZ_ACCESS_CFG`` domain update shape."""
    return _impl_requests.ezviz_lan_ezviz_access_set_domain_request(login_id, domain, _owner=_sys.modules[__name__])


def ezviz_lan_ezviz_access_replacement_domain_request(login_id: int, current_domain: str | bytes | None) -> HcNetSdkDvrConfigRequest:
    """Return the local-add domain rewrite request used on RU accounts."""
    return _impl_requests.ezviz_lan_ezviz_access_replacement_domain_request(login_id, current_domain, _owner=_sys.modules[__name__])


def ezviz_lan_audio_input_get_config_request(login_id: int, channel: int) -> HcNetSdkDvrConfigRequest:
    """Return the local audio-input config read request shape."""
    return _impl_configuration.ezviz_lan_audio_input_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_audioout_volume_get_config_request(login_id: int, channel: int) -> HcNetSdkDvrConfigRequest:
    """Return the local audio-output volume read request shape."""
    return _impl_configuration.ezviz_lan_audioout_volume_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_audio_volume_update_requests(login_id: int, channel: int, *, input_volume: int, output_volume: int) -> tuple[HcNetSdkDvrConfigRequest, HcNetSdkDvrConfigRequest]:
    """Return the two local audio-volume set calls made by the RN wrapper."""
    return _impl_configuration.ezviz_lan_audio_volume_update_requests(login_id, channel, input_volume=input_volume, output_volume=output_volume, _owner=_sys.modules[__name__])


def ezviz_lan_video_coding_get_config_request(login_id: int, channel: int) -> HcNetSdkDvrConfigRequest:
    """Return the local video-coding config read request shape."""
    return _impl_configuration.ezviz_lan_video_coding_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_video_coding_update_request(login_id: int, channel: int, *, video_encoding_type: int, video_frame_rate: int, video_bitrate: int) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN video-coding update request shape."""
    return _impl_requests.ezviz_lan_video_coding_update_request(login_id, channel, video_encoding_type=video_encoding_type, video_frame_rate=video_frame_rate, video_bitrate=video_bitrate, _owner=_sys.modules[__name__])


def ezviz_lan_pic_config_get_request(login_id: int, channel: int) -> HcNetSdkDvrConfigRequest:
    """Return the local image/OSD config read request shape."""
    return _impl_configuration.ezviz_lan_pic_config_get_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_pic_config_v30_get_request(login_id: int, channel: int) -> HcNetSdkDvrConfigRequest:
    """Return the traced legacy ``NET_DVR_PICCFG_V30`` read request shape."""
    return _impl_configuration.ezviz_lan_pic_config_v30_get_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_pic_config_update_request(login_id: int, channel: int, *, show_osd: int | None=None, channel_name: str | bytes | None=None) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN image/OSD update request shape."""
    return _impl_configuration.ezviz_lan_pic_config_update_request(login_id, channel, show_osd=show_osd, channel_name=channel_name, _owner=_sys.modules[__name__])


def ezviz_lan_hd_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local storage ``NET_DVR_HDCFG`` read request shape."""
    return _impl_configuration.ezviz_lan_hd_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_sd_format_start_request(login_id: int, disk_number: int) -> HcNetSdkFormatDiskRequest:
    """Return the local SD-card format start request shape."""
    return _impl_configuration.ezviz_lan_sd_format_start_request(login_id, disk_number, _owner=_sys.modules[__name__])


def ezviz_lan_sd_format_progress_request(format_handle: int) -> HcNetSdkFormatProgressRequest:
    """Return the local SD-card format progress request shape."""
    return _impl_configuration.ezviz_lan_sd_format_progress_request(format_handle, _owner=_sys.modules[__name__])


def ezviz_lan_sd_format_close_request(format_handle: int) -> HcNetSdkCloseFormatHandleRequest:
    """Return the local SD-card format close request shape."""
    return _impl_configuration.ezviz_lan_sd_format_close_request(format_handle, _owner=_sys.modules[__name__])


def ezviz_lan_sd_format_progress_result(*, native_succeeded: bool, current_disk: int=-1, current_disk_position: int=-1, status: int=-1, last_error: int=0) -> EzvizLanSdFormatProgress:
    """Map native SD format progress references to the RN result semantics."""
    return _impl_configuration.ezviz_lan_sd_format_progress_result(native_succeeded=native_succeeded, current_disk=current_disk, current_disk_position=current_disk_position, status=status, last_error=last_error, _owner=_sys.modules[__name__])


def hcnetsdk_setup_alarm_v30_request(login_id: int) -> HcNetSdkSetupAlarmRequest:
    """Return the legacy ``NET_DVR_SetupAlarmChan_V30`` request shape."""
    return _impl_requests.hcnetsdk_setup_alarm_v30_request(login_id, _owner=_sys.modules[__name__])


def hcnetsdk_setup_alarm_v41_request(login_id: int, *, level: int=0, alarm_info_type: int=0, ret_alarm_type_v40: int=0, ret_dev_info_version: int=0, ret_vqd_alarm_type: int=0, face_alarm_detection: int=0, support: int=0, broken_net_http: int=0, task_no: int=0) -> HcNetSdkSetupAlarmRequest:
    """Return a ``NET_DVR_SetupAlarmChan_V41`` request model."""
    return _impl_requests.hcnetsdk_setup_alarm_v41_request(login_id, level=level, alarm_info_type=alarm_info_type, ret_alarm_type_v40=ret_alarm_type_v40, ret_dev_info_version=ret_dev_info_version, ret_vqd_alarm_type=ret_vqd_alarm_type, face_alarm_detection=face_alarm_detection, support=support, broken_net_http=broken_net_http, task_no=task_no, _owner=_sys.modules[__name__])


def hcnetsdk_close_alarm_request(alarm_handle: int) -> HcNetSdkCloseAlarmRequest:
    """Return the ``NET_DVR_CloseAlarmChan_V30`` request shape."""
    return _impl_requests.hcnetsdk_close_alarm_request(alarm_handle, _owner=_sys.modules[__name__])


def hcnetsdk_set_sdk_local_cfg_request(cfg_type: int, *, structure: str, field_updates: Mapping[str, Any] | None=None, field_order: tuple[str, ...] | None=None) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return a generic ``NET_DVR_SetSDKLocalCfg`` request model."""
    return _impl_requests.hcnetsdk_set_sdk_local_cfg_request(cfg_type, structure=structure, field_updates=field_updates, field_order=field_order, _owner=_sys.modules[__name__])


def ezviz_hcnetsdk_local_ability_parse_request(*, enabled: int | bool=True) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local ability parser toggle exposed by the APK."""
    return _impl_discovery.ezviz_hcnetsdk_local_ability_parse_request(enabled=enabled, _owner=_sys.modules[__name__])


def ezviz_hcnetsdk_local_ptz_without_recv_request(*, without_recv: int | bool=True) -> HcNetSdkSetSdkLocalCfgRequest:
    """Return the SDK-local PTZ no-receive config exposed by the APK."""
    return _impl_configuration.ezviz_hcnetsdk_local_ptz_without_recv_request(without_recv=without_recv, _owner=_sys.modules[__name__])


def ezviz_lan_user_password_get_config_request(login_id: int) -> HcNetSdkDvrConfigRequest:
    """Return the local ``NET_DVR_USER_V30`` read request shape."""
    return _impl_configuration.ezviz_lan_user_password_get_config_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_user_password_update_request(login_id: int, password: str | bytes) -> HcNetSdkDvrConfigRequest:
    """Return the local admin-user password update request shape."""
    return _impl_authentication.ezviz_lan_user_password_update_request(login_id, password, _owner=_sys.modules[__name__])


def ezviz_lan_video_effect_get_config_request(login_id: int, channel: int=1) -> HcNetSdkDvrConfigRequest:
    """Return the local camera video-effect config read request shape."""
    return _impl_configuration.ezviz_lan_video_effect_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_video_effect_update_request(login_id: int, *, brightness: int, contrast: int, saturation: int, sharpness: int) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN camera video-effect update request shape."""
    return _impl_requests.ezviz_lan_video_effect_update_request(login_id, brightness=brightness, contrast=contrast, saturation=saturation, sharpness=sharpness, _owner=_sys.modules[__name__])


def ezviz_lan_backlight_wdr_get_config_request(login_id: int, channel: int=1) -> HcNetSdkDvrConfigRequest:
    """Return the local WDR/backlight config read request shape."""
    return _impl_configuration.ezviz_lan_backlight_wdr_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_backlight_wdr_update_request(login_id: int, *, wdr_enabled: int, backlight_mode: int) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN WDR/backlight update request shape."""
    return _impl_configuration.ezviz_lan_backlight_wdr_update_request(login_id, wdr_enabled=wdr_enabled, backlight_mode=backlight_mode, _owner=_sys.modules[__name__])


def ezviz_lan_day_night_get_config_request(login_id: int, channel: int=1) -> HcNetSdkDvrConfigRequest:
    """Return the local day/night config read request shape."""
    return _impl_configuration.ezviz_lan_day_night_get_config_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_day_night_update_request(login_id: int, *, day_night_filter_type: int, begin_time: int, begin_time_min: int, begin_time_sec: int, end_time: int, end_time_min: int, end_time_sec: int, night_to_day_filter_level: int) -> HcNetSdkDvrConfigRequest:
    """Return the RN LAN day/night update request shape."""
    return _impl_configuration.ezviz_lan_day_night_update_request(login_id, day_night_filter_type=day_night_filter_type, begin_time=begin_time, begin_time_min=begin_time_min, begin_time_sec=begin_time_sec, end_time=end_time, end_time_min=end_time_min, end_time_sec=end_time_sec, night_to_day_filter_level=night_to_day_filter_level, _owner=_sys.modules[__name__])


def hcnetsdk_device_ability_xml(root: str, *, channel: int | str | None=None, channel_tag: str='channelNO', version: str | None='2.0') -> bytes:
    """Return compact XML passed as ``NET_DVR_GetDeviceAbility`` input."""
    return _impl_configuration.hcnetsdk_device_ability_xml(root, channel=channel, channel_tag=channel_tag, version=version, _owner=_sys.modules[__name__])


def hcnetsdk_device_ability_request(login_id: int, ability_type: int, *, in_buffer: str | bytes | None=None, output_buffer_size: int=HCNETSDK_DEVICE_ABILITY_DEFAULT_OUTPUT_BUFFER_SIZE, retry_output_buffer_size: int | None=HCNETSDK_DEVICE_ABILITY_RETRY_OUTPUT_BUFFER_SIZE) -> HcNetSdkDeviceAbilityRequest:
    """Return a ``NET_DVR_GetDeviceAbility`` request model."""
    return _impl_configuration.hcnetsdk_device_ability_request(login_id, ability_type, in_buffer=in_buffer, output_buffer_size=output_buffer_size, retry_output_buffer_size=retry_output_buffer_size, _owner=_sys.modules[__name__])


def ezviz_lan_record_ability_input() -> bytes:
    """Return the playback conversion ability XML used by ``DeviceAbilityHelper``."""
    return _impl_configuration.ezviz_lan_record_ability_input(_owner=_sys.modules[__name__])


def ezviz_lan_audio_video_compress_info_input(channel: int) -> bytes:
    """Return the stream-config video ability XML used by the APK."""
    return _impl_requests.ezviz_lan_audio_video_compress_info_input(channel, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_ability_input(channel: int) -> bytes:
    """Return the PTZ ability XML used by ``DeviceAbilityHelper.c``."""
    return _impl_configuration.ezviz_lan_ptz_ability_input(channel, _owner=_sys.modules[__name__])


def ezviz_lan_image_display_param_ability_input(channel: int) -> bytes:
    """Return the image-display ability XML used by the RN LAN wrapper.

    Live devices may acknowledge this request with an empty body. The image
    parameter ranges used by the app are available through ``IPC_FRONT_PARAMETER``.
    """
    return _impl_configuration.ezviz_lan_image_display_param_ability_input(channel, _owner=_sys.modules[__name__])


def ezviz_lan_video_pic_ability_input(channel: int) -> bytes:
    """Return the video-picture ability XML used by the RN LAN wrapper."""
    return _impl_configuration.ezviz_lan_video_pic_ability_input(channel, _owner=_sys.modules[__name__])


def ezviz_lan_access_protocol_ability_input(channel: int | str='0xff') -> bytes:
    """Return the access-protocol ability XML used by local-add setup."""
    return _impl_configuration.ezviz_lan_access_protocol_ability_input(channel, _owner=_sys.modules[__name__])


def ezviz_lan_rn_device_ability_request(login_id: int, ability_type: int, *, in_buffer: str | bytes | None=None) -> HcNetSdkDeviceAbilityRequest:
    """Return the generic 2 MiB RN LAN ``NET_DVR_GetDeviceAbility`` shape."""
    return _impl_configuration.ezviz_lan_rn_device_ability_request(login_id, ability_type, in_buffer=in_buffer, _owner=_sys.modules[__name__])


def ezviz_lan_access_protocol_ability_request(login_id: int, channel: int | str='0xff') -> HcNetSdkDeviceAbilityRequest:
    """Return the access-protocol ability request used by local-add setup."""
    return _impl_configuration.ezviz_lan_access_protocol_ability_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_image_display_param_ability_request(login_id: int, channel: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN image-display ability request shape.

    Prefer ``ezviz_lan_ipc_front_parameter_ability_request`` for a live
    ``CAMERAPARA`` response containing image parameter ranges.
    """
    return _impl_configuration.ezviz_lan_image_display_param_ability_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_video_pic_ability_request(login_id: int, channel: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the RN LAN video-picture ability request shape."""
    return _impl_configuration.ezviz_lan_video_pic_ability_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_audio_video_compress_info_ability_request(login_id: int, channel: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the stream-config audio/video ability request shape."""
    return _impl_configuration.ezviz_lan_audio_video_compress_info_ability_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_soft_hardware_ability_request(login_id: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the device software/hardware ability request shape."""
    return _impl_configuration.ezviz_lan_soft_hardware_ability_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_record_ability_request(login_id: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the record/playback conversion ability request shape."""
    return _impl_configuration.ezviz_lan_record_ability_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_ability_request(login_id: int, channel: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the local PTZ ability request shape used by the Android app."""
    return _impl_configuration.ezviz_lan_ptz_ability_request(login_id, channel, _owner=_sys.modules[__name__])


def ezviz_lan_ipc_front_parameter_ability_request(login_id: int) -> HcNetSdkDeviceAbilityRequest:
    """Return the local IPC-front-parameter request used for mirror ability."""
    return _impl_configuration.ezviz_lan_ipc_front_parameter_ability_request(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_ability(response: str | bytes) -> EzvizLanPtzAbility:
    """Parse the PTZ ability fields read by EZVIZ's ``PTZAbilityHandler``."""
    return _impl_configuration.ezviz_lan_ptz_ability(response, _owner=_sys.modules[__name__])


def ezviz_lan_access_protocol_ability(response: str | bytes) -> EzvizLanAccessProtocolAbility:
    """Parse safe local-add fields from ``AccessProtocolAbility`` XML."""
    return _impl_configuration.ezviz_lan_access_protocol_ability(response, _owner=_sys.modules[__name__])


def ezviz_lan_video_pic_ability(response: str | bytes) -> EzvizLanVideoPicAbility:
    """Parse safe OSD/motion fields from ``VideoPicAbility`` XML."""
    return _impl_configuration.ezviz_lan_video_pic_ability(response, _owner=_sys.modules[__name__])


def ezviz_lan_ipc_front_parameter_ability(response: str | bytes) -> EzvizLanIpcFrontParameterAbility:
    """Parse safe image/front-parameter ranges from ``CAMERAPARA`` XML."""
    return _impl_configuration.ezviz_lan_ipc_front_parameter_ability(response, _owner=_sys.modules[__name__])


def ezviz_lan_audio_video_compress_info(response: str | bytes) -> EzvizLanAudioVideoCompressInfo:
    """Parse safe stream/audio fields from ``AudioVideoCompressInfo`` XML."""
    return _impl_requests.ezviz_lan_audio_video_compress_info(response, _owner=_sys.modules[__name__])


def ezviz_lan_soft_hardware_ability(response: str | bytes) -> EzvizLanDeviceSoftHardwareAbility:
    """Parse ``DEVICE_SOFTHARDWARE_ABILITY`` fields used by the app."""
    return _impl_configuration.ezviz_lan_soft_hardware_ability(response, _owner=_sys.modules[__name__])


def ezviz_lan_playback_convert_ability(response: str | bytes) -> EzvizLanPlaybackConvertAbility:
    """Parse playback conversion entries from ``RecordAbility`` XML."""
    return _impl_configuration.ezviz_lan_playback_convert_ability(response, _owner=_sys.modules[__name__])


def ezviz_cas_ptz_command(command: int) -> str:
    """Return the CAS/cloud PTZ command string used by the EZVIZ app."""
    return _impl_configuration.ezviz_cas_ptz_command(command, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_native_command(command: int) -> int:
    """Return the HCNetSDK LAN PTZ value for an EZVIZ app command ID."""
    return _impl_configuration.ezviz_lan_ptz_native_command(command, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_is_preset_command(command: int) -> bool:
    """Return whether the app routes this PTZ command through the preset API."""
    return _impl_configuration.ezviz_lan_ptz_is_preset_command(command, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_control_request(login_id: int, channel: int, command: int, *, action: int=EZVIZ_LAN_PTZ_ACTION_START, speed: int=EZVIZ_LAN_PTZ_SPEED_DEFAULT) -> HcNetSdkPtzControlRequest:
    """Return the APK-observed local PTZ control call for non-preset commands."""
    return _impl_configuration.ezviz_lan_ptz_control_request(login_id, channel, command, action=action, speed=speed, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_preset_request(login_id: int, channel: int, command: int, *, preset_index: int=0) -> HcNetSdkPtzPresetRequest:
    """Return the APK-observed local PTZ preset call shape."""
    return _impl_configuration.ezviz_lan_ptz_preset_request(login_id, channel, command, preset_index=preset_index, _owner=_sys.modules[__name__])


def ezviz_lan_ptz_request(login_id: int, channel: int, command: int, *, action: int=EZVIZ_LAN_PTZ_ACTION_START, speed: int=EZVIZ_LAN_PTZ_SPEED_DEFAULT, preset_index: int=0) -> HcNetSdkPtzControlRequest | HcNetSdkPtzPresetRequest:
    """Return the same PTZ native-call branch used by ``ptzControlLan``."""
    return _impl_configuration.ezviz_lan_ptz_request(login_id, channel, command, action=action, speed=speed, preset_index=preset_index, _owner=_sys.modules[__name__])


def ezviz_lan_settings_error_code(hcnetsdk_error: int) -> int:
    """Return the LAN settings UI error code for an HCNetSDK error."""
    return _impl_requests.ezviz_lan_settings_error_code(hcnetsdk_error, _owner=_sys.modules[__name__])


def ezviz_lan_settings_error_clears_password(error_code: int) -> bool:
    """Return whether LanDeviceListActivity.q(...) clears the LAN password."""
    return _impl_authentication.ezviz_lan_settings_error_clears_password(error_code, _owner=_sys.modules[__name__])


def ezviz_lan_settings_login_succeeded(login_id: int) -> bool:
    """Return whether the settings presenter treats an HCNetSDK login as OK."""
    return _impl_authentication.ezviz_lan_settings_login_succeeded(login_id, _owner=_sys.modules[__name__])


def ezviz_lan_play_device_login_succeeded(login_id: int) -> bool:
    """Return whether DeviceInfoEx.loginPlayDevice(...) returned a login id."""
    return _impl_authentication.ezviz_lan_play_device_login_succeeded(login_id, _owner=_sys.modules[__name__])


def classify_hcnetsdk_tcp_payload(data: bytes) -> HcNetSdkTcpPayloadShape:
    """Classify raw HCNetSDK command-port bytes without decoding secrets.

    Port 8000 traffic is still proprietary. This helper gives future live
    captures a stable Python target by recording byte-shape facts only:
    framing candidates, aggregate byte ratios, XML tag names when present, and
    common length-prefix guesses. It intentionally does not parse credentials.
    """
    return _impl_discovery.classify_hcnetsdk_tcp_payload(data, _owner=_sys.modules[__name__])


def parse_hcnetsdk_tcp_shape_log_line(line: str) -> HcNetSdkTcpShapeLogRecord | None:
    """Parse one secret-safe HCNetSDK TCP shape log line.

    These lines contain only metadata, not raw bytes. This parser turns that
    metadata into the same Python shape model used by direct byte
    classification, so captured traces can drive packet-builder tests without
    copying secrets into fixtures.
    """
    return _impl_discovery.parse_hcnetsdk_tcp_shape_log_line(line, _owner=_sys.modules[__name__])


def parse_hcnetsdk_semantic_log_line(line: str) -> HcNetSdkSemanticLogEvent | None:
    """Parse one secret-safe HCNetSDK semantic event line."""
    return _impl_discovery.parse_hcnetsdk_semantic_log_line(line, _owner=_sys.modules[__name__])


def summarize_hcnetsdk_command_trace(lines: Iterable[str]) -> HcNetSdkCommandTraceSummary:
    """Summarize one mixed HCNetSDK command-shape/semantic trace.

    This reducer is deliberately conservative: it uses semantic enter/leave
    boundaries to associate redacted write command candidates with
    HCNETUtil.s(...) settings login, leaves all later command candidates in
    followup_commands, and records only boolean proof points for playback
    login, keyframe request, and command-socket media.
    """
    return _impl_discovery.summarize_hcnetsdk_command_trace(lines, _owner=_sys.modules[__name__])


def parse_hcnetsdk_tcp_frame_header(data: bytes) -> HcNetSdkTcpFrameHeader:
    """Parse the observed 16-byte HCNetSDK command-port frame header."""
    return _impl_discovery.parse_hcnetsdk_tcp_frame_header(data, _owner=_sys.modules[__name__])


def parse_hcnetsdk_tcp_frame(data: bytes) -> HcNetSdkTcpFrame:
    """Parse one complete observed HCNetSDK command-port frame."""
    return _impl_discovery.parse_hcnetsdk_tcp_frame(data, _owner=_sys.modules[__name__])


def read_hcnetsdk_tcp_frame(sock: Any, *, max_frame_bytes: int | None=None, allow_short_ack: bool=True) -> HcNetSdkTcpFrame:
    """Read one complete HCNetSDK command-port frame from a socket-like object."""
    return _impl_requests.read_hcnetsdk_tcp_frame(sock, max_frame_bytes=max_frame_bytes, allow_short_ack=allow_short_ack, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_login_request_frame(public_key_der: bytes, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str) -> bytes:
    """Build the first port-8000 RSA login frame.

    The native SDK sends a PKCS#1 ``RSAPublicKey`` DER blob, not the longer
    SubjectPublicKeyInfo form returned by many RSA exporters.
    """
    return _impl_authentication.hcnetsdk_command_port_login_request_frame(public_key_der, username=username, local_ip=local_ip, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_password_digest(username: str, password: str | bytes, password_seed: bytes) -> bytes:
    """Return the native SDK SHA-256 password branch for command-port login.

    This is a device-protocol compatibility digest, not password storage.
    """
    return _impl_authentication.hcnetsdk_command_port_password_digest(username, password, password_seed, _owner=_sys.modules[__name__])


def _hcnetsdk_command_port_md5_digest(data: bytes=b'') -> Any:
    return _impl_requests._hcnetsdk_command_port_md5_digest(data, _owner=_sys.modules[__name__])


def _hcnetsdk_command_port_md5_hmac(key: bytes, data: bytes) -> bytes:
    return _impl_requests._hcnetsdk_command_port_md5_hmac(key, data, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_login_proof(username: str, password: str | bytes, challenge: bytes, password_seed: bytes) -> tuple[bytes, bytes]:
    """Return the two proof chunks for the second command-port login frame.

    The native device handshake uses MD5 HMAC branches here for compatibility;
    these values are not persisted password hashes.
    """
    return _impl_authentication.hcnetsdk_command_port_login_proof(username, password, challenge, password_seed, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_login_proof_frame(*, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, password: str | bytes, challenge: bytes, password_seed: bytes, local_ip: str) -> bytes:
    """Build the second port-8000 login proof frame."""
    return _impl_authentication.hcnetsdk_command_port_login_proof_frame(username=username, password=password, challenge=challenge, password_seed=password_seed, local_ip=local_ip, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_control_template_from_frame(frame: bytes, *, addend: int | None=None, addend_delta: int | None=None, auth_seed: int | None=None, key: bytes | None=None, mask_seed: bytes=b'\x00' * HCNETSDK_COMMAND_PORT_AUTH_MASK_LENGTH, body_tail_transform: str | None=None, name: str | None=None) -> HcNetSdkCommandPortControlTemplate:
    """Extract the reusable command id and body tail from a ``0x63`` frame."""
    return _impl_requests.hcnetsdk_command_port_control_template_from_frame(frame, addend=addend, addend_delta=addend_delta, auth_seed=auth_seed, key=key, mask_seed=mask_seed, body_tail_transform=body_tail_transform, name=name, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_public_key_der(rsa_key: Any) -> bytes:
    """Return PKCS#1 ``RSAPublicKey`` DER for a PyCryptodome RSA key."""
    return _impl_requests.hcnetsdk_command_port_public_key_der(rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_rsa_key() -> Any:
    """Generate the protocol-mandated RSA key for command-port login."""
    return _impl_requests.hcnetsdk_command_port_rsa_key(_owner=_sys.modules[__name__])


def decode_hcnetsdk_command_port_login_challenge(response: HcNetSdkTcpFrame, rsa_key: Any) -> HcNetSdkCommandPortLoginChallenge:
    """Decrypt the first command-port login response with the RSA private key."""
    return _impl_authentication.decode_hcnetsdk_command_port_login_challenge(response, rsa_key, _owner=_sys.modules[__name__])


def parse_hcnetsdk_command_port_login_session(first_response: HcNetSdkTcpFrame, second_response: HcNetSdkTcpFrame, *, challenge: bytes=b'', password_seed: bytes=b'') -> HcNetSdkCommandPortLoginSession:
    """Parse the successful second command-port login response."""
    return _impl_discovery.parse_hcnetsdk_command_port_login_session(first_response, second_response, challenge=challenge, password_seed=password_seed, _owner=_sys.modules[__name__])


def iter_hcnetsdk_tcp_frame_shapes(records: Iterable[HcNetSdkTcpShapeLogRecord]) -> Iterator[HcNetSdkTcpFrameShape]:
    """Yield command frames reconstructed from secret-safe socket shape logs.

    Some logs record response headers and bodies as separate reads when the app
    asks libc for 16 bytes first and then the implied body length. This reducer
    pairs those adjacent records without needing payload bytes. Whole-frame
    writes are yielded as header-only shapes because their body content remains
    intentionally redacted.
    """
    return _impl_requests.iter_hcnetsdk_tcp_frame_shapes(records, _owner=_sys.modules[__name__])


def iter_hcnetsdk_real_data_mpegps(packets: Iterable[HcNetSdkRealDataPacket], *, include_system_header: bool=False) -> Iterator[bytes]:
    """Yield MPEG-PS-like payloads from HCNetSDK real-play callback packets."""
    return _impl_requests.iter_hcnetsdk_real_data_mpegps(packets, include_system_header=include_system_header, _owner=_sys.modules[__name__])


def ezviz_lan_play_device_login(endpoint: HcNetSdkLanEndpoint, *, check_last_login_status: bool=False) -> EzvizLanPlayDeviceLogin:
    """Build the player-side LAN HCNetSDK login step observed in the APK.

    The settings screen's login id is only a gate for opening the player. The
    player path then calls IPlayDataInfo.loginPlayDevice(...) /
    DeviceInfoEx.loginPlayDevice(...) and uses that returned NetSDK id for
    InitParam.iNetSDKUserId and the later keyframe request.
    """
    return _impl_authentication.ezviz_lan_play_device_login(endpoint, check_last_login_status=check_last_login_status, _owner=_sys.modules[__name__])


def ezviz_lan_settings_channel_number(*, analog_channel_count: int, digital_channel_count: int, analog_start_channel: int, digital_start_channel: int) -> int:
    """Return the channel selected by LanDeviceListActivity.z0(...)."""
    return _impl_requests.ezviz_lan_settings_channel_number(analog_channel_count=analog_channel_count, digital_channel_count=digital_channel_count, analog_start_channel=analog_start_channel, digital_start_channel=digital_start_channel, _owner=_sys.modules[__name__])


def ezviz_lan_playback_intent(serial: str, *, channel_number: int, netsdk_login_id: int, ssid: str | None=None, lan_user_id: int | None=None) -> EzvizLanPlaybackIntent:
    """Build the LAN playback extras passed into VideoPlayActivity.

    netsdk_login_id is validated because the settings screen only opens
    playback after HCNetSDK login succeeds. The intent EXTRA_LAN_USERID is
    separate: ActivityUtil.b(...) parses it from the optional SSID string and
    otherwise sends -1. The stream core performs/uses its own NetSDK login
    when creating the native init params.
    """
    return _impl_requests.ezviz_lan_playback_intent(serial, channel_number=channel_number, netsdk_login_id=netsdk_login_id, ssid=ssid, lan_user_id=lan_user_id, _owner=_sys.modules[__name__])


def ezviz_lan_video_qualities() -> tuple[EzvizLanVideoQuality, ...]:
    """Return the two LAN quality entries exposed by the EZVIZ app."""
    return _impl_requests.ezviz_lan_video_qualities(_owner=_sys.modules[__name__])


def ezviz_lan_video_level_for_stream_type(stream_type: int) -> int:
    """Return the app's default LAN video level for a main/sub stream type."""
    return _impl_requests.ezviz_lan_video_level_for_stream_type(stream_type, _owner=_sys.modules[__name__])


def ezviz_lan_live_view_params(endpoint: HcNetSdkLanEndpoint, *, channel_number: int=1, channel_serial: str | None=None, channel_index: str | None=None, channel_count: int | None=None, stream_type: int=1, video_level: int | None=None, netsdk_login_id: int=-1) -> EzvizLanLiveViewParams:
    """Build the LAN fields the EZVIZ player passes into its stream SDK.

    The Android app still uses ``LivePlaySource`` for LAN preview. The key
    difference is that the converted device param has ``isLocal()`` true and
    carries local IP/command/stream ports; when HCNetSDK login succeeds, the
    stream core also forwards the NetSDK login id and channel number.
    """
    return _impl_requests.ezviz_lan_live_view_params(endpoint, channel_number=channel_number, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=stream_type, video_level=video_level, netsdk_login_id=netsdk_login_id, _owner=_sys.modules[__name__])


def ezviz_lan_preview_plan(endpoint: HcNetSdkLanEndpoint, verification_code: str, *, channel_number: int=1, channel_serial: str | None=None, channel_index: str | None=None, channel_count: int | None=None, stream_type: int=1, video_level: int | None=None, netsdk_login_id: int=-1, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME) -> EzvizLanPreviewPlan:
    """Build the APK-observed LAN preview setup sequence.

    The Java layer logs in through HCNetSDK first, passes the resulting login
    id into EZ stream ``InitParam``, starts native preview through
    ``NativeApi.startPreview()``, then asks HCNetSDK to force an I-frame for
    the selected channel and stream type.
    """
    return _impl_requests.ezviz_lan_preview_plan(endpoint, verification_code, channel_number=channel_number, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=stream_type, video_level=video_level, netsdk_login_id=netsdk_login_id, username=username, _owner=_sys.modules[__name__])


def ezviz_lan_complete_playback_path(endpoint: HcNetSdkLanEndpoint, verification_code: str, *, settings_login_id: int, play_device_login_id: int, analog_channel_count: int, digital_channel_count: int, analog_start_channel: int, digital_start_channel: int, channel_serial: str | None=None, channel_index: str | None=None, channel_count: int | None=None, stream_type: int=EZVIZ_LAN_MAIN_STREAM_TYPE, video_level: int | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, ssid: str | None=None, lan_user_id: int | None=None) -> EzvizLanPlaybackPath:  # noqa: PLR0913
    """Build the full APK-observed LAN Live View playback path.

    The settings-screen login id and the player-owned NetSDK login id are
    intentionally separate. The app first uses the settings login to allow the
    handoff into the player, then the player obtains/reuses a NetSDK id through
    DeviceInfoEx.loginPlayDevice(...) and passes that id into native preview
    and the post-start keyframe request.
    """
    return _impl_requests.ezviz_lan_complete_playback_path(endpoint, verification_code, settings_login_id=settings_login_id, play_device_login_id=play_device_login_id, analog_channel_count=analog_channel_count, digital_channel_count=digital_channel_count, analog_start_channel=analog_start_channel, digital_start_channel=digital_start_channel, channel_serial=channel_serial, channel_index=channel_index, channel_count=channel_count, stream_type=stream_type, video_level=video_level, username=username, ssid=ssid, lan_user_id=lan_user_id, _owner=_sys.modules[__name__])


def build_ezviz_local_stream_setup_request_body(*, session: str | int, rate: str | int=0, mode: str | int=0) -> bytes:
    """Build the plaintext XML body for the observed 0x3105 request."""
    return _impl_requests.build_ezviz_local_stream_setup_request_body(session=session, rate=rate, mode=mode, _owner=_sys.modules[__name__])


def build_ezviz_local_stop_preview_request_body(*, operation_code: str, session: str | int) -> bytes:
    """Build the native session-scoped bye; never generate wildcard stops."""
    return _impl_requests.build_ezviz_local_stop_preview_request_body(operation_code=operation_code, session=session, _owner=_sys.modules[__name__])


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
def _wait_for_socket_io(sock: Any, *, readable: bool, timeout: float) -> bool | None:
    """Wait for real socket readiness without changing its shared timeout."""
    return _impl_requests._wait_for_socket_io(sock, readable=readable, timeout=timeout, _owner=_sys.modules[__name__])


def _remaining_timeout(deadline: float | None, monotonic: Callable[[], float]) -> float | None:
    """Return time left before an absolute local-stream deadline."""
    return _impl_requests._remaining_timeout(deadline, monotonic, _owner=_sys.modules[__name__])


def _send_all_with_timeout(sock: Any, data: bytes, *, timeout: float | None, deadline: float | None, monotonic: Callable[[], float]) -> None:
    """Send a frame without letting writes exceed an optional deadline."""
    return _impl_requests._send_all_with_timeout(sock, data, timeout=timeout, deadline=deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


def _send_all_before_deadline(sock: Any, data: bytes, *, operation_deadline: float, configured_timeout: float | None, capture_deadline: bool, monotonic: Callable[[], float]) -> bool:
    """Partially send on a real socket while recomputing its deadline."""
    return _impl_requests._send_all_before_deadline(sock, data, operation_deadline=operation_deadline, configured_timeout=configured_timeout, capture_deadline=capture_deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


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
def _connect_with_optional_source_address(socket_factory: SocketFactory, address: tuple[str, int], timeout: float | None, *, source_address: SocketSourceAddress=None, deadline: float | None=None, monotonic: Callable[[], float]=time.monotonic) -> Any:
    return _impl_requests._connect_with_optional_source_address(socket_factory, address, timeout, source_address=source_address, deadline=deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


def _create_reusable_source_connection(address: tuple[str, int], timeout: float | None, *, source_address: tuple[str, int], deadline: float | None=None, monotonic: Callable[[], float]=time.monotonic) -> socket.socket:
    """Connect from an exact source port with platform-safe ownership."""
    return _impl_requests._create_reusable_source_connection(address, timeout, source_address=source_address, deadline=deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


def _connect_attempt_settings(timeout: float | None, *, deadline: float | None, monotonic: Callable[[], float]) -> tuple[float | None, bool]:
    """Return the timeout and whether the absolute deadline constrains it."""
    return _impl_requests._connect_attempt_settings(timeout, deadline=deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


def _create_deadline_connection(address: tuple[str, int], timeout: float | None, *, deadline: float, monotonic: Callable[[], float]) -> socket.socket:
    """Connect to resolved addresses without renewing an absolute deadline."""
    return _impl_requests._create_deadline_connection(address, timeout, deadline=deadline, monotonic=monotonic, _owner=_sys.modules[__name__])


def _getaddrinfo_before_deadline(host: str, port: int, *, deadline: float | None, monotonic: Callable[[], float], resolver: BoundedResolver | None=None) -> list[tuple[Any, ...]]:
    """Use the shared bounded resolver, or an explicitly owned injected service."""
    return _impl_requests._getaddrinfo_before_deadline(host, port, deadline=deadline, monotonic=monotonic, resolver=resolver, _owner=_sys.modules[__name__])


def _connect_bound_source_socket(family: int, sock_type: int, protocol: int, target: Any, timeout: float | None, *, source_address: SocketBindAddress, exclusive: bool) -> socket.socket:
    """Bind and connect one source socket with the requested ownership mode."""
    return _impl_requests._connect_bound_source_socket(family, sock_type, protocol, target, timeout, source_address=source_address, exclusive=exclusive, _owner=_sys.modules[__name__])


def _windows_concrete_source_address(source_address: tuple[str, int], family: int, target: Any) -> SocketBindAddress:
    """Resolve a wildcard source to the interface selected for the target."""
    return _impl_requests._windows_concrete_source_address(source_address, family, target, _owner=_sys.modules[__name__])


def parse_ezviz_local_device(data: Mapping[str, Any]) -> EzvizLocalDevice:
    """Parse one EZVIZ ``/v3/devices/loc/list`` local-device record."""
    return _impl_discovery.parse_ezviz_local_device(data, _owner=_sys.modules[__name__])


def parse_sadp_response(data: bytes | str) -> SadpDeviceInfo:
    """Parse an XML SADP response body into a small field mapping."""
    return _impl_discovery.parse_sadp_response(data, _owner=_sys.modules[__name__])


def parse_ezviz_local_sdk_frame_header(data: bytes) -> EzvizLocalSdkFrameHeader:
    """Parse the 32-byte EZVIZ local SDK control header.

    Normal app traces against a directly-owned camera showed this
    framing on both the command port and the stream setup port before XML
    bodies. The helper only parses the non-secret header; callers can decide
    whether retaining any body bytes is appropriate for their workflow.
    """
    return _impl_discovery.parse_ezviz_local_sdk_frame_header(data, _owner=_sys.modules[__name__])


def build_ezviz_local_sdk_frame_header(*, command: int, body_length: int=0, sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build the 32-byte EZVIZ local SDK header observed in app traces.

    This helper intentionally handles only the non-secret binary envelope. The
    body is caller-supplied because the XML fields still need classification
    before they are safe to persist or synthesize from app captures.
    """
    return _impl_requests.build_ezviz_local_sdk_frame_header(command=command, body_length=body_length, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def build_ezviz_local_sdk_frame(*, command: int, body: bytes | str=b'', sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build an EZVIZ local SDK frame from a command and caller-owned body."""
    return _impl_requests.build_ezviz_local_sdk_frame(command=command, body=body, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def encrypt_ezviz_local_sdk_body_aes_cbc(body: bytes | str, *, key: bytes | str, iv: bytes | str) -> bytes:
    """Encrypt a local SDK control body with AES-CBC/PKCS#5 padding.

    The EZVIZ app's local control frames use AES-CBC with 16-byte block
    padding before wrapping the encrypted bytes in the local SDK frame
    envelope. This helper does not derive or store device secrets; callers
    must supply key and IV bytes from their own credential source.
    """
    return _impl_authentication.encrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv, _owner=_sys.modules[__name__])


def decrypt_ezviz_local_sdk_body_aes_cbc(body: bytes, *, key: bytes | str, iv: bytes | str) -> bytes:
    """Decrypt a local SDK AES-CBC/PKCS#5 control body."""
    return _impl_authentication.decrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv, _owner=_sys.modules[__name__])


def build_encrypted_ezviz_local_sdk_frame(*, command: int, body: bytes | str, key: bytes | str, iv: bytes | str, sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build an encrypted EZVIZ local SDK control frame.

    This is the reusable piece needed by the standalone reproducer after
    a caller has resolved the local CAS device-info key and IV source.
    """
    return _impl_requests.build_encrypted_ezviz_local_sdk_frame(command=command, body=body, key=key, iv=iv, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def build_ezviz_local_sdk_ssl_frame(*, command: int, body: bytes | str, key: bytes | str, iv: bytes | str, sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build the app-observed local SDK SSL-like frame.

    Normal EZVIZ live view sends local control frames as a 32-byte local SDK
    header, AES-CBC/PKCS#5 ciphertext, and a 32-byte lowercase ASCII MD5 hex
    trailer over that ciphertext. The header body length covers only the
    ciphertext, matching the observed ``0x2011`` and ``0x3105`` sends.
    """
    return _impl_requests.build_ezviz_local_sdk_ssl_frame(command=command, body=body, key=key, iv=iv, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def build_ezviz_cas_encrypted_local_sdk_frame(*, command: int, body: bytes | str, device_info: EzvizCasDeviceInfo, sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build a local SDK frame using the app-observed CAS device-info tuple."""
    return _impl_requests.build_ezviz_cas_encrypted_local_sdk_frame(command=command, body=body, device_info=device_info, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def build_ezviz_cas_ssl_local_sdk_frame(*, command: int, body: bytes | str, device_info: EzvizCasDeviceInfo, iv: bytes | str, sequence: int=0, version: int=16777216, marker: int=0, status: int=4294967295, reserved: int=0) -> bytes:
    """Build a direct-local SDK frame with CAS key and ciphertext MD5 trailer."""
    return _impl_requests.build_ezviz_cas_ssl_local_sdk_frame(command=command, body=body, device_info=device_info, iv=iv, sequence=sequence, version=version, marker=marker, status=status, reserved=reserved, _owner=_sys.modules[__name__])


def parse_ezviz_local_sdk_frame(data: bytes) -> EzvizLocalSdkFrame:
    """Parse an EZVIZ local SDK frame and validate its declared body length."""
    return _impl_discovery.parse_ezviz_local_sdk_frame(data, _owner=_sys.modules[__name__])


def parse_ezviz_local_sdk_xml_fields(data: bytes | str | EzvizLocalSdkFrame) -> dict[str, str]:
    """Parse a local SDK XML body into simple tag text fields."""
    return _impl_discovery.parse_ezviz_local_sdk_xml_fields(data, _owner=_sys.modules[__name__])


def classify_ezviz_local_sdk_body(data: bytes) -> EzvizLocalSdkBodyShape:
    """Classify frame body shape without exposing body contents.

    The app trace showed plain XML response bodies, but request bodies
    did not surface XML tags under redacted instrumentation. This helper keeps
    only aggregate properties and tag names, so it is safe to store in notes.
    """
    return _impl_discovery.classify_ezviz_local_sdk_body(data, _owner=_sys.modules[__name__])


def read_ezviz_local_sdk_frame(sock: Any, *, trailer_length: int=0) -> EzvizLocalSdkFrame:
    """Read one complete EZVIZ local SDK frame from a socket-like object."""
    return _impl_requests.read_ezviz_local_sdk_frame(sock, trailer_length=trailer_length, _owner=_sys.modules[__name__])


def parse_ezviz_interleaved_rtp_frame_header(data: bytes) -> EzvizInterleavedRtpFrameHeader:
    """Parse the 4-byte interleaved RTP prefix from EZVIZ local media.

    The local stream port emits dollar + channel + big-endian length before an
    RTP payload. The RTP payload then carries MPEG-PS data, often beginning
    with an RTP header followed by the MPEG-PS pack header.
    """
    return _impl_discovery.parse_ezviz_interleaved_rtp_frame_header(data, _owner=_sys.modules[__name__])


def build_ezviz_interleaved_rtp_frame_header(*, channel: int, payload_length: int) -> bytes:
    """Build a 4-byte interleaved RTP header."""
    return _impl_requests.build_ezviz_interleaved_rtp_frame_header(channel=channel, payload_length=payload_length, _owner=_sys.modules[__name__])


def read_ezviz_interleaved_rtp_frame(sock: Any) -> EzvizInterleavedRtpFrame:
    """Read one complete interleaved RTP frame from a socket-like object."""
    return _impl_requests.read_ezviz_interleaved_rtp_frame(sock, _owner=_sys.modules[__name__])


def read_ezviz_interleaved_rtp_frame_after_prefix(sock: Any, *, max_prefix_bytes: int=4096) -> EzvizInterleavedRtpFrameWithPrefix:
    """Read the first interleaved RTP frame, preserving any binary preface.

    The local stream port sends a short binary preface after the encrypted
    ``0x3105`` setup succeeds, then switches to ``$`` interleaved RTP frames.
    A standalone reproducer needs to tolerate that preface without discarding
    it silently.
    """
    return _impl_requests.read_ezviz_interleaved_rtp_frame_after_prefix(sock, max_prefix_bytes=max_prefix_bytes, _owner=_sys.modules[__name__])


def read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock: Any, *, max_prefix_bytes: int=4096) -> EzvizInterleavedRtpFrameWithPrefix:
    """Read one HCNetSDK command-port interleaved media frame.

    The local stream port uses ``$`` + channel + big-endian payload length.
    Port 8000 uses the same magic byte, but its two length bytes are a
    little-endian total frame length. Keeping this reader separate prevents the
    command-port path from coalescing adjacent media frames.
    """
    return _impl_requests.read_hcnetsdk_command_port_interleaved_frame_after_prefix(sock, max_prefix_bytes=max_prefix_bytes, _owner=_sys.modules[__name__])


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
def hcnetsdk_device_ability_command_port_body_tail(request: HcNetSdkDeviceAbilityRequest) -> bytes:
    """Return the pure command-port tail for ``NET_DVR_GetDeviceAbility``."""
    return _impl_configuration.hcnetsdk_device_ability_command_port_body_tail(request, _owner=_sys.modules[__name__])


def hcnetsdk_device_ability_command_port_template(request: HcNetSdkDeviceAbilityRequest, *, addend_delta: int | None=0, addend: int | None=None, name: str | None=None) -> HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_GetDeviceAbility``."""
    return _impl_configuration.hcnetsdk_device_ability_command_port_template(request, addend_delta=addend_delta, addend=addend, name=name, _owner=_sys.modules[__name__])


def hcnetsdk_dvr_config_command_port_template(request: HcNetSdkDvrConfigRequest, *, command_id: int | None=None, body_tail: bytes | None=None, addend_delta: int | None=0, addend: int | None=None, name: str | None=None) -> HcNetSdkCommandPortControlTemplate:
    """Return a traced command-port template for ``NET_DVR_GetDVRConfig``.

    ``NET_DVR_GetDVRConfig`` does not carry the public SDK ``dwCommand`` value
    directly on the wire. Native traces show each config surface dispatching to
    a device-protocol command id, so unknown config commands must be supplied
    explicitly until traced.
    """
    return _impl_configuration.hcnetsdk_dvr_config_command_port_template(request, command_id=command_id, body_tail=body_tail, addend_delta=addend_delta, addend=addend, name=name, _owner=_sys.modules[__name__])


def hcnetsdk_dvr_config_command_port_body_tail(request: HcNetSdkDvrConfigRequest) -> bytes:
    """Return the traced command-port body tail for a DVR config request."""
    return _impl_configuration.hcnetsdk_dvr_config_command_port_body_tail(request, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_config_command_port_body_tail(request: HcNetSdkStdXmlConfigRequest | str | bytes) -> bytes:
    """Return the traced command-port tail for ``NET_DVR_STDXMLConfig``.

    A live Android SDK trace showed STDXML using the generated command-port
    control frame with command ``0x117000``, eight extra reserved bytes, a
    twelve-byte request descriptor, and then the request/in-buffer bytes.
    """
    return _impl_configuration.hcnetsdk_stdxml_config_command_port_body_tail(request, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_config_command_port_template(request: HcNetSdkStdXmlConfigRequest | str | bytes, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, name: str | None=None) -> HcNetSdkCommandPortControlTemplate:
    """Return a generated command-port template for ``NET_DVR_STDXMLConfig``."""
    return _impl_configuration.hcnetsdk_stdxml_config_command_port_template(request, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name=name, _owner=_sys.modules[__name__])


def hcnetsdk_command_port_execute_template(endpoint: HcNetSdkLanEndpoint, password: str | bytes, template: HcNetSdkCommandPortControlTemplate, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> HcNetSdkCommandPortControlResponse:
    """Execute one generated command-port control template in pure Python.

    The EZVIZ devices tested so far accept this pattern for local capability
    reads: perform the RSA login on one socket, close it, then send the
    authenticated control command on a fresh command-port socket.
    """
    return _impl_requests.hcnetsdk_command_port_execute_template(endpoint, password, template, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_get_device_ability_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, request: HcNetSdkDeviceAbilityRequest, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> bytes:
    """Read ``NET_DVR_GetDeviceAbility`` through the pure command-port path."""
    return _impl_configuration.hcnetsdk_get_device_ability_command_port(endpoint, password, request, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_get_dvr_config_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, request: HcNetSdkDvrConfigRequest, *, command_id: int | None=None, body_tail: bytes | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> bytes:
    """Read a traced ``NET_DVR_GetDVRConfig`` output buffer in pure Python."""
    return _impl_configuration.hcnetsdk_get_dvr_config_command_port(endpoint, password, request, command_id=command_id, body_tail=body_tail, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_config_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, request: HcNetSdkStdXmlConfigRequest | str | bytes, template: HcNetSdkCommandPortControlTemplate, *, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> HcNetSdkStdXmlConfigResponse:
    """Execute a traced ``NET_DVR_STDXMLConfig`` command in pure Python."""
    return _impl_configuration.hcnetsdk_stdxml_config_command_port(endpoint, password, request, template, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_config_command_port_from_trace(endpoint: HcNetSdkLanEndpoint, password: str | bytes, request: HcNetSdkStdXmlConfigRequest | str | bytes, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, name: str | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913
    """Execute traced ``NET_DVR_STDXMLConfig`` through pure command-port IO."""
    return _impl_configuration.hcnetsdk_stdxml_config_command_port_from_trace(endpoint, password, request, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name=name, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


def hcnetsdk_stdxml_isapi_command_port(endpoint: HcNetSdkLanEndpoint, password: str | bytes, method: str, path: str, body: Mapping[str, Any] | str | bytes | None=None, *, command_id: int=HCNETSDK_STDXML_COMMAND_PORT_COMMAND_ID, body_prefix: str | bytes | None=None, addend_delta: int | None=0, addend: int | None=None, name: str | None=None, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None) -> HcNetSdkStdXmlConfigResponse:  # noqa: PLR0913
    """Execute a generic ISAPI request through pure command-port STDXML."""
    return _impl_requests.hcnetsdk_stdxml_isapi_command_port(endpoint, password, method, path, body, command_id=command_id, body_prefix=body_prefix, addend_delta=addend_delta, addend=addend, name=name, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, _owner=_sys.modules[__name__])


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
    return _impl_discovery._parse_local_device_content(value, _owner=_sys.modules[__name__])


def _hcnetsdk_time_value(value: HcNetSdkTime | datetime | date, *, end_of_day: bool=False) -> HcNetSdkTime:
    return _impl_requests._hcnetsdk_time_value(value, end_of_day=end_of_day, _owner=_sys.modules[__name__])


def _native_string_bytes(label: str, value: str) -> bytes:
    return _impl_requests._native_string_bytes(label, value, _owner=_sys.modules[__name__])


def _services_switch_value(label: str, value: int | bool) -> int:
    return _impl_configuration._services_switch_value(label, value, _owner=_sys.modules[__name__])


def _fixed_ipv4_text(value: bytes | bytearray | memoryview) -> str:
    return _impl_requests._fixed_ipv4_text(value, _owner=_sys.modules[__name__])


def _mac_address_text(value: bytes | bytearray | memoryview) -> str:
    return _impl_requests._mac_address_text(value, _owner=_sys.modules[__name__])


def _byte_tuple(value: bytes | bytearray | memoryview) -> tuple[int, ...]:
    return _impl_requests._byte_tuple(value, _owner=_sys.modules[__name__])


def _fixed_secret_bytes(value: bytes | bytearray | memoryview) -> bytes:
    return _impl_requests._fixed_secret_bytes(value, _owner=_sys.modules[__name__])


def _fixed_secret_text(value: bytes | bytearray | memoryview) -> str:
    return _impl_requests._fixed_secret_text(value, _owner=_sys.modules[__name__])


def _mac_address_bytes(value: str | bytes) -> bytes:
    return _impl_requests._mac_address_bytes(value, _owner=_sys.modules[__name__])


def _dword_value(label: str, value: int) -> int:
    return _impl_requests._dword_value(label, value, _owner=_sys.modules[__name__])


def _device_ability_response_text(response: str | bytes) -> str:
    return _impl_configuration._device_ability_response_text(response, _owner=_sys.modules[__name__])


def _device_ability_xml_name(label: str, value: str) -> str:
    return _impl_configuration._device_ability_xml_name(label, value, _owner=_sys.modules[__name__])


def _xml_local_name(element: ET.Element) -> str:
    return _impl_requests._xml_local_name(element, _owner=_sys.modules[__name__])


def _xml_opt_attr(root: ET.Element, name: str, *, parent: str | None=None) -> str | None:
    return _impl_requests._xml_opt_attr(root, name, parent=parent, _owner=_sys.modules[__name__])


def _xml_attr(root: ET.Element, name: str, attr: str, *, parent: str | None=None) -> str | None:
    return _impl_requests._xml_attr(root, name, attr, parent=parent, _owner=_sys.modules[__name__])


def _xml_attr_int(root: ET.Element, name: str, attr: str, *, parent: str | None=None, default: int=0) -> int:
    return _impl_requests._xml_attr_int(root, name, attr, parent=parent, default=default, _owner=_sys.modules[__name__])


def _xml_bool_opt_attr(root: ET.Element, name: str) -> bool | None:
    return _impl_requests._xml_bool_opt_attr(root, name, _owner=_sys.modules[__name__])


def _xml_descendant_int(root: ET.Element, name: str, *, parent: str | None=None, default: int=0) -> int:
    return _impl_requests._xml_descendant_int(root, name, parent=parent, default=default, _owner=_sys.modules[__name__])


def _xml_descendant_bool_text(root: ET.Element, name: str, *, parent: str | None=None, default: bool=False) -> bool:
    return _impl_requests._xml_descendant_bool_text(root, name, parent=parent, default=default, _owner=_sys.modules[__name__])


def _xml_descendant_text(root: ET.Element, name: str, *, parent: str | None=None) -> str | None:
    return _impl_requests._xml_descendant_text(root, name, parent=parent, _owner=_sys.modules[__name__])


def _xml_has_descendant(root: ET.Element, name: str) -> bool:
    return _impl_requests._xml_has_descendant(root, name, _owner=_sys.modules[__name__])


def _xml_int_csv(value: str | None) -> tuple[int, ...]:
    return _impl_requests._xml_int_csv(value, _owner=_sys.modules[__name__])


def _xml_child_int_csv_with_prefix(root: ET.Element, prefix: str) -> tuple[int, ...]:
    return _impl_requests._xml_child_int_csv_with_prefix(root, prefix, _owner=_sys.modules[__name__])


def _xml_child_text(root: ET.Element, path: tuple[str, ...]) -> str | None:
    return _impl_requests._xml_child_text(root, path, _owner=_sys.modules[__name__])


def _xml_children(root: ET.Element, name: str) -> tuple[ET.Element, ...]:
    return _impl_requests._xml_children(root, name, _owner=_sys.modules[__name__])


def _xml_first_child(root: ET.Element, name: str) -> ET.Element | None:
    return _impl_requests._xml_first_child(root, name, _owner=_sys.modules[__name__])


def _ipc_front_parameter_field_root(root: ET.Element) -> ET.Element:
    return _impl_requests._ipc_front_parameter_field_root(root, _owner=_sys.modules[__name__])


def _xml_child_int(root: ET.Element, path: tuple[str, ...], *, default: int=0) -> int:
    return _impl_requests._xml_child_int(root, path, default=default, _owner=_sys.modules[__name__])


def _xml_child_optional_int(root: ET.Element, path: tuple[str, ...]) -> int | None:
    return _impl_requests._xml_child_optional_int(root, path, _owner=_sys.modules[__name__])


def _xml_child_int_range(root: ET.Element, path: tuple[str, ...]) -> EzvizLanIpcFrontParameterRange:
    return _impl_requests._xml_child_int_range(root, path, _owner=_sys.modules[__name__])


def _audio_video_compress_stream(root: ET.Element, *, index: int | None=None) -> EzvizLanAudioVideoCompressStream:
    return _impl_requests._audio_video_compress_stream(root, index=index, _owner=_sys.modules[__name__])


def _audio_video_compress_video_channels(root: ET.Element) -> tuple[EzvizLanAudioVideoCompressVideoChannel, ...]:
    return _impl_requests._audio_video_compress_video_channels(root, _owner=_sys.modules[__name__])


def _audio_video_compress_audio_channels(root: ET.Element) -> tuple[EzvizLanAudioVideoCompressAudioChannel, ...]:
    return _impl_requests._audio_video_compress_audio_channels(root, _owner=_sys.modules[__name__])


def _audio_video_compress_voice_talk_channels(root: ET.Element) -> tuple[EzvizLanAudioVideoCompressVoiceTalkChannel, ...]:
    return _impl_requests._audio_video_compress_voice_talk_channels(root, _owner=_sys.modules[__name__])


def _xml_has_parent(root: ET.Element, child: ET.Element, parent: str) -> bool:
    return _impl_requests._xml_has_parent(root, child, parent, _owner=_sys.modules[__name__])


def _ptz_int(label: str, value: int) -> int:
    return _impl_configuration._ptz_int(label, value, _owner=_sys.modules[__name__])


def _looks_tls_record(data: bytes) -> bool:
    return _impl_requests._looks_tls_record(data, _owner=_sys.modules[__name__])


def _hcnetsdk_tcp_payload_kind(data: bytes, *, printable_ratio: float, high_bit_ratio: float, xml_offset: int | None, xml_tags: tuple[str, ...], declared_length_offset: int | None) -> str:
    return _impl_requests._hcnetsdk_tcp_payload_kind(data, printable_ratio=printable_ratio, high_bit_ratio=high_bit_ratio, xml_offset=xml_offset, xml_tags=xml_tags, declared_length_offset=declared_length_offset, _owner=_sys.modules[__name__])


def _hcnetsdk_known_prefix_kind(data: bytes) -> str | None:
    return _impl_requests._hcnetsdk_known_prefix_kind(data, _owner=_sys.modules[__name__])


def _hcnetsdk_declared_length(data: bytes) -> tuple[int | None, int | None]:
    """Return a plausible embedded length field if one matches captured bytes."""
    return _impl_requests._hcnetsdk_declared_length(data, _owner=_sys.modules[__name__])


def _parse_shape_fields(text: str) -> dict[str, str]:
    return _impl_discovery._parse_shape_fields(text, _owner=_sys.modules[__name__])


def _parse_int(value: str | None) -> int | None:
    return _impl_discovery._parse_int(value, _owner=_sys.modules[__name__])


def _parse_float(value: str | None) -> float | None:
    return _impl_discovery._parse_float(value, _owner=_sys.modules[__name__])


def _event_field_int(event: HcNetSdkSemanticLogEvent, name: str) -> int | None:
    return _impl_requests._event_field_int(event, name, _owner=_sys.modules[__name__])


def _event_field_bool(event: HcNetSdkSemanticLogEvent, name: str) -> bool:
    return _impl_requests._event_field_bool(event, name, _owner=_sys.modules[__name__])


def _hcnetsdk_shape_command_candidate(record: HcNetSdkTcpShapeLogRecord) -> int | None:
    return _impl_requests._hcnetsdk_shape_command_candidate(record, _owner=_sys.modules[__name__])


def _hcnetsdk_command_port_login_prefix(local_ip: str) -> bytes:
    return _impl_authentication._hcnetsdk_command_port_login_prefix(local_ip, _owner=_sys.modules[__name__])


def _hcnetsdk_command_port_username(username: str) -> bytes:
    return _impl_requests._hcnetsdk_command_port_username(username, _owner=_sys.modules[__name__])


def _parse_length_candidates(value: str | None) -> dict[str, int]:
    return _impl_discovery._parse_length_candidates(value, _owner=_sys.modules[__name__])


def _parse_length_candidate_offset(name: str) -> int | None:
    return _impl_discovery._parse_length_candidate_offset(name, _owner=_sys.modules[__name__])


def _recv_exact(sock: Any, length: int) -> bytes:
    return _impl_requests._recv_exact(sock, length, _owner=_sys.modules[__name__])


def _send_all(sock: Any, data: bytes) -> None:
    return _impl_requests._send_all(sock, data, _owner=_sys.modules[__name__])


def _pkcs5_pad(data: bytes) -> bytes:
    return _impl_requests._pkcs5_pad(data, _owner=_sys.modules[__name__])


def _pkcs5_unpad(data: bytes) -> bytes:
    return _impl_requests._pkcs5_unpad(data, _owner=_sys.modules[__name__])


def _entropy_bits_per_byte(data: bytes) -> float:
    return _impl_requests._entropy_bits_per_byte(data, _owner=_sys.modules[__name__])


def _xml_offset(data: bytes) -> int | None:
    return _impl_requests._xml_offset(data, _owner=_sys.modules[__name__])


def _xml_tag_names(data: bytes) -> tuple[str, ...]:
    return _impl_requests._xml_tag_names(data, _owner=_sys.modules[__name__])


def _probe_port(host: str, port: int, *, timeout: float | None, socket_factory: SocketFactory) -> HcNetSdkPortProbe:
    return _impl_discovery._probe_port(host, port, timeout=timeout, socket_factory=socket_factory, _owner=_sys.modules[__name__])


def discover_hcnetsdk_stream_details(endpoint: HcNetSdkLanEndpoint, password: str | bytes, *, channel: int=1, username: str=HCNETSDK_EZVIZ_DEFAULT_USERNAME, local_ip: str | None=None, timeout: float | None=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None, monotonic: Callable[[], float]=time.monotonic, max_response_bytes: int=524288) -> HcNetSdkStreamDetails:
    """Login once and issue native GET1040 and ability8 queries on fresh sockets.

    Supplied credentials only: never renew or retry authentication. The finite
    network deadline covers login and both reads; RSA generation precedes it.
    Native frame-rate/resolution/codec IDs are preserved, not guessed as FPS or
    encryption protocols. Explicit capability-query rejection retains configuration
    with its raw error code; malformed/authentication/network errors propagate.
    """
    return _impl_discovery.discover_hcnetsdk_stream_details(endpoint, password, channel=channel, username=username, local_ip=local_ip, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, monotonic=monotonic, max_response_bytes=max_response_bytes, _owner=_sys.modules[__name__])


def _hcnetsdk_stream_details_query(endpoint: HcNetSdkLanEndpoint, template: HcNetSdkCommandPortControlTemplate, session: HcNetSdkCommandPortLoginSession, address: str, timeout: float, socket_factory: SocketFactory, deadline: float, monotonic: Callable[[], float], max_response_bytes: int) -> HcNetSdkTcpFrame:
    return _impl_requests._hcnetsdk_stream_details_query(endpoint, template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes, _owner=_sys.modules[__name__])


def discover_hcnetsdk_stream_details_for_login(endpoint: HcNetSdkLanEndpoint, login: HcNetSdkLoginCandidate, *, tls_context: ssl.SSLContext | None=None, channel: int=1, timeout: float=10.0, socket_factory: SocketFactory=socket.create_connection, rsa_key: Any | None=None, monotonic: Callable[[], float]=time.monotonic, max_response_bytes: int=524288) -> HcNetSdkStreamDetails:
    """Query one explicit native login profile, never enumerate or renew secrets.

    HTTPSV40 means the native binary SDK over TLS, not HTTP/ISAPI. Default TLS
    verifies certificates; private CA/self-signed handling belongs to a supplied
    SSLContext. TCP and TLS handshake share each connection's remaining budget.
    Authentication rejection propagates without a second credential/profile.
    """
    return _impl_discovery.discover_hcnetsdk_stream_details_for_login(endpoint, login, tls_context=tls_context, channel=channel, timeout=timeout, socket_factory=socket_factory, rsa_key=rsa_key, monotonic=monotonic, max_response_bytes=max_response_bytes, _owner=_sys.modules[__name__])

# Match the earlier implicit wildcard surface; named private compatibility hooks remain available.
__all__ = [name for name in globals() if not name.startswith("_")]

# Retained named compatibility exports; not additions to the wildcard API.
__compatibility_exports__ = {
    '_AES_SBOX': _AES_SBOX,
    '_AES_RCON': _AES_RCON,
}
