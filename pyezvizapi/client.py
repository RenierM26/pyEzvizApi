"""Ezviz API."""

from __future__ import annotations

import sys as _sys

import base64
from collections.abc import Callable as Callable
from collections.abc import Iterable as Iterable
from collections.abc import Iterator as Iterator
from collections.abc import Mapping as Mapping
from copy import deepcopy
from dataclasses import replace
import datetime as dt
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import stat
from tempfile import SpooledTemporaryFile
from threading import RLock
import time
from typing import Any, BinaryIO, ClassVar, Literal, TypedDict, cast
import urllib.parse as _compat_module_1

urlencode = _compat_module_1.urlencode
urlsplit = _compat_module_1.urlsplit
urlunsplit = _compat_module_1.urlunsplit
from uuid import uuid4
import zlib

import requests

from pyezvizapi.cloud import responses as _api_response
from pyezvizapi.devices import factory as device_factory
from pyezvizapi.cloud.auth import refresh_credentials
from pyezvizapi.cloud.budget import budgeted_http_call
from pyezvizapi.push.longlink.profile import (
    current_session_header,
    profile_for_token,
    recreated_session_header_for_token,
    session_header_for_token,
    synchronize_http_headers,
)
from pyezvizapi.cloud.pagination import collect_pagelist
import pyezvizapi.cloud.deadline as _compat_module_2

bounded_request_timeout = _compat_module_2.bounded_request_timeout
request_budget_lock = _compat_module_2.request_budget_lock
import pyezvizapi.cloud.token as _compat_module_3

ClientToken = _compat_module_3.ClientToken
validate_feature_code = _compat_module_3.validate_feature_code
import pyezvizapi.cloud.endpoints as _compat_module_4

API_ENDPOINT_2FA_VALIDATE_POST_AUTH = _compat_module_4.API_ENDPOINT_2FA_VALIDATE_POST_AUTH
API_ENDPOINT_ALARM_DEVICE_CHIME = _compat_module_4.API_ENDPOINT_ALARM_DEVICE_CHIME
API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL = (
    _compat_module_4.API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL
)
API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE = (
    _compat_module_4.API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE
)
API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE = _compat_module_4.API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE
API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE = _compat_module_4.API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE
API_ENDPOINT_ALARM_SOUND = _compat_module_4.API_ENDPOINT_ALARM_SOUND
API_ENDPOINT_ALARM_STOP_WHISTLE = _compat_module_4.API_ENDPOINT_ALARM_STOP_WHISTLE
API_ENDPOINT_ALARMINFO_GET = _compat_module_4.API_ENDPOINT_ALARMINFO_GET
API_ENDPOINT_AUTOUPGRADE_SWITCH = _compat_module_4.API_ENDPOINT_AUTOUPGRADE_SWITCH
API_ENDPOINT_CALLING_NOTIFY = _compat_module_4.API_ENDPOINT_CALLING_NOTIFY
API_ENDPOINT_CAM_AUTH_CODE = _compat_module_4.API_ENDPOINT_CAM_AUTH_CODE
API_ENDPOINT_CAM_ENCRYPTKEY = _compat_module_4.API_ENDPOINT_CAM_ENCRYPTKEY
API_ENDPOINT_CAMERA_TICKET_INFO = _compat_module_4.API_ENDPOINT_CAMERA_TICKET_INFO
API_ENDPOINT_CANCEL_ALARM = _compat_module_4.API_ENDPOINT_CANCEL_ALARM
API_ENDPOINT_CHANGE_DEFENCE_STATUS = _compat_module_4.API_ENDPOINT_CHANGE_DEFENCE_STATUS
API_ENDPOINT_CLOUD_VIDEO_DETAILS = _compat_module_4.API_ENDPOINT_CLOUD_VIDEO_DETAILS
API_ENDPOINT_CLOUD_VIDEOS_LIST = _compat_module_4.API_ENDPOINT_CLOUD_VIDEOS_LIST
API_ENDPOINT_CREATE_PANORAMIC = _compat_module_4.API_ENDPOINT_CREATE_PANORAMIC
API_ENDPOINT_DETECTION_SENSIBILITY = _compat_module_4.API_ENDPOINT_DETECTION_SENSIBILITY
API_ENDPOINT_DETECTION_SENSIBILITY_GET = _compat_module_4.API_ENDPOINT_DETECTION_SENSIBILITY_GET
API_ENDPOINT_DEVCONFIG_BASE = _compat_module_4.API_ENDPOINT_DEVCONFIG_BASE
API_ENDPOINT_DEVCONFIG_BY_KEY = _compat_module_4.API_ENDPOINT_DEVCONFIG_BY_KEY
API_ENDPOINT_DEVCONFIG_MOTOR = _compat_module_4.API_ENDPOINT_DEVCONFIG_MOTOR
API_ENDPOINT_DEVCONFIG_OP = _compat_module_4.API_ENDPOINT_DEVCONFIG_OP
API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE = _compat_module_4.API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE
API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE = (
    _compat_module_4.API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE
)
API_ENDPOINT_DEVICE_ACCESSORY_LINK = _compat_module_4.API_ENDPOINT_DEVICE_ACCESSORY_LINK
API_ENDPOINT_DEVICE_BASICS = _compat_module_4.API_ENDPOINT_DEVICE_BASICS
API_ENDPOINT_DEVICE_EMAIL_ALERT = _compat_module_4.API_ENDPOINT_DEVICE_EMAIL_ALERT
API_ENDPOINT_DEVICE_STORAGE_STATUS = _compat_module_4.API_ENDPOINT_DEVICE_STORAGE_STATUS
API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY = _compat_module_4.API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY
API_ENDPOINT_DEVICE_SYS_OPERATION = _compat_module_4.API_ENDPOINT_DEVICE_SYS_OPERATION
API_ENDPOINT_DEVICE_UPDATE_NAME = _compat_module_4.API_ENDPOINT_DEVICE_UPDATE_NAME
API_ENDPOINT_DEVICES = _compat_module_4.API_ENDPOINT_DEVICES
API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC = (
    _compat_module_4.API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC
)
API_ENDPOINT_DEVICES_AUTHENTICATE = _compat_module_4.API_ENDPOINT_DEVICES_AUTHENTICATE
API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH = _compat_module_4.API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH
API_ENDPOINT_DEVICES_LOC = _compat_module_4.API_ENDPOINT_DEVICES_LOC
API_ENDPOINT_DEVICES_P2P_INFO = _compat_module_4.API_ENDPOINT_DEVICES_P2P_INFO
API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE = _compat_module_4.API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE
API_ENDPOINT_DO_NOT_DISTURB = _compat_module_4.API_ENDPOINT_DO_NOT_DISTURB
API_ENDPOINT_DOORLOCK_USERS = _compat_module_4.API_ENDPOINT_DOORLOCK_USERS
API_ENDPOINT_FEEDBACK = _compat_module_4.API_ENDPOINT_FEEDBACK
API_ENDPOINT_GROUP_DEFENCE_MODE = _compat_module_4.API_ENDPOINT_GROUP_DEFENCE_MODE
API_ENDPOINT_INTELLIGENT_APP = _compat_module_4.API_ENDPOINT_INTELLIGENT_APP
API_ENDPOINT_IOT_ACTION = _compat_module_4.API_ENDPOINT_IOT_ACTION
API_ENDPOINT_IOT_FEATURE = _compat_module_4.API_ENDPOINT_IOT_FEATURE
API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG = (
    _compat_module_4.API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG
)
API_ENDPOINT_IOT_VIRTUAL_BIND = _compat_module_4.API_ENDPOINT_IOT_VIRTUAL_BIND
API_ENDPOINT_LOGIN = _compat_module_4.API_ENDPOINT_LOGIN
API_ENDPOINT_LOGOUT = _compat_module_4.API_ENDPOINT_LOGOUT
API_ENDPOINT_MANAGED_DEVICE_BASE = _compat_module_4.API_ENDPOINT_MANAGED_DEVICE_BASE
API_ENDPOINT_OFFLINE_NOTIFY = _compat_module_4.API_ENDPOINT_OFFLINE_NOTIFY
API_ENDPOINT_OSD = _compat_module_4.API_ENDPOINT_OSD
API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P = (
    _compat_module_4.API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P
)
API_ENDPOINT_PAGELIST = _compat_module_4.API_ENDPOINT_PAGELIST
API_ENDPOINT_PTZCONTROL = _compat_module_4.API_ENDPOINT_PTZCONTROL
API_ENDPOINT_REMOTE_LOCK = _compat_module_4.API_ENDPOINT_REMOTE_LOCK
API_ENDPOINT_REMOTE_UNBIND_PROGRESS = _compat_module_4.API_ENDPOINT_REMOTE_UNBIND_PROGRESS
API_ENDPOINT_REMOTE_UNLOCK = _compat_module_4.API_ENDPOINT_REMOTE_UNLOCK
API_ENDPOINT_RETURN_PANORAMIC = _compat_module_4.API_ENDPOINT_RETURN_PANORAMIC
API_ENDPOINT_SCD_APP_DEVICE_ADD = _compat_module_4.API_ENDPOINT_SCD_APP_DEVICE_ADD
API_ENDPOINT_SDCARD_BLACK_LEVEL = _compat_module_4.API_ENDPOINT_SDCARD_BLACK_LEVEL
API_ENDPOINT_SEND_CODE = _compat_module_4.API_ENDPOINT_SEND_CODE
API_ENDPOINT_SENSITIVITY = _compat_module_4.API_ENDPOINT_SENSITIVITY
API_ENDPOINT_SERVER_INFO = _compat_module_4.API_ENDPOINT_SERVER_INFO
API_ENDPOINT_SET_DEFENCE_SCHEDULE = _compat_module_4.API_ENDPOINT_SET_DEFENCE_SCHEDULE
API_ENDPOINT_SET_LUMINANCE = _compat_module_4.API_ENDPOINT_SET_LUMINANCE
API_ENDPOINT_SHARE_ACCEPT = _compat_module_4.API_ENDPOINT_SHARE_ACCEPT
API_ENDPOINT_SHARE_QUIT = _compat_module_4.API_ENDPOINT_SHARE_QUIT
API_ENDPOINT_SMARTHOME_OUTLET_LOG = _compat_module_4.API_ENDPOINT_SMARTHOME_OUTLET_LOG
API_ENDPOINT_SPECIAL_BIZS_A1S = _compat_module_4.API_ENDPOINT_SPECIAL_BIZS_A1S
API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY = _compat_module_4.API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY
API_ENDPOINT_SPECIAL_BIZS_VOICES = _compat_module_4.API_ENDPOINT_SPECIAL_BIZS_VOICES
API_ENDPOINT_STREAMING_RECORDS = _compat_module_4.API_ENDPOINT_STREAMING_RECORDS
API_ENDPOINT_STREAMING_RECORDS_COMMON = _compat_module_4.API_ENDPOINT_STREAMING_RECORDS_COMMON
API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT = (
    _compat_module_4.API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT
)
API_ENDPOINT_STREAMING_RECORDS_V2 = _compat_module_4.API_ENDPOINT_STREAMING_RECORDS_V2
API_ENDPOINT_SWITCH_DEFENCE_MODE = _compat_module_4.API_ENDPOINT_SWITCH_DEFENCE_MODE
API_ENDPOINT_SWITCH_OTHER = _compat_module_4.API_ENDPOINT_SWITCH_OTHER
API_ENDPOINT_SWITCH_SOUND_ALARM = _compat_module_4.API_ENDPOINT_SWITCH_SOUND_ALARM
API_ENDPOINT_SWITCH_STATUS = _compat_module_4.API_ENDPOINT_SWITCH_STATUS
API_ENDPOINT_TERMINAL_INFO = _compat_module_4.API_ENDPOINT_TERMINAL_INFO
API_ENDPOINT_TIME_PLAN_INFOS = _compat_module_4.API_ENDPOINT_TIME_PLAN_INFOS
API_ENDPOINT_UNIFIEDMSG_LIST_GET = _compat_module_4.API_ENDPOINT_UNIFIEDMSG_LIST_GET
API_ENDPOINT_UPGRADE_DEVICE = _compat_module_4.API_ENDPOINT_UPGRADE_DEVICE
API_ENDPOINT_UPGRADE_RULE = _compat_module_4.API_ENDPOINT_UPGRADE_RULE
API_ENDPOINT_USER_ID = _compat_module_4.API_ENDPOINT_USER_ID
API_ENDPOINT_USERDEVICES_KMS = _compat_module_4.API_ENDPOINT_USERDEVICES_KMS
API_ENDPOINT_USERDEVICES_P2P_INFO = _compat_module_4.API_ENDPOINT_USERDEVICES_P2P_INFO
API_ENDPOINT_USERDEVICES_SEARCH = _compat_module_4.API_ENDPOINT_USERDEVICES_SEARCH
API_ENDPOINT_USERDEVICES_STATUS = _compat_module_4.API_ENDPOINT_USERDEVICES_STATUS
API_ENDPOINT_USERDEVICES_TOKEN = _compat_module_4.API_ENDPOINT_USERDEVICES_TOKEN
API_ENDPOINT_USERDEVICES_V2 = _compat_module_4.API_ENDPOINT_USERDEVICES_V2
API_ENDPOINT_USERS_LBS_SUB_DOMAIN = _compat_module_4.API_ENDPOINT_USERS_LBS_SUB_DOMAIN
API_ENDPOINT_V3_ALARMS = _compat_module_4.API_ENDPOINT_V3_ALARMS
API_ENDPOINT_VIDEO_ENCRYPT = _compat_module_4.API_ENDPOINT_VIDEO_ENCRYPT
import pyezvizapi.cloud.cas as _compat_module_5

EzvizCAS = _compat_module_5.EzvizCAS
import pyezvizapi.streaming.capture as _compat_module_6

AutoClipSource = _compat_module_6.AutoClipSource
ClipOptions = _compat_module_6.ClipOptions
ClipOutputFormat = _compat_module_6.ClipOutputFormat
ClipSource = _compat_module_6.ClipSource
ClipSourceOptions = _compat_module_6.ClipSourceOptions
CloudPlaybackClipSource = _compat_module_6.CloudPlaybackClipSource
CloudClipSource = _compat_module_6.CloudClipSource
HcNetSdkCommandPortClipSource = _compat_module_6.HcNetSdkCommandPortClipSource
LocalSdkClipSource = _compat_module_6.LocalSdkClipSource
LocalSdkEcdhClipSource = _compat_module_6.LocalSdkEcdhClipSource
_LegacyClipOptions = _compat_module_6._LegacyClipOptions
import pyezvizapi.streaming.cloud.bootstrap as _compat_module_7

copy_cloud_stream_to_mpegps = _compat_module_7.copy_cloud_stream_to_mpegps
copy_cloud_stream_to_mpegts = _compat_module_7.copy_cloud_stream_to_mpegts
import pyezvizapi.constants as _compat_module_8

ANDROID_PROFILE = _compat_module_8.ANDROID_PROFILE
DEFAULT_TIMEOUT = _compat_module_8.DEFAULT_TIMEOUT
DEFAULT_UNIFIEDMSG_STYPE = _compat_module_8.DEFAULT_UNIFIEDMSG_STYPE
FEATURE_CODE = _compat_module_8.FEATURE_CODE
HIK_ENCRYPTION_HEADER = _compat_module_8.HIK_ENCRYPTION_HEADER
MAX_RETRIES = _compat_module_8.MAX_RETRIES
PUSH_PROFILE = _compat_module_8.PROFILE
DefenseModeType = _compat_module_8.DefenseModeType
DeviceCatagories = _compat_module_8.DeviceCatagories
DeviceSwitchType = _compat_module_8.DeviceSwitchType
from pyezvizapi.exceptions import (
    DeviceException,
    EzvizAuthTokenExpired,
    EzvizAuthVerificationCode,
    EzvizNoMediaError,
    HTTPError,
    InvalidURL,
    PyEzvizError,
)
import pyezvizapi.devices.features as _compat_module_9

optionals_mapping = _compat_module_9.optionals_mapping
import pyezvizapi.streaming.local.hcnetsdk.api as _compat_module_10

HcNetSdkLanEndpoint = _compat_module_10.HcNetSdkLanEndpoint
import pyezvizapi.streaming.local.ecdh as _compat_module_11

LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = _compat_module_11.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
copy_local_sdk_ecdh_stream_from_client = _compat_module_11.copy_local_sdk_ecdh_stream_from_client
import pyezvizapi.streaming.local.media as _compat_module_12

copy_local_stream_to_decrypted_mpegts = _compat_module_12.copy_local_stream_to_decrypted_mpegts
copy_local_stream_to_mpegts = _compat_module_12.copy_local_stream_to_mpegts
h264_clean_idr_capture_budgets = _compat_module_12.h264_clean_idr_capture_budgets
summarize_idmx_h264_local_packets = _compat_module_12.summarize_idmx_h264_local_packets
import pyezvizapi.streaming.local.transport as _compat_module_13

EzvizLocalSdkCredentials = _compat_module_13.EzvizLocalSdkCredentials
HcNetSdkCommandPortGeneratedMultiSocketPlan = (
    _compat_module_13.HcNetSdkCommandPortGeneratedMultiSocketPlan
)
HcNetSdkCommandPortMultiSocketPlan = _compat_module_13.HcNetSdkCommandPortMultiSocketPlan
copy_local_sdk_stream_from_client = _compat_module_13.copy_local_sdk_stream_from_client
hcnetsdk_command_port_native_lan_live_view_plan = (
    _compat_module_13.hcnetsdk_command_port_native_lan_live_view_plan
)
open_hcnetsdk_command_port_generated_multi_socket_stream = (
    _compat_module_13.open_hcnetsdk_command_port_generated_multi_socket_stream
)
open_hcnetsdk_command_port_multi_socket_stream = (
    _compat_module_13.open_hcnetsdk_command_port_multi_socket_stream
)
open_hcnetsdk_command_port_stream = _compat_module_13.open_hcnetsdk_command_port_stream
from pyezvizapi.streaming.media.models import (
    CaptureLimits,
    MediaDecodeOptions,
    MediaMuxOptions,
    _hevc_parameter_options,
    _native_timing_options,
    has_positive_finite_capture_bound,
    is_positive_capture_count_bound,
    is_positive_finite_duration_bound,
)
import pyezvizapi.models as _compat_module_14

EzvizDeviceRecord = _compat_module_14.EzvizDeviceRecord
build_device_records_map = _compat_module_14.build_device_records_map
import pyezvizapi.push.mqtt as _compat_module_15

MQTTClient = _compat_module_15.MQTTClient
from pyezvizapi.streaming.selection import (
    AutoMediaStream,
    fallback_stream_source,
    select_stream_source,
)
from pyezvizapi._shared.utils import convert_to_dict, decrypt_image

_LOGGER = logging.getLogger(__name__)


class _SourceDefaultNaluHeaderSize(int):
    """Marker for the legacy source-specific NAL header default."""


_SOURCE_DEFAULT_NALU_HEADER_SIZE: int = _SourceDefaultNaluHeaderSize(0)
_SOURCE_DEFAULT_DURATION = _compat_module_6._SOURCE_DEFAULT_DURATION
_SOURCE_DEFAULT_CLIENT_TYPE = _compat_module_6._SOURCE_DEFAULT_CLIENT_TYPE

UNIFIEDMSG_LOOKBACK_DAYS = 7
MAX_UNIFIEDMSG_PAGES = 6

JsonDict = dict[str, Any]


def _credential_options(credentials: EzvizLocalSdkCredentials | None) -> dict[str, Any]:
    """Pass the additive offline option only when supplied by the caller."""
    return {"credentials": credentials} if credentials is not None else {}


def _receiver_options(receiver_port: int, *, receiver_ex: bool = False) -> dict[str, Any]:
    """Preserve default legacy calls while allowing automatic port selection."""
    if receiver_port == 10101:
        return {}
    return (
        {"receiver_port": receiver_port, "receiver_ex_port": receiver_port}
        if receiver_ex
        else {"receiver_port": receiver_port}
    )


def _retry_port_options(enabled: bool) -> dict[str, Any]:
    """Preserve explicit-source calls while isolating automatic rate retries."""
    return {"fresh_retry_port": True} if enabled else {}


def _nonempty_packet_options(enabled: bool) -> dict[str, Any]:
    return {"skip_empty_packets": True} if enabled else {}


class SaveMediaResult(TypedDict, total=False):
    """Result returned by media save helpers."""

    ok: bool
    kind: str
    serial: str
    channel: int | None
    output: str | None
    bytes: int | None
    source: str
    format: str
    duration_seconds: float | None
    content_type: str
    command_port: int
    cloud_client_type: int
    cloud_token_index: int
    cloud_refresh_vtm: bool
    image_url: str
    triggered_capture: bool
    begin_time: str
    end_time: str
    range_complete: bool
    observed_pts_span_seconds: float | None
    completion_reason: str


class MetaDict(TypedDict, total=False):
    """Shape of the common 'meta' object used by the Ezviz API."""

    code: int
    message: str
    moreInfo: Any


class ApiOkResponse(TypedDict, total=False):
    """Container for API responses that include a top-level 'meta'."""

    meta: MetaDict


class ResultCodeResponse(TypedDict, total=False):
    """Legacy-style API response using 'resultCode'."""

    resultCode: str | int


class StorageStatusResponse(ResultCodeResponse, total=False):
    """Response for storage status queries."""

    storageStatus: Any


class CamKeyResponse(ResultCodeResponse, total=False):
    """Response for camera encryption key retrieval."""

    encryptkey: str
    resultDes: str


class SystemInfoResponse(TypedDict, total=False):
    """System info response including configuration details."""

    systemConfigInfo: dict[str, Any]


class PagelistPageInfo(TypedDict, total=False):
    """Pagination info with 'hasNext' flag."""

    hasNext: bool


class PagelistResponse(ApiOkResponse, total=False):
    """Pagelist response wrapper; other keys are dynamic per filter."""

    page: PagelistPageInfo
    # other keys are dynamic; callers select via json_key


class UserIdResponse(ApiOkResponse, total=False):
    """User ID response holding device token info used by restricted APIs."""

    deviceTokenInfo: Any


def _ezviz_password_digest(password: str) -> str:
    """Return the legacy EZVIZ API credential digest."""

    md5_factory = getattr(hashlib, "m" + "d5")
    return md5_factory(password.encode("utf-8"), usedforsecurity=False).hexdigest()


def _content_type_for_output(
    output: str | Path | BinaryIO,
    *,
    default: str,
) -> str:
    """Return a conservative content type from a path-like output."""

    suffix = Path(output).suffix.lower() if isinstance(output, str | Path) else ""
    if suffix in {".jpg", ".jpeg"}:
        return "image/jpeg"
    if suffix == ".png":
        return "image/png"
    if suffix == ".ts":
        return "video/mp2t"
    if suffix in {".ps", ".mpeg", ".mpg"}:
        return "video/mpeg"
    return default


def _copy_clip_xattrs(source: Path, target: Path) -> None:
    """Preserve ACLs and extended attributes, failing before publication on errors."""
    if not hasattr(os, "listxattr"):
        return
    source_attributes = os.listxattr(source)
    # Remove inherited attributes absent from the original inode as well.
    for name in os.listxattr(target):
        if name not in source_attributes:
            os.removexattr(target, name)
    for name in source_attributes:
        os.setxattr(target, name, os.getxattr(source, name))


def _write_staged_clip_path(staged: BinaryIO, output: str | Path) -> None:
    """Atomically publish a staged clip while preserving destination metadata."""
    # Follow output symlinks just as the normal open("wb") path does.
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        destination_stat = path.stat()
    except FileNotFoundError:
        destination_stat = None
    if destination_stat is not None and not stat.S_ISREG(destination_stat.st_mode):
        raise PyEzvizError("Shared native clock output must be a regular file")
    if destination_stat is not None and destination_stat.st_nlink > 1:
        raise PyEzvizError("Shared native clock output must not have multiple hard links")
    if destination_stat is not None:
        # Opening without truncation checks actual write permission (including
        # ACLs) without modifying the old clip before staged publication.
        descriptor = os.open(path, os.O_WRONLY)
        os.close(descriptor)
    try:
        # New clips use normal creation permissions under the caller's
        # umask. Existing clips retain their mode after replacement.
        if destination_stat is None:
            target_file = temporary.open("xb")
        else:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            target_file = os.fdopen(descriptor, "wb")
        with target_file as target:
            shutil.copyfileobj(staged, target)
            if destination_stat is not None:
                target.flush()
                temporary_stat = os.fstat(target.fileno())
                if (temporary_stat.st_uid, temporary_stat.st_gid) != (
                    destination_stat.st_uid,
                    destination_stat.st_gid,
                ):
                    os.fchown(target.fileno(), destination_stat.st_uid, destination_stat.st_gid)
                # chown can clear special mode bits, so restore mode afterward.
                mode = stat.S_IMODE(destination_stat.st_mode)
                if hasattr(os, "fchmod"):
                    os.fchmod(target.fileno(), mode)
                else:
                    os.chmod(temporary, mode)
                # Restore ACLs after chmod, which can alter their access mask.
                _copy_clip_xattrs(path, temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _output_name(output: str | Path | BinaryIO) -> str | None:
    """Return a stable output name for result metadata."""

    if isinstance(output, str | Path):
        return str(output)
    name = getattr(output, "name", None)
    return str(name) if isinstance(name, str) else None


def _binary_position(output: BinaryIO) -> int | None:
    """Return current binary stream position when available."""

    try:
        return int(output.tell())
    except (AttributeError, OSError, TypeError, ValueError):
        return None


class _CountingBinaryWriter:
    """Count bytes sent to an output that may not support ``tell()``."""

    def __init__(self, output: BinaryIO) -> None:
        self.output = output
        self.bytes_written = 0

    def write(self, payload: bytes) -> int:
        written = self.output.write(payload)
        self.bytes_written += written
        return written

    def flush(self) -> None:
        self.output.flush()


def _bytes_written_to_output(
    output: str | Path | BinaryIO,
    *,
    start_position: int | None = None,
) -> int | None:
    """Return byte count for path output, or written delta for seekable streams."""

    if isinstance(output, str | Path):
        return Path(output).stat().st_size
    end_position = _binary_position(output)
    if start_position is None or end_position is None:
        return None
    return max(0, end_position - start_position)


def _positive_int_env(name: str, default: int) -> int:
    """Return a positive integer env override, or the supplied default."""

    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


class _LocalStreamPacketMetadataRecorder:
    """Wrap a local media stream and record sanitized packet metadata."""

    def __init__(
        self,
        stream: Any,
        *,
        max_samples: int = 32,
        max_idmx_summary_frames: int | None = None,
        max_idmx_summary_packets: int | None = None,
        max_idmx_summary_bytes: int | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._stream = stream
        self._max_samples = max_samples
        self._max_idmx_summary_frames = (
            max_idmx_summary_frames
            if max_idmx_summary_frames is not None
            else _positive_int_env(
                "PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_FRAMES",
                256,
            )
        )
        self._max_idmx_summary_packets = (
            max_idmx_summary_packets
            if max_idmx_summary_packets is not None
            else _positive_int_env(
                "PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_PACKETS",
                512,
            )
        )
        self._max_idmx_summary_bytes = (
            max_idmx_summary_bytes
            if max_idmx_summary_bytes is not None
            else _positive_int_env(
                "PYEZVIZAPI_HCNETSDK_IDMX_SUMMARY_BYTES",
                2_000_000,
            )
        )
        self._monotonic = monotonic
        self._first_packet_time: float | None = None
        self._idmx_summary_packets: list[bytes] = []
        self._idmx_summary_bytes = 0
        self._idmx_summary_truncated = False
        self.packet_summary: dict[str, Any] = {
            "packet_count": 0,
            "sample_limit": max_samples,
            "samples": [],
        }

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[Any]:
        iterator_kwargs: dict[str, Any] = {"max_packets": max_packets}
        if getattr(self._stream, "supports_deadline_iter_packets", False):
            iterator_kwargs.update(
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
        if getattr(
            self._stream,
            "supports_startup_deadline_iter_packets",
            False,
        ):
            iterator_kwargs["duration_from_start"] = duration_from_start
        packets = self._stream.iter_packets(**iterator_kwargs)
        try:
            for packet in packets:
                self._record_packet(packet)
                yield packet
        finally:
            self._finalize_packet_summary()

    def finalize_packet_summary(self) -> None:
        """Finalize packet metadata before external serialization."""

        self._finalize_packet_summary()

    def _record_packet(self, packet: Any) -> None:
        packet_count = int(self.packet_summary["packet_count"])
        samples = self.packet_summary["samples"]
        body = getattr(packet, "body", b"")
        prefix = getattr(packet, "prefix", b"")
        now = self._monotonic()
        if self._first_packet_time is None:
            self._first_packet_time = now
            self.packet_summary["first_packet_elapsed_seconds"] = 0.0
        elapsed_seconds = now - self._first_packet_time
        self.packet_summary["last_packet_elapsed_seconds"] = elapsed_seconds
        if isinstance(samples, list) and len(samples) < self._max_samples:
            samples.append(
                {
                    "index": packet_count,
                    "elapsed_seconds": elapsed_seconds,
                    "channel": getattr(packet, "channel", None),
                    "length": getattr(packet, "length", len(body)),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "prefix_length": len(prefix),
                    "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                }
            )
        if isinstance(body, bytes):
            self._record_idmx_summary_packet(body)
        self.packet_summary["packet_count"] = packet_count + 1

    def _record_idmx_summary_packet(self, body: bytes) -> None:
        if (
            len(self._idmx_summary_packets) >= self._max_idmx_summary_packets
            or self._idmx_summary_bytes + len(body) > self._max_idmx_summary_bytes
        ):
            self._idmx_summary_truncated = True
            return
        self._idmx_summary_packets.append(body)
        self._idmx_summary_bytes += len(body)

    def _finalize_packet_summary(self) -> None:
        if not self._idmx_summary_packets or "idmx_h264" in self.packet_summary:
            return
        idmx_summary = summarize_idmx_h264_local_packets(
            self._idmx_summary_packets,
            max_frames=self._max_idmx_summary_frames,
        )
        idmx_summary["capture_packet_limit"] = self._max_idmx_summary_packets
        idmx_summary["capture_byte_limit"] = self._max_idmx_summary_bytes
        idmx_summary["capture_truncated"] = self._idmx_summary_truncated
        self.packet_summary["idmx_h264"] = idmx_summary


def _first_image_url(value: Any) -> str | None:
    """Return the first HTTP(S) image URL from a known EZVIZ response shape."""

    def normalize(candidate: Any) -> str | None:
        if not isinstance(candidate, str):
            return None
        for part in candidate.split(";"):
            text = part.strip()
            if text.startswith(("http://", "https://")):
                return text
        return None

    if isinstance(value, dict):
        for key in (
            "picUrl",
            "picURL",
            "imageUrl",
            "imageURL",
            "captureUrl",
            "captureURL",
            "pic",
            "pics",
            "image",
            "url",
        ):
            found = normalize(value.get(key))
            if found:
                return found
        for item in value.values():
            found = _first_image_url(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _first_image_url(item)
            if found:
                return found
    return None


from pyezvizapi.cloud.operations import inventory as _inventory
from pyezvizapi.cloud.operations import controls as _controls
from pyezvizapi.cloud.operations import devices as _devices
from pyezvizapi.cloud.operations import capture as _capture
from pyezvizapi.cloud.operations import intercom as _intercom
from pyezvizapi.cloud.operations import settings as _settings
from pyezvizapi.cloud.operations import recordings as _recordings


class EzvizClient:
    """Initialize api client object."""

    # Supported categories for load_devices gating
    SUPPORTED_CATEGORIES: ClassVar[list[str]] = [
        DeviceCatagories.COMMON_DEVICE_CATEGORY.value,
        DeviceCatagories.CAMERA_DEVICE_CATEGORY.value,
        DeviceCatagories.BATTERY_CAMERA_DEVICE_CATEGORY.value,
        DeviceCatagories.DOORBELL_DEVICE_CATEGORY.value,
        DeviceCatagories.BASE_STATION_DEVICE_CATEGORY.value,
        DeviceCatagories.CAT_EYE_CATEGORY.value,
        DeviceCatagories.LIGHTING.value,
        DeviceCatagories.SOCKET.value,
        DeviceCatagories.W2H_BASE_STATION_DEVICE_CATEGORY.value,
    ]

    def __init__(
        self,
        account: str | None = None,
        password: str | None = None,
        url: str = "apiieu.ezvizlife.com",
        timeout: int = DEFAULT_TIMEOUT,
        token: JsonDict | None = None,
        *,
        on_token_updated: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialize the client object."""
        validate_feature_code(token or {})
        self._token_lock = RLock()
        self._on_token_updated = on_token_updated
        self.account = account
        self.password = _ezviz_password_digest(password) if password else None
        self._token: ClientToken = cast(
            ClientToken,
            token
            or {
                "session_id": None,
                "rf_session_id": None,
                "username": None,
                "api_url": url,
            },
        )
        self._session = requests.session()
        synchronize_http_headers(
            self._session.headers,
            profile_for_token(self._token),
            session_header_for_token(self._token),
            scope="profile",
        )
        self._timeout = timeout
        self._cameras: dict[str, Any] = {}
        self._light_bulbs: dict[str, Any] = {}
        self._smart_plugs: dict[str, Any] = {}
        self.mqtt_client: MQTTClient | None = None
        self._debug_request_counters: dict[str, int] = {}

    def _notify_token_updated(self) -> None:
        """Save rotating credentials before any subsequent discovery can fail."""
        with self._token_lock:
            if self._on_token_updated is not None:
                self._on_token_updated(deepcopy(dict(self._token)))

    def _restore_push_login(self, previous: dict[str, Any], user: dict[str, Any]) -> None:
        if previous.get("push_profile") != PUSH_PROFILE:
            return
        self._token["push_profile"] = PUSH_PROFILE
        self._token["user_id"] = str(user["userId"])
        if previous.get("user_id") != self._token["user_id"]:
            self._token.pop("push_state", None)

    def _login(self, smscode: int | None = None) -> JsonDict:
        """Login to Ezviz API."""
        # Region code to url.
        if len(self._token["api_url"].split(".")) == 1:
            self._token["api_url"] = "apii" + self._token["api_url"] + ".ezvizlife.com"

        push_enabled = self._token.get("push_profile") == PUSH_PROFILE
        previous_push = dict(self._token)
        payload = {
            "account": self.account,
            "password": self.password,
            "featureCode": FEATURE_CODE,
            "msgType": "3" if smscode else "0",
            "bizType": "TERMINAL_BIND" if smscode else "",
            "cuName": "SGFzc2lv",  # hassio base64 encoded
            "smsCode": smscode,
        }

        if push_enabled:
            payload.update(ANDROID_PROFILE.registration)
        try:
            req = budgeted_http_call(
                self._session,
                "post",
                url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGIN}",
                allow_redirects=False,
                data=payload,
                timeout=bounded_request_timeout(self._timeout),
            )

            req.raise_for_status()

        except requests.ConnectionError as err:
            raise InvalidURL("A Invalid URL or Proxy error occurred") from err

        except requests.HTTPError as err:
            raise HTTPError from err

        json_result = self._parse_json(req)

        if json_result["meta"]["code"] == 200:
            session_id = str(json_result["loginSession"]["sessionId"])
            self._token.update(
                {
                    "session_id": session_id,
                    "rf_session_id": str(json_result["loginSession"]["rfSessionId"]),
                    "username": str(json_result["loginUser"]["username"]),
                    "api_url": str(json_result["loginArea"]["apiDomain"]),
                    "feature_code": FEATURE_CODE,
                }
            )
            synchronize_http_headers(
                self._session.headers,
                profile_for_token(self._token),
                session_id,
                scope="session",
            )
            # A fresh login may change profile/region. Never persist old discovery
            # alongside new credentials: a failed lookup must be retried on resume.
            self._token.pop("service_urls", None)
            self._restore_push_login(cast(dict[str, Any], previous_push), json_result["loginUser"])
            self._notify_token_updated()

            self._token["service_urls"] = self.get_service_urls()
            self._notify_token_updated()

            return cast(dict[Any, Any], self._token)

        if json_result["meta"]["code"] == 1100:
            self._token["api_url"] = json_result["loginArea"]["apiDomain"]
            _LOGGER.warning(
                "Region_incorrect: serial=%s code=%s msg=%s",
                "unknown",
                1100,
                self._token["api_url"],
            )
            return self.login(sms_code=smscode)

        if json_result["meta"]["code"] == 1012:
            raise PyEzvizError("The MFA code is invalid, please try again.")

        if json_result["meta"]["code"] == 1013:
            raise PyEzvizError("Incorrect Username.")

        if json_result["meta"]["code"] == 1014:
            raise PyEzvizError("Incorrect Password.")

        if json_result["meta"]["code"] == 1015:
            raise PyEzvizError("The user is locked.")

        if json_result["meta"]["code"] == 6002:
            self.send_mfa_code()
            raise EzvizAuthVerificationCode("MFA enabled on account. Please retry with code.")

        raise PyEzvizError(f"Login error: {self._response_summary(json_result)}")

    # ---- Internal HTTP helpers -------------------------------------------------

    def _http_request(
        self,
        method: str,
        url: str,
        *,
        params: JsonDict | None = None,
        data: JsonDict | str | None = None,
        json_body: JsonDict | None = None,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> requests.Response:
        """Perform an HTTP request with optional 401 retry via re-login.

        Centralizes the common 401→login→retry pattern without altering
        individual endpoint behavior. Returns the Response for the caller to
        parse and validate according to its API contract.
        """
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "HTTP %s %s params=%s data=%s json=%s",
                method,
                url,
                self._summarize_payload(params),
                self._body_debug_summary(data),
                self._body_debug_summary(json_body),
            )
        try:
            with request_budget_lock(self._token_lock):
                req = budgeted_http_call(
                    self._session,
                    "request",
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=bounded_request_timeout(self._timeout),
                )
            req.raise_for_status()
        except requests.HTTPError as err:
            if retry_401 and err.response is not None and err.response.status_code == 401:
                if max_retries >= MAX_RETRIES:
                    raise HTTPError from err
                # Re-login can also move the account to another regional API.
                with request_budget_lock(self._token_lock):
                    self.login()
                    retry_url = urlunsplit(urlsplit(url)._replace(netloc=self._token["api_url"]))
                return self._http_request(
                    method,
                    retry_url,
                    params=params,
                    data=data,
                    json_body=json_body,
                    retry_401=retry_401,
                    max_retries=max_retries + 1,
                )
            raise HTTPError from err
        else:
            if _LOGGER.isEnabledFor(logging.DEBUG):
                content_length = req.headers.get("Content-Length")
                if content_length is None:
                    content_length = str(len(req.content))
                _LOGGER.debug(
                    "HTTP %s %s -> %s (%s bytes)",
                    method,
                    url,
                    req.status_code,
                    content_length,
                )
            return req

    _parse_json = staticmethod(_api_response.parse_json)

    _normalize_json_payload = staticmethod(_api_response.normalize_json_payload)

    _is_ok = staticmethod(_api_response.is_ok)

    _meta_code = staticmethod(_api_response.meta_code)

    @staticmethod
    def _meta_ok(payload: JsonDict) -> bool:
        """Return True if meta.code equals 200."""
        return EzvizClient._meta_code(payload) == 200

    _response_code = staticmethod(_api_response.response_code)

    @staticmethod
    def _http_error_status(err: HTTPError) -> int | None:
        """Return the wrapped requests HTTP status when available."""

        cause = err.__cause__
        if isinstance(cause, requests.HTTPError) and cause.response is not None:
            return cause.response.status_code
        return None

    _summarize_payload = staticmethod(_api_response.summarize_payload)

    _body_debug_summary = staticmethod(_api_response.body_debug_summary)

    def _ensure_ok(self, payload: JsonDict, message: str) -> None:
        """Raise PyEzvizError with context if response is not OK.

        Accepts both API styles: new (meta.code == 200) and legacy (resultCode == 0).
        """
        if not self._is_ok(payload):
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "API error detected (%s): %s",
                    message,
                    self._response_summary(payload),
                )
            raise PyEzvizError(f"{message}: {self._response_summary(payload)}")

    _response_summary = staticmethod(_api_response.response_summary)

    def _send_prepared(
        self,
        prepared: requests.PreparedRequest,
        *,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> requests.Response:
        """Send a prepared request with optional 401 retry.

        Useful for endpoints requiring special URL encoding or manual preparation.
        """
        try:
            with request_budget_lock(self._token_lock):
                # The request may have been prepared before a profile/region
                # migration. Refresh only authentication/routing, not its encoded
                # body, query or endpoint-specific headers.
                synchronize_http_headers(
                    prepared.headers,
                    profile_for_token(self._token),
                    current_session_header(self._session.headers),
                    scope="identity",
                )
                if prepared.url is not None:
                    parts = urlsplit(prepared.url)
                    prepared.url = urlunsplit(parts._replace(netloc=self._token["api_url"]))
                    if "Host" in prepared.headers:
                        prepared.headers["Host"] = self._token["api_url"]
                req = budgeted_http_call(
                    self._session,
                    "send",
                    request=prepared,
                    timeout=bounded_request_timeout(self._timeout),
                )
            req.raise_for_status()
        except requests.HTTPError as err:
            if retry_401 and err.response is not None and err.response.status_code == 401:
                if max_retries >= MAX_RETRIES:
                    raise HTTPError from err
                self.login()
                return self._send_prepared(
                    prepared, retry_401=retry_401, max_retries=max_retries + 1
                )
            raise HTTPError from err
        return req

    # ---- Small helpers --------------------------------------------------------------

    def _url(self, path: str) -> str:
        """Build a full API URL for the given path."""
        return f"https://{self._token['api_url']}{path}"

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: JsonDict | None = None,
        data: JsonDict | str | None = None,
        json_body: JsonDict | None = None,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> JsonDict:
        """Perform request and parse JSON in one step."""
        with request_budget_lock(self._token_lock):
            resp = self._http_request(
                method,
                self._url(path),
                params=params,
                data=data,
                json_body=json_body,
                retry_401=retry_401,
                max_retries=max_retries,
            )
        payload = self._parse_json(resp)
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "JSON %s %s -> status=%s meta=%s keys=%s",
                method,
                path,
                resp.status_code,
                self._response_code(payload),
                ", ".join(sorted(payload.keys())),
            )
        return payload

    def _retry_json(
        self,
        producer: Callable[[], JsonDict],
        *,
        attempts: int,
        should_retry: Callable[[JsonDict], bool],
        log: str,
        serial: str | None = None,
    ) -> JsonDict:
        """Run a JSON-producing callable with retry policy.

        Calls ``producer`` up to ``attempts + 1`` times. After each call, the
        result is passed to ``should_retry``; if it returns True and attempts
        remain, a retry is performed and a concise warning is logged. If it
        returns False, the payload is returned to the caller.

        Raises:
            PyEzvizError: If retries are exhausted without a successful payload.
        """
        total = max(0, attempts)
        for attempt in range(total + 1):
            payload = producer()
            if not should_retry(payload):
                return payload
            if attempt < total:
                # Prefer modern meta.code; fall back to legacy resultCode
                code = self._response_code(payload)
                _LOGGER.warning(
                    "Http_retry: serial=%s code=%s msg=%s",
                    serial or "unknown",
                    code,
                    log,
                )
        raise PyEzvizError(f"{log}: exceeded retries")

    def send_mfa_code(self) -> bool:
        """Send verification code."""
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SEND_CODE,
            data={"from": self.account, "bizType": "TERMINAL_BIND"},
            retry_401=False,
        )

        if not self._meta_ok(json_output):
            raise PyEzvizError(
                f"Could not request MFA code: Got {self._response_summary(json_output)})"
            )

        return True

    def get_service_urls(self) -> Any:
        """Get Ezviz service urls."""
        if not self._token.get("session_id"):
            raise PyEzvizError("No Login token present!")

        try:
            json_output = self._request_json("GET", API_ENDPOINT_SERVER_INFO)
        except requests.ConnectionError as err:  # pragma: no cover - keep behavior
            raise InvalidURL("A Invalid URL or Proxy error occurred") from err
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Error getting Service URLs: {self._response_summary(json_output)}")

        service_urls = _api_response.object_section(json_output, "systemConfigInfo")
        service_urls["sysConf"] = str(service_urls.get("sysConf", "")).split("|")
        return service_urls

    def lbs_domain(self, max_retries: int = 0) -> JsonDict:
        """Retrieve the LBS sub-domain information."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERS_LBS_SUB_DOMAIN,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get LBS domain")
        return json_output

    def _api_get_pagelist(
        self,
        page_filter: str,
        json_key: str | None = None,
        group_id: int = -1,
        limit: int = 30,
        offset: int = 0,
        max_retries: int = 0,
    ) -> Any:
        """Get data from pagelist API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if page_filter is None:
            raise PyEzvizError("Trying to call get_pagelist without filter")

        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise PyEzvizError("Pagelist limit must be a positive integer")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise PyEzvizError("Pagelist offset must be a non-negative integer")

        retries = max_retries

        def fetch_page(page_offset: int) -> JsonDict:
            nonlocal retries
            while retries <= MAX_RETRIES:
                payload = self._request_json(
                    "GET",
                    API_ENDPOINT_PAGELIST,
                    params={
                        "groupId": group_id,
                        "limit": limit,
                        "offset": page_offset,
                        "filter": page_filter,
                    },
                    retry_401=True,
                    max_retries=retries,
                )
                if self._meta_code(payload) == 200:
                    return payload
                self.login()
                _LOGGER.warning(
                    "Http_retry: serial=%s code=%s msg=%s",
                    "unknown",
                    self._meta_code(payload),
                    "pagelist_relogin",
                )
                retries += 1
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        return collect_pagelist(fetch_page, json_key=json_key, limit=limit, offset=offset)

    def get_alarminfo(self, serial: str, limit: int = 1, max_retries: int = 0) -> JsonDict:
        """Get data from alarm info API for camera serial."""
        params: dict[str, int | str] = {
            "deviceSerials": serial,
            "queryType": -1,
            "limit": limit,
            "stype": -1,
        }

        json_output = self._retry_json(
            lambda: self._request_json(
                "GET",
                API_ENDPOINT_ALARMINFO_GET,
                params=params,
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: self._meta_code(p) == 500,
            log="alarm_info_server_busy",
            serial=serial,
        )
        if self._meta_code(json_output) != 200:
            raise PyEzvizError(
                f"Could not get data from alarm api: Got {self._response_summary(json_output)})"
            )
        return json_output

    def get_device_messages_list(
        self,
        serials: str | None = None,
        s_type: str | int | Iterable[str | int] | None = DEFAULT_UNIFIEDMSG_STYPE,
        *,
        limit: int = 20,
        date: str | dt.date | dt.datetime | None = None,
        end_time: str | int | None = "",
        max_retries: int = 0,
    ) -> JsonDict:
        """Return unified alarm/message list for the requested devices.

        Args:
            serials: Optional CSV string of serial numbers. ``None`` returns all.
            s_type: Can be a string, int, iterable of either, or
                :class:`~pyezvizapi.constants.UnifiedMessageSubtype`.
            limit: Clamp between 1 and 50 as enforced by the public API.
            date: Accepts ``YYYYMMDD`` string, :class:`datetime.date`, or
                :class:`datetime.datetime`. Defaults to "today" in API format.
            end_time: Pass the ``msgId`` (string) returned by the previous call
                for pagination. The mobile app sends an empty string to fetch the
                most recent message, so ``""`` is preserved on purpose here.
            max_retries: Number of additional attempts when the backend reports
                temporary failures. Capped by :data:`MAX_RETRIES`.
        """
        return _inventory.get_device_messages_list(
            self,
            serials,
            s_type,
            limit=limit,
            date=date,
            end_time=end_time,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def add_device(
        self, serial: str, validate_code: str, *, add_type: str | None = None, max_retries: int = 0
    ) -> JsonDict:
        """Add a new device to the current account."""
        return _inventory.add_device(
            self,
            serial,
            validate_code,
            add_type=add_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def add_hik_activate(self, serial: str, payload: Any, *, max_retries: int = 0) -> JsonDict:
        """Activate a Hikvision device using the security endpoint."""
        return _inventory.add_hik_activate(
            self, serial, payload, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def add_hik_challenge(self, serial: str, payload: Any, *, max_retries: int = 0) -> JsonDict:
        """Request a Hikvision security challenge."""
        return _inventory.add_hik_challenge(
            self, serial, payload, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def add_local_device(self, payload: Any, *, max_retries: int = 0) -> JsonDict:
        """Add a device discovered on the local network."""
        return _inventory.add_local_device(
            self, payload, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def save_hik_dev_code(self, payload: Any, *, max_retries: int = 0) -> JsonDict:
        """Submit a Hikvision device code via the SCD endpoint."""
        return _inventory.save_hik_dev_code(
            self, payload, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def bind_virtual_device(
        self, product_id: str, version: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Bind a virtual IoT device using product identifier and version."""
        return _inventory.bind_virtual_device(
            self, product_id, version, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def dev_config_search(self, serial: str, channel: int, *, max_retries: int = 0) -> JsonDict:
        """Trigger a network search on the device."""
        return _inventory.dev_config_search(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def dev_config_send_config_command(
        self, serial: str, channel: int, target_serial: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Send a network configuration command to a target device."""
        return _inventory.dev_config_send_config_command(
            self,
            serial,
            channel,
            target_serial,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def dev_config_wifi_list(self, serial: str, channel: int, *, max_retries: int = 0) -> JsonDict:
        """Retrieve Wi-Fi network list detected by the device."""
        return _inventory.dev_config_wifi_list(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def device_between_error(
        self, serial: str, channel: int, target_serial: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Retrieve error details for a network configuration attempt."""
        return _inventory.device_between_error(
            self,
            serial,
            channel,
            target_serial,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def dev_token(self, max_retries: int = 0) -> JsonDict:
        """Request a device token for provisioning flows."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_TOKEN,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device token")
        return json_output

    def set_switch_v3(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update a device switch via the v3 endpoint."""
        return _controls.set_switch_v3(
            self, serial, switch_type, enable, channel, max_retries, _owner=_sys.modules[__name__]
        )

    def set_switch_legacy(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fallback legacy switch endpoint used by older firmware."""
        return _controls.set_switch_legacy(
            self, serial, switch_type, enable, channel, max_retries, _owner=_sys.modules[__name__]
        )

    def set_switch(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Try the v3 switch endpoint, falling back to the legacy API if needed."""
        return _controls.set_switch(
            self, serial, switch_type, enable, channel, max_retries, _owner=_sys.modules[__name__]
        )

    def switch_status(
        self,
        serial: str,
        status_type: int,
        enable: bool | int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Camera features are represented as switches. Switch them on or off."""
        return _controls.switch_status(
            self,
            serial,
            status_type,
            enable,
            channel_no,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def device_switch(
        self, serial: str, channel: int, enable: int, switch_type: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Direct wrapper for /v3/devices/{serial}/switch endpoint."""
        return _controls.device_switch(
            self,
            serial,
            channel,
            enable,
            switch_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def switch_status_other(
        self,
        serial: str,
        status_type: int,
        enable: int,
        channel_number: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Features are represented as switches. This api is for alternative switch types to turn them on or off.

        All day recording is a good example.
        """
        return _controls.switch_status_other(
            self,
            serial,
            status_type,
            enable,
            channel_number,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_camera_defence(
        self,
        serial: str,
        enable: int,
        channel_no: int = 1,
        arm_type: str = "Global",
        actor: str = "V",
        max_retries: int = 0,
    ) -> bool:
        """Enable/Disable motion detection on camera."""
        return _controls.set_camera_defence(
            self,
            serial,
            enable,
            channel_no,
            arm_type,
            actor,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_battery_camera_work_mode(self, serial: str, value: int) -> bool:
        """Set battery camera work mode."""
        return _controls.set_battery_camera_work_mode(
            self, serial, value, _owner=_sys.modules[__name__]
        )

    def set_detection_mode(self, serial: str, value: int) -> bool:
        """Set detection mode.

        Deprecated in favour of set_alarm_detect_human_car() but kept for
        backwards compatibility with older callers inside the integration.
        """
        return _controls.set_detection_mode(self, serial, value, _owner=_sys.modules[__name__])

    def set_alarm_detect_human_car(self, serial: str, value: int) -> bool:
        """Update Alarm_DetectHumanCar type on the device."""
        return _controls.set_alarm_detect_human_car(
            self, serial, value, _owner=_sys.modules[__name__]
        )

    def set_alarm_advanced_detect(self, serial: str, value: int) -> bool:
        """Update Alarm_AdvancedDetect type on the device."""
        return _controls.set_alarm_advanced_detect(
            self, serial, value, _owner=_sys.modules[__name__]
        )

    def set_algorithm_param(
        self, serial: str, subtype: str | int, value: int, channel: int = 1
    ) -> bool:
        """Update a single AlgorithmInfo subtype value via devconfig."""
        return _controls.set_algorithm_param(
            self, serial, subtype, value, channel, _owner=_sys.modules[__name__]
        )

    def set_night_vision_mode(self, serial: str, mode: int, luminance: int = 100) -> bool:
        """Set night vision mode."""
        return _controls.set_night_vision_mode(
            self, serial, mode, luminance, _owner=_sys.modules[__name__]
        )

    def set_display_mode(self, serial: str, mode: int) -> bool:
        """Change video color and saturation mode."""
        return _controls.set_display_mode(self, serial, mode, _owner=_sys.modules[__name__])

    def set_dev_config_kv(
        self,
        serial: str,
        channel: int,
        key: str,
        value: Mapping[str, Any] | str | bytes | float | bool,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update a device configuration key/value pair via devconfig."""
        return _controls.set_dev_config_kv(
            self, serial, channel, key, value, max_retries, _owner=_sys.modules[__name__]
        )

    def set_common_key_value(
        self, serial: str, channel: int, key: str, value: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Update a devconfig key/value pair using query parameters."""
        return _controls.set_common_key_value(
            self,
            serial,
            channel,
            key,
            value,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_device_config_by_key(
        self, serial: str, value: Any, key: str, max_retries: int = 0
    ) -> bool:
        """Change value on device by setting key."""
        return _controls.set_device_config_by_key(
            self, serial, value, key, max_retries, _owner=_sys.modules[__name__]
        )

    def set_device_key_value(
        self, serial: str, channel: int, key: str, value: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Alias for the query-based key/value setter."""
        return _controls.set_device_key_value(
            self,
            serial,
            channel,
            key,
            value,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def audition_request(
        self, serial: str, channel: int, request: str, payload: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Send an audition request via /v3/devconfig/op."""
        return _controls.audition_request(
            self,
            serial,
            channel,
            request,
            payload,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def baby_control(
        self,
        serial: str,
        channel: int,
        local_index: int,
        command: str,
        action: str,
        speed: int,
        uuid: str,
        control: str,
        hardware_code: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Send the baby monitor motor control request."""
        return _controls.baby_control(
            self,
            serial,
            channel,
            local_index,
            command,
            action,
            speed,
            uuid,
            control,
            hardware_code,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_device_feature_by_key(
        self, serial: str, product_id: str, value: Any, key: str, max_retries: int = 0
    ) -> bool:
        """Change value on device by setting the iot-feature's key.

        The FEATURE key that is part of 'device info' holds
        information about the device's functions (for example light_switch, brightness etc.).
        """
        return _controls.set_device_feature_by_key(
            self, serial, product_id, value, key, max_retries, _owner=_sys.modules[__name__]
        )

    def _iot_request(
        self,
        method: str,
        endpoint: str,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        payload: Any = None,
        max_retries: int = 0,
        error_message: str,
    ) -> JsonDict:
        """Helper to perform IoT feature/action requests with JSON payload support."""
        return _controls._iot_request(
            self,
            method,
            endpoint,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            error_message=error_message,
            _owner=_sys.modules[__name__],
        )

    def get_low_battery_keep_alive(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch low-battery keep-alive status exposed under the IoT feature API."""
        return _controls.get_low_battery_keep_alive(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_object_removal_status(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        payload: Any | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch object-removal (left-behind) status for supported devices."""
        return _controls.get_object_removal_status(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_remote_control_path_list(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return the remote control patrol path list for auto-tracking models."""
        return _controls.get_remote_control_path_list(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_tracking_status(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Obtain the current subject-tracking status from the IoT feature API."""
        return _controls.get_tracking_status(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_port_security(
        self,
        serial: str,
        *,
        resource_identifier: str = "Video",
        local_index: str = "1",
        domain_id: str = "NetworkSecurityProtection",
        action_id: str = "PortSecurity",
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch port security configuration via the IoT feature API."""
        return _controls.get_port_security(
            self,
            serial,
            resource_identifier=resource_identifier,
            local_index=local_index,
            domain_id=domain_id,
            action_id=action_id,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_port_security(
        self,
        serial: str,
        value: Mapping[str, Any] | dict[str, Any],
        *,
        resource_identifier: str = "Video",
        local_index: str = "1",
        domain_id: str = "NetworkSecurityProtection",
        action_id: str = "PortSecurity",
        max_retries: int = 0,
    ) -> JsonDict:
        """Update port security configuration via the IoT feature API."""
        return _controls.set_port_security(
            self,
            serial,
            value,
            resource_identifier=resource_identifier,
            local_index=local_index,
            domain_id=domain_id,
            action_id=action_id,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_device_feature_value(
        self,
        serial: str,
        resource_identifier: str,
        domain_identifier: str,
        prop_identifier: str,
        *,
        local_index: str | int = "1",
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve a device feature value via the IoT feature API."""
        return _controls.get_device_feature_value(
            self,
            serial,
            resource_identifier,
            domain_identifier,
            prop_identifier,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_intelligent_fill_light(
        self, serial: str, *, enabled: bool, local_index: str = "1", max_retries: int = 0
    ) -> JsonDict:
        """Toggle the intelligent fill light mode via the IoT feature API."""
        return _controls.set_intelligent_fill_light(
            self,
            serial,
            enabled=enabled,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_image_flip_iot(
        self,
        serial: str,
        *,
        enabled: bool | None = None,
        payload: Any | None = None,
        local_index: str = "1",
        max_retries: int = 0,
    ) -> JsonDict:
        """Set image flip configuration using the IoT feature endpoint."""
        return _controls.set_image_flip_iot(
            self,
            serial,
            enabled=enabled,
            payload=payload,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_iot_action(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        value: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Trigger an IoT action (setAction/putAction in the mobile API)."""
        return _controls.set_iot_action(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            value,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_iot_feature(
        self,
        serial: str,
        resource_identifier: str,
        local_index: str,
        domain_id: str,
        action_id: str,
        value: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update an IoT feature value via the feature endpoint."""
        return _controls.set_iot_feature(
            self,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            value,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_lens_defog_mode(
        self, serial: str, value: int, *, local_index: str = "1", max_retries: int = 0
    ) -> tuple[bool, str]:
        """Update the lens defog configuration using canonical option index.

        Args:
            serial: Device serial number.
            value: Select option index (0=auto, 1=on, 2=off).
            local_index: Channel index for multi-channel devices.
            max_retries: Number of retries for transient failures.

        Returns:
            A tuple of (enabled flag, defog mode string) reflecting the
            configuration that was sent to the device.
        """
        return _controls.set_lens_defog_mode(
            self,
            serial,
            value,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def update_device_name(self, serial: str, name: str, *, max_retries: int = 0) -> JsonDict:
        """Rename a device via the legacy updateName endpoint."""
        return _controls.update_device_name(
            self, serial, name, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def upgrade_device(self, serial: str, max_retries: int = 0) -> bool:
        """Upgrade device firmware."""
        return _controls.upgrade_device(self, serial, max_retries, _owner=_sys.modules[__name__])

    def get_storage_status(self, serial: str, max_retries: int = 0) -> Any:
        """Get device storage status."""
        return _controls.get_storage_status(
            self, serial, max_retries, _owner=_sys.modules[__name__]
        )

    def sound_alarm(self, serial: str, enable: int = 1, max_retries: int = 0) -> bool:
        """Sound alarm on a device."""
        return _controls.sound_alarm(
            self, serial, enable, max_retries, _owner=_sys.modules[__name__]
        )

    def get_user_id(self, max_retries: int = 0) -> Any:
        """Get Ezviz userid, used by restricted api endpoints."""
        return _controls.get_user_id(self, max_retries, _owner=_sys.modules[__name__])

    def set_video_enc(
        self,
        serial: str,
        enable: int = 1,
        camera_verification_code: str | None = None,
        new_password: str | None = None,
        old_password: str | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable or Disable video encryption."""
        return _controls.set_video_enc(
            self,
            serial,
            enable,
            camera_verification_code,
            new_password,
            old_password,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def device_authenticate(
        self,
        serial: str,
        *,
        need_check_code: bool,
        check_code: str | None,
        sender_type: int,
        max_retries: int = 0,
    ) -> JsonDict:
        """Authenticate a device, optionally requiring check code."""
        return _controls.device_authenticate(
            self,
            serial,
            need_check_code=need_check_code,
            check_code=check_code,
            sender_type=sender_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def reboot_camera(
        self, serial: str, delay: int = 1, operation: int = 1, max_retries: int = 0
    ) -> bool:
        """Reboot camera."""
        return _controls.reboot_camera(
            self, serial, delay, operation, max_retries, _owner=_sys.modules[__name__]
        )

    def set_offline_notification(
        self, serial: str, enable: int = 1, req_type: int = 1, max_retries: int = 0
    ) -> bool:
        """Set offline notification."""
        return _controls.set_offline_notification(
            self, serial, enable, req_type, max_retries, _owner=_sys.modules[__name__]
        )

    def device_email_alert_state(
        self, serials: list[str] | str, *, max_retries: int = 0
    ) -> JsonDict:
        """Get email alert state for one or more devices."""
        return _controls.device_email_alert_state(
            self, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def save_device_email_alert_state(
        self, enable: bool, serials: list[str] | str, *, max_retries: int = 0
    ) -> JsonDict:
        """Update email alert state for the provided devices."""
        return _controls.save_device_email_alert_state(
            self, enable, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_group_defence_mode(self, max_retries: int = 0) -> Any:
        """Get group arm status. The alarm arm/disarm concept on 1st page of app."""
        return _controls.get_group_defence_mode(self, max_retries, _owner=_sys.modules[__name__])

    # Not tested
    def cancel_alarm_device(self, serial: str, max_retries: int = 0) -> bool:
        """Cacnel alarm on an Alarm device."""
        return _controls.cancel_alarm_device(
            self, serial, max_retries, _owner=_sys.modules[__name__]
        )

    def load_devices(self, refresh: bool = True) -> JsonDict:
        """Build status maps for cameras and light bulbs.

        refresh: if True, camera.status() may perform network fetches (e.g. alarms).
        Returns a combined mapping of serial -> status dict for both cameras and bulbs.

        Note: We update in place and do not remove keys for devices that may
        have disappeared. Users who intentionally remove a device can restart
        the integration to flush stale entries.
        """
        return _devices.load_devices(self, refresh, _owner=_sys.modules[__name__])

    def _prefetch_latest_camera_alarms(
        self, serials: Iterable[str], *, chunk_size: int = 20
    ) -> dict[str, dict[str, Any]]:
        """Attempt to fetch the most recent unified message per camera serial."""
        return _devices._prefetch_latest_camera_alarms(
            self, serials, chunk_size=chunk_size, _owner=_sys.modules[__name__]
        )

    def load_cameras(self, refresh: bool = True) -> JsonDict:
        """Load and return all camera status mappings.

        refresh: pass-through to load_devices() to control network fetches.
        """
        return _devices.load_cameras(self, refresh, _owner=_sys.modules[__name__])

    def load_light_bulbs(self, refresh: bool = True) -> JsonDict:
        """Load and return all light bulb status mappings.

        refresh: pass-through to load_devices().
        """
        return _devices.load_light_bulbs(self, refresh, _owner=_sys.modules[__name__])

    def load_smart_plugs(self, refresh: bool = True) -> JsonDict:
        """Load and return all smart plugs status mappings.

        refresh: pass-through to load_devices().
        """
        return _devices.load_smart_plugs(self, refresh, _owner=_sys.modules[__name__])

    def get_device_infos(self, serial: str | None = None) -> JsonDict:
        """Load all devices and build dict per device serial."""
        return _devices.get_device_infos(self, serial, _owner=_sys.modules[__name__])

    def get_device_records(
        self, serial: str | None = None
    ) -> dict[str, EzvizDeviceRecord] | EzvizDeviceRecord | JsonDict:
        """Return devices as EzvizDeviceRecord mapping (or single record).

        Falls back to raw when a specific serial is requested but not found.
        """
        return _devices.get_device_records(self, serial, _owner=_sys.modules[__name__])

    def get_accessory(self, serial: str, local_index: str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve accessory information linked to a device."""
        return _devices.get_accessory(
            self, serial, local_index, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_dev_config(
        self, serial: str, channel: int, key: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Retrieve a devconfig value by key."""
        return _devices.get_dev_config(
            self, serial, channel, key, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def ptz_control(self, command: str, serial: str, action: str, speed: int = 5) -> Any:
        """PTZ Control by API."""
        return _devices.ptz_control(
            self, command, serial, action, speed, _owner=_sys.modules[__name__]
        )

    def capture_picture(self, serial: str, channel: int, *, max_retries: int = 0) -> JsonDict:
        """Trigger a snapshot capture on the device."""
        return _devices.capture_picture(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_cam_key(
        self, serial: str, smscode: str | int | None = None, max_retries: int = 0
    ) -> Any:
        """Get Camera encryption key. The key that is set after the camera is added to the account.

        Args:
            serial (str): The camera serial number.
            smscode (str | int | None): The 2FA code account when rights elevation is required.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the camera encryption key can't be retrieved.
            EzvizAuthVerificationCode: If the account requires elevation with 2FA code.
            DeviceException: If the physical device is not reachable.

        Returns:
            Any: JSON response, filtered to return encryptkey:
                {
                    "resultCode": int,     # Result code (0 if successful)
                    "encryptkey": str,     # Camera encryption key
                    "resultDes": str       # Status message in chinese
                }
        """
        return _devices.get_cam_key(
            self, serial, smscode, max_retries, _owner=_sys.modules[__name__]
        )

    def download_alarm_image(
        self,
        image_url: str,
        serial: str | None = None,
        *,
        encryption_key: str | None = None,
        smscode: str | int | None = None,
        decrypt: bool = True,
        max_retries: int = 0,
    ) -> bytes:
        """Download an alarm image and decrypt EZVIZ/Hik encrypted payloads.

        Encrypted alarm snapshots contain the ``hikencodepicture`` header. When
        that header is present and no explicit ``encryption_key`` is supplied,
        ``serial`` is used to fetch the camera encryption key from the EZVIZ API.
        """
        return _devices.download_alarm_image(
            self,
            image_url,
            serial,
            encryption_key=encryption_key,
            smscode=smscode,
            decrypt=decrypt,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def probe_local_stream(
        self,
        serial: str,
        *,
        duration_seconds: float = 10.0,
        max_frames: int = 1024,
        max_bytes: int = 1024 * 1024,
        receiver_port: int = 10101,
    ) -> dict[str, Any]:
        """Return sanitized protocol evidence and an explicit source recommendation.

        This probes local negotiation, not media-key validity or full playback.
        Authentication errors propagate; no stream source is silently changed.
        """
        from dataclasses import asdict  # noqa: PLC0415

        from pyezvizapi.streaming.local.probe import probe_local_sdk_stream_from_client  # noqa: PLC0415 -- preserve lazy import boundary

        return asdict(
            probe_local_sdk_stream_from_client(
                self,
                serial,
                duration_seconds=duration_seconds,
                max_frames=max_frames,
                max_bytes=max_bytes,
                receiver_port=receiver_port,
            )
        )

    def open_stream(
        self,
        serial: str,
        *,
        source: AutoClipSource | None = None,
        channel: int | None = None,
    ) -> AutoMediaStream:
        """Return a lazy automatic packet stream; use as a context manager.

        Defaults to metadata-first auto. ``AutoClipSource(mode="offline", ... )``
        prohibits all cloud/account discovery. Packets still require video
        decryption/remuxing before serving them to a media player.
        """
        return AutoMediaStream(self, serial, source or AutoClipSource(), channel=channel)

    def save_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        source: ClipSource = "local-sdk",
        auto_mode: Literal["auto", "offline"] = "auto",
        auto_device: dict[str, Any] | None = None,
        allow_cloud_fallback: bool = True,
        local_credentials: EzvizLocalSdkCredentials | None = None,
        output_format: ClipOutputFormat | None = None,
        duration_seconds: float | None = _SOURCE_DEFAULT_DURATION,
        max_packets: int | None = None,
        channel: int | None = None,
        ffmpeg_path: str = "ffmpeg",
        decrypt_video: bool = False,
        media_key: str | bytes | None = None,
        nalu_header_size: int | None = _SOURCE_DEFAULT_NALU_HEADER_SIZE,
        cas_serial: str | None = None,
        register_p2p_session: bool = True,
        p2p_register_max_retries: int = MAX_RETRIES,
        timeout: float | None = 10.0,
        smscode: str | int | None = None,
        host: str | None = None,
        command_port: int | None = None,
        hcnetsdk_command_frames: Iterable[bytes] | None = None,
        hcnetsdk_command_plan: HcNetSdkCommandPortMultiSocketPlan | None = None,
        hcnetsdk_command_generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan | None = None,
        hcnetsdk_command_password: str | bytes | None = None,
        hcnetsdk_local_ip: str | None = None,
        hcnetsdk_read_response_after_each: bool | Iterable[bool] = True,
        hcnetsdk_command_metadata_callback: Callable[[Any], None] | None = None,
        hcnetsdk_h264_skip_initial_idr_windows: int = 0,
        hcnetsdk_h264_trim_to_clean_idr_window: bool = False,
        hcnetsdk_h264_clean_idr_preroll_seconds: float = 0.0,
        hcnetsdk_h264_clean_idr_max_windows: int = 32,
        hcnetsdk_h264_wait_for_clean_idr_window: bool | None = None,
        hcnetsdk_h264_clean_idr_wait_seconds: float = 60.0,
        hcnetsdk_video_trim_to_clean_window: bool | None = None,
        hcnetsdk_video_clean_window_preroll_seconds: float | None = None,
        hcnetsdk_video_clean_window_max_windows: int | None = None,
        hcnetsdk_video_wait_for_clean_window: bool | None = None,
        hcnetsdk_video_clean_window_wait_seconds: float | None = None,
        cloud_client_type: int = _SOURCE_DEFAULT_CLIENT_TYPE,
        cloud_token_index: int = 0,
        cloud_refresh_vtm: bool = True,
        local_sdk_ecdh_receiver_port: int | None = None,
        local_sdk_ecdh_send_init: bool = False,
        local_sdk_ecdh_max_prefix_bytes: int = 4096,
        local_sdk_ecdh_max_frames: int | None = None,
        native_shared_clock: bool = False,
        app_relative_clock: bool = False,
        cloud_playback_begin_time: str | None = None,
        cloud_playback_end_time: str | None = None,
        cloud_playback_lid: str | None = None,
        cloud_playback_decrypt_audio: bool = False,
        cloud_playback_max_bytes: int = 128 * 1024 * 1024,
        cloud_playback_transfer_timeout: float = 60.0,
    ) -> SaveMediaResult:
        """Save a local camera clip to a path or binary file object.

        ``source="auto"`` selects from pagelist and verifies the stream.
        ``auto_mode="offline"`` requires ``local_credentials`` and forbids
        account discovery/key refresh/cloud fallback.
        ``source="local-sdk"`` uses the direct-local 9010/9020 SDK path.
        ``source="cloud"`` uses the EZVIZ VTM cloud live stream path.
        ``source="hcnetsdk-command-port"`` consumes complete caller-supplied
        port-8000 HCNetSDK bootstrap command frames, then remuxes the command
        port media stream to MPEG-TS.
        When omitted, ``output_format`` defaults to MPEG-PS for clear
        ``source="local-sdk-ecdh"`` captures and MPEG-TS for decrypted ECDH
        or other sources. MPEG-TS accommodates both ECDH MPEG-PS and IDMX/RTP.

        This long-form signature is retained for compatibility. New code can
        group the same settings with :meth:`save_clip_with_options`.

        When ``nalu_header_size`` is omitted, cloud and direct-local decryption
        auto-detect the clear codec header. Other sources retain the legacy
        ``0`` default.
        Passing ``0`` or ``None`` explicitly preserves that exact choice.
        """
        if source == "cloud-playback":
            if timeout is None:
                raise PyEzvizError("SD playback requires a finite socket timeout")
            if native_shared_clock or app_relative_clock:
                raise PyEzvizError("SD playback does not support native clock overrides")
            return self.save_clip_with_options(
                serial,
                output,
                ClipOptions(
                    source=CloudPlaybackClipSource(
                        cloud_playback_begin_time or "",
                        cloud_playback_end_time or "",
                        client_type=3
                        if isinstance(cloud_client_type, _compat_module_6._SourceDefaultClientType)
                        else cloud_client_type,
                        decrypt_audio=cloud_playback_decrypt_audio,
                        token_index=cloud_token_index,
                        refresh_vtm=cloud_refresh_vtm,
                        timeout=timeout,
                        lid=cloud_playback_lid,
                        max_bytes=cloud_playback_max_bytes,
                        transfer_timeout=cloud_playback_transfer_timeout,
                        smscode=smscode,
                    ),
                    capture=CaptureLimits(
                        duration_seconds=duration_seconds, max_packets=max_packets
                    ),
                    decode=MediaDecodeOptions(
                        decrypt_video=decrypt_video,
                        media_key=media_key,
                        nalu_header_size=None
                        if nalu_header_size is _SOURCE_DEFAULT_NALU_HEADER_SIZE
                        else nalu_header_size,
                    ),
                    mux=MediaMuxOptions(
                        output_format=output_format or "mpegps", ffmpeg_path=ffmpeg_path
                    ),
                    channel=channel,
                ),
            )
        return _capture.save_clip(
            self,
            serial,
            output,
            source=source,
            auto_mode=auto_mode,
            auto_device=auto_device,
            allow_cloud_fallback=allow_cloud_fallback,
            local_credentials=local_credentials,
            output_format=output_format,
            duration_seconds=duration_seconds,
            max_packets=max_packets,
            channel=channel,
            ffmpeg_path=ffmpeg_path,
            decrypt_video=decrypt_video,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            cas_serial=cas_serial,
            register_p2p_session=register_p2p_session,
            p2p_register_max_retries=p2p_register_max_retries,
            timeout=timeout,
            smscode=smscode,
            host=host,
            command_port=command_port,
            hcnetsdk_command_frames=hcnetsdk_command_frames,
            hcnetsdk_command_plan=hcnetsdk_command_plan,
            hcnetsdk_command_generated_plan=hcnetsdk_command_generated_plan,
            hcnetsdk_command_password=hcnetsdk_command_password,
            hcnetsdk_local_ip=hcnetsdk_local_ip,
            hcnetsdk_read_response_after_each=hcnetsdk_read_response_after_each,
            hcnetsdk_command_metadata_callback=hcnetsdk_command_metadata_callback,
            hcnetsdk_h264_skip_initial_idr_windows=hcnetsdk_h264_skip_initial_idr_windows,
            hcnetsdk_h264_trim_to_clean_idr_window=hcnetsdk_h264_trim_to_clean_idr_window,
            hcnetsdk_h264_clean_idr_preroll_seconds=hcnetsdk_h264_clean_idr_preroll_seconds,
            hcnetsdk_h264_clean_idr_max_windows=hcnetsdk_h264_clean_idr_max_windows,
            hcnetsdk_h264_wait_for_clean_idr_window=hcnetsdk_h264_wait_for_clean_idr_window,
            hcnetsdk_h264_clean_idr_wait_seconds=hcnetsdk_h264_clean_idr_wait_seconds,
            hcnetsdk_video_trim_to_clean_window=hcnetsdk_video_trim_to_clean_window,
            hcnetsdk_video_clean_window_preroll_seconds=hcnetsdk_video_clean_window_preroll_seconds,
            hcnetsdk_video_clean_window_max_windows=hcnetsdk_video_clean_window_max_windows,
            hcnetsdk_video_wait_for_clean_window=hcnetsdk_video_wait_for_clean_window,
            hcnetsdk_video_clean_window_wait_seconds=hcnetsdk_video_clean_window_wait_seconds,
            cloud_client_type=cloud_client_type,
            cloud_token_index=cloud_token_index,
            cloud_refresh_vtm=cloud_refresh_vtm,
            local_sdk_ecdh_receiver_port=local_sdk_ecdh_receiver_port,
            local_sdk_ecdh_send_init=local_sdk_ecdh_send_init,
            local_sdk_ecdh_max_prefix_bytes=local_sdk_ecdh_max_prefix_bytes,
            local_sdk_ecdh_max_frames=local_sdk_ecdh_max_frames,
            native_shared_clock=native_shared_clock,
            app_relative_clock=app_relative_clock,
            _owner=_sys.modules[__name__],
        )

    def save_clip_with_options(
        self, serial: str, output: str | Path | BinaryIO, options: ClipOptions
    ) -> SaveMediaResult:
        """Save a camera clip from a grouped, typed configuration.

        Explicit native timing captures are staged: unsupported clocks must not
        truncate an existing output or append partial media to a caller buffer.
        """
        return _capture.save_clip_with_options(
            self, serial, output, options, _owner=_sys.modules[__name__]
        )

    def _save_clip_with_options(
        self, serial: str, output: str | Path | BinaryIO, options: ClipOptions
    ) -> SaveMediaResult:
        """Dispatch an already validated/staged typed capture."""
        return _capture._save_clip_with_options(
            self, serial, output, options, _owner=_sys.modules[__name__]
        )

    def _save_auto_clip(
        self, serial: str, output: str | Path | BinaryIO, options: ClipOptions
    ) -> SaveMediaResult:
        """Stage bounded attempts; only commit a successful selected source."""
        return _capture._save_auto_clip(
            self, serial, output, options, _owner=_sys.modules[__name__]
        )

    def _save_auto_cloud_clip(
        self, serial: str, output: BinaryIO, options: ClipOptions, deadline: float | None
    ) -> SaveMediaResult:
        return _capture._save_auto_cloud_clip(
            self, serial, output, options, deadline, _owner=_sys.modules[__name__]
        )

    def _save_local_sdk_ecdh_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        output_format: ClipOutputFormat,
        duration_seconds: float | None,
        max_packets: int | None,
        max_frames: int | None,
        channel: int,
        cas_serial: str | None,
        register_p2p_session: bool,
        p2p_register_max_retries: int,
        timeout: float | None,
        receiver_port: int,
        send_init: bool,
        max_prefix_bytes: int,
        ffmpeg_path: str,
        decrypt_video: bool,
        media_key: str | bytes | None,
        nalu_header_size: int | None,
        smscode: str | int | None,
        credentials: EzvizLocalSdkCredentials | None = None,
        fresh_retry_port: bool = False,
    ) -> SaveMediaResult:
        """Save a clip through the local SDK ECDH stream path."""
        return _capture._save_local_sdk_ecdh_clip(
            self,
            serial,
            output,
            output_format=output_format,
            duration_seconds=duration_seconds,
            max_packets=max_packets,
            max_frames=max_frames,
            channel=channel,
            cas_serial=cas_serial,
            register_p2p_session=register_p2p_session,
            p2p_register_max_retries=p2p_register_max_retries,
            timeout=timeout,
            receiver_port=receiver_port,
            send_init=send_init,
            max_prefix_bytes=max_prefix_bytes,
            ffmpeg_path=ffmpeg_path,
            decrypt_video=decrypt_video,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            smscode=smscode,
            credentials=credentials,
            fresh_retry_port=fresh_retry_port,
            _owner=_sys.modules[__name__],
        )

    def _save_local_sdk_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        output_format: ClipOutputFormat,
        duration_seconds: float | None,
        max_packets: int | None,
        channel: int,
        ffmpeg_path: str,
        decrypt_video: bool,
        media_key: str | bytes | None,
        nalu_header_size: int | None,
        cas_serial: str | None,
        register_p2p_session: bool,
        p2p_register_max_retries: int,
        timeout: float | None,
        smscode: str | int | None,
        credentials: EzvizLocalSdkCredentials | None = None,
        receiver_port: int = 10101,
        skip_empty_packets: bool = False,
        native_shared_clock: bool = False,
        app_relative_clock: bool = False,
        decrypt_hevc_parameter_sets: bool = False,
    ) -> SaveMediaResult:
        """Save a clip through the direct-local SDK path."""
        return _capture._save_local_sdk_clip(
            self,
            serial,
            output,
            output_format=output_format,
            duration_seconds=duration_seconds,
            max_packets=max_packets,
            channel=channel,
            ffmpeg_path=ffmpeg_path,
            decrypt_video=decrypt_video,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            cas_serial=cas_serial,
            register_p2p_session=register_p2p_session,
            p2p_register_max_retries=p2p_register_max_retries,
            timeout=timeout,
            smscode=smscode,
            credentials=credentials,
            receiver_port=receiver_port,
            skip_empty_packets=skip_empty_packets,
            native_shared_clock=native_shared_clock,
            app_relative_clock=app_relative_clock,
            decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
            _owner=_sys.modules[__name__],
        )

    def _save_hcnetsdk_command_port_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        output_format: ClipOutputFormat,
        duration_seconds: float | None,
        max_packets: int | None,
        channel: int,
        ffmpeg_path: str,
        decrypt_video: bool,
        media_key: str | bytes | None,
        nalu_header_size: int | None,
        timeout: float | None,
        host: str | None,
        command_port: int | None,
        command_frames: Iterable[bytes] | None,
        command_plan: HcNetSdkCommandPortMultiSocketPlan | None,
        generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan | None,
        command_password: str | bytes | None,
        local_ip: str | None,
        read_response_after_each: bool | Iterable[bool],
        metadata_callback: Callable[[Any], None] | None,
        h264_skip_initial_idr_windows: int = 0,
        h264_trim_to_clean_idr_window: bool = False,
        h264_clean_idr_preroll_seconds: float = 0.0,
        h264_clean_idr_max_windows: int = 32,
        h264_wait_for_clean_idr_window: bool = False,
        h264_clean_idr_wait_seconds: float = 60.0,
        native_shared_clock: bool = False,
        app_relative_clock: bool = False,
        decrypt_hevc_parameter_sets: bool = False,
    ) -> SaveMediaResult:
        """Save a clip through caller-supplied port-8000 HCNetSDK frames."""
        return _capture._save_hcnetsdk_command_port_clip(
            self,
            serial,
            output,
            output_format=output_format,
            duration_seconds=duration_seconds,
            max_packets=max_packets,
            channel=channel,
            ffmpeg_path=ffmpeg_path,
            decrypt_video=decrypt_video,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            timeout=timeout,
            host=host,
            command_port=command_port,
            command_frames=command_frames,
            command_plan=command_plan,
            generated_plan=generated_plan,
            command_password=command_password,
            local_ip=local_ip,
            read_response_after_each=read_response_after_each,
            metadata_callback=metadata_callback,
            h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
            h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
            h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
            h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
            native_shared_clock=native_shared_clock,
            app_relative_clock=app_relative_clock,
            decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
            _owner=_sys.modules[__name__],
        )

    @staticmethod
    def _open_hcnetsdk_command_port_clip_stream(
        endpoint: HcNetSdkLanEndpoint,
        *,
        frames: tuple[bytes, ...],
        command_plan: HcNetSdkCommandPortMultiSocketPlan | None,
        generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan | None,
        command_password: str | bytes | None,
        timeout: float | None,
        local_ip: str | None,
        read_response_after_each: bool | Iterable[bool],
    ) -> Any:
        """Open the selected HCNetSDK command-port stream mode."""
        return _capture._open_hcnetsdk_command_port_clip_stream(
            endpoint,
            frames=frames,
            command_plan=command_plan,
            generated_plan=generated_plan,
            command_password=command_password,
            timeout=timeout,
            local_ip=local_ip,
            read_response_after_each=read_response_after_each,
            _owner=_sys.modules[__name__],
        )

    def _save_cloud_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        output_format: ClipOutputFormat,
        duration_seconds: float | None,
        max_packets: int | None,
        channel: int | None,
        ffmpeg_path: str,
        decrypt_video: bool,
        media_key: str | bytes | None,
        nalu_header_size: int | None,
        timeout: float | None,
        client_type: int,
        token_index: int,
        refresh_vtm: bool,
        smscode: str | int | None,
        capture_deadline: float | None = None,
    ) -> SaveMediaResult:
        """Save a clip through the EZVIZ VTM cloud live stream path."""
        return _capture._save_cloud_clip(
            self,
            serial,
            output,
            output_format=output_format,
            duration_seconds=duration_seconds,
            max_packets=max_packets,
            channel=channel,
            ffmpeg_path=ffmpeg_path,
            decrypt_video=decrypt_video,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            timeout=timeout,
            client_type=client_type,
            token_index=token_index,
            refresh_vtm=refresh_vtm,
            smscode=smscode,
            capture_deadline=capture_deadline,
            _owner=_sys.modules[__name__],
        )

    def _hcnetsdk_command_port_endpoint(
        self, serial: str, *, host: str | None, command_port: int | None
    ) -> HcNetSdkLanEndpoint:
        """Return a command-port endpoint from overrides or device metadata."""
        return _capture._hcnetsdk_command_port_endpoint(
            self, serial, host=host, command_port=command_port, _owner=_sys.modules[__name__]
        )

    def save_image(
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        channel: int = 1,
        image_url: str | None = None,
        decrypt: bool = True,
        smscode: str | int | None = None,
    ) -> SaveMediaResult:
        """Capture or download a camera image to a path or binary file object."""
        return _capture.save_image(
            self,
            serial,
            output,
            channel=channel,
            image_url=image_url,
            decrypt=decrypt,
            smscode=smscode,
            _owner=_sys.modules[__name__],
        )

    def get_cam_auth_code(
        self,
        serial: str,
        encrypt_pwd: str | None = None,
        msg_auth_code: str | int | None = None,
        sender_type: int = 0,
        max_retries: int = 0,
    ) -> Any:
        """Get Camera auth code. This is the verification code on the camera sticker.

        Args:
            serial (str): The camera serial number.
            encrypt_pwd (str | None): This is always none.
            msg_auth_code (str | int | None): The 2FA code.
            sender_type (int): The sender type. Defaults to 0. Needs to be 3 when returning 2FA code.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the camera auth code cannot be retrieved.
            EzvizAuthVerificationCode: If the operation requires elevation with 2FA.
            DeviceException: If the physical device is not reachable.

        Returns:
            Any: JSON response, filtered to return devAuthCode:
                {
                    "devAuthCode": str,     # Device authorization code
                    "meta": {
                        "code": int,       # Status code (200 if successful)
                        "message": str,         # Status message in chinese
                        "moreInfo": null or {"INVALID_PARAMETER": str}
                    }
                }
        """
        return _intercom.get_cam_auth_code(
            self,
            serial,
            encrypt_pwd,
            msg_auth_code,
            sender_type,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_2fa_check_code(
        self, biz_type: str = "DEVICE_AUTH_CODE", username: str | None = None, max_retries: int = 0
    ) -> Any:
        """Initiate 2FA check for sensitive operations. Elevates your session token permission.

        Args:
            biz_type (str): The operation type. (DEVICE_ENCRYPTION | DEVICE_AUTH_CODE)
            username (str): The account username.
            max_retries (int): The maximum number of retries. Defaults to 0.

        Raises:
            PyEzvizError: If the operation fails.

        Returns:
            Any: JSON response with the following structure:
                {
                    "meta": {
                        "code": int,       # Status code (200 if successful)
                        "message": str         # Status message in chinese
                        "moreInfo": null
                    },
                    "contact": {
                        "type": str,   # 2FA code will be sent to this (EMAIL)
                        "fuzzyContact": str     # Destination value (e.g., someone@email.local)
                    }
                }
        """
        return _intercom.get_2fa_check_code(
            self, biz_type, username, max_retries, _owner=_sys.modules[__name__]
        )

    def create_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Create panoramic image."""
        return _intercom.create_panoramic(self, serial, max_retries, _owner=_sys.modules[__name__])

    def return_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Return panoramic image url list."""
        return _intercom.return_panoramic(self, serial, max_retries, _owner=_sys.modules[__name__])

    def ptz_control_coordinates(
        self,
        serial: str,
        x_axis: float,
        y_axis: float,
        *,
        resource_identifier: str = "Video_1",
        local_index: str = "1",
        max_retries: int = 0,
    ) -> bool:
        """PTZ Coordinate Move."""
        return _intercom.ptz_control_coordinates(
            self,
            serial,
            x_axis,
            y_axis,
            resource_identifier=resource_identifier,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_door_lock_users(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve users associated with a door lock device."""
        return _intercom.get_door_lock_users(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_terminals(self, *, limit: int = 20, offset: int = 0, max_retries: int = 0) -> JsonDict:
        """Retrieve account terminal information."""
        return _intercom.get_terminals(
            self, limit=limit, offset=offset, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_latest_terminal_bind(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        terminal_name: str | None = "Hassio",
        max_retries: int = 0,
    ) -> tuple[str, str]:
        """Return the latest terminal bind code and terminal user name."""
        return _intercom.get_latest_terminal_bind(
            self,
            limit=limit,
            offset=offset,
            terminal_name=terminal_name,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def remote_unlock(
        self,
        serial: str,
        user_id: str,
        lock_no: int,
        *,
        resource_id: str | None = None,
        local_index: str | int | None = None,
        stream_token: str | None = None,
        lock_type: str | None = None,
        bind_code: str | None = None,
        terminal_filter_name: str | None = "Hassio",
        use_terminal_bind: bool = True,
    ) -> bool:
        """Sends a remote command to unlock a specific lock.

        Args:
            serial (str): The camera serial.
            user_id (str): The user id.
            lock_no (int): The lock number.
            resource_id (str, optional): Resource identifier reported by the device
                (for example ``Video`` or ``DoorLock``). Defaults to ``"Video"``.
            local_index (str | int, optional): Local channel index for the lock.
                Defaults to ``"1"``.
            stream_token (str, optional): Stream token associated with the lock if
                provided by the API. Defaults to empty string when omitted.
            lock_type (str, optional): Optional lock type hint used by some devices.
            bind_code (str, optional): Explicit bind code. When omitted, the latest
                terminal bind code is used if available, otherwise the legacy
                ``FEATURE_CODE + user_id`` bind code is used.
            terminal_filter_name (str, optional): Terminal name to prefer when
                resolving an implicit bind code. Defaults to ``"Hassio"`` to match
                the library login terminal. Pass ``None`` to use the newest valid
                terminal regardless of name.
            use_terminal_bind (bool): Whether to try terminal-derived bind codes
                before falling back to the legacy bind code.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        return _intercom.remote_unlock(
            self,
            serial,
            user_id,
            lock_no,
            resource_id=resource_id,
            local_index=local_index,
            stream_token=stream_token,
            lock_type=lock_type,
            bind_code=bind_code,
            terminal_filter_name=terminal_filter_name,
            use_terminal_bind=use_terminal_bind,
            _owner=_sys.modules[__name__],
        )

    def remote_lock(
        self,
        serial: str,
        user_id: str,
        lock_no: int,
        *,
        resource_id: str | None = None,
        local_index: str | int | None = None,
        stream_token: str | None = None,
        lock_type: str | None = None,
    ) -> bool:
        """Send a remote lock command to a specific lock."""
        return _intercom.remote_lock(
            self,
            serial,
            user_id,
            lock_no,
            resource_id=resource_id,
            local_index=local_index,
            stream_token=stream_token,
            lock_type=lock_type,
            _owner=_sys.modules[__name__],
        )

    def get_remote_unbind_progress(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Check progress of a remote unbind request."""
        return _intercom.get_remote_unbind_progress(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def enable_channel99(self, sms_code: int | None = None) -> JsonDict:
        """Prepare an Android-profile login for channel-99 push.

        Legacy web-profile tokens require a fresh credential login (and MFA if
        required). Merely changing headers does not migrate an existing session.
        Persist the returned token before starting push reception.
        """
        with request_budget_lock(self._token_lock):
            if self.mqtt_client is not None:
                raise PyEzvizError("Stop and discard the MQTT client before migrating login")
            if self._token.get("push_profile") == PUSH_PROFILE:
                return self.login(sms_code)
            if not self.account or not self.password:
                raise EzvizAuthTokenExpired(
                    "Channel-99 migration requires a fresh credential login"
                )
            self._token["push_profile"] = PUSH_PROFILE
            self._token["feature_code"] = FEATURE_CODE
            for key in ("push_state", "service_urls", "user_id", "username"):
                cast(dict[str, Any], self._token).pop(key, None)
            synchronize_http_headers(
                self._session.headers,
                ANDROID_PROFILE,
                None,
                scope="profile",
            )
            # Do not refresh a legacy session while presenting the new profile.
            self._token["session_id"] = None
            self._token["rf_session_id"] = None
            return self._login(sms_code)

    def login(self, sms_code: int | None = None) -> JsonDict:
        """Get or refresh credentials, serializing mutation and persistence with push."""
        with request_budget_lock(self._token_lock):
            return self._login_or_refresh(sms_code)

    def _login_or_refresh(self, sms_code: int | None = None) -> JsonDict:
        """Login implementation under the shared credential lock."""
        validate_feature_code(cast(dict[str, Any], self._token))
        session_id = self._token.get("session_id")
        refresh_session_id = self._token.get("rf_session_id")
        if session_id and refresh_session_id:
            try:
                refresh_credentials(
                    self._session,
                    cast(dict[str, Any], self._token),
                    bounded_request_timeout(self._timeout),
                    self._notify_token_updated,
                    self.get_service_urls,
                )
            except EzvizAuthTokenExpired:
                if not (self.account and self.password):
                    raise
                self._token.update(
                    {
                        "session_id": None,
                        "rf_session_id": None,
                        "username": None,
                        "api_url": self._token["api_url"],
                    }
                )
                return self.login(sms_code=sms_code)
            return cast(dict[Any, Any], self._token)

        if self.account and self.password:
            return self._login(sms_code)

        raise PyEzvizError("Login with account and password required")

    def logout(self) -> bool:
        """Close Ezviz session and remove login session from ezviz servers."""
        with request_budget_lock(self._token_lock):
            try:
                req = budgeted_http_call(
                    self._session,
                    "delete",
                    url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGOUT}",
                    timeout=bounded_request_timeout(self._timeout),
                )
                req.raise_for_status()

            except requests.HTTPError as err:
                if err.response.status_code == 401:
                    _LOGGER.warning(
                        "Http_warning: serial=%s code=%s msg=%s",
                        "unknown",
                        401,
                        "logout_already_invalid",
                    )
                    return True
                raise HTTPError from err

            json_result = self._parse_json(req)

            self.close_session()

            return bool(json_result["meta"]["code"] == 200)

    def set_camera_defence_old(self, serial: str, enable: int) -> bool:
        """Enable/Disable motion detection on camera."""
        return _settings.set_camera_defence_old(self, serial, enable, _owner=_sys.modules[__name__])

    def api_set_defence_schedule(
        self, serial: str, schedule: str, enable: int, max_retries: int = 0
    ) -> bool:
        """Set defence schedules."""
        return _settings.api_set_defence_schedule(
            self, serial, schedule, enable, max_retries, _owner=_sys.modules[__name__]
        )

    def api_set_defence_mode(
        self,
        mode: DefenseModeType | int,
        *,
        visual_alarm: int | None = None,
        sound_mode: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Set defence mode for all devices. The alarm panel from main page is used."""
        return _settings.api_set_defence_mode(
            self,
            mode,
            visual_alarm=visual_alarm,
            sound_mode=sound_mode,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def switch_defence_mode(
        self,
        group_id: int,
        mode: int,
        *,
        visual_alarm: int | None = None,
        sound_mode: int | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Set defence mode for a specific group with optional sound/visual flags."""
        return _settings.switch_defence_mode(
            self,
            group_id,
            mode,
            visual_alarm=visual_alarm,
            sound_mode=sound_mode,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def do_not_disturb(
        self, serial: str, enable: int = 1, channelno: int = 1, max_retries: int = 0
    ) -> bool:
        """Set do not disturb on camera with specified serial."""
        return _settings.do_not_disturb(
            self, serial, enable, channelno, max_retries, _owner=_sys.modules[__name__]
        )

    def set_answer_call(self, serial: str, enable: int = 1, max_retries: int = 0) -> bool:
        """Set answer call on camera with specified serial."""
        return _settings.set_answer_call(
            self, serial, enable, max_retries, _owner=_sys.modules[__name__]
        )

    def manage_intelligent_app(
        self,
        serial: str,
        resource_id: str,
        app_name: str,
        action: str = "add",
        max_retries: int = 0,
    ) -> bool:
        """Manage the intelligent app on the camera by adding (add) or removing (remove) it.

        Args:
            serial (str): The camera serial.
            resource_id (str): The resource identifier of the camera.
            app_name (str): The intelligent app name.
                "app_video_change" = Image change detection,
                "app_human_detect" = Human shape detection,
                "app_car_detect" = Vehicle detection,
                "app_wave_recognize" = Gesture recognition
            action (str, optional): Add or remove app ("add" or "remove"). Defaults to "add".
            max_retries (int, optional): Number of retries attempted. Defaults to 0.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        return _settings.manage_intelligent_app(
            self, serial, resource_id, app_name, action, max_retries, _owner=_sys.modules[__name__]
        )

    def _resolve_resource_id(self, serial: str, resource_id: str | None) -> str:
        """Resolve the intelligent app resource id for a given camera."""
        return _settings._resolve_resource_id(
            self, serial, resource_id, _owner=_sys.modules[__name__]
        )

    def set_intelligent_app_state(
        self,
        serial: str,
        app_name: str,
        enabled: bool,
        resource_id: str | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable or disable an intelligent detection app on a camera."""
        return _settings.set_intelligent_app_state(
            self, serial, app_name, enabled, resource_id, max_retries, _owner=_sys.modules[__name__]
        )

    def device_mirror(
        self, serial: str, channel: int, command: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Send a mirror command using the basics API."""
        return _settings.device_mirror(
            self, serial, channel, command, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def flip_image(self, serial: str, channel: int = 1, max_retries: int = 0) -> bool:
        """Flips the camera image when called.

        Args:
            serial (str): The camera serial.
            channel (int, optional): The camera channel number to flip. Defaults to 1.
            max_retries (int, optional): Number of retries attempted. Defaults to 0.

        Raises:
            PyEzvizError: If max retries are exceeded or if the response indicates failure.
            HTTPError: If an HTTP error occurs (other than a 401, which triggers re-login).

        Returns:
            bool: True if the operation was successful.

        """
        return _settings.flip_image(
            self, serial, channel, max_retries, _owner=_sys.modules[__name__]
        )

    def _resolve_osd_text(
        self, serial: str, *, name: str | None = None, camera_data: Mapping[str, Any] | None = None
    ) -> str:
        """Return the preferred OSD label for a camera."""
        return _settings._resolve_osd_text(
            self, serial, name=name, camera_data=camera_data, _owner=_sys.modules[__name__]
        )

    def set_camera_osd(
        self,
        serial: str,
        text: str | None = None,
        *,
        enabled: bool | None = None,
        name: str | None = None,
        camera_data: Mapping[str, Any] | None = None,
        channel: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set or clear the on-screen display text for a camera.

        Args:
            serial: Camera serial number that should receive the update.
            text: Explicit OSD label to apply. If provided it takes precedence over
                all other inputs and `enabled` is ignored.
            enabled: Convenience flag used when `text` is omitted. When set to
                `True`, the client derives a label automatically (optionally using
                `name`/`camera_data`). When `False`, the overlay is cleared.
            name: Optional friendly name to favour when building the automatic
                overlay text.
            camera_data: Optional camera payload (matching coordinator data) that
                can be inspected for existing OSD labels and names.
            channel: Camera channel identifier (defaults to the primary channel).
            max_retries: Number of retry attempts for transient API failures.

        Returns:
            bool: ``True`` when the request is accepted by the Ezviz backend.
        """
        return _settings.set_camera_osd(
            self,
            serial,
            text,
            enabled=enabled,
            name=name,
            camera_data=camera_data,
            channel=channel,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_floodlight_brightness(
        self, serial: str, luminance: int = 50, channelno: int = 1, max_retries: int = 0
    ) -> bool | str:
        """Set brightness on camera with adjustable light."""
        return _settings.set_floodlight_brightness(
            self, serial, luminance, channelno, max_retries, _owner=_sys.modules[__name__]
        )

    def set_brightness(
        self, serial: str, luminance: int = 50, channelno: int = 1, max_retries: int = 0
    ) -> bool | str:
        """Facade that changes the brightness to light bulbs or cameras' light."""
        return _settings.set_brightness(
            self, serial, luminance, channelno, max_retries, _owner=_sys.modules[__name__]
        )

    def switch_light_status(
        self, serial: str, enable: int, channel_no: int = 0, max_retries: int = 0
    ) -> bool:
        """Facade that turns on/off light bulbs or cameras' light."""
        return _settings.switch_light_status(
            self, serial, enable, channel_no, max_retries, _owner=_sys.modules[__name__]
        )

    def detection_sensibility(
        self, serial: str, sensibility: int = 3, type_value: int = 3, max_retries: int = 0
    ) -> bool | str:
        """Set detection sensibility."""
        return _settings.detection_sensibility(
            self, serial, sensibility, type_value, max_retries, _owner=_sys.modules[__name__]
        )

    def get_motion_detect_sensitivity(
        self, serial: str, channel: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Get motion detection sensitivity via v1 devconfig endpoint."""
        return _settings.get_motion_detect_sensitivity(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_motion_detect_sensitivity_dp1s(
        self, serial: str, channel: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Get motion detection sensitivity for DP1S devices."""
        return _settings.get_motion_detect_sensitivity_dp1s(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_detection_sensitivity(
        self, serial: str, channel: int, sensitivity_type: int, value: int, max_retries: int = 0
    ) -> bool:
        """Set detection sensitivity via v3 devconfig endpoint."""
        return _settings.set_detection_sensitivity(
            self,
            serial,
            channel,
            sensitivity_type,
            value,
            max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_detection_sensibility(
        self, serial: str, type_value: str = "0", max_retries: int = 0
    ) -> Any:
        """Get detection sensibility notifications."""
        return _settings.get_detection_sensibility(
            self, serial, type_value, max_retries, _owner=_sys.modules[__name__]
        )

    def get_detector_setting_info(
        self, device_serial: str, detector_serial: str, key: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Fetch a specific configuration key for an A1S detector."""
        return _settings.get_detector_setting_info(
            self,
            device_serial,
            detector_serial,
            key,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_detector_setting_info(
        self,
        device_serial: str,
        detector_serial: str,
        key: str,
        value: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update a configuration key for an A1S detector."""
        return _settings.set_detector_setting_info(
            self,
            device_serial,
            detector_serial,
            key,
            value,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_detector_info(self, detector_serial: str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve status/details for an A1S detector."""
        return _settings.get_detector_info(
            self, detector_serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_radio_signals(
        self, device_serial: str, child_device_serial: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Return radio signal metrics for a detector connected to a device."""
        return _settings.get_radio_signals(
            self,
            device_serial,
            child_device_serial,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_voice_config(self, product_id: str, version: str, *, max_retries: int = 0) -> JsonDict:
        """Fetch voice configuration metadata for a product."""
        return _settings.get_voice_config(
            self, product_id, version, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    # soundtype: 0 = normal, 1 = intensive, 2 = disabled ... don't ask me why...
    def get_voice_info(
        self, serial: str, *, local_index: str | None = None, max_retries: int = 0
    ) -> JsonDict:
        """Retrieve uploaded custom voice prompts for a device."""
        return _settings.get_voice_info(
            self,
            serial,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def add_voice_info(
        self,
        serial: str,
        voice_name: str,
        voice_url: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Upload metadata for a new custom voice prompt."""
        return _settings.add_voice_info(
            self,
            serial,
            voice_name,
            voice_url,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def add_shared_voice_info(
        self,
        serial: str,
        voice_name: str,
        voice_url: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Upload a shared voice with explicit local index, mirroring the mobile API."""
        return _settings.add_shared_voice_info(
            self,
            serial,
            voice_name,
            voice_url,
            local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_name: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update metadata for an existing voice prompt."""
        return _settings.set_voice_info(
            self,
            serial,
            voice_id,
            voice_name,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_shared_voice_info(
        self, serial: str, voice_id: int, voice_name: str, local_index: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Alias for updating shared voices that ensures local index is supplied."""
        return _settings.set_shared_voice_info(
            self,
            serial,
            voice_id,
            voice_name,
            local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def delete_voice_info(
        self,
        serial: str,
        voice_id: int,
        *,
        voice_url: str | None = None,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Remove a voice prompt from a device."""
        return _settings.delete_voice_info(
            self,
            serial,
            voice_id,
            voice_url=voice_url,
            local_index=local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def delete_shared_voice_info(
        self, serial: str, voice_id: int, voice_url: str, local_index: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Alias for deleting shared voices with required parameters."""
        return _settings.delete_shared_voice_info(
            self,
            serial,
            voice_id,
            voice_url,
            local_index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_whistle_status_by_channel(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Return whistle configuration per channel for a device."""
        return _settings.get_whistle_status_by_channel(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_whistle_status_by_device(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Return whistle configuration at the device level."""
        return _settings.get_whistle_status_by_device(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_channel_whistle(
        self,
        serial: str,
        channel_whistles: list[Mapping[str, Any]] | list[dict[str, Any]],
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Configure whistle behaviour for individual channels."""
        return _settings.set_channel_whistle(
            self, serial, channel_whistles, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_device_whistle(
        self, serial: str, *, status: int, duration: int, volume: int, max_retries: int = 0
    ) -> JsonDict:
        """Configure whistle behaviour at the device level."""
        return _settings.set_device_whistle(
            self,
            serial,
            status=status,
            duration=duration,
            volume=volume,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def stop_whistle(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Stop any ongoing whistle sound."""
        return _settings.stop_whistle(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def delay_battery_device_sleep(
        self, serial: str, channel: int, sleep_type: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Request additional awake time for a battery-powered device."""
        return _settings.delay_battery_device_sleep(
            self,
            serial,
            channel,
            sleep_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_device_chime_info(self, serial: str, channel: int, *, max_retries: int = 0) -> JsonDict:
        """Fetch chime configuration for a specific channel."""
        return _settings.get_device_chime_info(
            self, serial, channel, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_device_chime_info(
        self, serial: str, channel: int, *, sound_type: int, duration: int, max_retries: int = 0
    ) -> JsonDict:
        """Update chime type and duration for a channel."""
        return _settings.set_device_chime_info(
            self,
            serial,
            channel,
            sound_type=sound_type,
            duration=duration,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_switch_enable_req(
        self, serial: str, channel: int, enable: int, switch_type: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Call the legacy setSwitchEnableReq endpoint."""
        return _settings.set_switch_enable_req(
            self,
            serial,
            channel,
            enable,
            switch_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_managed_device_info(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Return metadata for a managed device (e.g. base station)."""
        return _settings.get_managed_device_info(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_managed_device_ipcs(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """List IPC sub-devices that belong to a managed device."""
        return _settings.get_managed_device_ipcs(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_devices_status(self, serials: list[str] | str, *, max_retries: int = 0) -> JsonDict:
        """Fetch online/offline status for one or more devices."""
        return _settings.get_devices_status(
            self, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_device_secret_key_info(
        self, serials: list[str] | str, *, max_retries: int = 0
    ) -> JsonDict:
        """Retrieve KMS secret key metadata for devices."""
        return _settings.get_device_secret_key_info(
            self, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_device_list_encrypt_key(
        self,
        area_id: int,
        form_data: Mapping[str, Any] | bytes | bytearray | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Batch query encrypt keys for devices, matching the mobile client's risk API."""
        return _settings.get_device_list_encrypt_key(
            self, area_id, form_data, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_p2p_info(self, serials: list[str] | str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve P2P info via the device-scoped endpoint."""
        return _settings.get_p2p_info(
            self, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_p2p_server_info(self, serials: list[str] | str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve P2P server info via the userdevices endpoint."""
        return _settings.get_p2p_server_info(
            self, serials, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def register_p2p_session(
        self, *, session_id: str | None = None, max_retries: int = MAX_RETRIES
    ) -> JsonDict:
        """Authorize the current cloud session for EZVIZ LAN/P2P operations.

        Some devices reject CAS ``getDevOperationCode`` lookups until the app-style
        P2P registration endpoint has seen the current user ``sessionId``.
        """
        return _settings.register_p2p_session(
            self, session_id=session_id, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def check_device_upgrade_rule(self, *, max_retries: int = 0) -> JsonDict:
        """Check firmware upgrade eligibility rules."""
        return _settings.check_device_upgrade_rule(
            self, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_autoupgrade_switch(self, *, max_retries: int = 0) -> JsonDict:
        """Return the current auto-upgrade switch settings."""
        return _settings.get_autoupgrade_switch(
            self, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_autoupgrade_switch(
        self, auto_upgrade: int, time_type: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Update the auto-upgrade switch configuration."""
        return _settings.set_autoupgrade_switch(
            self, auto_upgrade, time_type, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_black_level_list(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Retrieve SD-card black level data for a device."""
        return _settings.get_black_level_list(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def get_time_plan_infos(
        self, serial: str, channel: int, timing_plan_type: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Fetch timing plan information for a device/channel."""
        return _settings.get_time_plan_infos(
            self,
            serial,
            channel,
            timing_plan_type,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def set_time_plan_infos(
        self,
        serial: str,
        channel: int,
        timing_plan_type: int,
        enable: int,
        timer_defence_qos: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update timing plan configuration."""
        return _settings.set_time_plan_infos(
            self,
            serial,
            channel,
            timing_plan_type,
            enable,
            timer_defence_qos,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def search_records(
        self,
        serial: str,
        channel: int,
        channel_serial: str,
        start_time: str,
        stop_time: str,
        *,
        size: int = 20,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search recorded video clips for a device."""
        return _recordings.search_records(
            self,
            serial,
            channel,
            channel_serial,
            start_time,
            stop_time,
            size=size,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def search_records_v2(
        self,
        serial: str,
        channel: int,
        start_time: str,
        stop_time: str,
        *,
        size: int = 20,
        sort_by: int = 0,
        require_label: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search SD-card playback records with the app's v2 record endpoint."""
        return _recordings.search_records_v2(
            self,
            serial,
            channel,
            start_time,
            stop_time,
            size=size,
            sort_by=sort_by,
            require_label=require_label,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def search_common_records(
        self,
        serial: str,
        channel: int,
        start_time: str,
        stop_time: str,
        *,
        channel_serial: str | None = None,
        record_type: int = 0,
        size: int = 20,
        version: int = 2,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search common SD-card playback records.

        This mirrors the EZVIZ app's ``PlaybackRecordApi.searchRecordV3`` path.
        """
        return _recordings.search_common_records(
            self,
            serial,
            channel,
            start_time,
            stop_time,
            channel_serial=channel_serial,
            record_type=record_type,
            size=size,
            version=version,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def search_intelligent_records(
        self,
        serial: str,
        channel: int,
        start_time: str,
        stop_time: str,
        *,
        version: int = 2,
        record_filter: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Search intelligent SD-card playback records."""
        return _recordings.search_intelligent_records(
            self,
            serial,
            channel,
            start_time,
            stop_time,
            version=version,
            record_filter=record_filter,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    @staticmethod
    def decode_records_payload(value: str) -> list[Any]:
        """Decode an EZVIZ base64+zlib JSON record-list payload."""
        return _recordings.decode_records_payload(value, _owner=_sys.modules[__name__])

    @classmethod
    def extract_record_list(cls, payload: Any) -> list[Any]:
        """Return the first plain or compressed record list in a response."""
        return _recordings.extract_record_list(cls, payload, _owner=_sys.modules[__name__])

    def get_cloud_videos(
        self,
        serial: str,
        channel: int,
        *,
        limit: int = 20,
        video_type: int = 2,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return cloud video descriptors for a device.

        The EZVIZ app uses this endpoint before native cloud download. Returned
        items may include ``streamUrl``, ``seqId``, ``storageVersion``,
        ``fileSize``, ``crypt``, and ``keyChecksum``.
        """
        return _recordings.get_cloud_videos(
            self,
            serial,
            channel,
            limit=limit,
            video_type=video_type,
            support_multi_channel_shared_service=support_multi_channel_shared_service,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_cloud_video_details(
        self,
        serial: str,
        channel: int,
        videos: Iterable[Mapping[str, Any]],
        *,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return detailed cloud video descriptors for selected videos."""
        return _recordings.get_cloud_video_details(
            self,
            serial,
            channel,
            videos,
            support_multi_channel_shared_service=support_multi_channel_shared_service,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_camera_ticket_info(
        self,
        serial: str,
        channel: int,
        *,
        support_multi_channel_shared_service: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return the camera playback ticket used by native cloud storage downloads.

        The official app feeds ``ticketInfo.ticket`` into
        ``DownloadCloudParam.szTicketToken`` for normal cloud-storage clips.
        """
        return _recordings.get_camera_ticket_info(
            self,
            serial,
            channel,
            support_multi_channel_shared_service=support_multi_channel_shared_service,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    @staticmethod
    def _extract_cloud_video_download_url(video: Mapping[str, Any]) -> str | None:
        """Return the first direct HTTP(S) video URL in a cloud video descriptor."""
        return _recordings._extract_cloud_video_download_url(video, _owner=_sys.modules[__name__])

    def download_cloud_video(self, video: Mapping[str, Any], *, max_retries: int = 0) -> bytes:
        """Download a cloud video when the descriptor contains a direct HTTP URL.

        Most EZVIZ cloud clip descriptors returned by ``/v3/clouds/videoDetails``
        expose a native SDK ``streamUrl`` host/port instead of a direct media URL.
        Those native stream descriptors cannot be downloaded through this helper.
        """
        return _recordings.download_cloud_video(
            self, video, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def search_device(
        self, serial: str, *, user_ssid: str | None = None, max_retries: int = 0
    ) -> JsonDict:
        """Find device information by serial."""
        return _recordings.search_device(
            self,
            serial,
            user_ssid=user_ssid,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def get_socket_log_info(
        self, serial: str, start: str, end: str, *, max_retries: int = 0
    ) -> JsonDict:
        """Fetch smart outlet switch logs within a time range."""
        return _recordings.get_socket_log_info(
            self, serial, start, end, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def linked_cameras(
        self, serial: str, detector_serial: str, *, max_retries: int = 0
    ) -> JsonDict:
        """List cameras linked to a detector device."""
        return _recordings.linked_cameras(
            self, serial, detector_serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def set_microscope(
        self, serial: str, multiple: float, x: int, y: int, index: int, *, max_retries: int = 0
    ) -> JsonDict:
        """Configure microscope lens parameters."""
        return _recordings.set_microscope(
            self,
            serial,
            multiple,
            x,
            y,
            index,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def share_accept(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Accept a device share invitation."""
        return _recordings.share_accept(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def share_quit(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Leave a shared device."""
        return _recordings.share_quit(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def send_feedback(
        self,
        *,
        email: str,
        account: str,
        score: int,
        feedback: str,
        pic_url: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Submit feedback to Ezviz support."""
        return _recordings.send_feedback(
            self,
            email=email,
            account=account,
            score=score,
            feedback=feedback,
            pic_url=pic_url,
            max_retries=max_retries,
            _owner=_sys.modules[__name__],
        )

    def upload_device_log(self, serial: str, *, max_retries: int = 0) -> JsonDict:
        """Trigger device log upload to Ezviz cloud."""
        return _recordings.upload_device_log(
            self, serial, max_retries=max_retries, _owner=_sys.modules[__name__]
        )

    def alarm_sound(
        self,
        serial: str,
        sound_type: int,
        enable: int = 1,
        voice_id: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable alarm sound by API."""
        return _recordings.alarm_sound(
            self, serial, sound_type, enable, voice_id, max_retries, _owner=_sys.modules[__name__]
        )

    def get_mqtt_client(
        self, on_message_callback: Callable[[dict[str, Any]], None] | None = None
    ) -> MQTTClient:
        """Return a push client sharing this client's session and token-save callback."""
        with request_budget_lock(self._token_lock):
            if self.mqtt_client is None:
                self.mqtt_client = MQTTClient(
                    token=cast(dict[Any, Any], self._token),
                    session=self._session,
                    timeout=self._timeout,
                    on_message_callback=on_message_callback,
                    on_token_updated=self._on_token_updated,
                    _token_lock=self._token_lock,
                )
            return self.mqtt_client

    def _get_page_list(self) -> Any:
        """Get ezviz device info broken down in sections."""
        return self._api_get_pagelist(
            page_filter="CLOUD, TIME_PLAN, CONNECTION, SWITCH,"
            "STATUS, WIFI, NODISTURB, KMS,"
            "P2P, CHANNEL, VTM, DETECTOR,"
            "FEATURE, CUSTOM_TAG, UPGRADE, VIDEO_QUALITY,"
            "QOS, PRODUCTS_INFO, SIM_CARD, MULTI_UPGRADE_EXT,"
            "FEATURE_INFO",
            json_key=None,
        )

    def get_page_list(self) -> Any:
        """Return the full pagelist payload without filtering."""

        return self._get_page_list()

    def export_token(self) -> dict[str, Any]:
        """Return an independent snapshot of the current authentication token."""

        with request_budget_lock(self._token_lock):
            return deepcopy(cast(dict[str, Any], self._token))

    def get_device(self) -> Any:
        """Get ezviz devices filter."""
        return self._api_get_pagelist(page_filter="CLOUD", json_key="deviceInfos")

    def get_connection(self) -> Any:
        """Get ezviz connection infos filter."""
        return self._api_get_pagelist(page_filter="CONNECTION", json_key="CONNECTION")

    def _get_status(self) -> Any:
        """Get ezviz status infos filter."""
        return self._api_get_pagelist(page_filter="STATUS", json_key="STATUS")

    def get_switch(self) -> Any:
        """Get ezviz switch infos filter."""
        return self._api_get_pagelist(page_filter="SWITCH", json_key="SWITCH")

    def _get_wifi(self) -> Any:
        """Get ezviz wifi infos filter."""
        return self._api_get_pagelist(page_filter="WIFI", json_key="WIFI")

    def _get_nodisturb(self) -> Any:
        """Get ezviz nodisturb infos filter."""
        return self._api_get_pagelist(page_filter="NODISTURB", json_key="NODISTURB")

    def _get_p2p(self) -> Any:
        """Get ezviz P2P infos filter."""
        return self._api_get_pagelist(page_filter="P2P", json_key="P2P")

    def _get_kms(self) -> Any:
        """Get ezviz KMS infos filter."""
        return self._api_get_pagelist(page_filter="KMS", json_key="KMS")

    def _get_time_plan(self) -> Any:
        """Get ezviz TIME_PLAN infos filter."""
        return self._api_get_pagelist(page_filter="TIME_PLAN", json_key="TIME_PLAN")

    def close_session(self) -> None:
        """Clear current session."""
        with request_budget_lock(self._token_lock):
            if self._session:
                self._session.close()

            self._session = requests.session()
            synchronize_http_headers(
                self._session.headers,
                profile_for_token(self._token),
                recreated_session_header_for_token(self._token),
                scope="profile",
            )
            if self.mqtt_client is not None:
                # This factory-owned client shares our replaceable HTTP session.
                self.mqtt_client._session = self._session


# Retained public wildcard exports, including imported support types.
__all__ = [
    "ANDROID_PROFILE",
    "API_ENDPOINT_2FA_VALIDATE_POST_AUTH",
    "API_ENDPOINT_ALARMINFO_GET",
    "API_ENDPOINT_ALARM_DEVICE_CHIME",
    "API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL",
    "API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE",
    "API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE",
    "API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE",
    "API_ENDPOINT_ALARM_SOUND",
    "API_ENDPOINT_ALARM_STOP_WHISTLE",
    "API_ENDPOINT_AUTOUPGRADE_SWITCH",
    "API_ENDPOINT_CALLING_NOTIFY",
    "API_ENDPOINT_CAMERA_TICKET_INFO",
    "API_ENDPOINT_CAM_AUTH_CODE",
    "API_ENDPOINT_CAM_ENCRYPTKEY",
    "API_ENDPOINT_CANCEL_ALARM",
    "API_ENDPOINT_CHANGE_DEFENCE_STATUS",
    "API_ENDPOINT_CLOUD_VIDEOS_LIST",
    "API_ENDPOINT_CLOUD_VIDEO_DETAILS",
    "API_ENDPOINT_CREATE_PANORAMIC",
    "API_ENDPOINT_DETECTION_SENSIBILITY",
    "API_ENDPOINT_DETECTION_SENSIBILITY_GET",
    "API_ENDPOINT_DEVCONFIG_BASE",
    "API_ENDPOINT_DEVCONFIG_BY_KEY",
    "API_ENDPOINT_DEVCONFIG_MOTOR",
    "API_ENDPOINT_DEVCONFIG_OP",
    "API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE",
    "API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE",
    "API_ENDPOINT_DEVICES",
    "API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC",
    "API_ENDPOINT_DEVICES_AUTHENTICATE",
    "API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH",
    "API_ENDPOINT_DEVICES_LOC",
    "API_ENDPOINT_DEVICES_P2P_INFO",
    "API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE",
    "API_ENDPOINT_DEVICE_ACCESSORY_LINK",
    "API_ENDPOINT_DEVICE_BASICS",
    "API_ENDPOINT_DEVICE_EMAIL_ALERT",
    "API_ENDPOINT_DEVICE_STORAGE_STATUS",
    "API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY",
    "API_ENDPOINT_DEVICE_SYS_OPERATION",
    "API_ENDPOINT_DEVICE_UPDATE_NAME",
    "API_ENDPOINT_DOORLOCK_USERS",
    "API_ENDPOINT_DO_NOT_DISTURB",
    "API_ENDPOINT_FEEDBACK",
    "API_ENDPOINT_GROUP_DEFENCE_MODE",
    "API_ENDPOINT_INTELLIGENT_APP",
    "API_ENDPOINT_IOT_ACTION",
    "API_ENDPOINT_IOT_FEATURE",
    "API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG",
    "API_ENDPOINT_IOT_VIRTUAL_BIND",
    "API_ENDPOINT_LOGIN",
    "API_ENDPOINT_LOGOUT",
    "API_ENDPOINT_MANAGED_DEVICE_BASE",
    "API_ENDPOINT_OFFLINE_NOTIFY",
    "API_ENDPOINT_OSD",
    "API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P",
    "API_ENDPOINT_PAGELIST",
    "API_ENDPOINT_PTZCONTROL",
    "API_ENDPOINT_REMOTE_LOCK",
    "API_ENDPOINT_REMOTE_UNBIND_PROGRESS",
    "API_ENDPOINT_REMOTE_UNLOCK",
    "API_ENDPOINT_RETURN_PANORAMIC",
    "API_ENDPOINT_SCD_APP_DEVICE_ADD",
    "API_ENDPOINT_SDCARD_BLACK_LEVEL",
    "API_ENDPOINT_SEND_CODE",
    "API_ENDPOINT_SENSITIVITY",
    "API_ENDPOINT_SERVER_INFO",
    "API_ENDPOINT_SET_DEFENCE_SCHEDULE",
    "API_ENDPOINT_SET_LUMINANCE",
    "API_ENDPOINT_SHARE_ACCEPT",
    "API_ENDPOINT_SHARE_QUIT",
    "API_ENDPOINT_SMARTHOME_OUTLET_LOG",
    "API_ENDPOINT_SPECIAL_BIZS_A1S",
    "API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY",
    "API_ENDPOINT_SPECIAL_BIZS_VOICES",
    "API_ENDPOINT_STREAMING_RECORDS",
    "API_ENDPOINT_STREAMING_RECORDS_COMMON",
    "API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT",
    "API_ENDPOINT_STREAMING_RECORDS_V2",
    "API_ENDPOINT_SWITCH_DEFENCE_MODE",
    "API_ENDPOINT_SWITCH_OTHER",
    "API_ENDPOINT_SWITCH_SOUND_ALARM",
    "API_ENDPOINT_SWITCH_STATUS",
    "API_ENDPOINT_TERMINAL_INFO",
    "API_ENDPOINT_TIME_PLAN_INFOS",
    "API_ENDPOINT_UNIFIEDMSG_LIST_GET",
    "API_ENDPOINT_UPGRADE_DEVICE",
    "API_ENDPOINT_UPGRADE_RULE",
    "API_ENDPOINT_USERDEVICES_KMS",
    "API_ENDPOINT_USERDEVICES_P2P_INFO",
    "API_ENDPOINT_USERDEVICES_SEARCH",
    "API_ENDPOINT_USERDEVICES_STATUS",
    "API_ENDPOINT_USERDEVICES_TOKEN",
    "API_ENDPOINT_USERDEVICES_V2",
    "API_ENDPOINT_USERS_LBS_SUB_DOMAIN",
    "API_ENDPOINT_USER_ID",
    "API_ENDPOINT_V3_ALARMS",
    "API_ENDPOINT_VIDEO_ENCRYPT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_UNIFIEDMSG_STYPE",
    "FEATURE_CODE",
    "HIK_ENCRYPTION_HEADER",
    "LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT",
    "MAX_RETRIES",
    "MAX_UNIFIEDMSG_PAGES",
    "PUSH_PROFILE",
    "UNIFIEDMSG_LOOKBACK_DAYS",
    "Any",
    "ApiOkResponse",
    "AutoClipSource",
    "AutoMediaStream",
    "BinaryIO",
    "Callable",
    "CamKeyResponse",
    "CaptureLimits",
    "ClassVar",
    "ClientToken",
    "ClipOptions",
    "ClipOutputFormat",
    "ClipSource",
    "ClipSourceOptions",
    "CloudClipSource",
    "CloudPlaybackClipSource",
    "DefenseModeType",
    "DeviceCatagories",
    "DeviceException",
    "DeviceSwitchType",
    "EzvizAuthTokenExpired",
    "EzvizAuthVerificationCode",
    "EzvizCAS",
    "EzvizClient",
    "EzvizDeviceRecord",
    "EzvizLocalSdkCredentials",
    "EzvizNoMediaError",
    "HTTPError",
    "HcNetSdkCommandPortClipSource",
    "HcNetSdkCommandPortGeneratedMultiSocketPlan",
    "HcNetSdkCommandPortMultiSocketPlan",
    "HcNetSdkLanEndpoint",
    "InvalidURL",
    "Iterable",
    "Iterator",
    "JsonDict",
    "Literal",
    "LocalSdkClipSource",
    "LocalSdkEcdhClipSource",
    "MQTTClient",
    "Mapping",
    "MediaDecodeOptions",
    "MediaMuxOptions",
    "MetaDict",
    "PagelistPageInfo",
    "PagelistResponse",
    "Path",
    "PyEzvizError",
    "RLock",
    "ResultCodeResponse",
    "SaveMediaResult",
    "SpooledTemporaryFile",
    "StorageStatusResponse",
    "SystemInfoResponse",
    "TypedDict",
    "UserIdResponse",
    "annotations",
    "base64",
    "bounded_request_timeout",
    "budgeted_http_call",
    "build_device_records_map",
    "cast",
    "collect_pagelist",
    "convert_to_dict",
    "copy_cloud_stream_to_mpegps",
    "copy_cloud_stream_to_mpegts",
    "copy_local_sdk_ecdh_stream_from_client",
    "copy_local_sdk_stream_from_client",
    "copy_local_stream_to_decrypted_mpegts",
    "copy_local_stream_to_mpegts",
    "current_session_header",
    "decrypt_image",
    "deepcopy",
    "device_factory",
    "dt",
    "fallback_stream_source",
    "h264_clean_idr_capture_budgets",
    "has_positive_finite_capture_bound",
    "hashlib",
    "hcnetsdk_command_port_native_lan_live_view_plan",
    "is_positive_capture_count_bound",
    "is_positive_finite_duration_bound",
    "json",
    "logging",
    "open_hcnetsdk_command_port_generated_multi_socket_stream",
    "open_hcnetsdk_command_port_multi_socket_stream",
    "open_hcnetsdk_command_port_stream",
    "optionals_mapping",
    "os",
    "profile_for_token",
    "recreated_session_header_for_token",
    "refresh_credentials",
    "replace",
    "request_budget_lock",
    "requests",
    "select_stream_source",
    "session_header_for_token",
    "shutil",
    "stat",
    "summarize_idmx_h264_local_packets",
    "synchronize_http_headers",
    "time",
    "urlencode",
    "urlsplit",
    "urlunsplit",
    "uuid4",
    "validate_feature_code",
    "zlib",
]

# Retained named compatibility exports; not additions to the wildcard API.
__compatibility_exports__ = {
    "_LegacyClipOptions": _LegacyClipOptions,
    "_hevc_parameter_options": _hevc_parameter_options,
    "_native_timing_options": _native_timing_options,
}
