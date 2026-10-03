"""Ezviz API."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import suppress
from copy import deepcopy
import datetime as dt
import errno
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from threading import RLock
import time
from typing import Any, BinaryIO, ClassVar, NamedTuple, TypedDict, cast
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import uuid4
import zlib

import requests

from . import device_factory
from ._auth import refresh_credentials
from ._longlink_profile import (
    current_session_header,
    profile_for_token,
    recreated_session_header_for_token,
    session_header_for_token,
    synchronize_http_headers,
)
from ._token import (
    ClientToken as ClientToken,  # noqa: PLC0414 - public type export
    validate_feature_code,
)
from .api_endpoints import (
    API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
    API_ENDPOINT_ALARM_DEVICE_CHIME,
    API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL,
    API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE,
    API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE,
    API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE,
    API_ENDPOINT_ALARM_SOUND,
    API_ENDPOINT_ALARM_STOP_WHISTLE,
    API_ENDPOINT_ALARMINFO_GET,
    API_ENDPOINT_AUTOUPGRADE_SWITCH,
    API_ENDPOINT_CALLING_NOTIFY,
    API_ENDPOINT_CAM_AUTH_CODE,
    API_ENDPOINT_CAM_ENCRYPTKEY,
    API_ENDPOINT_CAMERA_TICKET_INFO,
    API_ENDPOINT_CANCEL_ALARM,
    API_ENDPOINT_CHANGE_DEFENCE_STATUS,
    API_ENDPOINT_CLOUD_VIDEO_DETAILS,
    API_ENDPOINT_CLOUD_VIDEOS_LIST,
    API_ENDPOINT_CREATE_PANORAMIC,
    API_ENDPOINT_DETECTION_SENSIBILITY,
    API_ENDPOINT_DETECTION_SENSIBILITY_GET,
    API_ENDPOINT_DEVCONFIG_BASE,
    API_ENDPOINT_DEVCONFIG_BY_KEY,
    API_ENDPOINT_DEVCONFIG_MOTOR,
    API_ENDPOINT_DEVCONFIG_OP,
    API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE,
    API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE,
    API_ENDPOINT_DEVICE_ACCESSORY_LINK,
    API_ENDPOINT_DEVICE_BASICS,
    API_ENDPOINT_DEVICE_EMAIL_ALERT,
    API_ENDPOINT_DEVICE_STORAGE_STATUS,
    API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY,
    API_ENDPOINT_DEVICE_SYS_OPERATION,
    API_ENDPOINT_DEVICE_UPDATE_NAME,
    API_ENDPOINT_DEVICES,
    API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC,
    API_ENDPOINT_DEVICES_AUTHENTICATE,
    API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH,
    API_ENDPOINT_DEVICES_LOC,
    API_ENDPOINT_DEVICES_P2P_INFO,
    API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE,
    API_ENDPOINT_DO_NOT_DISTURB,
    API_ENDPOINT_DOORLOCK_USERS,
    API_ENDPOINT_FEEDBACK,
    API_ENDPOINT_GROUP_DEFENCE_MODE,
    API_ENDPOINT_INTELLIGENT_APP,
    API_ENDPOINT_IOT_ACTION,
    API_ENDPOINT_IOT_FEATURE,
    API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG,
    API_ENDPOINT_IOT_VIRTUAL_BIND,
    API_ENDPOINT_LOGIN,
    API_ENDPOINT_LOGOUT,
    API_ENDPOINT_MANAGED_DEVICE_BASE,
    API_ENDPOINT_OFFLINE_NOTIFY,
    API_ENDPOINT_OSD,
    API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P,
    API_ENDPOINT_PAGELIST,
    API_ENDPOINT_PTZCONTROL,
    API_ENDPOINT_REMOTE_LOCK,
    API_ENDPOINT_REMOTE_UNBIND_PROGRESS,
    API_ENDPOINT_REMOTE_UNLOCK,
    API_ENDPOINT_RETURN_PANORAMIC,
    API_ENDPOINT_SCD_APP_DEVICE_ADD,
    API_ENDPOINT_SDCARD_BLACK_LEVEL,
    API_ENDPOINT_SEND_CODE,
    API_ENDPOINT_SENSITIVITY,
    API_ENDPOINT_SERVER_INFO,
    API_ENDPOINT_SET_DEFENCE_SCHEDULE,
    API_ENDPOINT_SET_LUMINANCE,
    API_ENDPOINT_SHARE_ACCEPT,
    API_ENDPOINT_SHARE_QUIT,
    API_ENDPOINT_SMARTHOME_OUTLET_LOG,
    API_ENDPOINT_SPECIAL_BIZS_A1S,
    API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY,
    API_ENDPOINT_SPECIAL_BIZS_VOICES,
    API_ENDPOINT_STREAMING_RECORDS,
    API_ENDPOINT_STREAMING_RECORDS_COMMON,
    API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT,
    API_ENDPOINT_STREAMING_RECORDS_V2,
    API_ENDPOINT_SWITCH_DEFENCE_MODE,
    API_ENDPOINT_SWITCH_OTHER,
    API_ENDPOINT_SWITCH_SOUND_ALARM,
    API_ENDPOINT_SWITCH_STATUS,
    API_ENDPOINT_TERMINAL_INFO,
    API_ENDPOINT_TIME_PLAN_INFOS,
    API_ENDPOINT_UNIFIEDMSG_LIST_GET,
    API_ENDPOINT_UPGRADE_DEVICE,
    API_ENDPOINT_UPGRADE_RULE,
    API_ENDPOINT_USER_ID,
    API_ENDPOINT_USERDEVICES_KMS,
    API_ENDPOINT_USERDEVICES_P2P_INFO,
    API_ENDPOINT_USERDEVICES_SEARCH,
    API_ENDPOINT_USERDEVICES_STATUS,
    API_ENDPOINT_USERDEVICES_TOKEN,
    API_ENDPOINT_USERDEVICES_V2,
    API_ENDPOINT_USERS_LBS_SUB_DOMAIN,
    API_ENDPOINT_V3_ALARMS,
    API_ENDPOINT_VIDEO_ENCRYPT,
)
from .cas import EzvizCAS
from .clip import (
    ClipOptions,
    ClipOutputFormat,
    ClipSource,
    ClipSourceOptions,
    CloudClipSource,
    HcNetSdkCommandPortClipSource,
    LocalSdkClipSource,
    LocalSdkEcdhClipSource,
    _LegacyClipOptions,
)
from .cloud_stream import copy_cloud_stream_to_mpegps, copy_cloud_stream_to_mpegts
from .constants import (
    ANDROID_PROFILE,
    DEFAULT_TIMEOUT,
    DEFAULT_UNIFIEDMSG_STYPE,
    FEATURE_CODE,
    HIK_ENCRYPTION_HEADER,
    MAX_RETRIES,
    PROFILE as PUSH_PROFILE,
    DefenseModeType,
    DeviceCatagories,
    DeviceSwitchType,
)
from .exceptions import (
    DeviceException,
    EzvizAuthTokenExpired,
    EzvizAuthVerificationCode,
    HTTPError,
    InvalidURL,
    PyEzvizError,
)
from .feature import optionals_mapping
from .hcnetsdk import HcNetSdkLanEndpoint
from .local_stream_ecdh import (
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    copy_local_sdk_ecdh_stream_from_client,
)
from .local_stream_media import (
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegts,
    h264_clean_idr_capture_budgets,
    summarize_idmx_h264_local_packets,
)
from .local_stream_transport import (
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortMultiSocketPlan,
    copy_local_sdk_stream_from_client,
    open_hcnetsdk_command_port_generated_multi_socket_stream,
    open_hcnetsdk_command_port_multi_socket_stream,
    open_hcnetsdk_command_port_stream,
)
from .media import (
    CaptureLimits,
    MediaDecodeOptions,
    MediaMuxOptions,
    has_positive_finite_capture_bound,
    is_positive_capture_count_bound,
    is_positive_finite_duration_bound,
    is_positive_socket_timeout_bound,
)
from .models import EzvizDeviceRecord, build_device_records_map
from .mqtt import MQTTClient
from .utils import convert_to_dict, decrypt_image, deep_merge

_LOGGER = logging.getLogger(__name__)


class _SourceDefaultNaluHeaderSize(int):
    """Marker for the legacy source-specific NAL header default."""


_SOURCE_DEFAULT_NALU_HEADER_SIZE: int = _SourceDefaultNaluHeaderSize(0)
CLOUD_CLIP_VALIDATION_TIMEOUT_SECONDS = 5.0
CLOUD_CLIP_COPY_CHUNK_SIZE = 65536

UNIFIEDMSG_LOOKBACK_DAYS = 7
MAX_UNIFIEDMSG_PAGES = 6

JsonDict = dict[str, Any]


class SaveMediaResult(TypedDict, total=False):
    """Result returned by media save helpers."""

    ok: bool
    kind: str
    serial: str
    channel: int
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


def _require_decodable_saved_video_frame(
    path: Path,
    *,
    ffmpeg_path: str,
) -> None:
    """Require one decoded frame before reporting a saved clip as successful."""

    try:
        completed = subprocess.run(
            [
                ffmpeg_path,
                "-nostdin",
                "-v",
                "error",
                "-i",
                str(path),
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-vf",
                "scale=1:1",
                "-pix_fmt",
                "gray",
                "-f",
                "rawvideo",
                "pipe:1",
            ],
            capture_output=True,
            check=False,
            timeout=CLOUD_CLIP_VALIDATION_TIMEOUT_SECONDS,
        )
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err
    except subprocess.TimeoutExpired as err:
        raise PyEzvizError("Saved cloud clip video validation timed out") from err
    if completed.returncode != 0 or not completed.stdout:
        raise PyEzvizError("Saved cloud clip did not include a decodable video frame")


def _require_saved_mpegps_video_payload(path: Path) -> None:
    """Require structurally plausible clear video in an MPEG-PS capture.

    MPEG-PS capture and decryption are implemented in Python and must not gain
    an undeclared FFmpeg dependency merely for post-capture validation.  This
    check is deliberately structural; callers that need decoder-level proof
    can request MPEG-TS, whose remux path already requires FFmpeg.
    """

    nals = _annexb_nals(_mpegps_video_payload(path.read_bytes()))
    if _has_linked_h264_video(nals) or _has_linked_hevc_video(nals):
        return
    raise PyEzvizError("Saved cloud MPEG-PS clip did not include clear video payload")


def _mpegps_video_payload(data: bytes) -> bytes:  # noqa: PLR0911, PLR0912
    """Return concatenated MPEG-PS video PES payload bytes."""

    video_payload = bytearray()
    offset = 0
    while offset + 4 <= len(data):
        packet_start = data.find(b"\x00\x00\x01", offset)
        if packet_start < 0 or packet_start + 4 > len(data):
            break
        stream_id = data[packet_start + 3]
        if stream_id == 0xB9:  # program_end_code
            offset = packet_start + 4
            continue
        if stream_id == 0xBA:  # pack_start_code has no PES length field
            if packet_start + 14 > len(data):
                return b""
            offset = packet_start + 14 + (data[packet_start + 13] & 0x07)
            if offset > len(data):
                return b""
            continue
        if packet_start + 6 > len(data):
            return b""
        packet_length = int.from_bytes(data[packet_start + 4 : packet_start + 6], "big")
        if not packet_length and not 0xE0 <= stream_id <= 0xEF:
            return b""
        if packet_length:
            packet_end = packet_start + 6 + packet_length
        else:
            packet_end = len(data)
            next_start = data.find(b"\x00\x00\x01", packet_start + 9)
            while next_start >= 0 and next_start + 4 <= len(data):
                if data[next_start + 3] >= 0xB9:
                    packet_end = next_start
                    break
                next_start = data.find(b"\x00\x00\x01", next_start + 4)
        if packet_end > len(data):
            return b""
        if not 0xE0 <= stream_id <= 0xEF:
            offset = packet_end
            continue
        if packet_start + 9 > packet_end:
            return b""
        payload_start = packet_start + 9 + data[packet_start + 8]
        if payload_start > packet_end:
            return b""
        if payload_start < packet_end:
            video_payload.extend(data[payload_start:packet_end])
        offset = packet_end
    return bytes(video_payload)


def _annexb_nals(payload: bytes) -> list[tuple[bytes, bytes]]:
    """Return Annex-B NAL headers and bodies from one elementary stream."""

    nals: list[tuple[bytes, bytes]] = []
    start = 0
    while True:
        start_code = payload.find(b"\x00\x00\x01", start)
        if start_code < 0 or start_code + 3 >= len(payload):
            return nals
        header_start = start_code + 3
        next_start = payload.find(b"\x00\x00\x01", header_start + 1)
        nal_end = len(payload) if next_start < 0 else next_start
        nals.append((
            payload[header_start : header_start + 2],
            payload[header_start + 1 : nal_end].rstrip(b"\x00"),
        ))
        start = header_start


class _H264SpsInfo(NamedTuple):
    """SPS fields needed to parse a linked H.264 slice header."""

    sps_id: int
    chroma_format_idc: int
    separate_colour_plane: bool
    log2_max_frame_num: int
    pic_order_cnt_type: int
    log2_max_pic_order_cnt_lsb: int
    delta_pic_order_always_zero: bool
    frame_mbs_only: bool
    pic_width_in_mbs: int = 1
    pic_height_in_map_units: int = 1
    mb_adaptive_frame_field: bool = False


class _H264PpsInfo(NamedTuple):
    """PPS fields needed to parse a linked H.264 slice header."""

    pps_id: int
    sps_id: int
    entropy_coding_mode: bool
    bottom_field_pic_order_in_frame_present: bool
    num_ref_idx_l0_default_active_minus1: int
    num_ref_idx_l1_default_active_minus1: int
    weighted_pred: bool
    weighted_bipred_idc: int
    deblocking_filter_control_present: bool
    redundant_pic_cnt_present: bool
    slice_group_map_type: int = 0
    slice_group_change_rate: int = 0
    slice_group_count: int = 1
    slice_group_map: tuple[int, ...] = ()
    slice_group_change_direction: bool = False


class _HevcSpsInfo(NamedTuple):
    """SPS fields needed to parse a linked HEVC slice header."""

    vps_id: int
    log2_max_pic_order_cnt_lsb: int
    short_term_delta_poc_counts: tuple[int, ...]
    long_term_ref_pics_present: bool
    long_term_ref_pics_sps: int
    temporal_mvp_enabled: bool
    sample_adaptive_offset_enabled: bool
    chroma_format_idc: int
    separate_colour_plane: bool
    qp_bd_offset_y: int = 0


class _HevcPpsInfo(NamedTuple):
    """PPS fields needed to parse a linked HEVC slice header."""

    sps_id: int
    dependent_slices_enabled: bool
    output_flag_present: bool
    extra_slice_header_bits: int
    slice_chroma_qp_offsets_present: bool
    chroma_qp_offset_list_enabled: bool
    deblocking_filter_override_enabled: bool
    pps_deblocking_filter_disabled: bool
    loop_filter_across_slices_enabled: bool
    tiles_enabled: bool
    entropy_coding_sync_enabled: bool
    slice_header_extension_present: bool


def _has_linked_h264_video(nals: list[tuple[bytes, bytes]]) -> bool:
    """Return whether H.264 parameter sets link to a plausible slice."""

    h264_sps: dict[int, _H264SpsInfo] = {}
    h264_pps: dict[int, _H264PpsInfo] = {}
    pps_nals: list[bytes] = []
    slices: list[tuple[int, bytes]] = []
    for header_bytes, nal_body in nals:
        header = header_bytes[0]
        h264_type = header & 0x1F
        if header & 0x80:
            continue
        if h264_type == 7:
            sps_info = _h264_sps_info(nal_body)
            if sps_info is not None:
                h264_sps[sps_info.sps_id] = sps_info
        elif h264_type == 8:
            pps_nals.append(nal_body)
        elif h264_type in {1, 2, 5}:
            slices.append((header, nal_body))
    for nal_body in pps_nals:
        pps_info = _h264_pps_info(nal_body, sps_info=h264_sps)
        if pps_info is not None:
            h264_pps[pps_info.pps_id] = pps_info
    return any(
        _h264_slice_pps_id(
            nal_body,
            nal_header=header,
            sps_info=h264_sps,
            pps_info=h264_pps,
        )
        is not None
        for header, nal_body in slices
    )


def _has_linked_hevc_video(nals: list[tuple[bytes, bytes]]) -> bool:
    """Return whether HEVC parameter sets accompany a plausible slice."""

    vps_ids: set[int] = set()
    sps_info: dict[int, _HevcSpsInfo] = {}
    pps_info: dict[int, _HevcPpsInfo] = {}
    pps_nals: list[bytes] = []
    slices: list[tuple[bytes, int]] = []
    slice_pps_ids: set[int] = set()
    for header, body in nals:
        if len(header) < 2 or header[0] & 0x80 or not (header[1] & 0x07):
            continue
        nal_type = (header[0] >> 1) & 0x3F
        nal_body = body[1:]
        if nal_type == 32:
            vps_id = _hevc_vps_id(nal_body)
            if vps_id is not None:
                vps_ids.add(vps_id)
        elif nal_type == 33:
            sps_ids = _hevc_sps_ids(nal_body)
            if sps_ids is not None:
                sps_info[sps_ids[0]] = sps_ids[1]
        elif nal_type == 34:
            pps_nals.append(nal_body)
        elif nal_type <= 9 or 16 <= nal_type <= 21:
            slices.append((nal_body, nal_type))
    for nal_body in pps_nals:
        pps_ids = _hevc_pps_ids(nal_body, sps_info=sps_info)
        if pps_ids is not None:
            pps_info[pps_ids[0]] = pps_ids[1]
    for nal_body, nal_type in slices:
        pps_id = _hevc_slice_pps_id(
            nal_body,
            nal_type=nal_type,
            sps_info=sps_info,
            pps_info=pps_info,
        )
        if pps_id is not None:
            slice_pps_ids.add(pps_id)
    return any(
        pps_id in pps_info
        and pps_info[pps_id].sps_id in sps_info
        and sps_info[pps_info[pps_id].sps_id].vps_id in vps_ids
        for pps_id in slice_pps_ids
    )


def _rbsp_bits(data: bytes) -> str | None:
    """Return RBSP bits, rejecting malformed emulation-prevention sequences."""

    rbsp = bytearray()
    zero_count = 0
    for index, value in enumerate(data):
        if zero_count >= 2 and value < 0x03:
            return None
        if zero_count >= 2 and value == 0x03:
            if index + 1 >= len(data) or data[index + 1] > 0x03:
                return None
            zero_count = 0
            continue
        rbsp.append(value)
        zero_count = zero_count + 1 if value == 0 else 0
    return "".join(f"{value:08b}" for value in rbsp)


def _read_unsigned_exp_golomb(bits: str, offset: int) -> tuple[int, int] | None:
    """Read one unsigned Exp-Golomb value from ``bits``."""

    leading_zeros = 0
    while offset + leading_zeros < len(bits) and bits[offset + leading_zeros] == "0":
        leading_zeros += 1
    marker = offset + leading_zeros
    value_end = marker + leading_zeros + 1
    if marker >= len(bits) or value_end > len(bits):
        return None
    suffix = bits[marker + 1 : value_end]
    value = (1 << leading_zeros) - 1 + (int(suffix, 2) if suffix else 0)
    return value, value_end


def _read_signed_exp_golomb(bits: str, offset: int) -> tuple[int, int] | None:
    """Read one signed Exp-Golomb value from ``bits``."""

    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None:
        return None
    code_num, next_offset = decoded
    value = (code_num + 1) // 2
    return (-value if code_num % 2 == 0 else value), next_offset


def _skip_h264_scaling_list(bits: str, offset: int, size: int) -> int | None:
    """Return the bit offset after one H.264 scaling list."""

    last_scale = 8
    next_scale = 8
    for _ in range(size):
        if next_scale != 0:
            decoded = _read_signed_exp_golomb(bits, offset)
            if decoded is None:
                return None
            delta_scale, offset = decoded
            next_scale = (last_scale + delta_scale + 256) % 256
        last_scale = next_scale or last_scale
    return offset


def _skip_h264_hrd_parameters(bits: str, offset: int) -> int | None:
    """Return the bit offset after H.264 HRD syntax."""

    cpb_count = _read_unsigned_exp_golomb(bits, offset)
    if cpb_count is None or cpb_count[0] > 31:
        return None
    offset = cpb_count[1] + 8  # bit_rate_scale and cpb_size_scale
    if offset > len(bits):
        return None
    for _ in range(cpb_count[0] + 1):
        for _ in range(2):
            value = _read_unsigned_exp_golomb(bits, offset)
            if value is None:
                return None
            offset = value[1]
        offset += 1  # cbr_flag
    offset += 20  # four five-bit delay/offset length fields
    return offset if offset <= len(bits) else None


def _skip_h264_vui_parameters(  # noqa: PLR0911, PLR0912, PLR0915
    bits: str,
    offset: int,
) -> int | None:
    """Return the bit offset after mandatory H.264 VUI syntax."""

    if offset >= len(bits):
        return None
    aspect_ratio_present = bits[offset] == "1"
    offset += 1
    if aspect_ratio_present:
        if offset + 8 > len(bits):
            return None
        aspect_ratio_idc = int(bits[offset : offset + 8], 2)
        offset += 8
        if aspect_ratio_idc == 255:
            offset += 32
    if offset >= len(bits):
        return None
    overscan_present = bits[offset] == "1"
    offset += 1
    if overscan_present:
        offset += 1
    if offset >= len(bits):
        return None
    video_signal_present = bits[offset] == "1"
    offset += 1
    if video_signal_present:
        if offset + 5 > len(bits):
            return None
        colour_description = bits[offset + 4] == "1"
        offset += 5
        if colour_description:
            offset += 24
    if offset >= len(bits):
        return None
    chroma_location_present = bits[offset] == "1"
    offset += 1
    if chroma_location_present:
        for _ in range(2):
            location = _read_unsigned_exp_golomb(bits, offset)
            if location is None:
                return None
            offset = location[1]
    if offset >= len(bits):
        return None
    timing_info_present = bits[offset] == "1"
    offset += 1
    if timing_info_present:
        offset += 65  # num_units_in_tick, time_scale, fixed_frame_rate_flag
    if offset >= len(bits):
        return None
    nal_hrd_present = bits[offset] == "1"
    offset += 1
    if nal_hrd_present:
        hrd_offset = _skip_h264_hrd_parameters(bits, offset)
        if hrd_offset is None:
            return None
        offset = hrd_offset
    if offset >= len(bits):
        return None
    vcl_hrd_present = bits[offset] == "1"
    offset += 1
    if vcl_hrd_present:
        hrd_offset = _skip_h264_hrd_parameters(bits, offset)
        if hrd_offset is None:
            return None
        offset = hrd_offset
    if nal_hrd_present or vcl_hrd_present:
        offset += 1  # low_delay_hrd_flag
    offset += 1  # pic_struct_present_flag
    if offset >= len(bits):
        return None
    bitstream_restriction = bits[offset] == "1"
    offset += 1
    if bitstream_restriction:
        offset += 1  # motion_vectors_over_pic_boundaries_flag
        for _ in range(6):
            restriction = _read_unsigned_exp_golomb(bits, offset)
            if restriction is None:
                return None
            offset = restriction[1]
    return offset if offset <= len(bits) else None


def _h264_sps_info(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
) -> _H264SpsInfo | None:
    """Return fields needed to validate slices after parsing an H.264 SPS."""

    if len(data) < 4 or data[0] not in {44, 66, 77, 83, 86, 88, 100, 110, 118, 122, 128, 134, 135, 138, 139, 244}:
        return None
    if data[1] & 0x03 or data[2] == 0:
        return None
    bits = _rbsp_bits(data[3:])
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    decoded = _read_unsigned_exp_golomb(bits, 0)
    if decoded is None or decoded[0] > 31:
        return None
    sps_id, offset = decoded
    chroma_format_idc = 1
    separate_colour_plane = False
    if data[0] in {44, 83, 86, 100, 110, 118, 122, 128, 134, 135, 138, 139, 244}:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 3:
            return None
        chroma_format_idc, offset = decoded
        if chroma_format_idc == 3:
            if offset >= len(bits):
                return None
            separate_colour_plane = bits[offset] == "1"
            offset += 1
        for _ in range(2):
            decoded = _read_unsigned_exp_golomb(bits, offset)
            if decoded is None or decoded[0] > 6:
                return None
            offset = decoded[1]
        offset += 1
        if offset >= len(bits):
            return None
        scaling_matrix_present = bits[offset] == "1"
        offset += 1
        if scaling_matrix_present:
            for index in range(12 if chroma_format_idc == 3 else 8):
                if offset >= len(bits):
                    return None
                scaling_list_present = bits[offset] == "1"
                offset += 1
                if scaling_list_present:
                    skipped = _skip_h264_scaling_list(
                        bits,
                        offset,
                        16 if index < 6 else 64,
                    )
                    if skipped is None:
                        return None
                    offset = skipped
    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] > 12:
        return None
    log2_max_frame_num = decoded[0] + 4
    offset = decoded[1]
    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] > 2:
        return None
    pic_order_cnt_type, offset = decoded
    log2_max_pic_order_cnt_lsb = 0
    delta_pic_order_always_zero = False
    if pic_order_cnt_type == 0:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 12:
            return None
        log2_max_pic_order_cnt_lsb = decoded[0] + 4
        offset = decoded[1]
    elif pic_order_cnt_type == 1:
        if offset >= len(bits):
            return None
        delta_pic_order_always_zero = bits[offset] == "1"
        offset += 1
        for _ in range(2):
            decoded_signed = _read_signed_exp_golomb(bits, offset)
            if decoded_signed is None:
                return None
            offset = decoded_signed[1]
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 255:
            return None
        cycle_count, offset = decoded
        for _ in range(cycle_count):
            decoded_signed = _read_signed_exp_golomb(bits, offset)
            if decoded_signed is None:
                return None
            offset = decoded_signed[1]
    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None:
        return None
    offset = decoded[1] + 1
    dimensions: list[int] = []
    for _ in range(2):
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 65535:
            return None
        dimensions.append(decoded[0] + 1)
        offset = decoded[1]
    if offset >= len(bits):
        return None
    frame_mbs_only = bits[offset] == "1"
    offset += 1
    mb_adaptive_frame_field = False
    if not frame_mbs_only:
        if offset >= len(bits):
            return None
        mb_adaptive_frame_field = bits[offset] == "1"
        offset += 1
    offset += 1
    if offset >= len(bits):
        return None
    frame_cropping = bits[offset] == "1"
    offset += 1
    if frame_cropping:
        for _ in range(4):
            decoded = _read_unsigned_exp_golomb(bits, offset)
            if decoded is None:
                return None
            offset = decoded[1]
    if offset >= len(bits):
        return None
    vui_present = bits[offset] == "1"
    offset += 1
    if vui_present:
        vui_offset = _skip_h264_vui_parameters(bits, offset)
        if vui_offset is None:
            return None
        offset = vui_offset
    if offset != len(bits):
        return None
    return _H264SpsInfo(
        sps_id=sps_id,
        chroma_format_idc=chroma_format_idc,
        separate_colour_plane=separate_colour_plane,
        log2_max_frame_num=log2_max_frame_num,
        pic_order_cnt_type=pic_order_cnt_type,
        log2_max_pic_order_cnt_lsb=log2_max_pic_order_cnt_lsb,
        delta_pic_order_always_zero=delta_pic_order_always_zero,
        frame_mbs_only=frame_mbs_only,
        pic_width_in_mbs=dimensions[0],
        pic_height_in_map_units=dimensions[1],
        mb_adaptive_frame_field=mb_adaptive_frame_field,
    )


def _skip_h264_slice_groups(  # noqa: PLR0911, PLR0912, PLR0915
    bits: str,
    offset: int,
    group_count: int,
    sps: _H264SpsInfo,
) -> tuple[int, int, int, tuple[int, ...], bool] | None:
    """Skip a PPS flexible-macroblock-order map and retain slice controls."""

    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] > 6:
        return None
    map_type, offset = decoded
    pic_size = sps.pic_width_in_mbs * sps.pic_height_in_map_units
    if pic_size > 1_000_000:
        return None
    change_rate = 0
    change_direction = False
    groups = [group_count - 1] * pic_size
    if map_type == 0:
        runs: list[int] = []
        for _ in range(group_count):
            decoded = _read_unsigned_exp_golomb(bits, offset)
            if decoded is None or decoded[0] >= pic_size:
                return None
            runs.append(decoded[0] + 1)
            offset = decoded[1]
        position = 0
        while position < pic_size:
            for group, run in enumerate(runs):
                end = min(position + run, pic_size)
                groups[position:end] = [group] * (end - position)
                position = end
    elif map_type == 1:
        width = sps.pic_width_in_mbs
        # H.264 dispersed map uses (num_slice_groups_minus1 + 1) in both terms.
        groups = [
            (index % width + ((index // width) * group_count) // 2) % group_count
            for index in range(pic_size)
        ]
    elif map_type == 2:
        rectangles: list[tuple[int, int]] = []
        width = sps.pic_width_in_mbs
        for _ in range(group_count - 1):
            top_left = _read_unsigned_exp_golomb(bits, offset)
            if top_left is None or top_left[0] >= pic_size:
                return None
            bottom_right = _read_unsigned_exp_golomb(bits, top_left[1])
            if (
                bottom_right is None
                or not top_left[0] <= bottom_right[0] < pic_size
                or top_left[0] % width > bottom_right[0] % width
            ):
                return None
            rectangles.append((top_left[0], bottom_right[0]))
            offset = bottom_right[1]
        for group in range(group_count - 2, -1, -1):
            top_addr, bottom_addr = rectangles[group]
            for row in range(top_addr // width, bottom_addr // width + 1):
                left, right = top_addr % width, bottom_addr % width
                groups[row * width + left : row * width + right + 1] = [group] * (
                    right - left + 1
                )
    elif map_type in {3, 4, 5}:
        if group_count != 2 or offset >= len(bits):
            return None
        change_direction = bits[offset] == "1"
        rate = _read_unsigned_exp_golomb(bits, offset + 1)
        if rate is None or rate[0] >= pic_size:
            return None
        change_rate = rate[0] + 1
        offset = rate[1]
        groups = []  # Dynamic map depends on slice_group_change_cycle.
    elif map_type == 6:
        declared_size = _read_unsigned_exp_golomb(bits, offset)
        if declared_size is None or declared_size[0] + 1 != pic_size:
            return None
        offset = declared_size[1]
        group_bits = (group_count - 1).bit_length()
        if offset + pic_size * group_bits > len(bits):
            return None
        for index in range(pic_size):
            group = int(bits[offset : offset + group_bits], 2)
            if group >= group_count:
                return None
            groups[index] = group
            offset += group_bits
    return offset, map_type, change_rate, tuple(groups), change_direction


def _h264_slice_group_map(  # noqa: PLR0912
    pps: _H264PpsInfo,
    sps: _H264SpsInfo,
    change_cycle: int,
) -> tuple[int, ...]:
    """Build a dynamic H.264 FMO map for slice-group types 3, 4 and 5."""

    if pps.slice_group_map:
        return pps.slice_group_map
    width, height = sps.pic_width_in_mbs, sps.pic_height_in_map_units
    pic_size = width * height
    group_zero_size = min(change_cycle * pps.slice_group_change_rate, pic_size)
    direction = int(pps.slice_group_change_direction)
    if pps.slice_group_map_type == 3:
        groups = [1] * pic_size
        x, y = (width - direction) // 2, (height - direction) // 2
        left = right = x
        top = bottom = y
        x_dir, y_dir = direction - 1, direction
        assigned = 0
        steps = 0
        while assigned < group_zero_size and steps < 8 * pic_size + 8:
            steps += 1
            position = y * width + x
            if groups[position] == 1:
                groups[position] = 0
                assigned += 1
            if x_dir == -1 and x == left:
                left = max(left - 1, 0)
                x, x_dir, y_dir = left, 0, 2 * direction - 1
            elif x_dir == 1 and x == right:
                right = min(right + 1, width - 1)
                x, x_dir, y_dir = right, 0, 1 - 2 * direction
            elif y_dir == -1 and y == top:
                top = max(top - 1, 0)
                y, x_dir, y_dir = top, 1 - 2 * direction, 0
            elif y_dir == 1 and y == bottom:
                bottom = min(bottom + 1, height - 1)
                y, x_dir, y_dir = bottom, 2 * direction - 1, 0
            else:
                x += x_dir
                y += y_dir
        return tuple(groups) if assigned == group_zero_size else ()
    upper_left_size = pic_size - group_zero_size if direction else group_zero_size
    groups = [1 - direction] * pic_size
    order: Iterable[int]
    if pps.slice_group_map_type == 4:
        order = range(pic_size)
    else:
        order = (row * width + col for col in range(width) for row in range(height))
    for index, position in enumerate(order):
        if index < upper_left_size:
            groups[position] = direction
    return tuple(groups)


def _h264_pps_info(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
    *,
    sps_info: Mapping[int, _H264SpsInfo],
) -> _H264PpsInfo | None:
    """Return fields needed to validate slices after parsing an H.264 PPS."""

    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    pps = _read_unsigned_exp_golomb(bits, 0)
    if pps is None or pps[0] > 255:
        return None
    sps = _read_unsigned_exp_golomb(bits, pps[1])
    if sps is None or sps[0] > 31:
        return None
    offset = sps[1]
    if offset + 2 > len(bits):
        return None
    entropy_coding_mode = bits[offset] == "1"
    bottom_field_pic_order_in_frame_present = bits[offset + 1] == "1"
    offset += 2
    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] > 7:
        return None
    slice_group_count = decoded[0] + 1
    offset = decoded[1]
    slice_group_map_type = 0
    slice_group_change_rate = 0
    slice_group_map: tuple[int, ...] = ()
    slice_group_change_direction = False
    if slice_group_count > 1:
        linked_sps = sps_info.get(sps[0])
        if linked_sps is None:
            return None
        group_syntax = _skip_h264_slice_groups(
            bits, offset, slice_group_count, linked_sps
        )
        if group_syntax is None:
            return None
        (
            offset, slice_group_map_type, slice_group_change_rate,
            slice_group_map, slice_group_change_direction,
        ) = group_syntax
    default_ref_counts: list[int] = []
    for _ in range(2):
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 31:
            return None
        default_ref_counts.append(decoded[0])
        offset = decoded[1]
    if offset + 3 > len(bits):
        return None
    weighted_pred = bits[offset] == "1"
    weighted_bipred_idc = int(bits[offset + 1 : offset + 3], 2)
    offset += 3
    for _ in range(3):
        decoded_signed = _read_signed_exp_golomb(bits, offset)
        if decoded_signed is None:
            return None
        offset = decoded_signed[1]
    if offset + 3 > len(bits):
        return None
    deblocking_filter_control_present = bits[offset] == "1"
    redundant_pic_cnt_present = bits[offset + 2] == "1"
    offset += 3
    if offset < len(bits):
        if offset + 2 > len(bits):
            return None
        transform_8x8_mode = bits[offset] == "1"
        scaling_matrix_present = bits[offset + 1] == "1"
        offset += 2
        if scaling_matrix_present:
            linked_sps = sps_info.get(sps[0])
            if linked_sps is None:
                return None
            scaling_list_count = 6
            if transform_8x8_mode:
                scaling_list_count += 6 if linked_sps.chroma_format_idc == 3 else 2
            for index in range(scaling_list_count):
                if offset >= len(bits):
                    return None
                scaling_list_present = bits[offset] == "1"
                offset += 1
                if scaling_list_present:
                    skipped = _skip_h264_scaling_list(
                        bits,
                        offset,
                        16 if index < 6 else 64,
                    )
                    if skipped is None:
                        return None
                    offset = skipped
        second_chroma_qp = _read_signed_exp_golomb(bits, offset)
        if second_chroma_qp is None:
            return None
        offset = second_chroma_qp[1]
    if offset != len(bits):
        return None
    return _H264PpsInfo(
        pps_id=pps[0],
        sps_id=sps[0],
        entropy_coding_mode=entropy_coding_mode,
        bottom_field_pic_order_in_frame_present=(
            bottom_field_pic_order_in_frame_present
        ),
        num_ref_idx_l0_default_active_minus1=default_ref_counts[0],
        num_ref_idx_l1_default_active_minus1=default_ref_counts[1],
        weighted_pred=weighted_pred,
        weighted_bipred_idc=weighted_bipred_idc,
        deblocking_filter_control_present=deblocking_filter_control_present,
        redundant_pic_cnt_present=redundant_pic_cnt_present,
        slice_group_map_type=slice_group_map_type,
        slice_group_change_rate=slice_group_change_rate,
        slice_group_count=slice_group_count,
        slice_group_map=slice_group_map,
        slice_group_change_direction=slice_group_change_direction,
    )


def _skip_h264_ref_pic_list_modification(
    bits: str,
    offset: int,
) -> int | None:
    """Skip one H.264 reference-picture-list modification sequence."""

    if offset >= len(bits):
        return None
    if bits[offset] == "0":
        return offset + 1
    offset += 1
    while True:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 3:
            return None
        modification, offset = decoded
        if modification == 3:
            return offset
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None:
            return None
        offset = decoded[1]


def _skip_h264_pred_weight_table(  # noqa: PLR0911, PLR0912
    bits: str,
    offset: int,
    *,
    chroma_format_idc: int,
    ref_counts: tuple[int, ...],
) -> int | None:
    """Skip an H.264 prediction weight table."""

    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] > 7:
        return None
    offset = decoded[1]
    chroma_present = chroma_format_idc != 0
    if chroma_present:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 7:
            return None
        offset = decoded[1]
    for ref_count in ref_counts:
        for _ in range(ref_count + 1):
            if offset >= len(bits):
                return None
            luma_weight_present = bits[offset] == "1"
            offset += 1
            if luma_weight_present:
                for _ in range(2):
                    decoded_signed = _read_signed_exp_golomb(bits, offset)
                    if decoded_signed is None:
                        return None
                    offset = decoded_signed[1]
            if chroma_present:
                if offset >= len(bits):
                    return None
                chroma_weight_present = bits[offset] == "1"
                offset += 1
                if chroma_weight_present:
                    for _ in range(4):
                        decoded_signed = _read_signed_exp_golomb(bits, offset)
                        if decoded_signed is None:
                            return None
                        offset = decoded_signed[1]
    return offset


def _skip_h264_dec_ref_pic_marking(
    bits: str,
    offset: int,
    *,
    idr: bool,
) -> int | None:
    """Skip mandatory H.264 decoded-reference-picture marking syntax."""

    if idr:
        return offset + 2 if offset + 2 <= len(bits) else None
    if offset >= len(bits):
        return None
    if bits[offset] == "0":
        return offset + 1
    offset += 1
    while True:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 6:
            return None
        operation, offset = decoded
        if operation == 0:
            return offset
        operand_count = {1: 1, 2: 1, 3: 2, 4: 1, 5: 0, 6: 1}[operation]
        for _ in range(operand_count):
            decoded = _read_unsigned_exp_golomb(bits, offset)
            if decoded is None:
                return None
            offset = decoded[1]


def _h264_slice_pps_id(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
    *,
    nal_header: int,
    sps_info: Mapping[int, _H264SpsInfo],
    pps_info: Mapping[int, _H264PpsInfo],
) -> int | None:
    """Return the PPS id after parsing a linked mandatory H.264 slice header."""

    if len(data) < 2:
        return None
    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    offset = 0
    values: list[int] = []
    for _ in range(3):
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None:
            return None
        value, offset = decoded
        values.append(value)
    first_mb, slice_type, pic_parameter_set_id = values
    if first_mb > 65535 or slice_type > 9 or pic_parameter_set_id > 255:
        return None
    pps = pps_info.get(pic_parameter_set_id)
    if pps is None:
        return None
    sps = sps_info.get(pps.sps_id)
    if sps is None:
        return None
    if sps.separate_colour_plane:
        offset += 2
    if offset + sps.log2_max_frame_num > len(bits):
        return None
    offset += sps.log2_max_frame_num
    field_pic = False
    if not sps.frame_mbs_only:
        if offset >= len(bits):
            return None
        field_pic = bits[offset] == "1"
        offset += 1
        if field_pic:
            if offset >= len(bits):
                return None
            offset += 1
    mbaff_frame = sps.mb_adaptive_frame_field and not field_pic
    pic_size_in_mbs = sps.pic_width_in_mbs * sps.pic_height_in_map_units
    if not sps.frame_mbs_only and not field_pic:
        pic_size_in_mbs *= 2
    # MBAFF first_mb_in_slice addresses macroblock pairs, not single blocks.
    first_mb_addr = first_mb * (2 if mbaff_frame else 1)
    if first_mb_addr >= pic_size_in_mbs:
        return None
    nal_type = nal_header & 0x1F
    if nal_type == 5:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None:
            return None
        offset = decoded[1]
    if sps.pic_order_cnt_type == 0:
        if offset + sps.log2_max_pic_order_cnt_lsb > len(bits):
            return None
        offset += sps.log2_max_pic_order_cnt_lsb
        if pps.bottom_field_pic_order_in_frame_present and not field_pic:
            decoded_signed = _read_signed_exp_golomb(bits, offset)
            if decoded_signed is None:
                return None
            offset = decoded_signed[1]
    elif sps.pic_order_cnt_type == 1 and not sps.delta_pic_order_always_zero:
        decoded_signed = _read_signed_exp_golomb(bits, offset)
        if decoded_signed is None:
            return None
        offset = decoded_signed[1]
        if pps.bottom_field_pic_order_in_frame_present and not field_pic:
            decoded_signed = _read_signed_exp_golomb(bits, offset)
            if decoded_signed is None:
                return None
            offset = decoded_signed[1]
    if pps.redundant_pic_cnt_present:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None:
            return None
        offset = decoded[1]
    normalized_slice_type = slice_type % 5
    if normalized_slice_type == 1:
        offset += 1
    ref_counts = [pps.num_ref_idx_l0_default_active_minus1]
    if normalized_slice_type == 1:
        ref_counts.append(pps.num_ref_idx_l1_default_active_minus1)
    if normalized_slice_type in {0, 1, 3}:
        if offset >= len(bits):
            return None
        if bits[offset] == "1":
            offset += 1
            decoded = _read_unsigned_exp_golomb(bits, offset)
            if decoded is None or decoded[0] > 31:
                return None
            ref_counts[0], offset = decoded
            if normalized_slice_type == 1:
                decoded = _read_unsigned_exp_golomb(bits, offset)
                if decoded is None or decoded[0] > 31:
                    return None
                ref_counts[1], offset = decoded
        else:
            offset += 1
        modification_offset = _skip_h264_ref_pic_list_modification(bits, offset)
        if modification_offset is None:
            return None
        offset = modification_offset
        if normalized_slice_type == 1:
            modification_offset = _skip_h264_ref_pic_list_modification(bits, offset)
            if modification_offset is None:
                return None
            offset = modification_offset
    weighted = (
        pps.weighted_pred and normalized_slice_type in {0, 3}
    ) or (pps.weighted_bipred_idc == 1 and normalized_slice_type == 1)
    if weighted:
        weighted_offset = _skip_h264_pred_weight_table(
            bits,
            offset,
            chroma_format_idc=(
                0 if sps.separate_colour_plane else sps.chroma_format_idc
            ),
            ref_counts=tuple(ref_counts),
        )
        if weighted_offset is None:
            return None
        offset = weighted_offset
    if nal_header & 0x60:
        marking_offset = _skip_h264_dec_ref_pic_marking(
            bits,
            offset,
            idr=nal_type == 5,
        )
        if marking_offset is None:
            return None
        offset = marking_offset
    if pps.entropy_coding_mode and normalized_slice_type not in {2, 4}:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 2:
            return None
        offset = decoded[1]
    decoded_signed = _read_signed_exp_golomb(bits, offset)
    if decoded_signed is None:
        return None
    offset = decoded_signed[1]
    if normalized_slice_type in {3, 4}:
        if normalized_slice_type == 3:
            offset += 1
        decoded_signed = _read_signed_exp_golomb(bits, offset)
        if decoded_signed is None:
            return None
        offset = decoded_signed[1]
    if pps.deblocking_filter_control_present:
        decoded = _read_unsigned_exp_golomb(bits, offset)
        if decoded is None or decoded[0] > 2:
            return None
        disable_deblocking_filter_idc, offset = decoded
        if disable_deblocking_filter_idc != 1:
            for _ in range(2):
                decoded_signed = _read_signed_exp_golomb(bits, offset)
                if decoded_signed is None:
                    return None
                offset = decoded_signed[1]
    change_cycle = 0
    if pps.slice_group_change_rate:
        pic_size_in_map_units = sps.pic_width_in_mbs * sps.pic_height_in_map_units
        max_cycle = (
            (pic_size_in_map_units + pps.slice_group_change_rate - 1)
            // pps.slice_group_change_rate
        )
        cycle_bits = max_cycle.bit_length()
        if offset + cycle_bits > len(bits):
            return None
        change_cycle = int(bits[offset : offset + cycle_bits], 2)
        if change_cycle > max_cycle:
            return None
        offset += cycle_bits
    if nal_type == 2:
        slice_id = _read_unsigned_exp_golomb(bits, offset)
        if slice_id is None or slice_id[0] > 65535:
            return None
        offset = slice_id[1]
    if pps.entropy_coding_mode:
        while offset % 8:
            if offset >= len(bits) or bits[offset] != "1":
                return None
            offset += 1
        return pic_parameter_set_id if offset < len(bits) else None
    if normalized_slice_type in {0, 1, 3}:
        skip_run = _read_unsigned_exp_golomb(bits, offset)
        if skip_run is None or skip_run[0] > pic_size_in_mbs - first_mb_addr:
            return None
        if pps.slice_group_count > 1 and skip_run[0]:
            groups = _h264_slice_group_map(pps, sps, change_cycle)
            if not groups:
                return None
            width = sps.pic_width_in_mbs

            def map_index(mb_addr: int) -> int:
                if sps.frame_mbs_only or field_pic:
                    return mb_addr
                if mbaff_frame:
                    return mb_addr // 2
                return (mb_addr // (2 * width)) * width + mb_addr % width

            selected_group = groups[map_index(first_mb_addr)]
            remaining_in_group = sum(
                groups[map_index(addr)] == selected_group
                for addr in range(first_mb_addr, pic_size_in_mbs)
            )
            if skip_run[0] > remaining_in_group:
                return None
        if skip_run[0]:
            return pic_parameter_set_id
        offset = skip_run[1]
    if mbaff_frame:
        if offset >= len(bits):
            return None
        offset += 1  # mb_field_decoding_flag for the first macroblock pair
    first_cavlc_element = _read_unsigned_exp_golomb(bits, offset)
    max_mb_type = {0: 30, 1: 48, 2: 25, 3: 30, 4: 26}[normalized_slice_type]
    if first_cavlc_element is None or first_cavlc_element[0] > max_mb_type:
        return None
    return pic_parameter_set_id


def _hevc_vps_id(data: bytes) -> int | None:  # noqa: PLR0911, PLR0912, PLR0915
    """Return a VPS id after parsing its mandatory syntax prefix."""

    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 32:
        return None
    syntax = bits[:trailing_one]
    if len(syntax) < 32 or syntax[16:32] != "1" * 16:
        return None
    max_sub_layers_minus1 = int(syntax[12:15], 2)
    if max_sub_layers_minus1 > 6:
        return None
    offset = _skip_hevc_profile_tier_level(syntax, 32, max_sub_layers_minus1)
    if offset is None or offset >= len(syntax):
        return None
    ordering_info_present = syntax[offset] == "1"
    offset += 1
    start_layer = 0 if ordering_info_present else max_sub_layers_minus1
    for _ in range(start_layer, max_sub_layers_minus1 + 1):
        for _ in range(3):
            decoded = _read_unsigned_exp_golomb(syntax, offset)
            if decoded is None:
                return None
            offset = decoded[1]
    if offset + 6 > len(syntax):
        return None
    max_layer_id = int(syntax[offset : offset + 6], 2)
    offset += 6  # vps_max_layer_id
    layer_sets = _read_unsigned_exp_golomb(syntax, offset)
    if layer_sets is None or layer_sets[0] > 1023:
        return None
    layer_set_count, offset = layer_sets
    layer_flags = layer_set_count * (max_layer_id + 1)
    if offset + layer_flags >= len(syntax):
        return None
    offset += layer_flags
    timing_info_present = syntax[offset] == "1"
    offset += 1
    if timing_info_present:
        if offset + 65 > len(syntax):
            return None
        offset += 64  # vps_num_units_in_tick and vps_time_scale
        if syntax[offset] == "1":
            ticks = _read_unsigned_exp_golomb(syntax, offset + 1)
            if ticks is None:
                return None
            offset = ticks[1]
        else:
            offset += 1
        hrd_count = _read_unsigned_exp_golomb(syntax, offset)
        if hrd_count is None or hrd_count[0] > 1024:
            return None
        offset = hrd_count[1]
        hrd_flags = (False, False, False)
        for hrd_index in range(hrd_count[0]):
            layer_set_idx = _read_unsigned_exp_golomb(syntax, offset)
            if layer_set_idx is None or layer_set_idx[0] > layer_set_count:
                return None
            offset = layer_set_idx[1]
            common_info_present = True
            if hrd_index:
                if offset >= len(syntax):
                    return None
                common_info_present = syntax[offset] == "1"
                offset += 1
            hrd_result = _skip_hevc_hrd_parameters(
                syntax,
                offset,
                max_sub_layers_minus1=max_sub_layers_minus1,
                common_info_present=common_info_present,
                inherited_flags=hrd_flags,
            )
            if hrd_result is None:
                return None
            offset, hrd_flags = hrd_result
    if offset >= len(syntax):
        return None
    extension_present = syntax[offset] == "1"
    offset += 1
    if extension_present:
        offset = len(syntax)  # vps_extension_data_flag occupies the remainder
    return int(syntax[:4], 2) if offset == len(syntax) else None


def _skip_hevc_hrd_parameters(  # noqa: PLR0911, PLR0912
    bits: str,
    offset: int,
    *,
    max_sub_layers_minus1: int,
    common_info_present: bool,
    inherited_flags: tuple[bool, bool, bool],
) -> tuple[int, tuple[bool, bool, bool]] | None:
    """Return the bit offset after HEVC hrd_parameters syntax."""

    nal_hrd_present, vcl_hrd_present, sub_pic_present = inherited_flags
    if common_info_present:
        if offset + 2 > len(bits):
            return None
        nal_hrd_present = bits[offset] == "1"
        vcl_hrd_present = bits[offset + 1] == "1"
        offset += 2
        if nal_hrd_present or vcl_hrd_present:
            if offset >= len(bits):
                return None
            sub_pic_present = bits[offset] == "1"
            offset += 1
            if sub_pic_present:
                offset += 19
            offset += 8
            if sub_pic_present:
                offset += 4
            offset += 15
            if offset > len(bits):
                return None
    for _ in range(max_sub_layers_minus1 + 1):
        if offset >= len(bits):
            return None
        fixed_rate_general = bits[offset] == "1"
        offset += 1
        fixed_rate_within_cvs = True
        if not fixed_rate_general:
            if offset >= len(bits):
                return None
            fixed_rate_within_cvs = bits[offset] == "1"
            offset += 1
        low_delay = False
        if fixed_rate_within_cvs:
            duration = _read_unsigned_exp_golomb(bits, offset)
            if duration is None:
                return None
            offset = duration[1]
        else:
            if offset >= len(bits):
                return None
            low_delay = bits[offset] == "1"
            offset += 1
        cpb_count = 0
        if not low_delay:
            cpb = _read_unsigned_exp_golomb(bits, offset)
            if cpb is None or cpb[0] > 31:
                return None
            cpb_count, offset = cpb
        for present in (nal_hrd_present, vcl_hrd_present):
            if not present:
                continue
            sub_layer_offset = _skip_hevc_sub_layer_hrd(
                bits,
                offset,
                cpb_count=cpb_count,
                sub_pic_present=sub_pic_present,
            )
            if sub_layer_offset is None:
                return None
            offset = sub_layer_offset
    return offset, (nal_hrd_present, vcl_hrd_present, sub_pic_present)


def _skip_hevc_sub_layer_hrd(
    bits: str,
    offset: int,
    *,
    cpb_count: int,
    sub_pic_present: bool,
) -> int | None:
    """Return the bit offset after one HEVC sub_layer_hrd_parameters block."""

    for _ in range(cpb_count + 1):
        value_count = 4 if sub_pic_present else 2
        for _ in range(value_count):
            value = _read_unsigned_exp_golomb(bits, offset)
            if value is None:
                return None
            offset = value[1]
        if offset >= len(bits):
            return None
        offset += 1  # cbr_flag
    return offset


def _skip_hevc_profile_tier_level(
    bits: str,
    offset: int,
    max_sub_layers_minus1: int,
) -> int | None:
    """Return the bit offset after HEVC profile_tier_level syntax."""

    if offset + 96 > len(bits):
        return None
    offset += 96
    sub_layer_flags: list[tuple[str, str]] = []
    for _ in range(max_sub_layers_minus1):
        if offset + 2 > len(bits):
            return None
        sub_layer_flags.append((bits[offset], bits[offset + 1]))
        offset += 2
    if max_sub_layers_minus1:
        offset += 2 * (8 - max_sub_layers_minus1)
    for profile_present, level_present in sub_layer_flags:
        if profile_present == "1":
            offset += 88
        if level_present == "1":
            offset += 8
        if offset > len(bits):
            return None
    return offset


def _skip_hevc_scaling_list_data(
    bits: str,
    offset: int,
) -> int | None:
    """Return the bit offset after HEVC scaling_list_data syntax."""

    for size_id in range(4):
        matrix_step = 3 if size_id == 3 else 1
        for _matrix_id in range(0, 6, matrix_step):
            if offset >= len(bits):
                return None
            pred_mode = bits[offset] == "1"
            offset += 1
            if not pred_mode:
                delta = _read_unsigned_exp_golomb(bits, offset)
                if delta is None:
                    return None
                offset = delta[1]
                continue
            if size_id > 1:
                dc_coefficient = _read_signed_exp_golomb(bits, offset)
                if dc_coefficient is None:
                    return None
                offset = dc_coefficient[1]
            coefficient_count = min(64, 1 << (4 + (size_id << 1)))
            for _ in range(coefficient_count):
                coefficient = _read_signed_exp_golomb(bits, offset)
                if coefficient is None:
                    return None
                offset = coefficient[1]
    return offset


def _skip_hevc_pps_range_extension(  # noqa: PLR0911
    bits: str,
    offset: int,
    *,
    transform_skip_enabled: bool,
) -> tuple[int, bool] | None:
    """Return the offset and chroma-list flag after PPS range-extension syntax."""

    if transform_skip_enabled:
        transform_size = _read_unsigned_exp_golomb(bits, offset)
        if transform_size is None:
            return None
        offset = transform_size[1]
    if offset + 2 > len(bits):
        return None
    offset += 1  # cross_component_prediction_enabled_flag
    chroma_qp_offset_list_enabled = bits[offset] == "1"
    offset += 1
    if chroma_qp_offset_list_enabled:
        depth = _read_unsigned_exp_golomb(bits, offset)
        if depth is None:
            return None
        list_length = _read_unsigned_exp_golomb(bits, depth[1])
        if list_length is None or list_length[0] > 5:
            return None
        offset = list_length[1]
        for _ in range(list_length[0] + 1):
            for _ in range(2):
                chroma_offset = _read_signed_exp_golomb(bits, offset)
                if chroma_offset is None:
                    return None
                offset = chroma_offset[1]
    for _ in range(2):
        sao_scale = _read_unsigned_exp_golomb(bits, offset)
        if sao_scale is None:
            return None
        offset = sao_scale[1]
    return offset, chroma_qp_offset_list_enabled


def _skip_hevc_short_term_ref_pic_set(  # noqa: PLR0911, PLR0912
    bits: str,
    offset: int,
    *,
    set_index: int,
    delta_poc_counts: list[int],
    slice_context: bool = False,
) -> tuple[int, int] | None:
    """Return the offset and delta-POC count after one SPS short-term RPS."""

    inter_predicted = False
    if set_index:
        if offset >= len(bits):
            return None
        inter_predicted = bits[offset] == "1"
        offset += 1
    if inter_predicted:
        reference_index = set_index - 1
        if slice_context:
            delta_index = _read_unsigned_exp_golomb(bits, offset)
            if delta_index is None or delta_index[0] >= set_index:
                return None
            reference_index = set_index - (delta_index[0] + 1)
            offset = delta_index[1]
        if offset >= len(bits):
            return None
        offset += 1  # delta_rps_sign
        abs_delta = _read_unsigned_exp_golomb(bits, offset)
        if abs_delta is None:
            return None
        offset = abs_delta[1]
        delta_poc_count = 0
        for _ in range(delta_poc_counts[reference_index] + 1):
            if offset >= len(bits):
                return None
            used = bits[offset] == "1"
            offset += 1
            use_delta = False
            if not used:
                if offset >= len(bits):
                    return None
                use_delta = bits[offset] == "1"
                offset += 1
            if used or use_delta:
                delta_poc_count += 1
        return offset, delta_poc_count
    negative = _read_unsigned_exp_golomb(bits, offset)
    if negative is None or negative[0] > 64:
        return None
    positive = _read_unsigned_exp_golomb(bits, negative[1])
    if positive is None or positive[0] > 64:
        return None
    offset = positive[1]
    for _ in range(negative[0] + positive[0]):
        delta = _read_unsigned_exp_golomb(bits, offset)
        if delta is None or delta[1] >= len(bits):
            return None
        offset = delta[1] + 1  # used_by_curr_pic_s*_flag
    return offset, negative[0] + positive[0]


def _skip_hevc_vui_parameters(  # noqa: PLR0911, PLR0912, PLR0915
    bits: str,
    offset: int,
    *,
    max_sub_layers_minus1: int,
) -> int | None:
    """Return the bit offset after mandatory HEVC VUI syntax."""

    if offset >= len(bits):
        return None
    if bits[offset] == "1":
        if offset + 9 > len(bits):
            return None
        aspect_ratio_idc = int(bits[offset + 1 : offset + 9], 2)
        offset += 9
        if aspect_ratio_idc == 255:
            offset += 32
    else:
        offset += 1
    if offset >= len(bits):
        return None
    overscan_present = bits[offset] == "1"
    offset += 1
    if overscan_present:
        offset += 1
    if offset >= len(bits):
        return None
    video_signal_present = bits[offset] == "1"
    offset += 1
    if video_signal_present:
        if offset + 5 > len(bits):
            return None
        colour_description = bits[offset + 4] == "1"
        offset += 5
        if colour_description:
            offset += 24
    if offset >= len(bits):
        return None
    chroma_location_present = bits[offset] == "1"
    offset += 1
    if chroma_location_present:
        for _ in range(2):
            location = _read_unsigned_exp_golomb(bits, offset)
            if location is None:
                return None
            offset = location[1]
    offset += 3  # neutral_chroma_indication, field_seq, frame_field_info
    if offset >= len(bits):
        return None
    default_display_window = bits[offset] == "1"
    offset += 1
    if default_display_window:
        for _ in range(4):
            window = _read_unsigned_exp_golomb(bits, offset)
            if window is None:
                return None
            offset = window[1]
    if offset >= len(bits):
        return None
    timing_info_present = bits[offset] == "1"
    offset += 1
    if timing_info_present:
        if offset + 65 > len(bits):
            return None
        offset += 64
        if bits[offset] == "1":
            ticks = _read_unsigned_exp_golomb(bits, offset + 1)
            if ticks is None:
                return None
            offset = ticks[1]
        else:
            offset += 1
        if offset >= len(bits):
            return None
        hrd_present = bits[offset] == "1"
        offset += 1
        if hrd_present:
            hrd = _skip_hevc_hrd_parameters(
                bits,
                offset,
                max_sub_layers_minus1=max_sub_layers_minus1,
                common_info_present=True,
                inherited_flags=(False, False, False),
            )
            if hrd is None:
                return None
            offset = hrd[0]
    if offset >= len(bits):
        return None
    bitstream_restriction = bits[offset] == "1"
    offset += 1
    if bitstream_restriction:
        offset += 3
        for _ in range(5):
            value = _read_unsigned_exp_golomb(bits, offset)
            if value is None:
                return None
            offset = value[1]
    return offset if offset <= len(bits) else None


def _hevc_sps_ids(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
) -> tuple[int, _HevcSpsInfo] | None:
    """Return linked IDs and POC width after parsing mandatory SPS fields."""

    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    if len(bits) < 104:
        return None
    vps_id = int(bits[:4], 2)
    max_sub_layers_minus1 = int(bits[4:7], 2)
    if max_sub_layers_minus1 > 6 or (
        max_sub_layers_minus1 == 0 and bits[7] != "1"
    ):
        return None
    offset = _skip_hevc_profile_tier_level(bits, 8, max_sub_layers_minus1)
    if offset is None:
        return None
    sps = _read_unsigned_exp_golomb(bits, offset)
    if sps is None or sps[0] > 15:
        return None
    offset = sps[1]
    chroma_format = _read_unsigned_exp_golomb(bits, offset)
    if chroma_format is None or chroma_format[0] > 3:
        return None
    offset = chroma_format[1]
    separate_colour_plane = False
    if chroma_format[0] == 3:
        if offset >= len(bits):
            return None
        separate_colour_plane = bits[offset] == "1"
        offset += 1
    for _ in range(2):
        dimension = _read_unsigned_exp_golomb(bits, offset)
        if dimension is None or dimension[0] <= 0:
            return None
        offset = dimension[1]
    if offset >= len(bits):
        return None
    if bits[offset] == "1":
        offset += 1
        for _ in range(4):
            window_offset = _read_unsigned_exp_golomb(bits, offset)
            if window_offset is None:
                return None
            offset = window_offset[1]
    else:
        offset += 1
    values: list[int] = []
    for maximum in (8, 8, 12):
        value = _read_unsigned_exp_golomb(bits, offset)
        if value is None or value[0] > maximum:
            return None
        values.append(value[0])
        offset = value[1]
    if offset >= len(bits):
        return None
    ordering_info_present = bits[offset] == "1"
    offset += 1
    start_layer = 0 if ordering_info_present else max_sub_layers_minus1
    for _ in range(start_layer, max_sub_layers_minus1 + 1):
        for maximum in (16, 16, 16):
            ordering = _read_unsigned_exp_golomb(bits, offset)
            if ordering is None or ordering[0] > maximum:
                return None
            offset = ordering[1]
    for maximum in (3, 6, 3, 6, 5, 5):
        block_value = _read_unsigned_exp_golomb(bits, offset)
        if block_value is None or block_value[0] > maximum:
            return None
        offset = block_value[1]
    if offset >= len(bits):
        return None
    scaling_list_enabled = bits[offset] == "1"
    offset += 1
    if scaling_list_enabled:
        if offset >= len(bits):
            return None
        scaling_list_present = bits[offset] == "1"
        offset += 1
        if scaling_list_present:
            scaling_list_offset = _skip_hevc_scaling_list_data(bits, offset)
            if scaling_list_offset is None:
                return None
            offset = scaling_list_offset
    if offset + 3 > len(bits):
        return None
    offset += 1  # amp_enabled_flag
    sample_adaptive_offset_enabled = bits[offset] == "1"
    offset += 1
    pcm_enabled = bits[offset] == "1"
    offset += 1
    if pcm_enabled:
        if offset + 8 > len(bits):
            return None
        offset += 8
        for _ in range(2):
            pcm_block = _read_unsigned_exp_golomb(bits, offset)
            if pcm_block is None:
                return None
            offset = pcm_block[1]
        offset += 1
    short_term_sets = _read_unsigned_exp_golomb(bits, offset)
    if short_term_sets is None or short_term_sets[0] > 64:
        return None
    short_term_count, offset = short_term_sets
    delta_poc_counts: list[int] = []
    for set_index in range(short_term_count):
        short_term_set = _skip_hevc_short_term_ref_pic_set(
            bits,
            offset,
            set_index=set_index,
            delta_poc_counts=delta_poc_counts,
        )
        if short_term_set is None:
            return None
        offset, delta_poc_count = short_term_set
        delta_poc_counts.append(delta_poc_count)
    if offset >= len(bits):
        return None
    long_term_present = bits[offset] == "1"
    offset += 1
    long_term_ref_pics_sps = 0
    if long_term_present:
        long_term_count = _read_unsigned_exp_golomb(bits, offset)
        if long_term_count is None or long_term_count[0] > 32:
            return None
        long_term_ref_pics_sps = long_term_count[0]
        offset = long_term_count[1]
        long_term_bits = long_term_count[0] * (values[2] + 5)
        if offset + long_term_bits > len(bits):
            return None
        offset += long_term_bits
    if offset + 3 > len(bits):
        return None
    temporal_mvp_enabled = bits[offset] == "1"
    offset += 2  # temporal MVP and strong intra smoothing flags
    vui_present = bits[offset] == "1"
    offset += 1
    if vui_present:
        vui_offset = _skip_hevc_vui_parameters(
            bits,
            offset,
            max_sub_layers_minus1=max_sub_layers_minus1,
        )
        if vui_offset is None:
            return None
        offset = vui_offset
    if offset >= len(bits):
        return None
    extension_present = bits[offset] == "1"
    offset += 1
    if extension_present:
        if offset + 8 > len(bits):
            return None
        extension_flags = bits[offset : offset + 8]
        offset += 8
        range_extension = extension_flags[0] == "1"
        unsupported_declared_extension = "1" in extension_flags[1:4]
        if unsupported_declared_extension:
            return None
        if range_extension:
            if offset + 9 > len(bits):
                return None
            offset += 9
        if "1" in extension_flags[4:]:
            # sps_extension_data_flag occupies all remaining RBSP data.
            offset = len(bits)
    if offset != len(bits):
        return None
    return (
        sps[0],
        _HevcSpsInfo(
            vps_id=vps_id,
            log2_max_pic_order_cnt_lsb=values[2] + 4,
            short_term_delta_poc_counts=tuple(delta_poc_counts),
            long_term_ref_pics_present=long_term_present,
            long_term_ref_pics_sps=long_term_ref_pics_sps,
            temporal_mvp_enabled=temporal_mvp_enabled,
            sample_adaptive_offset_enabled=sample_adaptive_offset_enabled,
            chroma_format_idc=chroma_format[0],
            separate_colour_plane=separate_colour_plane,
            qp_bd_offset_y=6 * values[0],
        ),
    )


def _hevc_pps_ids(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
    *,
    sps_info: Mapping[int, _HevcSpsInfo],
) -> tuple[int, _HevcPpsInfo] | None:
    """Return linked IDs and slice controls after mandatory PPS fields."""

    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    pps = _read_unsigned_exp_golomb(bits, 0)
    if pps is None or pps[0] > 63:
        return None
    sps = _read_unsigned_exp_golomb(bits, pps[1])
    if sps is None or sps[0] > 15 or sps[1] + 7 > len(bits):
        return None
    linked_sps = sps_info.get(sps[0])
    if linked_sps is None:
        return None
    offset = sps[1]
    dependent_slices = bits[offset] == "1"
    output_flag_present = bits[offset + 1] == "1"
    extra_slice_header_bits = int(bits[offset + 2 : offset + 5], 2)
    offset += 7  # includes sign_data_hiding and cabac_init_present
    for _ in range(2):
        ref_count = _read_unsigned_exp_golomb(bits, offset)
        if ref_count is None or ref_count[0] > 14:
            return None
        offset = ref_count[1]
    init_qp = _read_signed_exp_golomb(bits, offset)
    if init_qp is None or not -(26 + linked_sps.qp_bd_offset_y) <= init_qp[0] <= 25:
        return None
    offset = init_qp[1]
    if offset + 3 > len(bits):
        return None
    transform_skip_enabled = bits[offset + 1] == "1"
    cu_qp_delta_enabled = bits[offset + 2] == "1"
    offset += 3
    if cu_qp_delta_enabled:
        depth = _read_unsigned_exp_golomb(bits, offset)
        if depth is None:
            return None
        offset = depth[1]
    for _ in range(2):
        chroma_offset = _read_signed_exp_golomb(bits, offset)
        if chroma_offset is None:
            return None
        offset = chroma_offset[1]
    if offset + 6 > len(bits):
        return None
    slice_chroma_qp_offsets_present = bits[offset] == "1"
    offset += 3  # slice chroma offsets, weighted prediction, weighted biprediction
    offset += 1  # transquant_bypass_enabled_flag
    tiles_enabled = bits[offset] == "1"
    entropy_coding_sync_enabled = bits[offset + 1] == "1"
    offset += 2
    if tiles_enabled:
        tile_columns = _read_unsigned_exp_golomb(bits, offset)
        if tile_columns is None or tile_columns[0] > 19:
            return None
        tile_rows = _read_unsigned_exp_golomb(bits, tile_columns[1])
        if tile_rows is None or tile_rows[0] > 21:
            return None
        offset = tile_rows[1]
        if offset >= len(bits):
            return None
        uniform_spacing = bits[offset] == "1"
        offset += 1
        if not uniform_spacing:
            for _ in range(tile_columns[0] + tile_rows[0]):
                tile_size = _read_unsigned_exp_golomb(bits, offset)
                if tile_size is None:
                    return None
                offset = tile_size[1]
        offset += 1  # loop_filter_across_tiles_enabled_flag
    if offset + 2 > len(bits):
        return None
    loop_filter_across_slices_enabled = bits[offset] == "1"
    offset += 1
    deblocking_filter_control_present = bits[offset] == "1"
    offset += 1
    deblocking_filter_override_enabled = False
    pps_deblocking_filter_disabled = False
    if deblocking_filter_control_present:
        if offset + 2 > len(bits):
            return None
        deblocking_filter_override_enabled = bits[offset] == "1"
        offset += 1
        deblocking_filter_disabled = bits[offset] == "1"
        pps_deblocking_filter_disabled = deblocking_filter_disabled
        offset += 1
        if not deblocking_filter_disabled:
            for _ in range(2):
                deblocking_offset = _read_signed_exp_golomb(bits, offset)
                if deblocking_offset is None:
                    return None
                offset = deblocking_offset[1]
    if offset >= len(bits):
        return None
    scaling_list_present = bits[offset] == "1"
    offset += 1
    if scaling_list_present:
        scaling_list_offset = _skip_hevc_scaling_list_data(bits, offset)
        if scaling_list_offset is None:
            return None
        offset = scaling_list_offset
    if offset >= len(bits):
        return None
    offset += 1  # lists_modification_present_flag
    parallel_merge_level = _read_unsigned_exp_golomb(bits, offset)
    if parallel_merge_level is None:
        return None
    offset = parallel_merge_level[1]
    if offset + 2 > len(bits):
        return None
    slice_header_extension_present = bits[offset] == "1"
    offset += 1
    extension_present = bits[offset] == "1"
    offset += 1
    chroma_qp_offset_list_enabled = False
    if extension_present:
        if offset + 8 > len(bits):
            return None
        extension_flags = bits[offset : offset + 8]
        offset += 8
        range_extension = extension_flags[0] == "1"
        if "1" in extension_flags[1:4]:
            return None
        if range_extension:
            range_offset = _skip_hevc_pps_range_extension(
                bits,
                offset,
                transform_skip_enabled=transform_skip_enabled,
            )
            if range_offset is None:
                return None
            offset, chroma_qp_offset_list_enabled = range_offset
        if "1" in extension_flags[4:]:
            offset = len(bits)
    if offset != len(bits):
        return None
    return (
        pps[0],
        _HevcPpsInfo(
            sps_id=sps[0],
            dependent_slices_enabled=dependent_slices,
            output_flag_present=output_flag_present,
            extra_slice_header_bits=extra_slice_header_bits,
            slice_chroma_qp_offsets_present=slice_chroma_qp_offsets_present,
            chroma_qp_offset_list_enabled=chroma_qp_offset_list_enabled,
            deblocking_filter_override_enabled=deblocking_filter_override_enabled,
            pps_deblocking_filter_disabled=pps_deblocking_filter_disabled,
            loop_filter_across_slices_enabled=loop_filter_across_slices_enabled,
            tiles_enabled=tiles_enabled,
            entropy_coding_sync_enabled=entropy_coding_sync_enabled,
            slice_header_extension_present=slice_header_extension_present,
        ),
    )


def _hevc_slice_pps_id(  # noqa: PLR0911, PLR0912, PLR0915
    data: bytes,
    *,
    nal_type: int,
    sps_info: dict[int, _HevcSpsInfo],
    pps_info: dict[int, _HevcPpsInfo],
) -> int | None:
    """Return a PPS id after parsing mandatory linked HEVC slice fields."""

    bits = _rbsp_bits(data)
    if bits is None:
        return None
    trailing_one = bits.rfind("1")
    if trailing_one < 0:
        return None
    bits = bits[:trailing_one]
    if not bits:
        return None
    first_slice_segment = bits[0] == "1"
    if not first_slice_segment:
        return None
    offset = 1
    if 16 <= nal_type <= 23:
        offset += 1  # no_output_of_prior_pics_flag
    decoded = _read_unsigned_exp_golomb(bits, offset)
    if decoded is None or decoded[0] not in pps_info:
        return None
    pps_id, offset = decoded
    linked_pps = pps_info[pps_id]
    linked_sps = sps_info.get(linked_pps.sps_id)
    if linked_sps is None:
        return None
    offset += linked_pps.extra_slice_header_bits
    slice_type = _read_unsigned_exp_golomb(bits, offset)
    if slice_type is None or slice_type[0] > 2:
        return None
    offset = slice_type[1]
    if linked_pps.output_flag_present:
        offset += 1
    if linked_sps.separate_colour_plane:
        if offset + 2 > len(bits):
            return None
        offset += 2
    if nal_type not in {19, 20}:
        log2_max_pic_order_cnt_lsb = linked_sps.log2_max_pic_order_cnt_lsb
        if offset + log2_max_pic_order_cnt_lsb > len(bits):
            return None
        offset += log2_max_pic_order_cnt_lsb
        if offset >= len(bits):
            return None
        short_term_ref_pic_set_sps = bits[offset] == "1"
        offset += 1
        short_term_counts = list(linked_sps.short_term_delta_poc_counts)
        if short_term_ref_pic_set_sps:
            if not short_term_counts:
                return None
            if len(short_term_counts) > 1:
                index_bits = (len(short_term_counts) - 1).bit_length()
                if offset + index_bits > len(bits):
                    return None
                set_index = int(bits[offset : offset + index_bits], 2)
                if set_index >= len(short_term_counts):
                    return None
                offset += index_bits
        else:
            short_term_set = _skip_hevc_short_term_ref_pic_set(
                bits,
                offset,
                set_index=len(short_term_counts),
                delta_poc_counts=short_term_counts,
                slice_context=True,
            )
            if short_term_set is None:
                return None
            offset = short_term_set[0]
        if linked_sps.long_term_ref_pics_present:
            if linked_sps.long_term_ref_pics_sps:
                long_term_sps = _read_unsigned_exp_golomb(bits, offset)
                if (
                    long_term_sps is None
                    or long_term_sps[0] > linked_sps.long_term_ref_pics_sps
                ):
                    return None
                num_long_term_sps, offset = long_term_sps
            else:
                num_long_term_sps = 0
            long_term_pics = _read_unsigned_exp_golomb(bits, offset)
            if long_term_pics is None or long_term_pics[0] > 32:
                return None
            num_long_term_pics, offset = long_term_pics
            long_term_index_bits = (
                (linked_sps.long_term_ref_pics_sps - 1).bit_length()
                if linked_sps.long_term_ref_pics_sps > 1
                else 0
            )
            for index in range(num_long_term_sps + num_long_term_pics):
                if index < num_long_term_sps:
                    if offset + long_term_index_bits > len(bits):
                        return None
                    long_term_index = (
                        int(bits[offset : offset + long_term_index_bits], 2)
                        if long_term_index_bits
                        else 0
                    )
                    if long_term_index >= linked_sps.long_term_ref_pics_sps:
                        return None
                    offset += long_term_index_bits
                else:
                    offset += log2_max_pic_order_cnt_lsb
                    if offset >= len(bits):
                        return None
                    offset += 1  # used_by_curr_pic_lt_flag
                if offset >= len(bits):
                    return None
                delta_poc_msb_present = bits[offset] == "1"
                offset += 1
                if delta_poc_msb_present:
                    delta_cycle = _read_unsigned_exp_golomb(bits, offset)
                    if delta_cycle is None:
                        return None
                    offset = delta_cycle[1]
        if linked_sps.temporal_mvp_enabled:
            if offset >= len(bits):
                return None
            offset += 1
    slice_sao_luma = False
    slice_sao_chroma = False
    if linked_sps.sample_adaptive_offset_enabled:
        if offset >= len(bits):
            return None
        slice_sao_luma = bits[offset] == "1"
        offset += 1
        if linked_sps.chroma_format_idc and not linked_sps.separate_colour_plane:
            if offset >= len(bits):
                return None
            slice_sao_chroma = bits[offset] == "1"
            offset += 1
    # The validation path only needs an independently decodable I slice.  Do
    # not guess over the substantially different P/B reference-list syntax.
    if slice_type[0] != 2:
        return None
    slice_qp_delta = _read_signed_exp_golomb(bits, offset)
    if slice_qp_delta is None:
        return None
    offset = slice_qp_delta[1]
    if linked_pps.slice_chroma_qp_offsets_present:
        for _ in range(2):
            chroma_offset = _read_signed_exp_golomb(bits, offset)
            if chroma_offset is None:
                return None
            offset = chroma_offset[1]
    if linked_pps.chroma_qp_offset_list_enabled:
        if offset >= len(bits):
            return None
        offset += 1
    slice_deblocking_filter_disabled = linked_pps.pps_deblocking_filter_disabled
    if linked_pps.deblocking_filter_override_enabled:
        if offset >= len(bits):
            return None
        slice_deblocking_filter_override = bits[offset] == "1"
        offset += 1
        if slice_deblocking_filter_override:
            if offset >= len(bits):
                return None
            slice_deblocking_filter_disabled = bits[offset] == "1"
            offset += 1
            if not slice_deblocking_filter_disabled:
                for _ in range(2):
                    deblocking_offset = _read_signed_exp_golomb(bits, offset)
                    if deblocking_offset is None:
                        return None
                    offset = deblocking_offset[1]
    if linked_pps.loop_filter_across_slices_enabled and (
        slice_sao_luma
        or slice_sao_chroma
        or not slice_deblocking_filter_disabled
    ):
        if offset >= len(bits):
            return None
        offset += 1
    if linked_pps.tiles_enabled or linked_pps.entropy_coding_sync_enabled:
        entry_points = _read_unsigned_exp_golomb(bits, offset)
        if entry_points is None or entry_points[0] > 65535:
            return None
        num_entry_points, offset = entry_points
        if num_entry_points:
            offset_length = _read_unsigned_exp_golomb(bits, offset)
            if offset_length is None or offset_length[0] > 31:
                return None
            offset = offset_length[1]
            entry_point_bits = num_entry_points * (offset_length[0] + 1)
            if offset + entry_point_bits > len(bits):
                return None
            offset += entry_point_bits
    if linked_pps.slice_header_extension_present:
        extension_length = _read_unsigned_exp_golomb(bits, offset)
        if extension_length is None or extension_length[0] > 4096:
            return None
        offset = extension_length[1]
        extension_bits = extension_length[0] * 8
        if offset + extension_bits > len(bits):
            return None
        offset += extension_bits
    if offset >= len(bits) or bits[offset] != "1":
        return None
    offset += 1
    while offset % 8:
        if offset >= len(bits) or bits[offset] != "0":
            return None
        offset += 1
    return pps_id if offset < len(bits) else None


def _publish_validated_cloud_clip(  # noqa: PLR0912, PLR0915
    temp_path: Path,
    target: Path,
    *,
    expected_identity: tuple[int, int] | None,
) -> None:
    """Publish validated bytes while preserving an existing target inode."""

    if expected_identity is None:
        staged_stat = temp_path.stat()
        linked_identity = (staged_stat.st_dev, staged_stat.st_ino)
        try:
            os.link(temp_path, target)
        except FileExistsError as err:
            raise PyEzvizError("Cloud clip output target changed during capture") from err
        except OSError as err:
            unsupported_windows_hard_link = (
                err.errno == errno.EINVAL and getattr(err, "winerror", None) == 1
            )
            if err.errno not in {
                errno.EPERM,
                errno.EOPNOTSUPP,
                errno.ENOSYS,
                errno.EXDEV,
            } and not unsupported_windows_hard_link:
                raise
            _copy_validated_clip_to_new_target(temp_path, target)
        else:
            if not _regular_path_has_identity(target, linked_identity):
                raise PyEzvizError("Cloud clip output target changed during capture")
        temp_path.unlink()
        return

    # Replacing an inode atomically necessarily loses its ACLs, xattrs, and
    # hard-link identity.  Validation has already succeeded, so update an
    # existing regular file in place just as the legacy save path did.
    open_flags = (
        os.O_WRONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        destination_fd = os.open(target, open_flags)
    except OSError as err:
        raise PyEzvizError("Cloud clip output target changed during capture") from err
    destination_stat = os.fstat(destination_fd)
    if (
        not stat.S_ISREG(destination_stat.st_mode)
        or (destination_stat.st_dev, destination_stat.st_ino) != expected_identity
    ):
        os.close(destination_fd)
        raise PyEzvizError("Cloud clip output target changed during capture")
    backup = tempfile.SpooledTemporaryFile(  # noqa: SIM115 - closed in finally
        max_size=16 * 1024 * 1024
    )
    read_fd: int | None = None
    try:
        try:
            read_fd = os.open(
                target,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except PermissionError:
            # A legacy save supports an owner-writable, read-disabled target.
            # Temporarily add owner-read access solely to make a rollback copy,
            # then restore the exact mode before touching its contents.
            try:
                os.fchmod(destination_fd, destination_stat.st_mode | stat.S_IRUSR)
            except PermissionError:
                # Group/ACL write access may not grant ownership.  In that
                # case publish the already validated sibling atomically; a
                # failed replace leaves the unreadable target untouched.
                unreadable_destination_fd = os.dup(destination_fd)
                os.close(destination_fd)
                destination_fd = -1
                _publish_unreadable_existing_clip(
                    temp_path,
                    target,
                    expected_identity=expected_identity,
                    destination_fd=unreadable_destination_fd,
                )
                return
            try:
                read_fd = os.open(
                    target,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                )
            finally:
                os.fchmod(destination_fd, stat.S_IMODE(destination_stat.st_mode))
        read_stat = os.fstat(read_fd)
        if (read_stat.st_dev, read_stat.st_ino) != expected_identity:
            raise PyEzvizError("Cloud clip output target changed during capture")
        with os.fdopen(read_fd, "rb") as original:
            read_fd = None
            while chunk := original.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                backup.write(chunk)
        backup.seek(0)
        _reserve_existing_clip_space(
            destination_fd,
            required_size=temp_path.stat().st_size,
            original_size=destination_stat.st_size,
            original_allocated_blocks=getattr(destination_stat, "st_blocks", None),
            filesystem_path=target.parent,
        )
        try:
            with temp_path.open("rb") as source, os.fdopen(
                destination_fd,
                "wb",
            ) as destination:
                destination_fd = -1
                destination.truncate(0)
                while chunk := source.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                    destination.write(chunk)
                destination.truncate()
                destination.flush()
                os.fsync(destination.fileno())
        except BaseException:
            _restore_cloud_clip_after_publication_failure(
                target,
                cast(BinaryIO, backup),
                expected_identity=expected_identity,
            )
            raise
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        backup.close()
    if not _regular_path_has_identity(target, expected_identity):
        raise PyEzvizError("Cloud clip output target changed during capture")
    temp_path.unlink()


def _publish_unreadable_existing_clip(
    temp_path: Path,
    target: Path,
    *,
    expected_identity: tuple[int, int],
    destination_fd: int,
) -> None:
    """Publish through a captured unreadable target descriptor."""

    try:
        if not _regular_path_has_identity(target, expected_identity):
            raise PyEzvizError("Cloud clip output target changed during capture")
        destination_stat = os.fstat(destination_fd)
        if (destination_stat.st_dev, destination_stat.st_ino) != expected_identity:
            raise PyEzvizError("Cloud clip output target changed during capture")
        # The caller may have content-write permission but neither read nor
        # parent-directory access.  No rollback snapshot is possible in that
        # permission model, so preserve the legacy in-place write semantics.
        with temp_path.open("rb") as source, os.fdopen(
            destination_fd,
            "wb",
        ) as destination:
            destination_fd = -1
            destination.truncate(0)
            while chunk := source.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                destination.write(chunk)
            destination.truncate()
            destination.flush()
            os.fsync(destination.fileno())
        if not _regular_path_has_identity(target, expected_identity):
            raise PyEzvizError("Cloud clip output target changed during capture")
        temp_path.unlink()
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)


def _reserve_existing_clip_space(
    destination_fd: int,
    *,
    required_size: int,
    original_size: int,
    original_allocated_blocks: int | None,
    filesystem_path: Path,
) -> None:
    """Conservatively preflight replacement space without changing the target."""

    # Reserving on the destination and then truncating it releases the very
    # blocks that were reserved.  Keep this check non-mutating; the rollback
    # copy above is the authority if the subsequent write still fails.
    if hasattr(os, "fstatvfs"):
        filesystem = os.fstatvfs(destination_fd)
        available_bytes = filesystem.f_bavail * filesystem.f_frsize
    else:
        available_bytes = shutil.disk_usage(filesystem_path).free
    reclaimable_bytes = (
        original_allocated_blocks * 512
        if original_allocated_blocks is not None
        else original_size
    )
    if required_size > available_bytes + reclaimable_bytes:
        raise OSError(errno.ENOSPC, "insufficient space to replace cloud clip safely")


def _restore_cloud_clip_after_publication_failure(
    target: Path,
    backup: BinaryIO,
    *,
    expected_identity: tuple[int, int],
) -> None:
    """Restore an existing clip after a fallible in-place publication."""

    restore_fd = os.open(
        target,
        os.O_WRONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        restore_stat = os.fstat(restore_fd)
        if (restore_stat.st_dev, restore_stat.st_ino) != expected_identity:
            raise PyEzvizError("Cloud clip output target changed during capture")
        backup.seek(0)
        with os.fdopen(restore_fd, "wb") as destination:
            restore_fd = -1
            destination.truncate(0)
            while chunk := backup.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                destination.write(chunk)
            destination.truncate()
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException as restore_error:
        raise PyEzvizError(
            "Cloud clip publication failed and the previous clip could not be restored"
        ) from restore_error
    finally:
        if restore_fd >= 0:
            os.close(restore_fd)


def _copy_validated_clip_to_new_target(temp_path: Path, target: Path) -> None:
    """Exclusively create a target when its filesystem cannot hard-link."""

    mode = stat.S_IMODE(temp_path.stat().st_mode)
    try:
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as err:
        raise PyEzvizError("Cloud clip output target changed during capture") from err
    target_stat = os.fstat(target_fd)
    target_identity = (target_stat.st_dev, target_stat.st_ino)
    try:
        with os.fdopen(target_fd, "wb") as destination, temp_path.open(
            "rb"
        ) as source:
            while chunk := source.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if not _regular_path_has_identity(target, target_identity):
            raise PyEzvizError("Cloud clip output target changed during capture")
    except BaseException:
        if _regular_path_has_identity(target, target_identity):
            with suppress(OSError):
                target.unlink()
        raise


def _regular_path_has_identity(path: Path, identity: tuple[int, int]) -> bool:
    """Return whether a path still names the expected regular-file inode."""

    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(path_stat.st_mode) and (
        path_stat.st_dev,
        path_stat.st_ino,
    ) == identity


def _legacy_duration_is_effectively_unbounded(duration_seconds: float | None) -> bool:
    """Return whether a preserved legacy duration cannot end a capture."""

    if duration_seconds is None:
        return True
    try:
        if not math.isfinite(duration_seconds):
            return True
        return duration_seconds > 0 and not is_positive_socket_timeout_bound(
            duration_seconds
        )
    except (OverflowError, TypeError):
        return isinstance(duration_seconds, int) and duration_seconds > 0


def _cloud_clip_staging(
    target: Path,
) -> tuple[Path, tuple[int, int] | None]:
    """Return the staging parent and original target identity."""

    try:
        target_stat = target.stat()
    except FileNotFoundError:
        return target.parent, None
    if not stat.S_ISREG(target_stat.st_mode):
        raise PyEzvizError("Cloud clip output target must be a regular file")
    return target.parent, (target_stat.st_dev, target_stat.st_ino)


def _cloud_clip_temporary_directory(
    preferred_parent: Path,
) -> tempfile.TemporaryDirectory[str]:
    """Stage beside the target, falling back when its parent is not writable."""

    try:
        return tempfile.TemporaryDirectory(
            prefix=".pyezvizapi-cloud-clip-",
            dir=preferred_parent,
        )
    except OSError as err:
        if err.errno not in {errno.EACCES, errno.EPERM, errno.EROFS}:
            raise
        return tempfile.TemporaryDirectory(prefix=".pyezvizapi-cloud-clip-")


def _is_existing_non_regular_path(path: Path) -> bool:
    """Return whether ``path`` exists and is not a regular file."""

    try:
        return not stat.S_ISREG(path.stat().st_mode)
    except FileNotFoundError:
        return False


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
            req = self._session.post(
                url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGIN}",
                allow_redirects=False,
                data=payload,
                timeout=self._timeout,
            )

            req.raise_for_status()

        except requests.ConnectionError as err:
            raise InvalidURL("A Invalid URL or Proxy error occurred") from err

        except requests.HTTPError as err:
            raise HTTPError from err

        try:
            json_result = req.json()

        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: " + str(err) + "\nResponse was: " + str(req.text)
            ) from err

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

        raise PyEzvizError(f"Login error: {json_result['meta']}")

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
            with self._token_lock:
                req = self._session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=self._timeout,
                )
            req.raise_for_status()
        except requests.HTTPError as err:
            if retry_401 and err.response is not None and err.response.status_code == 401:
                if max_retries >= MAX_RETRIES:
                    raise HTTPError from err
                # Re-login can also move the account to another regional API.
                with self._token_lock:
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

    @staticmethod
    def _parse_json(resp: requests.Response) -> JsonDict:
        """Parse JSON or raise a friendly error."""
        try:
            return cast(dict, resp.json())
        except ValueError as err:
            raise PyEzvizError(
                "Impossible to decode response: " + str(err) + "\nResponse was: " + str(resp.text)
            ) from err

    @staticmethod
    def _normalize_json_payload(payload: Any) -> Any:
        """Return a payload suitable for json= usage, decoding strings when needed."""

        if isinstance(payload, (Mapping, list)):
            return payload
        if isinstance(payload, tuple):
            return list(payload)
        if isinstance(payload, (bytes, bytearray)):
            try:
                return json.loads(payload.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as err:
                raise PyEzvizError("Invalid JSON payload provided") from err
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except json.JSONDecodeError as err:
                raise PyEzvizError("Invalid JSON payload provided") from err
        raise PyEzvizError("Unsupported payload type for JSON body")

    @staticmethod
    def _is_ok(payload: JsonDict) -> bool:
        """Return True if payload indicates success for both API styles."""
        meta = payload.get("meta")
        if isinstance(meta, dict) and meta.get("code") == 200:
            return True
        rc = payload.get("resultCode")
        return rc in (0, "0")

    @staticmethod
    def _meta_code(payload: JsonDict) -> int | None:
        """Safely extract meta.code as an int, or None if missing/invalid."""
        code = (payload.get("meta") or {}).get("code")
        if isinstance(code, (int, str)):
            try:
                return int(code)
            except (TypeError, ValueError):
                return None
        return None

    @staticmethod
    def _meta_ok(payload: JsonDict) -> bool:
        """Return True if meta.code equals 200."""
        return EzvizClient._meta_code(payload) == 200

    @staticmethod
    def _response_code(payload: JsonDict) -> int | str | None:
        """Return a best-effort code from a response for logging.

        Prefers modern ``meta.code`` if present; falls back to legacy
        ``resultCode`` or a top-level ``status`` field when available.
        Returns None if no code-like field is found.
        """
        # Prefer modern meta.code
        mc = EzvizClient._meta_code(payload)
        if mc is not None:
            return mc
        if "resultCode" in payload:
            return payload.get("resultCode")
        if "status" in payload:
            return payload.get("status")
        return None

    @staticmethod
    def _http_error_status(err: HTTPError) -> int | None:
        """Return the wrapped requests HTTP status when available."""

        cause = err.__cause__
        if isinstance(cause, requests.HTTPError) and cause.response is not None:
            return cause.response.status_code
        return None

    @staticmethod
    def _summarize_payload(payload: Any) -> str:
        """Return a compact, credential-safe payload description for debug logs."""

        if payload is None:
            return "-"
        if isinstance(payload, Mapping):
            sensitive_keys = {
                "password",
                "oldPassword",
                "newPassword",
                "token",
                "sessionId",
            }
            keys = ", ".join(
                "<redacted>" if key in sensitive_keys else key
                for key in sorted(str(key) for key in payload)
            )
            return f"dict[{keys}]"
        if isinstance(payload, (list, tuple, set)):
            return f"{type(payload).__name__}(len={len(payload)})"
        if isinstance(payload, (bytes, bytearray)):
            return f"bytes(len={len(payload)})"
        if isinstance(payload, str):
            trimmed = payload[:32] + "…" if len(payload) > 32 else payload
            return f"str(len={len(payload)}, preview={trimmed!r})"
        return f"{type(payload).__name__}"

    @staticmethod
    def _body_debug_summary(payload: Any) -> str:
        """Return a request-body summary without inspecting sensitive contents."""

        if payload is None:
            return "-"
        try:
            return f"{type(payload).__name__}(len={len(payload)})"
        except TypeError:
            return type(payload).__name__

    def _ensure_ok(self, payload: JsonDict, message: str) -> None:
        """Raise PyEzvizError with context if response is not OK.

        Accepts both API styles: new (meta.code == 200) and legacy (resultCode == 0).
        """
        if not self._is_ok(payload):
            if _LOGGER.isEnabledFor(logging.DEBUG):
                _LOGGER.debug(
                    "API error detected (%s): code=%s payload=%s",
                    message,
                    self._response_code(payload),
                    json.dumps(payload, ensure_ascii=False),
                )
            raise PyEzvizError(f"{message}: Got {payload})")

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
            with self._token_lock:
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
                req = self._session.send(request=prepared, timeout=self._timeout)
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
        with self._token_lock:
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
            raise PyEzvizError(f"Could not request MFA code: Got {json_output})")

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
            raise PyEzvizError(f"Error getting Service URLs: {json_output}")

        service_urls = json_output.get("systemConfigInfo", {})
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

        params: dict[str, int | str] = {
            "groupId": group_id,
            "limit": limit,
            "offset": offset,
            "filter": page_filter,
        }

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_PAGELIST,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        if self._meta_code(json_output) != 200:
            # session is wrong, need to relogin and retry
            self.login()
            _LOGGER.warning(
                "Http_retry: serial=%s code=%s msg=%s",
                "unknown",
                self._meta_code(json_output),
                "pagelist_relogin",
            )
            return self._api_get_pagelist(
                page_filter, json_key, group_id, limit, offset, max_retries + 1
            )

        page_info = json_output.get("page") or {}
        next_page = bool(page_info.get("hasNext", False))

        data = json_output[json_key] if json_key else json_output

        if next_page:
            next_offset = offset + limit
            # Recursive call to fetch next page
            next_data = self._api_get_pagelist(
                page_filter, json_key, group_id, limit, next_offset, max_retries
            )
            # Merge data from next page into current data
            data = deep_merge(data, next_data)

        return data

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
            raise PyEzvizError(f"Could not get data from alarm api: Got {json_output})")
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
        r"""Return unified alarm/message list for the requested devices.

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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        def _stringify(value: Any) -> str:
            raw = getattr(value, "value", value)
            return str(raw)

        stype_param: str | None
        if s_type is None:
            stype_param = DEFAULT_UNIFIEDMSG_STYPE
        elif isinstance(s_type, str):
            stype_param = s_type
        elif isinstance(s_type, Iterable) and not isinstance(s_type, (bytes, bytearray)):
            parts = [_stringify(item) for item in s_type if item not in (None, "")]
            stype_param = ",".join(parts) if parts else DEFAULT_UNIFIEDMSG_STYPE
        else:
            stype_param = _stringify(s_type)

        if date is None:
            date_value = dt.datetime.now().strftime("%Y%m%d")
        elif isinstance(date, (dt.date, dt.datetime)):
            date_value = date.strftime("%Y%m%d")
        else:
            date_value = str(date)

        try:
            limit_value = max(1, min(int(limit), 50))
        except (TypeError, ValueError):
            limit_value = 20

        end_time_value: str = "" if end_time is None else str(end_time)

        params: dict[str, Any] = {
            "serials": serials,
            "stype": stype_param,
            "limit": limit_value,
            "date": date_value,
            "endTime": end_time_value,
        }
        filtered_params = {k: v for k, v in params.items() if v not in (None, "")}
        # keep empty string endTime to mimic app behavior
        if end_time_value == "":
            filtered_params["endTime"] = ""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_UNIFIEDMSG_LIST_GET,
            params=filtered_params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get unified message list")
        if _LOGGER.isEnabledFor(logging.DEBUG):
            counter_key = "unifiedmsg"
            self._debug_request_counters[counter_key] = (
                self._debug_request_counters.get(counter_key, 0) + 1
            )
            _LOGGER.debug(
                "req_counter[%s]=%s params=%s",
                counter_key,
                self._debug_request_counters[counter_key],
                filtered_params,
            )
        return json_output

    def add_device(
        self,
        serial: str,
        validate_code: str,
        *,
        add_type: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Add a new device to the current account."""

        data = {
            "deviceSerial": serial,
            "validateCode": validate_code,
        }
        if add_type is not None:
            data["addType"] = add_type
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_USERDEVICES_V2,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add device")
        return json_output

    def add_hik_activate(
        self,
        serial: str,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Activate a Hikvision device using the security endpoint."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVCONFIG_SECURITY_ACTIVATE}{serial}",
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not activate Hik device")
        return json_output

    def add_hik_challenge(
        self,
        serial: str,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Request a Hikvision security challenge."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVCONFIG_SECURITY_CHALLENGE}{serial}",
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not request Hik challenge")
        return json_output

    def add_local_device(
        self,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Add a device discovered on the local network."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICES_LOC,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add local device")
        return json_output

    def save_hik_dev_code(
        self,
        payload: Any,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Submit a Hikvision device code via the SCD endpoint."""

        body = self._normalize_json_payload(payload)
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SCD_APP_DEVICE_ADD,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not save Hik device code")
        return json_output

    def bind_virtual_device(
        self,
        product_id: str,
        version: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Bind a virtual IoT device using product identifier and version."""

        params = {"productId": product_id, "version": version}
        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_IOT_VIRTUAL_BIND,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not bind virtual device")
        return json_output

    def dev_config_search(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Trigger a network search on the device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork"
        json_output = self._request_json(
            "POST",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not start network search")
        return json_output

    def dev_config_send_config_command(
        self,
        serial: str,
        channel: int,
        target_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Send a network configuration command to a target device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/command"
        json_output = self._request_json(
            "POST",
            path,
            params={"targetDeviceSerial": target_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send network command")
        return json_output

    def dev_config_wifi_list(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve Wi-Fi network list detected by the device."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get Wi-Fi list")
        return json_output

    def device_between_error(
        self,
        serial: str,
        channel: int,
        target_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve error details for a network configuration attempt."""

        path = f"{API_ENDPOINT_DEVCONFIG_BASE}/{serial}/{channel}/netWork/result"
        json_output = self._request_json(
            "GET",
            path,
            params={"targetDeviceSerial": target_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get network error info")
        return json_output

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

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        enable_flag = 1 if bool(enable) else 0
        path = (
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}/{enable_flag}/"
            f"{switch_type}{API_ENDPOINT_SWITCH_STATUS}"
        )
        payload = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set the switch")
        return payload

    def set_switch_legacy(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fallback legacy switch endpoint used by older firmware."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        payload = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_SWITCH_STATUS_LEGACY,
            data={
                "serial": serial,
                "enable": "1" if bool(enable) else "0",
                "type": str(switch_type),
                "channel": str(channel),
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set the switch (legacy)")
        return payload

    def set_switch(
        self,
        serial: str,
        switch_type: int,
        enable: bool | int,
        channel: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Try the v3 switch endpoint, falling back to the legacy API if needed."""

        try:
            return self.set_switch_v3(serial, switch_type, enable, channel, max_retries=max_retries)
        except PyEzvizError as first_error:
            try:
                return self.set_switch_legacy(
                    serial, switch_type, enable, channel, max_retries=max_retries
                )
            except PyEzvizError:
                raise first_error from None

    def switch_status(
        self,
        serial: str,
        status_type: int,
        enable: bool | int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Camera features are represented as switches. Switch them on or off."""

        target_state = bool(enable)
        self.set_switch(
            serial,
            status_type,
            target_state,
            channel=channel_no,
            max_retries=max_retries,
        )
        if self._cameras.get(serial):
            self._cameras[serial]["switches"][status_type] = target_state
        return True

    def device_switch(
        self,
        serial: str,
        channel: int,
        enable: int,
        switch_type: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Direct wrapper for /v3/devices/{serial}/switch endpoint."""

        params = {
            "channelNo": channel,
            "enable": enable,
            "switchType": switch_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_SWITCH_OTHER}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not toggle device switch")
        return json_output

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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_SWITCH_OTHER}",
            params={
                "channelNo": channel_number,
                "enable": enable,
                "switchType": status_type,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set the switch")
        return True

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
        json_output = self._retry_json(
            lambda: self._request_json(
                "PUT",
                f"{API_ENDPOINT_DEVICES}{serial}/{channel_no}{API_ENDPOINT_CHANGE_DEFENCE_STATUS}",
                data={"type": arm_type, "status": enable, "actor": actor},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: self._meta_code(p) == 504,
            log="arm_disarm_timeout",
            serial=serial,
        )
        if self._meta_code(json_output) != 200:
            raise PyEzvizError(f"Could not arm or disarm Camera {serial}: Got {json_output})")
        return True

    def set_battery_camera_work_mode(self, serial: str, value: int) -> bool:
        """Set battery camera work mode."""
        return self.set_device_config_by_key(serial, value, key="batteryCameraWorkMode")

    def set_detection_mode(self, serial: str, value: int) -> bool:
        """Set detection mode.

        Deprecated in favour of set_alarm_detect_human_car() but kept for
        backwards compatibility with older callers inside the integration.
        """
        return self.set_alarm_detect_human_car(serial, value)

    def set_alarm_detect_human_car(self, serial: str, value: int) -> bool:
        """Update Alarm_DetectHumanCar type on the device."""
        return self.set_device_config_by_key(
            serial, value=f'{{"type":{value}}}', key="Alarm_DetectHumanCar"
        )

    def set_alarm_advanced_detect(self, serial: str, value: int) -> bool:
        """Update Alarm_AdvancedDetect type on the device."""
        return self.set_device_config_by_key(
            serial, value=f'{{"type":{value}}}', key="Alarm_AdvancedDetect"
        )

    def set_algorithm_param(
        self,
        serial: str,
        subtype: str | int,
        value: int,
        channel: int = 1,
    ) -> bool:
        """Update a single AlgorithmInfo subtype value via devconfig."""

        payload = {
            "AlgorithmInfo": [
                {
                    "SubType": str(subtype),
                    "Value": str(value),
                    "channel": channel,
                }
            ]
        }

        return self.set_device_config_by_key(
            serial,
            value=json.dumps(payload, separators=(",", ":")),
            key="AlgorithmInfo",
        )

    def set_night_vision_mode(self, serial: str, mode: int, luminance: int = 100) -> bool:
        """Set night vision mode."""
        return self.set_device_config_by_key(
            serial,
            value=f'{{"graphicType":{mode},"luminance":{luminance}}}',
            key="NightVision_Model",
        )

    def set_display_mode(self, serial: str, mode: int) -> bool:
        """Change video color and saturation mode."""
        return self.set_device_config_by_key(serial, value=f'{{"mode":{mode}}}', key="display_mode")

    def set_dev_config_kv(
        self,
        serial: str,
        channel: int,
        key: str,
        value: Mapping[str, Any] | str | bytes | float | bool,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update a device configuration key/value pair via devconfig."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if isinstance(value, Mapping):
            value_payload = json.dumps(value, separators=(",", ":"))
        elif isinstance(value, bytes):
            value_payload = value.decode()
        elif isinstance(value, bool):
            value_payload = "1" if value else "0"
        elif isinstance(value, (int, float)):
            value_payload = str(value)
        else:
            value_payload = str(value)

        data = {
            "key": key,
            "value": value_payload,
        }

        payload = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set devconfig key")
        return payload

    def set_common_key_value(
        self,
        serial: str,
        channel: int,
        key: str,
        value: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update a devconfig key/value pair using query parameters."""

        params = {
            "key": key,
            "value": value if isinstance(value, str) else str(value),
        }
        payload = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(payload, "Could not set common key value")
        return payload

    def set_device_config_by_key(
        self,
        serial: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        """Change value on device by setting key."""

        self.set_dev_config_kv(
            serial,
            1,
            key,
            value,
            max_retries=max_retries,
        )
        return True

    def set_device_key_value(
        self,
        serial: str,
        channel: int,
        key: str,
        value: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Alias for the query-based key/value setter."""

        return self.set_common_key_value(
            serial,
            channel,
            key,
            value,
            max_retries=max_retries,
        )

    def audition_request(
        self,
        serial: str,
        channel: int,
        request: str,
        payload: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Send an audition request via /v3/devconfig/op."""

        data = {
            "deviceSerial": serial,
            "channelNo": channel,
            "request": request,
            "data": payload,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVCONFIG_OP,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send audition request")
        return json_output

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

        data = {
            "deviceSerial": serial,
            "channelNo": channel,
            "localIndex": local_index,
            "command": command,
            "action": action,
            "speed": speed,
            "uuid": uuid,
            "control": control,
            "hardwareCode": hardware_code,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVCONFIG_MOTOR,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not control baby motor")
        return json_output

    def set_device_feature_by_key(
        self,
        serial: str,
        product_id: str,
        value: Any,
        key: str,
        max_retries: int = 0,
    ) -> bool:
        """Change value on device by setting the iot-feature's key.

        The FEATURE key that is part of 'device info' holds
        information about the device's functions (for example light_switch, brightness etc.).
        """
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        payload = json.dumps({"itemKey": key, "productId": product_id, "value": value})

        full_url = f"https://{self._token['api_url']}{API_ENDPOINT_IOT_FEATURE}{serial.upper()}/0"

        headers = {
            **self._session.headers,
            "Content-Type": "application/json",
        }

        req_prep = requests.Request(
            method="PUT", url=full_url, headers=headers, data=payload
        ).prepare()

        req = self._send_prepared(req_prep, retry_401=True, max_retries=max_retries)
        json_output = self._parse_json(req)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not set iot-feature key '{key}': Got {json_output})")

        return True

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

        path = (
            f"{endpoint}{serial.upper()}/{resource_identifier}/"
            f"{local_index}/{domain_id}/{action_id}"
        )

        headers = dict(self._session.headers)
        data: str | bytes | bytearray | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            if isinstance(payload, (bytes, bytearray, str)):
                data = payload
            else:
                data = json.dumps(payload, separators=(",", ":"))

        req = requests.Request(
            method=method,
            url=self._url(path),
            headers=headers,
            data=data,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"{error_message}: Got {json_output})")
        return json_output

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

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch low battery keep-alive status",
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

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            error_message="Could not fetch object removal status",
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

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch remote control path list",
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

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch tracking status",
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

        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            max_retries=max_retries,
            error_message="Could not fetch port security status",
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

        payload = {"value": value}
        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=payload,
            max_retries=max_retries,
            error_message="Could not set port security status",
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

        local_idx = str(local_index)
        return self._iot_request(
            "GET",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_idx,
            domain_identifier,
            prop_identifier,
            max_retries=max_retries,
            error_message="Could not fetch device feature value",
        )

    def set_intelligent_fill_light(
        self,
        serial: str,
        *,
        enabled: bool,
        local_index: str = "1",
        max_retries: int = 0,
    ) -> JsonDict:
        """Toggle the intelligent fill light mode via the IoT feature API."""

        payload = {
            "value": {
                "enabled": bool(enabled),
                "supplementLightSwitchMode": "eventIntelligence" if enabled else "irLight",
            }
        }
        body = self._normalize_json_payload(payload)
        return self.set_iot_feature(
            serial,
            resource_identifier="Video",
            local_index=local_index,
            domain_id="SupplementLightMgr",
            action_id="ImageSupplementLightModeSwitchParams",
            value=body,
            max_retries=max_retries,
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

        if payload is None:
            if enabled is None:
                raise PyEzvizError("Either 'enabled' or 'payload' must be provided")
            payload = {"value": {"enabled": bool(enabled)}}
        body = self._normalize_json_payload(payload)
        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            "Video",
            local_index,
            "VideoAdjustment",
            "ImageFlip",
            payload=body,
            max_retries=max_retries,
            error_message="Could not set image flip",
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

        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_ACTION,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=value,
            max_retries=max_retries,
            error_message="Could not execute IoT action",
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

        return self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_FEATURE,
            serial,
            resource_identifier,
            local_index,
            domain_id,
            action_id,
            payload=value,
            max_retries=max_retries,
            error_message="Could not set IoT feature value",
        )

    def set_lens_defog_mode(
        self,
        serial: str,
        value: int,
        *,
        local_index: str = "1",
        max_retries: int = 0,
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

        if value == 1:
            enabled, mode = True, "open"
        elif value == 2:
            enabled, mode = False, "auto"
        else:
            enabled, mode = True, "auto"

        payload = {"value": {"enabled": enabled, "defogMode": mode}}
        self.set_iot_feature(
            serial,
            resource_identifier="Video",
            local_index=local_index,
            domain_id="LensCleaning",
            action_id="DefogCfg",
            value=payload,
            max_retries=max_retries,
        )

        return enabled, mode

    def update_device_name(
        self,
        serial: str,
        name: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Rename a device via the legacy updateName endpoint."""

        if not name:
            raise PyEzvizError("Device name must not be empty")

        data = {
            "deviceSerialNo": serial,
            "deviceName": name,
        }

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_UPDATE_NAME,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not update device name")
        return json_output

    def upgrade_device(self, serial: str, max_retries: int = 0) -> bool:
        """Upgrade device firmware."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_UPGRADE_DEVICE}{serial}/0/upgrade",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not initiate firmware upgrade")
        return True

    def get_storage_status(self, serial: str, max_retries: int = 0) -> Any:
        """Get device storage status."""
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_DEVICE_STORAGE_STATUS,
                data={"subSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="storage_status_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) != "0":
            raise PyEzvizError(f"Could not get device storage status: Got {json_output})")
        return json_output.get("storageStatus")

    def sound_alarm(self, serial: str, enable: int = 1, max_retries: int = 0) -> bool:
        """Sound alarm on a device."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/0{API_ENDPOINT_SWITCH_SOUND_ALARM}",
            data={"enable": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set the alarm sound")
        return True

    def get_user_id(self, max_retries: int = 0) -> Any:
        """Get Ezviz userid, used by restricted api endpoints."""
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USER_ID,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get user id")
        return json_output.get("deviceTokenInfo")

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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if enable == 2 and not old_password:
            raise PyEzvizError("Old password is required when changing password.")

        if new_password and not enable == 2:
            raise PyEzvizError("New password is only required when changing password.")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{API_ENDPOINT_VIDEO_ENCRYPT}",
            data={
                "deviceSerial": serial,
                "isEncrypt": enable,
                "oldPassword": old_password,
                "password": new_password,
                "featureCode": FEATURE_CODE,
                "validateCode": camera_verification_code,
                "msgType": -1,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set video encryption")

        return True

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

        data = {
            "needCheckCode": str(bool(need_check_code)).lower(),
            "checkCode": check_code or "",
            "senderType": sender_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES_AUTHENTICATE}{serial}",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not authenticate device")
        return json_output

    def reboot_camera(
        self,
        serial: str,
        delay: int = 1,
        operation: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Reboot camera."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                f"{API_ENDPOINT_DEVICE_SYS_OPERATION}{serial}",
                data={"oper": operation, "deviceSerial": serial, "delay": delay},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="reboot_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) not in ("0", 0):
            raise PyEzvizError(f"Could not reboot device {json_output})")
        return True

    def set_offline_notification(
        self,
        serial: str,
        enable: int = 1,
        req_type: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set offline notification."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_OFFLINE_NOTIFY,
                data={"reqType": req_type, "serial": serial, "status": enable},
                retry_401=True,
                max_retries=0,
            )
            result = str(json_output.get("resultCode"))
            if result == "0":
                return True
            if result == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Unable to set offline notification, camera %s is unreachable, retrying %s/%s",
                    serial,
                    attempt + 1,
                    attempts,
                )
                continue
            raise PyEzvizError(f"Could not set offline notification {json_output})")
        raise PyEzvizError("Could not set offline notification: exceeded retries")

    def device_email_alert_state(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Get email alert state for one or more devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICE_EMAIL_ALERT,
            params={"devices": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device email alert state")
        return json_output

    def save_device_email_alert_state(
        self,
        enable: bool,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update email alert state for the provided devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        data = {
            "enable": str(bool(enable)).lower(),
            "devices": serial_param,
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_DEVICE_EMAIL_ALERT,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not save device email alert state")
        return json_output

    def get_group_defence_mode(self, max_retries: int = 0) -> Any:
        """Get group arm status. The alarm arm/disarm concept on 1st page of app."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_GROUP_DEFENCE_MODE,
            params={"groupId": -1},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get group defence status")
        return json_output.get("mode")

    # Not tested
    def cancel_alarm_device(self, serial: str, max_retries: int = 0) -> bool:
        """Cacnel alarm on an Alarm device."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_CANCEL_ALARM,
            data={"subSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not cancel alarm siren")
        return True

    def load_devices(self, refresh: bool = True) -> JsonDict:
        """Build status maps for cameras and light bulbs.

        refresh: if True, camera.status() may perform network fetches (e.g. alarms).
        Returns a combined mapping of serial -> status dict for both cameras and bulbs.

        Note: We update in place and do not remove keys for devices that may
        have disappeared. Users who intentionally remove a device can restart
        the integration to flush stale entries.
        """

        # Build lightweight records for clean gating/selection
        records = cast(dict[str, EzvizDeviceRecord], self.get_device_records(None))
        supported_categories = self.SUPPORTED_CATEGORIES

        def _is_supported_camera(rec: EzvizDeviceRecord) -> bool:
            """Return True if record should be treated as a camera."""
            if rec.device_category not in supported_categories:
                return False
            if rec.device_category in (
                DeviceCatagories.LIGHTING.value,
                DeviceCatagories.SOCKET.value,
            ):
                return False
            return not (
                rec.device_category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value
                and not ((rec.raw.get("deviceInfos") or {}).get("hik"))
            )

        latest_alarms: dict[str, dict[str, Any]] = {}
        if refresh:
            camera_serials = [
                serial for serial, record in records.items() if _is_supported_camera(record)
            ]
            latest_alarms = self._prefetch_latest_camera_alarms(camera_serials)

        for device, rec in records.items():
            if rec.device_category in supported_categories:
                # Add support for connected HikVision cameras
                if rec.device_category == DeviceCatagories.COMMON_DEVICE_CATEGORY.value and not (
                    rec.raw.get("deviceInfos") or {}
                ).get("hik"):
                    continue

                if rec.device_category == DeviceCatagories.LIGHTING.value:
                    try:
                        self._light_bulbs[device] = device_factory.light_bulb_status(
                            self, device, dict(rec.raw)
                        )
                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
                elif rec.device_category == DeviceCatagories.SOCKET.value:
                    try:
                        self._smart_plugs[device] = device_factory.smart_plug_status(
                            self, device, dict(rec.raw)
                        )
                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
                else:
                    try:
                        self._cameras[device] = device_factory.camera_status(
                            self,
                            device,
                            dict(rec.raw),
                            refresh=refresh,
                            latest_alarm=latest_alarms.get(device),
                        )

                    except (
                        PyEzvizError,
                        KeyError,
                        TypeError,
                        ValueError,
                    ) as err:
                        _LOGGER.warning(
                            "Load_device_failed: serial=%s code=%s msg=%s",
                            device,
                            "load_error",
                            str(err),
                        )
        return {**self._cameras, **self._light_bulbs, **self._smart_plugs}

    def _prefetch_latest_camera_alarms(
        self, serials: Iterable[str], *, chunk_size: int = 20
    ) -> dict[str, dict[str, Any]]:
        """Attempt to fetch the most recent unified message per camera serial."""
        serial_list = [serial for serial in serials if serial]
        if not serial_list:
            return {}

        latest: dict[str, dict[str, Any]] = {}

        def _query_chunk(missing: set[str], limit: int, *, filtered: bool) -> None:
            """Populate latest alarms for a given chunk, retrying a few times."""
            attempts = 0
            while missing and attempts < MAX_UNIFIEDMSG_PAGES:
                attempts += 1
                serial_param = None if not filtered else ",".join(sorted(missing))
                try:
                    response = self.get_device_messages_list(
                        serials=serial_param,
                        limit=limit,
                        date="",
                        end_time="",
                        max_retries=1,
                    )
                except PyEzvizError as err:
                    _LOGGER.debug(
                        "alarm_prefetch_failed: serials=%s error=%r",
                        serial_param or "",
                        err,
                    )
                    return

                items = response.get("message") or response.get("messages") or []
                if not isinstance(items, list) or not items:
                    return

                matched = 0
                for item in items:
                    serial = item.get("deviceSerial")
                    if isinstance(serial, str) and serial in missing and serial not in latest:
                        latest[serial] = item
                        missing.discard(serial)
                        matched += 1

                # If this filtered call returned fewer entries than we still need,
                # assume remaining serials truly have no data and stop retrying.
                if filtered and matched < len(missing):
                    return

                if not response.get("hasNext"):
                    return

        remaining_serials = set(serial_list)

        # First, try a global fetch without serial filtering to capture the freshest alarms
        before = set(remaining_serials)
        _query_chunk(remaining_serials, limit=50, filtered=False)
        satisfied = before - remaining_serials
        if satisfied:
            remaining_serials.difference_update(satisfied)

        for start_idx in range(0, len(serial_list), chunk_size):
            chunk = [serial for serial in serial_list[start_idx : start_idx + chunk_size] if serial]
            if not chunk:
                continue
            remaining = {serial for serial in chunk if serial in remaining_serials}
            if not remaining:
                continue
            chunk_key = ",".join(chunk)
            limit = min(50, max(len(chunk), 20))
            before_chunk = set(remaining)
            _query_chunk(remaining, limit, filtered=True)
            satisfied_chunk = before_chunk - remaining
            if satisfied_chunk:
                remaining_serials.difference_update(satisfied_chunk)
            if remaining:
                _LOGGER.debug(
                    "alarm_prefetch_incomplete: serials=%s missing=%s",
                    chunk_key,
                    ",".join(sorted(remaining)),
                )
        return latest

    def load_cameras(self, refresh: bool = True) -> JsonDict:
        """Load and return all camera status mappings.

        refresh: pass-through to load_devices() to control network fetches.
        """
        self.load_devices(refresh=refresh)
        return self._cameras

    def load_light_bulbs(self, refresh: bool = True) -> JsonDict:
        """Load and return all light bulb status mappings.

        refresh: pass-through to load_devices().
        """
        self.load_devices(refresh=refresh)
        return self._light_bulbs

    def load_smart_plugs(self, refresh: bool = True) -> JsonDict:
        """Load and return all smart plugs status mappings.

        refresh: pass-through to load_devices().
        """
        self.load_devices(refresh=refresh)
        return self._smart_plugs

    def get_device_infos(self, serial: str | None = None) -> JsonDict:
        """Load all devices and build dict per device serial."""
        devices = self._get_page_list()
        result: dict[str, Any] = {}

        for device in devices.get("deviceInfos", []) or []:
            _serial = device["deviceSerial"]
            _res_id_list = {
                item
                for item in devices.get("CLOUD", {})
                if devices["CLOUD"][item].get("deviceSerial") == _serial
            }
            _res_id = _res_id_list.pop() if _res_id_list else "NONE"

            result[_serial] = {
                "CLOUD": {_res_id: devices.get("CLOUD", {}).get(_res_id, {})},
                "VTM": {_res_id: devices.get("VTM", {}).get(_res_id, {})},
                "P2P": devices.get("P2P", {}).get(_serial, {}),
                "CONNECTION": devices.get("CONNECTION", {}).get(_serial, {}),
                "KMS": devices.get("KMS", {}).get(_serial, {}),
                "STATUS": devices.get("STATUS", {}).get(_serial, {}),
                "TIME_PLAN": devices.get("TIME_PLAN", {}).get(_serial, {}),
                "CHANNEL": {_res_id: devices.get("CHANNEL", {}).get(_res_id, {})},
                "QOS": devices.get("QOS", {}).get(_serial, {}),
                "NODISTURB": devices.get("NODISTURB", {}).get(_serial, {}),
                "FEATURE": devices.get("FEATURE", {}).get(_serial, {}),
                "UPGRADE": devices.get("UPGRADE", {}).get(_serial, {}),
                "FEATURE_INFO": devices.get("FEATURE_INFO", {}).get(_serial, {}),
                "SWITCH": devices.get("SWITCH", {}).get(_serial, {}),
                "CUSTOM_TAG": devices.get("CUSTOM_TAG", {}).get(_serial, {}),
                "VIDEO_QUALITY": {_res_id: devices.get("VIDEO_QUALITY", {}).get(_res_id, {})},
                "resourceInfos": [
                    item
                    for item in (devices.get("resourceInfos") or [])
                    if isinstance(item, dict) and item.get("deviceSerial") == _serial
                ],  # Could be more than one
                "WIFI": devices.get("WIFI", {}).get(_serial, {}),
                "deviceInfos": device,
            }
            # Nested keys are still encoded as JSON strings
            try:
                support_ext = result[_serial].get("deviceInfos", {}).get("supportExt")
                if isinstance(support_ext, str) and support_ext:
                    result[_serial]["deviceInfos"]["supportExt"] = json.loads(support_ext)
            except (TypeError, ValueError):
                # Leave as-is if not valid JSON
                pass
            convert_to_dict(result[_serial]["STATUS"].get("optionals"))

        if not serial:
            return result

        return cast(dict[Any, Any], result.get(serial, {}))

    def get_device_records(
        self, serial: str | None = None
    ) -> dict[str, EzvizDeviceRecord] | EzvizDeviceRecord | JsonDict:
        """Return devices as EzvizDeviceRecord mapping (or single record).

        Falls back to raw when a specific serial is requested but not found.
        """
        devices = self.get_device_infos()
        records = build_device_records_map(devices)
        if serial is None:
            return records
        return records.get(serial) or devices.get(serial, {})

    def get_accessory(
        self,
        serial: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve accessory information linked to a device."""

        path = f"{API_ENDPOINT_DEVICE_ACCESSORY_LINK}{serial}/{local_index}/1/linked/info"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get accessory info")
        return json_output

    def get_dev_config(
        self,
        serial: str,
        channel: int,
        key: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve a devconfig value by key."""

        params = {"key": key}
        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVCONFIG_BY_KEY}{serial}/{channel}/op",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get devconfig value")
        return json_output

    def ptz_control(self, command: str, serial: str, action: str, speed: int = 5) -> Any:
        """PTZ Control by API."""
        if command is None:
            raise PyEzvizError("Trying to call ptzControl without command")
        if action is None:
            raise PyEzvizError("Trying to call ptzControl without action")

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_PTZCONTROL}",
            data={
                "command": command,
                "action": action,
                "channelNo": 1,
                "speed": speed,
                "uuid": str(uuid4()),
                "serial": serial,
            },
            retry_401=False,
        )

        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(json_output),
            "ptz_control",
        )

        return True

    def capture_picture(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Trigger a snapshot capture on the device."""

        path = f"/v3/devconfig/v1/{serial}/{channel}/capture"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not capture picture")
        return json_output

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
        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_CAM_ENCRYPTKEY,
                data={
                    "checkcode": smscode,
                    "serial": serial,
                    "clientNo": "web_site",
                    "clientType": 3,
                    "netType": "WIFI",
                    "featureCode": FEATURE_CODE,
                    "sessionId": self._token.get("session_id"),
                },
                retry_401=True,
                max_retries=0,
            )

            code = str(json_output.get("resultCode"))
            if code == "20002":
                raise EzvizAuthVerificationCode(f"MFA code required: Got {json_output})")
            if code == "2009":
                raise DeviceException(f"Device not reachable: Got {json_output})")
            if code == "0":
                return json_output.get("encryptkey")
            if code == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Http_retry: serial=%s code=%s msg=%s",
                    serial,
                    code,
                    "cam_key_not_found",
                )
                continue
            raise PyEzvizError(f"Could not get camera encryption key: Got {json_output})")

        raise PyEzvizError("Could not get camera encryption key: exceeded retries")

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

        resp = self._http_request(
            "GET",
            image_url,
            retry_401=False,
            max_retries=0,
        )
        image_data = resp.content
        if not decrypt or not image_data or HIK_ENCRYPTION_HEADER not in image_data:
            return image_data

        key = encryption_key
        if key is None:
            if not serial:
                raise PyEzvizError("Camera serial or encryption key is required to decrypt image")
            key = self.get_cam_key(serial, smscode=smscode, max_retries=max_retries)
        return decrypt_image(image_data, key)

    def save_clip(  # noqa: PLR0913
        self,
        serial: str,
        output: str | Path | BinaryIO,
        *,
        source: ClipSource = "local-sdk",
        output_format: ClipOutputFormat | None = None,
        duration_seconds: float | None = 10.0,
        max_packets: int | None = None,
        channel: int = 1,
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
        hcnetsdk_h264_wait_for_clean_idr_window: bool = False,
        hcnetsdk_h264_clean_idr_wait_seconds: float = 60.0,
        hcnetsdk_video_trim_to_clean_window: bool | None = None,
        hcnetsdk_video_clean_window_preroll_seconds: float | None = None,
        hcnetsdk_video_clean_window_max_windows: int | None = None,
        hcnetsdk_video_wait_for_clean_window: bool | None = None,
        hcnetsdk_video_clean_window_wait_seconds: float | None = None,
        cloud_client_type: int = 9,
        cloud_token_index: int = 0,
        cloud_refresh_vtm: bool = True,
        local_sdk_ecdh_receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        local_sdk_ecdh_send_init: bool = False,
        local_sdk_ecdh_max_prefix_bytes: int = 4096,
        local_sdk_ecdh_max_frames: int | None = None,
    ) -> SaveMediaResult:
        """Save a local camera clip to a path or binary file object.

        ``source="local-sdk"`` uses the direct-local 9010/9020 SDK path.
        ``source="cloud"`` uses the EZVIZ VTM cloud live stream path.
        ``source="hcnetsdk-command-port"`` consumes complete caller-supplied
        port-8000 HCNetSDK bootstrap command frames, then remuxes the command
        port media stream to MPEG-TS.
        When omitted, ``output_format`` defaults to MPEG-PS for
        ``source="local-sdk-ecdh"`` and MPEG-TS for other sources.

        This long-form signature is retained for compatibility. New code can
        group the same settings with :meth:`save_clip_with_options`.

        When ``nalu_header_size`` is omitted, cloud decryption auto-detects the
        clear codec header while local sources retain the legacy ``0`` default.
        Passing ``0`` or ``None`` explicitly preserves that exact choice.
        """

        if nalu_header_size is _SOURCE_DEFAULT_NALU_HEADER_SIZE:
            nalu_header_size = None if source == "cloud" else 0

        if output_format is None:
            output_format = "mpegps" if source == "local-sdk-ecdh" else "mpegts"
        mux_options = MediaMuxOptions(
            output_format=output_format,
            ffmpeg_path=ffmpeg_path,
        )

        source_options: ClipSourceOptions
        if source == "local-sdk":
            source_options = LocalSdkClipSource(
                cas_serial=cas_serial,
                register_p2p_session=register_p2p_session,
                p2p_register_max_retries=p2p_register_max_retries,
                timeout=timeout,
                smscode=smscode,
            )
        elif source == "local-sdk-ecdh":
            source_options = LocalSdkEcdhClipSource(
                cas_serial=cas_serial,
                register_p2p_session=register_p2p_session,
                p2p_register_max_retries=p2p_register_max_retries,
                timeout=timeout,
                smscode=smscode,
                receiver_port=local_sdk_ecdh_receiver_port,
                send_init=local_sdk_ecdh_send_init,
                max_prefix_bytes=local_sdk_ecdh_max_prefix_bytes,
                max_frames=local_sdk_ecdh_max_frames,
            )
        elif source == "hcnetsdk-command-port":
            trim_to_clean_window = (
                hcnetsdk_h264_trim_to_clean_idr_window
                if hcnetsdk_video_trim_to_clean_window is None
                else hcnetsdk_video_trim_to_clean_window
            )
            clean_window_preroll_seconds = (
                hcnetsdk_h264_clean_idr_preroll_seconds
                if hcnetsdk_video_clean_window_preroll_seconds is None
                else hcnetsdk_video_clean_window_preroll_seconds
            )
            clean_window_max_windows = (
                hcnetsdk_h264_clean_idr_max_windows
                if hcnetsdk_video_clean_window_max_windows is None
                else hcnetsdk_video_clean_window_max_windows
            )
            wait_for_clean_window = (
                hcnetsdk_h264_wait_for_clean_idr_window
                if hcnetsdk_video_wait_for_clean_window is None
                else hcnetsdk_video_wait_for_clean_window
            )
            clean_window_wait_seconds = (
                hcnetsdk_h264_clean_idr_wait_seconds
                if hcnetsdk_video_clean_window_wait_seconds is None
                else hcnetsdk_video_clean_window_wait_seconds
            )
            mux_options = MediaMuxOptions(
                output_format=output_format,
                ffmpeg_path=ffmpeg_path,
                h264_skip_initial_idr_windows=(
                    hcnetsdk_h264_skip_initial_idr_windows
                ),
                h264_trim_to_clean_idr_window=trim_to_clean_window,
                h264_clean_idr_preroll_seconds=clean_window_preroll_seconds,
                h264_clean_idr_max_windows=clean_window_max_windows,
                h264_wait_for_clean_idr_window=wait_for_clean_window,
                h264_clean_idr_wait_seconds=clean_window_wait_seconds,
            )
            source_options = HcNetSdkCommandPortClipSource(
                timeout=timeout,
                host=host,
                command_port=command_port,
                command_frames=hcnetsdk_command_frames,
                command_plan=hcnetsdk_command_plan,
                generated_plan=hcnetsdk_command_generated_plan,
                command_password=hcnetsdk_command_password,
                local_ip=hcnetsdk_local_ip,
                read_response_after_each=hcnetsdk_read_response_after_each,
                metadata_callback=hcnetsdk_command_metadata_callback,
            )
        elif source == "cloud":
            source_options = CloudClipSource(
                timeout=timeout,
                client_type=cloud_client_type,
                token_index=cloud_token_index,
                refresh_vtm=cloud_refresh_vtm,
                smscode=smscode,
            )
        else:
            raise PyEzvizError(f"Unsupported clip source: {source}")

        clip_options = ClipOptions(
            source=source_options,
            capture=CaptureLimits(
                max_packets=(
                    max_packets
                    if max_packets is None
                    or is_positive_capture_count_bound(max_packets)
                    else None
                ),
                duration_seconds=(
                    duration_seconds
                    if duration_seconds is None
                    or is_positive_finite_duration_bound(duration_seconds)
                    else None
                ),
            ),
            decode=MediaDecodeOptions(
                decrypt_video=decrypt_video,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
            ),
            mux=mux_options,
            channel=channel,
        )
        if (
            max_packets is not None
            and not is_positive_capture_count_bound(max_packets)
        ) or (
            duration_seconds is not None
            and not is_positive_finite_duration_bound(duration_seconds)
        ):
            clip_options = _LegacyClipOptions.from_options(
                clip_options,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
            )
        return self.save_clip_with_options(serial, output, clip_options)

    def save_clip_with_options(
        self,
        serial: str,
        output: str | Path | BinaryIO,
        options: ClipOptions,
    ) -> SaveMediaResult:
        """Save a camera clip from a grouped, typed configuration."""

        if options.capture.max_bytes is not None:
            raise PyEzvizError("save_clip_with_options does not support CaptureLimits.max_bytes")
        if options.decode.decrypt_hevc_parameter_sets:
            raise PyEzvizError(
                "save_clip_with_options does not support "
                "MediaDecodeOptions.decrypt_hevc_parameter_sets"
            )

        source = options.source
        decode = options.decode
        mux = options.resolved_mux()
        default_mux = MediaMuxOptions()
        if not isinstance(source, HcNetSdkCommandPortClipSource) and (
            mux.h264_skip_initial_idr_windows
            or mux.h264_trim_to_clean_idr_window
            or mux.h264_clean_idr_preroll_seconds
            or mux.h264_clean_idr_max_windows
            != default_mux.h264_clean_idr_max_windows
            or mux.h264_wait_for_clean_idr_window
            or mux.h264_clean_idr_wait_seconds
            != default_mux.h264_clean_idr_wait_seconds
        ):
            raise PyEzvizError(
                "H.264 clean-window mux options require "
                "HcNetSdkCommandPortClipSource"
            )
        if isinstance(source, LocalSdkClipSource):
            return self._save_local_sdk_clip(
                serial,
                output,
                output_format=mux.output_format,
                duration_seconds=options.duration_seconds,
                max_packets=options.max_packets,
                channel=options.channel,
                ffmpeg_path=mux.ffmpeg_path,
                decrypt_video=decode.decrypt_video,
                media_key=decode.media_key,
                nalu_header_size=decode.nalu_header_size,
                cas_serial=source.cas_serial,
                register_p2p_session=source.register_p2p_session,
                p2p_register_max_retries=source.p2p_register_max_retries,
                timeout=source.timeout,
                smscode=source.smscode,
            )
        if isinstance(source, LocalSdkEcdhClipSource):
            return self._save_local_sdk_ecdh_clip(
                serial,
                output,
                output_format=mux.output_format,
                duration_seconds=options.duration_seconds,
                max_packets=options.max_packets,
                max_frames=source.max_frames,
                channel=options.channel,
                cas_serial=source.cas_serial,
                register_p2p_session=source.register_p2p_session,
                p2p_register_max_retries=source.p2p_register_max_retries,
                timeout=source.timeout,
                receiver_port=source.receiver_port,
                send_init=source.send_init,
                max_prefix_bytes=source.max_prefix_bytes,
                ffmpeg_path=mux.ffmpeg_path,
                decrypt_video=decode.decrypt_video,
                media_key=decode.media_key,
                nalu_header_size=decode.nalu_header_size,
                smscode=source.smscode,
            )
        if isinstance(source, HcNetSdkCommandPortClipSource):
            return self._save_hcnetsdk_command_port_clip(
                serial,
                output,
                output_format=mux.output_format,
                duration_seconds=options.duration_seconds,
                max_packets=options.max_packets,
                channel=options.channel,
                ffmpeg_path=mux.ffmpeg_path,
                decrypt_video=decode.decrypt_video,
                media_key=decode.media_key,
                nalu_header_size=decode.nalu_header_size,
                timeout=source.timeout,
                host=source.host,
                command_port=source.command_port,
                command_frames=source.command_frames,
                command_plan=source.command_plan,
                generated_plan=source.generated_plan,
                command_password=source.command_password,
                local_ip=source.local_ip,
                read_response_after_each=source.read_response_after_each,
                metadata_callback=source.metadata_callback,
                h264_skip_initial_idr_windows=mux.h264_skip_initial_idr_windows,
                h264_trim_to_clean_idr_window=mux.h264_trim_to_clean_idr_window,
                h264_clean_idr_preroll_seconds=(mux.h264_clean_idr_preroll_seconds),
                h264_clean_idr_max_windows=mux.h264_clean_idr_max_windows,
                h264_wait_for_clean_idr_window=mux.h264_wait_for_clean_idr_window,
                h264_clean_idr_wait_seconds=mux.h264_clean_idr_wait_seconds,
            )
        if isinstance(source, CloudClipSource):
            return self._save_cloud_clip(
                serial,
                output,
                output_format=mux.output_format,
                duration_seconds=options.duration_seconds,
                max_packets=options.max_packets,
                channel=options.channel,
                ffmpeg_path=mux.ffmpeg_path,
                decrypt_video=decode.decrypt_video,
                media_key=decode.media_key,
                nalu_header_size=decode.nalu_header_size,
                timeout=source.timeout,
                client_type=source.client_type,
                token_index=source.token_index,
                refresh_vtm=source.refresh_vtm,
                smscode=source.smscode,
            )
        raise PyEzvizError(f"Unsupported clip source options: {type(source).__name__}")

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
    ) -> SaveMediaResult:
        """Save a clip through the local SDK ECDH stream path."""

        resolved_max_frames = max_frames if max_frames is not None else max_packets
        start_position = None
        if isinstance(output, str | Path):
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as output_file:
                copy_local_sdk_ecdh_stream_from_client(
                    self,
                    serial,
                    output_file,
                    cas_serial=cas_serial,
                    channel=channel,
                    receiver_port=receiver_port,
                    send_init=send_init,
                    register_p2p_session=register_p2p_session,
                    p2p_register_max_retries=p2p_register_max_retries,
                    timeout=timeout,
                    max_prefix_bytes=max_prefix_bytes,
                    max_packets=max_packets,
                    max_frames=resolved_max_frames,
                    duration_seconds=duration_seconds,
                    output_format=output_format,
                    decrypt_video=decrypt_video,
                    media_key=media_key,
                    ffmpeg_path=ffmpeg_path,
                    nalu_header_size=nalu_header_size,
                    smscode=smscode,
                )
        else:
            start_position = _binary_position(output)
            copy_local_sdk_ecdh_stream_from_client(
                self,
                serial,
                output,
                cas_serial=cas_serial,
                channel=channel,
                receiver_port=receiver_port,
                send_init=send_init,
                register_p2p_session=register_p2p_session,
                p2p_register_max_retries=p2p_register_max_retries,
                timeout=timeout,
                max_prefix_bytes=max_prefix_bytes,
                max_packets=max_packets,
                max_frames=resolved_max_frames,
                duration_seconds=duration_seconds,
                output_format=output_format,
                decrypt_video=decrypt_video,
                media_key=media_key,
                ffmpeg_path=ffmpeg_path,
                nalu_header_size=nalu_header_size,
                smscode=smscode,
            )

        return {
            "ok": True,
            "kind": "clip",
            "serial": serial,
            "channel": channel,
            "output": _output_name(output),
            "bytes": _bytes_written_to_output(output, start_position=start_position),
            "source": "local-sdk-ecdh",
            "format": output_format,
            "duration_seconds": duration_seconds,
            "content_type": _content_type_for_output(
                output,
                default="video/mpeg",
            ),
        }

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
    ) -> SaveMediaResult:
        """Save a clip through the direct-local SDK path."""

        start_position = None
        if isinstance(output, str | Path):
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("wb") as output_file:
                copy_local_sdk_stream_from_client(
                    self,
                    serial,
                    output_file,
                    output_format=output_format,
                    decrypt_video=decrypt_video,
                    media_key=media_key,
                    nalu_header_size=nalu_header_size,
                    channel=channel,
                    cas_serial=cas_serial,
                    register_p2p_session=register_p2p_session,
                    p2p_register_max_retries=p2p_register_max_retries,
                    timeout=timeout,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    ffmpeg_path=ffmpeg_path,
                    smscode=smscode,
                )
        else:
            start_position = _binary_position(output)
            copy_local_sdk_stream_from_client(
                self,
                serial,
                output,
                output_format=output_format,
                decrypt_video=decrypt_video,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
                channel=channel,
                cas_serial=cas_serial,
                register_p2p_session=register_p2p_session,
                p2p_register_max_retries=p2p_register_max_retries,
                timeout=timeout,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                ffmpeg_path=ffmpeg_path,
                smscode=smscode,
            )

        return {
            "ok": True,
            "kind": "clip",
            "serial": serial,
            "channel": channel,
            "output": _output_name(output),
            "bytes": _bytes_written_to_output(output, start_position=start_position),
            "source": "local-sdk",
            "format": output_format,
            "duration_seconds": duration_seconds,
            "content_type": _content_type_for_output(
                output,
                default="video/mp2t" if output_format == "mpegts" else "video/mpeg",
            ),
        }

    def _save_hcnetsdk_command_port_clip(  # noqa: PLR0912, PLR0913
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
    ) -> SaveMediaResult:
        """Save a clip through caller-supplied port-8000 HCNetSDK frames."""

        if output_format != "mpegts":
            raise PyEzvizError("source='hcnetsdk-command-port' currently writes MPEG-TS only")
        if decrypt_video and media_key is None:
            raise PyEzvizError("source='hcnetsdk-command-port' decrypt_video requires media_key")
        if decrypt_video:
            h264_clean_idr_capture_budgets(
                duration_seconds=duration_seconds,
                h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
                h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
                h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
                h264_clean_idr_max_windows=h264_clean_idr_max_windows,
                h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
                h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
            )
        if decrypt_video and not has_positive_finite_capture_bound(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        ):
            raise PyEzvizError(
                "source='hcnetsdk-command-port' encrypted capture requires a positive "
                "finite duration_seconds or max_packets"
            )

        frames = tuple(command_frames or ())
        supplied_modes = sum(
            bool(mode)
            for mode in (
                frames,
                command_plan is not None,
                generated_plan is not None,
            )
        )
        if supplied_modes != 1:
            raise PyEzvizError(
                "source='hcnetsdk-command-port' requires exactly one of "
                "hcnetsdk_command_frames, hcnetsdk_command_plan, or "
                "hcnetsdk_command_generated_plan"
            )
        if generated_plan is not None and command_password is None:
            raise PyEzvizError(
                "source='hcnetsdk-command-port' generated plans require hcnetsdk_command_password"
            )
        endpoint = self._hcnetsdk_command_port_endpoint(
            serial,
            host=host,
            command_port=command_port,
        )
        start_position = None
        if isinstance(output, str | Path):
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            stream_context = self._open_hcnetsdk_command_port_clip_stream(
                endpoint,
                frames=frames,
                command_plan=command_plan,
                generated_plan=generated_plan,
                command_password=command_password,
                timeout=timeout,
                local_ip=local_ip,
                read_response_after_each=read_response_after_each,
            )
            with stream_context as stream, output_path.open("wb") as output_file:
                metadata_stream = (
                    _LocalStreamPacketMetadataRecorder(stream)
                    if metadata_callback is not None
                    else stream
                )
                try:
                    if decrypt_video:
                        assert media_key is not None
                        copy_local_stream_to_decrypted_mpegts(
                            metadata_stream,
                            output_file,
                            media_key,
                            ffmpeg_path=ffmpeg_path,
                            nalu_header_size=nalu_header_size,
                            max_packets=max_packets,
                            duration_seconds=duration_seconds,
                            h264_skip_initial_idr_windows=(h264_skip_initial_idr_windows),
                            h264_trim_to_clean_idr_window=(h264_trim_to_clean_idr_window),
                            h264_clean_idr_preroll_seconds=(h264_clean_idr_preroll_seconds),
                            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
                            h264_wait_for_clean_idr_window=(h264_wait_for_clean_idr_window),
                            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
                        )
                    else:
                        copy_local_stream_to_mpegts(
                            metadata_stream,
                            output_file,
                            ffmpeg_path=ffmpeg_path,
                            max_packets=max_packets,
                            duration_seconds=duration_seconds,
                            h264_skip_initial_idr_windows=(h264_skip_initial_idr_windows),
                            h264_trim_to_clean_idr_window=(h264_trim_to_clean_idr_window),
                            h264_clean_idr_preroll_seconds=(h264_clean_idr_preroll_seconds),
                            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
                            h264_wait_for_clean_idr_window=(h264_wait_for_clean_idr_window),
                            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
                        )
                finally:
                    if metadata_callback is not None:
                        metadata_callback(metadata_stream)
        else:
            start_position = _binary_position(output)
            stream_context = self._open_hcnetsdk_command_port_clip_stream(
                endpoint,
                frames=frames,
                command_plan=command_plan,
                generated_plan=generated_plan,
                command_password=command_password,
                timeout=timeout,
                local_ip=local_ip,
                read_response_after_each=read_response_after_each,
            )
            with stream_context as stream:
                metadata_stream = (
                    _LocalStreamPacketMetadataRecorder(stream)
                    if metadata_callback is not None
                    else stream
                )
                try:
                    if decrypt_video:
                        assert media_key is not None
                        copy_local_stream_to_decrypted_mpegts(
                            metadata_stream,
                            output,
                            media_key,
                            ffmpeg_path=ffmpeg_path,
                            nalu_header_size=nalu_header_size,
                            max_packets=max_packets,
                            duration_seconds=duration_seconds,
                            h264_skip_initial_idr_windows=(h264_skip_initial_idr_windows),
                            h264_trim_to_clean_idr_window=(h264_trim_to_clean_idr_window),
                            h264_clean_idr_preroll_seconds=(h264_clean_idr_preroll_seconds),
                            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
                            h264_wait_for_clean_idr_window=(h264_wait_for_clean_idr_window),
                            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
                        )
                    else:
                        copy_local_stream_to_mpegts(
                            metadata_stream,
                            output,
                            ffmpeg_path=ffmpeg_path,
                            max_packets=max_packets,
                            duration_seconds=duration_seconds,
                            h264_skip_initial_idr_windows=(h264_skip_initial_idr_windows),
                            h264_trim_to_clean_idr_window=(h264_trim_to_clean_idr_window),
                            h264_clean_idr_preroll_seconds=(h264_clean_idr_preroll_seconds),
                            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
                            h264_wait_for_clean_idr_window=(h264_wait_for_clean_idr_window),
                            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
                        )
                finally:
                    if metadata_callback is not None:
                        metadata_callback(metadata_stream)

        return {
            "ok": True,
            "kind": "clip",
            "serial": serial,
            "channel": channel,
            "output": _output_name(output),
            "bytes": _bytes_written_to_output(output, start_position=start_position),
            "source": "hcnetsdk-command-port",
            "format": output_format,
            "duration_seconds": duration_seconds,
            "content_type": _content_type_for_output(output, default="video/mp2t"),
            "command_port": endpoint.command_port,
        }

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
        if generated_plan is not None and command_password is not None:
            return open_hcnetsdk_command_port_generated_multi_socket_stream(
                endpoint,
                generated_plan,
                password=command_password,
                timeout=timeout,
                local_ip=local_ip,
            )
        if command_plan is not None:
            return open_hcnetsdk_command_port_multi_socket_stream(
                endpoint,
                command_plan,
                timeout=timeout,
                local_ip=local_ip,
            )
        return open_hcnetsdk_command_port_stream(
            endpoint,
            frames,
            timeout=timeout,
            read_response_after_each=read_response_after_each,
            local_ip=local_ip,
        )

    def _save_cloud_clip(  # noqa: PLR0913
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
        client_type: int,
        token_index: int,
        refresh_vtm: bool,
        smscode: str | int | None,
    ) -> SaveMediaResult:
        """Save a clip through the EZVIZ VTM cloud live stream path."""

        start_position = None
        unbounded_clear_capture = (
            not decrypt_video
            and max_packets is None
            and _legacy_duration_is_effectively_unbounded(duration_seconds)
        )
        capture_duration_seconds = (
            None if unbounded_clear_capture else duration_seconds
        )

        def copy_cloud(output_file: BinaryIO) -> None:
            if output_format == "mpegts":
                copy_cloud_stream_to_mpegts(
                    self,
                    serial,
                    output_file,
                    channel=channel,
                    client_type=client_type,
                    token_index=token_index,
                    refresh_vtm=refresh_vtm,
                    timeout=timeout,
                    ffmpeg_path=ffmpeg_path,
                    max_packets=max_packets,
                    duration_seconds=capture_duration_seconds,
                    decrypt_video=decrypt_video,
                    media_key=media_key,
                    nalu_header_size=nalu_header_size,
                    smscode=smscode,
                )
                return
            copy_cloud_stream_to_mpegps(
                self,
                serial,
                output_file,
                channel=channel,
                client_type=client_type,
                token_index=token_index,
                refresh_vtm=refresh_vtm,
                timeout=timeout,
                max_packets=max_packets,
                duration_seconds=capture_duration_seconds,
                decrypt_video=decrypt_video,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
                smscode=smscode,
            )

        if isinstance(output, str | Path):
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            publication_target = (
                output_path.resolve(strict=False)
                if output_path.is_symlink()
                else output_path
            )
            if unbounded_clear_capture or (
                not decrypt_video
                and _is_existing_non_regular_path(publication_target)
            ):
                with output_path.open("wb") as output_file:
                    copy_cloud(output_file)
            else:
                staging_parent, target_identity = _cloud_clip_staging(publication_target)
                suffix = ".ts" if output_format == "mpegts" else ".ps"
                with _cloud_clip_temporary_directory(staging_parent) as temp_dir:
                    temp_path = Path(temp_dir) / f"capture{suffix}"
                    with temp_path.open("wb") as path_temp_output:
                        copy_cloud(path_temp_output)
                    if decrypt_video and output_format == "mpegts":
                        _require_decodable_saved_video_frame(
                            temp_path,
                            ffmpeg_path=ffmpeg_path,
                        )
                    elif decrypt_video:
                        _require_saved_mpegps_video_payload(temp_path)
                    _publish_validated_cloud_clip(
                        temp_path,
                        publication_target,
                        expected_identity=target_identity,
                    )
        else:
            start_position = _binary_position(output)
            if decrypt_video:
                suffix = ".ts" if output_format == "mpegts" else ".ps"
                with tempfile.TemporaryDirectory(
                    prefix="pyezvizapi-cloud-clip-"
                ) as temp_dir:
                    temp_path = Path(temp_dir) / f"capture{suffix}"
                    with temp_path.open("wb") as binary_temp_output:
                        copy_cloud(binary_temp_output)
                    if output_format == "mpegts":
                        _require_decodable_saved_video_frame(
                            temp_path,
                            ffmpeg_path=ffmpeg_path,
                        )
                    else:
                        _require_saved_mpegps_video_payload(temp_path)
                    with temp_path.open("rb") as validated_input:
                        while chunk := validated_input.read(CLOUD_CLIP_COPY_CHUNK_SIZE):
                            output.write(chunk)
                    output.flush()
            else:
                copy_cloud(output)

        return {
            "ok": True,
            "kind": "clip",
            "serial": serial,
            "channel": channel,
            "output": _output_name(output),
            "bytes": _bytes_written_to_output(output, start_position=start_position),
            "source": "cloud",
            "format": output_format,
            "duration_seconds": duration_seconds,
            "content_type": _content_type_for_output(
                output,
                default="video/mp2t" if output_format == "mpegts" else "video/mpeg",
            ),
            "cloud_client_type": client_type,
            "cloud_token_index": token_index,
            "cloud_refresh_vtm": refresh_vtm,
        }

    def _hcnetsdk_command_port_endpoint(
        self,
        serial: str,
        *,
        host: str | None,
        command_port: int | None,
    ) -> HcNetSdkLanEndpoint:
        """Return a command-port endpoint from overrides or device metadata."""

        if host:
            return HcNetSdkLanEndpoint(
                serial=serial,
                host=host,
                command_port=command_port or 8000,
            )

        device_info = self.get_device_infos(serial)
        device: dict[str, Any] | None = None
        if isinstance(device_info, dict):
            if isinstance(device_info.get("CONNECTION"), dict):
                device = device_info
            else:
                for value in device_info.values():
                    if isinstance(value, dict) and isinstance(value.get("CONNECTION"), dict):
                        device = value
                        break
        if not isinstance(device, dict):
            raise PyEzvizError(
                "Could not find CONNECTION metadata for HCNetSDK command-port stream; provide host"
            )
        endpoint = HcNetSdkLanEndpoint.from_connection(serial, device.get("CONNECTION"))
        if command_port is None:
            return endpoint
        return HcNetSdkLanEndpoint(
            serial=endpoint.serial,
            host=endpoint.host,
            net_host=endpoint.net_host,
            command_port=command_port,
            net_command_port=endpoint.net_command_port,
            stream_port=endpoint.stream_port,
            net_stream_port=endpoint.net_stream_port,
            rtsp_port=endpoint.rtsp_port,
            sdk_tls_port=endpoint.sdk_tls_port,
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

        capture_response: dict[str, Any] | None = None
        selected_image_url = image_url
        if selected_image_url is None:
            capture_response = self.capture_picture(serial, channel, max_retries=1)
            selected_image_url = _first_image_url(capture_response)
            if selected_image_url is None:
                raise PyEzvizError("Camera capture response did not include an image URL")

        image_data = self.download_alarm_image(
            selected_image_url,
            serial,
            decrypt=decrypt,
            smscode=smscode,
            max_retries=1,
        )
        start_position = None
        if isinstance(output, str | Path):
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(image_data)
        else:
            start_position = _binary_position(output)
            output.write(image_data)
            output.flush()

        return {
            "ok": True,
            "kind": "image",
            "serial": serial,
            "channel": channel,
            "output": _output_name(output),
            "bytes": _bytes_written_to_output(output, start_position=start_position),
            "content_type": _content_type_for_output(output, default="image/jpeg"),
            "image_url": selected_image_url,
            "triggered_capture": capture_response is not None,
        }

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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        params: dict[str, int | str | None] = {
            "encrptPwd": encrypt_pwd,
            "msgAuthCode": msg_auth_code,
            "senderType": sender_type,
        }

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_CAM_AUTH_CODE}{serial}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )

        if self._meta_code(json_output) == 80000:
            raise EzvizAuthVerificationCode("Operation requires 2FA check")

        if self._meta_code(json_output) == 2009:
            raise DeviceException(f"Device not reachable: Got {json_output}")

        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not get camera verification key: Got {json_output}")

        return json_output["devAuthCode"]

    def get_2fa_check_code(
        self,
        biz_type: str = "DEVICE_AUTH_CODE",
        username: str | None = None,
        max_retries: int = 0,
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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_2FA_VALIDATE_POST_AUTH,
            data={"bizType": biz_type, "from": username},
            retry_401=True,
            max_retries=max_retries,
        )

        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not request elevated permission: Got {json_output})")

        return json_output

    def create_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Create panoramic image."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        attempts = max(0, max_retries)
        for attempt in range(attempts + 1):
            json_output = self._request_json(
                "POST",
                API_ENDPOINT_CREATE_PANORAMIC,
                data={"deviceSerial": serial},
                retry_401=True,
                max_retries=0,
            )
            result = str(json_output.get("resultCode"))
            if result == "0":
                return json_output
            if result == "-1" and attempt < attempts:
                _LOGGER.warning(
                    "Create panoramic failed on device %s retrying %s/%s",
                    serial,
                    attempt + 1,
                    attempts,
                )
                continue
            raise PyEzvizError(
                f"Could not send command to create panoramic photo: Got {json_output})"
            )
        raise PyEzvizError("Could not send command to create panoramic photo: exceeded retries")

    def return_panoramic(self, serial: str, max_retries: int = 0) -> Any:
        """Return panoramic image url list."""
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_RETURN_PANORAMIC,
                data={"deviceSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="panoramic_busy_or_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) != "0":
            raise PyEzvizError(f"Could retrieve panoramic photo: Got {json_output})")
        return json_output

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
        if not 0 <= x_axis <= 1:
            raise PyEzvizError(
                f"Invalid X coordinate: {x_axis}: Should be between 0 and 1 inclusive"
            )

        if not 0 <= y_axis <= 1:
            raise PyEzvizError(
                f"Invalid Y coordinate: {y_axis}: Should be between 0 and 1 inclusive"
            )

        json_result = self._iot_request(
            "PUT",
            API_ENDPOINT_IOT_ACTION,
            serial,
            resource_identifier,
            local_index,
            "PTZManualCtrl",
            "CtrlPTZ3DPosition",
            payload={
                "positionCtrlType": "point",
                "positionPoint": {
                    "x": x_axis,
                    "y": y_axis,
                },
                "positionRect": {
                    "height": 1.0,
                    "width": 1.0,
                    "x": 0.0,
                    "y": 0.0,
                },
            },
            max_retries=max_retries,
            error_message="Could not move PTZ to coordinates",
        )

        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(json_result),
            "ptz_control_coordinates",
        )

        return True

    def get_door_lock_users(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve users associated with a door lock device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DOORLOCK_USERS}{serial}/users",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get door lock users")
        return json_output

    def get_terminals(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve account terminal information."""

        return self._request_json(
            "GET",
            API_ENDPOINT_TERMINAL_INFO,
            params={"limit": limit, "offset": offset},
            retry_401=True,
            max_retries=max_retries,
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

        json_output = self.get_terminals(
            limit=limit,
            offset=offset,
            max_retries=max_retries,
        )
        terminals = json_output.get("terminals")
        if not isinstance(terminals, list) or not terminals:
            raise PyEzvizError("No terminal information found")

        terminal_items = [
            item
            for item in terminals
            if isinstance(item, Mapping)
            and str(item.get("sign") or "").strip()
            and str(item.get("userId") or "").strip()
        ]
        if not terminal_items:
            raise PyEzvizError("No terminal bind information found")

        if terminal_name:
            expected_name = terminal_name.casefold()
            terminal_items = [
                item
                for item in terminal_items
                if str(item.get("name") or item.get("terminalName") or "").casefold()
                == expected_name
            ]
            if not terminal_items:
                raise PyEzvizError(f"No terminal bind information found for {terminal_name}")

        terminal = max(
            terminal_items,
            key=lambda item: str(item.get("lastModifytime") or item.get("lastModifyTime") or ""),
        )
        sign = str(terminal["sign"]).strip()
        terminal_user_id = str(terminal["userId"]).strip()
        user_name = terminal.get("name") or terminal.get("terminalName") or terminal_user_id
        return f"{sign}{terminal_user_id}", str(user_name)

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
        route_resource = resource_id or "Video"
        route_index = str(local_index if local_index is not None else 1)
        effective_bind_code = bind_code
        effective_user_name = user_id
        if effective_bind_code is None and use_terminal_bind:
            try:
                effective_bind_code, effective_user_name = self.get_latest_terminal_bind(
                    terminal_name=terminal_filter_name
                )
            except (requests.RequestException, HTTPError, PyEzvizError) as err:
                _LOGGER.debug(
                    "Terminal bind unavailable for %s, using legacy bind code: %s",
                    serial,
                    err,
                )

        if effective_bind_code is None:
            effective_bind_code = f"{FEATURE_CODE}{user_id}"

        un_lock_info: dict[str, Any] = {
            "bindCode": effective_bind_code,
            "lockNo": lock_no,
            "streamToken": stream_token or "",
            "userName": effective_user_name,
        }
        if lock_type:
            un_lock_info["type"] = lock_type
        payload = {"unLockInfo": un_lock_info}
        json_result = self._request_json(
            "PUT",
            f"{API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{API_ENDPOINT_REMOTE_UNLOCK}",
            json_body=payload,
            retry_401=True,
            max_retries=0,
        )
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._response_code(json_result),
            "remote_unlock",
        )
        return True

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

        route_resource = resource_id or "Video"
        route_index = str(local_index if local_index is not None else 1)
        un_lock_info: dict[str, Any] = {
            "bindCode": f"{FEATURE_CODE}{user_id}",
            "lockNo": lock_no,
            "streamToken": stream_token or "",
            "userName": user_id,
        }
        if lock_type:
            un_lock_info["type"] = lock_type
        payload = {"unLockInfo": un_lock_info}
        json_result = self._request_json(
            "PUT",
            f"{API_ENDPOINT_IOT_ACTION}{serial}/{route_resource}/{route_index}{API_ENDPOINT_REMOTE_LOCK}",
            json_body=payload,
            retry_401=True,
            max_retries=0,
        )
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._response_code(json_result),
            "remote_lock",
        )
        return True

    def get_remote_unbind_progress(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Check progress of a remote unbind request."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_REMOTE_UNBIND_PROGRESS}{serial}/progress",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get unbind progress")
        return json_output

    def enable_channel99(self, sms_code: int | None = None) -> JsonDict:
        """Prepare an Android-profile login for channel-99 push.

        Legacy web-profile tokens require a fresh credential login (and MFA if
        required). Merely changing headers does not migrate an existing session.
        Persist the returned token before starting push reception.
        """
        with self._token_lock:
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
        with self._token_lock:
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
                    self._timeout,
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
        with self._token_lock:
            try:
                req = self._session.delete(
                    url=f"https://{self._token['api_url']}{API_ENDPOINT_LOGOUT}",
                    timeout=self._timeout,
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

            try:
                json_result = req.json()

            except ValueError as err:
                raise PyEzvizError(
                    "Impossible to decode response: "
                    + str(err)
                    + "\nResponse was: "
                    + str(req.text)
                ) from err

            self.close_session()

            return bool(json_result["meta"]["code"] == 200)

    def set_camera_defence_old(self, serial: str, enable: int) -> bool:
        """Enable/Disable motion detection on camera."""
        cas_client = EzvizCAS(cast(dict[str, Any], self._token))
        cas_client.set_camera_defence_state(serial, enable)

        return True

    def api_set_defence_schedule(
        self, serial: str, schedule: str, enable: int, max_retries: int = 0
    ) -> bool:
        """Set defence schedules."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        schedulestring = (
            '{"CN":0,"EL":' + str(enable) + ',"SS":"' + serial + '","WP":[' + schedule + "]}]}"
        )
        json_output = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_SET_DEFENCE_SCHEDULE,
                data={"devTimingPlan": schedulestring},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log="defence_schedule_offline_or_unreachable",
            serial=serial,
        )
        if str(json_output.get("resultCode")) not in ("0", 0):
            raise PyEzvizError(f"Could not set the schedule: Got {json_output})")
        return True

    def api_set_defence_mode(
        self,
        mode: DefenseModeType | int,
        *,
        visual_alarm: int | None = None,
        sound_mode: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Set defence mode for all devices. The alarm panel from main page is used."""
        data: dict[str, Any] = {
            "groupId": -1,
            "mode": int(mode.value if isinstance(mode, DefenseModeType) else mode),
        }
        if visual_alarm is not None:
            data["visualAlarm"] = visual_alarm
        if sound_mode is not None:
            data["soundMode"] = sound_mode

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SWITCH_DEFENCE_MODE,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set defence mode")
        return True

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

        data: dict[str, Any] = {
            "groupId": group_id,
            "mode": mode,
        }
        if visual_alarm is not None:
            data["visualAlarm"] = visual_alarm
        if sound_mode is not None:
            data["soundMode"] = sound_mode

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SWITCH_DEFENCE_MODE,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not switch defence mode")
        return json_output

    def do_not_disturb(
        self,
        serial: str,
        enable: int = 1,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set do not disturb on camera with specified serial."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_V3_ALARMS}{serial}/{channelno}{API_ENDPOINT_DO_NOT_DISTURB}",
            data={"enable": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set do not disturb")
        return True

    def set_answer_call(
        self,
        serial: str,
        enable: int = 1,
        max_retries: int = 0,
    ) -> bool:
        """Set answer call on camera with specified serial."""
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_CALLING_NOTIFY}{serial}{API_ENDPOINT_DO_NOT_DISTURB}",
            data={"deviceSerial": serial, "switchStatus": enable},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set answer call")

        return True

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
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")
        url_path = f"{API_ENDPOINT_INTELLIGENT_APP}{serial}/{resource_id}/{app_name}"
        # Determine which method to call based on the parameter.
        action = action.lower()
        if action == "add":
            method = "PUT"
        elif action == "remove":
            method = "DELETE"
        else:
            raise PyEzvizError(f"Invalid action '{action}'. Use 'add' or 'remove'.")

        json_output = self._request_json(method, url_path, retry_401=True, max_retries=max_retries)
        self._ensure_ok(json_output, f"Could not {action} intelligent app")

        return True

    def _resolve_resource_id(self, serial: str, resource_id: str | None) -> str:
        """Resolve the intelligent app resource id for a given camera."""

        if resource_id:
            return resource_id

        camera = self._cameras.get(serial)
        if not camera:
            raise PyEzvizError(
                f"Unknown camera serial {serial}. Call load_devices/load_cameras first"
            )

        resource_infos = camera.get("resourceInfos") or []
        for item in resource_infos:
            if isinstance(item, dict) and item.get("resourceId"):
                return cast(str, item["resourceId"])

        legacy = camera.get("resouceid") or camera.get("resource_id")
        if isinstance(legacy, str) and legacy:
            return legacy

        raise PyEzvizError("Unable to determine resourceId for intelligent app operation")

    def set_intelligent_app_state(
        self,
        serial: str,
        app_name: str,
        enabled: bool,
        resource_id: str | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable or disable an intelligent detection app on a camera."""

        resolved_id = self._resolve_resource_id(serial, resource_id)
        action = "add" if enabled else "remove"
        return self.manage_intelligent_app(
            serial,
            resolved_id,
            app_name,
            action=action,
            max_retries=max_retries,
        )

    def device_mirror(
        self,
        serial: str,
        channel: int,
        command: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Send a mirror command using the basics API."""

        path = f"{API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/{command}/mirror"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set mirror state")
        return json_output

    def flip_image(
        self,
        serial: str,
        channel: int = 1,
        max_retries: int = 0,
    ) -> bool:
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
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICE_BASICS}{serial}/{channel}/CENTER/mirror",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not flip image on camera")

        return True

    def _resolve_osd_text(
        self,
        serial: str,
        *,
        name: str | None = None,
        camera_data: Mapping[str, Any] | None = None,
    ) -> str:
        """Return the preferred OSD label for a camera."""

        if isinstance(name, str) and name.strip():
            return name.strip()

        candidates: list[Mapping[str, Any]] = []

        if isinstance(camera_data, Mapping):
            candidates.append(camera_data)

        cached = self._cameras.get(serial)
        if isinstance(cached, Mapping):
            candidates.append(cached)

        for data in candidates:
            direct = data.get("name")
            if isinstance(direct, str) and direct.strip():
                return direct.strip()

            device_info = data.get("deviceInfos")
            if isinstance(device_info, Mapping):
                alt = device_info.get("name")
                if isinstance(alt, str) and alt.strip():
                    return alt.strip()

            optionals = optionals_mapping(data)
            osd_entries = optionals.get("OSD")
            if isinstance(osd_entries, Mapping):
                osd_entries = [osd_entries]
            if isinstance(osd_entries, list):
                for entry in osd_entries:
                    if not isinstance(entry, Mapping):
                        continue
                    text = entry.get("name")
                    if isinstance(text, str) and text.strip():
                        return text.strip()

        return serial

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

        if text is not None:
            resolved = text
        elif enabled is False:
            resolved = ""
        else:
            if camera_data is None:
                camera_data = self._cameras.get(serial)
            if camera_data is None:
                raise PyEzvizError(
                    "Camera data unavailable; call load_devices() before setting the OSD"
                )

            resolved = (
                self._resolve_osd_text(
                    serial,
                    name=name,
                    camera_data=camera_data,
                )
                if enabled
                else ""
            )

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_OSD}{serial}/{channel}/osd",
            data={"osd": resolved},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could set osd message on camera")

        return True

    def set_floodlight_brightness(
        self,
        serial: str,
        luminance: int = 50,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool | str:
        """Set brightness on camera with adjustable light."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if luminance not in range(1, 101):
            raise PyEzvizError("Range of luminance is 1-100, got " + str(luminance) + ".")

        response_json = self._request_json(
            "POST",
            f"{API_ENDPOINT_SET_LUMINANCE}{serial}/{channelno}",
            data={"luminance": luminance},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(response_json, "Unable to set brightness")

        return True

    def set_brightness(
        self,
        serial: str,
        luminance: int = 50,
        channelno: int = 1,
        max_retries: int = 0,
    ) -> bool | str:
        """Facade that changes the brightness to light bulbs or cameras' light."""
        device = self._light_bulbs.get(serial)
        if device:
            # the device is a light bulb
            return self.set_device_feature_by_key(
                serial, device["productId"], luminance, "brightness", max_retries
            )

        # assume the device is a camera
        return self.set_floodlight_brightness(serial, luminance, channelno, max_retries)

    def switch_light_status(
        self,
        serial: str,
        enable: int,
        channel_no: int = 0,
        max_retries: int = 0,
    ) -> bool:
        """Facade that turns on/off light bulbs or cameras' light."""
        device = self._light_bulbs.get(serial)
        if device:
            # the device is a light bulb
            return self.set_device_feature_by_key(
                serial, device["productId"], bool(enable), "light_switch", max_retries
            )

        # assume the device is a camera
        return self.switch_status(
            serial, DeviceSwitchType.ALARM_LIGHT.value, enable, channel_no, max_retries
        )

    def detection_sensibility(
        self,
        serial: str,
        sensibility: int = 3,
        type_value: int = 3,
        max_retries: int = 0,
    ) -> bool | str:
        """Set detection sensibility."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sensibility not in [0, 1, 2, 3, 4, 5, 6] and type_value == 0:
            raise PyEzvizError("Unproper sensibility for type 0 (should be within 1 to 6).")
        try:
            with self._token_lock:
                req = self._session.post(
                    url=f"https://{self._token['api_url']}{API_ENDPOINT_DETECTION_SENSIBILITY}",
                    data={
                        "subSerial": serial,
                        "type": type_value,
                        "channelNo": 1,
                        "value": sensibility,
                    },
                    timeout=self._timeout,
                )

            req.raise_for_status()

        except requests.HTTPError as err:
            if err.response.status_code == 401:
                # session is wrong, need to re-log-in
                self.login()
                return self.detection_sensibility(serial, sensibility, type_value, max_retries + 1)

            raise HTTPError from err

        try:
            response_json = req.json()

        except ValueError as err:
            raise PyEzvizError("Could not decode response:" + str(err)) from err

        if response_json["resultCode"] != "0":
            if response_json["resultCode"] == "-1":
                _LOGGER.warning(
                    "Camera %s is offline or unreachable, can't set sensitivity, retrying %s of %s",
                    serial,
                    max_retries,
                    MAX_RETRIES,
                )
                return self.detection_sensibility(serial, sensibility, type_value, max_retries + 1)
            raise PyEzvizError(f"Unable to set detection sensibility. Got: {response_json}")

        return True

    def get_motion_detect_sensitivity(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Get motion detection sensitivity via v1 devconfig endpoint."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_SENSITIVITY}{serial}/{channel}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get motion detect sensitivity")
        return json_output

    def get_motion_detect_sensitivity_dp1s(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Get motion detection sensitivity for DP1S devices."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}/sensitivity",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get DP1S motion sensitivity")
        return json_output

    def set_detection_sensitivity(
        self,
        serial: str,
        channel: int,
        sensitivity_type: int,
        value: int,
        max_retries: int = 0,
    ) -> bool:
        """Set detection sensitivity via v3 devconfig endpoint."""

        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sensitivity_type == 0 and not 1 <= value <= 6:
            raise PyEzvizError("Detection sensitivity must be within 1..6")
        if sensitivity_type != 0 and not 1 <= value <= 100:
            raise PyEzvizError("Detection sensitivity must be within 1..100")

        url_path = f"{API_ENDPOINT_SENSITIVITY}{serial}/{channel}/{sensitivity_type}/{value}"
        json_output = self._request_json(
            "PUT",
            url_path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set detection sensitivity")

        return True

    def get_detection_sensibility(
        self, serial: str, type_value: str = "0", max_retries: int = 0
    ) -> Any:
        """Get detection sensibility notifications."""
        response_json = self._retry_json(
            lambda: self._request_json(
                "POST",
                API_ENDPOINT_DETECTION_SENSIBILITY_GET,
                data={"subSerial": serial},
                retry_401=True,
                max_retries=0,
            ),
            attempts=max_retries,
            should_retry=lambda p: str(p.get("resultCode")) == "-1",
            log=f"Camera {serial} is offline or unreachable",
        )
        if str(response_json.get("resultCode")) != "0":
            raise PyEzvizError(f"Unable to get detection sensibility. Got: {response_json}")

        if response_json.get("algorithmConfig", {}).get("algorithmList"):
            for idx in response_json["algorithmConfig"]["algorithmList"]:
                if idx.get("type") == type_value:
                    return idx.get("value")

        return None

    def get_detector_setting_info(
        self,
        device_serial: str,
        detector_serial: str,
        key: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch a specific configuration key for an A1S detector."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/{detector_serial}/{key}"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get detector setting info")
        return json_output

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

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/detector/{detector_serial}"
        json_output = self._request_json(
            "POST",
            path,
            params={"key": key},
            data={"value": value},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set detector setting info")
        return json_output

    def get_detector_info(
        self,
        detector_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve status/details for an A1S detector."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}detector/{detector_serial}"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get detector info")
        return json_output

    def get_radio_signals(
        self,
        device_serial: str,
        child_device_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return radio signal metrics for a detector connected to a device."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_A1S}{device_serial}/radioSignal"
        json_output = self._request_json(
            "GET",
            path,
            params={"childDevSerial": child_device_serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get radio signals")
        return json_output

    def get_voice_config(
        self,
        product_id: str,
        version: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch voice configuration metadata for a product."""

        params = {"productId": product_id, "version": version}
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_IOT_FEATURE_PRODUCT_VOICE_CONFIG,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get voice config")
        return json_output

    # soundtype: 0 = normal, 1 = intensive, 2 = disabled ... don't ask me why...
    def get_voice_info(
        self,
        serial: str,
        *,
        local_index: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve uploaded custom voice prompts for a device."""

        params: dict[str, Any] = {"deviceSerial": serial}
        if local_index is not None:
            params["localIndex"] = local_index

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get voice list")
        return json_output

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

        data: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceName": voice_name,
            "voiceUrl": voice_url,
        }
        if local_index is not None:
            data["localIndex"] = local_index

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not add voice info")
        return json_output

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

        return self.add_voice_info(
            serial,
            voice_name,
            voice_url,
            local_index=local_index,
            max_retries=max_retries,
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

        data: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceId": voice_id,
            "voiceName": voice_name,
        }
        if local_index is not None:
            data["localIndex"] = local_index

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not update voice info")
        return json_output

    def set_shared_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_name: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Alias for updating shared voices that ensures local index is supplied."""

        return self.set_voice_info(
            serial,
            voice_id,
            voice_name,
            local_index=local_index,
            max_retries=max_retries,
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

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "voiceId": voice_id,
        }
        if voice_url is not None:
            params["voiceUrl"] = voice_url
        if local_index is not None:
            params["localIndex"] = local_index

        json_output = self._request_json(
            "DELETE",
            API_ENDPOINT_SPECIAL_BIZS_VOICES,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not delete voice info")
        return json_output

    def delete_shared_voice_info(
        self,
        serial: str,
        voice_id: int,
        voice_url: str,
        local_index: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Alias for deleting shared voices with required parameters."""

        return self.delete_voice_info(
            serial,
            voice_id,
            voice_url=voice_url,
            local_index=local_index,
            max_retries=max_retries,
        )

    def get_whistle_status_by_channel(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return whistle configuration per channel for a device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_CHANNEL}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get whistle status by channel")
        return json_output

    def get_whistle_status_by_device(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return whistle configuration at the device level."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_GET_WHISTLE_STATUS_BY_DEVICE}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get whistle status by device")
        return json_output

    def set_channel_whistle(
        self,
        serial: str,
        channel_whistles: list[Mapping[str, Any]] | list[dict[str, Any]],
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Configure whistle behaviour for individual channels."""

        if not channel_whistles:
            raise PyEzvizError("channel_whistles must contain at least one entry")

        entries: list[dict[str, Any]] = []
        required_fields = {"channel", "status", "duration", "volume"}
        for item in channel_whistles:
            entry = dict(item)
            entry.setdefault("deviceSerial", serial)
            missing = [field for field in required_fields if field not in entry]
            if missing:
                raise PyEzvizError("channel_whistles entries must include " + ", ".join(missing))
            entries.append(entry)

        payload = {"channelWhistleList": entries}

        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SET_CHANNEL_WHISTLE}",
            json_body=payload,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set channel whistle")
        return json_output

    def set_device_whistle(
        self,
        serial: str,
        *,
        status: int,
        duration: int,
        volume: int,
        max_retries: int = 0,
    ) -> JsonDict:
        """Configure whistle behaviour at the device level."""

        params = {
            "status": status,
            "duration": duration,
            "volume": volume,
        }

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SET_DEVICE_WHISTLE}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set device whistle")
        return json_output

    def stop_whistle(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Stop any ongoing whistle sound."""

        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_STOP_WHISTLE}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not stop whistle")
        return json_output

    def delay_battery_device_sleep(
        self,
        serial: str,
        channel: int,
        sleep_type: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Request additional awake time for a battery-powered device."""

        path = f"{API_ENDPOINT_SPECIAL_BIZS_V1_BATTERY}{serial}/{channel}/{sleep_type}/sleep"
        json_output = self._request_json(
            "PUT",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not delay battery device sleep")
        return json_output

    def get_device_chime_info(
        self,
        serial: str,
        channel: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch chime configuration for a specific channel."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get chime info")
        return json_output

    def set_device_chime_info(
        self,
        serial: str,
        channel: int,
        *,
        sound_type: int,
        duration: int,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update chime type and duration for a channel."""

        data = {
            "type": sound_type,
            "duration": duration,
        }

        json_output = self._request_json(
            "POST",
            f"{API_ENDPOINT_ALARM_DEVICE_CHIME}{serial}/{channel}",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set chime info")
        return json_output

    def set_switch_enable_req(
        self,
        serial: str,
        channel: int,
        enable: int,
        switch_type: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Call the legacy setSwitchEnableReq endpoint."""

        params = {
            "enable": enable,
            "type": switch_type,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/{channel}{API_ENDPOINT_DEVICES_SET_SWITCH_ENABLE}",
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set switch enable request")
        return json_output

    def get_managed_device_info(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return metadata for a managed device (e.g. base station)."""

        path = f"{API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/base"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get managed device info")
        return json_output

    def get_managed_device_ipcs(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """List IPC sub-devices that belong to a managed device."""

        path = f"{API_ENDPOINT_MANAGED_DEVICE_BASE}{serial}/ipcs"
        json_output = self._request_json(
            "GET",
            path,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get managed IPC list")
        return json_output

    def get_devices_status(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch online/offline status for one or more devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_STATUS,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device status")
        return json_output

    def get_device_secret_key_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve KMS secret key metadata for devices."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_KMS,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get device secret key info")
        return json_output

    def get_device_list_encrypt_key(
        self,
        area_id: int,
        form_data: Mapping[str, Any] | bytes | bytearray | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Batch query encrypt keys for devices, matching the mobile client's risk API."""

        headers = {
            **self._session.headers,
            "Content-Type": "application/x-www-form-urlencoded",
            "areaId": str(area_id),
        }
        if isinstance(form_data, (bytes, bytearray, str)):
            body = form_data
        else:
            body = urlencode(form_data, doseq=True)
        req = requests.Request(
            method="POST",
            url=self._url(API_ENDPOINT_DEVICES_ENCRYPTKEY_BATCH),
            headers=headers,
            data=body,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not get device encrypt key list: Got {json_output})")
        return json_output

    def get_p2p_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve P2P info via the device-scoped endpoint."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICES_P2P_INFO,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get P2P info")
        return json_output

    def get_p2p_server_info(
        self,
        serials: list[str] | str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve P2P server info via the userdevices endpoint."""

        if isinstance(serials, (list, tuple, set)):
            serial_param = ",".join(sorted({str(s) for s in serials}))
        else:
            serial_param = str(serials)

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_USERDEVICES_P2P_INFO,
            params={"deviceSerials": serial_param},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get P2P server info")
        return json_output

    def register_p2p_session(
        self,
        *,
        session_id: str | None = None,
        max_retries: int = MAX_RETRIES,
    ) -> JsonDict:
        """Authorize the current cloud session for EZVIZ LAN/P2P operations.

        Some devices reject CAS ``getDevOperationCode`` lookups until the app-style
        P2P registration endpoint has seen the current user ``sessionId``.
        """

        selected_session_id = session_id
        attempts = 0
        while True:
            current_session_id = selected_session_id or self._token.get("session_id")
            if not current_session_id:
                raise PyEzvizError("P2P session registration requires a session_id")

            try:
                json_output = self._request_json(
                    "POST",
                    API_ENDPOINT_P2PBUSINESS_CONFIGURATIONS_P2P,
                    data={"sessionId": str(current_session_id)},
                    retry_401=False,
                )
            except HTTPError as err:
                if self._http_error_status(err) != 401 or attempts >= max_retries:
                    raise
                attempts += 1
                selected_session_id = None
                self.login()
                continue
            self._ensure_ok(json_output, "Could not register P2P session")
            return json_output

    def check_device_upgrade_rule(
        self,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Check firmware upgrade eligibility rules."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_UPGRADE_RULE,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get upgrade rules")
        return json_output

    def get_autoupgrade_switch(
        self,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Return the current auto-upgrade switch settings."""

        json_output = self._request_json(
            "GET",
            API_ENDPOINT_AUTOUPGRADE_SWITCH,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get auto-upgrade switch")
        return json_output

    def set_autoupgrade_switch(
        self,
        auto_upgrade: int,
        time_type: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Update the auto-upgrade switch configuration."""

        data = {
            "autoUpgrade": auto_upgrade,
            "timeType": time_type,
        }

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_AUTOUPGRADE_SWITCH,
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set auto-upgrade switch")
        return json_output

    def get_black_level_list(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Retrieve SD-card black level data for a device."""

        json_output = self._request_json(
            "GET",
            f"{API_ENDPOINT_SDCARD_BLACK_LEVEL}{serial}",
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get black level list")
        return json_output

    def get_time_plan_infos(
        self,
        serial: str,
        channel: int,
        timing_plan_type: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch timing plan information for a device/channel."""

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "timingPlanType": timing_plan_type,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_TIME_PLAN_INFOS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get time plan infos")
        return json_output

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

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "timingPlanType": timing_plan_type,
            "enable": enable,
        }
        if not isinstance(timer_defence_qos, str):
            params["timerDefenceQos"] = json.dumps(timer_defence_qos)
        else:
            params["timerDefenceQos"] = timer_defence_qos

        json_output = self._request_json(
            "PUT",
            API_ENDPOINT_TIME_PLAN_INFOS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set time plan infos")
        return json_output

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

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "channelSerial": channel_serial,
            "startTime": start_time,
            "stopTime": stop_time,
            "size": size,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search records")
        return json_output

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

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "size": size,
            "sortBy": sort_by,
            "requireLabel": require_label,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_V2,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search v2 records")
        return json_output

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

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "recordType": record_type,
            "size": size,
            "version": version,
        }
        if channel_serial is not None:
            params["channelSerial"] = channel_serial
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_COMMON,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search common records")
        return json_output

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

        params: dict[str, Any] = {
            "deviceSerial": serial,
            "channelNo": channel,
            "startTime": start_time,
            "stopTime": stop_time,
            "version": version,
        }
        if record_filter is not None:
            params["filter"] = record_filter
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_STREAMING_RECORDS_INTELLIGENT,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not search intelligent records")
        return json_output

    @staticmethod
    def decode_records_payload(value: str) -> list[Any]:
        """Decode an EZVIZ base64+zlib JSON record-list payload."""

        try:
            raw = base64.b64decode(value, validate=True)
            decoded = zlib.decompress(raw).decode("utf-8").strip()
            parsed = json.loads(decoded)
        except (ValueError, zlib.error, UnicodeDecodeError, json.JSONDecodeError):
            return []
        return parsed if isinstance(parsed, list) else []

    @classmethod
    def extract_record_list(cls, payload: Any) -> list[Any]:
        """Return the first plain or compressed record list in a response."""

        if isinstance(payload, str):
            return cls.decode_records_payload(payload)
        if not isinstance(payload, Mapping):
            return payload if isinstance(payload, list) else []

        records: list[Any] = []
        for key in ("records", "record", "files", "fileList", "videos", "videoList", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                records = value
                break
            if isinstance(value, str):
                nested = cls.decode_records_payload(value)
                if nested:
                    records = nested
                    break
            if isinstance(value, Mapping):
                nested = cls.extract_record_list(value)
                if nested:
                    records = nested
                    break
        if not records:
            for value in payload.values():
                if isinstance(value, Mapping):
                    nested = cls.extract_record_list(value)
                    if nested:
                        records = nested
                        break
        return records

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

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "limit": limit,
            "videoType": video_type,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_CLOUD_VIDEOS_LIST,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get cloud videos")
        return json_output

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

        body = {
            "deviceSerial": serial,
            "channelNo": channel,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
            "videos": [
                {
                    "seqId": video["seqId"],
                    "startTime": video["startTime"],
                    "stopTime": video["stopTime"],
                    "storageVersion": video.get("storageVersion", 2),
                }
                for video in videos
            ],
        }
        json_output = self._request_json(
            "POST",
            API_ENDPOINT_CLOUD_VIDEO_DETAILS,
            json_body=body,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get cloud video details")
        return json_output

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

        params = {
            "deviceSerial": serial,
            "channelNo": channel,
            "supportMultiChannelSharedService": support_multi_channel_shared_service,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_CAMERA_TICKET_INFO,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get camera ticket info")
        return json_output

    @staticmethod
    def _extract_cloud_video_download_url(video: Mapping[str, Any]) -> str | None:
        """Return the first direct HTTP(S) video URL in a cloud video descriptor."""

        media_url_keys = {
            "downloadUrl",
            "downloadURL",
            "fileUrl",
            "fileURL",
            "playbackUrl",
            "playbackURL",
            "videoUrl",
            "videoURL",
        }
        media_container_keys = {
            "clip",
            "clips",
            "download",
            "downloadInfo",
            "file",
            "files",
            "media",
            "playback",
            "playbackInfo",
            "video",
            "videos",
        }
        queue: list[tuple[Any, bool]] = [(video, False)]
        while queue:
            current, is_media_container = queue.pop(0)
            if isinstance(current, Mapping):
                for key, value in current.items():
                    child_is_media_container = is_media_container or key in media_container_keys
                    if isinstance(value, str):
                        if key in media_url_keys and value.startswith(("http://", "https://")):
                            return value
                        if (
                            key == "url"
                            and is_media_container
                            and value.startswith(("http://", "https://"))
                        ):
                            return value
                    elif isinstance(value, Mapping | list):
                        queue.append((value, child_is_media_container))
            elif isinstance(current, list):
                queue.extend((item, is_media_container) for item in current)
        return None

    def download_cloud_video(
        self,
        video: Mapping[str, Any],
        *,
        max_retries: int = 0,
    ) -> bytes:
        """Download a cloud video when the descriptor contains a direct HTTP URL.

        Most EZVIZ cloud clip descriptors returned by ``/v3/clouds/videoDetails``
        expose a native SDK ``streamUrl`` host/port instead of a direct media URL.
        Those native stream descriptors cannot be downloaded through this helper.
        """

        url = self._extract_cloud_video_download_url(video)
        if url is None:
            stream_url = video.get("streamUrl")
            suffix = (
                f" Native streamUrl={stream_url!r} requires the EZVIZ SDK path."
                if stream_url
                else ""
            )
            raise PyEzvizError(
                "Cloud video descriptor does not include a direct HTTP(S) download URL." + suffix
            )

        resp = self._http_request(
            "GET",
            url,
            retry_401=False,
            max_retries=max_retries,
        )
        return resp.content

    def search_device(
        self,
        serial: str,
        *,
        user_ssid: str | None = None,
        max_retries: int = 0,
    ) -> JsonDict:
        """Find device information by serial."""

        headers = dict(self._session.headers)
        if user_ssid is not None:
            headers["userSsid"] = user_ssid

        params = {"deviceSerial": serial}
        req = requests.Request(
            method="GET",
            url=self._url(API_ENDPOINT_USERDEVICES_SEARCH),
            headers=headers,
            params=params,
        ).prepare()

        resp = self._send_prepared(
            req,
            retry_401=True,
            max_retries=max_retries,
        )
        json_output = self._parse_json(resp)
        if not self._meta_ok(json_output):
            raise PyEzvizError(f"Could not search device: Got {json_output})")
        return json_output

    def get_socket_log_info(
        self,
        serial: str,
        start: str,
        end: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Fetch smart outlet switch logs within a time range."""

        path = API_ENDPOINT_SMARTHOME_OUTLET_LOG.format(**{"from": start, "to": end})
        json_output = self._request_json(
            "GET",
            path,
            params={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get socket log info")
        return json_output

    def linked_cameras(
        self,
        serial: str,
        detector_serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """List cameras linked to a detector device."""

        params = {
            "deviceSerial": serial,
            "detectorDeviceSerial": detector_serial,
        }
        json_output = self._request_json(
            "GET",
            API_ENDPOINT_DEVICES_ASSOCIATION_LINKED_IPC,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not get linked cameras")
        return json_output

    def set_microscope(
        self,
        serial: str,
        multiple: float,
        x: int,
        y: int,
        index: int,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Configure microscope lens parameters."""

        data = {
            "multiple": multiple,
            "x": x,
            "y": y,
            "index": index,
        }
        json_output = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}/microscope",
            data=data,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not set microscope")
        return json_output

    def share_accept(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Accept a device share invitation."""

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_SHARE_ACCEPT,
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not accept share")
        return json_output

    def share_quit(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Leave a shared device."""

        json_output = self._request_json(
            "DELETE",
            API_ENDPOINT_SHARE_QUIT,
            params={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not quit share")
        return json_output

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

        params: dict[str, Any] = {
            "email": email,
            "account": account,
            "score": score,
            "feedback": feedback,
        }
        if pic_url is not None:
            params["picUrl"] = pic_url

        json_output = self._request_json(
            "POST",
            API_ENDPOINT_FEEDBACK,
            params=params,
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not send feedback")
        return json_output

    def upload_device_log(
        self,
        serial: str,
        *,
        max_retries: int = 0,
    ) -> JsonDict:
        """Trigger device log upload to Ezviz cloud."""

        json_output = self._request_json(
            "POST",
            "/v3/devconfig/dump/app/trigger",
            data={"deviceSerial": serial},
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(json_output, "Could not upload device log")
        return json_output

    def alarm_sound(
        self,
        serial: str,
        sound_type: int,
        enable: int = 1,
        voice_id: int | None = None,
        max_retries: int = 0,
    ) -> bool:
        """Enable alarm sound by API."""
        if max_retries > MAX_RETRIES:
            raise PyEzvizError("Can't gather proper data. Max retries exceeded.")

        if sound_type not in [0, 1, 2]:
            raise PyEzvizError("Invalid sound_type, should be 0,1,2: " + str(sound_type))

        voice_id_value = 0 if voice_id is None else voice_id

        response_json = self._request_json(
            "PUT",
            f"{API_ENDPOINT_DEVICES}{serial}{API_ENDPOINT_ALARM_SOUND}",
            data={
                "enable": enable,
                "soundType": sound_type,
                "voiceId": voice_id_value,
                "deviceSerial": serial,
            },
            retry_401=True,
            max_retries=max_retries,
        )
        self._ensure_ok(response_json, "Could not set alarm sound")
        _LOGGER.debug(
            "http_debug: serial=%s code=%s msg=%s",
            serial,
            self._meta_code(response_json),
            "alarm_sound",
        )
        return True

    def get_mqtt_client(
        self, on_message_callback: Callable[[dict[str, Any]], None] | None = None
    ) -> MQTTClient:
        """Return a push client sharing this client's session and token-save callback."""
        with self._token_lock:
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

        with self._token_lock:
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
        with self._token_lock:
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
                self.mqtt_client._session = self._session  # noqa: SLF001
