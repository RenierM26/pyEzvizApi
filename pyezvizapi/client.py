lines: 8523

---MAIN---
"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
import datetime as dt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
import time
from typing import Any, BinaryIO, cast
from urllib.parse import parse_qs, urlparse

from .camera import EzvizCamera
from .cas import CasDeviceSession, EzvizCAS
from .client import EzvizClient
from .cloud_stream import open_cloud_stream
from .constants import BatteryCameraWorkMode, DefenseModeType, DeviceSwitchType
from .exceptions import EzvizAuthVerificationCode, PyEzvizError
from .hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfo,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoEx,
    EzvizLocalReceiverInfoExAttrs,
    HcNetSdkLanEndpoint,
    classify_ezviz_local_sdk_body,
)
from .light_bulb import EzvizLightBulb
from .local_stream import (
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    get_local_sdk_stream_credentials_from_client,
    open_local_sdk_stream,
)
from .stream import (
    StreamTransport,
    decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size,
    detect_transport,
    download_ezviz_cloud_replay,
    mpeg_ps_decryptable_prefix_length,
    rtp_payload,
)

_LOGGER = logging.getLogger(__name__)
_REAL_EZVIZ_CLIENT = EzvizClient


@dataclass(frozen=True)
class StreamProxyConfig:
    """Configuration for the experimental HTTP stream proxy."""

    serial: str
    channel: int | None
    client_type: int
    token_index: int
    refresh_vtm: bool
    timeout: float | None
    path: str
    ffmpeg_path: str
    allow_encrypted: bool
    decrypt_video: bool
    decrypt_codec: str
    max_packets: int | None


class StreamProxyHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server that does not block CLI shutdown on active streams."""

    daemon_threads = True
    block_on_close = False


def _parse_duration_seconds(value: str) -> float | None:
    """Parse a CLI duration value into seconds."""

    text = value.strip().lower()
    if text in {"0", "none", "unlimited"}:
        return None

    multipliers = {
        "s": 1.0,
        "sec": 1.0,
        "secs": 1.0,
        "second": 1.0,
        "seconds": 1.0,
        "m": 60.0,
        "min": 60.0,
        "mins": 60.0,
        "minute": 60.0,
        "minutes": 60.0,
        "h": 3600.0,
        "hr": 3600.0,
        "hrs": 3600.0,
        "hour": 3600.0,
        "hours": 3600.0,
    }

    multiplier = 1.0
    for suffix, suffix_multiplier in sorted(
        multipliers.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            multiplier = suffix_multiplier
            break
    else:
        number = text

    try:
        duration = float(number) * multiplier
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"invalid duration: {value}") from err

    if duration <= 0:
        raise argparse.ArgumentTypeError("duration must be positive, or 0 for unlimited")
    return duration


def _setup_logging(debug: bool) -> None:
    """Configure root logger for CLI usage."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s: %(message)s")
    if debug:
        # Verbose requests logging in debug mode
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Build and parse CLI arguments.

    Returns a populated `argparse.Namespace`. Pass `argv` for testing.
    """
    parser = argparse.ArgumentParser(prog="pyezvizapi")
    parser.add_argument("-u", "--username", required=False, help="Ezviz username")
    parser.add_argument("-p", "--password", required=False, help="Ezviz Password")
    parser.add_argument(
        "-r",
        "--region",
        required=False,
        default="apiieu.ezvizlife.com",
        help="Ezviz API region",
    )
    parser.add_argument("--debug", "-d", action="store_true", help="Print debug messages to stderr")
    parser.add_argument("--json", action="store_true", help="Force JSON output when possible")
    parser.add_argument(
        "--token-file",
        type=str,
        default="ezviz_token.json",
        help="Path to JSON token file in the current directory (default: ezviz_token.json)",
    )
    parser.add_argument(
        "--save-token",
        action="store_true",
        help="Save token to --token-file after successful login",
    )

    subparsers = parser.add_subparsers(dest="action")

    parser_device = subparsers.add_parser("devices", help="Play with all devices at once")
    parser_device.add_argument(
        "device_action",
        type=str,
        default="status",
        help="Device action to perform",
        choices=["device", "status", "switch", "connection"],
    )
    parser_device.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh alarm info before composing status (default: on)",
    )

    parser_device_lights = subparsers.add_parser("devices_light", help="Get all the light bulbs")
    parser_device_lights.add_argument(
        "devices_light_action",
        type=str,
        default="status",
        help="Light bulbs action to perform",
        choices=["status"],
    )
    parser_device_lights.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh device data before composing status (default: on)",
    )

    parser_light = subparsers.add_parser("light", help="Light actions")
    parser_light.add_argument("--serial", required=True, help="light bulb SERIAL")

    subparsers_light = parser_light.add_subparsers(dest="light_action")
    subparsers_light.add_parser("toggle", help="Toggle the light bulb")
    subparsers_light.add_parser("status", help="Get information about the light bulb")

    parser_home_defence_mode = subparsers.add_parser(
        "home_defence_mode", help="Set home defence mode"
    )

    subparsers.add_parser("mqtt", help="Connect to mqtt push notifications")

    parser_home_defence_mode.add_argument(
        "--mode", required=False, help="Choose mode", choices=["HOME_MODE", "AWAY_MODE"]
    )

    parser_camera = subparsers.add_parser("camera", help="Camera actions")
    parser_camera.add_argument("--serial", required=True, help="camera SERIAL")

    subparsers_camera = parser_camera.add_subparsers(dest="camera_action")

    parser_camera_status = subparsers_camera.add_parser(
        "status", help="Get the status of the camera"
    )
    parser_camera_status.add_argument(
        "--refresh",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Refresh alarm info before composing status (default: on)",
    )
    subparsers_camera.add_parser("unlock-door", help="Unlock the door lock")
    subparsers_camera.add_parser("unlock-gate", help="Unlock the gate lock")
    parser_camera_move = subparsers_camera.add_parser("move", help="Move the camera")
    parser_camera_move.add_argument(
        "--direction",
        required=True,
        help="Direction to move the camera to",
        choices=["up", "down", "right", "left"],
    )
    parser_camera_move.add_argument(
        "--speed",
        required=False,
        help="Speed of the movement",
        default=5,
        type=int,
        choices=range(1, 10),
    )

    parser_camera_move_coords = subparsers_camera.add_parser(
        "move_coords", help="Move the camera to the X,Y coordinates"
    )
    parser_camera_move_coords.add_argument(
        "--x",
        required=True,
        help="The X coordinate to move the camera to",
        type=float,
    )
    parser_camera_move_coords.add_argument(
        "--y",
        required=True,
        help="The Y coordinate to move the camera to",
        type=float,
    )

    parser_camera_switch = subparsers_camera.add_parser(
        "switch", help="Change the status of a switch"
    )
    parser_camera_switch.add_argument(
        "--switch",
        required=True,
        help="Switch to switch",
        choices=[
            "audio",
            "ir",
            "state",
            "privacy",
            "sleep",
            "follow_move",
            "sound_alarm",
        ],
    )
    parser_camera_switch.add_argument(
        "--enable",
        required=False,
        help="Enable (or not)",
        default=1,
        type=int,
        choices=[0, 1],
    )

    parser_camera_alarm = subparsers_camera.add_parser("alarm", help="Configure the camera alarm")
    parser_camera_alarm.add_argument(
        "--notify", required=False, help="Enable (or not)", type=int, choices=[0, 1]
    )
    parser_camera_alarm.add_argument(
        "--sound",
        required=False,
        help="Sound level (2 is silent, 1 intensive, 0 soft)",
        type=int,
        choices=[0, 1, 2],
    )
    parser_camera_alarm.add_argument(
        "--sensibility",
        required=False,
        help="Sensibility level (Non-Cameras = from 1 to 6) or (Cameras = 1 to 100)",
        type=int,
        choices=range(100),
    )
    parser_camera_alarm.add_argument(
        "--do_not_disturb",
        required=False,
        help=(
            "Enable/disable push notifications for motion events. "
            "Some camera models expose this setting in the EZVIZ app, but not all. "
            "Motion alarms are still recorded and available even when push notifications are disabled."
        ),
        default=None,
        type=int,
        choices=[0, 1],
    )
    parser_camera_alarm.add_argument(
        "--schedule", required=False, help="Schedule in json format *test*", type=str
    )

    parser_camera_select = subparsers_camera.add_parser(
        "select",
        help="Change the value of a multi-value option (for on/off value, see 'switch' command)",
    )

    parser_camera_select.add_argument(
        "--battery_work_mode",
        required=False,
        help="Change the work mode for battery powered camera",
        choices=[
            mode.name for mode in BatteryCameraWorkMode if mode is not BatteryCameraWorkMode.UNKNOWN
        ],
    )

    # Dump full pagelist for exploration
    subparsers.add_parser("pagelist", help="Output full pagelist as JSON")

    # Dump device infos mapping (optionally for a single serial)
    parser_device_infos = subparsers.add_parser(
        "device_infos",
        help="Output device infos (raw JSON), optionally filtered by serial",
    )
    parser_device_infos.add_argument(
        "--serial", required=False, help="Optional serial to filter a single device"
    )

    parser_unified = subparsers.add_parser(
        "unifiedmsg",
        help="Fetch unified message list (alarm feed) and dump URLs/metadata",
    )
    parser_unified.add_argument(
        "--serials",
        required=False,
        help="Comma-separated serials to filter (default: all devices)",
    )
    parser_unified.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of messages to request (max 50; default: 20)",
    )
    parser_unified.add_argument(
        "--date",
        required=False,
        help="Date in YYYYMMDD format (default: today in API timezone)",
    )
    parser_unified.add_argument(
        "--end-time",
        required=False,
        help="Pagination token (msgId) returned by previous call (default: latest)",
    )
    parser_unified.add_argument(
        "--urls-only",
        action="store_true",
        help="Print only deviceSerial + media URLs instead of full metadata",
    )

    parser_sdcard_videos = subparsers.add_parser(
        "sdcard_videos",
        help="Fetch SD-card playback record descriptors",
    )
    parser_sdcard_videos.add_argument("--serial", required=True, help="camera SERIAL")
    parser_sdcard_videos.add_argument(
        "--channel",
        type=int,
        default=1,
        help="Camera channel number (default: 1)",
    )
    parser_sdcard_videos.add_argument(
        "--start-time",
        required=True,
        help="Record search start time, as accepted by EZVIZ API",
    )
    parser_sdcard_videos.add_argument(
        "--stop-time",
        required=True,
        help="Record search stop time, as accepted by EZVIZ API",
    )
    parser_sdcard_videos.add_argument(
        "--source",
        choices=("legacy", "v2", "common", "intelligent"),
        default="v2",
        help="Record endpoint to query (default: v2)",
    )
    parser_sdcard_videos.add_argument(
        "--channel-serial",
        help="Channel serial for legacy/common record endpoints",
    )
    parser_sdcard_videos.add_argument(
        "--size",
        type=int,
        default=20,
        help="Number of records to request (default: 20)",
    )
    parser_sdcard_videos.add_argument(
        "--record-type",
        type=int,
        default=0,
        help="Record type for legacy/common endpoints (default: 0)",
    )
    parser_sdcard_videos.add_argument(
        "--sort-by",
        type=int,
        default=0,
        help="Sort mode for v2 endpoint (default: 0)",
    )
    parser_sdcard_videos.add_argument(
        "--require-label",
        type=int,
        default=0,
        help="Label flag for v2 endpoint (default: 0)",
    )
    parser_sdcard_videos.add_argument(
        "--version",
        type=int,
        default=2,
        help="Record API version for common/intelligent endpoints (default: 2)",
    )
    parser_sdcard_videos.add_argument(
        "--filter",
        help="Filter JSON/string for intelligent records",
    )

    parser_cloud_videos = subparsers.add_parser(
        "cloud_videos",
        help="Fetch cloud video descriptors used by the EZVIZ app download path",
    )
    parser_cloud_videos.add_argument("--serial", required=True, help="camera SERIAL")
    parser_cloud_videos.add_argument(
        "--channel",
        type=int,
        default=1,
        help="Camera channel number (default: 1)",
    )
    parser_cloud_videos.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of cloud videos to request (default: 20)",
    )
    parser_cloud_videos.add_argument(
        "--video-type",
        type=int,
        default=2,
        help="Cloud video type (default: 2, as used by the app list view)",
    )
    parser_cloud_videos.add_argument(
        "--support-multi-channel-shared-service",
        type=int,
        default=0,
        help="EZVIZ multi-channel shared-service flag (default: 0)",
    )
    parser_cloud_videos.add_argument(
        "--details",
        action="store_true",
        help="Fetch /v3/clouds/videoDetails for the returned clips",
    )

    parser_cloud_video_download = subparsers.add_parser(
        "cloud_video_download",
        help="Download one cloud video from direct HTTP(S) or cloud replay streamUrl details",
    )
    parser_cloud_video_download.add_argument("--serial", required=True, help="camera SERIAL")
    parser_cloud_video_download.add_argument(
        "--channel",
        type=int,
        default=1,
        help="Camera channel number (default: 1)",
    )
    parser_cloud_video_download.add_argument(
        "--seq-id",
        required=True,
        help="Cloud video seqId to select from /v3/clouds/videos/list",
    )
    parser_cloud_video_download.add_argument(
        "--output",
        required=True,
        help="Output path for the downloaded media bytes",
    )
    parser_cloud_video_download.add_argument(
        "--encrypted-output",
        help="Optional path to save encrypted native cloud replay .tmp bytes",
    )
    parser_cloud_video_download.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Cloud replay socket timeout in seconds (default: 30)",
    )
    parser_cloud_video_download.add_argument(
        "--decrypt-codec",
        choices=(
            "auto",
            "hevc",
            "hevc-encrypted-header",
            "h264",
            "h264-clear-header",
            "h264-encrypted-header",
            "encrypted-header",
        ),
        default="auto",
        help=(
            "Video codec transform when decrypting streamUrl clips: auto detects the "
            "NAL header mode; hevc preserves "
            "the two-byte HEVC NAL header; h264/h264-clear-header preserve the "
            "one-byte H.264 NAL header; encrypted-header/hevc-encrypted-header "
            "decrypts the codec header too (default: auto)"
        ),
    )
    parser_cloud_video_download.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of cloud videos to inspect while finding seqId (default: 20)",
    )
    parser_cloud_video_download.add_argument(
        "--video-type",
        type=int,
        default=2,
        help="Cloud video type (default: 2, as used by the app list view)",
    )
    parser_cloud_video_download.add_argument(
        "--support-multi-channel-shared-service",
        type=int,
        default=0,
        help="EZVIZ multi-channel shared-service flag (default: 0)",
    )

    parser_cloud_video_decrypt = subparsers.add_parser(
        "cloud_video_decrypt",
        help="Decrypt an EZVIZ/Hikvision encrypted cloud .tmp PS file in Python",
    )
    parser_cloud_video_decrypt.add_argument(
        "--input",
        required=True,
        help="Input encrypted cloud .tmp / MPEG-PS file",
    )
    parser_cloud_video_decrypt.add_argument(
        "--output",
        required=True,
        help="Output decrypted MPEG-PS file",
    )
    parser_cloud_video_decrypt.add_argument(
        "--serial",
        help="Camera serial used to fetch the encrypt key",
    )
    parser_cloud_video_decrypt.add_argument(
        "--key",
        help="Camera encrypt key. Prefer --serial so the key is not exposed in shell history",
    )
    parser_cloud_video_decrypt.add_argument(
        "--decrypt-codec",
        choices=(
            "auto",
            "hevc",
            "hevc-encrypted-header",
            "h264",
            "h264-clear-header",
            "h264-encrypted-header",
            "encrypted-header",
        ),
        default="auto",
        help=(
            "Video codec transform during decryption: auto detects the NAL header "
            "mode; hevc preserves the two-byte "
            "HEVC NAL header; h264/h264-clear-header preserve the one-byte H.264 "
            "NAL header; encrypted-header/hevc-encrypted-header decrypts the "
            "codec header too "
            "(default: auto)"
        ),
    )

    parser_stream = subparsers.add_parser(
        "stream",
        help="Experimental VTM cloud stream helpers",
    )
    subparsers_stream = parser_stream.add_subparsers(dest="stream_action")
    parser_stream_trace = subparsers_stream.add_parser(
        "trace",
        help="Trace sanitized VTM packet metadata for a camera",
    )
    parser_stream_trace.add_argument("--serial", required=True, help="camera SERIAL")
    parser_stream_trace.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Camera channel/local index (default: first matching VTM resource)",
    )
    parser_stream_trace.add_argument(
        "--max-packets",
        ty…61174 tokens truncated…rt_time: str,
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
            suffix = f" Native streamUrl={stream_url!r} requires the EZVIZ SDK path." if stream_url else ""
            raise PyEzvizError(
                "Cloud video descriptor does not include a direct HTTP(S) download URL."
                + suffix
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
            raise PyEzvizError(
                "Invalid sound_type, should be 0,1,2: " + str(sound_type)
            )

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
        """Return a configured MQTTClient using this client's session."""
        if self.mqtt_client is None:
            self.mqtt_client = MQTTClient(
                token=cast(dict[Any, Any], self._token),
                session=self._session,
                timeout=self._timeout,
                on_message_callback=on_message_callback,
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
        """Return a shallow copy of the current authentication token."""

        return dict(self._token)

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
        if self._session:
            self._session.close()

        self._session = requests.session()
        self._session.headers.update(REQUEST_HEADER)  # Reset session.
