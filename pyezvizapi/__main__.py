"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
import datetime as dt
import hashlib
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
from .constants import (
    MAX_RETRIES,
    BatteryCameraWorkMode,
    DefenseModeType,
    DeviceSwitchType,
)
from .exceptions import EzvizAuthVerificationCode, PyEzvizError
from .hcnetsdk import (
    HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
    EzvizCasDeviceInfo,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfo,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoEx,
    EzvizLocalReceiverInfoExAttrs,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    classify_ezviz_local_sdk_body,
    parse_hcnetsdk_tcp_frame,
)
from .light_bulb import EzvizLightBulb
from .local_stream import (
    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortGeneratedSocketStep,
    HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep,
    _idmx_local_packets_to_annexb_with_codec,
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    get_local_sdk_stream_credentials_from_client,
    hcnetsdk_command_port_generated_plan_from_socket_plan,
    hcnetsdk_command_port_native_lan_live_view_plan,
    open_local_sdk_stream,
    summarize_h264_annexb_idr_windows,
    summarize_h264_annexb_units,
    summarize_hevc_annexb_irap_windows,
    summarize_idmx_h264_local_packets,
)
from .local_stream_ecdh import (
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    copy_local_sdk_ecdh_stream_to_mpegps,
    open_local_sdk_ecdh_stream,
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
HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS = 5.0


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

    parser_save = subparsers.add_parser(
        "save",
        help="Save a local live clip or camera image to a file",
    )
    subparsers_save = parser_save.add_subparsers(dest="save_action")
    parser_save_clip = subparsers_save.add_parser(
        "clip",
        help="Save a direct-local camera clip to a local file",
    )
    parser_save_clip.add_argument("--serial", required=True, help="camera SERIAL")
    parser_save_clip.add_argument(
        "--source",
        choices=("local-sdk", "local-sdk-ecdh", "cloud", "hcnetsdk-command-port"),
        default="local-sdk",
        help=(
            "Source to use: direct 9010/9020 SDK, encrypted local SDK ECDH, "
            "VTM cloud live stream, or full HCNetSDK command-port media on "
            "port 8000 (default: local-sdk)"
        ),
    )
    parser_save_clip.add_argument(
        "--channel",
        type=int,
        default=1,
        help="Camera channel number (default: 1)",
    )
    parser_save_clip.add_argument(
        "--output",
        required=True,
        help="Local output path for the clip",
    )
    parser_save_clip.add_argument(
        "--duration",
        type=_parse_duration_seconds,
        default=10.0,
        help="Capture duration; accepts seconds or units like 10s/1m (default: 10s)",
    )
    parser_save_clip.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Optional packet limit in addition to --duration",
    )
    parser_save_clip.add_argument(
        "--format",
        choices=("mpegts", "mpegps"),
        default=None,
        help=(
            "Output container: MPEG-TS is easiest for FFmpeg/Home Assistant; "
            "defaults to mpegps for local-sdk-ecdh and mpegts otherwise"
        ),
    )
    parser_save_clip.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable to use for MPEG-TS remuxing (default: ffmpeg)",
    )
    parser_save_clip.add_argument(
        "--decrypt-video",
        action="store_true",
        help="Decrypt encrypted local video before writing/remuxing",
    )
    parser_save_clip.add_argument(
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
        default="encrypted-header",
        help="Video codec transform for --decrypt-video (default: encrypted-header)",
    )
    parser_save_clip.add_argument(
        "--media-key",
        help=(
            "Camera media decrypt key, or EZVIZ_LOCAL_MEDIA_KEY. This is used "
            "when --decrypt-video is set."
        ),
    )
    parser_save_clip.add_argument(
        "--media-key-hex",
        help=(
            "Hex-encoded binary media decrypt key, or EZVIZ_LOCAL_MEDIA_KEY_HEX. "
            "Use this when the native local media key is not printable text."
        ),
    )
    parser_save_clip.add_argument(
        "--cas-serial",
        help="Device serial to send to cloud CAS when it differs from --serial",
    )
    parser_save_clip.add_argument(
        "--no-p2p-register",
        action="store_true",
        help="Skip app-style P2P session registration before local SDK CAS lookup",
    )
    parser_save_clip.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Local socket timeout in seconds (default: 10)",
    )
    parser_save_clip.add_argument(
        "--sms-code",
        help="Optional MFA/elevation code for media key retrieval",
    )
    parser_save_clip.add_argument(
        "--local-sdk-ecdh-send-init",
        action="store_true",
        help="Send the optional local SDK ECDH 0x2013 pre-start INIT before preview setup",
    )
    parser_save_clip.add_argument(
        "--local-sdk-ecdh-receiver-port",
        type=int,
        default=LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        help=(
            "Receiver port to include in local SDK ECDH preview XML "
            f"(default: {LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT})"
        ),
    )
    parser_save_clip.add_argument(
        "--local-sdk-ecdh-max-frames",
        type=int,
        default=None,
        help=(
            "Stop local SDK ECDH capture after reading this many encrypted input frames "
            "(default: unlimited)"
        ),
    )
    parser_save_clip.add_argument(
        "--host",
        help="Camera LAN address for --source hcnetsdk-command-port",
    )
    parser_save_clip.add_argument(
        "--command-port",
        type=int,
        help="Camera command port for --source hcnetsdk-command-port (default: 8000)",
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-frame-hex",
        action="append",
        default=[],
        help=(
            "One complete port-8000 HCNetSDK command frame as hex. May be "
            "passed more than once."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-frames-file",
        help=(
            "JSON or text file containing complete port-8000 command frame hex "
            "values. JSON may be a list or an object with command_frames/frames."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-plan-file",
        help=(
            "JSON file describing a native-style multi-socket port-8000 "
            "command plan. Use for HCNetSDK flows that open short control "
            "sockets before the media socket."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-generated-plan-file",
        help=(
            "JSON file describing a generated native-style multi-socket "
            "port-8000 command plan. The CLI logs in first, then renders "
            "session-relative command templates."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-native-plan",
        choices=(HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,),
        help=(
            "Use a built-in app-observed native-style generated port-8000 "
            "command plan. Currently supports app-lan-live-view."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-password",
        help=(
            "LAN command-port password for generated HCNetSDK command-port "
            "plans. This is usually the device verification/LAN password."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-local-ip",
        help=(
            "Client LAN IPv4 address to patch into HCNetSDK command-port "
            "frames when replaying a plan captured on another host."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-metadata-output",
        help=(
            "Optional JSON file for sanitized HCNetSDK command-port response "
            "metadata when saving a clip."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-command-sampled-packets-output",
        help=(
            "Optional binary file for the bounded HCNetSDK command-port media "
            "packet sample used by metadata summaries. The file uses the same "
            "little-endian $ framing as raw command-port dump artifacts. This "
            "diagnostic sidecar records sampled packets observed before final "
            "clean-window trimming/recovery, so it is not an exact byte source "
            "map for the remuxed clip."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-skip-initial-idr-windows",
        type=int,
        default=0,
        help=(
            "For clear H.264 IDMX command-port streams, drop this many initial "
            "IDR-started windows before remuxing (default: 0)."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-trim-to-clean-idr-window",
        "--hcnetsdk-video-trim-to-clean-window",
        dest="hcnetsdk_h264_trim_to_clean_idr_window",
        action="store_true",
        help=(
            "For clear IDMX command-port streams, decode-check sampled video "
            "windows and remux from the first clean one."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-clean-idr-preroll-seconds",
        "--hcnetsdk-video-clean-window-preroll-seconds",
        dest="hcnetsdk_h264_clean_idr_preroll_seconds",
        type=float,
        default=0.0,
        help=(
            "Extra capture seconds to allow before clean-window trimming, so "
            "generated command-port streams can stabilize before the requested "
            "clip window is kept (default: 0)."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-clean-idr-max-windows",
        "--hcnetsdk-video-clean-window-max-windows",
        dest="hcnetsdk_h264_clean_idr_max_windows",
        type=int,
        default=32,
        help=(
            "Maximum sampled video windows to decode-check when using "
            "clean-window trimming or waiting (default: 32)."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-wait-for-clean-idr-window",
        "--hcnetsdk-video-wait-for-clean-window",
        dest="hcnetsdk_h264_wait_for_clean_idr_window",
        action="store_true",
        help=(
            "For clear IDMX command-port streams, discard startup media until "
            "a decodable H.264 IDR or HEVC IRAP window is found, then start the requested "
            "duration window."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-clean-idr-wait-seconds",
        "--hcnetsdk-video-clean-window-wait-seconds",
        dest="hcnetsdk_h264_clean_idr_wait_seconds",
        type=float,
        default=60.0,
        help=(
            "Maximum seconds to wait for a clean video window "
            "before failing (default: 60)."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-read-responses",
        help=(
            "Comma-separated booleans controlling whether to read a response "
            "after each HCNetSDK command frame (default: read after every frame)."
        ),
    )
    parser_save_clip.add_argument(
        "--client-type",
        type=int,
        default=9,
        help="VTM client type for --source cloud (default: 9)",
    )
    parser_save_clip.add_argument(
        "--token-index",
        type=int,
        default=0,
        help="VTDU token index for --source cloud (default: 0)",
    )
    parser_save_clip.add_argument(
        "--no-refresh-vtm",
        action="store_true",
        help="Use pagelist VTM metadata without refreshing it for --source cloud",
    )

    parser_save_image = subparsers_save.add_parser(
        "image",
        help="Capture or download a camera image to a local file",
    )
    parser_save_image.add_argument("--serial", required=True, help="camera SERIAL")
    parser_save_image.add_argument(
        "--channel",
        type=int,
        default=1,
        help="Camera channel number (default: 1)",
    )
    parser_save_image.add_argument(
        "--output",
        required=True,
        help="Local output path for the image",
    )
    parser_save_image.add_argument(
        "--image-url",
        help="Download this existing EZVIZ image URL instead of triggering capture",
    )
    parser_save_image.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Write encrypted image bytes as-is instead of decrypting when needed",
    )
    parser_save_image.add_argument(
        "--sms-code",
        help="Optional MFA/elevation code for encrypted image key retrieval",
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
        type=int,
        default=20,
        help="Number of incoming VTM packets to summarize (default: 20)",
    )
    parser_stream_trace.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    parser_stream_trace.add_argument(
        "--client-type",
        type=int,
        default=9,
        help="VTM client type used in the ysproto URL (default: 9)",
    )
    parser_stream_trace.add_argument(
        "--token-index",
        type=int,
        default=0,
        help="VTDU token index to use from /vtdutoken2 (default: 0)",
    )
    parser_stream_trace.add_argument(
        "--no-refresh-vtm",
        action="store_true",
        help="Use pagelist VTM metadata without refreshing via /v3/streaming/vtm",
    )
    parser_stream_trace.add_argument(
        "--json-lines",
        action="store_true",
        help="Print one JSON object per trace event instead of a JSON array",
    )
    parser_stream_dump = subparsers_stream.add_parser(
        "dump",
        help="Dump VTM stream payload bytes for FFmpeg/proxy experiments",
    )
    parser_stream_dump.add_argument("--serial", required=True, help="camera SERIAL")
    parser_stream_dump.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Camera channel/local index (default: first matching VTM resource)",
    )
    parser_stream_dump.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after this many stream packets (default: run until interrupted)",
    )
    parser_stream_dump.add_argument(
        "--duration",
        type=_parse_duration_seconds,
        default=60.0,
        help=(
            "Stop after this capture duration; accepts seconds or units like "
            "30s/1m/2min (default: 1m, use 0 for unlimited)"
        ),
    )
    parser_stream_dump.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    parser_stream_dump.add_argument(
        "--client-type",
        type=int,
        default=9,
        help="VTM client type used in the ysproto URL (default: 9)",
    )
    parser_stream_dump.add_argument(
        "--token-index",
        type=int,
        default=0,
        help="VTDU token index to use from /vtdutoken2 (default: 0)",
    )
    parser_stream_dump.add_argument(
        "--no-refresh-vtm",
        action="store_true",
        help="Use pagelist VTM metadata without refreshing via /v3/streaming/vtm",
    )
    parser_stream_dump.add_argument(
        "--output",
        default="-",
        help="Output file for stream bytes, or '-' for stdout (default: -)",
    )
    parser_stream_dump.add_argument(
        "--format",
        choices=("mpegts", "raw"),
        default="mpegts",
        help="Output container format: mpegts is VLC-friendly and remuxes with codec copy; raw writes VTM payloads unchanged (default: mpegts)",
    )
    parser_stream_dump.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable to use for MPEG-TS remuxing (default: ffmpeg)",
    )
    parser_stream_dump.add_argument(
        "--allow-encrypted",
        action="store_true",
        help="Write encrypted stream payloads instead of failing on first encrypted packet",
    )
    parser_stream_dump.add_argument(
        "--decrypt-video",
        action="store_true",
        help=(
            "Decrypt Hikvision/EZVIZ encrypted video NAL payloads with the "
            "camera encrypt key before writing/remuxing (experimental)"
        ),
    )
    parser_stream_dump.add_argument(
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
            "Video codec transform for --decrypt-video: auto detects the NAL header "
            "mode; hevc preserves the two-byte "
            "HEVC NAL header; h264/h264-clear-header preserve the one-byte H.264 "
            "NAL header; encrypted-header/hevc-encrypted-header decrypts the "
            "codec header too "
            "(default: auto)"
        ),
    )
    parser_stream_proxy = subparsers_stream.add_parser(
        "proxy",
        help="Serve a local HTTP MPEG-TS stream for FFmpeg/Home Assistant",
    )
    parser_stream_proxy.add_argument("--serial", required=True, help="camera SERIAL")
    parser_stream_proxy.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Camera channel/local index (default: first matching VTM resource)",
    )
    parser_stream_proxy.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Host/IP to bind the proxy to (default: 127.0.0.1)",
    )
    parser_stream_proxy.add_argument(
        "--listen-port",
        type=int,
        default=8558,
        help="TCP port to bind the proxy to (default: 8558)",
    )
    parser_stream_proxy.add_argument(
        "--path",
        default=None,
        help="HTTP path to serve (default: /<serial>.ts)",
    )
    parser_stream_proxy.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    parser_stream_proxy.add_argument(
        "--client-type",
        type=int,
        default=9,
        help="VTM client type used in the ysproto URL (default: 9)",
    )
    parser_stream_proxy.add_argument(
        "--token-index",
        type=int,
        default=0,
        help="VTDU token index to use from /vtdutoken2 (default: 0)",
    )
    parser_stream_proxy.add_argument(
        "--no-refresh-vtm",
        action="store_true",
        help="Use pagelist VTM metadata without refreshing via /v3/streaming/vtm",
    )
    parser_stream_proxy.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable to use for MPEG-TS remuxing (default: ffmpeg)",
    )
    parser_stream_proxy.add_argument(
        "--allow-encrypted",
        action="store_true",
        help="Forward encrypted stream payloads instead of failing on first encrypted packet",
    )
    parser_stream_proxy.add_argument(
        "--decrypt-video",
        action="store_true",
        help=(
            "Decrypt Hikvision/EZVIZ encrypted video NAL payloads with the "
            "camera encrypt key before remuxing (experimental)"
        ),
    )
    parser_stream_proxy.add_argument(
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
            "Video codec transform for --decrypt-video: auto detects the NAL header "
            "mode; hevc preserves the two-byte "
            "HEVC NAL header; h264/h264-clear-header preserve the one-byte H.264 "
            "NAL header; encrypted-header/hevc-encrypted-header decrypts the "
            "codec header too "
            "(default: auto)"
        ),
    )
    parser_stream_proxy.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop each HTTP stream after this many packets (default: unlimited)",
    )
    parser_stream_local_dump = subparsers_stream.add_parser(
        "local-sdk-dump",
        help="Dump the direct-local 9010/9020 SDK stream with caller-supplied fields",
    )
    parser_stream_local_dump.add_argument("--host", help="camera LAN address")
    parser_stream_local_dump.add_argument("--serial", help="device serial")
    parser_stream_local_dump.add_argument(
        "--credentials-file",
        help=(
            "JSON file produced by local-sdk-keys; supplies serial, endpoint, "
            "CAS tuple, and optional media key"
        ),
    )
    parser_stream_local_dump.add_argument("--command-port", type=int)
    parser_stream_local_dump.add_argument("--stream-port", type=int)
    parser_stream_local_dump.add_argument("--channel", type=int, default=1)
    parser_stream_local_dump.add_argument(
        "--operation-code",
        help="CAS operation code, or EZVIZ_LOCAL_OPERATION_CODE",
    )
    parser_stream_local_dump.add_argument(
        "--cas-key",
        help="CAS local-control key, or EZVIZ_LOCAL_CAS_KEY",
    )
    parser_stream_local_dump.add_argument(
        "--fetch-cas",
        action="store_true",
        help=(
            "Fetch operation-code/cas-key from authenticated EZVIZ CAS instead "
            "of requiring --operation-code/--cas-key"
        ),
    )
    parser_stream_local_dump.add_argument(
        "--cas-serial",
        help=(
            "Device serial to send to cloud CAS when --fetch-cas is used "
            "(default: --serial)"
        ),
    )
    parser_stream_local_dump.add_argument(
        "--no-p2p-register",
        action="store_true",
        help="Skip app-style P2P session registration before --fetch-cas lookup",
    )
    parser_stream_local_dump.add_argument("--encrypt-type", type=int, default=1)
    parser_stream_local_dump.add_argument("--uuid", help="or EZVIZ_LOCAL_UUID")
    parser_stream_local_dump.add_argument("--timestamp", help="or EZVIZ_LOCAL_TIMESTAMP")
    parser_stream_local_dump.add_argument("--identifier")
    parser_stream_local_dump.add_argument(
        "--local-sdk-ecdh",
        action="store_true",
        help="Use the local SDK ECDH encrypted stream path instead of plain local SDK media",
    )
    parser_stream_local_dump.add_argument(
        "--local-sdk-ecdh-send-init",
        action="store_true",
        help="Send the optional local SDK ECDH 0x2013 pre-start INIT before preview setup",
    )
    parser_stream_local_dump.add_argument(
        "--local-sdk-ecdh-receiver-port",
        type=int,
        default=LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        help=(
            "Receiver port to include in local SDK ECDH preview XML "
            f"(default: {LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT})"
        ),
    )
    parser_stream_local_dump.add_argument("--nat-address", default="")
    parser_stream_local_dump.add_argument("--nat-port", type=int, default=0)
    parser_stream_local_dump.add_argument("--upnp-address", default="")
    parser_stream_local_dump.add_argument("--upnp-port", type=int, default=0)
    parser_stream_local_dump.add_argument("--inner-address", default="")
    parser_stream_local_dump.add_argument("--inner-port", type=int, default=0)
    parser_stream_local_dump.add_argument(
        "--receiver-shape",
        choices=("app", "structured"),
        default="app",
        help=(
            "Preview ReceiverInfo XML shape: app attributes from live EZVIZ "
            "traces, or nested structured fields (default: app)"
        ),
    )
    parser_stream_local_dump.add_argument("--receiver-stream-type", default="MAIN")
    parser_stream_local_dump.add_argument("--receiver-port", type=int, default=10101)
    parser_stream_local_dump.add_argument("--receiver-server-type", type=int, default=1)
    parser_stream_local_dump.add_argument("--receiver-new-stream-type", type=int, default=1)
    parser_stream_local_dump.add_argument("--receiver-trans-proto", default="TCP")
    parser_stream_local_dump.add_argument("--receiver-ex-port", type=int, default=10101)
    parser_stream_local_dump.add_argument("--auth-biz-code", default="biz=1")
    parser_stream_local_dump.add_argument("--auth-interval", type=int, default=180)
    parser_stream_local_dump.add_argument(
        "--is-encrypt",
        default="TRUE",
        help="Preview IsEncrypt value (default: TRUE, matching the app local path)",
    )
    parser_stream_local_dump.add_argument("--udt", type=int)
    parser_stream_local_dump.add_argument("--nat", type=int)
    parser_stream_local_dump.add_argument("--port-guess-type", type=int)
    parser_stream_local_dump.add_argument("--setup-timeout", type=int)
    parser_stream_local_dump.add_argument("--heartbeat-interval", type=int)
    parser_stream_local_dump.add_argument(
        "--pre-start-body-file",
        help="Optional file containing caller-owned 0x2013 pre-start body bytes",
    )
    parser_stream_local_dump.add_argument("--pre-start-sequence", type=int, default=27)
    parser_stream_local_dump.add_argument("--preview-sequence", type=int, default=28)
    parser_stream_local_dump.add_argument("--stream-sequence", type=int, default=29)
    parser_stream_local_dump.add_argument("--stream-rate", default=1)
    parser_stream_local_dump.add_argument("--stream-mode", default=-1)
    parser_stream_local_dump.add_argument(
        "--duration",
        type=_parse_duration_seconds,
        default=60.0,
        help="Stop after this capture duration (default: 1m, use 0 for unlimited)",
    )
    parser_stream_local_dump.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop after this many local RTP packets (default: duration only)",
    )
    parser_stream_local_dump.add_argument(
        "--socket-timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    parser_stream_local_dump.add_argument(
        "--max-prefix-bytes",
        type=int,
        default=4096,
        help="Maximum non-RTP preface bytes to tolerate before first media",
    )
    parser_stream_local_dump.add_argument(
        "--output",
        default="-",
        help="Output file for stream bytes, or '-' for stdout (default: -)",
    )
    parser_stream_local_dump.add_argument(
        "--metadata-output",
        help=(
            "Optional JSON file for non-secret local-SDK response metadata "
            "(commands, statuses, body shapes, and first-media shape)"
        ),
    )
    parser_stream_local_dump.add_argument(
        "--format",
        choices=("mpegps", "mpegts"),
        default=None,
        help=(
            "Output container: raw MPEG-PS payloads or remuxed MPEG-TS "
            "(default: mpegps for --local-sdk-ecdh, mpegts otherwise)"
        ),
    )
    parser_stream_local_dump.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable to use for MPEG-TS remuxing (default: ffmpeg)",
    )
    parser_stream_local_dump.add_argument(
        "--decrypt-video",
        action="store_true",
        help=(
            "Decrypt Hikvision/EZVIZ encrypted video NAL payloads before "
            "writing/remuxing. The media key can come from --media-key, "
            "--media-key-hex, EZVIZ_LOCAL_MEDIA_KEY, "
            "EZVIZ_LOCAL_MEDIA_KEY_HEX, --credentials-file, or the "
            "authenticated client."
        ),
    )
    parser_stream_local_dump.add_argument(
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
            "Video codec transform for --decrypt-video: auto detects the NAL header "
            "mode; use hevc-encrypted-header/encrypted-header for the observed "
            "local-SDK encrypted-header path "
            "(default: auto)"
        ),
    )
    parser_stream_local_dump.add_argument(
        "--media-key",
        help=(
            "Camera media decrypt key, or EZVIZ_LOCAL_MEDIA_KEY. This is distinct "
            "from --cas-key, which only protects the local-SDK control channel."
        ),
    )
    parser_stream_local_dump.add_argument(
        "--media-key-hex",
        help=(
            "Hex-encoded binary media decrypt key, or EZVIZ_LOCAL_MEDIA_KEY_HEX. "
            "Use this when the native local media key is not printable text."
        ),
    )
    parser_stream_local_keys = subparsers_stream.add_parser(
        "local-sdk-keys",
        help="Fetch direct-local LAN endpoint, CAS tuple and media decrypt key",
    )
    parser_stream_local_keys.add_argument("--serial", required=True, help="device serial")
    parser_stream_local_keys.add_argument(
        "--cas-serial",
        help="Device serial to send to cloud CAS (default: --serial)",
    )
    parser_stream_local_keys.add_argument(
        "--no-media-key",
        action="store_true",
        help="Only fetch the LAN endpoint and CAS tuple",
    )
    parser_stream_local_keys.add_argument(
        "--no-p2p-register",
        action="store_true",
        help="Skip app-style P2P session registration before cloud CAS lookup",
    )
    parser_stream_local_keys.add_argument(
        "--sms-code",
        help="Optional MFA/elevation code for camera media key retrieval",
    )
    parser_stream_h264_summary = subparsers_stream.add_parser(
        "h264-annexb-summary",
        help="Summarize a local H.264 Annex-B file without printing media bytes",
    )
    parser_stream_h264_summary.add_argument(
        "--input",
        required=True,
        help="Input .h264 Annex-B elementary stream",
    )
    parser_stream_h264_summary.add_argument(
        "--max-units",
        type=int,
        default=64,
        help="Maximum NAL-unit samples to include (default: 64)",
    )
    parser_stream_h264_summary.add_argument(
        "--max-idr-windows",
        type=int,
        default=16,
        help="Maximum IDR-window samples to include (default: 16)",
    )
    parser_stream_h264_summary.add_argument(
        "--decode-idr-windows",
        action="store_true",
        help="Run ffmpeg decode checks for each sampled IDR-started window",
    )
    parser_stream_h264_summary.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable for --decode-idr-windows (default: ffmpeg)",
    )
    parser_stream_command_dump_summary = subparsers_stream.add_parser(
        "hcnetsdk-command-dump-summary",
        help="Summarize offline HCNetSDK command-port Frida dump files",
    )
    parser_stream_command_dump_summary.add_argument(
        "--command-frame-dir",
        help="Directory containing ezviz-hcnetsdk-command-frame-*.bin dumps",
    )
    parser_stream_command_dump_summary.add_argument(
        "--inbound-media-file",
        help="Raw ezviz-hcnetsdk-inbound-media-*.bin dump to scan for $ media frames",
    )
    parser_stream_command_dump_summary.add_argument(
        "--playm4-input-dir",
        help="Directory containing *-playm4-input-*.bin dumps from the transform hook",
    )
    parser_stream_command_dump_summary.add_argument(
        "--native-annexb-dir",
        help=(
            "Directory containing native Frida Annex-B dumps, such as "
            "*-playctrl-idmx-aes-frame-after-*.bin"
        ),
    )
    parser_stream_command_dump_summary.add_argument(
        "--native-annexb-label",
        default="playctrl-idmx-aes-frame-after",
        help=(
            "Native Annex-B dump label to summarize with --native-annexb-dir "
            "(default: playctrl-idmx-aes-frame-after)"
        ),
    )
    parser_stream_command_dump_summary.add_argument(
        "--native-annexb-codec",
        choices=("auto", "h264", "hevc"),
        default="auto",
        help="Codec for --native-annexb-dir decode-window checks (default: auto)",
    )
    parser_stream_command_dump_summary.add_argument(
        "--max-frames",
        type=int,
        default=64,
        help="Maximum command/media samples to include (default: 64)",
    )
    parser_stream_command_dump_summary.add_argument(
        "--decode-idr-windows",
        action="store_true",
        help=(
            "Run ffmpeg decode checks for reconstructed H.264 IDR or HEVC IRAP "
            "windows from inbound media and PlayM4 input dumps"
        ),
    )
    parser_stream_command_dump_summary.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable for --decode-idr-windows (default: ffmpeg)",
    )
    parser_stream_plan_generate = subparsers_stream.add_parser(
        "hcnetsdk-command-plan-generate",
        help="Convert a concrete HCNetSDK command-port socket plan to generated JSON",
    )
    parser_stream_plan_generate.add_argument(
        "--input",
        required=True,
        help="Concrete command plan JSON file accepted by save clip --hcnetsdk-command-plan-file",
    )
    parser_stream_plan_generate.add_argument(
        "--output",
        default="-",
        help="Generated command-plan JSON output file, or '-' for stdout (default: -)",
    )
    parser_stream_plan_generate.add_argument(
        "--auth-seed",
        help=(
            "Optional login auth seed from the concrete capture. With --key-hex, "
            "this infers session-relative addend_delta values."
        ),
    )
    parser_stream_plan_generate.add_argument(
        "--key-hex",
        help=(
            "Optional command auth key/challenge hex from the concrete capture. "
            "Use only with owned diagnostic captures."
        ),
    )

    return parser.parse_args(argv)


def _token_has_service_urls(token: dict[str, Any] | None) -> bool:
    """Return True when a saved token carries the CAS sysConf endpoint metadata."""

    service_urls = token.get("service_urls") if token else None
    if not isinstance(service_urls, dict):
        return False
    sys_conf = service_urls.get("sysConf")
    return (
        isinstance(sys_conf, (list, tuple))
        and len(sys_conf) > 16
        and bool(sys_conf[15])
        and bool(sys_conf[16])
    )


def _token_has_refresh_session(token: dict[str, Any] | None) -> bool:
    """Return True when a saved token can refresh itself without credentials."""

    return bool(
        token
        and token.get("session_id")
        and token.get("rf_session_id")
        and token.get("api_url")
    )


def _action_requires_service_urls(args: argparse.Namespace) -> bool:
    """Return True when the selected CLI path needs CAS service metadata."""

    return bool(
        (
            args.action == "stream"
            and (
                args.stream_action == "local-sdk-keys"
                or (args.stream_action == "local-sdk-dump" and args.fetch_cas)
            )
        )
        or (
            args.action == "save"
            and getattr(args, "save_action", None) == "clip"
            and getattr(args, "source", None) == "local-sdk"
        )
    )


def _ensure_client_service_urls(client: EzvizClient) -> None:
    """Refresh the client's token service metadata for CAS-only CLI paths."""

    token = client.export_token()
    if _token_has_service_urls(token):
        return
    service_urls = client.get_service_urls()
    if hasattr(client, "_token"):
        client._token["service_urls"] = service_urls  # noqa: SLF001
    if hasattr(client, "exported_token"):
        cast(Any, client).exported_token["service_urls"] = service_urls


def _login(
    client: EzvizClient,
    token: dict[str, Any] | None = None,
    *,
    require_service_urls: bool = False,
) -> None:
    """Login only when the saved token cannot satisfy the selected action."""
    if token and token.get("session_id") and (
        not require_service_urls or _token_has_service_urls(token)
    ):
        return

    if not (client.account and client.password) and not _token_has_refresh_session(token):
        return

    logged_in = False
    if client.account and client.password:
        try:
            client.login()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.login(sms_code=code_int)
        logged_in = True

    if not logged_in:
        client.login()

    if require_service_urls:
        _ensure_client_service_urls(client)


def _write_json(obj: Any) -> None:
    """Write an object to stdout as pretty JSON."""
    sys.stdout.write(json.dumps(obj, indent=2) + "\n")


def _format_cell(value: Any) -> str:
    """Return a compact printable representation for table cells."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _write_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    """Write rows to stdout as a simple fixed-width table."""
    if not rows:
        sys.stdout.write("No rows returned.\n")
        return

    widths = {column: len(column) for column in columns}
    formatted_rows: list[dict[str, str]] = []
    for row in rows:
        formatted = {column: _format_cell(row.get(column)) for column in columns}
        formatted_rows.append(formatted)
        for column, value in formatted.items():
            widths[column] = max(widths[column], len(value))

    header = "  ".join(column.ljust(widths[column]) for column in columns)
    separator = "  ".join("-" * widths[column] for column in columns)
    sys.stdout.write(header + "\n")
    sys.stdout.write(separator + "\n")
    for row in formatted_rows:
        sys.stdout.write("  ".join(row[column].ljust(widths[column]) for column in columns) + "\n")


def _handle_devices(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices` subcommands (device/status/switch/connection)."""
    if args.device_action == "device":
        _write_json(client.get_device())
        return 0

    if args.device_action == "status":
        data = client.load_cameras(refresh=getattr(args, "refresh", True))
        if args.json:
            _write_json(data)
        else:
            # Enrich with common switch flags when available
            for payload in data.values():
                sw = payload.get("SWITCH")
                if sw is None:
                    continue

                # Compute all switch flags present on the device
                flags: dict[str, bool] = {}
                if isinstance(sw, list):
                    for item in sw:
                        if not isinstance(item, dict):
                            continue
                        t = item.get("type")
                        en = item.get("enable")
                        if not isinstance(t, int) or not isinstance(en, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(en)
                elif isinstance(sw, dict):
                    for k, v in sw.items():
                        try:
                            t = int(k)
                        except (TypeError, ValueError):
                            continue
                        if not isinstance(v, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(v)

                if flags:
                    payload["switch_flags"] = flags

                # Keep legacy-friendly individual columns
                payload["sleep"] = flags.get("sleep")
                payload["privacy"] = flags.get("privacy")
                payload["audio"] = flags.get("sound")
                payload["ir_led"] = flags.get("infrared_light")
                payload["state_led"] = flags.get("light")

            columns = [
                "serial",
                "name",
                "status",
                "device_category",
                "device_sub_category",
                "sleep",
                "privacy",
                "audio",
                "ir_led",
                "state_led",
                "local_ip",
                "local_rtsp_port",
                "battery_level",
                "alarm_schedules_enabled",
                "alarm_notify",
                "Motion_Trigger",
            ]
            rows = [
                {"serial": serial, **payload}
                for serial, payload in data.items()
                if isinstance(payload, dict)
            ]
            _write_table(rows, columns)
        return 0

    if args.device_action == "switch":
        _write_json(client.get_switch())
        return 0

    if args.device_action == "connection":
        _write_json(client.get_connection())
        return 0

    _LOGGER.error("Action not implemented: %s", args.device_action)
    return 2


def _handle_devices_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices_light` subcommands (status)."""
    if args.devices_light_action == "status":
        data = client.load_light_bulbs(refresh=getattr(args, "refresh", True))
        if args.json:
            _write_json(data)
        else:
            columns = [
                "serial",
                "name",
                "status",
                "device_category",
                "device_sub_category",
                "local_ip",
                "productId",
                "is_on",
                "brightness",
                "color_temperature",
            ]
            rows = [
                {"serial": serial, **payload}
                for serial, payload in data.items()
                if isinstance(payload, dict)
            ]
            _write_table(rows, columns)
        return 0
    return 2


def _handle_pagelist(client: EzvizClient) -> int:
    """Output full pagelist (raw JSON) for exploration in editors like Notepad++."""
    data = client.get_page_list()
    _write_json(data)
    return 0


def _handle_device_infos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Output device infos mapping (raw JSON), optionally filtered by serial."""
    data = client.get_device_infos(args.serial) if args.serial else client.get_device_infos()
    _write_json(data)
    return 0


def _handle_unifiedmsg(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch unified message list and optionally dump media URLs."""

    response = client.get_device_messages_list(
        serials=args.serials,
        limit=args.limit,
        date=args.date,
        end_time=args.end_time or "",
    )
    raw_messages = response.get("message")
    if not isinstance(raw_messages, list):
        raw_messages = response.get("messages")
    if not isinstance(raw_messages, list):
        raw_messages = []
    messages: list[dict[str, Any]] = [msg for msg in raw_messages if isinstance(msg, dict)]

    def _extract_url(message: dict[str, Any]) -> str | None:
        url = message.get("pic")
        if not url:
            url = message.get("defaultPic") or message.get("image")
        if not url:
            ext = message.get("ext")
            if isinstance(ext, dict):
                pics = ext.get("pics")
                if isinstance(pics, str) and pics:
                    url = pics.split(";")[0]
        return url

    if args.urls_only:
        for item in messages:
            media_url = _extract_url(item)
            if not media_url:
                continue
            sys.stdout.write(f"{item.get('deviceSerial', 'unknown')}: {media_url}\n")
        return 0

    if args.json:
        _write_json(messages)
        return 0

    rows: list[dict[str, Any]] = []
    for item in messages:
        ext = item.get("ext")
        ext_dict = ext if isinstance(ext, dict) else None
        rows.append(
            {
                "deviceSerial": item.get("deviceSerial"),
                "time": item.get("timeStr") or item.get("time"),
                "subType": item.get("subType"),
                "alarmType": ext_dict.get("alarmType") if ext_dict else None,
                "title": item.get("title")
                or item.get("detail")
                or (ext_dict or {}).get("alarmName"),
                "url": _extract_url(item) or "",
                "msgId": item.get("msgId"),
            }
        )

    if rows:
        _write_table(
            rows,
            ["deviceSerial", "time", "subType", "alarmType", "title", "url", "msgId"],
        )
    else:
        sys.stdout.write("No unified messages returned.\n")
    return 0


def _decode_compressed_record_list(value: str) -> list[Any]:
    """Decode the app's base64+zlib JSON record-list payload when present."""

    return _REAL_EZVIZ_CLIENT.decode_records_payload(value)


def _first_record_list(payload: Any) -> list[Any]:
    """Return the first plausible list of record dictionaries from an API response."""

    return _REAL_EZVIZ_CLIENT.extract_record_list(payload)


def _handle_sdcard_videos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch SD-card playback record descriptors."""

    if args.source == "legacy":
        channel_serial = args.channel_serial or args.serial
        response = client.search_records(
            args.serial,
            args.channel,
            channel_serial,
            args.start_time,
            args.stop_time,
            size=args.size,
        )
    elif args.source == "common":
        response = client.search_common_records(
            args.serial,
            args.channel,
            args.start_time,
            args.stop_time,
            channel_serial=args.channel_serial,
            record_type=args.record_type,
            size=args.size,
            version=args.version,
        )
    elif args.source == "intelligent":
        response = client.search_intelligent_records(
            args.serial,
            args.channel,
            args.start_time,
            args.stop_time,
            version=args.version,
            record_filter=args.filter,
        )
    else:
        response = client.search_records_v2(
            args.serial,
            args.channel,
            args.start_time,
            args.stop_time,
            size=args.size,
            sort_by=args.sort_by,
            require_label=args.require_label,
        )

    records = _first_record_list(response)
    if args.json:
        _write_json(records if records else response)
        return 0

    rows: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "begin": item.get("begin")
                or item.get("B")
                or item.get("startTime")
                or item.get("startTimeStr"),
                "end": item.get("end")
                or item.get("E")
                or item.get("stopTime")
                or item.get("stopTimeStr"),
                "type": item.get("type")
                or item.get("Type")
                or item.get("recordType")
                or item.get("videoType"),
                "path": item.get("path") or item.get("filePath") or item.get("fileUrl"),
                "cover": item.get("cover") or item.get("coverUrl") or item.get("coverPic"),
            }
        )

    if rows:
        _write_table(rows, ["begin", "end", "type", "path", "cover"])
    else:
        sys.stdout.write("No SD-card videos returned.\n")
    return 0


def _handle_cloud_videos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch cloud video descriptors and optionally hydrate details."""

    response = client.get_cloud_videos(
        args.serial,
        args.channel,
        limit=args.limit,
        video_type=args.video_type,
        support_multi_channel_shared_service=args.support_multi_channel_shared_service,
    )
    videos = response.get("videos")
    if not isinstance(videos, list):
        videos = []

    if args.details and videos:
        response = client.get_cloud_video_details(
            args.serial,
            args.channel,
            [video for video in videos if isinstance(video, dict)],
            support_multi_channel_shared_service=args.support_multi_channel_shared_service,
        )
        videos = response.get("videos")
        if not isinstance(videos, list):
            videos = []

    if args.json:
        _write_json(videos)
        return 0

    rows: list[dict[str, Any]] = []
    for item in videos:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "seqId": item.get("seqId"),
                "startTime": item.get("startTime"),
                "stopTime": item.get("stopTime"),
                "fileSize": item.get("fileSize"),
                "crypt": item.get("crypt"),
                "keyChecksum": item.get("keyChecksum") or item.get("checksum"),
                "streamUrl": item.get("streamUrl"),
            }
        )

    if rows:
        _write_table(
            rows,
            ["seqId", "startTime", "stopTime", "fileSize", "crypt", "keyChecksum", "streamUrl"],
        )
    else:
        sys.stdout.write("No cloud videos returned.\n")
    return 0


def _handle_cloud_video_download(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch cloud video details, then download the selected media bytes."""

    response = client.get_cloud_videos(
        args.serial,
        args.channel,
        limit=args.limit,
        video_type=args.video_type,
        support_multi_channel_shared_service=args.support_multi_channel_shared_service,
    )
    videos = response.get("videos")
    if not isinstance(videos, list):
        videos = []

    selected = None
    for video in videos:
        if isinstance(video, dict) and str(video.get("seqId")) == str(args.seq_id):
            selected = video
            break
    if selected is None:
        raise PyEzvizError(f"Cloud video seqId {args.seq_id!r} was not returned")

    details_response = client.get_cloud_video_details(
        args.serial,
        args.channel,
        [selected],
        support_multi_channel_shared_service=args.support_multi_channel_shared_service,
    )
    details = details_response.get("videos")
    if isinstance(details, list) and details and isinstance(details[0], dict):
        selected = details[0]

    encrypted_output = Path(args.encrypted_output) if args.encrypted_output else None
    transform = "direct"
    try:
        data = client.download_cloud_video(selected)
    except PyEzvizError:
        if not isinstance(selected.get("streamUrl"), str):
            raise

        ticket = _extract_ticket(
            client.get_camera_ticket_info(
                args.serial,
                args.channel,
                support_multi_channel_shared_service=args.support_multi_channel_shared_service,
            )
        )
        secret_key = client.get_cam_key(args.serial, max_retries=1)

        start_millis = _cloud_video_start_millis(selected)
        stop_millis = start_millis + int(selected.get("videoLong") or 0)
        if stop_millis <= start_millis:
            stop_millis = start_millis + 10_000

        encrypted_data = download_ezviz_cloud_replay(
            stream_url=selected["streamUrl"],
            ticket=ticket,
            serial=args.serial,
            channel=args.channel,
            seq_id=selected.get("seqId") or args.seq_id,
            begin_cas=_cas_time_from_millis(start_millis),
            end_cas=_cas_time_from_millis(stop_millis),
            storage_version=int(selected.get("storageVersion") or 2),
            video_type=int(selected.get("videoType") or args.video_type),
            file_size=(
                int(selected["fileSize"])
                if isinstance(selected.get("fileSize"), int | str)
                and str(selected.get("fileSize")).isdigit()
                else None
            ),
            timeout=args.timeout,
        )
        if encrypted_output is not None:
            encrypted_output.parent.mkdir(parents=True, exist_ok=True)
            encrypted_output.write_bytes(encrypted_data)
        data = decrypt_hikvision_ps_video(
            encrypted_data,
            secret_key,
            nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
        )
        transform = "cloud_replay_python"

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)

    result = {
        "output": str(output),
        "encrypted_output": str(encrypted_output) if encrypted_output else None,
        "bytes": len(data),
        "seqId": selected.get("seqId"),
        "transform": transform,
    }
    if args.json:
        _write_json(result)
    else:
        sys.stdout.write(f"Wrote {len(data)} bytes to {output}\n")
    return 0


def _select_cloud_video_for_seq_id(
    client: EzvizClient,
    *,
    serial: str,
    channel: int,
    seq_id: str,
    limit: int,
    video_type: int,
    support_multi_channel_shared_service: int,
) -> dict[str, Any]:
    """Return a hydrated cloud video descriptor for a selected seqId."""

    response = client.get_cloud_videos(
        serial,
        channel,
        limit=limit,
        video_type=video_type,
        support_multi_channel_shared_service=support_multi_channel_shared_service,
    )
    videos = response.get("videos")
    if not isinstance(videos, list):
        videos = []

    selected = None
    for video in videos:
        if isinstance(video, dict) and str(video.get("seqId")) == str(seq_id):
            selected = video
            break
    if selected is None:
        raise PyEzvizError(f"Cloud video seqId {seq_id!r} was not returned")

    details_response = client.get_cloud_video_details(
        serial,
        channel,
        [selected],
        support_multi_channel_shared_service=support_multi_channel_shared_service,
    )
    details = details_response.get("videos")
    if isinstance(details, list) and details and isinstance(details[0], dict):
        return cast(dict[str, Any], details[0])
    return selected


def _extract_ticket(ticket_response: dict[str, Any]) -> str:
    """Extract the ticket string from known EZVIZ ticketInfo response shapes."""

    candidates: list[Any] = [ticket_response.get("ticketInfo")]
    data = ticket_response.get("data")
    if isinstance(data, dict):
        candidates.append(data.get("ticketInfo"))
    for candidate in candidates:
        if isinstance(candidate, dict) and isinstance(candidate.get("ticket"), str):
            return candidate["ticket"]
    raise PyEzvizError("Camera ticket response does not include ticketInfo.ticket")


def _cloud_video_start_millis(video: dict[str, Any]) -> int:
    """Return cloud clip start time in epoch milliseconds."""

    cover_pic = video.get("coverPic")
    if isinstance(cover_pic, str):
        parsed = urlparse(cover_pic)
        values = parse_qs(parsed.query).get("startTime")
        if values:
            with suppress(ValueError):
                return int(values[0])

    start_time = video.get("startTime")
    if isinstance(start_time, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            with suppress(ValueError):
                parsed_dt = dt.datetime.strptime(start_time, fmt).replace(tzinfo=dt.UTC)
                return int(parsed_dt.timestamp() * 1000)
    raise PyEzvizError("Cloud video descriptor does not include a usable start time")


def _cas_time_from_millis(value: int) -> str:
    """Format epoch milliseconds as the CAS timestamp string used by the app."""

    return dt.datetime.fromtimestamp(value / 1000, tz=dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _handle_cloud_video_decrypt(
    args: argparse.Namespace,
    client: EzvizClient | None,
) -> int:
    """Decrypt a cloud download .tmp file using the Python PS/NAL transform."""

    if bool(args.serial) == bool(args.key):
        raise PyEzvizError("Provide exactly one of --serial or --key")

    if args.key:
        key = args.key
    else:
        if client is None:
            raise PyEzvizError("Provide --key or EZVIZ credentials/token for --serial")
        key = client.get_cam_key(args.serial, max_retries=1)
    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(
        decrypt_hikvision_ps_video(
            input_path.read_bytes(),
            key,
            nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
        )
    )

    result = {"input": str(input_path), "output": str(output_path), "bytes": output_path.stat().st_size}
    if args.json:
        _write_json(result)
    else:
        sys.stdout.write(f"Wrote decrypted cloud video to {output_path}\n")
    return 0


def _write_save_result(args: argparse.Namespace, result: Mapping[str, Any]) -> None:
    """Write a human or JSON result for save commands."""

    if args.json:
        _write_json(result)
    else:
        sys.stdout.write(f"Wrote {result['bytes']} bytes to {result['output']}\n")


def _handle_save_clip(args: argparse.Namespace, client: EzvizClient) -> int:
    """Save a short direct-local camera clip to disk."""

    command_generated_plan = (
        _hcnetsdk_command_generated_plan_from_args(args)
        if args.source == "hcnetsdk-command-port"
        else None
    )
    command_plan = (
        _hcnetsdk_command_plan_from_args(args)
        if args.source == "hcnetsdk-command-port"
        else None
    )
    command_frames = (
        _hcnetsdk_command_frames_from_args(args)
        if (
            args.source == "hcnetsdk-command-port"
            and command_plan is None
            and command_generated_plan is None
        )
        else None
    )
    read_response_after_each = (
        _hcnetsdk_read_response_policy(args, len(command_frames or ()))
        if command_frames is not None
        else True
    )
    hcnetsdk_command_metadata_callback = (
        (
            lambda stream: _write_local_sdk_metadata_output(
                args.hcnetsdk_command_metadata_output,
                stream,
                packet_output_path=args.hcnetsdk_command_sampled_packets_output,
            )
        )
        if (
            args.source == "hcnetsdk-command-port"
            and (
                args.hcnetsdk_command_metadata_output
                or args.hcnetsdk_command_sampled_packets_output
            )
        )
        else None
    )
    output_format = args.format
    if output_format is None:
        output_format = "mpegps" if args.source == "local-sdk-ecdh" else "mpegts"

    save_kwargs: dict[str, Any] = {
        "source": args.source,
        "output_format": output_format,
        "duration_seconds": args.duration,
        "max_packets": args.max_packets,
        "channel": args.channel,
        "ffmpeg_path": args.ffmpeg_path,
        "decrypt_video": args.decrypt_video,
        "nalu_header_size": _codec_nalu_header_size(args.decrypt_codec),
        "cas_serial": args.cas_serial,
        "timeout": args.timeout,
        "smscode": args.sms_code,
        "host": args.host,
        "command_port": args.command_port,
        "hcnetsdk_command_frames": command_frames,
        "hcnetsdk_command_plan": command_plan,
        "hcnetsdk_command_generated_plan": command_generated_plan,
        "hcnetsdk_command_password": args.hcnetsdk_command_password,
        "hcnetsdk_local_ip": args.hcnetsdk_local_ip,
        "hcnetsdk_read_response_after_each": read_response_after_each,
        "hcnetsdk_command_metadata_callback": hcnetsdk_command_metadata_callback,
        "hcnetsdk_h264_skip_initial_idr_windows": (
            args.hcnetsdk_h264_skip_initial_idr_windows
        ),
        "hcnetsdk_h264_trim_to_clean_idr_window": (
            args.hcnetsdk_h264_trim_to_clean_idr_window
        ),
        "hcnetsdk_h264_clean_idr_preroll_seconds": (
            args.hcnetsdk_h264_clean_idr_preroll_seconds
        ),
        "hcnetsdk_h264_clean_idr_max_windows": (
            args.hcnetsdk_h264_clean_idr_max_windows
        ),
        "hcnetsdk_h264_wait_for_clean_idr_window": (
            args.hcnetsdk_h264_wait_for_clean_idr_window
        ),
        "hcnetsdk_h264_clean_idr_wait_seconds": (
            args.hcnetsdk_h264_clean_idr_wait_seconds
        ),
    }
    if args.source in {"local-sdk", "local-sdk-ecdh"}:
        save_kwargs["register_p2p_session"] = not args.no_p2p_register
    if args.source == "local-sdk-ecdh":
        save_kwargs.update(
            {
                "local_sdk_ecdh_receiver_port": args.local_sdk_ecdh_receiver_port,
                "local_sdk_ecdh_send_init": args.local_sdk_ecdh_send_init,
                "local_sdk_ecdh_max_frames": args.local_sdk_ecdh_max_frames,
            }
        )
    if args.source == "cloud":
        save_kwargs.update(
            {
                "cloud_client_type": args.client_type,
                "cloud_token_index": args.token_index,
                "cloud_refresh_vtm": not args.no_refresh_vtm,
            }
        )
    if args.decrypt_video and (
        args.source == "hcnetsdk-command-port" or _local_sdk_has_static_media_key(args)
    ):
        save_kwargs["media_key"] = _local_sdk_media_key(args, client)
    result = client.save_clip(args.serial, args.output, **save_kwargs)
    _write_save_result(args, result)
    return 0


def _hcnetsdk_command_plan_from_args(
    args: argparse.Namespace,
) -> HcNetSdkCommandPortMultiSocketPlan | None:
    """Load a native-style multi-socket command plan from CLI args."""

    plan_file = getattr(args, "hcnetsdk_command_plan_file", None)
    if not plan_file:
        return None
    text = Path(plan_file).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise PyEzvizError("Invalid HCNetSDK command plan JSON") from err
    return _hcnetsdk_command_plan_from_json(data)


def _hcnetsdk_command_generated_plan_from_args(
    args: argparse.Namespace,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan | None:
    """Load a generated multi-socket command plan from CLI args."""

    plan_file = getattr(args, "hcnetsdk_command_generated_plan_file", None)
    native_plan = getattr(args, "hcnetsdk_command_native_plan", None)
    if plan_file and native_plan:
        raise PyEzvizError(
            "Provide only one of --hcnetsdk-command-generated-plan-file or "
            "--hcnetsdk-command-native-plan"
        )
    if native_plan:
        if getattr(args, "channel", 1) != 1:
            raise PyEzvizError(
                "--hcnetsdk-command-native-plan app-lan-live-view currently "
                "supports only --channel 1 because the app-observed command "
                "tails contain channel-1 fields"
            )
        return hcnetsdk_command_port_native_lan_live_view_plan(native_plan)
    if not plan_file:
        return None
    text = Path(plan_file).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise PyEzvizError("Invalid HCNetSDK generated command plan JSON") from err
    return _hcnetsdk_command_generated_plan_from_json(data)


def _hcnetsdk_command_plan_from_json(
    value: Any,
) -> HcNetSdkCommandPortMultiSocketPlan:
    """Build a command-port socket plan from simple JSON shapes."""

    raw_steps: list[Any] | None
    if isinstance(value, list):
        raw_steps = value
    elif isinstance(value, dict):
        raw_steps = None
        for key in ("socket_plan", "socketPlan", "sockets", "sessions", "steps"):
            item = value.get(key)
            if isinstance(item, list):
                raw_steps = item
                break
        if raw_steps is None:
            raise PyEzvizError("HCNetSDK command plan JSON is missing socket steps")
    else:
        raise PyEzvizError("HCNetSDK command plan JSON must be an object or list")

    steps = tuple(_hcnetsdk_command_plan_step_from_json(item) for item in raw_steps)
    return HcNetSdkCommandPortMultiSocketPlan(steps=steps)


def _hcnetsdk_command_generated_plan_from_json(
    value: Any,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Build a generated command-port socket plan from JSON."""

    raw_steps = _hcnetsdk_command_plan_raw_steps(value)
    steps = tuple(
        _hcnetsdk_command_generated_plan_step_from_json(item) for item in raw_steps
    )
    return HcNetSdkCommandPortGeneratedMultiSocketPlan(steps=steps)


def _hcnetsdk_command_plan_raw_steps(value: Any) -> list[Any]:
    """Return raw socket step objects from concrete or generated JSON."""

    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("socket_plan", "socketPlan", "sockets", "sessions", "steps"):
            item = value.get(key)
            if isinstance(item, list):
                return item
        raise PyEzvizError("HCNetSDK command plan JSON is missing socket steps")
    raise PyEzvizError("HCNetSDK command plan JSON must be an object or list")


def _hcnetsdk_command_plan_step_from_json(
    value: Any,
) -> HcNetSdkCommandPortSocketStep:
    """Build one socket step from a JSON object."""

    if not isinstance(value, dict):
        raise PyEzvizError("HCNetSDK command plan step must be an object")
    frames = _hcnetsdk_command_plan_frames_from_json(
        value,
        ("command_frames", "commandFrames", "frames"),
    )
    keepalive_frames = _hcnetsdk_command_plan_frames_from_json(
        value,
        ("keepalive_frames", "keepaliveFrames"),
        required=False,
    )
    media_socket = _hcnetsdk_command_plan_media_socket(value)
    read_policy = _hcnetsdk_command_plan_read_policy(
        value,
        default=not media_socket,
    )
    response_reads = _hcnetsdk_command_plan_response_reads(value)
    read_first_media_immediately = _hcnetsdk_command_plan_immediate_media_read(value)
    delay_after_commands = _hcnetsdk_command_plan_delay_after_commands(value)
    drain_media_before_next = _hcnetsdk_command_plan_drain_media_before_next(value)
    interval = value.get("keepalive_interval_seconds")
    if interval is None:
        interval = value.get("keepaliveIntervalSeconds", 5.0)
    initial_delay = value.get("keepalive_initial_delay_seconds")
    if initial_delay is None:
        initial_delay = value.get("keepaliveInitialDelaySeconds")
    name = value.get("name")
    return HcNetSdkCommandPortSocketStep(
        command_frames=frames,
        read_response_after_each=read_policy,
        response_reads_after_each=response_reads,
        media_socket=media_socket,
        read_first_media_immediately=read_first_media_immediately,
        delay_after_commands_seconds=delay_after_commands,
        drain_media_before_next_step_seconds=drain_media_before_next,
        keepalive_frames=keepalive_frames,
        keepalive_interval_seconds=float(interval),
        keepalive_initial_delay_seconds=(
            None if initial_delay is None else float(initial_delay)
        ),
        name=name if isinstance(name, str) else None,
    )


def _hcnetsdk_command_generated_plan_step_from_json(
    value: Any,
) -> HcNetSdkCommandPortGeneratedSocketStep:
    """Build one generated socket step from a JSON object."""

    if not isinstance(value, dict):
        raise PyEzvizError("HCNetSDK generated command plan step must be an object")
    templates = _hcnetsdk_command_plan_templates_from_json(
        value,
        ("control_templates", "controlTemplates", "templates", "commands"),
    )
    keepalive_templates = _hcnetsdk_command_plan_templates_from_json(
        value,
        ("keepalive_templates", "keepaliveTemplates"),
        required=False,
    )
    media_socket = _hcnetsdk_command_plan_media_socket(value)
    read_policy = _hcnetsdk_command_plan_read_policy(
        value,
        default=not media_socket,
    )
    response_reads = _hcnetsdk_command_plan_response_reads(value)
    read_first_media_immediately = _hcnetsdk_command_plan_immediate_media_read(value)
    delay_after_commands = _hcnetsdk_command_plan_delay_after_commands(value)
    drain_media_before_next = _hcnetsdk_command_plan_drain_media_before_next(value)
    interval = value.get("keepalive_interval_seconds")
    if interval is None:
        interval = value.get("keepaliveIntervalSeconds", 5.0)
    initial_delay = value.get("keepalive_initial_delay_seconds")
    if initial_delay is None:
        initial_delay = value.get("keepaliveInitialDelaySeconds")
    name = value.get("name")
    return HcNetSdkCommandPortGeneratedSocketStep(
        control_templates=templates,
        read_response_after_each=read_policy,
        response_reads_after_each=response_reads,
        media_socket=media_socket,
        read_first_media_immediately=read_first_media_immediately,
        delay_after_commands_seconds=delay_after_commands,
        drain_media_before_next_step_seconds=drain_media_before_next,
        keepalive_templates=keepalive_templates,
        keepalive_interval_seconds=float(interval),
        keepalive_initial_delay_seconds=(
            None if initial_delay is None else float(initial_delay)
        ),
        name=name if isinstance(name, str) else None,
    )


def _hcnetsdk_command_plan_templates_from_json(
    value: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    required: bool = True,
) -> tuple[HcNetSdkCommandPortControlTemplate, ...]:
    """Read generated control templates from one command-plan JSON step."""

    for key in keys:
        item = value.get(key)
        if item is not None:
            templates = tuple(
                _hcnetsdk_command_plan_template_from_json(template)
                for template in _iter_hcnetsdk_command_template_values(item)
            )
            if templates or not required:
                return templates
    if required:
        raise PyEzvizError("HCNetSDK generated command plan step is missing templates")
    return ()


def _iter_hcnetsdk_command_template_values(value: Any) -> Iterator[Any]:
    """Yield generated command template objects from JSON."""

    if isinstance(value, list):
        for item in value:
            yield from _iter_hcnetsdk_command_template_values(item)
        return
    yield value


def _hcnetsdk_command_plan_template_from_json(
    value: Any,
) -> HcNetSdkCommandPortControlTemplate:
    """Build one generated control template from a JSON object."""

    if not isinstance(value, dict):
        raise PyEzvizError("HCNetSDK generated command template must be an object")
    command_id = _hcnetsdk_int_required(
        value,
        ("command_id", "commandId", "command"),
        "HCNetSDK generated command template is missing command_id",
    )
    body_tail = _hcnetsdk_bytes_from_json(
        value,
        ("body_tail", "bodyTail", "body_tail_hex", "bodyTailHex", "tail", "tailHex"),
    )
    addend = _hcnetsdk_optional_int(value, ("addend",))
    addend_delta = _hcnetsdk_optional_int(value, ("addend_delta", "addendDelta"))
    mask_seed = _hcnetsdk_bytes_from_json(
        value,
        ("mask_seed", "maskSeed", "mask_seed_hex", "maskSeedHex"),
        default=b"\x00" * 6,
    )
    body_tail_transform = value.get("body_tail_transform")
    if body_tail_transform is None:
        body_tail_transform = value.get("bodyTailTransform")
    if body_tail_transform is not None and not isinstance(body_tail_transform, str):
        raise PyEzvizError("HCNetSDK body_tail_transform must be a string")
    name = value.get("name")
    return HcNetSdkCommandPortControlTemplate(
        command_id=command_id,
        body_tail=body_tail,
        addend=addend,
        addend_delta=addend_delta,
        mask_seed=mask_seed,
        body_tail_transform=body_tail_transform,
        name=name if isinstance(name, str) else None,
    )


def _hcnetsdk_int_required(
    value: Mapping[str, Any],
    keys: tuple[str, ...],
    message: str,
) -> int:
    """Read a required integer field from a JSON object."""

    for key in keys:
        if key in value:
            return _hcnetsdk_int(value[key])
    raise PyEzvizError(message)


def _hcnetsdk_optional_int(
    value: Mapping[str, Any],
    keys: tuple[str, ...],
) -> int | None:
    """Read an optional integer field from a JSON object."""

    for key in keys:
        if key in value and value[key] is not None:
            return _hcnetsdk_int(value[key])
    return None


def _hcnetsdk_bytes_from_json(
    value: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    default: bytes = b"",
) -> bytes:
    """Read an optional hex byte field from a JSON object."""

    for key in keys:
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str):
            raise PyEzvizError("HCNetSDK byte fields must be hex strings")
        return _bytes_from_hex_value(item)
    return default


def _hcnetsdk_command_plan_frames_from_json(
    value: Mapping[str, Any],
    keys: tuple[str, ...],
    *,
    required: bool = True,
) -> tuple[bytes, ...]:
    """Read a frame list from one command-plan JSON step."""

    for key in keys:
        item = value.get(key)
        if item is not None:
            frames = tuple(
                _bytes_from_hex_value(frame_hex)
                for frame_hex in _iter_hcnetsdk_command_frame_hex_values(item)
            )
            if frames or not required:
                return frames
    if required:
        raise PyEzvizError("HCNetSDK command plan step is missing frames")
    return ()


def _hcnetsdk_command_plan_read_policy(
    value: Mapping[str, Any],
    *,
    default: bool = True,
) -> bool | tuple[bool, ...]:
    """Read the response policy for one command-plan step."""

    raw = value.get("read_response_after_each")
    if raw is None:
        raw = value.get("readResponseAfterEach")
    if raw is None:
        raw = value.get("read_responses")
    if raw is None:
        raw = value.get("readResponses", default)
    if isinstance(raw, list):
        return tuple(_hcnetsdk_bool(raw_value) for raw_value in raw)
    if isinstance(raw, str) and "," in raw:
        return tuple(
            _hcnetsdk_bool(part.strip())
            for part in raw.split(",")
            if part.strip()
        )
    return _hcnetsdk_bool(raw)


def _hcnetsdk_command_plan_response_reads(
    value: Mapping[str, Any],
) -> int | tuple[int, ...] | None:
    """Read optional response-frame counts for one command-plan step."""

    raw = value.get("response_reads_after_each")
    if raw is None:
        raw = value.get("responseReadsAfterEach")
    if raw is None:
        raw = value.get("response_reads")
    if raw is None:
        raw = value.get("responseReads")
    if raw is None:
        return None
    if isinstance(raw, list):
        return tuple(_hcnetsdk_int(raw_value) for raw_value in raw)
    if isinstance(raw, str) and "," in raw:
        return tuple(
            _hcnetsdk_int(part.strip())
            for part in raw.split(",")
            if part.strip()
        )
    return _hcnetsdk_int(raw)


def _hcnetsdk_command_plan_media_socket(value: Mapping[str, Any]) -> bool:
    """Return whether a command-plan step is the media socket."""

    for key in ("media_socket", "mediaSocket", "read_media", "readMedia", "media"):
        raw = value.get(key)
        if raw is not None:
            return _hcnetsdk_bool(raw)
    role = value.get("role")
    return isinstance(role, str) and role.lower() in {"media", "stream"}


def _hcnetsdk_command_plan_immediate_media_read(value: Mapping[str, Any]) -> bool:
    """Return whether a media step should read first media before later steps."""

    for key in (
        "read_first_media_immediately",
        "readFirstMediaImmediately",
        "read_first_media_before_next_step",
        "readFirstMediaBeforeNextStep",
    ):
        raw = value.get(key)
        if raw is not None:
            return _hcnetsdk_bool(raw)
    return False


def _hcnetsdk_command_plan_delay_after_commands(value: Mapping[str, Any]) -> float:
    """Return optional pacing delay after one command-plan step."""

    for key in (
        "delay_after_commands_seconds",
        "delayAfterCommandsSeconds",
        "delay_after_commands",
        "delayAfterCommands",
    ):
        raw = value.get(key)
        if raw is not None:
            delay = float(raw)
            if delay < 0:
                raise PyEzvizError("HCNetSDK command step delay must be non-negative")
            return delay
    return 0.0


def _hcnetsdk_command_plan_drain_media_before_next(value: Mapping[str, Any]) -> float:
    """Return optional media-drain duration before later command-plan steps."""

    for key in (
        "drain_media_before_next_step_seconds",
        "drainMediaBeforeNextStepSeconds",
        "drain_media_before_next_step",
        "drainMediaBeforeNextStep",
    ):
        raw = value.get(key)
        if raw is not None:
            drain = float(raw)
            if drain < 0:
                raise PyEzvizError("HCNetSDK command media drain must be non-negative")
            return drain
    return 0.0


def _hcnetsdk_bool(value: Any) -> bool:
    """Parse permissive boolean values from CLI JSON."""

    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y"}:
            return True
        if normalized in {"0", "false", "no", "n"}:
            return False
    raise PyEzvizError("Invalid HCNetSDK boolean value")


def _hcnetsdk_int(value: Any) -> int:
    """Parse non-negative integer values from CLI JSON."""

    if isinstance(value, bool):
        raise PyEzvizError("Invalid HCNetSDK integer value")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError as err:
            with suppress(ValueError):
                return int(value.strip())
            raise PyEzvizError("Invalid HCNetSDK integer value") from err
    raise PyEzvizError("Invalid HCNetSDK integer value")


def _hcnetsdk_command_frames_from_args(args: argparse.Namespace) -> tuple[bytes, ...]:
    """Load complete command-port frames from CLI hex values or a file."""

    frame_hex_values = list(getattr(args, "hcnetsdk_command_frame_hex", []) or [])
    frames_file = getattr(args, "hcnetsdk_command_frames_file", None)
    if frames_file:
        frame_hex_values.extend(_hcnetsdk_command_frame_hex_values_from_file(frames_file))
    frames = tuple(_bytes_from_hex_value(value) for value in frame_hex_values)
    if not frames:
        raise PyEzvizError(
            "--source hcnetsdk-command-port requires --hcnetsdk-command-frame-hex "
            "or --hcnetsdk-command-frames-file"
        )
    return frames


def _hcnetsdk_command_frame_hex_values_from_file(path: str) -> list[str]:
    """Read command-frame hex values from JSON or text."""

    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [
            line.split("#", 1)[0].strip()
            for line in text.splitlines()
            if line.split("#", 1)[0].strip()
        ]
    return list(_iter_hcnetsdk_command_frame_hex_values(data))


def _iter_hcnetsdk_command_frame_hex_values(value: Any) -> Iterator[str]:
    """Yield command-frame hex strings from simple JSON shapes."""

    if isinstance(value, str):
        yield value
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_hcnetsdk_command_frame_hex_values(item)
        return
    if isinstance(value, dict):
        for key in (
            "hex",
            "frame_hex",
            "frameHex",
            "command_frame_hex",
            "commandFrameHex",
        ):
            item = value.get(key)
            if isinstance(item, str):
                yield item
        for key in ("command_frames", "commandFrames", "frames"):
            item = value.get(key)
            if isinstance(item, list):
                yield from _iter_hcnetsdk_command_frame_hex_values(item)


def _bytes_from_hex_value(value: str) -> bytes:
    """Decode a user-supplied hex byte string."""

    normalized = value.strip().replace(" ", "").replace(":", "").replace("-", "")
    if normalized.startswith(("0x", "0X")):
        normalized = normalized[2:]
    try:
        return bytes.fromhex(normalized)
    except ValueError as err:
        raise PyEzvizError("Invalid HCNetSDK command frame hex") from err


def _hcnetsdk_read_response_policy(
    args: argparse.Namespace,
    frame_count: int,
) -> bool | tuple[bool, ...]:
    """Return response-read policy for command-port bootstrapping."""

    value = getattr(args, "hcnetsdk_read_responses", None)
    if not value:
        return True
    parts = [part.strip().lower() for part in value.split(",") if part.strip()]
    flags = tuple(part in {"1", "true", "yes", "y"} for part in parts)
    if len(flags) != frame_count:
        raise PyEzvizError(
            "--hcnetsdk-read-responses must include one boolean per command frame"
        )
    valid_values = {"1", "0", "true", "false", "yes", "no", "y", "n"}
    unknown = [part for part in parts if part not in valid_values]
    if unknown:
        raise PyEzvizError("Invalid --hcnetsdk-read-responses value")
    return flags


def _handle_save_image(args: argparse.Namespace, client: EzvizClient) -> int:
    """Save a camera image to disk, triggering capture when no URL is supplied."""

    result = client.save_image(
        args.serial,
        args.output,
        channel=args.channel,
        image_url=args.image_url,
        decrypt=not args.no_decrypt,
        smscode=args.sms_code,
    )
    _write_save_result(args, result)
    return 0


def _handle_save(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle person-friendly local save commands."""

    if args.save_action == "clip":
        return _handle_save_clip(args, client)
    if args.save_action == "image":
        return _handle_save_image(args, client)
    _LOGGER.error("Action not implemented, try running with -h switch for help")
    return 2


def _handle_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `light` subcommands (toggle/status)."""
    light_bulb = EzvizLightBulb(client, args.serial)
    _LOGGER.debug("Light bulb loaded")
    if args.light_action == "toggle":
        light_bulb.toggle_switch()
        return 0
    if args.light_action == "status":
        _write_json(light_bulb.status())
        return 0
    _LOGGER.error("Action not implemented for light: %s", args.light_action)
    return 2


def _handle_home_defence_mode(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `home_defence_mode` subcommands (set mode)."""
    if args.mode:
        res = client.api_set_defence_mode(getattr(DefenseModeType, args.mode).value)
        _write_json(res)
        return 0
    return 2


def _handle_mqtt(_: argparse.Namespace, client: EzvizClient) -> int:
    """Connect to MQTT push notifications using current session token."""
    logging.getLogger().setLevel(logging.DEBUG)
    client.login()
    mqtt = client.get_mqtt_client()
    mqtt.connect()
    return 0


def _write_stream_payloads(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    transform_payload: Callable[[bytes], bytes] | None = None,
    flush_each: bool = False,
    monotonic: Any = time.monotonic,
) -> None:
    """Write VTM stream packet bodies to a binary file-like object."""

    deadline = None
    if duration_seconds is not None:
        deadline = monotonic() + duration_seconds

    for packet in stream.iter_packets(max_packets=max_packets):
        if deadline is not None and monotonic() >= deadline:
            break
        if packet.encrypted and not allow_encrypted:
            raise PyEzvizError(
                "Received encrypted VTM stream packet; media decryption is not implemented"
            )
        payload = transform_payload(packet.body) if transform_payload else packet.body
        if payload:
            output.write(payload)
        if flush_each:
            output.flush()
    if transform_payload and hasattr(transform_payload, "flush"):
        tail = transform_payload.flush()
        if tail:
            output.write(tail)
    output.flush()


def _collect_stream_payloads(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    monotonic: Any = time.monotonic,
) -> bytes:
    """Collect VTM stream packet bodies into memory."""

    output = BytesIO()
    try:
        _write_stream_payloads(
            stream,
            output,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            allow_encrypted=allow_encrypted,
            monotonic=monotonic,
        )
    except PyEzvizError as err:
        if output.tell() == 0 or "VTM socket closed" not in str(err):
            raise
        _LOGGER.warning("%s; using partial captured stream", err)
    return output.getvalue()


def _collect_stream_packets(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    monotonic: Any = time.monotonic,
) -> list[Any]:
    """Collect VTM stream packets while preserving packet boundaries."""

    packets: list[Any] = []
    deadline = None
    if duration_seconds is not None:
        deadline = monotonic() + duration_seconds

    try:
        for packet in stream.iter_packets(max_packets=max_packets):
            if deadline is not None and monotonic() >= deadline:
                break
            if packet.encrypted and not allow_encrypted:
                raise PyEzvizError(
                    "Received encrypted VTM stream packet; media decryption is not implemented"
                )
            packets.append(packet)
    except PyEzvizError as err:
        if not packets or "VTM socket closed" not in str(err):
            raise
        _LOGGER.warning("%s; using partial captured stream", err)
    return packets


def _detect_stream_packets_transport(packets: list[Any]) -> StreamTransport:
    """Return the first known media transport from collected VTM packets."""

    for packet in packets:
        transport = detect_transport(packet.body)
        if transport != StreamTransport.UNKNOWN:
            return transport
    return StreamTransport.UNKNOWN


def _rtp_payload_video_codec(payload: bytes) -> str | None:
    """Best-effort codec detection for EZVIZ RTP video payloads."""

    if len(payload) < 2:
        return None
    h264_type = payload[0] & 0x1F
    hevc_type = (payload[0] >> 1) & 0x3F
    if hevc_type in {48, 49} and _is_plausible_hevc_rtp_header(payload):
        return "hevc"
    if 1 <= h264_type <= 5:
        return "h264"
    if hevc_type in {32, 33, 34, 39, 40}:
        return "hevc"
    if h264_type in {7, 8, 24, 28}:
        return "h264"
    return None


def _is_plausible_hevc_rtp_header(payload: bytes) -> bool:
    """Return True when the RTP payload begins with a plausible HEVC NAL header."""

    if len(payload) < 2:
        return False
    forbidden_zero = payload[0] & 0x80 == 0
    layer_id = ((payload[0] & 0x01) << 5) | (payload[1] >> 3)
    temporal_id_plus1 = payload[1] & 0x07
    nal_type = (payload[0] >> 1) & 0x3F
    return forbidden_zero and layer_id == 0 and temporal_id_plus1 > 0 and nal_type <= 49


def _detect_rtp_video_codec(packets: list[Any]) -> str:
    """Detect whether RTP stream packets carry HEVC or H.264 video."""

    fallback: str | None = None
    for packet in packets:
        try:
            payload = rtp_payload(packet.body)
        except PyEzvizError:
            continue
        codec = _rtp_payload_video_codec(payload)
        if codec in {"hevc", "h264"}:
            return codec
        if len(payload) >= 2 and fallback is None:
            hevc_type = (payload[0] >> 1) & 0x3F
            h264_type = payload[0] & 0x1F
            if 0 <= hevc_type <= 50:
                fallback = "hevc"
            elif 1 <= h264_type <= 23:
                fallback = "h264"
    if fallback:
        return fallback
    raise PyEzvizError("Could not detect RTP video codec")


def _rtp_packets_to_annexb(packets: list[Any], *, codec: str) -> bytes:
    """Convert RTP HEVC/H.264 packets to Annex B elementary-stream bytes."""

    output = bytearray()
    fragmented_nal = bytearray()
    in_fragment = False

    def append_nal(nal: bytes) -> None:
        if nal:
            output.extend(b"\x00\x00\x00\x01")
            output.extend(nal)

    for packet in packets:
        payload = rtp_payload(packet.body)
        if codec == "hevc":
            if len(payload) < 2:
                continue
            nal_type = (payload[0] >> 1) & 0x3F
            if nal_type == 48:
                # Aggregation packet. The streams observed here do not include DONL.
                offset = 2
                while offset + 2 <= len(payload):
                    nal_size = int.from_bytes(payload[offset : offset + 2], "big")
                    offset += 2
                    if nal_size <= 0 or offset + nal_size > len(payload):
                        break
                    append_nal(payload[offset : offset + nal_size])
                    offset += nal_size
                in_fragment = False
                fragmented_nal.clear()
            elif nal_type == 49 and len(payload) >= 3:
                fu_header = payload[2]
                starts_fragment = bool(fu_header & 0x80)
                ends_fragment = bool(fu_header & 0x40)
                original_type = fu_header & 0x3F
                if starts_fragment:
                    fragmented_nal = bytearray()
                    fragmented_nal.append((payload[0] & 0x81) | (original_type << 1))
                    fragmented_nal.append(payload[1])
                    fragmented_nal.extend(payload[3:])
                    in_fragment = True
                    if ends_fragment:
                        append_nal(bytes(fragmented_nal))
                        fragmented_nal.clear()
                        in_fragment = False
                elif in_fragment:
                    fragmented_nal.extend(payload[3:])
                    if ends_fragment:
                        append_nal(bytes(fragmented_nal))
                        fragmented_nal.clear()
                        in_fragment = False
            else:
                append_nal(payload)
                in_fragment = False
                fragmented_nal.clear()
            continue

        if codec == "h264":
            nal_type = payload[0] & 0x1F if payload else 0
            if 1 <= nal_type <= 23:
                append_nal(payload)
                in_fragment = False
                fragmented_nal.clear()
            elif nal_type == 24:
                offset = 1
                while offset + 2 <= len(payload):
                    nal_size = int.from_bytes(payload[offset : offset + 2], "big")
                    offset += 2
                    if nal_size <= 0 or offset + nal_size > len(payload):
                        break
                    append_nal(payload[offset : offset + nal_size])
                    offset += nal_size
                in_fragment = False
                fragmented_nal.clear()
            elif nal_type == 28 and len(payload) >= 2:
                fu_indicator = payload[0]
                fu_header = payload[1]
                starts_fragment = bool(fu_header & 0x80)
                ends_fragment = bool(fu_header & 0x40)
                original_type = fu_header & 0x1F
                if starts_fragment:
                    fragmented_nal = bytearray([(fu_indicator & 0xE0) | original_type])
                    fragmented_nal.extend(payload[2:])
                    in_fragment = True
                    if ends_fragment:
                        append_nal(bytes(fragmented_nal))
                        fragmented_nal.clear()
                        in_fragment = False
                elif in_fragment:
                    fragmented_nal.extend(payload[2:])
                    if ends_fragment:
                        append_nal(bytes(fragmented_nal))
                        fragmented_nal.clear()
                        in_fragment = False
            continue

        raise PyEzvizError(f"Unsupported RTP video codec: {codec}")

    return bytes(output)


def _decrypt_annexb_video_bytes(
    client: EzvizClient,
    serial: str,
    data: bytes,
    *,
    codec: str,
) -> bytes:
    """Decrypt Annex B video NAL payload bytes using the MPEG-PS transform."""

    key = client.get_cam_key(serial, max_retries=1)
    if not key:
        raise PyEzvizError("Could not get camera encryption key")
    header_size = _codec_nalu_header_size(codec)
    if header_size is None:
        header_size = 2 if codec == "hevc" else 1
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + data
    return decrypt_hikvision_ps_video(
        video_pes,
        str(key),
        nalu_header_size=header_size,
    )[9:]


def _remux_elementary_video_bytes_to_mpegts(
    data: bytes,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    codec: str,
) -> None:
    """Remux Annex B HEVC/H.264 elementary stream bytes to MPEG-TS."""

    process = _open_mpegts_remux_process(ffmpeg_path, input_format=codec)
    stdout, _stderr = process.communicate(data)
    if process.returncode != 0:
        raise PyEzvizError(f"FFmpeg exited with status {process.returncode}")
    output.write(stdout)
    output.flush()


def _decrypt_stream_payload_bytes(
    client: EzvizClient,
    serial: str,
    data: bytes,
    *,
    codec: str,
) -> bytes:
    """Decrypt captured MPEG-PS stream bytes using the camera encrypt key."""

    key = client.get_cam_key(serial, max_retries=1)
    if not key:
        raise PyEzvizError("Could not get camera encryption key")
    return decrypt_hikvision_ps_video(
        data,
        str(key),
        nalu_header_size=_codec_nalu_header_size(codec),
    )


def _codec_nalu_header_size(codec: str) -> int | None:
    """Return the Annex B NAL header length preserved by the decrypt transform."""

    if codec == "auto":
        return None
    if codec == "hevc":
        return 2
    if codec in {"h264", "h264-clear-header"}:
        return 1
    if codec in {"hevc-encrypted-header", "h264-encrypted-header", "encrypted-header"}:
        return 0
    return 0


class _BufferedStreamPayloadDecryptor:
    """Decrypt MPEG-PS payloads after buffering across VTM packet splits."""

    def __init__(self, key: str, *, codec: str) -> None:
        self._key = key
        self._nalu_header_size = _codec_nalu_header_size(codec)
        self._buffer = bytearray()

    def _decrypt_chunk(self, chunk: bytes) -> bytes:
        if self._nalu_header_size is None:
            detected_nalu_header_size = detect_hikvision_ps_video_nalu_header_size(
                chunk,
                self._key,
                default=None,
            )
            if detected_nalu_header_size is None:
                return decrypt_hikvision_ps_video(
                    chunk,
                    self._key,
                    nalu_header_size=2,
                )
            self._nalu_header_size = detected_nalu_header_size
        return decrypt_hikvision_ps_video(
            chunk,
            self._key,
            nalu_header_size=self._nalu_header_size,
        )

    def __call__(self, data: bytes) -> bytes:
        self._buffer.extend(data)
        complete_end = mpeg_ps_decryptable_prefix_length(self._buffer)
        if complete_end <= 0:
            return b""
        chunk = bytes(self._buffer[:complete_end])
        del self._buffer[:complete_end]
        return self._decrypt_chunk(chunk)

    def flush(self) -> bytes:
        """Decrypt and return any buffered tail at stream end."""

        if not self._buffer:
            return b""
        chunk = bytes(self._buffer)
        self._buffer.clear()
        return self._decrypt_chunk(chunk)


def _stream_payload_decryptor(
    client: EzvizClient,
    serial: str,
    *,
    codec: str,
) -> Callable[[bytes], bytes]:
    """Return a buffered MPEG-PS decryptor using the camera encrypt key."""

    key = client.get_cam_key(serial, max_retries=1)
    if not key:
        raise PyEzvizError("Could not get camera encryption key")
    return _BufferedStreamPayloadDecryptor(str(key), codec=codec)


def _remux_mpegps_bytes_to_mpegts(
    data: bytes,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
) -> None:
    """Remux in-memory MPEG-PS bytes to MPEG-TS."""

    process = _open_mpegts_remux_process(ffmpeg_path)
    stdout, _stderr = process.communicate(data)
    if process.returncode != 0:
        raise PyEzvizError(f"FFmpeg exited with status {process.returncode}")
    output.write(stdout)
    output.flush()


def _remux_stream_payloads_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
) -> None:
    """Remux VTM MPEG-PS payloads to MPEG-TS and write them to output."""

    process = _open_mpegts_remux_process(ffmpeg_path)
    _copy_stream_payloads_to_mpegts(
        stream,
        output,
        process=process,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        allow_encrypted=allow_encrypted,
    )


def _open_mpegts_remux_process(
    ffmpeg_path: str,
    *,
    input_format: str = "mpeg",
) -> subprocess.Popen[bytes]:
    """Open an FFmpeg process ready to remux MPEG-PS stdin to MPEG-TS stdout."""

    try:
        return subprocess.Popen(
            [
                ffmpeg_path,
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                input_format,
                "-i",
                "pipe:0",
                "-c",
                "copy",
                "-f",
                "mpegts",
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err


def _copy_stream_payloads_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    process: subprocess.Popen[bytes],
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    transform_payload: Callable[[bytes], bytes] | None = None,
) -> None:
    """Copy stream payloads through an already-started FFmpeg remuxer."""

    stdin = process.stdin
    stdout = process.stdout
    if stdin is None or stdout is None:
        raise PyEzvizError("Could not open FFmpeg pipes")

    writer_errors: list[Exception] = []

    def _write_input() -> None:
        try:
            _write_stream_payloads(
                stream,
                cast(BinaryIO, stdin),
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                allow_encrypted=allow_encrypted,
                transform_payload=transform_payload,
                flush_each=True,
            )
        except (BrokenPipeError, ConnectionResetError):
            _LOGGER.debug("FFmpeg closed its input pipe")
        except Exception as err:  # pragma: no cover - defensive thread handoff
            writer_errors.append(err)
        finally:
            with suppress(OSError):
                stdin.close()

    writer = Thread(target=_write_input, daemon=True)
    writer.start()
    try:
        while True:
            chunk = stdout.read(65536)
            if not chunk:
                break
            output.write(chunk)
            output.flush()
    finally:
        if process.poll() is None:
            process.terminate()
        writer.join(timeout=2)
        try:
            return_code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait()

    if writer_errors:
        raise writer_errors[0]
    if return_code not in (0, -15):
        raise PyEzvizError(f"FFmpeg exited with status {return_code}")


def _default_stream_proxy_path(serial: str) -> str:
    """Return the default HTTP path for a camera stream."""

    return f"/{serial}.ts"


def _normalize_stream_proxy_path(path: str | None, serial: str) -> str:
    """Normalize a user-supplied proxy path."""

    if not path:
        return _default_stream_proxy_path(serial)
    return path if path.startswith("/") else f"/{path}"


def _handle_stream_proxy_get(
    handler: BaseHTTPRequestHandler,
    config: StreamProxyConfig,
    client: EzvizClient,
) -> None:
    """Handle one experimental VTM-to-MPEG-TS HTTP proxy request."""

    if urlparse(handler.path).path != config.path:
        handler.send_error(404, "Stream not found")
        return

    response_started = False
    try:
        with open_cloud_stream(
            client,
            config.serial,
            channel=config.channel,
            client_type=config.client_type,
            token_index=config.token_index,
            refresh_vtm=config.refresh_vtm,
            timeout=config.timeout,
        ) as stream:
            stream.start()
            process = _open_mpegts_remux_process(config.ffmpeg_path)
            handler.send_response(200)
            response_started = True
            handler.send_header("Content-Type", "video/MP2T")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Connection", "close")
            handler.end_headers()
            _copy_stream_payloads_to_mpegts(
                stream,
                cast(BinaryIO, handler.wfile),
                process=process,
                max_packets=config.max_packets,
                allow_encrypted=config.allow_encrypted,
                transform_payload=(
                    _stream_payload_decryptor(client, config.serial, codec=config.decrypt_codec)
                    if config.decrypt_video
                    else None
                ),
            )
    except (BrokenPipeError, ConnectionResetError):
        _LOGGER.debug("Stream proxy client disconnected")
    except PyEzvizError as err:
        _LOGGER.error("%s", err)
        if response_started:
            if not handler.wfile.closed:
                handler.close_connection = True
        else:
            handler.send_error(502, str(err))


def _serve_stream_proxy(args: argparse.Namespace, client: EzvizClient) -> None:
    """Serve the experimental VTM-to-MPEG-TS HTTP proxy until interrupted."""

    config = StreamProxyConfig(
        serial=args.serial,
        channel=args.channel,
        client_type=args.client_type,
        token_index=args.token_index,
        refresh_vtm=not args.no_refresh_vtm,
        timeout=args.timeout,
        path=_normalize_stream_proxy_path(args.path, args.serial),
        ffmpeg_path=args.ffmpeg_path,
        allow_encrypted=args.allow_encrypted,
        decrypt_video=args.decrypt_video,
        decrypt_codec=args.decrypt_codec,
        max_packets=args.max_packets,
    )

    class StreamProxyHandler(BaseHTTPRequestHandler):
        server_version = "pyezvizapi-stream-proxy/0"

        def do_GET(self) -> None:
            _handle_stream_proxy_get(self, config, client)

        def log_message(self, format: str, *args: Any) -> None:
            _LOGGER.info("stream proxy: " + format, *args)

    try:
        server = StreamProxyHTTPServer(
            (args.listen_host, args.listen_port),
            StreamProxyHandler,
        )
    except OSError as err:
        raise PyEzvizError(
            f"Could not bind stream proxy to {args.listen_host}:{args.listen_port}: {err}"
        ) from err
    url = f"http://{args.listen_host}:{args.listen_port}{config.path}"
    _LOGGER.info("Serving VTM stream proxy at %s", url)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _env_or_arg(args: argparse.Namespace, attr: str, env_name: str) -> str | None:
    """Return a CLI argument value or matching environment fallback."""

    value = getattr(args, attr, None)
    if value:
        return cast(str, value)
    env_value = os_environ_get(env_name)
    return env_value if env_value else None


def os_environ_get(name: str) -> str | None:
    """Small wrapper to make environment fallback easy to patch in tests."""
    return os.environ.get(name)


def _required_local_sdk_secret(
    args: argparse.Namespace,
    attr: str,
    env_name: str,
) -> str:
    """Read a required local-SDK secret without logging or persisting it."""

    value = _env_or_arg(args, attr, env_name)
    if not value:
        raise PyEzvizError(f"Missing --{attr.replace('_', '-')} or {env_name}")
    return value


def _local_sdk_credentials_file(args: argparse.Namespace) -> dict[str, Any]:
    """Read a local-SDK credential bundle without logging secret values."""

    cached = getattr(args, "_local_sdk_credentials_file_data", None)
    if isinstance(cached, dict):
        return cached
    path = getattr(args, "credentials_file", None)
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as err:
        raise PyEzvizError(f"Could not read --credentials-file: {err}") from err
    except json.JSONDecodeError as err:
        raise PyEzvizError(f"Invalid --credentials-file JSON: {err}") from err
    if not isinstance(data, dict):
        raise PyEzvizError("--credentials-file must contain a JSON object")
    vars(args)["_local_sdk_credentials_file_data"] = data
    return data


def _local_sdk_credentials_value(
    args: argparse.Namespace,
    path: tuple[str, ...],
) -> Any:
    """Return a value from the optional local-SDK credential bundle."""

    current: Any = _local_sdk_credentials_file(args)
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _local_sdk_arg_or_credentials(
    args: argparse.Namespace,
    attr: str,
    path: tuple[str, ...],
) -> Any:
    """Return an explicit CLI value or matching credential-bundle value."""

    value = getattr(args, attr, None)
    if value not in (None, ""):
        return value
    return _local_sdk_credentials_value(args, path)


def _required_local_sdk_arg_or_credentials(
    args: argparse.Namespace,
    attr: str,
    path: tuple[str, ...],
) -> Any:
    """Return a required direct-local field from args or credentials file."""

    value = _local_sdk_arg_or_credentials(args, attr, path)
    if value in (None, ""):
        option = attr.replace("_", "-")
        raise PyEzvizError(
            f"Missing --{option}; provide it explicitly or via --credentials-file"
        )
    return value


def _local_sdk_media_key(
    args: argparse.Namespace,
    client: EzvizClient | None,
) -> str | bytes:
    """Read the direct-local media decrypt key without logging or persisting it."""

    key_hex = _env_or_arg(args, "media_key_hex", "EZVIZ_LOCAL_MEDIA_KEY_HEX")
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError as err:
            raise PyEzvizError("Invalid --media-key-hex/EZVIZ_LOCAL_MEDIA_KEY_HEX") from err

    key = _env_or_arg(args, "media_key", "EZVIZ_LOCAL_MEDIA_KEY")
    if key:
        return key
    credential_key_hex = _local_sdk_credentials_value(args, ("media_key_hex",))
    if credential_key_hex:
        try:
            return bytes.fromhex(str(credential_key_hex))
        except ValueError as err:
            raise PyEzvizError("Invalid media_key_hex in --credentials-file") from err
    credential_key = _local_sdk_credentials_value(args, ("media_key",))
    if credential_key:
        return str(credential_key)
    if client is not None:
        serial = str(
            _required_local_sdk_arg_or_credentials(args, "serial", ("serial",))
        )
        sms_code = getattr(args, "sms_code", None)
        if sms_code is None:
            cloud_key = client.get_cam_key(serial, max_retries=1)
        else:
            cloud_key = client.get_cam_key(
                serial,
                smscode=sms_code,
                max_retries=1,
            )
        if cloud_key:
            return str(cloud_key)
    raise PyEzvizError(
        "Missing media key for --decrypt-video; provide --media-key, "
        "--media-key-hex, EZVIZ_LOCAL_MEDIA_KEY, EZVIZ_LOCAL_MEDIA_KEY_HEX, "
        "credentials-file media_key/media_key_hex, or authenticated client access"
    )


def _local_sdk_has_static_media_key(args: argparse.Namespace) -> bool:
    """Return True when local-sdk-dump can decrypt without cloud key lookup."""

    return bool(
        _env_or_arg(args, "media_key_hex", "EZVIZ_LOCAL_MEDIA_KEY_HEX")
        or _env_or_arg(args, "media_key", "EZVIZ_LOCAL_MEDIA_KEY")
        or _local_sdk_credentials_value(args, ("media_key_hex",))
        or _local_sdk_credentials_value(args, ("media_key",))
    )


def _read_optional_binary_file(path: str | None) -> bytes | None:
    """Read an optional caller-owned binary body from disk."""

    if not path:
        return None
    return Path(path).read_bytes()


def _local_sdk_cas_device_info(
    args: argparse.Namespace,
    client: EzvizClient | None,
) -> EzvizCasDeviceInfo:
    """Build local CAS device info from explicit fields or cloud CAS."""

    if args.fetch_cas:
        if client is None:
            raise PyEzvizError("--fetch-cas requires --token-file or credentials")
        serial = str(
            _required_local_sdk_arg_or_credentials(args, "serial", ("serial",))
        )
        cas_serial = args.cas_serial or serial
        if not args.no_p2p_register:
            register = getattr(client, "register_p2p_session", None)
            if callable(register):
                register(max_retries=MAX_RETRIES)
        session = CasDeviceSession.from_response(
            EzvizCAS(client.export_token()).cas_get_encryption(cas_serial)
        )
        return EzvizCasDeviceInfo(
            serial=serial,
            operation_code=session.operation_code,
            key=session.key,
            encrypt_type=session.encrypt_type,
        )

    operation_code = _env_or_arg(
        args,
        "operation_code",
        "EZVIZ_LOCAL_OPERATION_CODE",
    ) or _local_sdk_credentials_value(args, ("cas", "operation_code"))
    if not operation_code:
        raise PyEzvizError(
            "Missing --operation-code or EZVIZ_LOCAL_OPERATION_CODE; "
            "provide it explicitly or via --credentials-file"
        )
    cas_key = _env_or_arg(args, "cas_key", "EZVIZ_LOCAL_CAS_KEY") or (
        _local_sdk_credentials_value(args, ("cas", "key"))
    )
    if not cas_key:
        raise PyEzvizError(
            "Missing --cas-key or EZVIZ_LOCAL_CAS_KEY; "
            "provide it explicitly or via --credentials-file"
        )
    serial = str(
        _required_local_sdk_arg_or_credentials(args, "serial", ("serial",))
    )
    encrypt_type = _local_sdk_arg_or_credentials(
        args,
        "encrypt_type",
        ("cas", "encrypt_type"),
    )
    return EzvizCasDeviceInfo(
        serial=serial,
        operation_code=str(operation_code),
        key=str(cas_key),
        encrypt_type=int(encrypt_type),
    )


def _build_local_sdk_cli_stream(
    args: argparse.Namespace,
    client: EzvizClient | None = None,
) -> Any:
    """Build the direct-local SDK stream from explicit CLI/environment fields."""

    device_info = _local_sdk_cas_device_info(args, client)
    host = str(_required_local_sdk_arg_or_credentials(args, "host", ("endpoint", "host")))
    endpoint = HcNetSdkLanEndpoint(
        serial=device_info.serial,
        host=host,
        command_port=int(
            _local_sdk_arg_or_credentials(
                args,
                "command_port",
                ("endpoint", "command_port"),
            )
            or 9010
        ),
        stream_port=int(
            _local_sdk_arg_or_credentials(
                args,
                "stream_port",
                ("endpoint", "stream_port"),
            )
            or 9020
        ),
    )
    preview_request = EzvizLocalPreviewRequest(
        operation_code=device_info.operation_code,
        channel=args.channel,
        receiver_info=_local_sdk_receiver_info_from_args(args),
        receiver_info_ex=_local_sdk_receiver_info_ex_from_args(args),
        authentication=_local_sdk_authentication_from_args(args),
        is_encrypt=args.is_encrypt,
        identifier=args.identifier,
        uuid=(
            _env_or_arg(args, "uuid", "EZVIZ_LOCAL_UUID")
            if args.receiver_shape == "app"
            else None
        ),
        timestamp=(
            _env_or_arg(args, "timestamp", "EZVIZ_LOCAL_TIMESTAMP")
            if args.receiver_shape == "app"
            else None
        ),
        udt=args.udt,
        nat=args.nat,
        port_guess_type=args.port_guess_type,
        timeout=args.setup_timeout,
        heartbeat_interval=args.heartbeat_interval,
    )
    return open_local_sdk_stream(
        endpoint,
        device_info,
        preview_request,
        timeout=args.socket_timeout,
        pre_start_body=_read_optional_binary_file(args.pre_start_body_file),
        pre_start_sequence=args.pre_start_sequence,
        preview_sequence=args.preview_sequence,
        stream_setup_sequence=args.stream_sequence,
        stream_rate=args.stream_rate,
        stream_mode=args.stream_mode,
        max_prefix_bytes=args.max_prefix_bytes,
        command_source_port=(
            args.receiver_port if args.receiver_shape == "app" else None
        ),
    )


def _build_local_sdk_ecdh_cli_stream(
    args: argparse.Namespace,
    client: EzvizClient | None = None,
) -> Any:
    """Build an encrypted local SDK ECDH stream."""

    device_info = _local_sdk_cas_device_info(args, client)
    host = str(_required_local_sdk_arg_or_credentials(args, "host", ("endpoint", "host")))
    endpoint = HcNetSdkLanEndpoint(
        serial=device_info.serial,
        host=host,
        command_port=int(
            _local_sdk_arg_or_credentials(
                args,
                "command_port",
                ("endpoint", "command_port"),
            )
            or 9010
        ),
        stream_port=int(
            _local_sdk_arg_or_credentials(
                args,
                "stream_port",
                ("endpoint", "stream_port"),
            )
            or 9020
        ),
    )
    return open_local_sdk_ecdh_stream(
        endpoint,
        device_info,
        channel=args.channel,
        receiver_port=args.local_sdk_ecdh_receiver_port,
        send_init=args.local_sdk_ecdh_send_init,
        pre_start_sequence=args.pre_start_sequence,
        preview_sequence=args.preview_sequence,
        stream_setup_sequence=args.stream_sequence,
        timeout=args.socket_timeout,
        max_prefix_bytes=args.max_prefix_bytes,
    )


def _local_sdk_receiver_info_from_args(
    args: argparse.Namespace,
) -> EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs:
    """Build the requested ReceiverInfo XML shape for local-SDK preview."""

    if args.receiver_shape == "structured":
        return EzvizLocalReceiverInfo(
            nat_address=args.nat_address,
            nat_port=args.nat_port,
            upnp_address=args.upnp_address,
            upnp_port=args.upnp_port,
            inner_address=args.inner_address,
            inner_port=args.inner_port,
            stream_type=args.receiver_stream_type,
        )
    return EzvizLocalReceiverInfoAttrs(
        address=args.nat_address,
        port=args.receiver_port,
        server_type=args.receiver_server_type,
        stream_type=args.receiver_stream_type,
        new_stream_type=args.receiver_new_stream_type,
        trans_proto=args.receiver_trans_proto,
    )


def _local_sdk_receiver_info_ex_from_args(
    args: argparse.Namespace,
) -> EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs:
    """Build the requested ReceiverInfoEx XML shape for local-SDK preview."""

    if args.receiver_shape == "structured":
        return EzvizLocalReceiverInfoEx(
            uuid=_env_or_arg(args, "uuid", "EZVIZ_LOCAL_UUID"),
            timestamp=_env_or_arg(args, "timestamp", "EZVIZ_LOCAL_TIMESTAMP"),
        )
    return EzvizLocalReceiverInfoExAttrs(port=args.receiver_ex_port)


def _local_sdk_authentication_from_args(
    args: argparse.Namespace,
) -> EzvizLocalAuthenticationAttrs | None:
    """Return app-shaped Authentication only when that XML shape is requested."""

    if args.receiver_shape == "structured":
        return None
    return EzvizLocalAuthenticationAttrs(
        biz_code=args.auth_biz_code,
        interval=args.auth_interval,
    )


def _handle_local_sdk_stream_dump(
    args: argparse.Namespace,
    client: EzvizClient | None = None,
) -> int:
    """Dump direct-local SDK media with caller-supplied local fields."""

    if args.format is None:
        args.format = "mpegps" if args.local_sdk_ecdh else "mpegts"

    if args.local_sdk_ecdh:
        if args.decrypt_video:
            raise PyEzvizError("--local-sdk-ecdh does not support --decrypt-video")
        if args.format != "mpegps":
            raise PyEzvizError("--local-sdk-ecdh currently supports --format mpegps only")
        with _build_local_sdk_ecdh_cli_stream(args, client) as stream:
            if args.output == "-":
                copy_local_sdk_ecdh_stream_to_mpegps(
                    stream,
                    sys.stdout.buffer,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            else:
                with Path(args.output).open("wb") as output:
                    copy_local_sdk_ecdh_stream_to_mpegps(
                        stream,
                        output,
                        max_packets=args.max_packets,
                        duration_seconds=args.duration,
                    )
            _write_local_sdk_metadata_output(args.metadata_output, stream)
        return 0

    with _build_local_sdk_cli_stream(args, client) as stream:
        if args.output == "-":
            if args.decrypt_video and args.format == "mpegps":
                copy_local_stream_to_decrypted_mpegps(
                    stream,
                    sys.stdout.buffer,
                    _local_sdk_media_key(args, client),
                    nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            elif args.decrypt_video:
                copy_local_stream_to_decrypted_mpegts(
                    stream,
                    sys.stdout.buffer,
                    _local_sdk_media_key(args, client),
                    ffmpeg_path=args.ffmpeg_path,
                    nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            elif args.format == "mpegps":
                copy_local_stream_to_mpegps(
                    stream,
                    sys.stdout.buffer,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            else:
                copy_local_stream_to_mpegts(
                    stream,
                    sys.stdout.buffer,
                    ffmpeg_path=args.ffmpeg_path,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            _write_local_sdk_metadata_output(args.metadata_output, stream)
            return 0

        with Path(args.output).open("wb") as output:
            if args.decrypt_video and args.format == "mpegps":
                copy_local_stream_to_decrypted_mpegps(
                    stream,
                    output,
                    _local_sdk_media_key(args, client),
                    nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            elif args.decrypt_video:
                copy_local_stream_to_decrypted_mpegts(
                    stream,
                    output,
                    _local_sdk_media_key(args, client),
                    ffmpeg_path=args.ffmpeg_path,
                    nalu_header_size=_codec_nalu_header_size(args.decrypt_codec),
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            elif args.format == "mpegps":
                copy_local_stream_to_mpegps(
                    stream,
                    output,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
            else:
                copy_local_stream_to_mpegts(
                    stream,
                    output,
                    ffmpeg_path=args.ffmpeg_path,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                )
        _write_local_sdk_metadata_output(args.metadata_output, stream)
    return 0


def _handle_local_sdk_keys(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch and print direct-local SDK credentials for explicit setup flows."""

    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        args.serial,
        cas_serial=args.cas_serial,
        fetch_media_key=not args.no_media_key,
        register_p2p_session=not args.no_p2p_register,
        smscode=args.sms_code,
    )
    _write_json(credentials.as_dict(include_media_key=not args.no_media_key))
    return 0


def _handle_h264_annexb_summary(args: argparse.Namespace) -> int:
    """Summarize a local H.264 Annex-B elementary stream."""

    data = Path(args.input).read_bytes()
    idr_windows = summarize_h264_annexb_idr_windows(
        data,
        max_windows=args.max_idr_windows,
    )
    summary: dict[str, Any] = {
        "input": args.input,
        "units": summarize_h264_annexb_units(data, max_units=args.max_units),
        "idr_windows": idr_windows,
    }
    if args.decode_idr_windows:
        summary["decode_idr_windows"] = _decode_h264_annexb_idr_windows(
            data,
            idr_windows,
            ffmpeg_path=args.ffmpeg_path,
        )
    _write_json(summary)
    return 0


def _handle_hcnetsdk_command_dump_summary(args: argparse.Namespace) -> int:
    """Summarize offline HCNetSDK command-port dump artifacts."""

    if (
        not args.command_frame_dir
        and not args.inbound_media_file
        and not args.playm4_input_dir
        and not args.native_annexb_dir
    ):
        raise PyEzvizError(
            "hcnetsdk-command-dump-summary requires --command-frame-dir "
            "or --inbound-media-file or --playm4-input-dir or --native-annexb-dir"
        )
    summary: dict[str, Any] = {}
    if args.command_frame_dir:
        summary["command_frames"] = _hcnetsdk_command_frame_dump_summary(
            Path(args.command_frame_dir),
            max_frames=args.max_frames,
        )
    if args.inbound_media_file:
        summary["inbound_media"] = _hcnetsdk_inbound_media_dump_summary(
            Path(args.inbound_media_file),
            max_frames=args.max_frames,
            decode_idr_windows=args.decode_idr_windows,
            ffmpeg_path=args.ffmpeg_path,
        )
    if args.playm4_input_dir:
        summary["playm4_input"] = _hcnetsdk_playm4_input_dump_summary(
            Path(args.playm4_input_dir),
            max_frames=args.max_frames,
            decode_idr_windows=args.decode_idr_windows,
            ffmpeg_path=args.ffmpeg_path,
        )
    if args.native_annexb_dir:
        summary["native_annexb"] = _hcnetsdk_native_annexb_dump_summary(
            Path(args.native_annexb_dir),
            label=args.native_annexb_label,
            codec=args.native_annexb_codec,
            max_frames=args.max_frames,
            decode_idr_windows=args.decode_idr_windows,
            ffmpeg_path=args.ffmpeg_path,
        )
    _write_json(summary)
    return 0


def _hcnetsdk_command_frame_dump_summary(
    directory: Path,
    *,
    max_frames: int,
) -> dict[str, Any]:
    """Return sanitized metadata for dumped outbound command frames."""

    if max_frames <= 0:
        raise PyEzvizError("--max-frames must be positive")
    if not directory.is_dir():
        raise PyEzvizError(f"Command frame dump directory not found: {directory}")

    paths = sorted(directory.rglob("ezviz-hcnetsdk-command-frame-*.bin"))
    samples: list[dict[str, Any]] = []
    command_counts: dict[str, int] = {}
    parse_errors: list[dict[str, str]] = []
    for path in paths:
        try:
            frame_bytes = path.read_bytes()
            frame = parse_hcnetsdk_tcp_frame(frame_bytes)
        except (OSError, PyEzvizError) as err:
            if len(parse_errors) < max_frames:
                parse_errors.append({"path": str(path), "error": str(err)})
            continue

        command_id = (
            frame.header.field_12
            if frame.header.field_4 == HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
            else None
        )
        if command_id is not None:
            key = f"0x{command_id:x}"
            command_counts[key] = command_counts.get(key, 0) + 1
        if len(samples) >= max_frames:
            continue
        sample: dict[str, Any] = {
            "path": str(path),
            "length": len(frame_bytes),
            "total_length": frame.header.total_length,
            "field_4": frame.header.field_4,
            "field_8": frame.header.field_8,
            "field_12": frame.header.field_12,
            "body_length": len(frame.body),
            "body_prefix_hex": frame.body[:16].hex(),
        }
        if command_id is not None:
            sample["command_id"] = command_id
            sample["auth_word"] = frame.header.field_8
            tail = frame.body[16:]
            if tail:
                sample["body_tail_length"] = len(tail)
                sample["body_tail_word_samples"] = (
                    _hcnetsdk_command_port_body_tail_word_samples(tail)
                )
        samples.append(sample)

    return {
        "input": str(directory),
        "file_count": len(paths),
        "sample_limit": max_frames,
        "samples": samples,
        "truncated": len(paths) > len(samples),
        "command_counts": command_counts,
        "parse_errors": parse_errors,
    }


def _hcnetsdk_inbound_media_dump_summary(
    path: Path,
    *,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> dict[str, Any]:
    """Return sanitized metadata for raw dumped command-port inbound media bytes."""

    if max_frames <= 0:
        raise PyEzvizError("--max-frames must be positive")
    try:
        data = path.read_bytes()
    except OSError as err:
        raise PyEzvizError(f"Inbound media dump not found: {path}") from err

    scan = _scan_hcnetsdk_command_port_media_frames(data, max_frames=max_frames)
    summary: dict[str, Any] = {
        "input": str(path),
        "byte_count": len(data),
        **scan,
    }
    payloads = scan.get("payloads")
    if isinstance(payloads, list):
        packet_payloads = cast(list[bytes], payloads)
        summary["idmx_h264"] = summarize_idmx_h264_local_packets(
            packet_payloads,
            max_frames=max_frames,
        )
        _add_hcnetsdk_annexb_dump_summary(
            summary,
            packet_payloads,
            max_frames=max_frames,
            decode_idr_windows=decode_idr_windows,
            ffmpeg_path=ffmpeg_path,
        )
        del summary["payloads"]
    return summary


def _hcnetsdk_playm4_input_dump_summary(
    directory: Path,
    *,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> dict[str, Any]:
    """Return sanitized metadata for PlayM4 input dump chunks."""

    if max_frames <= 0:
        raise PyEzvizError("--max-frames must be positive")
    if not directory.is_dir():
        raise PyEzvizError(f"PlayM4 input dump directory not found: {directory}")

    paths = sorted(directory.rglob("*-playm4-input-*.bin"))
    packets = [path.read_bytes() for path in paths]
    summary: dict[str, Any] = {
        "input": str(directory),
        "file_count": len(paths),
        "byte_count": sum(len(packet) for packet in packets),
        "idmx_h264": summarize_idmx_h264_local_packets(
            packets,
            max_frames=max_frames,
        ),
    }
    _add_hcnetsdk_annexb_dump_summary(
        summary,
        packets,
        max_frames=max_frames,
        decode_idr_windows=decode_idr_windows,
        ffmpeg_path=ffmpeg_path,
    )
    return summary


def _hcnetsdk_native_annexb_dump_summary(
    directory: Path,
    *,
    label: str,
    codec: str,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> dict[str, Any]:
    """Return sanitized metadata for native Annex-B Frida dump chunks."""

    if max_frames <= 0:
        raise PyEzvizError("--max-frames must be positive")
    if not directory.is_dir():
        raise PyEzvizError(f"Native Annex-B dump directory not found: {directory}")

    paths = sorted(directory.rglob(f"*-{label}-*.bin"))
    chunks = [path.read_bytes() for path in paths]
    data = b"".join(chunks)
    detected_codec = _detect_native_annexb_codec(data, requested=codec)
    samples = [
        {
            "path": str(path),
            "size": len(chunk),
            "sha256": hashlib.sha256(chunk).hexdigest(),
        }
        for path, chunk in zip(paths[:max_frames], chunks[:max_frames], strict=False)
    ]
    summary: dict[str, Any] = {
        "input": str(directory),
        "label": label,
        "codec": detected_codec,
        "requested_codec": codec,
        "file_count": len(paths),
        "byte_count": len(data),
        "sample_limit": max_frames,
        "samples": samples,
        "truncated": len(paths) > len(samples),
    }
    if detected_codec == "hevc":
        irap_windows = summarize_hevc_annexb_irap_windows(
            data,
            max_windows=max_frames,
        )
        summary["annexb_irap_windows"] = irap_windows
        if decode_idr_windows:
            summary["decode_irap_windows"] = _decode_annexb_windows(
                data,
                irap_windows,
                ffmpeg_path=ffmpeg_path,
                input_format="hevc",
            )
            summary["decode_chunk_windows"] = _decode_native_annexb_chunk_windows(
                paths,
                codec="hevc",
                max_windows=max_frames,
                ffmpeg_path=ffmpeg_path,
            )
        return summary

    idr_windows = summarize_h264_annexb_idr_windows(
        data,
        max_windows=max_frames,
    )
    summary["annexb_units"] = summarize_h264_annexb_units(
        data,
        max_units=max_frames,
    )
    summary["annexb_idr_windows"] = idr_windows
    if decode_idr_windows:
        summary["decode_idr_windows"] = _decode_annexb_windows(
            data,
            idr_windows,
            ffmpeg_path=ffmpeg_path,
            input_format="h264",
        )
        summary["decode_chunk_windows"] = _decode_native_annexb_chunk_windows(
            paths,
            codec="h264",
            max_windows=max_frames,
            ffmpeg_path=ffmpeg_path,
        )
    return summary


def _decode_native_annexb_chunk_windows(
    paths: list[Path],
    *,
    codec: str,
    max_windows: int,
    ffmpeg_path: str,
) -> list[dict[str, Any]]:
    """Decode sampled IDR/IRAP-bearing native dump chunks independently."""

    results: list[dict[str, Any]] = []
    for path in paths:
        data = path.read_bytes()
        if codec == "hevc":
            windows = summarize_hevc_annexb_irap_windows(data, max_windows=1)
            decoded = _decode_annexb_windows(
                data,
                windows,
                ffmpeg_path=ffmpeg_path,
                input_format="hevc",
            )
        else:
            windows = summarize_h264_annexb_idr_windows(data, max_windows=1)
            decoded = _decode_annexb_windows(
                data,
                windows,
                ffmpeg_path=ffmpeg_path,
                input_format="h264",
            )
        if not decoded:
            continue
        result = {
            "path": str(path),
            "size": len(data),
            **decoded[0],
        }
        results.append(result)
        if len(results) >= max_windows:
            break
    return results


def _detect_native_annexb_codec(data: bytes, *, requested: str) -> str:
    """Return the requested or likely codec for Annex-B dump bytes."""

    if requested != "auto":
        return requested

    h264_score = 0
    hevc_score = 0
    for index, prefix in enumerate(_iter_annexb_nal_prefixes(data)):
        if index >= 256:
            break
        h264_type = prefix[0] & 0x1F
        hevc_type = (prefix[0] >> 1) & 0x3F
        if h264_type in {1, 5, 6, 7, 8, 9}:
            h264_score += 2 if h264_type in {5, 7, 8} else 1
        if hevc_type in {32, 33, 34}:
            hevc_score += 3
        elif 16 <= hevc_type <= 23:
            hevc_score += 2
        elif 0 <= hevc_type <= 31:
            hevc_score += 1
    return "hevc" if hevc_score > h264_score else "h264"


def _iter_annexb_nal_prefixes(data: bytes) -> Iterator[bytes]:
    """Yield the first bytes after Annex-B start codes."""

    offset = 0
    while offset < len(data):
        three = data.find(b"\x00\x00\x01", offset)
        four = data.find(b"\x00\x00\x00\x01", offset)
        if three < 0 and four < 0:
            return
        if four >= 0 and (three < 0 or four <= three):
            start_code_offset = four
            start_code_size = 4
        else:
            start_code_offset = three
            start_code_size = 3
        nal_offset = start_code_offset + start_code_size
        if nal_offset < len(data):
            yield data[nal_offset : nal_offset + 2]
        offset = nal_offset + 1


def _add_hcnetsdk_annexb_dump_summary(
    summary: dict[str, Any],
    packets: list[bytes],
    *,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> None:
    """Attach sanitized reconstructed Annex-B metadata to a dump summary."""

    try:
        annexb, codec = _idmx_local_packets_to_annexb_with_codec(packets)
    except PyEzvizError as err:
        summary["annexb_error"] = str(err)
        return
    summary["annexb_codec"] = codec
    if codec == "hevc":
        irap_windows = summarize_hevc_annexb_irap_windows(
            annexb,
            max_windows=max_frames,
        )
        summary["annexb_irap_windows"] = irap_windows
        if decode_idr_windows:
            summary["decode_irap_windows"] = _decode_annexb_windows(
                annexb,
                irap_windows,
                ffmpeg_path=ffmpeg_path,
                input_format="hevc",
            )
        return

    idr_windows = summarize_h264_annexb_idr_windows(
        annexb,
        max_windows=max_frames,
    )
    summary["annexb_units"] = summarize_h264_annexb_units(
        annexb,
        max_units=max_frames,
    )
    summary["annexb_idr_windows"] = idr_windows
    if decode_idr_windows:
        summary["decode_idr_windows"] = _decode_annexb_windows(
            annexb,
            idr_windows,
            ffmpeg_path=ffmpeg_path,
            input_format="h264",
        )


def _scan_hcnetsdk_command_port_media_frames(
    data: bytes,
    *,
    max_frames: int,
) -> dict[str, Any]:
    """Scan raw command-port bytes for little-endian ``$`` media frames."""

    offset = 0
    payloads: list[bytes] = []
    samples: list[dict[str, Any]] = []
    prefix_bytes = 0
    invalid_markers = 0
    while offset < len(data):
        marker = data.find(b"$", offset)
        if marker < 0:
            prefix_bytes += len(data) - offset
            break
        prefix_bytes += marker - offset
        if marker + 4 > len(data):
            invalid_markers += 1
            break
        channel = data[marker + 1]
        total_length = int.from_bytes(data[marker + 2 : marker + 4], "little")
        if total_length < 4 or marker + total_length > len(data):
            invalid_markers += 1
            offset = marker + 1
            continue
        payload = data[marker + 4 : marker + total_length]
        payloads.append(payload)
        if len(samples) < max_frames:
            samples.append(
                {
                    "index": len(payloads) - 1,
                    "offset": marker,
                    "channel": channel,
                    "total_length": total_length,
                    "payload_length": len(payload),
                    "payload_prefix_hex": payload[:16].hex(),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        offset = marker + total_length

    return {
        "frame_count": len(payloads),
        "prefix_bytes": prefix_bytes,
        "invalid_markers": invalid_markers,
        "sample_limit": max_frames,
        "samples": samples,
        "truncated": len(payloads) > len(samples),
        "payloads": payloads,
    }


def _handle_hcnetsdk_command_plan_generate(args: argparse.Namespace) -> int:
    """Convert concrete port-8000 control frames into generated templates."""

    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise PyEzvizError("Invalid HCNetSDK command plan JSON") from err
    concrete = _hcnetsdk_command_plan_from_json(data)
    auth_seed = None if args.auth_seed is None else _hcnetsdk_int(args.auth_seed)
    key = None if args.key_hex is None else _bytes_from_hex_value(args.key_hex)
    if (auth_seed is None) != (key is None):
        raise PyEzvizError("--auth-seed and --key-hex must be supplied together")
    generated = hcnetsdk_command_port_generated_plan_from_socket_plan(
        concrete,
        auth_seed=auth_seed,
        key=key,
    )
    text = (
        json.dumps(
            _hcnetsdk_generated_plan_to_json(generated),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.output == "-":
        sys.stdout.write(text)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding="utf-8")
    return 0


def _hcnetsdk_generated_plan_to_json(
    plan: HcNetSdkCommandPortGeneratedMultiSocketPlan,
) -> dict[str, Any]:
    """Return the public JSON shape for a generated command-port plan."""

    return {
        "steps": [
            _hcnetsdk_generated_plan_step_to_json(step)
            for step in plan.steps
        ]
    }


def _hcnetsdk_generated_plan_step_to_json(
    step: HcNetSdkCommandPortGeneratedSocketStep,
) -> dict[str, Any]:
    """Return JSON for one generated command-port socket step."""

    value: dict[str, Any] = {
        "templates": [
            _hcnetsdk_command_template_to_json(template)
            for template in step.control_templates
        ],
    }
    if step.name is not None:
        value["name"] = step.name
    if step.read_response_after_each is not True:
        value["read_responses"] = step.read_response_after_each
    if step.response_reads_after_each is not None:
        value["response_reads"] = step.response_reads_after_each
    if step.media_socket:
        value["media_socket"] = True
    if step.read_first_media_immediately:
        value["read_first_media_immediately"] = True
    if step.delay_after_commands_seconds:
        value["delay_after_commands_seconds"] = step.delay_after_commands_seconds
    if step.drain_media_before_next_step_seconds:
        value["drain_media_before_next_step_seconds"] = (
            step.drain_media_before_next_step_seconds
        )
    if step.keepalive_templates:
        value["keepalive_templates"] = [
            _hcnetsdk_command_template_to_json(template)
            for template in step.keepalive_templates
        ]
    if (
        step.keepalive_interval_seconds
        != HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS
    ):
        value["keepalive_interval_seconds"] = step.keepalive_interval_seconds
    if step.keepalive_initial_delay_seconds is not None:
        value["keepalive_initial_delay_seconds"] = (
            step.keepalive_initial_delay_seconds
        )
    return value


def _hcnetsdk_command_template_to_json(
    template: HcNetSdkCommandPortControlTemplate,
) -> dict[str, Any]:
    """Return JSON for one generated command-port control template."""

    value: dict[str, Any] = {
        "command_id": f"0x{template.command_id:x}",
    }
    if template.name is not None:
        value["name"] = template.name
    if template.body_tail:
        value["body_tail_hex"] = template.body_tail.hex()
    if template.addend is not None:
        value["addend"] = f"0x{template.addend:x}"
    if template.addend_delta is not None:
        value["addend_delta"] = template.addend_delta
    if template.mask_seed != b"\x00" * 6:
        value["mask_seed_hex"] = template.mask_seed.hex()
    if template.body_tail_transform is not None:
        value["body_tail_transform"] = template.body_tail_transform
    return value


def _decode_annexb_windows(
    data: bytes,
    window_summary: Mapping[str, Any],
    *,
    ffmpeg_path: str,
    input_format: str,
) -> list[dict[str, Any]]:
    """Return bounded ffmpeg decode results for sampled Annex-B windows."""

    results: list[dict[str, Any]] = []
    samples = window_summary.get("samples")
    if not isinstance(samples, list):
        return results
    for sample in samples:
        if not isinstance(sample, Mapping):
            continue
        start_offset = sample.get("start_code_offset")
        if not isinstance(start_offset, int):
            continue
        cut = data[start_offset:]
        result: dict[str, Any] = {
            "index": sample.get("index"),
            "start_code_offset": start_offset,
            "input_bytes": len(cut),
        }
        try:
            completed = subprocess.run(
                [
                    ffmpeg_path,
                    "-v",
                    "error",
                    "-f",
                    input_format,
                    "-i",
                    "pipe:0",
                    "-f",
                    "null",
                    "-",
                ],
                input=cut,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
        except OSError as err:
            raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err
        except subprocess.TimeoutExpired:
            result["returncode"] = None
            result["decode_clean"] = False
            result["stderr"] = ["ffmpeg decode timed out"]
            results.append(result)
            continue
        stderr_text = completed.stderr.decode("utf-8", errors="replace")
        stderr_lines = [line for line in stderr_text.splitlines() if line][:8]
        result["returncode"] = completed.returncode
        result["decode_clean"] = completed.returncode == 0 and not stderr_lines
        result["stderr"] = stderr_lines
        results.append(result)
    return results


def _decode_h264_annexb_idr_windows(
    data: bytes,
    idr_summary: Mapping[str, Any],
    *,
    ffmpeg_path: str,
) -> list[dict[str, Any]]:
    """Return bounded ffmpeg decode results for sampled H.264 IDR windows."""

    return _decode_annexb_windows(
        data,
        idr_summary,
        ffmpeg_path=ffmpeg_path,
        input_format="h264",
    )


def _write_local_sdk_metadata_output(
    path: str | None,
    stream: Any,
    *,
    packet_output_path: str | None = None,
) -> None:
    """Write safe stream metadata and optional bounded packet samples."""

    metadata = _local_sdk_stream_metadata(stream)
    if packet_output_path:
        _write_hcnetsdk_sampled_packet_output(packet_output_path, stream)
    if path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _write_hcnetsdk_sampled_packet_output(path: str, stream: Any) -> None:
    """Write bounded sampled command-port packets as raw dump-compatible frames."""

    packets = getattr(stream, "_idmx_summary_packets", None)
    if not isinstance(packets, list):
        return
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output:
        for packet in packets:
            if not isinstance(packet, bytes):
                continue
            output.write(b"$\0")
            output.write((len(packet) + 4).to_bytes(2, "little"))
            output.write(packet)


def _local_sdk_stream_metadata(stream: Any) -> dict[str, Any]:
    """Return non-secret direct-local SDK bootstrap and media metadata."""

    finalize_packet_summary = getattr(stream, "finalize_packet_summary", None)
    if callable(finalize_packet_summary):
        finalize_packet_summary()

    bootstrap = getattr(stream, "bootstrap", None)
    metadata: dict[str, Any] = {
        "bootstrap_complete": bootstrap is not None,
    }
    sdk_client = getattr(stream, "sdk_client", None)
    endpoint = getattr(sdk_client, "endpoint", None)
    if endpoint is not None:
        metadata["endpoint"] = {
            "serial": getattr(endpoint, "serial", None),
            "host": getattr(endpoint, "host", None),
            "command_port": getattr(endpoint, "command_port", None),
            "stream_port": getattr(endpoint, "stream_port", None),
        }
    if bootstrap is None:
        return metadata

    command_port_exchanges = getattr(bootstrap, "exchanges", None)
    if command_port_exchanges is not None:
        metadata["command_port_exchanges"] = [
            _hcnetsdk_command_port_exchange_metadata(exchange)
            for exchange in command_port_exchanges
        ]
    packet_summary = getattr(stream, "packet_summary", None)
    if isinstance(packet_summary, dict):
        metadata["packets"] = packet_summary
    keepalive_events = getattr(stream, "keepalive_events", None)
    if keepalive_events:
        metadata["keepalive_events"] = [
            {
                "index": getattr(event, "index", None),
                "command_id": getattr(event, "command_id", None),
                "elapsed_seconds": getattr(event, "elapsed_seconds", None),
                "sent": getattr(event, "sent", None),
                "error": getattr(event, "error", None),
            }
            for event in keepalive_events
        ]

    exchanges: dict[str, Any] = {}
    for name in ("pre_start", "preview", "stream_setup"):
        exchange = getattr(bootstrap, name, None)
        if exchange is None:
            continue
        response = getattr(exchange, "response", None)
        header = getattr(response, "header", None)
        body = getattr(response, "body", b"")
        body_shape = classify_ezviz_local_sdk_body(body)
        exchanges[name] = {
            "response_command": getattr(header, "command", None),
            "response_sequence": getattr(header, "sequence", None),
            "response_status": getattr(header, "status", None),
            "response_body_length": getattr(header, "body_length", None),
            "response_body_kind": body_shape.kind,
            "response_xml_tags": list(body_shape.xml_tags),
        }
    metadata["exchanges"] = exchanges

    first_media = getattr(bootstrap, "first_media", None)
    if first_media is not None:
        frame = first_media.frame
        metadata["first_media"] = {
            "prefix_length": len(first_media.prefix),
            "prefix_sha256": hashlib.sha256(first_media.prefix).hexdigest(),
            "channel": frame.header.channel,
            "payload_length": frame.header.payload_length,
            "payload_sha256": hashlib.sha256(frame.payload).hexdigest(),
        }
    return metadata


def _hcnetsdk_command_port_exchange_metadata(exchange: Any) -> dict[str, Any]:
    """Return non-secret metadata for one command-port request/response."""

    frame = getattr(exchange, "request", b"")
    response = getattr(exchange, "response", None)
    metadata: dict[str, Any] = {
        "request_length": len(frame),
    }
    if len(frame) >= 16:
        metadata["request_command_family"] = int.from_bytes(frame[4:8], "big")
        metadata["request_auth_word"] = int.from_bytes(frame[8:12], "big")
        metadata["request_command_id"] = int.from_bytes(frame[12:16], "big")
    if len(frame) > 32:
        tail = frame[32:]
        metadata["request_body_tail_length"] = len(tail)
        metadata["request_body_tail_word_samples"] = (
            _hcnetsdk_command_port_body_tail_word_samples(tail)
        )

    if response is None:
        metadata["response"] = None
        return metadata

    header = getattr(response, "header", None)
    body = getattr(response, "body", b"")
    metadata["response"] = {
        "total_length": getattr(header, "total_length", None),
        "field_4": getattr(header, "field_4", None),
        "field_8": getattr(header, "field_8", None),
        "field_12": getattr(header, "field_12", None),
        "body_length": len(body),
        "body_prefix_hex": body[:16].hex(),
    }
    if body:
        metadata["response"]["body_word_samples"] = (
            _hcnetsdk_command_port_body_word_samples(body)
        )
    return metadata


def _hcnetsdk_command_port_body_word_samples(
    body: bytes,
    *,
    max_samples: int = 16,
) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit body words for diagnostics."""

    samples: list[dict[str, int]] = []
    for offset in range(0, len(body) - 3, 4):
        value = int.from_bytes(body[offset : offset + 4], "big")
        if value == 0:
            continue
        samples.append({"offset": offset, "be": value})
        if len(samples) >= max_samples:
            break
    return samples


def _hcnetsdk_command_port_body_tail_word_samples(
    tail: bytes,
    *,
    max_samples: int = 16,
) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit request-tail words for diagnostics."""

    return _hcnetsdk_command_port_body_word_samples(
        tail,
        max_samples=max_samples,
    )


def _handle_stream(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle experimental stream helpers."""

    if args.stream_action not in {
        "trace",
        "dump",
        "proxy",
        "local-sdk-dump",
        "local-sdk-keys",
        "h264-annexb-summary",
        "hcnetsdk-command-dump-summary",
        "hcnetsdk-command-plan-generate",
    }:
        _LOGGER.error("Action not implemented, try running with -h switch for help")
        return 2

    if args.stream_action == "hcnetsdk-command-dump-summary":
        return _handle_hcnetsdk_command_dump_summary(args)

    if args.stream_action == "hcnetsdk-command-plan-generate":
        return _handle_hcnetsdk_command_plan_generate(args)

    if args.stream_action == "h264-annexb-summary":
        return _handle_h264_annexb_summary(args)

    if args.stream_action == "local-sdk-keys":
        return _handle_local_sdk_keys(args, client)

    if args.stream_action == "local-sdk-dump":
        return _handle_local_sdk_stream_dump(args, client)

    if args.stream_action == "proxy":
        _serve_stream_proxy(args, client)
        return 0

    with open_cloud_stream(
        client,
        args.serial,
        channel=args.channel,
        client_type=args.client_type,
        token_index=args.token_index,
        refresh_vtm=not args.no_refresh_vtm,
        timeout=args.timeout,
    ) as stream:
        if args.stream_action == "dump":
            stream.start()
            if args.decrypt_video and args.duration is None and args.max_packets is None:
                raise PyEzvizError(
                    "--decrypt-video requires --duration or --max-packets to bound memory use"
                )
            collected_packets: list[Any] | None = None
            if args.decrypt_video:
                collected_packets = _collect_stream_packets(
                    stream,
                    max_packets=args.max_packets,
                    duration_seconds=args.duration,
                    allow_encrypted=args.allow_encrypted,
                )
                transport = _detect_stream_packets_transport(collected_packets)
                if transport == StreamTransport.RTP:
                    rtp_codec = _detect_rtp_video_codec(collected_packets)
                    decrypt_codec = (
                        rtp_codec if args.decrypt_codec == "auto" else args.decrypt_codec
                    )
                    payload = _rtp_packets_to_annexb(collected_packets, codec=rtp_codec)
                    payload = _decrypt_annexb_video_bytes(
                        client,
                        args.serial,
                        payload,
                        codec=decrypt_codec,
                    )
                    if args.output == "-":
                        if args.format == "raw":
                            sys.stdout.buffer.write(payload)
                            sys.stdout.buffer.flush()
                        else:
                            _remux_elementary_video_bytes_to_mpegts(
                                payload,
                                sys.stdout.buffer,
                                ffmpeg_path=args.ffmpeg_path,
                                codec=rtp_codec,
                            )
                    else:
                        with Path(args.output).open("wb") as output:
                            if args.format == "raw":
                                output.write(payload)
                                output.flush()
                            else:
                                _remux_elementary_video_bytes_to_mpegts(
                                    payload,
                                    output,
                                    ffmpeg_path=args.ffmpeg_path,
                                    codec=rtp_codec,
                                )
                    return 0
            if args.output == "-":
                if args.decrypt_video:
                    payload = b"".join(packet.body for packet in collected_packets or [])
                    payload = _decrypt_stream_payload_bytes(
                        client,
                        args.serial,
                        payload,
                        codec=args.decrypt_codec,
                    )
                    if args.format == "raw":
                        sys.stdout.buffer.write(payload)
                        sys.stdout.buffer.flush()
                    else:
                        _remux_mpegps_bytes_to_mpegts(
                            payload,
                            sys.stdout.buffer,
                            ffmpeg_path=args.ffmpeg_path,
                        )
                elif args.format == "raw":
                    _write_stream_payloads(
                        stream,
                        sys.stdout.buffer,
                        max_packets=args.max_packets,
                        duration_seconds=args.duration,
                        allow_encrypted=args.allow_encrypted,
                    )
                else:
                    _remux_stream_payloads_to_mpegts(
                        stream,
                        sys.stdout.buffer,
                        ffmpeg_path=args.ffmpeg_path,
                        max_packets=args.max_packets,
                        duration_seconds=args.duration,
                        allow_encrypted=args.allow_encrypted,
                    )
            else:
                with Path(args.output).open("wb") as output:
                    if args.decrypt_video:
                        payload = b"".join(packet.body for packet in collected_packets or [])
                        payload = _decrypt_stream_payload_bytes(
                            client,
                            args.serial,
                            payload,
                            codec=args.decrypt_codec,
                        )
                        if args.format == "raw":
                            output.write(payload)
                            output.flush()
                        else:
                            _remux_mpegps_bytes_to_mpegts(
                                payload,
                                output,
                                ffmpeg_path=args.ffmpeg_path,
                            )
                    elif args.format == "raw":
                        _write_stream_payloads(
                            stream,
                            output,
                            max_packets=args.max_packets,
                            duration_seconds=args.duration,
                            allow_encrypted=args.allow_encrypted,
                        )
                    else:
                        _remux_stream_payloads_to_mpegts(
                            stream,
                            output,
                            ffmpeg_path=args.ffmpeg_path,
                            max_packets=args.max_packets,
                            duration_seconds=args.duration,
                            allow_encrypted=args.allow_encrypted,
                        )
            return 0

        events = [event.as_dict() for event in stream.trace_packets(max_packets=args.max_packets)]

    if args.json_lines:
        for event in events:
            sys.stdout.write(json.dumps(event, sort_keys=True) + "\n")
    else:
        _write_json(events)
    return 0


def _handle_camera(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `camera` subcommands (status/move/unlock/switch/alarm/select)."""
    camera = EzvizCamera(client, args.serial)
    _LOGGER.debug("Camera loaded")

    if args.camera_action == "move":
        camera.move(args.direction, args.speed)
        return 0

    if args.camera_action == "move_coords":
        camera.move_coordinates(args.x, args.y)
        return 0

    if args.camera_action == "status":
        _write_json(camera.status(refresh=getattr(args, "refresh", True)))
        return 0

    if args.camera_action == "unlock-door":
        camera.door_unlock()
        return 0

    if args.camera_action == "unlock-gate":
        camera.gate_unlock()
        return 0

    if args.camera_action == "switch":
        if args.switch == "ir":
            camera.switch_device_ir_led(args.enable)
        elif args.switch == "state":
            sys.stdout.write(str(args.enable) + "\n")
            camera.switch_device_state_led(args.enable)
        elif args.switch == "audio":
            camera.switch_device_audio(args.enable)
        elif args.switch == "privacy":
            camera.switch_privacy_mode(args.enable)
        elif args.switch == "sleep":
            camera.switch_sleep_mode(args.enable)
        elif args.switch == "follow_move":
            camera.switch_follow_move(args.enable)
        elif args.switch == "sound_alarm":
            camera.switch_sound_alarm(args.enable + 1)
        else:
            _LOGGER.error("Unknown switch: %s", args.switch)
            return 2
        return 0

    if args.camera_action == "alarm":
        if args.sound is not None:
            camera.alarm_sound(args.sound)
        if args.notify is not None:
            camera.alarm_notify(args.notify)
        if args.sensibility is not None:
            camera.alarm_detection_sensibility(args.sensibility)
        if args.do_not_disturb is not None:
            camera.do_not_disturb(args.do_not_disturb)
        if args.schedule is not None:
            camera.change_defence_schedule(args.schedule)
        return 0

    if args.camera_action == "select":
        if args.battery_work_mode is not None:
            camera.set_battery_camera_work_mode(
                getattr(BatteryCameraWorkMode, args.battery_work_mode)
            )
            return 0
        return 2

    _LOGGER.error("Action not implemented, try running with -h switch for help")
    return 2


def _load_token_file(path: str | None) -> dict[str, Any] | None:
    """Load a token dictionary from `path` if it exists; else return None."""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(p.read_text(encoding="utf-8")))
    except (
        OSError,
        json.JSONDecodeError,
    ):  # pragma: no cover - tolerate malformed file
        _LOGGER.warning("Failed to read token file: %s", p)
        return None


def _save_token_file(path: str | None, token: dict[str, Any]) -> None:
    """Persist the token dictionary to `path` in JSON format."""
    if not path:
        return
    p = Path(path)
    try:
        p.write_text(json.dumps(token, indent=2), encoding="utf-8")
        _LOGGER.info("Saved token to %s", p)
    except OSError:  # pragma: no cover - filesystem issues
        _LOGGER.warning("Failed to save token file: %s", p)


def _save_clip_can_run_without_cloud_credentials(args: argparse.Namespace) -> bool:
    return (
        args.action == "save"
        and getattr(args, "save_action", None) == "clip"
        and getattr(args, "source", None) == "hcnetsdk-command-port"
        and (not args.decrypt_video or _local_sdk_has_static_media_key(args))
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

    token = _load_token_file(args.token_file)
    has_session_token = bool(token and token.get("session_id"))
    if args.action == "cloud_video_decrypt" and args.key and not args.serial and not token:
        try:
            return _handle_cloud_video_decrypt(args, None)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if (
        args.action == "stream"
        and args.stream_action == "local-sdk-dump"
        and not args.fetch_cas
        and (not args.decrypt_video or _local_sdk_has_static_media_key(args))
    ):
        try:
            return _handle_local_sdk_stream_dump(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "h264-annexb-summary":
        try:
            return _handle_h264_annexb_summary(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "hcnetsdk-command-dump-summary":
        try:
            return _handle_hcnetsdk_command_dump_summary(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "hcnetsdk-command-plan-generate":
        try:
            return _handle_hcnetsdk_command_plan_generate(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1

    if _save_clip_can_run_without_cloud_credentials(args):
        client = EzvizClient(args.username, args.password, args.region, token=token)
        try:
            return _handle_save(args, client)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
        finally:
            client.close_session()

    if not has_session_token and (not args.username or not args.password):
        _LOGGER.error("Provide --token-file (existing) or --username/--password")
        return 2

    client = EzvizClient(args.username, args.password, args.region, token=token)
    try:
        _login(
            client,
            token,
            require_service_urls=_action_requires_service_urls(args),
        )

        if args.action == "devices":
            return _handle_devices(args, client)
        if args.action == "devices_light":
            return _handle_devices_light(args, client)
        if args.action == "light":
            return _handle_light(args, client)
        if args.action == "home_defence_mode":
            return _handle_home_defence_mode(args, client)
        if args.action == "mqtt":
            return _handle_mqtt(args, client)
        if args.action == "stream":
            return _handle_stream(args, client)
        if args.action == "save":
            return _handle_save(args, client)
        if args.action == "camera":
            return _handle_camera(args, client)
        if args.action == "pagelist":
            return _handle_pagelist(client)
        if args.action == "device_infos":
            return _handle_device_infos(args, client)
        if args.action == "unifiedmsg":
            return _handle_unifiedmsg(args, client)
        if args.action == "sdcard_videos":
            return _handle_sdcard_videos(args, client)
        if args.action == "cloud_videos":
            return _handle_cloud_videos(args, client)
        if args.action == "cloud_video_download":
            return _handle_cloud_video_download(args, client)
        if args.action == "cloud_video_decrypt":
            return _handle_cloud_video_decrypt(args, client)

    except PyEzvizError as exp:
        _LOGGER.error("%s", exp)
        return 1
    except KeyboardInterrupt:
        _LOGGER.error("Interrupted")
        return 130
    else:
        _LOGGER.error("Action not implemented: %s", args.action)
        return 2
    finally:
        if args.save_token and args.token_file:
            _save_token_file(args.token_file, client.export_token())
        client.close_session()


if __name__ == "__main__":
    sys.exit(main())
