"""Command-specific argparse builders; no client/session construction."""

from __future__ import annotations

import argparse
from typing import Any

from pyezvizapi.constants import LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT, BatteryCameraWorkMode
from pyezvizapi.streaming.capture import _SOURCE_DEFAULT_DURATION, _SourceDefaultClientType
from pyezvizapi.streaming.cloud.playback_range import (
    DEFAULT_PLAYBACK_MAX_BYTES,
    DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
)
from pyezvizapi.streaming.local.transport import HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW


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


def add_devices_arguments(subparsers: Any) -> None:
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


def add_devices_light_arguments(subparsers: Any) -> None:
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


def add_light_arguments(subparsers: Any) -> None:
    parser_light = subparsers.add_parser("light", help="Light actions")
    parser_light.add_argument("--serial", required=True, help="light bulb SERIAL")

    subparsers_light = parser_light.add_subparsers(dest="light_action")
    subparsers_light.add_parser("toggle", help="Toggle the light bulb")
    subparsers_light.add_parser("status", help="Get information about the light bulb")


def add_home_defence_mode_arguments(subparsers: Any) -> None:
    parser_home_defence_mode = subparsers.add_parser(
        "home_defence_mode", help="Set home defence mode"
    )
    parser_home_defence_mode.add_argument(
        "--mode", required=False, help="Choose mode", choices=["HOME_MODE", "AWAY_MODE"]
    )


def add_mqtt_arguments(subparsers: Any) -> None:
    subparsers.add_parser("mqtt", help="Connect to mqtt push notifications")


def add_camera_arguments(subparsers: Any) -> None:
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


def add_pagelist_arguments(subparsers: Any) -> None:
    subparsers.add_parser("pagelist", help="Output full pagelist as JSON")


def add_device_infos_arguments(subparsers: Any) -> None:
    parser_device_infos = subparsers.add_parser(
        "device_infos",
        help="Output device infos (raw JSON), optionally filtered by serial",
    )
    parser_device_infos.add_argument(
        "--serial", required=False, help="Optional serial to filter a single device"
    )


def add_unifiedmsg_arguments(subparsers: Any) -> None:
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


def add_sdcard_videos_arguments(subparsers: Any) -> None:
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


def add_cloud_videos_arguments(subparsers: Any) -> None:
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


def add_cloud_video_download_arguments(subparsers: Any) -> None:
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


def add_cloud_video_decrypt_arguments(subparsers: Any) -> None:
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


def add_save_arguments(subparsers: Any) -> None:
    parser_save = subparsers.add_parser(
        "save",
        help="Save a local live clip or camera image to a file",
    )
    subparsers_save = parser_save.add_subparsers(dest="save_action")
    add_save_clip_arguments(subparsers_save)
    add_save_image_arguments(subparsers_save)


def add_save_clip_arguments(subparsers_save: Any) -> None:
    parser_save_clip = subparsers_save.add_parser(
        "clip",
        help="Save a direct-local camera clip to a local file",
    )
    parser_save_clip.add_argument("--serial", required=True, help="camera SERIAL")
    parser_save_clip.add_argument(
        "--source",
        choices=(
            "auto",
            "local-sdk",
            "local-sdk-ecdh",
            "cloud",
            "hcnetsdk-command-port",
            "cloud-playback",
        ),
        default="local-sdk",
        help=(
            "Source to use: automatic metadata-first selection, direct 9010/9020 SDK, encrypted local SDK ECDH, "
            "VTM cloud live stream, or full HCNetSDK command-port media on "
            "port 8000 (default: local-sdk)"
        ),
    )
    parser_save_clip.add_argument(
        "--decrypt-audio",
        action="store_true",
        help="Explicitly decrypt encrypted SD ADTS AAC (cloud-playback only)",
    )
    parser_save_clip.add_argument("--begin-time", help="SD playback UTC begin: YYYYMMDDTHHMMSSZ")
    parser_save_clip.add_argument("--end-time", help="SD playback UTC end: YYYYMMDDTHHMMSSZ")
    parser_save_clip.add_argument(
        "--lid", help="Optional native SD playback label/session selector"
    )
    parser_save_clip.add_argument(
        "--playback-max-bytes",
        type=int,
        default=DEFAULT_PLAYBACK_MAX_BYTES,
        help="SD playback byte budget (default: 128 MiB)",
    )
    parser_save_clip.add_argument(
        "--playback-transfer-timeout",
        type=float,
        default=DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
        help="SD playback total transfer budget, including bootstrap (seconds)",
    )
    parser_save_clip.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Camera channel number (default: auto for cloud, 1 for local)",
    )
    parser_save_clip.add_argument(
        "--output",
        required=True,
        help="Local output path for the clip",
    )
    parser_save_clip.add_argument(
        "--duration",
        type=_parse_duration_seconds,
        default=_SOURCE_DEFAULT_DURATION,
        help="Capture duration; accepts seconds or units like 10s/1m (default: full range for cloud-playback, 10s otherwise)",
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
            "defaults to mpegps for clear local-sdk-ecdh, mpegts otherwise"
        ),
    )
    parser_save_clip.add_argument(
        "--ffmpeg-path",
        default="ffmpeg",
        help="FFmpeg executable to use for MPEG-TS remuxing (default: ffmpeg)",
    )
    parser_save_clip.add_argument(
        "--native-shared-clock",
        action="store_true",
        help=(
            "Experimental native TCP 90kHz/16kHz shared-epoch assertion; "
            "explicit local-sdk/hcnetsdk-command-port MPEG-TS only, not app smoothing"
        ),
    )
    parser_save_clip.add_argument(
        "--decrypt-video",
        action="store_true",
        help=(
            "Decrypt encrypted media before writing/remuxing; supported cloud "
            "RTP AAC is retained when native descriptor metadata is present"
        ),
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
        default=None,
        help=(
            "Video codec transform for --decrypt-video; defaults to auto for "
            "cloud and direct-local SDK streams, encrypted-header for HCNetSDK"
        ),
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
        default=None,
        help=(
            "Receiver port to include in local SDK ECDH preview XML "
            f"(default: auto allocates a fresh port; explicit ECDH uses {LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT})"
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
        "--local-sdk-ecdh-max-prefix-bytes",
        type=int,
        default=4096,
        help=(
            "Maximum pre-media prefix bytes to skip on the local SDK ECDH stream (default: 4096)"
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
            "One complete port-8000 HCNetSDK command frame as hex. May be passed more than once."
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
        default=None,
        help=(
            "For clear IDMX command-port streams, discard startup media until "
            "a decodable H.264 IDR or HEVC IRAP window is found, then start the requested "
            "duration window. This is automatic for bounded generated LAN plans."
        ),
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-video-no-wait-for-clean-window",
        dest="hcnetsdk_h264_wait_for_clean_idr_window",
        action="store_false",
        default=None,
        help="Disable automatic clean-window waiting for HCNetSDK generated LAN plans.",
    )
    parser_save_clip.add_argument(
        "--hcnetsdk-h264-clean-idr-wait-seconds",
        "--hcnetsdk-video-clean-window-wait-seconds",
        dest="hcnetsdk_h264_clean_idr_wait_seconds",
        type=float,
        default=60.0,
        help=("Maximum seconds to wait for a clean video window before failing (default: 60)."),
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
        default=_SourceDefaultClientType(9),
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


def add_save_image_arguments(subparsers_save: Any) -> None:
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


def add_stream_arguments(subparsers: Any) -> None:
    parser_stream = subparsers.add_parser(
        "stream",
        help="Experimental VTM cloud stream helpers",
    )
    subparsers_stream = parser_stream.add_subparsers(dest="stream_action")
    add_stream_trace_arguments(subparsers_stream)
    add_stream_dump_arguments(subparsers_stream)
    add_stream_proxy_arguments(subparsers_stream)
    add_stream_local_sdk_dump_arguments(subparsers_stream)
    add_stream_local_sdk_keys_arguments(subparsers_stream)
    add_stream_h264_annexb_summary_arguments(subparsers_stream)
    add_stream_hcnetsdk_command_dump_summary_arguments(subparsers_stream)
    add_stream_hcnetsdk_command_plan_generate_arguments(subparsers_stream)


def add_stream_trace_arguments(subparsers_stream: Any) -> None:
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


def add_stream_dump_arguments(subparsers_stream: Any) -> None:
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
            "Decrypt Hikvision/EZVIZ encrypted video NAL payloads and supported "
            "descriptor-backed AAC with the camera encrypt key before "
            "writing/remuxing (experimental)"
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
    parser_stream_dump.add_argument(
        "--sms-code",
        help="Optional MFA/elevation code for media key retrieval",
    )
    parser_stream_dump.add_argument(
        "--media-key",
        help="Camera media decrypt key; used instead of cloud key retrieval",
    )
    parser_stream_dump.add_argument(
        "--media-key-hex",
        help="Hex-encoded binary camera media decrypt key",
    )


def add_stream_proxy_arguments(subparsers_stream: Any) -> None:
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
            "Decrypt Hikvision/EZVIZ encrypted video NAL payloads and supported "
            "descriptor-backed AAC with the camera encrypt key before remuxing "
            "(experimental)"
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
        "--sms-code",
        help="Optional MFA/elevation code for media key retrieval",
    )
    parser_stream_proxy.add_argument(
        "--media-key",
        help="Camera media decrypt key; used instead of cloud key retrieval",
    )
    parser_stream_proxy.add_argument(
        "--media-key-hex",
        help="Hex-encoded binary camera media decrypt key",
    )
    parser_stream_proxy.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="Stop each HTTP stream after this many packets (default: unlimited)",
    )


def add_stream_local_sdk_dump_arguments(subparsers_stream: Any) -> None:  # noqa: PLR0915
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
        help=("Device serial to send to cloud CAS when --fetch-cas is used (default: --serial)"),
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
    parser_stream_local_dump.add_argument("--pre-start-sequence", type=int)
    parser_stream_local_dump.add_argument("--preview-sequence", type=int)
    parser_stream_local_dump.add_argument("--stream-sequence", type=int)
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
            "(default: mpegps for clear --local-sdk-ecdh, mpegts otherwise)"
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


def add_stream_local_sdk_keys_arguments(subparsers_stream: Any) -> None:
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


def add_stream_h264_annexb_summary_arguments(subparsers_stream: Any) -> None:
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


def add_stream_hcnetsdk_command_dump_summary_arguments(subparsers_stream: Any) -> None:
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


def add_stream_hcnetsdk_command_plan_generate_arguments(subparsers_stream: Any) -> None:
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


def build_parser() -> argparse.ArgumentParser:
    """Build CLI syntax without account, camera or optional decoder access."""
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
    add_devices_arguments(subparsers)
    add_devices_light_arguments(subparsers)
    add_light_arguments(subparsers)
    add_home_defence_mode_arguments(subparsers)
    add_mqtt_arguments(subparsers)
    add_camera_arguments(subparsers)
    add_pagelist_arguments(subparsers)
    add_device_infos_arguments(subparsers)
    add_unifiedmsg_arguments(subparsers)
    add_sdcard_videos_arguments(subparsers)
    add_cloud_videos_arguments(subparsers)
    add_cloud_video_download_arguments(subparsers)
    add_cloud_video_decrypt_arguments(subparsers)
    add_save_arguments(subparsers)
    add_stream_arguments(subparsers)
    return parser


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)
