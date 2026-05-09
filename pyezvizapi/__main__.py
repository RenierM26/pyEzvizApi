"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import argparse
from contextlib import suppress
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import subprocess
import sys
from threading import Thread
import time
from typing import Any, BinaryIO, cast
from urllib.parse import urlparse

from .camera import EzvizCamera
from .client import EzvizClient
from .cloud_stream import open_cloud_stream
from .constants import BatteryCameraWorkMode, DefenseModeType, DeviceSwitchType
from .exceptions import EzvizAuthVerificationCode, PyEzvizError
from .light_bulb import EzvizLightBulb

_LOGGER = logging.getLogger(__name__)


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
    max_packets: int | None


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
    logging.basicConfig(
        level=level, stream=sys.stderr, format="%(levelname)s: %(message)s"
    )
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
    parser.add_argument(
        "--debug", "-d", action="store_true", help="Print debug messages to stderr"
    )
    parser.add_argument(
        "--json", action="store_true", help="Force JSON output when possible"
    )
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

    parser_device = subparsers.add_parser(
        "devices", help="Play with all devices at once"
    )
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

    parser_device_lights = subparsers.add_parser(
        "devices_light", help="Get all the light bulbs"
    )
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

    parser_camera_alarm = subparsers_camera.add_parser(
        "alarm", help="Configure the camera alarm"
    )
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
            mode.name
            for mode in BatteryCameraWorkMode
            if mode is not BatteryCameraWorkMode.UNKNOWN
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
        "--max-packets",
        type=int,
        default=None,
        help="Stop each HTTP stream after this many packets (default: unlimited)",
    )

    return parser.parse_args(argv)


def _login(client: EzvizClient) -> None:
    """Login if credentials are configured; skip when only a token is used."""
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
    data = (
        client.get_device_infos(args.serial)
        if args.serial
        else client.get_device_infos()
    )
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
                "title": item.get("title") or item.get("detail") or (ext_dict or {}).get("alarmName"),
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
                "Received encrypted VTM stream packet; "
                "media decryption is not implemented"
            )
        output.write(packet.body)
        if flush_each:
            output.flush()
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

    process = subprocess.Popen(
        [
            ffmpeg_path,
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "mpeg",
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
    stdin = process.stdin
    stdout = process.stdout
    if stdin is None or stdout is None:
        raise PyEzvizError("Could not open FFmpeg pipes")

    writer_errors: list[BaseException] = []

    def _write_input() -> None:
        try:
            _write_stream_payloads(
                stream,
                cast(BinaryIO, stdin),
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                allow_encrypted=allow_encrypted,
                flush_each=True,
            )
        except (BrokenPipeError, ConnectionResetError):
            pass
        except BaseException as err:  # pragma: no cover - defensive thread handoff
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
        max_packets=args.max_packets,
    )

    class StreamProxyHandler(BaseHTTPRequestHandler):
        server_version = "pyezvizapi-stream-proxy/0"

        def do_GET(self) -> None:
            if urlparse(self.path).path != config.path:
                self.send_error(404, "Stream not found")
                return

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
                    self.send_response(200)
                    self.send_header("Content-Type", "video/MP2T")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    _remux_stream_payloads_to_mpegts(
                        stream,
                        cast(BinaryIO, self.wfile),
                        ffmpeg_path=config.ffmpeg_path,
                        max_packets=config.max_packets,
                        allow_encrypted=config.allow_encrypted,
                    )
            except (BrokenPipeError, ConnectionResetError):
                _LOGGER.debug("Stream proxy client disconnected")
            except PyEzvizError as err:
                _LOGGER.error("%s", err)
                if not self.wfile.closed:
                    self.close_connection = True

        def log_message(self, format: str, *args: Any) -> None:
            _LOGGER.info("stream proxy: " + format, *args)

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), StreamProxyHandler)
    url = f"http://{args.listen_host}:{args.listen_port}{config.path}"
    _LOGGER.info("Serving VTM stream proxy at %s", url)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _handle_stream(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle experimental stream helpers."""

    if args.stream_action not in {"trace", "dump", "proxy"}:
        _LOGGER.error("Action not implemented, try running with -h switch for help")
        return 2

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
            if args.output == "-":
                if args.format == "raw":
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
                    if args.format == "raw":
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

        events = [
            event.as_dict()
            for event in stream.trace_packets(max_packets=args.max_packets)
        ]

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


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _setup_logging(args.debug)

    token = _load_token_file(args.token_file)
    if not token and (not args.username or not args.password):
        _LOGGER.error("Provide --token-file (existing) or --username/--password")
        return 2

    client = EzvizClient(args.username, args.password, args.region, token=token)
    try:
        _login(client)

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
        if args.action == "camera":
            return _handle_camera(args, client)
        if args.action == "pagelist":
            return _handle_pagelist(client)
        if args.action == "device_infos":
            return _handle_device_infos(args, client)
        if args.action == "unifiedmsg":
            return _handle_unifiedmsg(args, client)

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
