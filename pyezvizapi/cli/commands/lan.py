"""Explicit LAN-only service controls; no account or token-file access."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from functools import partial
from ipaddress import IPv4Address
import json
import math
from pathlib import Path
import time
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    EZVIZ_LAN_PTZ_ACTION_START,
    EZVIZ_LAN_PTZ_ACTION_STOP,
    EzvizLanServicesSwitchState,
    EzvizPtzCommand,
    HcNetSdkCommandPortControlResponse,
    HcNetSdkLanEndpoint,
    HcNetSdkPurePythonClient,
)

_MAX_PASSWORD_BYTES = 1024
_NUL = b"\0"
_PTZ_DIRECTIONS = {
    "up": EzvizPtzCommand.UP,
    "down": EzvizPtzCommand.DOWN,
    "left": EzvizPtzCommand.LEFT,
    "right": EzvizPtzCommand.RIGHT,
}
_PTZ_MAX_DURATION = 5.0
_PTZ_STOP_ATTEMPTS = 2
_PTZ_SPEED_RANGE = range(1, 8)


def add_lan_arguments(subparsers: Any) -> None:
    """Add discoverable RTSP controls with explicit local credentials."""
    parser = subparsers.add_parser("lan", help="Local device controls (no account login)")
    commands = parser.add_subparsers(dest="lan_action", required=True)
    rtsp = commands.add_parser("rtsp", help="Read or change the local RTSP service switch")
    rtsp.add_argument("rtsp_action", choices=("status", "enable", "disable"))
    _add_endpoint_arguments(rtsp)
    ptz = commands.add_parser("ptz", help="Move the camera for a bounded time, then stop")
    ptz.add_argument("direction", choices=tuple(_PTZ_DIRECTIONS))
    ptz.add_argument(
        "--duration",
        type=float,
        default=0.5,
        help=f"Seconds between start and stop (default: 0.5, max: {_PTZ_MAX_DURATION:g})",
    )
    ptz.add_argument("--speed", type=int, default=4, help="PTZ speed 1-7 (default: 4)")
    ptz.add_argument("--channel", type=int, default=1, help="Camera channel (default: 1)")
    _add_endpoint_arguments(ptz)


def _add_endpoint_arguments(parser: Any) -> None:
    """Add the shared explicit local credential and socket options."""
    parser.add_argument("--host", required=True, help="Camera IPv4 address")
    parser.add_argument("--serial", required=True, help="Camera serial")
    parser.add_argument("--lan-password-file", required=True, help="Private device password file")
    parser.add_argument("--lan-username", default="admin", help="Local SDK user (default: admin)")
    parser.add_argument("--command-port", type=int, default=8000)
    parser.add_argument("--local-ip", help="Optional local IPv4 address used in SDK login")
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Finite socket timeout in seconds"
    )


def _rtsp_value(state: EzvizLanServicesSwitchState) -> int:
    """Reject absent/unknown/malformed switches before any device write."""
    services = state.raw.get("servicesSwitch") if state.raw is not None else None
    value = services.get("rtsp") if isinstance(services, Mapping) else None
    if (type(value) is int and value in (0, 1)) or (isinstance(value, str) and value in ("0", "1")):
        return int(value)
    raise PyEzvizError("Device does not expose a recognized RTSP service switch")


def _local_client(args: argparse.Namespace) -> HcNetSdkPurePythonClient:
    """Validate all inputs before constructing a device client."""
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise PyEzvizError("timeout must be finite and positive")
    if not 0 < args.command_port <= 65535:
        raise PyEzvizError("command-port must be between 1 and 65535")
    IPv4Address(args.host)
    if args.local_ip is not None:
        IPv4Address(args.local_ip)
    if not args.serial.strip() or not args.lan_username.strip():
        raise PyEzvizError("serial and LAN username must not be empty")
    # Device passwords are short; do not read unbounded user-selected files.
    with Path(args.lan_password_file).open("rb") as password_file:
        password = password_file.read(_MAX_PASSWORD_BYTES + 1).rstrip(b"\r\n")
    if not password or len(password) > _MAX_PASSWORD_BYTES or _NUL in password:
        raise PyEzvizError("Invalid device password file")
    return HcNetSdkPurePythonClient(
        HcNetSdkLanEndpoint(args.serial, args.host, command_port=args.command_port),
        password,
        username=args.lan_username,
        local_ip=args.local_ip,
        timeout=args.timeout,
    )


def handle_lan(args: argparse.Namespace) -> int:
    """Dispatch one explicit LAN-only action."""
    if args.lan_action == "ptz":
        return _handle_ptz(args)
    return _handle_rtsp(args)


def _ptz_acknowledged(response: HcNetSdkCommandPortControlResponse) -> bool:
    """Match the 16-byte acknowledgment observed for accepted PTZ frames."""
    header = response.response.header
    return (header.total_length, header.field_4, header.field_8, header.field_12) == (16, 1, 1, 0)


def _handle_ptz(args: argparse.Namespace) -> int:
    """Start one direction, wait a bounded time, then always try to stop.

    An acknowledgment means the camera accepted the frame, not that it moved.
    The motor can start as soon as the start frame is written, so the duration
    counts from that moment and the wait for the start acknowledgment never
    runs past it: at the deadline the stop is sent, acknowledged or not. Only
    an acknowledged start waits out the duration; any other outcome stops at
    once. Start is never retried. Stop is retried once, after an error or a
    missing acknowledgment, since a start without a stop leaves the motor
    running.

    Each stop attempt, login included, must finish within --timeout. Worst
    case run time is therefore the duration plus one --timeout, or two when
    the first stop attempt fails before its frame is written. A start without
    an acknowledgment is closed with a reset, so a start packet lost on the
    network is not retransmitted after the stop.
    """
    stage = "arguments"
    start = stop = "not-sent"
    try:
        if not math.isfinite(args.duration) or not 0 < args.duration <= _PTZ_MAX_DURATION:
            raise PyEzvizError(f"duration must be greater than 0 and at most {_PTZ_MAX_DURATION:g}")
        if args.speed not in _PTZ_SPEED_RANGE:
            raise PyEzvizError("speed must be between 1 and 7")
        if args.channel < 0:
            raise PyEzvizError("channel must be non-negative")
        client = _local_client(args)
        command = _PTZ_DIRECTIONS[args.direction]
        start_sent: list[float] = []
        stage = "start"
        try:
            reply = client.ptz_control(
                command,
                action=EZVIZ_LAN_PTZ_ACTION_START,
                channel=args.channel,
                speed=args.speed,
                ack_timeout=args.duration,
                on_sent=lambda: start_sent.append(time.monotonic()),
            )
            start = "acknowledged" if _ptz_acknowledged(reply) else "unacknowledged"
            if start == "acknowledged":
                remaining = start_sent[0] + args.duration - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
        finally:
            if start == "not-sent" and start_sent:
                start = "unacknowledged"
            for attempt in range(_PTZ_STOP_ATTEMPTS):
                stop_sent: list[bool] = []
                try:
                    reply = client.ptz_control(
                        command,
                        action=EZVIZ_LAN_PTZ_ACTION_STOP,
                        channel=args.channel,
                        speed=args.speed,
                        on_sent=partial(stop_sent.append, True),
                        deadline=time.monotonic() + args.timeout,
                    )
                except (PyEzvizError, OSError):
                    if stop_sent:
                        stop = "unacknowledged"
                    if attempt + 1 == _PTZ_STOP_ATTEMPTS:
                        raise
                    continue
                if _ptz_acknowledged(reply):
                    stop = "acknowledged"
                    break
                stop = "unacknowledged"
        if start != "acknowledged":
            raise PyEzvizError("Device did not acknowledge the PTZ start")
        stage = "stop"
        if stop != "acknowledged":
            raise PyEzvizError("Device did not acknowledge the PTZ stop")
    except (PyEzvizError, OSError, ValueError) as error:
        message = str(error) if type(error) is PyEzvizError else "LAN operation failed"
        if stage == "start" and start == "acknowledged":
            stage = "stop"
        if stage != "arguments":
            message = "PTZ command unavailable, refused, or not acknowledged"
        print(
            json.dumps(
                {
                    "ok": False,
                    "stage": stage,
                    "message": message,
                    "start": start,
                    "stop": stop,
                    "stopped": stop == "acknowledged",
                }
            )
        )
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "direction": args.direction,
                "duration": args.duration,
                "stopped": True,
                "verified": "acknowledgment",
            }
        )
    )
    return 0


def _handle_rtsp(args: argparse.Namespace) -> int:
    """Read, optionally update RTSP alone, then verify device configuration.

    No automatic write retry: firmware can restart services before acknowledging
    a write. A failed write/read-back has an unknown outcome, not proven rollback.
    """
    stage = "arguments"
    write_attempted = False
    try:
        client = _local_client(args)
        stage = "read"
        before = client.services_switch_state()
        current = _rtsp_value(before)
        desired = {"enable": 1, "disable": 0}.get(args.rtsp_action, current)
        if desired != current:
            stage = "write"
            write_attempted = True
            response = client.services_switch_set(before.raw, rtsp=desired)
            status = response.json().get("statusCode") if response.succeeded else None
            if type(status) is not int or status != 1:
                raise PyEzvizError("Device refused the RTSP switch update")
            stage = "read-back"
            current = _rtsp_value(client.services_switch_state())
            if current != desired:
                raise PyEzvizError("RTSP configuration read-back did not match")
    except (PyEzvizError, OSError, ValueError) as error:
        # Never expose response bodies, password paths or arbitrary socket errors.
        message = str(error) if type(error) is PyEzvizError else "LAN operation failed"
        # Transport PyEzvizError messages may include device-controlled data too.
        if stage != "arguments":
            message = "RTSP switch unavailable, refused, or not verified"
        print(
            json.dumps(
                {
                    "ok": False,
                    "stage": stage,
                    "message": message,
                    "outcome": "unknown" if write_attempted else "not-written",
                }
            )
        )
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "rtsp": current,
                "enabled": current == 1,
                "changed": write_attempted,
                "verified": "configuration",
            }
        )
    )
    return 0
