"""Explicit LAN-only service controls; no account or token-file access."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from ipaddress import IPv4Address
import json
import math
from pathlib import Path
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    EzvizLanServicesSwitchState,
    HcNetSdkLanEndpoint,
    HcNetSdkPurePythonClient,
)

_MAX_PASSWORD_BYTES = 1024
_NUL = b"\0"


def add_lan_arguments(subparsers: Any) -> None:
    """Add discoverable RTSP controls with explicit local credentials."""
    parser = subparsers.add_parser("lan", help="Local device controls (no account login)")
    commands = parser.add_subparsers(dest="lan_action", required=True)
    rtsp = commands.add_parser("rtsp", help="Read or change the local RTSP service switch")
    rtsp.add_argument("rtsp_action", choices=("status", "enable", "disable"))
    rtsp.add_argument("--host", required=True, help="Camera IPv4 address")
    rtsp.add_argument("--serial", required=True, help="Camera serial")
    rtsp.add_argument("--lan-password-file", required=True, help="Private device password file")
    rtsp.add_argument("--lan-username", default="admin", help="Local SDK user (default: admin)")
    rtsp.add_argument("--command-port", type=int, default=8000)
    rtsp.add_argument("--local-ip", help="Optional local IPv4 address used in SDK login")
    rtsp.add_argument(
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
