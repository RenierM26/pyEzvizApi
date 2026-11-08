"""Shared endpoint validation, bounded reads and numeric LAN SD errors."""

from __future__ import annotations

from ipaddress import IPv4Address
import time
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import HcNetSdkLanEndpoint


class LanPlaybackError(PyEzvizError):
    """A LAN playback operation failed with a numeric device response."""

    def __init__(self, stage: str, result_code: int) -> None:
        self.stage = stage
        self.result_code = result_code
        self.source = "local-playback"
        super().__init__(f"LAN SD playback {stage} refused (result {result_code})")


def read_exact(
    sock: Any, size: int, deadline: float, timeout: float, *, operation: str = "download"
) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PyEzvizError("LAN SD transfer deadline expired")
        sock.settimeout(min(timeout, remaining))
        try:
            chunk = sock.recv(size - len(data))
        except TimeoutError:
            raise PyEzvizError(f"LAN SD {operation} timed out before its end marker") from None
        if not chunk:
            raise PyEzvizError(f"LAN SD {operation} ended before its complete end marker")
        data.extend(chunk)
    return bytes(data)


def validate_connection(
    endpoint: HcNetSdkLanEndpoint, username: str, password: str | bytes
) -> None:
    if (
        not isinstance(password, str | bytes)
        or not 0 < len(password.encode() if isinstance(password, str) else password) <= 64
    ):
        raise PyEzvizError("LAN SD requires a supplied device password of 1-64 bytes")
    if not isinstance(username, str) or not username or len(username.encode()) > 32:
        raise PyEzvizError("LAN SD requires a username of 1-32 bytes")
    if not isinstance(endpoint.host, str):
        raise PyEzvizError("LAN SD requires an explicit camera IPv4 address")
    try:
        address = IPv4Address(endpoint.host)
    except (ValueError, TypeError):
        raise PyEzvizError("LAN SD requires an explicit camera IPv4 address") from None
    if address.is_unspecified or address.is_multicast:
        raise PyEzvizError("LAN SD camera address must be unicast")
    if (
        isinstance(endpoint.command_port, bool)
        or not isinstance(endpoint.command_port, int)
        or not 1 <= endpoint.command_port <= 65535
    ):
        raise PyEzvizError("LAN SD command port is invalid")
    if (
        not isinstance(endpoint.serial, str)
        or len(endpoint.serial) < 9
        or not endpoint.serial.isascii()
        or not endpoint.serial.isalnum()
    ):
        raise PyEzvizError(
            "LAN SD requires the full device serial (at least 9 ASCII alphanumeric characters)"
        )
