"""Account-free, bounded native HCNetSDK recording enumeration."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime
import socket
import struct
import time
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.cloud.playback_range import (
    native_playback_range,
    playback_integer,
    playback_range,
    positive_timeout,
)
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    hcnetsdk_command_port_rsa_key,
)
from pyezvizapi.streaming.local.playback import (
    LanPlaybackError,
    _read_exact,
    _validate_connection,
)
from pyezvizapi.streaming.recordings import RecordingCatalog, StoredRecording, _record_time, _stamp

_SEARCH = 0x111040
_LOGOUT = 0x10100
_RECORD_BYTES = 80


def lan_recording_search_body(channel: int, begin: str, end: str, timezone: str) -> bytes:
    """Encode the observed FindFile_V30 all-types/unlocked-or-locked selector."""
    playback_integer(channel, "LAN channel")
    if channel > 0xFFFFFFFF:
        raise PyEzvizError("LAN channel exceeds 32 bits")
    fields = [channel, 255, 255, 0, 0, 0, 0, 0, 0]
    for value in native_playback_range(begin, end, timezone):
        instant = datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        fields.extend(
            (instant.year, instant.month, instant.day, instant.hour, instant.minute, instant.second)
        )
    return struct.pack(">21I", *fields) + bytes(64)


def _receive_search(  # noqa: PLR0912 -- validate native streaming marker states
    sock: Any,
    *,
    deadline: float,
    timeout: float,
    max_bytes: int,
    max_records: int,
    begin: datetime,
    end: datetime,
    timezone: str,
) -> tuple[StoredRecording, ...]:
    total = 0
    count = 0
    started = False
    found: set[StoredRecording] = set()
    while True:
        size, kind = struct.unpack(">II", _read_exact(sock, 8, deadline, timeout))
        total += size
        if size < 8 or total > max_bytes or size > 12 + max_records * _RECORD_BYTES:
            raise PyEzvizError("LAN catalog block exceeds its byte budget or native shape")
        if kind == 25:
            if size != 8 or started:
                raise PyEzvizError("Invalid LAN catalog start marker")
            started = True
        elif kind == 26:
            if size != 8 or not started:
                raise PyEzvizError("Invalid LAN catalog end marker")
            return tuple(sorted(found))
        elif kind == 27:
            if not started or size < 12:
                raise PyEzvizError("LAN catalog records arrived without start marker")
            records = struct.unpack(">I", _read_exact(sock, 4, deadline, timeout))[0]
            if not 1 <= records <= max_records or size != 12 + records * _RECORD_BYTES:
                raise PyEzvizError("Invalid LAN catalog record count/length")
            count += records
            if count > max_records:
                raise PyEzvizError("LAN catalog record budget exhausted; narrow the range")
            data = _read_exact(sock, size - 12, deadline, timeout)
            for offset in range(0, len(data), _RECORD_BYTES):
                # Native seconds encode a wall clock, not a UTC instant. SDK
                # FindNext expands these to NET_DVR_TIME without an offset.
                left, right = struct.unpack_from(">II", data, offset + 32)
                wall = [datetime.fromtimestamp(v, UTC).replace(tzinfo=None) for v in (left, right)]
                first, last = (_record_time(v.isoformat(), timezone) for v in wall)
                if last <= first:
                    raise PyEzvizError("LAN catalog returned an invalid recording interval")
                first, last = max(first, begin), min(last, end)
                if first < last:
                    found.add(StoredRecording(_stamp(first), _stamp(last)))
        else:
            raise PyEzvizError("Unsupported LAN catalog block type")


def query_lan_recordings(  # noqa: PLR0913 -- explicit account-free bounds and connection
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    begin_time: str,
    end_time: str,
    *,
    channel: int = 1,
    timezone: str = "UTC",
    username: str = "admin",
    max_records: int = 10000,
    max_bytes: int = 1024 * 1024,
    timeout: float = 10.0,
    transfer_timeout: float = 60.0,
    socket_factory: Callable[..., Any] = socket.create_connection,
) -> RecordingCatalog:
    """Enumerate up to 24h using only the explicit camera endpoint/credential.

    A catalog is returned only after the native end marker and acknowledged
    logout. UTC inputs require the camera's explicit selector timezone. No
    account, HTTP, SDK runtime, fallback or credential guessing is used.
    """
    begin, end = playback_range(begin_time, end_time)
    body = lan_recording_search_body(channel, begin_time, end_time, timezone)
    _validate_connection(endpoint, username, password)
    for name, value in (("max_records", max_records), ("max_bytes", max_bytes)):
        playback_integer(value, name)
    positive_timeout(timeout, "socket timeout")
    positive_timeout(transfer_timeout, "transfer timeout")
    deadline = time.monotonic() + transfer_timeout
    rsa_key = hcnetsdk_command_port_rsa_key()
    session = None
    local_ip = ""

    def client() -> HcNetSdkCommandPortClient:
        return HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)

    def frame(command: int, tail: bytes = b"") -> bytes:
        if session is None:
            raise PyEzvizError("LAN catalog has no owned login")
        return HcNetSdkCommandPortControlTemplate(command, tail).to_frame(
            session_id=session.session_id,
            auth_seed=session.auth_seed,
            key=session.challenge,
            local_ip=local_ip,
        )

    def logout() -> None:
        with closing(client()) as control:
            control.send_command_frame(frame(_LOGOUT), deadline=deadline)
            response = control.read_tcp_frame(max_frame_bytes=4096, deadline=deadline)
            if response.header.field_8 != 1:
                raise LanPlaybackError("catalog logout", response.header.field_8)

    try:
        with closing(client()) as login:
            session = login.login(
                password=password,
                username=username,
                rsa_key=rsa_key,
                max_frame_bytes=4096,
                deadline=deadline,
            )
            local_ip = str(login.sock.getsockname()[0])
            if not session.serial.endswith(endpoint.serial):
                raise PyEzvizError("LAN catalog identity differs from supplied serial")
        with closing(client()) as search:
            search.send_command_frame(frame(_SEARCH, body), deadline=deadline)
            response = search.read_tcp_frame(max_frame_bytes=4096, deadline=deadline)
            if response.header.field_8 != 1:
                raise LanPlaybackError("catalog search", response.header.field_8)
            records = _receive_search(
                search.sock,
                deadline=deadline,
                timeout=timeout,
                max_bytes=max_bytes,
                max_records=max_records,
                begin=begin,
                end=end,
                timezone=timezone,
            )
    except BaseException as error:
        if session is not None:
            try:
                logout()
            except Exception:
                error.add_note("LAN catalog logout unacknowledged; owned sockets closed")
        raise
    else:
        logout()
    return RecordingCatalog(endpoint.serial, channel, timezone, records, discovery="lan-hcnetsdk")
