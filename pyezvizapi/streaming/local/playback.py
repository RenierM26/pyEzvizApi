"""Finite, account-free SD downloads over the camera's HCNetSDK command port.

Only caller-supplied IPv4 endpoints and device credentials are used. There is
no cloud discovery, Android runtime, fallback, retry or camera configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, closing
from datetime import datetime
from ipaddress import IPv4Address
import os
from pathlib import Path
import socket
import struct
from tempfile import NamedTemporaryFile, SpooledTemporaryFile
import time
from typing import Any, BinaryIO, cast

from pyezvizapi.exceptions import EzvizIncompleteMediaError, PyEzvizError
from pyezvizapi.streaming.cloud.playback_range import (
    DEFAULT_PLAYBACK_MAX_BYTES,
    DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
    native_playback_range,
    playback_integer,
    positive_timeout,
    selected_playback_range,
)
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    hcnetsdk_command_port_rsa_key,
)
from pyezvizapi.streaming.media.mpegps import (
    mpeg_ps_video_pts_span_seconds,
    validate_sd_playback_framing,
)

_SELECT_TIME = 0x30102
_START_DOWNLOAD = 0x30103
_LOGOUT = 0x10100
_METADATA = 19
_MEDIA = 20
_END = 21
_MAX_BLOCK_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 4096
_SPOOL_BYTES = 1024 * 1024
_STREAM_SIGNATURE = b"IMKH"


class LanPlaybackError(PyEzvizError):
    """A LAN playback operation failed with a numeric device response."""

    def __init__(self, stage: str, result_code: int) -> None:
        self.stage = stage
        self.result_code = result_code
        self.source = "local-playback"
        super().__init__(f"LAN SD playback {stage} refused (result {result_code})")


def lan_playback_body(channel: int, begin_time: str, end_time: str, timezone: str) -> bytes:
    """Encode the native GetFileByTime selector, using an explicit wall clock."""
    playback_integer(channel, "LAN channel")
    if channel > 0xFFFFFFFF:
        raise PyEzvizError("LAN SD channel exceeds the native 32-bit selector")
    native_begin, native_end = native_playback_range(begin_time, end_time, timezone)
    fields = [channel]
    for value in (native_begin, native_end):
        instant = datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        fields.extend(
            (instant.year, instant.month, instant.day, instant.hour, instant.minute, instant.second)
        )
    # PackVodSendData: reserved/download flag bytes following the two NET_DVR_TIMEs.
    return struct.pack(">13I", *fields) + b"\x00\x01" + bytes(10)


def _write(output: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = output.write(view)
        if isinstance(count, bool) or not isinstance(count, int) or not 0 < count <= len(view):
            raise PyEzvizError("LAN SD output write made no valid progress")
        view = view[count:]


def _read_exact(sock: Any, size: int, deadline: float, timeout: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PyEzvizError("LAN SD transfer deadline expired")
        sock.settimeout(min(timeout, remaining))
        try:
            chunk = sock.recv(size - len(data))
        except TimeoutError:
            raise PyEzvizError("LAN SD download timed out before its end marker") from None
        if not chunk:
            raise PyEzvizError("LAN SD download ended before its complete end marker")
        data.extend(chunk)
    return bytes(data)


def _metadata(data: bytes) -> tuple[dict[str, int], int]:
    if len(data) < 16:
        raise PyEzvizError("LAN SD metadata is truncated")
    advertised_size, seconds, frames, header_size = struct.unpack(">4I", data[:16])
    if header_size != len(data) - 16 or header_size != 40:
        raise PyEzvizError("LAN SD stream header is unsupported")
    if data[16:20] != _STREAM_SIGNATURE:
        raise PyEzvizError("LAN SD stream header signature is unsupported")
    return {
        "advertised_bytes": advertised_size,
        "advertised_duration_seconds": seconds,
        "advertised_video_frames": frames,
    }, header_size


def _receive(
    stream: HcNetSdkCommandPortClient,
    staged: BinaryIO,
    *,
    deadline: float,
    timeout: float,
    max_bytes: int,
) -> dict[str, Any]:
    sock = stream.sock
    total_wire = 0
    header_size: int | None = None
    blocks = 0
    while True:
        header = _read_exact(sock, 8, deadline, timeout)
        size, kind = struct.unpack(">II", header)
        if size < 8 or size > _MAX_BLOCK_BYTES:
            raise PyEzvizError("LAN SD block length is invalid")
        total_wire += size
        if total_wire > max_bytes:
            raise PyEzvizError("LAN SD download exceeded its wire byte budget")
        if kind == _METADATA:
            if header_size is not None or size > _MAX_METADATA_BYTES:
                raise PyEzvizError("LAN SD metadata is repeated or oversized")
            data = _read_exact(sock, size - 8, deadline, timeout)
            metadata, header_size = _metadata(data)
            _write(staged, data[16:])
        elif kind == _MEDIA:
            if header_size is None or size == 8:
                raise PyEzvizError("LAN SD media arrived without metadata or is empty")
            _write(staged, _read_exact(sock, size - 8, deadline, timeout))
            blocks += 1
        elif kind == _END:
            if size != 8 or header_size is None or not blocks:
                raise PyEzvizError("LAN SD end marker is invalid or contains no media")
            return {**metadata, "wire_bytes": total_wire, "media_blocks": blocks}
        else:
            raise PyEzvizError("LAN SD received an unsupported block type")


def _publish(staged: BinaryIO, output: str | Path | BinaryIO) -> str | None:
    def copy_to(destination: BinaryIO) -> None:
        staged.seek(0)
        while chunk := staged.read(_SPOOL_BYTES):
            _write(destination, chunk)
        destination.flush()

    if not isinstance(output, str | Path):
        copy_to(output)
        return None
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        temporary = stack.enter_context(
            NamedTemporaryFile(
                mode="w+b", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
            )
        )
        temporary_path = Path(temporary.name)
        try:
            copy_to(cast(BinaryIO, temporary))
            os.fsync(temporary.fileno())
            temporary.close()
            os.replace(temporary_path, path)
        finally:
            try:
                temporary.close()
            finally:
                temporary_path.unlink(missing_ok=True)
    return str(path)


def _validate_connection(
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


def _acquire(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    staged: BinaryIO,
    body: bytes,
    *,
    username: str,
    timeout: float,
    deadline: float,
    max_bytes: int,
    socket_factory: Callable[..., Any],
    rsa_key: Any,
) -> dict[str, Any]:
    login_session = None
    local_ip = ""

    def client() -> HcNetSdkCommandPortClient:
        return HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)

    def frame(command: int, tail: bytes = b"") -> bytes:
        if login_session is None:
            raise PyEzvizError("LAN SD has no owned login session")
        return HcNetSdkCommandPortControlTemplate(command, tail).to_frame(
            session_id=login_session.session_id,
            auth_seed=login_session.auth_seed,
            key=login_session.challenge,
            local_ip=local_ip,
        )

    def logout() -> None:
        with closing(client()) as control:
            control.send_command_frame(frame(_LOGOUT), deadline=deadline)
            response = control.read_tcp_frame(
                max_frame_bytes=_MAX_METADATA_BYTES, deadline=deadline
            )
            if response.header.field_8 != 1:
                raise LanPlaybackError("logout", response.header.field_8)

    try:
        # Do not enter the client context here: that would connect before
        # login's deadline-aware connect path gets a chance to run.
        with closing(client()) as login:
            login_session = login.login(
                password=password,
                username=username,
                rsa_key=rsa_key,
                max_frame_bytes=_MAX_METADATA_BYTES,
                deadline=deadline,
            )
            local_ip = str(login.sock.getsockname()[0])
            if not login_session.serial.endswith(endpoint.serial):
                raise PyEzvizError("LAN SD camera identity differs from supplied serial")
        with closing(client()) as stream:
            stream.send_command_frame(frame(_SELECT_TIME, body), deadline=deadline)
            selected = stream.read_tcp_frame(max_frame_bytes=_MAX_METADATA_BYTES, deadline=deadline)
            if selected.header.field_8 != 1:
                raise LanPlaybackError("selection", selected.header.field_8)
            stream.send_command_frame(frame(_START_DOWNLOAD, bytes(4)), deadline=deadline)
            metadata = _receive(
                stream,
                staged,
                deadline=deadline,
                timeout=timeout,
                max_bytes=max_bytes,
            )
    except BaseException as error:
        if login_session is not None:
            try:
                logout()
            except Exception:
                error.add_note("LAN SD logout was not acknowledged; owned sockets were closed")
        raise
    else:
        logout()
    return metadata


def download_lan_sd_recording(  # noqa: PLR0913 -- explicit account-free connection/transfer contract
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    output: str | Path | BinaryIO,
    begin_time: str,
    end_time: str,
    *,
    channel: int = 1,
    timezone: str = "UTC",
    username: str = "admin",
    duration_seconds: float | None = None,
    max_bytes: int = DEFAULT_PLAYBACK_MAX_BYTES,
    timeout: float = 10.0,
    transfer_timeout: float = DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
    socket_factory: Callable[..., Any] = socket.create_connection,
) -> dict[str, Any]:
    """Download one complete SD range, staging until end marker + PTS validation.

    Public times are UTC; ``timezone`` explicitly declares the camera's wall
    clock. ``max_bytes`` bounds all download blocks including their framing.
    Native channel numbers are one-based, unlike some VTM resource indices.
    Account tokens/HTTP are never used. Only the supplied credential is tried.
    """
    selected_end, requested = selected_playback_range(begin_time, end_time, duration_seconds)
    body = lan_playback_body(channel, begin_time, selected_end, timezone)
    positive_timeout(timeout, "socket timeout")
    positive_timeout(transfer_timeout, "transfer timeout")
    playback_integer(max_bytes, "max_bytes")
    _validate_connection(endpoint, username, password)
    deadline = time.monotonic() + transfer_timeout
    rsa_key = hcnetsdk_command_port_rsa_key()
    if time.monotonic() >= deadline:
        raise PyEzvizError("LAN SD key preparation exhausted transfer deadline")
    with SpooledTemporaryFile(max_size=_SPOOL_BYTES, mode="w+b") as staged:
        metadata = _acquire(
            endpoint,
            password,
            cast(BinaryIO, staged),
            body,
            username=username,
            timeout=timeout,
            deadline=deadline,
            max_bytes=max_bytes,
            socket_factory=socket_factory,
            rsa_key=rsa_key,
        )
        staged.seek(40)
        snapshot = staged.read()
        validate_sd_playback_framing(snapshot)
        span = mpeg_ps_video_pts_span_seconds(snapshot, max_gap_seconds=1.0)
        if span is None or span < requested - min(1.0, requested * 0.05):
            raise EzvizIncompleteMediaError(
                source="local-playback",
                requested_duration_seconds=requested,
                observed_pts_span_seconds=span or 0.0,
            )
        size = staged.tell()
        output_name = _publish(cast(BinaryIO, staged), output)
    native_begin, native_end = native_playback_range(begin_time, selected_end, timezone)
    return {
        "ok": True,
        "kind": "clip",
        "serial": endpoint.serial,
        "source": "local-playback",
        "channel": channel,
        "format": "mpegps",
        "output": output_name,
        "bytes": size,
        "begin_time": begin_time,
        "end_time": selected_end,
        "playback_timezone": timezone,
        "native_begin_time": native_begin,
        "native_end_time": native_end,
        "observed_pts_span_seconds": span,
        "range_complete": True,
        "completion_reason": "native_end_marker",
        "logout_acknowledged": True,
        "duration_seconds": requested,
        **metadata,
    }


def save_lan_playback_clip(serial: str, output: Any, options: Any) -> dict[str, Any]:
    """Adapt grouped capture options without consulting an account client."""
    from pyezvizapi.streaming.capture import _SourceDefaultDuration  # noqa: PLC0415
    from pyezvizapi.streaming.media.models import MediaMuxOptions  # noqa: PLC0415

    source = options.source
    mux = options.resolved_mux()
    if mux != MediaMuxOptions(output_format="mpegps", ffmpeg_path=mux.ffmpeg_path):
        raise PyEzvizError("LAN SD supports original-clock MPEG-PS output only")
    if (
        options.max_packets is not None
        or options.decode.decrypt_video
        or options.decode.decrypt_hevc_parameter_sets
    ):
        raise PyEzvizError("LAN SD does not support packet truncation or cloud/video decryption")
    return download_lan_sd_recording(
        HcNetSdkLanEndpoint(serial=serial, host=source.host, command_port=source.command_port),
        source.password,
        output,
        source.begin_time,
        source.end_time,
        channel=1 if options.channel is None else options.channel,
        timezone=source.timezone,
        username=source.username,
        timeout=source.timeout,
        transfer_timeout=source.transfer_timeout,
        max_bytes=min(source.max_bytes, options.capture.max_bytes or source.max_bytes),
        duration_seconds=None
        if isinstance(options.duration_seconds, _SourceDefaultDuration)
        else options.duration_seconds,
    )
