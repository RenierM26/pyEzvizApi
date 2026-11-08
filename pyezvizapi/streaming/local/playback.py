"""Finite, account-free SD downloads over the camera's HCNetSDK command port.

Only caller-supplied IPv4 endpoints and device credentials are used. There is
no cloud discovery, Android runtime, fallback, retry or camera configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, closing
from datetime import datetime
import os
from pathlib import Path
import socket
import struct
from tempfile import NamedTemporaryFile, SpooledTemporaryFile
import time
from typing import Any, BinaryIO, cast

from pyezvizapi.exceptions import EzvizIncompleteMediaError, PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HcNetSdkCommandPortClient,
    HcNetSdkLanEndpoint,
    hcnetsdk_command_port_rsa_key,
)
from pyezvizapi.streaming.local.sd_session import lan_sd_session
from pyezvizapi.streaming.local.sd_transport import (
    LanPlaybackError,
    read_exact as _read_exact,
    validate_connection as _validate_connection,
)
from pyezvizapi.streaming.media.mpegps import (
    mpeg_ps_video_pts_span_seconds,
    validate_sd_playback_framing,
)
from pyezvizapi.streaming.ranges import (
    DEFAULT_PLAYBACK_MAX_BYTES,
    DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
    native_playback_range,
    playback_integer,
    positive_timeout,
    selected_playback_range,
)

_SELECT_TIME = 0x30102
_START_DOWNLOAD = 0x30103
_METADATA = 19
_MEDIA = 20
_END = 21
_MAX_BLOCK_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 4096
_SPOOL_BYTES = 1024 * 1024
_STREAM_SIGNATURE = b"IMKH"


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
    with (
        lan_sd_session(
            endpoint,
            password,
            username=username,
            deadline=deadline,
            rsa_key=rsa_key,
            client_factory=lambda: HcNetSdkCommandPortClient(
                endpoint, timeout=timeout, socket_factory=socket_factory
            ),
            purpose="playback",
        ) as session,
        closing(session.client()) as stream,
    ):
        stream.send_command_frame(session.frame(_SELECT_TIME, body), deadline=deadline)
        selected = stream.read_tcp_frame(max_frame_bytes=_MAX_METADATA_BYTES, deadline=deadline)
        if selected.header.field_8 != 1:
            raise LanPlaybackError("selection", selected.header.field_8)
        stream.send_command_frame(session.frame(_START_DOWNLOAD, bytes(4)), deadline=deadline)
        metadata = _receive(
            stream,
            staged,
            deadline=deadline,
            timeout=timeout,
            max_bytes=max_bytes,
        )
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
