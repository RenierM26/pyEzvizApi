"""Bounded SD recording download through VTM, based on @adirgan's PR #266.

This is camera SD playback relayed by EZVIZ, not cloud-storage replay or live
capture. A socket timeout alone is not proof that the selected range arrived.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
import os
from pathlib import Path
from tempfile import NamedTemporaryFile, SpooledTemporaryFile
import time
from typing import Any, BinaryIO, cast
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pyezvizapi.cloud.deadline import request_deadline
from pyezvizapi.exceptions import (
    EzvizIncompleteMediaError,
    EzvizNoMediaError,
    EzvizPlaybackNegotiationError,
    PyEzvizError,
)
from pyezvizapi.streaming.cloud import bootstrap
from pyezvizapi.streaming.cloud.playback_audio import decrypt_playback_adts_audio
from pyezvizapi.streaming.cloud.protocol import (
    SocketFactory,
    VtmStreamClient,
    VtmStreamEOF,
    VtmStreamTimeout,
    build_vtm_url,
)
from pyezvizapi.streaming.media.containers import (
    decrypt_hikvision_ps_video,
    mpeg_ps_video_pts_span_seconds,
)
from pyezvizapi.streaming.media.mpegps import (
    _mpeg_ps_video_decrypt_ranges,
    _next_mpeg_ps_packet_start,
    _pes_payload_start,
    validate_sd_playback_framing,
)
from pyezvizapi.streaming.ranges import (
    DEFAULT_PLAYBACK_MAX_BYTES as DEFAULT_PLAYBACK_MAX_BYTES,  # noqa: PLC0414 -- preserve compatibility export
    DEFAULT_PLAYBACK_TRANSFER_TIMEOUT as DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,  # noqa: PLC0414 -- preserve compatibility export
    native_playback_range,
    playback_integer,
    positive_timeout as _positive_timeout,
    selected_playback_range,
)

# Exact terminal bytes observed after complete PS packets in the retained H9c
# recording. Permit only this whole marker, never arbitrary trailing bytes.
_PLAYBACK_VENDOR_TRAILER = b"\x24kih\x04\x03\x02\x01"


def build_vtm_playback_url(  # noqa: PLR0913 -- native URL field contract
    host: str,
    port: int,
    serial: str,
    stream_biz_url: str,
    vtdu_token: str,
    begin_time: str,
    end_time: str,
    *,
    channel: int = 1,
    timezone: str = "UTC",
    client_type: int = 3,
    lid: str | None = None,
    timestamp_ms: int | None = None,
) -> str:
    """Build the native ysproto playback selector; never guess a timezone."""
    begin_time, end_time = native_playback_range(begin_time, end_time, timezone)
    playback_integer(channel, "channel", minimum=0)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise PyEzvizError("SD playback port must be a valid TCP port")
    if not serial or not vtdu_token:
        raise PyEzvizError("SD playback requires a serial and VTDU token")
    stamp = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    parsed = urlparse(
        build_vtm_url(
            host,
            port,
            serial,
            stream_biz_url,
            vtdu_token,
            channel=channel,
            client_type=client_type,
            timestamp_ms=stamp,
        )
    )
    params = dict(parse_qsl(parsed.query))
    params.pop("vip", None)
    params.update(
        begin=begin_time, end=end_time, serial=serial, etp="1", rnd=str(stamp & 0x7FFFFFFF)
    )
    if lid is not None:
        params["lid"] = lid
    return urlunparse(parsed._replace(path="/playback", query=urlencode(params)))


def get_cloud_playback_stream_info(
    client: Any,
    serial: str,
    begin_time: str,
    end_time: str,
    *,
    channel: int | None = None,
    timezone: str = "UTC",
    client_type: int = 3,
    token_index: int = 0,
    refresh_vtm: bool = True,
    lid: str | None = None,
) -> dict[str, Any]:
    """Resolve the ordinary VTM resource/token, but request its playback mode."""
    native_playback_range(begin_time, end_time, timezone)
    playback_integer(token_index, "token_index", minimum=0)
    if channel is not None:
        playback_integer(channel, "channel", minimum=0)
    info = bootstrap.get_cloud_stream_info(
        client,
        serial,
        channel=channel,
        client_type=client_type,
        token_index=token_index,
        refresh_vtm=refresh_vtm,
    )
    parsed = urlparse(info["stream_url"])
    selected_channel = int(dict(parse_qsl(parsed.query))["chn"])
    resource = info["resource"]
    url = build_vtm_playback_url(
        parsed.hostname or "",
        parsed.port or 0,
        serial,
        str(resource.get("streamBizUrl") or ""),
        info["vtdu_token"],
        begin_time,
        end_time,
        channel=selected_channel,
        timezone=timezone,
        client_type=client_type,
        lid=lid,
    )
    return {**info, "stream_url": url}


def open_cloud_playback_stream(  # noqa: PLR0913 -- source options
    client: Any,
    serial: str,
    begin_time: str,
    end_time: str,
    *,
    channel: int | None = None,
    timezone: str = "UTC",
    client_type: int = 3,
    token_index: int = 0,
    refresh_vtm: bool = True,
    timeout: float = 10.0,
    lid: str | None = None,
    socket_factory: SocketFactory | None = None,
    capture_deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> VtmStreamClient:
    """Return an unstarted playback transport with the native server request timeout (protobuf field 8)."""
    timeout = _positive_timeout(timeout, "timeout")
    with request_deadline(capture_deadline, monotonic):
        info = get_cloud_playback_stream_info(
            client,
            serial,
            begin_time,
            end_time,
            channel=channel,
            timezone=timezone,
            client_type=client_type,
            token_index=token_index,
            refresh_vtm=refresh_vtm,
            lid=lid,
        )
    kwargs = {} if socket_factory is None else {"socket_factory": socket_factory}
    return VtmStreamClient(
        info["stream_url"],
        timeout=timeout,
        stream_info_timeout=10,
        client_version="v3.9.0.20251120",
        **kwargs,
    )


def _collect_playback(
    stream: VtmStreamClient,
    *,
    deadline: float,
    timeout: float,
    max_packets: int | None,
    max_bytes: int,
    monotonic: Callable[[], float],
) -> tuple[bytes, str]:
    with SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b") as staging:
        reason = _collect_playback_into(
            stream,
            cast(BinaryIO, staging),
            deadline=deadline,
            timeout=timeout,
            max_packets=max_packets,
            max_bytes=max_bytes,
            monotonic=monotonic,
        )
        staging.seek(0)
        data = staging.read()
    if not data:
        raise EzvizNoMediaError("SD playback returned no media")
    if not data.startswith(b"\x00\x00\x01\xba"):
        raise PyEzvizError("SD playback did not return MPEG-PS media")
    return data, reason


def _collect_playback_into(
    stream: VtmStreamClient,
    staging: BinaryIO,
    *,
    deadline: float,
    timeout: float,
    max_packets: int | None,
    max_bytes: int,
    monotonic: Callable[[], float],
) -> str:
    reason = "iteration_limit"
    try:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise EzvizNoMediaError("SD playback bootstrap exhausted transfer deadline")
        for packet in stream.iter_packets(
            max_packets=max_packets,
            duration_seconds=remaining,
            duration_from_start=True,
            first_packet_deadline=deadline,
            stream_packet_timeout_seconds=timeout,
            monotonic=monotonic,
        ):
            if packet.encrypted:
                raise PyEzvizError("Encrypted VTM transport packets are unsupported")
            if staging.tell() + len(packet.body) > max_bytes:
                raise PyEzvizError("SD playback exceeded its byte budget")
            _write_playback_output(staging, packet.body)
    except VtmStreamEOF:
        reason = "peer_eof"
    except VtmStreamTimeout:
        # A timed-out partial header/body is corruption, not a completed range.
        if stream.has_pending_packet:
            raise PyEzvizError("SD playback timed out inside a VTM packet") from None
        reason = "idle_timeout"
    if reason == "iteration_limit":
        reason = (
            "transfer_deadline"
            if monotonic() >= deadline
            else "packet_limit"
            if max_packets is not None
            else "idle_timeout"
        )
    if stream.has_pending_packet:
        raise PyEzvizError("SD playback ended inside a VTM packet")
    return reason


def _validate_playback_framing(data: bytes) -> None:
    """Retain the cloud helper while sharing complete PS framing validation."""
    validate_sd_playback_framing(data, vendor_trailer=_PLAYBACK_VENDOR_TRAILER)


def copy_cloud_playback_to_mpegps(  # noqa: PLR0913 -- public copier contract
    client: Any,
    serial: str,
    output: BinaryIO,
    begin_time: str,
    end_time: str,
    *,
    channel: int | None = None,
    timezone: str = "UTC",
    client_type: int = 3,
    token_index: int = 0,
    refresh_vtm: bool = True,
    timeout: float | None = 10.0,
    lid: str | None = None,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    decrypt_video: bool = False,
    decrypt_audio: bool = False,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = None,
    smscode: str | int | None = None,
    max_bytes: int = DEFAULT_PLAYBACK_MAX_BYTES,
    transfer_timeout: float = DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Stage and validate a finite range before exposing bytes to the caller.

    An explicit duration selects a shorter media-time range, not a live-capture
    wall timer. Packet-limited saves are explicitly partial. Full-range saves
    require continuous video PTS span within 5% (at most 1s) of the selection;
    EOF/idle alone must never turn an arbitrary prefix into success.
    """
    end_time, requested = selected_playback_range(begin_time, end_time, duration_seconds)
    native_begin, native_end = native_playback_range(begin_time, end_time, timezone)
    timeout = _positive_timeout(timeout, "timeout")
    transfer_timeout = _positive_timeout(transfer_timeout, "transfer_timeout")
    playback_integer(max_bytes, "max_bytes")
    playback_integer(token_index, "token_index", minimum=0)
    if channel is not None:
        playback_integer(channel, "channel", minimum=0)
    if max_packets is not None:
        playback_integer(max_packets, "max_packets")
    deadline = monotonic() + transfer_timeout
    with request_deadline(deadline, monotonic):
        if (decrypt_video or decrypt_audio) and media_key is None:
            media_key = client.get_cam_key(
                serial, **({"smscode": smscode} if smscode is not None else {})
            )
        if (decrypt_video or decrypt_audio) and media_key is None:
            raise PyEzvizError("SD playback decrypt requires a camera media key")
        stream = open_cloud_playback_stream(
            client,
            serial,
            begin_time,
            end_time,
            channel=channel,
            timezone=timezone,
            client_type=client_type,
            token_index=token_index,
            refresh_vtm=refresh_vtm,
            timeout=timeout,
            lid=lid,
            capture_deadline=deadline,
            monotonic=monotonic,
        )
        with bootstrap._closing_unconnected_cloud_stream(stream):  # noqa: SLF001
            info = stream.start(deadline=deadline, monotonic=monotonic)
            if info.result not in (None, 0):
                raise EzvizPlaybackNegotiationError(info.result)
            data, reason = _collect_playback(
                stream,
                deadline=deadline,
                timeout=timeout,
                max_packets=max_packets,
                max_bytes=max_bytes,
                monotonic=monotonic,
            )
    _validate_playback_framing(data)
    span = mpeg_ps_video_pts_span_seconds(data, max_gap_seconds=1.0)
    complete = span is not None and span >= requested - min(1.0, requested * 0.05)
    if span is None and max_packets is None:
        raise PyEzvizError("SD playback has no continuous video PTS span to verify the range")
    if not complete and max_packets is None:
        raise EzvizIncompleteMediaError(
            source="cloud-playback",
            requested_duration_seconds=requested,
            observed_pts_span_seconds=span or 0.0,
        )
    data = _decode_playback_media(
        data,
        media_key,
        decrypt_video=decrypt_video,
        decrypt_audio=decrypt_audio,
        nalu_header_size=nalu_header_size,
    )
    _write_playback_output(output, data)
    output.flush()
    return {
        "begin_time": begin_time,
        "native_begin_time": native_begin,
        "native_end_time": native_end,
        "playback_timezone": timezone,
        "end_time": end_time,
        "observed_pts_span_seconds": span,
        "range_complete": complete,
        "completion_reason": reason,
        "bytes": len(data),
    }


def _decode_playback_media(
    data: bytes,
    key: str | bytes | None,
    *,
    decrypt_video: bool,
    decrypt_audio: bool,
    nalu_header_size: int | None,
) -> bytes:
    if not (decrypt_video or decrypt_audio):
        return data
    if key is None:
        raise PyEzvizError("SD media decrypt requires a camera media key")
    if decrypt_video:
        data = decrypt_hikvision_ps_video(data, key, nalu_header_size=nalu_header_size)
    if decrypt_audio:
        data = decrypt_playback_adts_audio(data, key)
    return data


def _write_playback_output(output: BinaryIO, data: bytes | memoryview) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = output.write(view[offset:])
        if (
            not isinstance(written, int)
            or isinstance(written, bool)
            or not 0 < written <= len(view) - offset
        ):
            raise PyEzvizError("SD playback output write made no valid progress")
        offset += written


def save_cloud_playback_clip(client: Any, serial: str, output: Any, options: Any) -> dict[str, Any]:
    """Publish only validated SD bytes; never truncate an existing path on failure."""
    from pyezvizapi.streaming.capture import _SourceDefaultDuration  # noqa: PLC0415

    mux = options.resolved_mux()
    from pyezvizapi.streaming.media.models import MediaMuxOptions  # noqa: PLC0415

    if mux != MediaMuxOptions(output_format="mpegps", ffmpeg_path=mux.ffmpeg_path):
        raise PyEzvizError("SD playback supports MPEG-PS without native clock overrides")
    source = options.source
    duration = (
        None
        if isinstance(options.duration_seconds, _SourceDefaultDuration)
        else options.duration_seconds
    )
    max_bytes = min(source.max_bytes, options.capture.max_bytes or source.max_bytes)
    with ExitStack() as stack:
        data = stack.enter_context(SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b"))
        result = copy_cloud_playback_to_mpegps(
            client,
            serial,
            cast(BinaryIO, data),
            source.begin_time,
            source.end_time,
            channel=options.channel,
            timezone=source.timezone,
            client_type=source.client_type,
            token_index=source.token_index,
            refresh_vtm=source.refresh_vtm,
            timeout=source.timeout,
            lid=source.lid,
            max_packets=options.max_packets,
            duration_seconds=duration,
            max_bytes=max_bytes,
            transfer_timeout=source.transfer_timeout,
            decrypt_video=options.decode.decrypt_video,
            decrypt_audio=source.decrypt_audio,
            media_key=options.decode.media_key,
            nalu_header_size=options.decode.nalu_header_size,
            smscode=source.smscode,
        )
        data.seek(0)
        if isinstance(output, str | Path):
            path = Path(output)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Same-directory staging permits atomic replacement on one filesystem.
            staged = stack.enter_context(
                NamedTemporaryFile(
                    mode="w+b",
                    dir=path.parent,
                    prefix=f".{path.name}.",
                    suffix=".tmp",
                    delete=False,
                )
            )
            temporary = Path(staged.name)
            try:
                _publish_playback(cast(BinaryIO, data), cast(BinaryIO, staged))
                os.fsync(staged.fileno())
                staged.close()  # Required before replacement on Windows.
                os.replace(temporary, path)
            finally:
                try:
                    staged.close()
                finally:
                    temporary.unlink(missing_ok=True)
            output_name = str(path)
        else:
            _publish_playback(cast(BinaryIO, data), output)
            output_name = None
    return {
        **result,
        "ok": True,
        "kind": "clip",
        "serial": serial,
        "channel": options.channel,
        "source": "cloud-playback",
        "format": "mpegps",
        "output": output_name,
        "duration_seconds": duration,
    }


def _publish_playback(staging: BinaryIO, output: BinaryIO) -> None:
    """Copy staged bytes with bounded buffers and checked short-write progress."""
    while chunk := staging.read(1024 * 1024):
        _write_playback_output(output, chunk)
    output.flush()


# Retained named compatibility exports; not additions to the wildcard API.
__compatibility_exports__ = {
    "_mpeg_ps_video_decrypt_ranges": _mpeg_ps_video_decrypt_ranges,
    "_next_mpeg_ps_packet_start": _next_mpeg_ps_packet_start,
    "_pes_payload_start": _pes_payload_start,
}
