"""Client-oriented helpers for EZVIZ cloud stream bootstrap metadata."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from itertools import chain
import json
from pathlib import Path
from queue import Empty, Full, Queue
import socket
import subprocess
import tempfile
from threading import Event, Lock, Thread
import time
from typing import Any, BinaryIO, TypedDict, cast
from urllib.parse import urlparse

from .api_endpoints import API_ENDPOINT_STREAMING_VTM, API_ENDPOINT_VTDU_TOKEN_V2
from .constants import MAX_RETRIES
from .exceptions import HTTPError, PyEzvizError, UnsupportedRtpVideoCodecError
from .media import has_positive_finite_capture_bound
from .remux import copy_remuxed_output, open_mpegts_remux_process, remux_bytes
from .rtp import (
    ANNEX_B_START_CODE,
    DEFAULT_AAC_PAYLOAD_TYPES,
    RtpAacStream,
    RtpPacket,
    RtpRouteProfile,
    RtpVideoCodec,
    RtpVideoDepacketizer,
    decrypt_idmx_aac_packets,
    detect_rtp_video_codec,
    idmx_aac_descriptor,
    idmx_rtp_stream_descriptors,
    parse_rtp_packet,
    rtp_codec_payload_types,
    rtp_media_kind,
    rtp_packets_to_nal_units,
)
from .stream_media import decrypt_hikvision_ps_video, detect_transport
from .stream_transport import (
    SocketFactory,
    StreamTransport,
    VtmStreamClient,
    build_vtm_url,
)

JsonDict = dict[str, Any]
_RTP_CODEC_PROBE_MAX_PACKETS = 32
_RTP_AUDIO_PROBE_MAX_PACKETS = 256
_RTP_AUDIO_QUEUE_MAX_FRAMES = 128
_RTP_AUDIO_QUEUE_TIMEOUT_SECONDS = 2.0


class _CloudRtpAudioInput:
    """Bounded loopback transport for FFmpeg's second elementary input."""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.25)
        port = cast("tuple[str, int]", self._listener.getsockname())[1]
        self.url = f"tcp://127.0.0.1:{port}"
        self._queue: Queue[bytes | None] = Queue(_RTP_AUDIO_QUEUE_MAX_FRAMES)
        self._stop = Event()
        self._connection: socket.socket | None = None
        self._connection_lock = Lock()
        self._errors: list[Exception] = []
        self._thread = Thread(
            target=self._run,
            name="pyezvizapi-cloud-rtp-audio",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def write(self, data: bytes) -> None:
        if not data:
            return
        deadline = time.monotonic() + _RTP_AUDIO_QUEUE_TIMEOUT_SECONDS
        while not self._stop.is_set():
            try:
                self._queue.put(data, timeout=0.25)
                return
            except Full:
                if time.monotonic() >= deadline:
                    self.cancel()
                    raise PyEzvizError(
                        "FFmpeg AAC input stopped consuming data"
                    ) from None
        raise BrokenPipeError("FFmpeg audio input closed")

    def close_input(self) -> None:
        deadline = time.monotonic() + _RTP_AUDIO_QUEUE_TIMEOUT_SECONDS
        while not self._stop.is_set():
            try:
                self._queue.put(None, timeout=0.25)
                return
            except Full:
                if time.monotonic() >= deadline:
                    self.cancel()
                    raise PyEzvizError("FFmpeg AAC input could not be closed") from None

    def cancel(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._listener.close()
        with self._connection_lock:
            connection = self._connection
        if connection is not None:
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                connection.close()

    def finish(self, *, raise_errors: bool) -> None:
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            self.cancel()
            self._thread.join(timeout=2.0)
        if raise_errors and self._thread.is_alive():
            raise PyEzvizError("FFmpeg audio input writer did not stop")
        if raise_errors and self._errors:
            raise self._errors[0]

    def _run(self) -> None:  # noqa: PLR0912
        connection: socket.socket | None = None
        try:
            while not self._stop.is_set():
                try:
                    connection, _address = self._listener.accept()
                    break
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        return
                    raise
            if connection is None:
                return
            with self._connection_lock:
                if self._stop.is_set():
                    connection.close()
                    return
                self._connection = connection
            with connection:
                while not self._stop.is_set():
                    try:
                        chunk = self._queue.get(timeout=0.25)
                    except Empty:
                        continue
                    if chunk is None:
                        return
                    connection.sendall(chunk)
        except (BrokenPipeError, ConnectionResetError):
            if not self._stop.is_set():
                self._errors.append(PyEzvizError("FFmpeg closed its AAC input"))
        except Exception as err:  # pragma: no cover - defensive thread handoff
            if not self._stop.is_set():
                self._errors.append(err)
        finally:
            self._stop.set()
            with self._connection_lock:
                if self._connection is connection:
                    self._connection = None
            with suppress(OSError):
                self._listener.close()


class VtduTokenResponse(TypedDict, total=False):
    """Response from the VTDU token endpoint."""

    msg: str
    tokens: list[str]
    retcode: int


@dataclass(frozen=True)
class VtmServerPublicKey:
    """VTM server public key material from pagelist metadata."""

    version: int
    key: str
    key_bytes: bytes


def get_vtm_info(client: Any, serial: str, channel: int = 1) -> JsonDict:
    """Fetch the app's current VTM server metadata for a camera channel.

    The Android app uses ``GET v3/streaming/vtm/{deviceSerial}/{channelNo}``
    and stores the returned ``streamServerConfig`` before starting the native
    player. Channel ``0`` is normalized to ``1`` to match the app.
    """

    channel_no = 1 if channel == 0 else channel
    if channel_no < 1:
        raise PyEzvizError("VTM channel must be greater than zero")

    payload = cast(
        JsonDict,
        client._request_json(
            "GET",
            API_ENDPOINT_STREAMING_VTM.format(
                device_serial=serial,
                channel_no=channel_no,
            ),
        ),
    )
    server_config = payload.get("streamServerConfig")
    if not isinstance(server_config, dict):
        raise PyEzvizError(f"VTM response is missing streamServerConfig: {payload}")
    return cast(JsonDict, server_config)


def get_vtdu_token_v2(client: Any, max_retries: int = 0) -> VtduTokenResponse:
    """Fetch VTDU stream tokens from the auth service for an EzvizClient."""

    if max_retries > MAX_RETRIES:
        raise PyEzvizError("Could not get VTDU token. Max retries exceeded.")

    token = getattr(client, "_token", {})
    session_id = token.get("session_id") if isinstance(token, dict) else None
    sign = _session_sign(session_id)
    try:
        json_output = client._parse_json(
            client._http_request(
                "GET",
                f"{_auth_base_url(client)}{API_ENDPOINT_VTDU_TOKEN_V2}",
                params={"ssid": session_id, "sign": sign},
                retry_401=False,
            )
        )
    except HTTPError as err:
        if _http_status_code(err) != 401:
            raise
        client.login()
        return get_vtdu_token_v2(client, max_retries=max_retries + 1)

    if not _success_retcode(json_output.get("retcode")):
        raise PyEzvizError(f"Could not get VTDU token: Got {json_output})")
    tokens = json_output.get("tokens")
    if not isinstance(tokens, list) or not tokens:
        raise PyEzvizError(f"Could not get VTDU token: Got {json_output})")
    return cast(VtduTokenResponse, json_output)


def get_vtm_page_list(client: Any) -> JsonDict:
    """Return pagelist payload filtered to VTM cloud stream metadata."""

    return cast(JsonDict, client._api_get_pagelist(page_filter="VTM", limit=50))


def get_cloud_stream_info(
    client: Any,
    serial: str,
    *,
    channel: int | None = None,
    client_type: int = 9,
    token_index: int = 0,
    refresh_vtm: bool = False,
) -> JsonDict:
    """Build VTM stream bootstrap metadata for a camera.

    This does not open the TCP VTM/VTDU stream. It gathers the resource, VTM
    server, VTDU token, and ysproto URL needed by an experimental stream client.
    """

    pagelist = get_vtm_page_list(client)
    resources = pagelist.get("resourceInfos") or []
    vtms = pagelist.get("VTM") or {}
    if not isinstance(resources, list) or not isinstance(vtms, dict):
        raise PyEzvizError("VTM pagelist response is missing resource metadata")

    resource = _find_vtm_resource(resources, serial, channel=channel)
    if not isinstance(resource, dict):
        channel_text = f" channel {channel}" if channel is not None else ""
        raise PyEzvizError(f"Could not find VTM resource for serial {serial}{channel_text}")

    resource_id = resource.get("resourceId")
    tokens = get_vtdu_token_v2(client).get("tokens", [])
    try:
        vtdu_token = tokens[token_index]
    except IndexError as err:
        raise PyEzvizError(f"VTDU token index out of range: {token_index}") from err
    if not isinstance(vtdu_token, str):
        raise PyEzvizError(f"Invalid VTDU token at index {token_index}")

    stream_channel = channel
    if stream_channel is None:
        local_index = resource.get("localIndex")
        local_index_text = str(local_index)
        stream_channel = int(local_index_text) if local_index_text.isdigit() else 1

    vtm = vtms.get(resource_id)
    if not isinstance(vtm, dict):
        if not refresh_vtm:
            raise PyEzvizError(f"Could not find VTM server for resource {resource_id}")
        vtm = {}
    if refresh_vtm:
        vtm = {**vtm, **get_vtm_info(client, serial, stream_channel)}

    host = vtm.get("externalIp") or vtm.get("domain") or vtm.get("internalIp")
    if not isinstance(host, str) or not host.strip():
        raise PyEzvizError(f"Could not find VTM endpoint for resource {resource_id}")
    port_value = vtm.get("port")
    if not isinstance(port_value, (int, str)) or not str(port_value).isdigit():
        raise PyEzvizError(f"Could not find VTM port for resource {resource_id}")
    port = int(port_value)
    if port < 1 or port > 65535:
        raise PyEzvizError(f"Could not find VTM port for resource {resource_id}")

    stream_url = build_vtm_url(
        host.strip(),
        port,
        serial,
        str(resource.get("streamBizUrl") or ""),
        vtdu_token,
        channel=stream_channel,
        client_type=client_type,
    )
    return {
        "resource": resource,
        "vtm": vtm,
        "vtm_public_key": parse_vtm_server_public_key(vtm),
        "vtdu_token": vtdu_token,
        "stream_url": stream_url,
    }


def open_cloud_stream(
    client: Any,
    serial: str,
    *,
    channel: int | None = None,
    client_type: int = 9,
    token_index: int = 0,
    refresh_vtm: bool = True,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
) -> VtmStreamClient:
    """Return a VTM TCP client bootstrapped from EZVIZ cloud metadata.

    The returned client is not started automatically. Use ``with`` and call
    ``start()`` before reading packets.
    """

    info = get_cloud_stream_info(
        client,
        serial,
        channel=channel,
        client_type=client_type,
        token_index=token_index,
        refresh_vtm=refresh_vtm,
    )
    if socket_factory is None:
        return VtmStreamClient(info["stream_url"], timeout=timeout)
    return VtmStreamClient(
        info["stream_url"],
        timeout=timeout,
        socket_factory=socket_factory,
    )


def copy_cloud_stream_to_mpegps(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    channel: int | None = None,
    client_type: int = 9,
    token_index: int = 0,
    refresh_vtm: bool = True,
    timeout: float | None = 10.0,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = None,
    smscode: str | int | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Copy a cloud VTM live stream to MPEG-PS bytes.

    ``decrypt_video`` collects a bounded capture before writing because the
    Hikvision NAL-prefix transform is stateful across VTM packet boundaries.
    """

    if decrypt_video:
        _require_bounded_cloud_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )
        if media_key is None and smscode is not None:
            selected_key = client.get_cam_key(serial, smscode=smscode)
        else:
            selected_key = media_key if media_key is not None else client.get_cam_key(serial)
        if selected_key is None:
            raise PyEzvizError("decrypt_video requires a media_key or camera media key")
        with open_cloud_stream(
            client,
            serial,
            channel=channel,
            client_type=client_type,
            token_index=token_index,
            refresh_vtm=refresh_vtm,
            timeout=timeout,
        ) as stream:
            stream.start()
            packets = _collect_cloud_stream_packets(
                stream,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
        transport, media_packets = _peek_cloud_transport(iter(packets))
        packets = list(media_packets)
        if transport == StreamTransport.RTP:
            raise PyEzvizError(
                "Cloud stream carries RTP/IDMX, not MPEG-PS; request MPEG-TS output"
            )
        if transport == StreamTransport.MPEG_TS:
            raise PyEzvizError(
                "Cloud stream carries MPEG-TS, not MPEG-PS; request MPEG-TS output"
            )
        payload = b"".join(packet.body for packet in packets)
        output.write(
            decrypt_hikvision_ps_video(
                payload,
                selected_key,
                nalu_header_size=nalu_header_size,
            )
        )
        output.flush()
        return

    with open_cloud_stream(
        client,
        serial,
        channel=channel,
        client_type=client_type,
        token_index=token_index,
        refresh_vtm=refresh_vtm,
        timeout=timeout,
    ) as stream:
        stream.start()
        _copy_cloud_stream_payloads_to_mpegps(
            stream,
            output,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )


def copy_cloud_stream_to_mpegts(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    channel: int | None = None,
    client_type: int = 9,
    token_index: int = 0,
    refresh_vtm: bool = True,
    timeout: float | None = 10.0,
    ffmpeg_path: str = "ffmpeg",
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = None,
    smscode: str | int | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Copy a cloud VTM live stream to MPEG-TS bytes."""

    if decrypt_video:
        _require_bounded_cloud_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )
        if media_key is None and smscode is not None:
            selected_key = client.get_cam_key(serial, smscode=smscode)
        else:
            selected_key = media_key if media_key is not None else client.get_cam_key(serial)
        if selected_key is None:
            raise PyEzvizError("decrypt_video requires a media_key or camera media key")
        with open_cloud_stream(
            client,
            serial,
            channel=channel,
            client_type=client_type,
            token_index=token_index,
            refresh_vtm=refresh_vtm,
            timeout=timeout,
        ) as stream:
            stream.start()
            packets = _collect_cloud_stream_packets(
                stream,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
        transport, media_packets = _peek_cloud_transport(iter(packets))
        packets = list(media_packets)
        copy_decrypted_cloud_stream_packets_to_mpegts(
            packets,
            output,
            ffmpeg_path=ffmpeg_path,
            media_key=selected_key,
            nalu_header_size=nalu_header_size,
            transport=transport,
        )
        return

    with open_cloud_stream(
        client,
        serial,
        channel=channel,
        client_type=client_type,
        token_index=token_index,
        refresh_vtm=refresh_vtm,
        timeout=timeout,
    ) as stream:
        stream.start()
        copy_cloud_stream_packets_to_mpegts(
            stream,
            output,
            ffmpeg_path=ffmpeg_path,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )


def _require_bounded_cloud_decrypt_capture(
    *,
    max_packets: int | None,
    duration_seconds: float | None,
) -> None:
    if not has_positive_finite_capture_bound(
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    ):
        raise PyEzvizError(
            "Encrypted cloud stream decrypt requires a positive finite "
            "duration_seconds or max_packets"
        )


def _write_cloud_stream_payloads(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    flush_each: bool = False,
) -> None:
    """Write clear VTM stream packet bodies to a binary file-like object."""

    for packet in _iter_bounded_cloud_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    ):
        if packet.encrypted:
            raise PyEzvizError(
                "Received encrypted VTM stream packet; media decryption is not implemented"
            )
        if packet.body:
            output.write(packet.body)
        if flush_each:
            output.flush()
    output.flush()


def _copy_cloud_stream_payloads_to_mpegps(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Copy clear MPEG-PS packets while rejecting known incompatible transports."""

    packets = _iter_bounded_cloud_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    transport, packets = _peek_cloud_transport(packets)
    if transport == StreamTransport.RTP:
        raise PyEzvizError(
            "Cloud stream carries RTP/IDMX, not MPEG-PS; request MPEG-TS output"
        )
    if transport == StreamTransport.MPEG_TS:
        raise PyEzvizError(
            "Cloud stream carries MPEG-TS, not MPEG-PS; request MPEG-TS output"
        )
    _write_clear_cloud_packets(packets, output)


def _collect_cloud_stream_payloads(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    """Collect clear VTM stream packet bodies into memory."""

    chunks: list[bytes] = []
    for packet in _iter_bounded_cloud_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    ):
        if packet.encrypted:
            raise PyEzvizError(
                "Received encrypted VTM stream packet; media decryption is not implemented"
            )
        chunks.append(packet.body)
    return b"".join(chunks)


def _collect_cloud_stream_packets(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[Any]:
    """Collect clear VTM packets while retaining RTP packet boundaries."""

    packets: list[Any] = []
    for packet in _iter_bounded_cloud_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    ):
        _require_clear_cloud_packet(packet)
        packets.append(packet)
    return packets


def _cloud_rtp_packet_nal_units(
    packets: Iterable[Any],
) -> tuple[RtpVideoCodec, tuple[bytes, ...]]:
    parsed = _cloud_rtp_packets(packets)

    codec = detect_rtp_video_codec(parsed)
    return codec, rtp_packets_to_nal_units(
        parsed,
        codec=codec,
        allow_ezviz_headerless_hevc_fu=True,
    )


def _cloud_rtp_packets(packets: Iterable[Any]) -> list[RtpPacket]:
    """Parse valid RTP packet bodies while ignoring interleaved control data."""

    parsed: list[RtpPacket] = []
    for packet in packets:
        rtp_packet = _parse_cloud_rtp_packet(packet.body)
        if rtp_packet is not None:
            parsed.append(rtp_packet)
    return parsed


def cloud_rtp_packets_have_audio(packets: Iterable[Any]) -> bool:
    """Return whether a bounded cloud capture contains routed RTP audio."""

    parsed = _cloud_rtp_packets(packets)
    descriptors = idmx_rtp_stream_descriptors(parsed)
    return any(
        rtp_media_kind(packet, stream_descriptors=descriptors) == "audio"
        for packet in parsed
    )


def _parse_cloud_rtp_packet(body: bytes) -> RtpPacket | None:
    """Return a valid RTP packet or ignore a nonmedia/invalid VTM body."""

    if not body or detect_transport(body) != StreamTransport.RTP:
        return None
    try:
        return parse_rtp_packet(body)
    except PyEzvizError:
        return None


def _decrypt_cloud_rtp_nal_unit(
    nal_unit: bytes,
    key: str | bytes,
    *,
    nalu_header_size: int,
) -> bytes:
    """Decrypt one RTP NAL while retaining its clear codec header."""

    annexb = ANNEX_B_START_CODE + nal_unit
    video_pes = b"\x00\x00\x01\xe0\x00\x00\x80\x00\x00" + annexb
    return decrypt_hikvision_ps_video(
        video_pes,
        key,
        nalu_header_size=nalu_header_size,
    )[9:]


def copy_decrypted_cloud_stream_packets_to_mpegts(
    packets: Iterable[Any],
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    media_key: str | bytes,
    nalu_header_size: int | None = None,
    transport: StreamTransport | None = None,
) -> None:
    """Decrypt one bounded cloud capture and remux its supported media to MPEG-TS."""

    packet_list = list(packets)
    selected_transport = transport
    if selected_transport is None:
        selected_transport, media_packets = _peek_cloud_transport(iter(packet_list))
        packet_list = list(media_packets)
    if selected_transport == StreamTransport.RTP:
        parsed = _cloud_rtp_packets(packet_list)
        codec = detect_rtp_video_codec(parsed)
        nal_units = rtp_packets_to_nal_units(
            parsed,
            codec=codec,
            allow_ezviz_headerless_hevc_fu=True,
        )
        header_size = nalu_header_size
        if header_size is None:
            header_size = 2 if codec == "hevc" else 1
        decrypted_annexb = b"".join(
            _decrypt_cloud_rtp_nal_unit(
                nal_unit,
                media_key,
                nalu_header_size=header_size,
            )
            for nal_unit in nal_units
        )
        audio = decrypt_idmx_aac_packets(parsed, media_key)
        if audio is not None:
            _remux_cloud_elementary_av_bytes_to_mpegts(
                decrypted_annexb,
                audio,
                output,
                ffmpeg_path=ffmpeg_path,
                codec=codec,
            )
            return
        _remux_cloud_elementary_bytes_to_mpegts(
            decrypted_annexb,
            output,
            ffmpeg_path=ffmpeg_path,
            codec=codec,
        )
        return
    if selected_transport == StreamTransport.MPEG_TS:
        raise PyEzvizError("decrypt_video does not support MPEG-TS cloud payloads")
    payload = b"".join(packet.body for packet in packet_list)
    _remux_cloud_mpegps_bytes_to_mpegts(
        decrypt_hikvision_ps_video(
            payload,
            media_key,
            nalu_header_size=nalu_header_size,
        ),
        output,
        ffmpeg_path=ffmpeg_path,
    )


def _iter_bounded_cloud_packets(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float],
) -> Iterator[Any]:
    """Iterate cloud packets with transport-level deadlines when available."""

    if isinstance(stream, VtmStreamClient):
        return stream.iter_packets(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )

    def _fallback() -> Iterator[Any]:
        deadline = None if duration_seconds is None else monotonic() + duration_seconds
        for packet in stream.iter_packets(max_packets=max_packets):
            if deadline is not None and monotonic() >= deadline:
                break
            yield packet

    return _fallback()


def copy_cloud_stream_packets_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    max_packets: int | None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    allow_encrypted: bool = False,
    mpegps_transform: Callable[[bytes], bytes] | None = None,
    rtp_transform: Callable[[bytes, RtpVideoCodec], bytes] | None = None,
    rtp_audio_key: str | bytes | None = None,
) -> None:
    """Route VTM payloads by transport and write MPEG-TS."""

    packets = _iter_bounded_cloud_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    transport, packets = _peek_cloud_transport(
        packets,
        allow_encrypted=allow_encrypted,
    )
    if transport == StreamTransport.MPEG_TS:
        if mpegps_transform is not None or rtp_transform is not None:
            raise PyEzvizError("Video decryption does not support MPEG-TS cloud payloads")
        _write_cloud_mpegts_packets(
            packets,
            output,
            allow_encrypted=allow_encrypted,
        )
        return
    if transport == StreamTransport.RTP:
        _copy_cloud_rtp_packets_to_mpegts(
            packets,
            output,
            ffmpeg_path=ffmpeg_path,
            cancel_input=getattr(stream, "close", None),
            transform=rtp_transform,
            audio_key=rtp_audio_key,
            allow_encrypted=allow_encrypted,
        )
        return

    process = _open_cloud_mpegts_remux_process(ffmpeg_path)

    def _write_input(stdin: BinaryIO) -> None:
        _write_clear_cloud_packets(
            packets,
            stdin,
            flush_each=True,
            transform=mpegps_transform,
            allow_encrypted=allow_encrypted,
        )

    copy_remuxed_output(
        process,
        output,
        write_input=_write_input,
        cancel_input=getattr(stream, "close", None),
    )


def _peek_cloud_transport(
    packets: Iterator[Any],
    *,
    allow_encrypted: bool = False,
) -> tuple[StreamTransport, Iterator[Any]]:
    """Discard nonmedia prelude packets until a known transport is found."""

    prefix: list[Any] = []
    for packet in packets:
        _require_clear_cloud_packet(packet, allow_encrypted=allow_encrypted)
        prefix.append(packet)
        if not packet.body:
            continue
        transport = detect_transport(packet.body)
        if transport == StreamTransport.MPEG_TS and not _is_valid_mpegts_body(
            packet.body
        ):
            continue
        if transport != StreamTransport.UNKNOWN:
            return transport, chain((packet,), packets)
    return StreamTransport.UNKNOWN, iter(prefix)


def _require_clear_cloud_packet(
    packet: Any,
    *,
    allow_encrypted: bool = False,
) -> None:
    if packet.encrypted and not allow_encrypted:
        raise PyEzvizError(
            "Received encrypted VTM stream packet; media decryption is not implemented"
        )


def _write_clear_cloud_packets(
    packets: Iterable[Any],
    output: BinaryIO,
    *,
    flush_each: bool = False,
    transform: Callable[[bytes], bytes] | None = None,
    allow_encrypted: bool = False,
) -> None:
    for packet in packets:
        _require_clear_cloud_packet(packet, allow_encrypted=allow_encrypted)
        payload = transform(packet.body) if transform else packet.body
        if payload:
            output.write(payload)
        if flush_each:
            output.flush()
    if transform is not None and hasattr(transform, "flush"):
        tail = transform.flush()
        if tail:
            output.write(tail)
    output.flush()


def _is_valid_mpegts_body(body: bytes) -> bool:
    """Return whether a VTM body contains complete 188-byte MPEG-TS packets."""

    packet_size = 188
    return (
        len(body) >= packet_size
        and len(body) % packet_size == 0
        and all(
            body[offset] == 0x47 and body[offset + 3] & 0x30
            for offset in range(0, len(body), packet_size)
        )
    )


def _write_cloud_mpegts_packets(
    packets: Iterable[Any],
    output: BinaryIO,
    *,
    allow_encrypted: bool,
) -> None:
    """Write only completely framed MPEG-TS VTM packet bodies."""

    for packet in packets:
        _require_clear_cloud_packet(packet, allow_encrypted=allow_encrypted)
        if _is_valid_mpegts_body(packet.body):
            output.write(packet.body)
    output.flush()


def _copy_cloud_rtp_packets_to_mpegts(  # noqa: PLR0912,PLR0915
    packets: Iterator[Any],
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    cancel_input: Callable[[], None] | None,
    transform: Callable[[bytes, RtpVideoCodec], bytes] | None = None,
    audio_key: str | bytes | None = None,
    allow_encrypted: bool = False,
) -> None:
    """Depacketize RTP video and optional descriptor-backed AAC to MPEG-TS."""

    prefix: list[RtpPacket] = []
    route_profile = RtpRouteProfile()
    video_probe: list[RtpPacket] = []
    codec: RtpVideoCodec | None = None
    audio_metadata: tuple[int, int] | None = None
    audio_decodable = False
    for packet in packets:
        _require_clear_cloud_packet(packet, allow_encrypted=allow_encrypted)
        parsed = _parse_cloud_rtp_packet(packet.body)
        if parsed is None:
            continue
        prefix.append(parsed)
        route_profile.absorb(parsed)
        stream_descriptors = route_profile.descriptors
        video_route_is_authoritative = any(
            descriptor.media_kind == "video"
            for descriptor in stream_descriptors
        )
        aac_payload_types = rtp_codec_payload_types(
            stream_descriptors,
            "aac",
            fallback_payload_types=DEFAULT_AAC_PAYLOAD_TYPES,
        )
        kind = rtp_media_kind(
            parsed,
            stream_descriptors=stream_descriptors,
        )
        if audio_metadata is None:
            audio_metadata = idmx_aac_descriptor((parsed,))
        if kind == "video":
            video_probe.append(parsed)
        try:
            codec = detect_rtp_video_codec(
                prefix,
                allow_fallback=False,
                stream_descriptors=stream_descriptors,
            )
        except UnsupportedRtpVideoCodecError:
            codec = None
            if (
                video_route_is_authoritative
                or len(prefix) >= _RTP_CODEC_PROBE_MAX_PACKETS
            ):
                raise
        except PyEzvizError:
            if len(video_probe) >= _RTP_CODEC_PROBE_MAX_PACKETS:
                codec = detect_rtp_video_codec(
                    prefix,
                    stream_descriptors=stream_descriptors,
                )
        if (
            audio_key is not None
            and audio_metadata is not None
            and kind in {"audio", "metadata"}
            and not audio_decodable
        ):
            audio_decodable = any(
                decrypt_idmx_aac_packets(
                    (candidate,),
                    audio_key,
                    audio_metadata=audio_metadata,
                    audio_payload_types=aac_payload_types,
                    require_contiguous=False,
                )
                is not None
                for candidate in prefix
                if rtp_media_kind(
                    candidate,
                    stream_descriptors=stream_descriptors,
                )
                == "audio"
            )
        if codec is None:
            continue
        if (
            not video_route_is_authoritative
            and len(video_probe) < _RTP_CODEC_PROBE_MAX_PACKETS
        ):
            continue
        if audio_key is None or audio_decodable:
            break
        if len(prefix) >= _RTP_AUDIO_PROBE_MAX_PACKETS:
            break
    if codec is None:
        try:
            codec = detect_rtp_video_codec(
                prefix,
                stream_descriptors=route_profile.descriptors,
            )
        except UnsupportedRtpVideoCodecError:
            raise
        except PyEzvizError as err:
            raise PyEzvizError(
                "Could not detect RTP video codec in cloud stream"
            ) from err

    def _remaining_rtp_packets() -> Iterator[RtpPacket]:
        for packet in packets:
            _require_clear_cloud_packet(packet, allow_encrypted=allow_encrypted)
            parsed = _parse_cloud_rtp_packet(packet.body)
            if parsed is None:
                continue
            yield parsed

    selected_audio_key = audio_key if audio_decodable else None
    stream_descriptors = route_profile.descriptors
    aac_payload_types = rtp_codec_payload_types(
        stream_descriptors,
        "aac",
        fallback_payload_types=DEFAULT_AAC_PAYLOAD_TYPES,
    )
    audio_input = _CloudRtpAudioInput() if selected_audio_key is not None else None
    if audio_input is not None:
        audio_input.start()
    try:
        if audio_input is None:
            process = _open_cloud_elementary_mpegts_remux_process(
                ffmpeg_path,
                codec,
            )
        else:
            process = _open_cloud_elementary_mpegts_remux_process(
                ffmpeg_path,
                codec,
                audio_url=audio_input.url,
            )
    except Exception:
        if audio_input is not None:
            audio_input.cancel()
            audio_input.finish(raise_errors=False)
        raise

    audio_failed = False

    def _write_input(stdin: BinaryIO) -> None:  # noqa: PLR0912,PLR0915
        nonlocal audio_failed
        depacketizer = RtpVideoDepacketizer(
            codec,
            allow_ezviz_headerless_hevc_fu=True,
        )
        nal_count = 0
        audio_enabled = audio_input is not None
        last_audio_sequence: dict[int, int] = {}
        next_audio_timestamp: dict[int, int] = {}

        def _disable_audio() -> None:
            nonlocal audio_enabled, audio_failed
            if not audio_enabled or audio_input is None:
                return
            audio_enabled = False
            audio_failed = True
            try:
                audio_input.close_input()
            except (BrokenPipeError, PyEzvizError):
                audio_input.cancel()

        try:
            buffered_packets = ((packet, True) for packet in prefix)
            live_packets = (
                (packet, False) for packet in _remaining_rtp_packets()
            )
            for packet, buffered in chain(buffered_packets, live_packets):
                if not buffered:
                    route_profile.absorb(packet)
                kind = route_profile.media_kind(packet)
                if (
                    kind == "audio"
                    and packet.payload_type in aac_payload_types
                    and audio_enabled
                    and audio_input is not None
                ):
                    route_profile.mark_media(packet, absorb=False)
                    previous_sequence = last_audio_sequence.get(packet.ssrc)
                    expected_timestamp = next_audio_timestamp.get(packet.ssrc)
                    if previous_sequence is not None and packet.sequence == previous_sequence:
                        continue
                    if previous_sequence is not None and packet.sequence != (
                        previous_sequence + 1
                    ) & 0xFFFF:
                        _disable_audio()
                        continue
                    if expected_timestamp is not None and (
                        packet.timestamp != expected_timestamp
                    ):
                        _disable_audio()
                        continue
                    assert selected_audio_key is not None
                    audio = decrypt_idmx_aac_packets(
                        (packet,),
                        selected_audio_key,
                        audio_metadata=audio_metadata,
                        audio_payload_types=aac_payload_types,
                        require_contiguous=False,
                    )
                    if audio is None:
                        _disable_audio()
                        continue
                    try:
                        audio_input.write(audio.adts)
                    except (BrokenPipeError, PyEzvizError):
                        _disable_audio()
                        continue
                    last_audio_sequence[packet.ssrc] = packet.sequence
                    next_audio_timestamp[packet.ssrc] = (
                        packet.timestamp + 1024 * audio.frame_count
                    ) & 0xFFFFFFFF
                    continue
                if kind != "video":
                    continue
                route_profile.mark_media(packet, absorb=False)
                for nal_unit in depacketizer.push(packet):
                    if nal_unit:
                        annexb = ANNEX_B_START_CODE + nal_unit
                        stdin.write(transform(annexb, codec) if transform else annexb)
                        stdin.flush()
                        nal_count += 1
            if nal_count == 0:
                raise PyEzvizError(
                    "RTP cloud stream did not contain a complete video NAL unit"
                )
        finally:
            if audio_input is not None and audio_enabled:
                audio_input.close_input()

    def _cancel_inputs() -> None:
        if cancel_input is not None:
            cancel_input()
        if audio_input is not None:
            audio_input.cancel()

    remux_error: BaseException | None = None
    try:
        copy_remuxed_output(
            process,
            output,
            write_input=_write_input,
            cancel_input=_cancel_inputs,
        )
    except BaseException as err:
        remux_error = err
        raise
    finally:
        if audio_input is not None:
            audio_input.finish(
                raise_errors=remux_error is None and not audio_failed,
            )


def _remux_cloud_mpegps_bytes_to_mpegts(
    data: bytes,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
) -> None:
    """Remux in-memory MPEG-PS bytes to MPEG-TS."""

    process = _open_cloud_mpegts_remux_process(ffmpeg_path)
    remux_bytes(process, data, output)


def _remux_cloud_elementary_bytes_to_mpegts(
    data: bytes,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    codec: RtpVideoCodec,
) -> None:
    """Remux in-memory Annex-B H.264 or HEVC bytes to MPEG-TS."""

    process = _open_cloud_elementary_mpegts_remux_process(ffmpeg_path, codec)
    remux_bytes(process, data, output)


def _remux_cloud_elementary_av_bytes_to_mpegts(
    video: bytes,
    audio: RtpAacStream,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    codec: RtpVideoCodec,
) -> None:
    """Remux bounded Annex-B video and descriptor-backed AAC into MPEG-TS."""

    with tempfile.TemporaryDirectory(prefix="pyezvizapi-cloud-rtp-") as directory:
        audio_path = Path(directory) / "audio.aac"
        audio_path.write_bytes(audio.adts)
        process = open_mpegts_remux_process(
            ffmpeg_path,
            input_format=codec,
            audio_path=str(audio_path),
            popen=subprocess.Popen,
        )
        remux_bytes(process, video, output)


def _open_cloud_mpegts_remux_process(ffmpeg_path: str) -> subprocess.Popen[bytes]:
    """Open an FFmpeg process ready to remux MPEG-PS stdin to MPEG-TS."""

    return open_mpegts_remux_process(ffmpeg_path, popen=subprocess.Popen)


def _open_cloud_elementary_mpegts_remux_process(
    ffmpeg_path: str,
    codec: RtpVideoCodec,
    *,
    audio_url: str | None = None,
) -> subprocess.Popen[bytes]:
    """Open FFmpeg for a depacketized H.264 or HEVC elementary stream."""

    return open_mpegts_remux_process(
        ffmpeg_path,
        input_format=codec,
        audio_url=audio_url,
        popen=subprocess.Popen,
    )


def parse_vtm_server_public_key(vtm: JsonDict) -> VtmServerPublicKey | None:
    """Return decoded VTM server public key metadata when present."""

    public_key = vtm.get("publicKey")
    if not isinstance(public_key, dict):
        return None

    key = public_key.get("key")
    version = public_key.get("version")
    if not isinstance(key, str) or not key:
        return None
    if not isinstance(version, (int, str)) or not str(version).isdigit():
        raise PyEzvizError("VTM public key version is invalid")

    try:
        key_bytes = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error) as err:
        raise PyEzvizError("VTM public key is not valid base64") from err

    return VtmServerPublicKey(
        version=int(version),
        key=key,
        key_bytes=key_bytes,
    )


def _find_vtm_resource(
    resources: list[Any],
    serial: str,
    *,
    channel: int | None,
) -> JsonDict | None:
    serial_resources = [
        item for item in resources if isinstance(item, dict) and item.get("deviceSerial") == serial
    ]
    if channel is None:
        return cast(JsonDict, serial_resources[0]) if serial_resources else None

    channel_text = str(channel)
    return next(
        (
            cast(JsonDict, item)
            for item in serial_resources
            if str(item.get("localIndex")) == channel_text
        ),
        None,
    )


def _http_status_code(err: HTTPError) -> int | None:
    cause = err.__cause__
    response = getattr(cause, "response", None)
    status_code = getattr(response, "status_code", None)
    return status_code if isinstance(status_code, int) else None


def _success_retcode(retcode: Any) -> bool:
    return retcode in {0, "0"}


def _session_sign(session_id: Any) -> str:
    if not session_id:
        raise PyEzvizError("No Login token present!")
    parts = str(session_id).split(".")
    if len(parts) < 2:
        raise PyEzvizError("Current session token is not a JWT")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode())
        claims = json.loads(decoded.decode())
    except (ValueError, UnicodeDecodeError) as err:
        raise PyEzvizError("Could not decode current session token claims") from err
    if not isinstance(claims, dict):
        raise PyEzvizError("Session token claims are not an object")
    sign = claims.get("s")
    if not isinstance(sign, str) or not sign:
        raise PyEzvizError("Current session token does not contain VTDU sign claim")
    return sign


def _auth_base_url(client: Any) -> str:
    token = getattr(client, "_token", {})
    service_urls = token.get("service_urls") if isinstance(token, dict) else None
    if not isinstance(service_urls, dict) or _missing_auth_addr(service_urls.get("authAddr")):
        service_urls = client.get_service_urls()
        if isinstance(token, dict):
            token["service_urls"] = service_urls

    auth_addr = str(service_urls.get("authAddr", "")).strip()
    if _missing_auth_addr(auth_addr):
        auth_addr = _derive_auth_addr(token)
    if not auth_addr.startswith(("http://", "https://")):
        auth_addr = f"https://{auth_addr}"
    parsed = urlparse(auth_addr)
    if not parsed.netloc:
        raise PyEzvizError(f"Invalid authAddr: {auth_addr}")
    return auth_addr.rstrip("/")


def _missing_auth_addr(value: Any) -> bool:
    auth_addr = str(value or "").strip()
    if not auth_addr or auth_addr.lower() in {"none", "null"}:
        return True
    candidate = auth_addr
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    return (parsed.hostname or "").lower() in {"", "none", "null"}


def _derive_auth_addr(token: Any) -> str:
    """Derive the auth service host when system info returns a null authAddr."""

    api_url = str(token.get("api_url", "") if isinstance(token, dict) else "").strip()
    parsed = urlparse(api_url if "://" in api_url else f"https://{api_url}")
    host = parsed.hostname or ""
    prefix = "apii"
    suffix = ".ezvizlife.com"
    if host.startswith(prefix) and host.endswith(suffix):
        region = host[len(prefix) : -len(suffix)]
        if region:
            return f"https://{region}auth.ezvizlife.com"
    raise PyEzvizError("Missing authAddr in service URLs")
