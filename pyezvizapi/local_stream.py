"""Local EZVIZ stream adapters with native MPEG-PS output."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from itertools import chain
import subprocess
from threading import Thread
import time
from typing import Any, BinaryIO, Literal, cast

from Crypto.Cipher import AES

from .cas import CasDeviceSession, EzvizCAS
from .exceptions import PyEzvizError
from .hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoExAttrs,
    EzvizLocalSdkClient,
    EzvizLocalSdkStreamBootstrap,
    HcNetSdkLanEndpoint,
    HcNetSdkRealDataPacket,
    SocketFactory,
    iter_hcnetsdk_real_data_mpegps,
)
from .stream import (
    ANNEX_B_LONG_START_CODE,
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    MPEG_PS_START_CODE,
    _hikvision_aes_ecb_cipher,
    decrypt_hikvision_ps_video,
    rtp_payload,
)


@dataclass(frozen=True)
class EzvizLocalStreamPacket:
    """One local SDK media packet converted to an MPEG-PS payload."""

    channel: int
    length: int
    body: bytes
    encrypted: bool = False
    prefix: bytes = b""


@dataclass(frozen=True)
class EzvizLocalSdkCredentials:
    """Credentials and endpoint data needed for direct-local SDK streaming."""

    endpoint: HcNetSdkLanEndpoint
    device_info: EzvizCasDeviceInfo = field(repr=False)
    media_key: str | bytes | None = field(default=None, repr=False)

    def as_dict(self, *, include_media_key: bool = False) -> dict[str, Any]:
        """Return a JSON-friendly representation for explicit inspection flows."""
        result: dict[str, Any] = {
            "serial": self.device_info.serial,
            "endpoint": {
                "host": self.endpoint.host,
                "command_port": self.endpoint.command_port,
                "stream_port": self.endpoint.stream_port,
            },
            "cas": {
                "operation_code": self.device_info.operation_code,
                "key": self.device_info.key,
                "encrypt_type": self.device_info.encrypt_type,
            },
        }
        if include_media_key and self.media_key is not None:
            if isinstance(self.media_key, bytes):
                result["media_key_hex"] = self.media_key.hex()
            else:
                result["media_key"] = self.media_key
        return result


LocalSdkOutputFormat = Literal["mpegps", "mpegts"]


class EzvizLocalSdkMediaStream:
    """Direct-local SDK media stream compatible with the cloud stream dump path.

    This adapter is for the CAS/local-SDK socket family, where Python can
    bootstrap ``0x2011``/``0x3105`` and then read interleaved RTP frames from
    the stream socket. It intentionally does not claim to implement the
    proprietary HCNetSDK command protocol on port 8000.
    """

    def __init__(
        self,
        sdk_client: EzvizLocalSdkClient,
        preview_request: EzvizLocalPreviewRequest,
        *,
        pre_start_body: bytes | str | None = None,
        pre_start_sequence: int = 0,
        preview_sequence: int = 0,
        stream_setup_sequence: int = 0,
        stream_rate: str | int = 0,
        stream_mode: str | int = 0,
        max_prefix_bytes: int = 4096,
    ) -> None:
        self.sdk_client = sdk_client
        self.preview_request = preview_request
        self.pre_start_body = pre_start_body
        self.pre_start_sequence = pre_start_sequence
        self.preview_sequence = preview_sequence
        self.stream_setup_sequence = stream_setup_sequence
        self.stream_rate = stream_rate
        self.stream_mode = stream_mode
        self.max_prefix_bytes = max_prefix_bytes
        self.bootstrap: EzvizLocalSdkStreamBootstrap | None = None
        self._first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

    def __enter__(self) -> EzvizLocalSdkMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying local SDK sockets."""
        self.sdk_client.close()

    def start(self) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap preview setup and read the first local RTP media frame."""
        self.bootstrap = self.sdk_client.bootstrap_preview_from_fields(
            preview_request=self.preview_request,
            pre_start_body=self.pre_start_body,
            pre_start_sequence=self.pre_start_sequence,
            preview_sequence=self.preview_sequence,
            stream_setup_sequence=self.stream_setup_sequence,
            stream_rate=self.stream_rate,
            stream_mode=self.stream_mode,
            read_first_media=True,
            max_prefix_bytes=self.max_prefix_bytes,
        )
        self._first_media = self.bootstrap.first_media
        if self._first_media is None:
            raise PyEzvizError("EZVIZ local stream did not return a first media frame")
        return self.bootstrap

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield local RTP payloads as MPEG-PS packet bodies."""
        if max_packets is not None and max_packets <= 0:
            return

        if self.bootstrap is None:
            self.start()

        emitted = 0
        if self._first_media is not None:
            yield _local_media_packet(self._first_media)
            emitted += 1
            self._first_media = None

        while max_packets is None or emitted < max_packets:
            media = self.sdk_client.read_stream_frame_after_prefix(
                max_prefix_bytes=self.max_prefix_bytes,
            )
            yield _local_media_packet(media)
            emitted += 1


def open_local_sdk_stream(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    device_info: EzvizCasDeviceInfo,
    preview_request: EzvizLocalPreviewRequest,
    *,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    pre_start_body: bytes | str | None = None,
    pre_start_sequence: int = 0,
    preview_sequence: int = 0,
    stream_setup_sequence: int = 0,
    stream_rate: str | int = 0,
    stream_mode: str | int = 0,
    max_prefix_bytes: int = 4096,
    command_source_port: int | None = None,
) -> EzvizLocalSdkMediaStream:
    """Return a direct-local SDK media stream ready for native packet reads."""
    if socket_factory is None:
        sdk_client = EzvizLocalSdkClient(
            endpoint,
            device_info,
            timeout=timeout,
            command_source_port=command_source_port,
        )
    else:
        sdk_client = EzvizLocalSdkClient(
            endpoint,
            device_info,
            timeout=timeout,
            socket_factory=socket_factory,
            command_source_port=command_source_port,
        )
    return EzvizLocalSdkMediaStream(
        sdk_client,
        preview_request,
        pre_start_body=pre_start_body,
        pre_start_sequence=pre_start_sequence,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
    )


def open_local_sdk_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    *,
    channel: int = 1,
    cas_serial: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    receiver_port: int = 10101,
    receiver_stream_type: str = "MAIN",
    receiver_server_type: int = 1,
    receiver_new_stream_type: int = 1,
    receiver_trans_proto: str = "TCP",
    receiver_ex_port: int = 10101,
    auth_biz_code: str = "biz=1",
    auth_interval: int = 180,
    is_encrypt: str = "TRUE",
    uuid: str | None = None,
    timestamp: str | None = None,
    preview_sequence: int = 16,
    stream_setup_sequence: int = 17,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    max_prefix_bytes: int = 4096,
) -> EzvizLocalSdkMediaStream:
    """Return a direct-local stream using an authenticated EZVIZ client.

    This convenience wrapper fetches the LAN endpoint from get_device_infos
    and the CAS tuple from EzvizCAS.cas_get_encryption. It is still the
    direct-local 9010/9020 SDK path; it does not implement the proprietary
    HCNetSDK command protocol used on port 8000.
    """
    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        fetch_media_key=False,
    )
    preview_request = _local_sdk_preview_request_from_credentials(
        credentials,
        channel=channel,
        receiver_port=receiver_port,
        receiver_stream_type=receiver_stream_type,
        receiver_server_type=receiver_server_type,
        receiver_new_stream_type=receiver_new_stream_type,
        receiver_trans_proto=receiver_trans_proto,
        receiver_ex_port=receiver_ex_port,
        auth_biz_code=auth_biz_code,
        auth_interval=auth_interval,
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )
    return open_local_sdk_stream(
        credentials.endpoint,
        credentials.device_info,
        preview_request,
        timeout=timeout,
        socket_factory=socket_factory,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
        command_source_port=receiver_port,
    )


def copy_local_sdk_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    output_format: LocalSdkOutputFormat = "mpegts",
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = 0,
    channel: int = 1,
    cas_serial: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    receiver_port: int = 10101,
    receiver_stream_type: str = "MAIN",
    receiver_server_type: int = 1,
    receiver_new_stream_type: int = 1,
    receiver_trans_proto: str = "TCP",
    receiver_ex_port: int = 10101,
    auth_biz_code: str = "biz=1",
    auth_interval: int = 180,
    is_encrypt: str = "TRUE",
    uuid: str | None = None,
    timestamp: str | None = None,
    preview_sequence: int = 16,
    stream_setup_sequence: int = 17,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    max_prefix_bytes: int = 4096,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    ffmpeg_path: str = "ffmpeg",
    monotonic: Callable[[], float] = time.monotonic,
    smscode: str | int | None = None,
    cam_key_max_retries: int = 1,
) -> EzvizLocalSdkCredentials:
    """Open a direct-local SDK stream from an authenticated client and copy bytes.

    This is the public convenience path for integrations that want local
    9010/9020 media without wiring the CAS lookup, preview bootstrap, MPEG-PS
    collection, optional video decrypt, and MPEG-TS remux steps by hand.
    """
    if output_format not in ("mpegps", "mpegts"):
        raise PyEzvizError("output_format must be 'mpegps' or 'mpegts'")
    if decrypt_video:
        _require_bounded_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )

    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        fetch_media_key=decrypt_video and media_key is None,
        smscode=smscode,
        cam_key_max_retries=cam_key_max_retries,
    )
    selected_media_key = media_key if media_key is not None else credentials.media_key
    if decrypt_video and selected_media_key is None:
        raise PyEzvizError("decrypt_video requires a media_key or fetchable camera media key")

    preview_request = _local_sdk_preview_request_from_credentials(
        credentials,
        channel=channel,
        receiver_port=receiver_port,
        receiver_stream_type=receiver_stream_type,
        receiver_server_type=receiver_server_type,
        receiver_new_stream_type=receiver_new_stream_type,
        receiver_trans_proto=receiver_trans_proto,
        receiver_ex_port=receiver_ex_port,
        auth_biz_code=auth_biz_code,
        auth_interval=auth_interval,
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )
    with open_local_sdk_stream(
        credentials.endpoint,
        credentials.device_info,
        preview_request,
        timeout=timeout,
        socket_factory=socket_factory,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
        command_source_port=receiver_port,
    ) as stream:
        if output_format == "mpegps":
            if decrypt_video:
                copy_local_stream_to_decrypted_mpegps(
                    stream,
                    output,
                    cast(str | bytes, selected_media_key),
                    nalu_header_size=nalu_header_size,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
            else:
                copy_local_stream_to_mpegps(
                    stream,
                    output,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
        elif decrypt_video:
            copy_local_stream_to_decrypted_mpegts(
                stream,
                output,
                cast(str | bytes, selected_media_key),
                ffmpeg_path=ffmpeg_path,
                nalu_header_size=nalu_header_size,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
        else:
            copy_local_stream_to_mpegts(
                stream,
                output,
                ffmpeg_path=ffmpeg_path,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
    return credentials


def get_local_sdk_stream_credentials_from_client(
    client: Any,
    serial: str,
    *,
    cas_serial: str | None = None,
    fetch_media_key: bool = True,
    smscode: str | int | None = None,
    cam_key_max_retries: int = 1,
) -> EzvizLocalSdkCredentials:
    """Fetch LAN endpoint, CAS tuple and optional media key from EZVIZ services."""
    endpoint = _local_sdk_endpoint_from_client(client, serial)
    cas_session = CasDeviceSession.from_response(
        EzvizCAS(client.export_token()).cas_get_encryption(cas_serial or serial)
    )
    media_key: str | bytes | None = None
    if fetch_media_key:
        if smscode is None:
            media_key = client.get_cam_key(serial, max_retries=cam_key_max_retries)
        else:
            media_key = client.get_cam_key(
                serial,
                smscode=smscode,
                max_retries=cam_key_max_retries,
            )
        if media_key is not None:
            media_key = str(media_key)

    return EzvizLocalSdkCredentials(
        endpoint=endpoint,
        device_info=EzvizCasDeviceInfo(
            serial=serial,
            operation_code=cas_session.operation_code,
            key=cas_session.key,
            encrypt_type=cas_session.encrypt_type,
        ),
        media_key=media_key,
    )


def _local_sdk_preview_request_from_credentials(  # noqa: PLR0913
    credentials: EzvizLocalSdkCredentials,
    *,
    channel: int,
    receiver_port: int,
    receiver_stream_type: str,
    receiver_server_type: int,
    receiver_new_stream_type: int,
    receiver_trans_proto: str,
    receiver_ex_port: int,
    auth_biz_code: str,
    auth_interval: int,
    is_encrypt: str,
    uuid: str | None,
    timestamp: str | None,
) -> EzvizLocalPreviewRequest:
    return EzvizLocalPreviewRequest(
        operation_code=credentials.device_info.operation_code,
        channel=channel,
        receiver_info=EzvizLocalReceiverInfoAttrs(
            port=receiver_port,
            server_type=receiver_server_type,
            stream_type=receiver_stream_type,
            new_stream_type=receiver_new_stream_type,
            trans_proto=receiver_trans_proto,
        ),
        receiver_info_ex=EzvizLocalReceiverInfoExAttrs(port=receiver_ex_port),
        authentication=EzvizLocalAuthenticationAttrs(
            biz_code=auth_biz_code,
            interval=auth_interval,
        ),
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )


def copy_local_stream_to_mpegps(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Write local MPEG-PS payloads directly without an FFmpeg subprocess."""
    _write_local_stream_payloads(
        stream,
        output,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )


def collect_local_stream_mpegps(
    stream: Any,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    """Collect bounded local MPEG-PS payloads into memory.

    This is intended for transforms, such as the EZVIZ encrypted-video NAL
    decrypt pass, that need complete MPEG-PS packet context across local RTP
    packet boundaries.
    """
    output = bytearray()
    deadline = None if duration_seconds is None else monotonic() + duration_seconds
    for packet in stream.iter_packets(max_packets=max_packets):
        if deadline is not None and monotonic() >= deadline:
            break
        output.extend(packet.body)
    return bytes(output)


def copy_local_stream_to_decrypted_mpegps(
    stream: Any,
    output: BinaryIO,
    media_key: str | bytes,
    *,
    nalu_header_size: int | None = None,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Collect, decrypt and write local MPEG-PS payloads.

    Decryption is deliberately bounded by max_packets or duration_seconds
    because the MPEG-PS/NAL transform is stateful across packet splits and must
    operate on an in-memory capture.
    """
    _require_bounded_decrypt_capture(
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    )
    packets = collect_local_stream_media_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    if _local_stream_packets_are_idmx(packets):
        raise _unsupported_idmx_local_payload_error()
    payload = b"".join(packets)
    output.write(
        decrypt_hikvision_ps_video(
            payload,
            media_key,
            nalu_header_size=nalu_header_size,
        )
    )
    output.flush()


def copy_local_stream_to_decrypted_mpegts(
    stream: Any,
    output: BinaryIO,
    media_key: str | bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    nalu_header_size: int | None = None,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Collect, decrypt, remux and write local MPEG-TS bytes."""
    _require_bounded_decrypt_capture(
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    )
    packets = collect_local_stream_media_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    if _local_stream_packets_are_idmx(packets):
        hevc = _decrypt_idmx_local_packets_to_annexb(packets, media_key)
        process = _open_local_hevc_mpegts_remux_process(ffmpeg_path)
        _copy_mpegps_payloads_to_mpegts([hevc], output, process=process)
        return
    decrypted = decrypt_hikvision_ps_video(
        b"".join(packets),
        media_key,
        nalu_header_size=nalu_header_size,
    )
    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts([decrypted], output, process=process)


def _require_bounded_decrypt_capture(
    *,
    max_packets: int | None,
    duration_seconds: float | None,
) -> None:
    if max_packets is None and duration_seconds is None:
        raise PyEzvizError(
            "Encrypted local stream decrypt requires duration_seconds or max_packets"
        )


def copy_local_stream_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Pipe local media payloads through FFmpeg and write MPEG-TS bytes."""
    payloads = _iter_local_stream_payloads(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    try:
        first_payload = next(payloads)
    except StopIteration:
        output.flush()
        return

    if _looks_like_idmx_local_payload(first_payload):
        raise _unsupported_idmx_local_payload_error()
    if not first_payload.startswith(MPEG_PS_START_CODE):
        raise PyEzvizError(
            "Unsupported EZVIZ local stream payload format: expected MPEG-PS payload"
        )

    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts(
        chain((first_payload,), payloads),
        output,
        process=process,
    )


def copy_hcnetsdk_real_data_to_mpegts(
    packets: Iterable[HcNetSdkRealDataPacket],
    output: BinaryIO,
    *,
    ffmpeg_path: str = "ffmpeg",
) -> None:
    """Remux HCNetSDK real-play MPEG-PS callback packets to MPEG-TS."""
    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts(
        iter_hcnetsdk_real_data_mpegps(packets),
        output,
        process=process,
    )


def _local_media_packet(
    media: EzvizInterleavedRtpFrameWithPrefix,
) -> EzvizLocalStreamPacket:
    body = _strip_local_sdk_payload_header(rtp_payload(media.frame.payload))
    return EzvizLocalStreamPacket(
        channel=media.frame.header.channel,
        length=len(body),
        body=body,
        prefix=media.prefix,
    )


def _strip_local_sdk_payload_header(payload: bytes) -> bytes:
    """Remove the 2-byte EZVIZ local stream fragment header before MPEG-PS.

    The direct-local 9020 path wraps every RTP payload body with a small
    fragment marker. Observed local-SDK values are 1c80 for the first fragment
    of a PS packet and 1c00 for continuations. FFmpeg expects concatenated
    MPEG-PS bytes, so callers should not see this local transport marker.
    """
    if len(payload) >= 2 and payload[0] == 0x1C:
        return payload[2:]
    return payload


def _local_sdk_endpoint_from_client(client: Any, serial: str) -> HcNetSdkLanEndpoint:
    devices = client.get_device_infos(serial)
    device = None
    if isinstance(devices, dict):
        if isinstance(devices.get(serial), dict):
            device = devices[serial]
        elif isinstance(devices.get("CONNECTION"), dict):
            device = devices
    if not isinstance(device, dict):
        raise PyEzvizError(f"EZVIZ device {serial!r} was not found")
    connection = device.get("CONNECTION")
    if not isinstance(connection, dict):
        raise PyEzvizError(f"EZVIZ device {serial!r} does not include CONNECTION data")
    return HcNetSdkLanEndpoint.from_connection(serial, connection)


def _open_local_mpegts_remux_process(ffmpeg_path: str) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(
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
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err


def _open_local_hevc_mpegts_remux_process(
    ffmpeg_path: str,
) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(
            [
                ffmpeg_path,
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "hevc",
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
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err


IDMX_LOCAL_FRAME_SENTINEL = b"\x55\x66\x77\x88"
IDMX_LOCAL_FRAME_HEADER_SIZE = 13
HEVC_NAL_HEADER_SIZE = 2
IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET = 12


def collect_local_stream_media_packets(
    stream: Any,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[bytes]:
    """Collect bounded local media payloads while preserving RTP packet boundaries."""

    return list(
        _iter_local_stream_payloads(
            stream,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )
    )


def _looks_like_idmx_local_payload(payload: bytes) -> bool:
    return (
        len(payload) >= IDMX_LOCAL_FRAME_HEADER_SIZE
        and payload[0] == 0x0D
        and payload[9:13] == IDMX_LOCAL_FRAME_SENTINEL
    )


def _local_stream_packets_are_idmx(packets: list[bytes]) -> bool:
    return bool(packets) and _looks_like_idmx_local_payload(packets[0])


def _unsupported_idmx_local_payload_error() -> PyEzvizError:
    return PyEzvizError(
        "Unsupported encrypted EZVIZ local IDMX stream payload: decrypt-video is required"
    )


def _decrypt_idmx_local_packets_to_annexb(
    packets: list[bytes],
    media_key: str | bytes,
) -> bytes:
    aes_key = _local_media_aes_key(media_key)
    output = bytearray()
    active_fu: bytearray | None = None
    for packet in packets:
        if not _looks_like_idmx_local_payload(packet):
            raise PyEzvizError("Mixed EZVIZ local stream payload formats are unsupported")
        body = packet[IDMX_LOCAL_FRAME_HEADER_SIZE:]
        if _looks_like_idmx_hevc_parameter_frame(body):
            # Live PlayCtrl takes parameter sets from the media-wrapper frames below;
            # the short sidecar-looking 00 01/00 02 records are not fed to FFmpeg.
            continue
        if _looks_like_idmx_hevc_media_frame(body):
            active_fu = _append_idmx_hevc_media_payload(
                output,
                body[IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET:],
                aes_key,
                active_fu=active_fu,
            )
    if active_fu is not None:
        _append_decrypted_hevc_nal(output, bytes(active_fu), aes_key)
    if not output:
        raise PyEzvizError("EZVIZ local IDMX stream did not include HEVC media frames")
    return bytes(output)


def _local_media_aes_key(media_key: str | bytes) -> bytes:
    key_bytes = media_key.encode() if isinstance(media_key, str) else media_key
    return key_bytes.ljust(16, b"\0")[:16]


def _looks_like_idmx_hevc_parameter_frame(body: bytes) -> bool:
    return len(body) > 4 and body[:2] in (
        b"\x00\x01",
        b"\x00\x02",
    )


def _looks_like_idmx_hevc_media_frame(body: bytes) -> bool:
    return (
        len(body) > IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET
        and body.startswith(b"\x40\x00\x00\x02\x80\x06")
    )


def _append_idmx_hevc_media_payload(
    output: bytearray,
    payload: bytes,
    aes_key: bytes,
    *,
    active_fu: bytearray | None,
) -> bytearray | None:
    if len(payload) < HEVC_NAL_HEADER_SIZE:
        return active_fu
    nal_type = (payload[0] >> 1) & 0x3F
    if nal_type != 49:
        if _is_plausible_hevc_nal(payload):
            _append_decrypted_hevc_nal(output, payload, aes_key)
        return active_fu
    if len(payload) < 3:
        return active_fu

    fu_header = payload[2]
    is_start = bool(fu_header & 0x80)
    is_end = bool(fu_header & 0x40)
    original_type = fu_header & 0x3F
    reconstructed_header = bytes(
        [
            (payload[0] & 0x81) | (original_type << 1),
            payload[1],
        ]
    )
    if is_start or active_fu is None:
        active_fu = bytearray(reconstructed_header)
    active_fu.extend(payload[3:])
    if is_end:
        _append_decrypted_hevc_nal(output, bytes(active_fu), aes_key)
        return None
    return active_fu


def _append_decrypted_hevc_nal(
    output: bytearray,
    nal: bytes,
    aes_key: bytes,
) -> None:
    if not _is_plausible_hevc_nal(nal):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(_decrypt_hevc_nal_prefix(nal, aes_key))


def _is_plausible_hevc_nal(nal: bytes) -> bool:
    return (
        len(nal) >= HEVC_NAL_HEADER_SIZE
        and not nal[0] & 0x80
        and nal[1] & 0x07 != 0
        and (nal[0] >> 1) & 0x3F <= 40
    )


def _decrypt_hevc_nal_prefix(nal: bytes, aes_key: bytes) -> bytes:
    # PlayCtrl's live HEVC path passes encLenInfo=null and decrypts a fixed
    # 4096-byte AES-ECB prefix after the clear HEVC NAL header. For fragmented
    # units, we reconstruct the full NAL first so the prefix spans fragments.
    frame = bytearray(nal)
    decrypt_length = min(
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        len(frame) - HEVC_NAL_HEADER_SIZE,
    )
    decrypt_length -= decrypt_length % AES.block_size
    if decrypt_length > 0:
        cipher = _hikvision_aes_ecb_cipher(aes_key)
        decrypt_end = HEVC_NAL_HEADER_SIZE + decrypt_length
        frame[HEVC_NAL_HEADER_SIZE:decrypt_end] = cipher.decrypt(
            bytes(frame[HEVC_NAL_HEADER_SIZE:decrypt_end])
        )
    return bytes(frame)


def _iter_local_stream_payloads(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float],
) -> Iterator[bytes]:
    deadline = None if duration_seconds is None else monotonic() + duration_seconds
    for packet in stream.iter_packets(max_packets=max_packets):
        if deadline is not None and monotonic() >= deadline:
            break
        yield packet.body


def _copy_mpegps_payloads_to_mpegts(
    payloads: Iterable[bytes],
    output: BinaryIO,
    *,
    process: subprocess.Popen[bytes],
) -> None:
    stdin = process.stdin
    stdout = process.stdout
    if stdin is None or stdout is None:
        raise PyEzvizError("Could not open FFmpeg pipes")

    writer_errors: list[Exception] = []

    def _write_input() -> None:
        try:
            for payload in payloads:
                stdin.write(payload)
                stdin.flush()
        except (BrokenPipeError, ConnectionResetError):
            # FFmpeg may close stdin after producing enough output for the caller.
            return
        except Exception as err:  # pragma: no cover - defensive thread handoff
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


def _write_local_stream_payloads(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float],
) -> None:
    deadline = None if duration_seconds is None else monotonic() + duration_seconds
    for packet in stream.iter_packets(max_packets=max_packets):
        if deadline is not None and monotonic() >= deadline:
            break
        output.write(packet.body)
        output.flush()
