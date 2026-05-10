"""Helpers for EZVIZ cloud stream discovery and VTM/VTDU framing."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from enum import IntEnum
import hashlib
from ipaddress import IPv6Address, ip_address
import re
import socket
import ssl
import struct
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from Crypto.Cipher import AES

from .exceptions import PyEzvizError

VTM_MAGIC = 0x24
VTM_HEADER_SIZE = 8
MPEG_PS_START_CODE = b"\x00\x00\x01\xba"
MPEG_TS_SYNC_BYTE = b"\x47"
MPEG_START_CODE_PREFIX = b"\x00\x00\x01"
ANNEX_B_LONG_START_CODE = b"\x00\x00\x00\x01"
HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH = 4096
VIDEO_PES_STREAM_ID = 0xE0
_PACK_HEADER_STREAM_ID = 0xBA
_SYSTEM_HEADER_STREAM_ID = 0xBB
_PROGRAM_STREAM_MAP_ID = 0xBC
_PRIVATE_STREAM_1_ID = 0xBD
_PADDING_STREAM_ID = 0xBE
_PRIVATE_STREAM_2_ID = 0xBF
CLOUD_REPLAY_MAGIC = 0x9EBAACE9
CLOUD_REPLAY_OPEN_CMD = 0x5003
CLOUD_REPLAY_HEARTBEAT_CMD = 0x5010
CLOUD_REPLAY_HEADER_SIZE = 32
XML_PREFIX = b"<?xml"
_XML_END_RE = re.compile(br"</(Request|Response)>")


def _ezviz_md5_hex(data: bytes) -> str:
    """Return the EZVIZ protocol MD5 checksum for non-security integrity fields."""

    return hashlib.md5(data, usedforsecurity=False).hexdigest()


class VtmChannel(IntEnum):
    """Known VTM/VTDU channels."""

    MESSAGE = 0x00
    STREAM = 0x01
    ENCRYPTED_MESSAGE = 0x0A
    ENCRYPTED_STREAM = 0x0B


class VtmMessageCode(IntEnum):
    """Known VTM/VTDU message codes."""

    KEEPALIVE_REQ = 0x132
    KEEPALIVE_RSP = 0x133
    STREAMINFO_REQ = 0x13B
    STREAMINFO_RSP = 0x13C
    STREAMINFO_NOTIFY = 0x13D
    STREAM_VTMSTREAM_ECDH_NOTIFY = 0x14A


class StreamTransport(IntEnum):
    """Best-effort transport detection for stream-channel payloads."""

    UNKNOWN = 0
    MPEG_TS = 2
    MPEG_PS = 3
    RTP = 4


@dataclass(frozen=True)
class VtmPacket:
    """Decoded VTM/VTDU packet container."""

    channel: int
    length: int
    sequence: int
    message_code: int
    body: bytes = b""

    @property
    def encrypted(self) -> bool:
        """Return True when the channel is one of the encrypted channel IDs."""

        return self.channel in (
            VtmChannel.ENCRYPTED_MESSAGE,
            VtmChannel.ENCRYPTED_STREAM,
        )


@dataclass(frozen=True)
class VtmTraceEvent:
    """Sanitized VTM/VTDU packet summary for live stream tracing."""

    index: int
    channel: int
    channel_name: str | None
    length: int
    sequence: int
    message_code: int
    message_name: str | None
    encrypted: bool
    transport: str

    def as_dict(self) -> dict[str, int | str | bool | None]:
        """Return a JSON-serializable trace event."""

        return asdict(self)


@dataclass(frozen=True)
class StreamInfoResponse:
    """Limited decoded fields from a StreamInfoRsp protobuf body."""

    result: int | None = None
    datakey: int | None = None
    streamhead: str | None = None
    streamssn: str | None = None
    vtmstreamkey: str | None = None
    serverinfo: str | None = None
    streamurl: str | None = None
    srvinfo: str | None = None
    aesmd5: str | None = None
    udptransinfo: str | None = None
    peerpbkey: str | None = None
    pdslist: tuple[bytes, ...] = ()
    srvipv6_addr: str | None = None


@dataclass(frozen=True)
class VtduInfoResponse:
    """Decoded fields from a GetVtduInfoRsp protobuf body."""

    result: int | None = None
    host: str | None = None
    port: int | None = None
    streamkey: str | None = None
    peerhost: str | None = None
    peerport: int | None = None
    srvinfo: str | None = None


@dataclass(frozen=True)
class VtduStreamResponse:
    """Decoded fields shared by StartStreamRsp and PeerStreamRsp."""

    result: int | None = None
    streamhead: str | None = None
    streamssn: str | None = None
    datakey: int | None = None


@dataclass(frozen=True)
class StopStreamResponse:
    """Decoded fields from a StopStreamRsp protobuf body."""

    result: int | None = None


SocketFactory = Callable[[tuple[str, int], float | None], Any]


class VtmStreamClient:
    """Experimental synchronous client for the APK-discovered VTM TCP stream.

    This implements the unencrypted VTM framing path observed in the EZVIZ APK:
    open TCP to the VTM endpoint, send ``StreamInfoReq`` on the message channel,
    parse ``StreamInfoRsp``, then consume stream-channel packets. Encrypted ECDH
    packets are surfaced as packets but not decrypted.
    """

    def __init__(
        self,
        stream_url: str,
        *,
        timeout: float | None = 10.0,
        client_version: str = "v3.6.3.20221124",
        socket_factory: SocketFactory = socket.create_connection,
    ) -> None:
        self.stream_url = stream_url
        self.timeout = timeout
        self.client_version = client_version
        self._socket_factory = socket_factory
        self._socket: Any | None = None
        self._sequence = 0
        self.stream_info: StreamInfoResponse | None = None

    def __enter__(self) -> VtmStreamClient:
        """Open the TCP connection when used as a context manager."""

        return self.connect()

    def __exit__(self, *_exc_info: object) -> None:
        """Close the TCP connection when leaving a context manager."""

        self.close()

    @property
    def connected(self) -> bool:
        """Return True when a socket is currently attached."""

        return self._socket is not None

    def connect(self) -> VtmStreamClient:
        """Open the VTM TCP connection."""

        if self._socket is not None:
            return self
        host, port, _path, _params = parse_vtm_url(self.stream_url)
        sock = self._socket_factory((host, port), self.timeout)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        self._socket = sock
        return self

    def close(self) -> None:
        """Close the VTM TCP connection."""

        sock = self._socket
        self._socket = None
        if sock is not None:
            sock.close()

    def send_packet(
        self,
        body: bytes,
        *,
        channel: int = VtmChannel.MESSAGE,
        message_code: int = VtmMessageCode.STREAMINFO_REQ,
    ) -> int:
        """Send a VTM packet and return the sequence number used."""

        sock = self._require_socket()
        sequence = self._sequence
        packet = encode_vtm_packet(
            body,
            channel=channel,
            message_code=message_code,
            sequence=sequence,
        )
        sock.sendall(packet)
        self._sequence = (self._sequence + 1) & 0xFFFF
        return sequence

    def read_packet(self) -> VtmPacket:
        """Read one complete VTM packet from the TCP stream."""

        header = decode_vtm_header(self._recv_exact(VTM_HEADER_SIZE))
        body = self._recv_exact(header.length)
        return VtmPacket(
            channel=header.channel,
            length=header.length,
            sequence=header.sequence,
            message_code=header.message_code,
            body=body,
        )

    def start(
        self,
        *,
        vtm_stream_key: str | None = None,
        max_control_packets: int = 20,
        max_redirects: int = 3,
    ) -> StreamInfoResponse:
        """Request stream info and return the decoded ``StreamInfoRsp``."""

        redirect_count = 0
        while True:
            self.connect()
            request = build_stream_info_request(
                self.stream_url,
                vtm_stream_key=vtm_stream_key,
                client_version=self.client_version,
            )
            self.send_packet(request)

            for _ in range(max_control_packets):
                packet = self.read_packet()
                if packet.message_code == VtmMessageCode.STREAMINFO_RSP:
                    self.stream_info = parse_stream_info_response(packet.body)
                    redirect_url = self.stream_info.streamurl
                    redirect_key = self.stream_info.vtmstreamkey
                    if (
                        self.stream_info.result
                        and redirect_url
                        and redirect_key
                        and redirect_count < max_redirects
                    ):
                        self.close()
                        self.stream_url = redirect_url
                        vtm_stream_key = redirect_key
                        redirect_count += 1
                        break
                    return self.stream_info
            else:
                raise PyEzvizError("Timed out waiting for VTM stream info response")

    def send_keepalive(
        self,
        stream_ssn: str | None = None,
        *,
        message_code: int = VtmMessageCode.KEEPALIVE_REQ,
    ) -> int:
        """Send a VTM stream keepalive request."""

        stream_ssn = stream_ssn or (
            self.stream_info.streamssn if self.stream_info is not None else None
        )
        if not stream_ssn:
            raise PyEzvizError("Cannot send keepalive without a stream session")
        return self.send_packet(
            build_stream_keepalive_request(stream_ssn),
            message_code=message_code,
        )

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        include_control: bool = False,
        keepalive_interval: float | None = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[VtmPacket]:
        """Yield stream packets from the VTM connection.

        Control packets are normally handled internally. Set ``include_control``
        to surface them to callers while still iterating over the same TCP feed.
        """

        seen = 0
        last_keepalive = monotonic()
        while max_packets is None or seen < max_packets:
            if (
                keepalive_interval is not None
                and self.stream_info is not None
                and self.stream_info.streamssn
                and monotonic() - last_keepalive >= keepalive_interval
            ):
                self.send_keepalive()
                last_keepalive = monotonic()

            packet = self.read_packet()
            if packet.message_code == VtmMessageCode.KEEPALIVE_REQ:
                self.send_keepalive(message_code=VtmMessageCode.KEEPALIVE_RSP)
                last_keepalive = monotonic()
                if include_control:
                    seen += 1
                    yield packet
                continue

            if packet.channel in (VtmChannel.STREAM, VtmChannel.ENCRYPTED_STREAM):
                seen += 1
                yield packet
                continue

            if include_control:
                seen += 1
                yield packet

    def iter_payloads(self, *, max_packets: int | None = None) -> Iterator[bytes]:
        """Yield stream packet bodies from the VTM connection."""

        for packet in self.iter_packets(max_packets=max_packets):
            yield packet.body

    def trace_packets(
        self,
        *,
        max_packets: int = 20,
        vtm_stream_key: str | None = None,
        max_redirects: int = 3,
    ) -> list[VtmTraceEvent]:
        """Return sanitized packet summaries from the VTM connection.

        The trace opens the connection, sends ``StreamInfoReq``, records packet
        metadata only, parses ``StreamInfoRsp`` when seen, and auto-responds to
        keepalive requests so the server continues sending packets. Packet
        bodies are intentionally not included because they may contain tokens,
        keys, or encrypted media.
        """

        if max_packets < 1:
            raise PyEzvizError("VTM trace must request at least one packet")

        events: list[VtmTraceEvent] = []
        redirect_count = 0
        while len(events) < max_packets:
            self.connect()
            request = build_stream_info_request(
                self.stream_url,
                vtm_stream_key=vtm_stream_key,
                client_version=self.client_version,
            )
            self.send_packet(request)

            redirected = False
            while len(events) < max_packets:
                packet = self.read_packet()
                events.append(summarize_vtm_packet(packet, index=len(events)))

                if packet.message_code == VtmMessageCode.STREAMINFO_RSP:
                    self.stream_info = parse_stream_info_response(packet.body)
                    redirect_url = self.stream_info.streamurl
                    redirect_key = self.stream_info.vtmstreamkey
                    if (
                        self.stream_info.result
                        and redirect_url
                        and redirect_key
                        and redirect_count < max_redirects
                        and len(events) < max_packets
                    ):
                        self.close()
                        self.stream_url = redirect_url
                        vtm_stream_key = redirect_key
                        redirect_count += 1
                        redirected = True
                        break
                elif packet.message_code == VtmMessageCode.KEEPALIVE_REQ:
                    self.send_packet(
                        packet.body,
                        message_code=VtmMessageCode.KEEPALIVE_RSP,
                    )

            if not redirected:
                break
        return events

    def _require_socket(self) -> Any:
        sock = self._socket
        if sock is None:
            raise PyEzvizError("VTM socket is not connected")
        return sock

    def _recv_exact(self, length: int) -> bytes:
        sock = self._require_socket()
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise PyEzvizError("VTM socket closed while reading packet")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def encode_vtm_packet(
    body: bytes,
    *,
    channel: int = VtmChannel.MESSAGE,
    message_code: int = VtmMessageCode.STREAMINFO_REQ,
    sequence: int = 0,
) -> bytes:
    """Encode a VTM/VTDU packet using the 8-byte header."""

    if len(body) > 0xFFFF:
        raise PyEzvizError("VTM packet body is too large")
    header = bytes(
        (
            VTM_MAGIC,
            int(channel) & 0xFF,
            *len(body).to_bytes(2, "big"),
            *(sequence & 0xFFFF).to_bytes(2, "big"),
            *int(message_code).to_bytes(2, "big"),
        )
    )
    return header + body


def decode_vtm_header(header: bytes) -> VtmPacket:
    """Decode an 8-byte VTM/VTDU packet header."""

    if len(header) != VTM_HEADER_SIZE:
        raise PyEzvizError("VTM header must be exactly 8 bytes")
    if header[0] != VTM_MAGIC:
        raise PyEzvizError("VTM magic byte not found")

    channel = header[1]
    if channel not in {int(item) for item in VtmChannel}:
        raise PyEzvizError(f"Unknown VTM channel: 0x{channel:02x}")

    return VtmPacket(
        channel=channel,
        length=int.from_bytes(header[2:4], "big"),
        sequence=int.from_bytes(header[4:6], "big"),
        message_code=int.from_bytes(header[6:8], "big"),
    )


def decode_vtm_packet(packet: bytes) -> VtmPacket:
    """Decode a complete VTM/VTDU packet."""

    header = decode_vtm_header(packet[:VTM_HEADER_SIZE])
    body = packet[VTM_HEADER_SIZE:]
    if len(body) != header.length:
        raise PyEzvizError(
            f"VTM packet length mismatch: header={header.length} body={len(body)}"
        )
    return VtmPacket(
        channel=header.channel,
        length=header.length,
        sequence=header.sequence,
        message_code=header.message_code,
        body=body,
    )


def summarize_vtm_packet(packet: VtmPacket, *, index: int = 0) -> VtmTraceEvent:
    """Build a body-free packet summary for debugging live VTM streams."""

    transport = StreamTransport.UNKNOWN
    if packet.channel == VtmChannel.STREAM:
        transport = detect_transport(packet.body)

    return VtmTraceEvent(
        index=index,
        channel=packet.channel,
        channel_name=_enum_name(VtmChannel, packet.channel),
        length=packet.length,
        sequence=packet.sequence,
        message_code=packet.message_code,
        message_name=_enum_name(VtmMessageCode, packet.message_code),
        encrypted=packet.encrypted,
        transport=transport.name,
    )


def build_vtm_url(
    host: str,
    port: int,
    serial: str,
    stream_biz_url: str,
    vtdu_token: str,
    *,
    channel: int = 1,
    client_type: int = 9,
    timestamp_ms: int | None = None,
) -> str:
    """Build the ysproto live URL used for the VTM stream-info request."""

    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    biz = _parse_stream_biz_params(stream_biz_url)
    params = {
        **biz,
        "dev": serial,
        "chn": str(channel),
        "stream": "1",
        "cln": str(client_type),
        "isp": "0",
        "auth": "1",
        "ssn": vtdu_token,
        "vip": "0",
        "timestamp": str(timestamp_ms),
    }
    return f"ysproto://{_format_url_host(host)}:{port}/live?{urlencode(params)}"


def parse_vtm_url(url: str) -> tuple[str, int, str, dict[str, str]]:
    """Parse a ysproto URL into host, port, path, and query parameters."""

    try:
        parsed = urlparse(url)
    except ValueError as err:
        raise PyEzvizError("Invalid VTM URL host or port") from err
    if parsed.scheme != "ysproto":
        raise PyEzvizError("Invalid VTM URL scheme")
    try:
        port = parsed.port
    except ValueError as err:
        raise PyEzvizError("Invalid VTM URL host or port") from err
    if not parsed.hostname or port is None:
        raise PyEzvizError("Invalid VTM URL host or port")
    return (
        parsed.hostname,
        port,
        parsed.path,
        dict(parse_qsl(parsed.query, keep_blank_values=True)),
    )


def build_stream_info_request(
    stream_url: str,
    *,
    vtm_stream_key: str | None = None,
    client_version: str = "v3.6.3.20221124",
) -> bytes:
    """Encode the limited StreamInfoReq protobuf used by VTM/VTDU."""

    parts = [_proto_string(1, stream_url)]
    if vtm_stream_key:
        parts.append(_proto_string(2, vtm_stream_key))
    parts.extend(
        (
            _proto_string(3, client_version),
            _proto_varint(4, 0),
            _proto_string(6, client_version),
        )
    )
    return b"".join(parts)


def build_stream_keepalive_request(stream_ssn: str) -> bytes:
    """Encode the limited StreamKeepAliveReq protobuf."""

    return _proto_bytes(1, stream_ssn.encode())


def build_get_vtdu_info_request(
    serial: str,
    vtdu_token: str,
    *,
    channel: int = 1,
    stream_type: int = 1,
    business_type: int = 0,
    client_isp_type: int = 0,
    is_proxy: bool = False,
) -> bytes:
    """Encode the native GetVtduInfoReq protobuf."""

    return b"".join(
        (
            _proto_string(1, serial),
            _proto_varint(2, channel),
            _proto_varint(3, stream_type),
            _proto_varint(4, client_isp_type),
            _proto_varint(5, business_type),
            _proto_string(6, vtdu_token),
            _proto_varint(7, int(is_proxy)),
        )
    )


def build_start_stream_request(
    serial: str,
    vtdu_token: str,
    stream_key: str,
    *,
    channel: int = 1,
    stream_type: int = 1,
    business_type: int = 0,
    client_type: int = 9,
    peer_host: str | None = None,
    peer_port: int | None = None,
) -> bytes:
    """Encode the native StartStreamReq protobuf."""

    parts = [
        _proto_string(1, serial),
        _proto_varint(2, channel),
        _proto_varint(3, stream_type),
        _proto_varint(4, business_type),
        _proto_string(5, vtdu_token),
        _proto_varint(6, client_type),
        _proto_string(7, stream_key),
    ]
    if peer_host:
        parts.append(_proto_string(8, peer_host))
    if peer_port is not None:
        parts.append(_proto_varint(9, peer_port))
    return b"".join(parts)


def build_peer_stream_request(
    serial: str,
    vtdu_token: str,
    *,
    channel: int = 1,
    stream_type: int = 1,
    business_type: int = 0,
) -> bytes:
    """Encode the native PeerStreamReq protobuf."""

    return b"".join(
        (
            _proto_string(1, serial),
            _proto_varint(2, channel),
            _proto_varint(3, stream_type),
            _proto_varint(4, business_type),
            _proto_string(5, vtdu_token),
        )
    )


def build_stop_stream_request(stream_ssn: str, *, ssn_info: str | None = None) -> bytes:
    """Encode the native StopStreamReq protobuf."""

    parts = [_proto_string(1, stream_ssn)]
    if ssn_info:
        parts.append(_proto_string(2, ssn_info))
    return b"".join(parts)


def parse_stream_info_response(data: bytes) -> StreamInfoResponse:
    """Decode known scalar fields from a StreamInfoRsp protobuf body."""

    fields = _read_proto_fields(data, "StreamInfoRsp")

    return StreamInfoResponse(
        result=_proto_last_int(fields, 1),
        datakey=_proto_last_int(fields, 2),
        streamhead=_proto_last_str(fields, 3),
        streamssn=_proto_last_str(fields, 4),
        vtmstreamkey=_proto_last_str(fields, 5),
        serverinfo=_proto_last_str(fields, 6),
        streamurl=_proto_last_str(fields, 7),
        srvinfo=_proto_last_str(fields, 8),
        aesmd5=_proto_last_str(fields, 9),
        udptransinfo=_proto_last_str(fields, 10),
        peerpbkey=_proto_last_str(fields, 11),
        pdslist=tuple(_proto_bytes_values(fields, 12)),
        srvipv6_addr=_proto_last_str(fields, 13),
    )


def parse_get_vtdu_info_response(data: bytes) -> VtduInfoResponse:
    """Decode known scalar fields from a GetVtduInfoRsp protobuf body."""

    fields = _read_proto_fields(data, "GetVtduInfoRsp")
    return VtduInfoResponse(
        result=_proto_last_int(fields, 1),
        host=_proto_last_str(fields, 2),
        port=_proto_last_int(fields, 3),
        streamkey=_proto_last_str(fields, 4),
        peerhost=_proto_last_str(fields, 5),
        peerport=_proto_last_int(fields, 6),
        srvinfo=_proto_last_str(fields, 7),
    )


def parse_start_stream_response(data: bytes) -> VtduStreamResponse:
    """Decode known scalar fields from a StartStreamRsp protobuf body."""

    return _parse_vtdu_stream_response(data, "StartStreamRsp")


def parse_peer_stream_response(data: bytes) -> VtduStreamResponse:
    """Decode known scalar fields from a PeerStreamRsp protobuf body."""

    return _parse_vtdu_stream_response(data, "PeerStreamRsp")


def parse_stop_stream_response(data: bytes) -> StopStreamResponse:
    """Decode known scalar fields from a StopStreamRsp protobuf body."""

    fields = _read_proto_fields(data, "StopStreamRsp")
    return StopStreamResponse(result=_proto_last_int(fields, 1))


def detect_transport(data: bytes) -> StreamTransport:
    """Best-effort detection of stream payload transport."""

    if len(data) >= len(MPEG_PS_START_CODE) and data[:4] == MPEG_PS_START_CODE:
        return StreamTransport.MPEG_PS
    if data[:1] == MPEG_TS_SYNC_BYTE:
        return StreamTransport.MPEG_TS
    if data and data[0] >> 6 == 2:
        return StreamTransport.RTP
    return StreamTransport.UNKNOWN


def _video_pes_payload_ranges(data: bytes) -> list[tuple[int, int]]:
    """Return payload byte ranges for MPEG-PS video PES packets."""

    ranges: list[tuple[int, int]] = []
    i = 0
    while i < len(data) - 9:
        if data[i : i + 3] != MPEG_START_CODE_PREFIX:
            i += 1
            continue

        stream_id = data[i + 3]
        if not _is_video_pes_stream_id(stream_id):
            i += 4
            continue

        pes_length = int.from_bytes(data[i + 4 : i + 6], "big")

        payload_start = _pes_payload_start(data, i)
        if payload_start is None:
            break

        packet_end = (
            i + 6 + pes_length
            if pes_length
            else _next_unbounded_video_pes_boundary(data, payload_start) or len(data)
        )
        if packet_end > len(data):
            break

        if payload_start < packet_end:
            ranges.append((payload_start, packet_end))
        i = max(i + 4, packet_end)
    return ranges


@dataclass(frozen=True)
class _MpegPsPacketRange:
    """Parsed MPEG-PS packet bounds."""

    start: int
    end: int
    stream_id: int


def mpeg_ps_complete_prefix_length(data: bytes | bytearray) -> int:
    """Return the length of the fully parsed MPEG-PS packet prefix."""

    ranges = _mpeg_ps_complete_packet_ranges(data)
    return ranges[-1].end if ranges else 0


def mpeg_ps_decryptable_prefix_length(data: bytes | bytearray) -> int:
    """Return complete MPEG-PS bytes that are safe to decrypt independently.

    A video NAL can continue across adjacent video PES packets. Keep any trailing
    video PES run buffered until a following non-video packet or stream end lets
    the decryptor see the full run in one call.
    """

    ranges = _mpeg_ps_complete_packet_ranges(data)
    if not ranges:
        return 0

    decryptable_end = ranges[-1].end
    trailing_video_start = decryptable_end
    for packet_range in reversed(ranges):
        if not _is_video_pes_stream_id(packet_range.stream_id):
            break
        trailing_video_start = packet_range.start
    return trailing_video_start if trailing_video_start != decryptable_end else decryptable_end


def _mpeg_ps_complete_packet_ranges(
    data: bytes | bytearray,
) -> list[_MpegPsPacketRange]:
    """Return fully parsed MPEG-PS packet ranges from the start of ``data``."""

    view = bytes(data)
    ranges: list[_MpegPsPacketRange] = []
    i = 0
    while i < len(view):
        packet_end = _mpeg_ps_packet_end(view, i)
        if packet_end is not None:
            ranges.append(_MpegPsPacketRange(i, packet_end, view[i + 3]))
            i = packet_end
            continue

        if (
            i + 9 <= len(view)
            and view[i : i + 3] == MPEG_START_CODE_PREFIX
            and 0xC0 <= view[i + 3] <= 0xEF
            and int.from_bytes(view[i + 4 : i + 6], "big") == 0
        ):
            payload_start = _pes_payload_start(view, i)
            if payload_start is None:
                break
            next_start = _next_complete_mpeg_ps_packet_start(view, payload_start)
            if next_start is None:
                break
            ranges.append(_MpegPsPacketRange(i, next_start, view[i + 3]))
            i = next_start
            continue

        break
    return ranges


def _mpeg_ps_packet_end(data: bytes, start: int) -> int | None:
    """Return the end offset for a complete MPEG-PS packet at ``start``."""

    packet_end = None
    if start + 4 <= len(data) and data[start : start + 3] == MPEG_START_CODE_PREFIX:
        stream_id = data[start + 3]
        if (
            stream_id == _PACK_HEADER_STREAM_ID
            and start + 14 <= len(data)
            and _is_mpeg2_pack_header(data, start)
        ):
            stuffing_length = data[start + 13] & 0x07
            candidate_end = start + 14 + stuffing_length
            if candidate_end <= len(data):
                packet_end = candidate_end
        elif _is_mpeg_ps_packet_start_id(stream_id) and start + 6 <= len(data):
            packet_length = int.from_bytes(data[start + 4 : start + 6], "big")
            candidate_end = start + 6 + packet_length
            if packet_length and candidate_end <= len(data):
                payload_start = (
                    _pes_payload_start(data, start)
                    if 0xC0 <= stream_id <= 0xEF or stream_id == _PRIVATE_STREAM_1_ID
                    else start + 6
                )
                if payload_start is not None and payload_start <= candidate_end:
                    packet_end = candidate_end
    return packet_end


def _is_mpeg2_pack_header(data: bytes, start: int) -> bool:
    """Return True when ``start`` has MPEG-2 pack-header marker bits."""

    return (
        (data[start + 4] & 0xC4) == 0x44
        and (data[start + 6] & 0x04) == 0x04
        and (data[start + 8] & 0x04) == 0x04
        and (data[start + 12] & 0x01) == 0x01
        and (data[start + 13] & 0xF8) == 0xF8
    )


def _pes_payload_start(data: bytes, packet_start: int) -> int | None:
    """Return the payload start for a complete-enough PES header."""

    if packet_start + 9 > len(data):
        return None
    stream_id = data[packet_start + 3]
    flags = data[packet_start + 6]
    if (flags & 0xC0) == 0x80:
        return packet_start + 9 + data[packet_start + 8]
    if 0xC0 <= stream_id <= 0xEF or stream_id == _PRIVATE_STREAM_1_ID:
        return None
    return packet_start + 6


def _next_complete_mpeg_ps_packet_start(data: bytes, start: int) -> int | None:
    """Return the next start code that parses as a complete MPEG-PS packet."""

    i = start
    while i < len(data) - 3:
        if _mpeg_ps_packet_end(data, i) is not None:
            return i
        i += 1
    return None


def _next_unbounded_video_pes_boundary(data: bytes, start: int) -> int | None:
    """Return the next packet boundary after a zero-length video PES payload."""

    i = start
    while i < len(data) - 3:
        if _mpeg_ps_packet_end(data, i) is not None or _is_zero_length_video_pes_start(
            data,
            i,
        ):
            return i
        i += 1
    return None


def _is_zero_length_video_pes_start(data: bytes, start: int) -> bool:
    """Return True for a complete-enough zero-length video PES header."""

    return (
        start + 9 <= len(data)
        and data[start : start + 3] == MPEG_START_CODE_PREFIX
        and _is_video_pes_stream_id(data[start + 3])
        and int.from_bytes(data[start + 4 : start + 6], "big") == 0
        and _pes_payload_start(data, start) is not None
    )


def _is_video_pes_stream_id(stream_id: int) -> bool:
    """Return True for MPEG-PS video PES stream IDs."""

    return 0xE0 <= stream_id <= 0xEF


def _is_mpeg_ps_packet_start_id(stream_id: int) -> bool:
    """Return True for MPEG-PS packet start codes, excluding Annex B NAL IDs."""

    return (
        stream_id
        in {
            _PACK_HEADER_STREAM_ID,
            _SYSTEM_HEADER_STREAM_ID,
            _PROGRAM_STREAM_MAP_ID,
            _PRIVATE_STREAM_1_ID,
            _PADDING_STREAM_ID,
            _PRIVATE_STREAM_2_ID,
        }
        or 0xC0 <= stream_id <= 0xEF
    )


def _next_mpeg_ps_packet_start(data: bytes, start: int) -> int | None:
    """Return the next plausible MPEG-PS packet start code at or after ``start``."""

    i = start
    while i < len(data) - 3:
        if data[i : i + 3] == MPEG_START_CODE_PREFIX and _is_mpeg_ps_packet_start_id(
            data[i + 3]
        ):
            return i
        i += 1
    return None


def _find_nal_start_codes(
    data: bytes, start: int, end: int
) -> list[tuple[int, int]]:
    """Find Annex B NAL start codes in ``data[start:end]``."""

    positions: list[tuple[int, int]] = []
    i = start
    while i < end - 3:
        if data[i : i + 4] == ANNEX_B_LONG_START_CODE:
            positions.append((i, 4))
            i += 4
        elif data[i : i + 3] == MPEG_START_CODE_PREFIX:
            positions.append((i, 3))
            i += 3
        else:
            i += 1
    return positions


def _hevc_nal_type(data: bytes, start_code_pos: int, start_code_len: int) -> int | None:
    """Return the HEVC NAL unit type after an Annex B start code."""

    header_pos = start_code_pos + start_code_len
    if header_pos + 1 >= len(data):
        return None
    return (data[header_pos] >> 1) & 0x3F


def _h264_nal_type(data: bytes, start_code_pos: int, start_code_len: int) -> int | None:
    """Return the H.264 NAL unit type after an Annex B start code."""

    header_pos = start_code_pos + start_code_len
    if header_pos >= len(data):
        return None
    return data[header_pos] & 0x1F


def _find_hevc_nal_start_codes(
    data: bytes, start: int, end: int
) -> list[tuple[int, int]]:
    """Find plausible HEVC Annex B NAL start codes.

    Encrypted NAL payloads can contain accidental ``00 00 01`` byte sequences.
    Treating those ciphertext bytes as real NAL boundaries shifts AES block
    alignment and corrupts the decrypted frame.
    """

    return [
        (pos, length)
        for pos, length in _find_nal_start_codes(data, start, end)
        if (nal_type := _hevc_nal_type(data, pos, length)) is not None
        and nal_type <= 40
    ]


def _find_h264_nal_start_codes(
    data: bytes, start: int, end: int
) -> list[tuple[int, int]]:
    """Find plausible H.264 Annex B NAL start codes."""

    return [
        (pos, length)
        for pos, length in _find_nal_start_codes(data, start, end)
        if (nal_type := _h264_nal_type(data, pos, length)) is not None
        and 1 <= nal_type <= 23
    ]


def decrypt_hikvision_ps_video(  # noqa: PLR0915
    data: bytes,
    key: str | bytes,
    *,
    nalu_header_size: int = 2,
) -> bytes:
    """Decrypt Hikvision/EZVIZ encrypted MPEG-PS video NAL payloads.

    EZVIZ battery-camera VTM streams keep MPEG-PS/PES and Annex B NAL framing
    clear, but encrypt the video NAL body after the codec NAL header. The mobile
    SDK's native transform layer accepts the camera encrypt key as AES material;
    observed HEVC streams decrypt the first encrypted prefix of each NAL body
    with AES-ECB, key zero-padded/truncated to 16 bytes, while preserving the
    two-byte HEVC NAL header.
    """

    if nalu_header_size < 0:
        raise ValueError("nalu_header_size must be non-negative")

    key_bytes = key.encode() if isinstance(key, str) else key
    aes_key = key_bytes.ljust(16, b"\0")[:16]
    output = bytearray(data)
    pending_block_positions: list[int] = []
    pending_block = bytearray()
    active_nal = False
    active_nal_decrypted = active_nal_body_start = 0
    find_nal_start_codes = (
        _find_nal_start_codes
        if nalu_header_size == 0
        else _find_h264_nal_start_codes
        if nalu_header_size == 1
        else _find_hevc_nal_start_codes
    )

    def reset_nal_state() -> None:
        nonlocal active_nal, active_nal_body_start, active_nal_decrypted
        pending_block_positions.clear()
        pending_block.clear()
        active_nal = False
        active_nal_decrypted = active_nal_body_start = 0

    def decrypt_nal_body_segment(start: int, end: int) -> None:
        nonlocal active_nal_decrypted
        if end <= start:
            return
        remaining = HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH - active_nal_decrypted
        if remaining <= 0:
            return
        decrypt_end = min(end, start + remaining)
        for pos in range(start, decrypt_end):
            pending_block_positions.append(pos)
            pending_block.append(output[pos])
            active_nal_decrypted += 1
            if len(pending_block) != AES.block_size:
                continue
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(AES.block_size))
            decrypted = cipher.decrypt(bytes(pending_block))
            for block_pos, decrypted_byte in zip(
                pending_block_positions,
                decrypted,
                strict=True,
            ):
                output[block_pos] = decrypted_byte
            pending_block_positions.clear()
            pending_block.clear()

    def starts_plausible_encrypted_h264_nal(start: int, end: int) -> bool:
        if end - start < AES.block_size:
            return False
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(AES.block_size))
        decrypted_header = cipher.decrypt(bytes(output[start : start + AES.block_size]))[0]
        nal_type = decrypted_header & 0x1F
        return 1 <= nal_type <= 23

    for payload_start, payload_end in _video_pes_payload_ranges(data):
        nal_starts = find_nal_start_codes(data, payload_start, payload_end)
        segment_start = payload_start
        if not nal_starts:
            if active_nal:
                decrypt_nal_body_segment(payload_start, payload_end)
            continue

        for idx, (start_code_pos, start_code_len) in enumerate(nal_starts):
            decrypt_end = (
                nal_starts[idx + 1][0]
                if idx + 1 < len(nal_starts)
                else payload_end
            )
            if (
                active_nal
                and nalu_header_size == 0
                and (
                    candidate_decrypted := active_nal_decrypted
                    + max(0, start_code_pos - segment_start)
                )
                < HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
                and (
                    candidate_decrypted == 0
                    or not starts_plausible_encrypted_h264_nal(
                        start_code_pos + start_code_len,
                        decrypt_end,
                    )
                )
            ):
                continue
            if (
                active_nal
                and active_nal_decrypted >= HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
                and start_code_pos
                > active_nal_body_start + HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
            ):
                continue
            if active_nal and segment_start < start_code_pos:
                decrypt_nal_body_segment(segment_start, start_code_pos)
            reset_nal_state()
            active_nal = True
            decrypt_start = start_code_pos + start_code_len + nalu_header_size
            active_nal_body_start = decrypt_start
            decrypt_nal_body_segment(decrypt_start, decrypt_end)
            segment_start = decrypt_end
        if active_nal and segment_start < payload_end:
            decrypt_nal_body_segment(segment_start, payload_end)

    return bytes(output)


def download_ezviz_cloud_replay(  # noqa: PLR0913
    *,
    stream_url: str,
    ticket: str,
    serial: str,
    channel: int,
    seq_id: str | int,
    begin_cas: str,
    end_cas: str,
    storage_version: int = 2,
    video_type: int = 2,
    file_size: int | None = None,
    timeout: float = 30.0,
) -> bytes:
    """Download encrypted cloud replay bytes from the EZVIZ cloud replay server.

    This reproduces the native ``EZStreamClient.startDownloadFromCloud`` wire
    path for regular cloud-storage clips. The returned bytes are still the
    encrypted MPEG-PS ``.tmp`` payload and should be passed through
    :func:`decrypt_hikvision_ps_video` with the camera verification key.
    """

    host, port = _parse_cloud_replay_stream_url(stream_url)
    request_xml = _build_cloud_replay_open_xml(
        ticket=ticket,
        serial=serial,
        channel=channel,
        seq_id=seq_id,
        begin_cas=begin_cas,
        end_cas=end_cas,
        storage_version=storage_version,
        video_type=video_type,
    )

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    output = bytearray()
    buffer = b""
    sequence = 1
    last_heartbeat = time.monotonic()

    with (
        socket.create_connection((host, port), timeout=timeout) as raw_socket,
        context.wrap_socket(raw_socket, server_hostname=host) as tls_socket,
    ):
            tls_socket.settimeout(timeout)
            tls_socket.sendall(
                _cloud_replay_frame(
                    request_xml,
                    sequence=sequence,
                    command=CLOUD_REPLAY_OPEN_CMD,
                )
            )
            sequence += 1

            while True:
                message, buffer = _read_cloud_replay_message(tls_socket, buffer)
                if not message.md5_ok:
                    raise PyEzvizError("Cloud replay packet failed MD5 validation")
                if message.result not in (None, 0):
                    raise PyEzvizError(f"Cloud replay returned error result {message.result}")
                if message.err_code not in (None, 0):
                    raise PyEzvizError(f"Cloud replay returned packet error {message.err_code}")

                if message.data_type in (0, 1, 2) and message.data:
                    output.extend(message.data)
                    if file_size is not None and len(output) >= file_size:
                        return bytes(output[:file_size])
                elif message.data_type == 100:
                    if file_size is not None and len(output) < file_size:
                        raise PyEzvizError(
                            "Cloud replay ended before expected file size: "
                            f"{len(output)}/{file_size} bytes"
                        )
                    return bytes(output)

                if time.monotonic() - last_heartbeat >= 5:
                    tls_socket.sendall(
                        _cloud_replay_frame(
                            _cloud_replay_heartbeat_xml(),
                            sequence=sequence,
                            command=CLOUD_REPLAY_HEARTBEAT_CMD,
                        )
                    )
                    sequence += 1
                    last_heartbeat = time.monotonic()


@dataclass(frozen=True)
class _CloudReplayMessage:
    xml: bytes
    data: bytes
    md5_ok: bool
    result: int | None = None
    err_code: int | None = None
    data_type: int | None = None


def _parse_cloud_replay_stream_url(stream_url: str) -> tuple[str, int]:
    host, sep, port_text = stream_url.partition(":")
    if not host or sep != ":":
        raise PyEzvizError(f"Invalid cloud replay streamUrl: {stream_url!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise PyEzvizError(f"Invalid cloud replay streamUrl port: {stream_url!r}") from exc
    return host, port


def _build_cloud_replay_open_xml(
    *,
    ticket: str,
    serial: str,
    channel: int,
    seq_id: str | int,
    begin_cas: str,
    end_cas: str,
    storage_version: int,
    video_type: int,
) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<Request>\n"
        "\t<Authorization></Authorization>\n"
        "\t<Session></Session>\n"
        f"\t<Token>{ticket}</Token>\n"
        "\t<FrontType>2</FrontType>\n"
        "\t<PlayType>2</PlayType>\n"
        "\t<BusType>2</BusType>\n"
        "\t<FileInfo>\n"
        "\t\t<FileType>1</FileType>\n"
        f'\t\t<File StorageVersion="{storage_version}" Id="{seq_id}" />\n'
        f"\t\t<VideoType>{video_type}</VideoType>\n"
        f'\t\t<Time Begin="{begin_cas}" End="{end_cas}" />\n'
        f'\t\t<CameraInfo SubSerial="{serial}_{channel}" ChannelNo="{channel}" />\n'
        "\t\t<InterlaceFlag>0</InterlaceFlag>\n"
        "\t</FileInfo>\n"
        "\t<ClientType>3</ClientType>\n"
        "\t<PlaySpeed>0</PlaySpeed>\n"
        "</Request>\n"
    ).encode()


def _cloud_replay_heartbeat_xml() -> bytes:
    return (
        b'<?xml version="1.0" encoding="utf-8"?>\n'
        b"<Response>\n"
        b"\t<Result>0</Result>\n"
        b"\t<Command>HB</Command>\n"
        b"</Response>\n"
    )


def _cloud_replay_frame(payload: bytes, *, sequence: int, command: int) -> bytes:
    header = struct.pack(
        ">IIIIIIII",
        CLOUD_REPLAY_MAGIC,
        1,
        sequence,
        0,
        command,
        0,
        len(payload),
        0,
    )
    return header + payload + _ezviz_md5_hex(payload).encode()


def _read_cloud_replay_message(
    tls_socket: ssl.SSLSocket,
    buffer: bytes,
) -> tuple[_CloudReplayMessage, bytes]:
    while XML_PREFIX not in buffer:
        buffer += _cloud_replay_recv(tls_socket)

    prefix = buffer.index(XML_PREFIX)
    if prefix:
        # Server packets carry the same 32-byte frame prefix used by the client.
        buffer = buffer[prefix:]

    while (match := _XML_END_RE.search(buffer)) is None:
        buffer += _cloud_replay_recv(tls_socket)

    xml_end = match.end()
    while len(buffer) < xml_end + 2:
        buffer += _cloud_replay_recv(tls_socket)

    body_end = xml_end + 2
    xml = buffer[:xml_end]
    length = _cloud_xml_int(xml, b"Length")
    if length is not None:
        while len(buffer) < body_end + length + 32:
            buffer += _cloud_replay_recv(tls_socket)
        data = buffer[body_end : body_end + length]
        body = buffer[: body_end + length]
        digest = buffer[body_end + length : body_end + length + 32]
        rest = buffer[body_end + length + 32 :]
    else:
        while len(buffer) < body_end + 32:
            buffer += _cloud_replay_recv(tls_socket)
        data = b""
        body = buffer[:body_end]
        digest = buffer[body_end : body_end + 32]
        rest = buffer[body_end + 32 :]

    return (
        _CloudReplayMessage(
            xml=xml,
            data=data,
            md5_ok=_ezviz_md5_hex(body).encode() == digest,
            result=_cloud_xml_int(xml, b"Result"),
            err_code=_cloud_xml_attr_int(xml, b"Type", b"ErrCode"),
            data_type=_cloud_xml_int(xml, b"Type"),
        ),
        rest,
    )


def _cloud_xml_int(xml: bytes, tag: bytes) -> int | None:
    match = re.search(rb"<" + tag + rb"(?: [^>]*)?>(-?\d+)</" + tag + rb">", xml)
    return int(match.group(1)) if match else None


def _cloud_replay_recv(tls_socket: ssl.SSLSocket) -> bytes:
    chunk = tls_socket.recv(8192)
    if not chunk:
        raise PyEzvizError("Cloud replay socket closed unexpectedly")
    return chunk


def _cloud_xml_attr_int(xml: bytes, tag: bytes, attr: bytes) -> int | None:
    match = re.search(rb"<" + tag + rb" [^>]*" + attr + rb'="(-?\d+)"', xml)
    return int(match.group(1)) if match else None


def rtp_payload(data: bytes) -> bytes:
    """Return the RTP payload after fixed, CSRC, extension, and padding headers."""

    if len(data) < 12:
        raise PyEzvizError("RTP packet is too short")
    if data[0] >> 6 != 2:
        raise PyEzvizError("Unsupported RTP version")

    has_padding = bool(data[0] & 0x20)
    has_extension = bool(data[0] & 0x10)
    csrc_count = data[0] & 0x0F
    offset = 12 + (csrc_count * 4)
    if len(data) < offset:
        raise PyEzvizError("RTP CSRC header exceeds packet length")

    if has_extension:
        if len(data) < offset + 4:
            raise PyEzvizError("RTP extension header exceeds packet length")
        extension_words = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4 + (extension_words * 4)
        if len(data) < offset:
            raise PyEzvizError("RTP extension payload exceeds packet length")

    payload = data[offset:]
    if has_padding:
        if not payload:
            raise PyEzvizError("RTP padding set without payload")
        padding_len = payload[-1]
        if padding_len == 0 or padding_len > len(payload):
            raise PyEzvizError("Invalid RTP padding length")
        payload = payload[:-padding_len]

    return payload


def _proto_key(field: int, wire_type: int) -> bytes:
    return _encode_varint((field << 3) | wire_type)


def _enum_name(enum_type: type[IntEnum], value: int) -> str | None:
    try:
        return enum_type(value).name
    except ValueError:
        return None


def _format_url_host(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host
    try:
        address = ip_address(host)
    except ValueError:
        return host
    if isinstance(address, IPv6Address):
        return f"[{host}]"
    return host


def _parse_stream_biz_params(stream_biz_url: str) -> dict[str, str]:
    parsed = urlparse(stream_biz_url)
    query = parsed.query or stream_biz_url.lstrip("?")
    return dict(parse_qsl(query, keep_blank_values=True))


def _proto_varint(field: int, value: int) -> bytes:
    return _proto_key(field, 0) + _encode_varint(value)


def _proto_bytes(field: int, value: bytes) -> bytes:
    return _proto_key(field, 2) + _encode_varint(len(value)) + value


def _proto_string(field: int, value: str) -> bytes:
    return _proto_bytes(field, value.encode())


ProtoValue = int | bytes


def _read_proto_fields(data: bytes, message_name: str) -> dict[int, list[ProtoValue]]:
    values: dict[int, list[ProtoValue]] = {}
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        field = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            values.setdefault(field, []).append(value)
            continue
        if wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > len(data):
                raise PyEzvizError(
                    f"{message_name} length-delimited field exceeds payload"
                )
            values.setdefault(field, []).append(data[pos : pos + length])
            pos += length
            continue
        raise PyEzvizError(f"Unsupported {message_name} wire type: {wire_type}")
    return values


def _proto_last_int(fields: dict[int, list[ProtoValue]], field: int) -> int | None:
    values = fields.get(field)
    if not values:
        return None
    value = values[-1]
    return value if isinstance(value, int) else None


def _proto_last_str(fields: dict[int, list[ProtoValue]], field: int) -> str | None:
    values = fields.get(field)
    if not values:
        return None
    value = values[-1]
    if isinstance(value, int):
        return None
    return value.decode("utf-8", errors="replace")


def _proto_bytes_values(fields: dict[int, list[ProtoValue]], field: int) -> list[bytes]:
    return [value for value in fields.get(field, []) if isinstance(value, bytes)]


def _parse_vtdu_stream_response(data: bytes, message_name: str) -> VtduStreamResponse:
    fields = _read_proto_fields(data, message_name)
    return VtduStreamResponse(
        result=_proto_last_int(fields, 1),
        streamhead=_proto_last_str(fields, 2),
        streamssn=_proto_last_str(fields, 3),
        datakey=_proto_last_int(fields, 4),
    )


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise PyEzvizError("Negative protobuf varints are not supported")
    out = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            return bytes(out)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift >= 64:
            break
    raise PyEzvizError("Malformed protobuf varint")


def _maybe_int(value: int | str | None) -> int | None:
    return value if isinstance(value, int) else None


def _maybe_str(value: int | str | None) -> str | None:
    return value if isinstance(value, str) else None
