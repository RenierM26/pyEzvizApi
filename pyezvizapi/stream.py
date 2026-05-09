"""Helpers for EZVIZ cloud stream discovery and VTM/VTDU framing."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv6Address, ip_address
import socket
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from .exceptions import PyEzvizError

VTM_MAGIC = 0x24
VTM_HEADER_SIZE = 8
MPEG_PS_START_CODE = b"\x00\x00\x01\xba"
MPEG_TS_SYNC_BYTE = b"\x47"


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
    ) -> StreamInfoResponse:
        """Request stream info and return the decoded ``StreamInfoRsp``."""

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
                return self.stream_info

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
    ) -> Iterator[VtmPacket]:
        """Yield stream packets from the VTM connection.

        Control packets are normally handled internally. Set ``include_control``
        to surface them to callers while still iterating over the same TCP feed.
        """

        seen = 0
        while max_packets is None or seen < max_packets:
            packet = self.read_packet()
            if packet.message_code == VtmMessageCode.KEEPALIVE_REQ:
                self.send_keepalive(message_code=VtmMessageCode.KEEPALIVE_RSP)
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
