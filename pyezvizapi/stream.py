"""Helpers for EZVIZ cloud stream discovery and VTM/VTDU framing."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv6Address, ip_address
import time
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


def parse_stream_info_response(data: bytes) -> StreamInfoResponse:
    """Decode known scalar fields from a StreamInfoRsp protobuf body."""

    values: dict[int, int | str] = {}
    pos = 0
    while pos < len(data):
        key, pos = _read_varint(data, pos)
        field = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            values[field] = value
            continue
        if wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > len(data):
                raise PyEzvizError(
                    "StreamInfoRsp length-delimited field exceeds payload"
                )
            raw = data[pos : pos + length]
            pos += length
            if field != 12:
                values[field] = raw.decode("utf-8", errors="replace")
            continue
        raise PyEzvizError(f"Unsupported StreamInfoRsp wire type: {wire_type}")

    return StreamInfoResponse(
        result=_maybe_int(values.get(1)),
        datakey=_maybe_int(values.get(2)),
        streamhead=_maybe_str(values.get(3)),
        streamssn=_maybe_str(values.get(4)),
        vtmstreamkey=_maybe_str(values.get(5)),
        serverinfo=_maybe_str(values.get(6)),
        streamurl=_maybe_str(values.get(7)),
        srvinfo=_maybe_str(values.get(8)),
        aesmd5=_maybe_str(values.get(9)),
        udptransinfo=_maybe_str(values.get(10)),
        peerpbkey=_maybe_str(values.get(11)),
    )


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
