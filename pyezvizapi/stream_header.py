"""Camera-supplied PlayM4 media headers, distinct from SDK configuration codes.

Field offsets and codec codes follow the native ST_MEDIA_INFO / IDMXRTPDemux
in EZVIZ Android 7.4.1 libSystemTransform. These describe a negotiated session,
not decoded media, encryption, or RTP payload assignments.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import struct
import xml.etree.ElementTree as ET

from .exceptions import PyEzvizError

_STREAM_HEADER_MAGIC = b"IMKH"

_VIDEO_CODECS = {
    1: "h264", 0x100: "h264", 2: "mpeg2video", 3: "mpeg4video",
    4: "mjpeg", 5: "hevc", 6: "svac",
}
_AUDIO_CODECS = {
    0x2000: "mp2", 0x2001: "aac", 0x2002: "aac-ld", 0x3002: "opus",
    0x7000: "pcm", 0x7001: "pcm", 0x7110: "pcm_mulaw",
    0x7111: "pcm_alaw", 0x7221: "g722",
}


@dataclass(frozen=True)
class EzvizStreamHeader:
    """Sanitized negotiated media fields; raw header/session keys excluded."""

    version: int
    system_format_code: int
    video_codec_code: int
    audio_codec_code: int
    video_codec: str | None
    audio_codec: str | None
    audio_channels: int | None
    audio_bits_per_sample: int | None
    audio_sample_rate: int | None
    audio_bitrate_bps: int | None


def parse_ezviz_stream_header(data: bytes) -> EzvizStreamHeader:
    """Parse the evidenced 40-byte IMKH v1.1 layout without guessing variants."""
    if len(data) != 40 or data[:4] != _STREAM_HEADER_MAGIC:
        raise PyEzvizError("Unsupported EZVIZ stream header layout")
    version, = struct.unpack_from("<I", data, 4)
    if version != 0x101:
        raise PyEzvizError("Unsupported EZVIZ stream header version")
    system, video, audio, channels, bits, rate, bitrate = struct.unpack_from(
        "<HHHBBII", data, 8
    )
    return EzvizStreamHeader(
        version=version, system_format_code=system, video_codec_code=video,
        audio_codec_code=audio, video_codec=_VIDEO_CODECS.get(video),
        audio_codec=_AUDIO_CODECS.get(audio), audio_channels=channels or None,
        audio_bits_per_sample=bits or None, audio_sample_rate=rate or None,
        audio_bitrate_bps=bitrate or None,
    )


def stream_header_from_preview(body: bytes) -> EzvizStreamHeader | None:
    """Read optional StreamHeader attributes from a local preview response.

    Base64Length counts encoded characters (56 for the 40-byte native header),
    not decoded bytes. Malformed/present data raises; absent data stays unknown.
    """
    try:
        root = ET.fromstring(body.rstrip(b"\0"))
        elements = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "StreamHeader"]
        if not elements:
            return None
        if len(elements) != 1:
            raise ValueError("Duplicate header")
        element = elements[0]
        encoded = element.attrib["Base64Data"]
        if len(encoded) != 56 or int(element.attrib["Base64Length"]) != len(encoded):
            raise ValueError("Invalid encoded length")
        data = base64.b64decode(encoded, validate=True)
    except (ET.ParseError, KeyError, ValueError, binascii.Error) as exc:
        raise PyEzvizError("Malformed EZVIZ preview stream header") from exc
    return parse_ezviz_stream_header(data)
