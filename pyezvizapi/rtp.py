"""Shared RTP parsing, media routing, and video depacketization."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal

from Crypto.Cipher import AES

from .exceptions import PyEzvizError, UnsupportedRtpVideoCodecError

ANNEX_B_START_CODE = b"\x00\x00\x00\x01"
MPEG_VIDEO_START_CODE_PREFIX = b"\x00\x00\x01"
DEFAULT_VIDEO_PAYLOAD_TYPES = frozenset({96})
KNOWN_VIDEO_PAYLOAD_TYPES = frozenset({26, 32, 96, 99})
KNOWN_AUDIO_PAYLOAD_TYPES = frozenset(
    {0, 4, 8, 11, 14, 18, 98, 100, 102, 103, 104, 115}
)
DEFAULT_AAC_PAYLOAD_TYPES = frozenset({104})
DEFAULT_METADATA_PAYLOAD_TYPES = frozenset({112})
IDMX_AAC_SAMPLES_PER_FRAME = 1024
IDMX_AAC_AUDIO_SPECIFIC_CONFIG_OBJECT_TYPE = 2
IDMX_AAC_ADTS_HEADER_SIZE = 7
IDMX_AAC_ADTS_MAX_FRAME_LENGTH = 0x1FFF
IDMX_AUDIO_EXTENSION_VERSION = b"\x00\x01"
IDMX_AAC_SAMPLE_RATES = (
    96_000,
    88_200,
    64_000,
    48_000,
    44_100,
    32_000,
    24_000,
    22_050,
    16_000,
    12_000,
    11_025,
    8_000,
    7_350,
)

RtpMediaKind = Literal["video", "audio", "metadata", "unknown"]
RtpVideoCodec = Literal["h264", "hevc"]
RtpCodec = Literal[
    "h264",
    "hevc",
    "mpeg2video",
    "mpeg4video",
    "mjpeg",
    "svac",
    "private-video",
    "mpeg-audio",
    "aac",
    "aac-ld",
    "pcm",
    "g711-alaw",
    "g711-mulaw",
    "g722",
    "g723",
    "g726",
    "g729",
    "opus",
]

# Extracted from the official EZVIZ Android app's
# rtp_pack_stream_type_to_codec_type() and CodecTypeToMediaType() mappings.
_IDMX_RTP_STREAM_TYPES: dict[int, tuple[RtpCodec, RtpMediaKind]] = {
    0x02: ("mpeg2video", "video"),
    0x03: ("mpeg-audio", "audio"),
    0x04: ("mpeg-audio", "audio"),
    0x0F: ("aac", "audio"),
    0x10: ("mpeg4video", "video"),
    0x1B: ("h264", "video"),
    0x24: ("hevc", "video"),
    0x80: ("svac", "video"),
    0x90: ("g711-alaw", "audio"),
    0x91: ("g711-mulaw", "audio"),
    0x92: ("g722", "audio"),
    0x93: ("g723", "audio"),
    0x96: ("g726", "audio"),
    0x98: ("g726", "audio"),
    0x99: ("g729", "audio"),
    0x9C: ("pcm", "audio"),
    0x9D: ("pcm", "audio"),
    0x9E: ("private-video", "video"),
    0xA6: ("aac-ld", "audio"),
    0xB0: ("h264", "video"),
    0xB1: ("mjpeg", "video"),
    0xB2: ("hevc", "video"),
}
_IDMX_STATIC_VIDEO_PAYLOAD_CODECS: dict[int, RtpCodec] = {
    26: "mjpeg",
    32: "mpeg2video",
    99: "svac",
}


@dataclass(frozen=True)
class RtpPacket:
    """One parsed RTP packet with its payload separated from framing."""

    payload: bytes
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    marker: bool
    extension_profile: int | None = None
    extension_data: bytes = b""


@dataclass
class RtpContinuityStats:
    """Observable discontinuities rejected by an RTP video depacketizer."""

    duplicates: int = 0
    sequence_conflicts: int = 0
    reordered: int = 0
    sequence_gaps: int = 0
    timestamp_changes: int = 0
    discarded_fragments: int = 0


@dataclass(frozen=True)
class RtpAacStream:
    """Decrypted RFC 3640 AAC access units framed as ADTS."""

    adts: bytes
    sample_rate: int
    channels: int
    frame_count: int


@dataclass(frozen=True)
class RtpStreamDescriptor:
    """Codec routing advertised by native IDMX RTP descriptor ``0x45``."""

    stream_type: int
    payload_type: int
    codec: RtpCodec
    media_kind: RtpMediaKind


@dataclass
class _FragmentedNal:
    data: bytearray
    last_sequence: int
    timestamp: int


def parse_rtp_packet(data: bytes) -> RtpPacket:
    """Parse an RTP v2 packet, including CSRC, extension, and padding fields."""

    if len(data) < 12:
        raise PyEzvizError("RTP packet is too short")
    if data[0] >> 6 != 2:
        raise PyEzvizError("Unsupported RTP version")

    has_padding = bool(data[0] & 0x20)
    has_extension = bool(data[0] & 0x10)
    offset = 12 + ((data[0] & 0x0F) * 4)
    if len(data) < offset:
        raise PyEzvizError("RTP CSRC header exceeds packet length")

    extension_profile: int | None = None
    extension_data = b""
    if has_extension:
        if len(data) < offset + 4:
            raise PyEzvizError("RTP extension header exceeds packet length")
        extension_profile = int.from_bytes(data[offset : offset + 2], "big")
        extension_length = int.from_bytes(data[offset + 2 : offset + 4], "big") * 4
        extension_start = offset + 4
        offset = extension_start + extension_length
        if len(data) < offset:
            raise PyEzvizError("RTP extension payload exceeds packet length")
        extension_data = data[extension_start:offset]

    payload = data[offset:]
    if has_padding:
        if not payload:
            raise PyEzvizError("RTP padding set without payload")
        padding_length = payload[-1]
        if padding_length == 0 or padding_length > len(payload):
            raise PyEzvizError("Invalid RTP padding length")
        payload = payload[:-padding_length]

    return RtpPacket(
        payload=payload,
        payload_type=data[1] & 0x7F,
        sequence=int.from_bytes(data[2:4], "big"),
        timestamp=int.from_bytes(data[4:8], "big"),
        ssrc=int.from_bytes(data[8:12], "big"),
        marker=bool(data[1] & 0x80),
        extension_profile=extension_profile,
        extension_data=extension_data,
    )


def rtp_payload(data: bytes) -> bytes:
    """Return an RTP payload after all variable framing fields."""

    return parse_rtp_packet(data).payload


def rtp_media_kind(
    packet: RtpPacket,
    *,
    video_payload_types: frozenset[int] = KNOWN_VIDEO_PAYLOAD_TYPES,
    audio_payload_types: frozenset[int] = KNOWN_AUDIO_PAYLOAD_TYPES,
    metadata_payload_types: frozenset[int] = DEFAULT_METADATA_PAYLOAD_TYPES,
    stream_descriptors: Iterable[RtpStreamDescriptor] = (),
) -> RtpMediaKind:
    """Classify one RTP packet using the EZVIZ dynamic payload mapping."""

    for descriptor in stream_descriptors:
        if descriptor.payload_type == packet.payload_type:
            return descriptor.media_kind
    if packet.payload_type in video_payload_types:
        return "video"
    if packet.payload_type in audio_payload_types:
        return "audio"
    if packet.payload_type in metadata_payload_types:
        return "metadata"
    return "unknown"


def idmx_rtp_stream_descriptors(
    packets: Iterable[RtpPacket],
) -> tuple[RtpStreamDescriptor, ...]:
    """Return native IDMX codec routes from stream descriptor ``0x45``.

    The official app reads the stream type and RTP payload type from bytes two
    and three of this descriptor, then maps the stream type to a codec before
    inspecting media payloads. Unknown stream types are intentionally ignored.
    """

    descriptors: list[RtpStreamDescriptor] = []
    seen: set[RtpStreamDescriptor] = set()
    for packet in packets:
        data = packet.extension_data
        offset = 0
        while offset + 2 <= len(data):
            descriptor_length = data[offset + 1]
            descriptor_end = offset + descriptor_length + 2
            if descriptor_end > len(data):
                break
            if data[offset] == 0x45 and descriptor_length >= 2:
                stream_type = data[offset + 2]
                codec_info = _IDMX_RTP_STREAM_TYPES.get(stream_type)
                if codec_info is not None:
                    codec, media_kind = codec_info
                    descriptor = RtpStreamDescriptor(
                        stream_type=stream_type,
                        payload_type=data[offset + 3] & 0x7F,
                        codec=codec,
                        media_kind=media_kind,
                    )
                    if descriptor not in seen:
                        descriptors.append(descriptor)
                        seen.add(descriptor)
            offset = descriptor_end
    return tuple(descriptors)


def rtp_codec_payload_types(
    descriptors: Iterable[RtpStreamDescriptor],
    codec: RtpCodec,
    *,
    fallback_payload_types: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Return payload types for one codec with descriptor routes taking priority."""

    descriptor_tuple = tuple(descriptors)
    assigned_payload_types = frozenset(
        descriptor.payload_type for descriptor in descriptor_tuple
    )
    return (fallback_payload_types - assigned_payload_types) | frozenset(
        descriptor.payload_type
        for descriptor in descriptor_tuple
        if descriptor.codec == codec
    )


def idmx_aac_descriptor(packets: Iterable[RtpPacket]) -> tuple[int, int] | None:
    """Return authoritative sample-rate/channel metadata from descriptor ``0x43``."""

    for packet in packets:
        data = packet.extension_data
        offset = 0
        while offset + 2 <= len(data):
            descriptor_length = data[offset + 1]
            descriptor_end = offset + descriptor_length + 2
            if descriptor_end > len(data):
                break
            if data[offset] == 0x43 and descriptor_length >= 10:
                channels = (data[offset + 4] & 0x01) + 1
                sample_rate = (
                    (data[offset + 5] << 14)
                    | (data[offset + 6] << 6)
                    | (data[offset + 7] >> 2)
                )
                if sample_rate in IDMX_AAC_SAMPLE_RATES and channels in (1, 2):
                    return sample_rate, channels
            offset = descriptor_end
    return None


def _idmx_audio_extension_is_aac(packet: RtpPacket) -> bool:
    data = packet.extension_data
    return (
        packet.extension_profile == 0x4000
        and len(data) >= 8
        and data[0] == 0x80
        and data[1] >= 6
        and data[2:4] == IDMX_AUDIO_EXTENSION_VERSION
        and data[4] & 0xF0 == 0x20
    )


def rtp_packet_is_idmx_aac(packet: RtpPacket) -> bool:
    """Return whether native RTP extension metadata identifies IDMX AAC."""

    return _idmx_audio_extension_is_aac(packet)


def _idmx_aac_access_unit(payload: bytes) -> bytes | None:
    """Parse one RFC 3640 MPEG4-GENERIC access unit from an RTP payload."""

    if len(payload) < 4 or int.from_bytes(payload[:2], "big") != 16:
        return None
    access_unit_header = int.from_bytes(payload[2:4], "big")
    access_unit_size = access_unit_header >> 3
    if access_unit_header & 0x07 or access_unit_size != len(payload) - 4:
        return None
    return payload[4:]


def _rtp_media_aes_key(media_key: str | bytes) -> bytes:
    key_bytes = media_key.encode() if isinstance(media_key, str) else media_key
    return key_bytes.ljust(16, b"\0")[:16]


def _decrypt_idmx_aac_access_unit(access_unit: bytes, aes_key: bytes) -> bytes:
    decrypt_length = len(access_unit) - len(access_unit) % AES.block_size
    if decrypt_length == 0:
        return access_unit
    cipher = AES.new(aes_key, AES.MODE_ECB)  # codeql[py/weak-cryptographic-algorithm]
    decrypted_prefix = cipher.decrypt(access_unit[:decrypt_length])  # codeql[py/weak-cryptographic-algorithm] lgtm[py/weak-cryptographic-algorithm]
    return decrypted_prefix + access_unit[decrypt_length:]


def _aac_adts_header(payload_length: int, sample_rate: int, channels: int) -> bytes:
    try:
        sample_rate_index = IDMX_AAC_SAMPLE_RATES.index(sample_rate)
    except ValueError as err:
        raise PyEzvizError(f"Unsupported IDMX AAC sample rate: {sample_rate}") from err
    frame_length = payload_length + IDMX_AAC_ADTS_HEADER_SIZE
    if frame_length > IDMX_AAC_ADTS_MAX_FRAME_LENGTH:
        raise PyEzvizError("IDMX AAC access unit exceeds the ADTS frame limit")
    profile = IDMX_AAC_AUDIO_SPECIFIC_CONFIG_OBJECT_TYPE - 1
    return bytes(
        (
            0xFF,
            0xF1,
            (profile << 6) | (sample_rate_index << 2) | (channels >> 2),
            ((channels & 0x03) << 6) | (frame_length >> 11),
            (frame_length >> 3) & 0xFF,
            ((frame_length & 0x07) << 5) | 0x1F,
            0xFC,
        )
    )


def decrypt_idmx_aac_packets(  # noqa: PLR0911
    packets: Iterable[RtpPacket],
    media_key: str | bytes,
    *,
    audio_metadata: tuple[int, int] | None = None,
    audio_payload_types: frozenset[int] | None = None,
    require_contiguous: bool = True,
) -> RtpAacStream | None:
    """Return descriptor-backed encrypted IDMX AAC as ADTS when safely decodable."""

    packet_list = list(packets)
    descriptors = idmx_rtp_stream_descriptors(packet_list)
    selected_audio_payload_types = audio_payload_types
    if selected_audio_payload_types is None:
        selected_audio_payload_types = rtp_codec_payload_types(
            descriptors,
            "aac",
            fallback_payload_types=DEFAULT_AAC_PAYLOAD_TYPES,
        )
    encrypted_access_units: list[bytes] = []
    timestamps: list[int] = []
    for packet in packet_list:
        if packet.payload_type not in selected_audio_payload_types:
            continue
        if not _idmx_audio_extension_is_aac(packet):
            return None
        access_unit = _idmx_aac_access_unit(packet.payload)
        if access_unit is None:
            return None
        timestamps.append(packet.timestamp)
        encrypted_access_units.append(access_unit)
    if not encrypted_access_units:
        return None
    if require_contiguous and any(
        ((current - previous) & 0xFFFFFFFF) != IDMX_AAC_SAMPLES_PER_FRAME
        for previous, current in pairwise(timestamps)
    ):
        return None
    if any(
        len(access_unit) + IDMX_AAC_ADTS_HEADER_SIZE
        > IDMX_AAC_ADTS_MAX_FRAME_LENGTH
        for access_unit in encrypted_access_units
    ):
        return None

    descriptor = idmx_aac_descriptor(packet_list) or audio_metadata
    if descriptor is None:
        return None
    sample_rate, channels = descriptor
    aes_key = _rtp_media_aes_key(media_key)
    access_units = [
        _decrypt_idmx_aac_access_unit(access_unit, aes_key)
        for access_unit in encrypted_access_units
    ]
    return RtpAacStream(
        adts=b"".join(
            _aac_adts_header(len(access_unit), sample_rate, channels) + access_unit
            for access_unit in access_units
        ),
        sample_rate=sample_rate,
        channels=channels,
        frame_count=len(access_units),
    )


def rtp_payload_video_codec(payload: bytes) -> RtpVideoCodec | None:
    """Best-effort codec detection for an EZVIZ RTP video payload."""

    if len(payload) < 2:
        return None
    h264_type = payload[0] & 0x1F
    hevc_type = (payload[0] >> 1) & 0x3F
    if hevc_type in {48, 49} and _is_plausible_hevc_header(payload):
        codec: RtpVideoCodec | None = "hevc"
    elif _is_ambiguous_h264_hevc_payload(payload):
        codec = None
    elif 1 <= h264_type <= 5:
        codec = "h264"
    elif hevc_type in {32, 33, 34, 39, 40}:
        codec = "hevc"
    elif h264_type in {7, 8, 24, 28}:
        codec = "h264"
    else:
        codec = None
    return codec


def _rtp_payload_unsupported_video_codec(payload: bytes) -> RtpCodec | None:
    if len(payload) < 4 or payload[:3] != MPEG_VIDEO_START_CODE_PREFIX:
        return None
    start_code = payload[3]
    if start_code in {0xB3, 0xB8}:
        return "mpeg2video"
    if start_code <= 0x2F or start_code in {0xB0, 0xB5, 0xB6}:
        return "mpeg4video"
    return None


def _advertised_rtp_video_codec(
    descriptors: Iterable[RtpStreamDescriptor],
) -> RtpVideoCodec | None:
    advertised_codecs = {
        descriptor.codec
        for descriptor in descriptors
        if descriptor.media_kind == "video"
    }
    if not advertised_codecs:
        return None
    if len(advertised_codecs) > 1:
        codecs = ", ".join(sorted(advertised_codecs))
        raise PyEzvizError(
            f"Conflicting RTP video codecs advertised by IDMX metadata: {codecs}"
        )
    advertised_codec = next(iter(advertised_codecs))
    if advertised_codec == "h264":
        return "h264"
    if advertised_codec == "hevc":
        return "hevc"
    raise UnsupportedRtpVideoCodecError(
        "Unsupported RTP video codec advertised by IDMX metadata: "
        f"{advertised_codec}"
    )


def detect_rtp_video_codec(
    packets: Iterable[RtpPacket],
    *,
    video_payload_types: frozenset[int] = DEFAULT_VIDEO_PAYLOAD_TYPES,
    allow_fallback: bool = True,
) -> RtpVideoCodec:
    """Detect H.264 or HEVC from routed RTP video packets."""

    packet_list = list(packets)
    descriptors = idmx_rtp_stream_descriptors(packet_list)
    advertised_codec = _advertised_rtp_video_codec(descriptors)
    if advertised_codec is not None:
        return advertised_codec
    routed_video_payload_types = video_payload_types | frozenset(
        descriptor.payload_type
        for descriptor in descriptors
        if descriptor.media_kind == "video"
    )
    unsupported_static_codecs = {
        _IDMX_STATIC_VIDEO_PAYLOAD_CODECS[packet.payload_type]
        for packet in packet_list
        if packet.payload_type in _IDMX_STATIC_VIDEO_PAYLOAD_CODECS
    }
    if unsupported_static_codecs:
        codecs = ", ".join(sorted(unsupported_static_codecs))
        raise UnsupportedRtpVideoCodecError(
            f"Unsupported RTP video codec: {codecs}"
        )
    fallback: RtpVideoCodec | None = None
    for packet in packet_list:
        if packet.payload_type not in routed_video_payload_types:
            continue
        unsupported_codec = _rtp_payload_unsupported_video_codec(packet.payload)
        if unsupported_codec is not None:
            raise UnsupportedRtpVideoCodecError(
                f"Unsupported RTP video codec: {unsupported_codec}"
            )
        codec = rtp_payload_video_codec(packet.payload)
        if codec is not None:
            return codec
        if _is_ambiguous_h264_hevc_payload(packet.payload):
            continue
        if len(packet.payload) >= 2 and fallback is None:
            hevc_type = (packet.payload[0] >> 1) & 0x3F
            h264_type = packet.payload[0] & 0x1F
            if 0 <= hevc_type <= 50:
                fallback = "hevc"
            elif 1 <= h264_type <= 23:
                fallback = "h264"
    if fallback is not None and allow_fallback:
        return fallback
    raise PyEzvizError("Could not detect RTP video codec")


class RtpVideoDepacketizer:
    """Reassemble H.264 or HEVC NAL units while enforcing RTP continuity.

    ``allow_ezviz_headerless_hevc_fu`` accepts the non-standard continuation
    layout observed on local IDMX streams. Keep the strict default for ordinary
    RTP sources, where a changed FU NAL type invalidates the active fragment.
    """

    def __init__(
        self,
        codec: RtpVideoCodec,
        *,
        allow_ezviz_headerless_hevc_fu: bool = False,
    ) -> None:
        self.codec = codec
        self.allow_ezviz_headerless_hevc_fu = allow_ezviz_headerless_hevc_fu
        self.stats = RtpContinuityStats()
        self._last_sequence_by_ssrc: dict[int, int] = {}
        self._last_identity_by_ssrc: dict[int, tuple[int, int, bool, bytes]] = {}
        self._fragment_by_ssrc: dict[int, _FragmentedNal] = {}

    def push(self, packet: RtpPacket) -> tuple[bytes, ...]:
        """Consume one routed video packet and return complete NAL units."""

        continuity = self._continuity(packet)
        if continuity in {"duplicate", "reordered"}:
            return ()
        if continuity == "conflict":
            self._discard_fragment(packet.ssrc)
            return ()
        if continuity == "gap":
            self._discard_fragment(packet.ssrc)

        fragment = self._fragment_by_ssrc.get(packet.ssrc)
        if fragment is not None and fragment.timestamp != packet.timestamp:
            self.stats.timestamp_changes += 1
            self._discard_fragment(packet.ssrc)

        if self.codec == "h264":
            return self._push_h264(packet)
        if self.codec == "hevc":
            return self._push_hevc(packet)
        raise PyEzvizError(f"Unsupported RTP video codec: {self.codec}")

    def _continuity(self, packet: RtpPacket) -> str:
        previous = self._last_sequence_by_ssrc.get(packet.ssrc)
        identity = (packet.sequence, packet.timestamp, packet.marker, packet.payload)
        if previous is None:
            self._last_sequence_by_ssrc[packet.ssrc] = packet.sequence
            self._last_identity_by_ssrc[packet.ssrc] = identity
            return "first"
        delta = (packet.sequence - previous) & 0xFFFF
        if delta == 0:
            if self._last_identity_by_ssrc.get(packet.ssrc) == identity:
                self.stats.duplicates += 1
                return "duplicate"
            self.stats.sequence_conflicts += 1
            return "conflict"
        if delta >= 0x8000:
            self.stats.reordered += 1
            return "reordered"
        self._last_sequence_by_ssrc[packet.ssrc] = packet.sequence
        self._last_identity_by_ssrc[packet.ssrc] = identity
        if delta > 1:
            self.stats.sequence_gaps += 1
            return "gap"
        return "next"

    def _discard_fragment(self, ssrc: int) -> None:
        if self._fragment_by_ssrc.pop(ssrc, None) is not None:
            self.stats.discarded_fragments += 1

    def _push_h264(self, packet: RtpPacket) -> tuple[bytes, ...]:  # noqa: PLR0911
        payload = packet.payload
        if not payload:
            self._discard_fragment(packet.ssrc)
            return ()
        nal_type = payload[0] & 0x1F
        if 1 <= nal_type <= 23:
            self._discard_fragment(packet.ssrc)
            return (payload,)
        if nal_type == 24:
            self._discard_fragment(packet.ssrc)
            return _aggregation_units(payload, header_size=1)
        if nal_type != 28:
            self._discard_fragment(packet.ssrc)
            return ()
        if len(payload) < 2:
            self._discard_fragment(packet.ssrc)
            return ()

        fu_header = payload[1]
        is_start = bool(fu_header & 0x80)
        is_end = bool(fu_header & 0x40)
        if is_start:
            self._discard_fragment(packet.ssrc)
            self._fragment_by_ssrc[packet.ssrc] = _FragmentedNal(
                data=bytearray([(payload[0] & 0xE0) | (fu_header & 0x1F)])
                + payload[2:],
                last_sequence=packet.sequence,
                timestamp=packet.timestamp,
            )
        else:
            fragment = self._fragment_by_ssrc.get(packet.ssrc)
            if fragment is None:
                self.stats.discarded_fragments += 1
                return ()
            reconstructed_header = (payload[0] & 0xE0) | (fu_header & 0x1F)
            if reconstructed_header != fragment.data[0]:
                self._discard_fragment(packet.ssrc)
                return ()
            fragment.data.extend(payload[2:])
            fragment.last_sequence = packet.sequence
        if not is_end:
            return ()
        fragment = self._fragment_by_ssrc.pop(packet.ssrc, None)
        return (bytes(fragment.data),) if fragment is not None else ()

    def _push_hevc(self, packet: RtpPacket) -> tuple[bytes, ...]:  # noqa: PLR0911
        payload = packet.payload
        if not payload:
            self._discard_fragment(packet.ssrc)
            return ()
        nal_type = (payload[0] >> 1) & 0x3F
        if nal_type == 49 and len(payload) < 3:
            self._discard_fragment(packet.ssrc)
            return ()
        if len(payload) < 2:
            self._discard_fragment(packet.ssrc)
            return ()
        if nal_type == 48:
            self._discard_fragment(packet.ssrc)
            return _aggregation_units(payload, header_size=2)
        if nal_type != 49:
            self._discard_fragment(packet.ssrc)
            return (payload,)
        fu_header = payload[2]
        is_start = bool(fu_header & 0x80)
        is_end = bool(fu_header & 0x40)
        if is_start:
            self._discard_fragment(packet.ssrc)
            original_type = fu_header & 0x3F
            self._fragment_by_ssrc[packet.ssrc] = _FragmentedNal(
                data=bytearray(
                    [(payload[0] & 0x81) | (original_type << 1), payload[1]]
                )
                + payload[3:],
                last_sequence=packet.sequence,
                timestamp=packet.timestamp,
            )
        else:
            fragment = self._fragment_by_ssrc.get(packet.ssrc)
            if fragment is None:
                self.stats.discarded_fragments += 1
                return ()
            if (
                payload[0] & 0x81 != fragment.data[0] & 0x81
                or payload[1] != fragment.data[1]
            ):
                self._discard_fragment(packet.ssrc)
                return ()
            original_type = fu_header & 0x3F
            active_type = (fragment.data[0] >> 1) & 0x3F
            active_header0 = fragment.data[0]
            has_pseudo_header = (
                self.allow_ezviz_headerless_hevc_fu
                and fu_header in {active_header0, active_header0 | 0x40}
            )
            has_fu_header = original_type == active_type or has_pseudo_header
            if not has_fu_header and not self.allow_ezviz_headerless_hevc_fu:
                self._discard_fragment(packet.ssrc)
                return ()
            fragment.data.extend(payload[3:] if has_fu_header else payload[2:])
            fragment.last_sequence = packet.sequence
            is_end = is_end if has_fu_header else packet.marker
        if not is_end:
            return ()
        fragment = self._fragment_by_ssrc.pop(packet.ssrc, None)
        return (bytes(fragment.data),) if fragment is not None else ()


def rtp_packets_to_annexb(
    packets: Iterable[RtpPacket],
    *,
    codec: RtpVideoCodec,
    video_payload_types: frozenset[int] = DEFAULT_VIDEO_PAYLOAD_TYPES,
    allow_ezviz_headerless_hevc_fu: bool = False,
) -> bytes:
    """Route RTP video packets and return continuity-checked Annex-B bytes."""

    return b"".join(
        ANNEX_B_START_CODE + nal
        for nal in rtp_packets_to_nal_units(
            packets,
            codec=codec,
            video_payload_types=video_payload_types,
            allow_ezviz_headerless_hevc_fu=allow_ezviz_headerless_hevc_fu,
        )
    )


def rtp_packets_to_nal_units(
    packets: Iterable[RtpPacket],
    *,
    codec: RtpVideoCodec,
    video_payload_types: frozenset[int] = DEFAULT_VIDEO_PAYLOAD_TYPES,
    allow_ezviz_headerless_hevc_fu: bool = False,
) -> tuple[bytes, ...]:
    """Route RTP video packets and return complete continuity-checked NAL units."""

    packet_list = list(packets)
    descriptors = idmx_rtp_stream_descriptors(packet_list)
    routed_video_payload_types = rtp_codec_payload_types(
        descriptors,
        codec,
        fallback_payload_types=video_payload_types,
    )
    depacketizer = RtpVideoDepacketizer(
        codec,
        allow_ezviz_headerless_hevc_fu=allow_ezviz_headerless_hevc_fu,
    )
    output: list[bytes] = []
    for packet in packet_list:
        if packet.payload_type not in routed_video_payload_types:
            continue
        for nal in depacketizer.push(packet):
            if nal:
                output.append(nal)
    return tuple(output)


def _aggregation_units(payload: bytes, *, header_size: int) -> tuple[bytes, ...]:
    units: list[bytes] = []
    offset = header_size
    while offset + 2 <= len(payload):
        unit_size = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        if unit_size <= 0 or offset + unit_size > len(payload):
            break
        units.append(payload[offset : offset + unit_size])
        offset += unit_size
    return tuple(units)


def _is_plausible_hevc_header(payload: bytes) -> bool:
    forbidden_zero = payload[0] & 0x80 == 0
    layer_id = ((payload[0] & 0x01) << 5) | (payload[1] >> 3)
    temporal_id_plus1 = payload[1] & 0x07
    nal_type = (payload[0] >> 1) & 0x3F
    return forbidden_zero and layer_id == 0 and temporal_id_plus1 > 0 and nal_type <= 49


def _is_ambiguous_h264_hevc_payload(payload: bytes) -> bool:
    if len(payload) < 2 or not _is_plausible_hevc_header(payload):
        return False
    h264_type = payload[0] & 0x1F
    hevc_type = (payload[0] >> 1) & 0x3F
    return 1 <= h264_type <= 5 and 0 <= hevc_type <= 40
