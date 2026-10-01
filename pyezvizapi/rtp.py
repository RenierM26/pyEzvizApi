"""Shared RTP parsing, media routing, and video depacketization."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from .exceptions import PyEzvizError

ANNEX_B_START_CODE = b"\x00\x00\x00\x01"
DEFAULT_VIDEO_PAYLOAD_TYPES = frozenset({96})
DEFAULT_AAC_PAYLOAD_TYPES = frozenset({104})
DEFAULT_METADATA_PAYLOAD_TYPES = frozenset({112})

RtpMediaKind = Literal["video", "audio", "metadata", "unknown"]
RtpVideoCodec = Literal["h264", "hevc"]


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
    video_payload_types: frozenset[int] = DEFAULT_VIDEO_PAYLOAD_TYPES,
    audio_payload_types: frozenset[int] = DEFAULT_AAC_PAYLOAD_TYPES,
    metadata_payload_types: frozenset[int] = DEFAULT_METADATA_PAYLOAD_TYPES,
) -> RtpMediaKind:
    """Classify one RTP packet using the EZVIZ dynamic payload mapping."""

    if packet.payload_type in video_payload_types:
        return "video"
    if packet.payload_type in audio_payload_types:
        return "audio"
    if packet.payload_type in metadata_payload_types:
        return "metadata"
    return "unknown"


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


def detect_rtp_video_codec(
    packets: Iterable[RtpPacket],
    *,
    video_payload_types: frozenset[int] = DEFAULT_VIDEO_PAYLOAD_TYPES,
    allow_fallback: bool = True,
) -> RtpVideoCodec:
    """Detect H.264 or HEVC from routed RTP video packets."""

    fallback: RtpVideoCodec | None = None
    for packet in packets:
        if packet.payload_type not in video_payload_types:
            continue
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

    depacketizer = RtpVideoDepacketizer(
        codec,
        allow_ezviz_headerless_hevc_fu=allow_ezviz_headerless_hevc_fu,
    )
    output: list[bytes] = []
    for packet in packets:
        if packet.payload_type not in video_payload_types:
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
