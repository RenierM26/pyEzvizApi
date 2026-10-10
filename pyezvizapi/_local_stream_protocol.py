"""Bounded wire evidence shared by local probing and strict ECDH decoding."""

from __future__ import annotations

from .exceptions import PyEzvizError
from .rtp import parse_rtp_packet, rtp_payload
from .stream_media import MPEG_START_CODE_PREFIX, _is_mpeg_ps_packet_start_id

_LEGACY_PS_EVIDENCE_PACKETS = 8


class LocalSdkProtocolDetector:
    """Recognize repeated PS starts on one syntactically valid RTP route.

    Never infer a protocol from RTP version bits, a single packet, duplicate
    records, or SSRC alone. Keep only a small bounded set of observations.
    """

    def __init__(self) -> None:
        self._route: tuple[int, int, int] | None = None
        self._records: set[tuple[int, int]] = set()

    @property
    def legacy_rtp_ps(self) -> bool:
        """Whether eight distinct records establish a legacy RTP/PS route."""
        return len(self._records) >= _LEGACY_PS_EVIDENCE_PACKETS

    def observe(self, channel: int, payload: bytes) -> None:
        """Observe framing only; retain neither payloads nor key material."""
        if self.legacy_rtp_ps:
            return
        try:
            packet = parse_rtp_packet(payload)
            body = rtp_payload(payload)
        except PyEzvizError:
            return
        if body.startswith(b"\x1c") and len(body) >= 2:
            body = body[2:]
        elif body.startswith(b"\x0d"):
            body = body[1:]
        if not (
            len(body) >= 4
            and body.startswith(MPEG_START_CODE_PREFIX)
            and _is_mpeg_ps_packet_start_id(body[3])
        ):
            return
        route = (channel, packet.ssrc, packet.payload_type)
        if route != self._route:
            self._route = route
            self._records.clear()
        self._records.add((packet.sequence, packet.timestamp))


