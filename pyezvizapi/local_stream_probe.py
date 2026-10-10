"""Bounded, payload-free diagnostics for negotiated local stream protocols."""

from __future__ import annotations

from dataclasses import dataclass
import math
import time
from typing import Any, Literal

from .exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
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


@dataclass(frozen=True)
class LocalSdkProtocolProbeResult:
    """Sanitized negotiation result, not a media-key or playback validation."""

    protocol: Literal["ecdh", "legacy_rtp_ps", "unknown", "no_data"]
    recommended_source: Literal["local-sdk", "local-sdk-ecdh"] | None
    authenticated_ecdh: bool
    frames_received: int
    bytes_received: int


def probe_local_sdk_stream_from_client(
    client: Any,
    serial: str,
    *,
    duration_seconds: float = 10.0,
    max_frames: int = 1024,
    max_bytes: int = 1024 * 1024,
    receiver_port: int = 10101,
) -> LocalSdkProtocolProbeResult:
    """Probe an ECDH-requested local session without publishing media.

    Credential discovery precedes the stream deadline. Bootstrap and reads
    then share a finite deadline plus frame/byte budgets. An ECDH result
    requires native handshake verification; legacy evidence recommends an
    explicit direct-local source, never an implicit authentication downgrade.
    Authentication/network errors propagate. Unknown data is not silence.
    """
    # Lazy import keeps the shared detector independent of the ECDH decoder.
    from .local_stream_ecdh import open_local_sdk_ecdh_stream_from_client  # noqa: PLC0415

    if not math.isfinite(duration_seconds) or duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive and finite")
    if isinstance(max_frames, bool) or not isinstance(max_frames, int) or max_frames <= 0:
        raise ValueError("max_frames must be a positive integer")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    detector = LocalSdkProtocolDetector()
    frames = 0
    received = 0
    with open_local_sdk_ecdh_stream_from_client(
        client, serial, receiver_port=receiver_port
    ) as stream:
        deadline = time.monotonic() + duration_seconds
        try:
            stream.start(read_first_media=False, deadline=deadline)
            while frames < max_frames and received < max_bytes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                frame = stream.sdk_client.read_stream_frame_after_prefix(
                    max_prefix_bytes=stream.max_prefix_bytes,
                    timeout=remaining,
                    deadline=deadline,
                )
                frames += 1
                size = len(frame.frame.payload)
                if received + size > max_bytes:
                    # The frame was received but not fed to any decoder.
                    received += size
                    break
                received += size
                detector.observe(frame.frame.header.channel, frame.frame.payload)
                if detector.legacy_rtp_ps:
                    return LocalSdkProtocolProbeResult(
                        "legacy_rtp_ps", "local-sdk", False, frames, received
                    )
                stream.decoder.feed_interleaved_frame(frame)
                if stream.decoder.keys_derived:
                    return LocalSdkProtocolProbeResult(
                        "ecdh", "local-sdk-ecdh", True, frames, received
                    )
        except EzvizLocalSdkDeadlineExpired:
            pass
    return LocalSdkProtocolProbeResult(
        "unknown" if frames else "no_data", None, False, frames, received
    )
