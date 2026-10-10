"""Bounded, payload-free diagnostics for negotiated local stream protocols."""

from __future__ import annotations

from dataclasses import dataclass
import math
import time
from typing import Any, Literal

from ._local_stream_protocol import LocalSdkProtocolDetector
from .exceptions import EzvizLocalSdkDeadlineExpired


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
    # The probe opens an ECDH-requested session; the shared detector has no
    # dependency on the ECDH transport or public probe module.
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
        # Failure to establish a session is not evidence of stream silence.
        stream.start(read_first_media=False, deadline=deadline)
        try:
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
            # Exhausting the observation window is an expected probe outcome,
            # not an authentication error or evidence of permanent incapability.
            pass
    return LocalSdkProtocolProbeResult(
        "unknown" if frames else "no_data", None, False, frames, received
    )
