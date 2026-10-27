"""Bounded incremental MPEG-PS framing/decryption, independent of any player."""

from __future__ import annotations

from ._stream import _decrypt_hikvision_ps_video_packets, _MpegPsVideoDecryptState
from .exceptions import PyEzvizError
from .stream_media import mpeg_ps_complete_prefix_length

MAX_PENDING_PS_BYTES = 1024 * 1024
_PS_START = b"\x00\x00\x01"


class NativePsTransform:
    """Preserve complete PS packets and video continuation prerequisites.

    A key opts into Hikvision video-NAL decryption, not transport decryption.
    Header size is explicit; there is no guessed key/mode or fallback at EOF.
    Only an explicitly finite source may call finish; cancellation never flushes.
    """

    def __init__(self, media_key: str | bytes | None = None, *, nalu_header_size: int = 2) -> None:
        if isinstance(nalu_header_size, bool) or nalu_header_size not in (1, 2):
            raise ValueError("Continuous decryption requires clear 1- or 2-byte NAL headers")
        if media_key is not None and (not isinstance(media_key, str | bytes) or not media_key):
            raise ValueError("Supply a nonempty media key or explicitly clear input")
        raw_key = media_key.encode() if isinstance(media_key, str) else media_key
        self._key = raw_key.ljust(16, b"\x00")[:16] if raw_key is not None else None
        self._header = nalu_header_size
        self._buffer = bytearray()
        self._output = bytearray()
        self._states: dict[int, _MpegPsVideoDecryptState] = {}
        self._processed = self._emitted = 0
        self._closed = False
        self._finished = False
        self.peak_pending_bytes = 0

    @property
    def pending_bytes(self) -> int:
        """Current retained PS bytes, not libav/transport memory."""
        return len(self._buffer) + len(self._output)

    def feed(self, data: bytes) -> bytes:
        """Bound before append; never resynchronize past unrecognized input."""
        if self._closed or self._finished:
            raise PyEzvizError("PS transform is closed")
        if not isinstance(data, bytes) or not data:
            raise PyEzvizError("Native PS input must contain nonempty immutable bytes")
        if len(data) + self.pending_bytes > MAX_PENDING_PS_BYTES:
            raise PyEzvizError("Native PS pending byte limit exceeded before append")
        self._buffer.extend(data)
        self.peak_pending_bytes = max(self.peak_pending_bytes, self.pending_bytes)
        if len(self._buffer) >= 3 and self._buffer[:3] != _PS_START:
            raise PyEzvizError("Native stream requires MPEG-PS; IDMX/RTP is not supported here")
        end = mpeg_ps_complete_prefix_length(self._buffer)
        if not end:
            return b""
        chunk = bytes(self._buffer[:end])
        del self._buffer[:end]
        self._output.extend(chunk)
        if self._key is not None:
            _decrypt_hikvision_ps_video_packets(
                chunk,
                self._output,
                aes_key=self._key,
                nalu_header_size=self._header,
                states=self._states,
                data_offset=self._processed,
                output_offset=self._emitted,
            )
        self._processed += len(chunk)
        # An incomplete AES block can straddle audio/other-lens PES packets.
        # Only those unresolved positions hold output; completed video-only
        # pictures do not need an audio packet to release their original bytes.
        safe = min(
            (
                position
                for state in self._states.values()
                for position in state.pending_block_positions
            ),
            default=self._processed,
        )
        count = safe - self._emitted
        result = bytes(self._output[:count])
        del self._output[:count]
        self._emitted = safe
        return result

    def finish(self) -> bytes:
        """Finish a caller-attested finite recording, rejecting partial PES."""
        if self._closed or self._finished:
            raise PyEzvizError("PS transform is closed")
        if self._buffer and mpeg_ps_complete_prefix_length(self._buffer) != len(self._buffer):
            raise PyEzvizError("Finite native PS source ended with a partial packet")
        result = bytes(self._output)
        self._output.clear()
        self._buffer.clear()
        self._states.clear()
        self._finished = True
        return result

    def close(self) -> None:
        """Discard pending input and the key reference; not secure memory erasure."""
        self._closed = True
        self._buffer.clear()
        self._output.clear()
        self._states.clear()
        self._key = None
