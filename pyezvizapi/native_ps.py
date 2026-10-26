"""Bounded incremental MPEG-PS framing/decryption, independent of any player."""

from __future__ import annotations

from .exceptions import PyEzvizError
from .stream_media import (
    decrypt_hikvision_ps_video,
    mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length,
)

MAX_PENDING_PS_BYTES = 1024 * 1024
_PS_START = b"\x00\x00\x01"


class NativePsTransform:
    """Preserve complete PS packets and video continuation prerequisites.

    A key opts into Hikvision video-NAL decryption, not transport decryption.
    Header size is explicit; there is no guessed key/mode or fallback at EOF.
    Only an explicitly finite source may call finish; cancellation never flushes.
    """

    def __init__(self, media_key: str | bytes | None = None, *, nalu_header_size: int = 2) -> None:
        if isinstance(nalu_header_size, bool) or nalu_header_size not in (0, 1, 2):
            raise ValueError("NAL header size must be 0, 1 or 2")
        if media_key is not None and (not isinstance(media_key, str | bytes) or not media_key):
            raise ValueError("Supply a nonempty media key or explicitly clear input")
        self._key = media_key
        self._header = nalu_header_size
        self._buffer = bytearray()
        self._closed = False
        self.peak_pending_bytes = 0

    @property
    def pending_bytes(self) -> int:
        """Current retained PS bytes, not libav/transport memory."""
        return len(self._buffer)

    def _decode(self, data: bytes) -> bytes:
        return (
            decrypt_hikvision_ps_video(data, self._key, nalu_header_size=self._header)
            if self._key is not None
            else data
        )

    def feed(self, data: bytes) -> bytes:
        """Bound before append; never resynchronize past unrecognized input."""
        if self._closed:
            raise PyEzvizError("PS transform is closed")
        if not isinstance(data, bytes) or not data:
            raise PyEzvizError("Native PS input must contain nonempty immutable bytes")
        if len(data) + len(self._buffer) > MAX_PENDING_PS_BYTES:
            raise PyEzvizError("Native PS pending byte limit exceeded before append")
        self._buffer.extend(data)
        self.peak_pending_bytes = max(self.peak_pending_bytes, len(self._buffer))
        if len(self._buffer) >= 3 and self._buffer[:3] != _PS_START:
            raise PyEzvizError("Native stream requires MPEG-PS; IDMX/RTP is not supported here")
        end = (
            mpeg_ps_decryptable_prefix_length(self._buffer)
            if self._key is not None
            else mpeg_ps_complete_prefix_length(self._buffer)
        )
        result = self._decode(bytes(self._buffer[:end])) if end else b""
        del self._buffer[:end]
        return result

    def finish(self) -> bytes:
        """Finish a caller-attested finite recording, rejecting partial PES."""
        if self._closed:
            raise PyEzvizError("PS transform is closed")
        if self._buffer and mpeg_ps_complete_prefix_length(self._buffer) != len(self._buffer):
            raise PyEzvizError("Finite native PS source ended with a partial packet")
        result = self._decode(bytes(self._buffer)) if self._buffer else b""
        self._buffer.clear()
        return result

    def close(self) -> None:
        """Discard pending input and the key reference; not secure memory erasure."""
        self._closed = True
        self._buffer.clear()
        self._key = None
