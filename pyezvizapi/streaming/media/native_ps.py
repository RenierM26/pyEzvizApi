"""Bounded incremental MPEG-PS framing/decryption, independent of any player."""

from __future__ import annotations

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.cloud.protocol import (
    _decrypt_hikvision_ps_video_packets,
    _MpegPsVideoDecryptState,
    decrypt_hikvision_ps_video,
)
from pyezvizapi.streaming.media.containers import (
    mpeg_ps_complete_prefix_length,
    mpeg_ps_decryptable_prefix_length,
)
from pyezvizapi.streaming.media.mpegps import (
    _is_video_pes_stream_id,
    _mpeg_ps_complete_packet_ranges,
    _mpeg_ps_video_decrypt_ranges,
    _MpegPsPacketRange,
    _pes_payload_start,
)

MAX_PENDING_PS_BYTES = 1024 * 1024
_PS_START = b"\x00\x00\x01"


def _cloud_ps_live_ranges(data: bytes) -> list[_MpegPsPacketRange]:
    """Hold the last video PES until a successor or a pack anchors its end."""
    strict = _mpeg_ps_complete_packet_ranges(data)
    if not strict or not _is_video_pes_stream_id(strict[-1].stream_id):
        return strict
    if data.find(b"\x00\x00\x01\xba", strict[-1].end) >= 0:
        recovered = _mpeg_ps_video_decrypt_ranges(data)
        for index, packet in enumerate(recovered):
            if index and packet.start != recovered[index - 1].end:
                # A gap not owned by video is not recoverable.
                break
            if packet.stream_id == 0xBA and packet.start >= strict[-1].end:
                return recovered[:index]
    return strict[:-1]


class NativePsTransform:
    """Preserve complete PS packets and video continuation prerequisites.

    A key opts into Hikvision video-NAL decryption, not transport decryption.
    Header size is explicit; there is no guessed key/mode or fallback at EOF.
    Only an explicitly finite source may call finish; cancellation never flushes.
    """

    def __init__(
        self,
        media_key: str | bytes | None = None,
        *,
        nalu_header_size: int = 2,
        recover_cloud_pes: bool = False,
    ) -> None:
        if isinstance(nalu_header_size, bool) or nalu_header_size not in (1, 2):
            raise ValueError("Continuous decryption requires clear 1- or 2-byte NAL headers")
        if media_key is not None and (not isinstance(media_key, str | bytes) or not media_key):
            raise ValueError("Supply a nonempty media key or explicitly clear input")
        raw_key = media_key.encode() if isinstance(media_key, str) else media_key
        self._key = raw_key.ljust(16, b"\x00")[:16] if raw_key is not None else None
        self._header = nalu_header_size
        self._recover_cloud_pes = recover_cloud_pes
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
        ranges = None
        if self._recover_cloud_pes:
            ranges = _cloud_ps_live_ranges(bytes(self._buffer))
            end = ranges[-1].end if ranges else 0
        else:
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
                packet_ranges=ranges,
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


class LegacyPsVideoTransform:
    """Decrypt whole-header NALs once a complete video PES run is available."""

    def __init__(self, key: str | bytes) -> None:
        if not key:
            raise ValueError("Supply a nonempty media key")
        self._key = key
        self._buffer = bytearray()

    def feed(self, data: bytes) -> bytes:
        if len(self._buffer) + len(data) > MAX_PENDING_PS_BYTES:
            raise PyEzvizError("Legacy MPEG-PS pending byte limit exceeded before append")
        self._buffer.extend(data)
        if len(self._buffer) >= 3 and self._buffer[:3] != _PS_START:
            raise PyEzvizError("Legacy video decryption requires MPEG-PS input")
        end = mpeg_ps_decryptable_prefix_length(self._buffer)
        # A new aligned NAL can end the buffered video run without audio.
        view = bytes(self._buffer)
        for packet in reversed(_mpeg_ps_complete_packet_ranges(view, start_offset=end)):
            if not _is_video_pes_stream_id(packet.stream_id) or not view[packet.start + 6] & 4:
                continue
            start = _pes_payload_start(view, packet.start)
            if start is None or not view.startswith((_PS_START, b"\0" + _PS_START), start):
                continue
            # Use the same validated encrypted-header scanner as buffered playback.
            header = start - packet.start + (4 if view.startswith(b"\0" + _PS_START, start) else 3)
            probe = view[packet.start : packet.end]
            decoded = decrypt_hikvision_ps_video(probe, self._key, nalu_header_size=0)
            if decoded[header : header + 16] != probe[header : header + 16]:
                end = packet.start
                break
        if not end:
            return b""
        run = bytes(self._buffer[:end])
        del self._buffer[:end]
        return decrypt_hikvision_ps_video(run, self._key, nalu_header_size=0)

    def close(self) -> None:
        self._buffer.clear()
        self._key = b""
