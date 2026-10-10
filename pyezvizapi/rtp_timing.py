"""Carry native RTP access-unit timing through a clear MPEG-PS remux input."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from heapq import merge
from itertools import groupby

from .exceptions import EzvizUnsupportedMediaError, PyEzvizError
from .rtp import ANNEX_B_START_CODE, RtpAacStream, RtpVideoCodec, rtp_nal_units_have_vcl

_PES_CHUNK_BYTES = 60_000
_RTP_VIDEO_CLOCK = 90_000
_ADTS_HEADER_PREFIX = b"\xff\xf1"


def _mpeg_crc32(data: bytes) -> bytes:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04C11DB7 if value & 0x80000000 else 0)) & 0xFFFFFFFF
    return value.to_bytes(4, "big")


def _program_stream_map(codec: RtpVideoCodec, *, audio: bool) -> bytes:
    entries = bytes((0x24 if codec == "hevc" else 0x1B, 0xE0, 0, 0))
    if audio:
        entries += b"\x0f\xc0\x00\x00"
    body = b"\xe0\xff\x00\x00" + len(entries).to_bytes(2, "big") + entries
    header = b"\x00\x00\x01\xbc" + (len(body) + 4).to_bytes(2, "big") + body
    return header + _mpeg_crc32(header)


def _pack_header(timestamp: int) -> bytes:
    timestamp &= 0x1FFFFFFFF
    fields = (
        (2, 1), (3, timestamp >> 30), (1, 1),
        (15, (timestamp >> 15) & 0x7FFF), (1, 1),
        (15, timestamp & 0x7FFF), (1, 1), (9, 0), (1, 1),
        (22, 0x3FFFFF), (1, 1), (1, 1), (5, 31), (3, 0),
    )
    value = 0
    for width, part in fields:
        value = (value << width) | part
    return b"\x00\x00\x01\xba" + value.to_bytes(10, "big")


def _pes(timestamp: int, stream_id: int, payload: bytes) -> bytes:
    timestamp &= 0x1FFFFFFFF
    pts = bytes((
        0x21 | ((timestamp >> 29) & 14), (timestamp >> 22) & 255,
        ((timestamp >> 14) & 254) | 1, (timestamp >> 7) & 255,
        ((timestamp << 1) & 254) | 1,
    ))
    return (b"\x00\x00\x01" + bytes((stream_id,))
            + (len(payload) + 8).to_bytes(2, "big") + b"\x80\x80\x05" + pts + payload)


def _video_events(
    nal_units: Iterable[bytes], timestamps: Iterable[int], codec: RtpVideoCodec,
) -> Iterator[tuple[int, int, bytes]]:
    pending: list[bytes] = []
    previous_raw: int | None = None
    elapsed = 0
    for timestamp, entries in groupby(zip(timestamps, nal_units, strict=True), key=lambda pair: pair[0]):
        units = [unit for _timestamp, unit in entries]
        pending.extend(units)
        if not rtp_nal_units_have_vcl(units, codec=codec):
            continue
        delta = (timestamp - previous_raw) & 0xFFFFFFFF if previous_raw is not None else 0
        if previous_raw is not None and (delta == 0 or delta >= 0x80000000):
            raise EzvizUnsupportedMediaError(
                "Native RTP video timestamps are nonmonotonic; use another stream source",
                source="rtp", reason="unsupported_video_timing",
            )
        previous_raw = timestamp
        elapsed += delta
        yield elapsed, 0xE0, b"".join(ANNEX_B_START_CODE + unit for unit in pending)
        pending.clear()


def _audio_events(audio: RtpAacStream | None) -> Iterator[tuple[int, int, bytes]]:
    if audio is None:
        return
    for start_sample, data in audio.timed_segments or ((0, audio.adts),):
        sample_offset = start_sample
        offset = 0
        while offset < len(data):
            if offset + 7 > len(data) or data[offset:offset + 2] != _ADTS_HEADER_PREFIX:
                raise PyEzvizError("Invalid staged ADTS header")
            length = ((data[offset + 3] & 3) << 11) | (data[offset + 4] << 3) | (data[offset + 5] >> 5)
            if length < 7 or offset + length > len(data):
                raise PyEzvizError("Invalid staged ADTS frame length")
            timestamp = (sample_offset * _RTP_VIDEO_CLOCK + audio.sample_rate // 2) // audio.sample_rate
            yield timestamp, 0xC0, data[offset:offset + length]
            offset += length
            sample_offset += 1024


def timed_rtp_mpegps_payloads(
    nal_units: Iterable[bytes], timestamps: Iterable[int], *,
    codec: RtpVideoCodec, audio: RtpAacStream | None = None,
) -> Iterator[bytes]:
    """Preserve relative native clocks, with each track's first received AU at zero.

    This does not infer absolute inter-track synchronization without RTCP.
    PES chunks are length-delimited, including large video access units; a
    zero-length video PES is not reliably recognized by MPEG-PS demuxers.
    """

    stream_map = _program_stream_map(codec, audio=audio is not None)
    events = merge(_video_events(nal_units, timestamps, codec), _audio_events(audio), key=lambda item: item[0])
    for timestamp, stream_id, payload in events:
        for offset in range(0, len(payload), _PES_CHUNK_BYTES):
            yield (_pack_header(timestamp) + stream_map
                   + _pes(timestamp, stream_id, payload[offset:offset + _PES_CHUNK_BYTES]))


class NativeRtpPsMuxer:
    """Bounded incremental PS framing for native video and AAC RTP clocks.

    Track origins are independently zero; no absolute RTCP alignment is inferred.
    """

    def __init__(self, codec: RtpVideoCodec, *, audio: bool) -> None:
        self.codec: RtpVideoCodec = codec
        self._map = _program_stream_map(codec, audio=audio)
        self._video_raw: int | None = None
        self._audio_raw: int | None = None
        self._video_elapsed = 0
        self._audio_elapsed = 0
        self._scr = 0
        self._pending = bytearray()

    def _frame(self, timestamp: int, stream_id: int, payload: bytes) -> Iterator[bytes]:
        self._scr = max(self._scr, timestamp)
        for offset in range(0, len(payload), _PES_CHUNK_BYTES):
            yield (_pack_header(self._scr) + self._map
                   + _pes(timestamp, stream_id, payload[offset:offset + _PES_CHUNK_BYTES]))

    def video(self, timestamp: int, nal_unit: bytes) -> Iterator[bytes]:
        """Frame completed NALs, holding only bounded initial parameter data."""

        if self._video_raw is None:
            self._pending.extend(ANNEX_B_START_CODE + nal_unit)
            if not rtp_nal_units_have_vcl((nal_unit,), codec=self.codec):
                if len(self._pending) > 1_048_576:
                    raise PyEzvizError("Native RTP video startup parameters exceed buffer limit")
                return
            payload = bytes(self._pending)
            self._pending.clear()
        else:
            payload = ANNEX_B_START_CODE + nal_unit
        delta = (timestamp - self._video_raw) & 0xFFFFFFFF if self._video_raw is not None else 0
        if delta >= 0x80000000:
            raise PyEzvizError("Native RTP video clock reset or reordered access unit")
        self._video_raw = timestamp
        self._video_elapsed += delta
        yield from self._frame(self._video_elapsed, 0xE0, payload)

    def audio(self, timestamp: int, audio: RtpAacStream) -> Iterator[bytes]:
        """Preserve forward whole-AU gaps without generating silence."""

        delta = (timestamp - self._audio_raw) & 0xFFFFFFFF if self._audio_raw is not None else 0
        if self._audio_raw is not None and (delta == 0 or delta >= 0x80000000 or delta % 1024):
            raise PyEzvizError("Native RTP AAC clock reset or invalid access-unit spacing")
        self._audio_raw = timestamp
        self._audio_elapsed += delta
        for offset, stream_id, payload in _audio_events(audio):
            clock = (self._audio_elapsed * _RTP_VIDEO_CLOCK + audio.sample_rate // 2) // audio.sample_rate + offset
            yield from self._frame(clock, stream_id, payload)
