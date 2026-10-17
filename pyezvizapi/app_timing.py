"""Opt-in HEVC/AAC clock profile observed in the official app's PlayCtrl path.

This accepts parsed, clear access units, not arbitrary RTP counters or encrypted
PS. It is independent of capture defaults and is not physical AV calibration.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import chain
import subprocess
from typing import BinaryIO, Literal

from .exceptions import PyEzvizError
from .remux import copy_remuxed_output, open_mpegts_remux_process
from .rtp_timing import _mpeg_crc32, _pack_header, _pes

_PES_CHUNK_BYTES = 60_000
_TICKS_PER_MS = 90


@dataclass(frozen=True)
class AppTimedFrame:
    """One clear HEVC access unit or ADTS AAC frame with unwrapped source time.

    ``clock_id`` identifies one playback track's clock, not a file. Paired lenses
    may explicitly share a video clock and source ``picture_id``. Unrelated
    cameras must never share these identities. ``duration_ms`` is the native
    frame duration: AAC metadata duration or floor(1000 / video frame rate).
    Preserve the original timestamp/identity separately for provenance.
    """

    stream_id: int
    clock_id: str
    source_ms: int
    duration_ms: int
    data: bytes
    picture_id: int | None = None


@dataclass
class _TrackClock:
    origin_ms: int
    audio: bool
    previous_ms: int = 0
    picture_id: int | None = None


class AppPlaybackClock:
    """Stateful, explicitly selected app-relative playback timing profile.

    Defaults are observed live/playback repair limits, not firmware guarantees.
    Caller timestamps must already be unwrapped. Keep this object through seeks
    and recording cuts; call ``reset`` only for a new playback session. Feed
    startup frames even if recording begins later. No wall-clock alignment,
    silence generation, payload decoding or fixed lip-sync offset is applied.
    """

    def __init__(
        self, *, mode: Literal["live", "playback"] = "live",
        max_interval_ms: int | None = None,
    ) -> None:
        if mode not in ("live", "playback"):
            raise PyEzvizError("App timing mode must be live or playback")
        limit = (17_000 if mode == "live" else 1_500) if max_interval_ms is None else max_interval_ms
        if type(limit) is not int or limit <= 0:
            raise PyEzvizError("App timing maximum interval must be a positive integer")
        self.max_interval_ms = limit
        self._tracks: dict[str, _TrackClock] = {}

    @property
    def max_interval_ms(self) -> int:
        """Configured discontinuity limit; may change with playback mode."""
        return self._max_interval_ms

    @max_interval_ms.setter
    def max_interval_ms(self, value: int) -> None:
        if type(value) is not int or value <= 0:
            raise PyEzvizError("App timing maximum interval must be a positive integer")
        self._max_interval_ms = value

    def reset(self) -> None:
        """Begin a new playback session, not a seek or a new output file."""
        self._tracks.clear()

    def timestamp_ms(self, frame: AppTimedFrame) -> int:
        """Consume a frame and return its app-relative, continuity-repaired time."""
        _validate_frame(frame)
        audio = frame.stream_id < 0xE0
        state = self._tracks.get(frame.clock_id)
        if state is None:
            state = _TrackClock(frame.source_ms, audio)
            self._tracks[frame.clock_id] = state
        if state.audio != audio:
            raise PyEzvizError("Audio and video must use different app clock identities")
        if not audio and frame.picture_id == state.picture_id and state.picture_id is not None:
            return state.previous_ms
        candidate = frame.source_ms - state.origin_ms
        delta = candidate - state.previous_ms
        if delta < 0 or delta > self.max_interval_ms:
            candidate = state.previous_ms + frame.duration_ms
        state.previous_ms = candidate
        state.picture_id = frame.picture_id
        return candidate


def _validate_frame(frame: AppTimedFrame) -> None:
    if type(frame.stream_id) is not int or not (0xC0 <= frame.stream_id <= 0xDF or 0xE0 <= frame.stream_id <= 0xEF):
        raise PyEzvizError("App timing requires an audio or video PES stream ID")
    if not isinstance(frame.clock_id, str) or not frame.clock_id:
        raise PyEzvizError("App timing requires an explicit clock identity")
    if type(frame.source_ms) is not int or frame.source_ms < 0:
        raise PyEzvizError("App timing requires nonnegative unwrapped integer source milliseconds")
    if type(frame.duration_ms) is not int or frame.duration_ms <= 0:
        raise PyEzvizError("App timing requires a positive integer frame duration")
    if not isinstance(frame.data, bytes) or not frame.data:
        raise PyEzvizError("App timing requires nonempty clear encoded frame bytes")
    if frame.picture_id is not None and (type(frame.picture_id) is not int or frame.picture_id < 0):
        raise PyEzvizError("App timing picture identity must be a nonnegative integer")
    if frame.stream_id < 0xE0 and frame.picture_id is not None:
        raise PyEzvizError("AAC frames must not use a video picture identity")


def _stream_map(video_stream_ids: tuple[int, ...], audio_stream_id: int | None) -> bytes:
    if not video_stream_ids or len(set(video_stream_ids)) != len(video_stream_ids) or any(
        type(sid) is not int or not 0xE0 <= sid <= 0xEF for sid in video_stream_ids
    ):
        raise PyEzvizError("App mux requires unique HEVC video PES stream IDs")
    if audio_stream_id is not None and (type(audio_stream_id) is not int or not 0xC0 <= audio_stream_id <= 0xDF):
        raise PyEzvizError("App mux requires an AAC PES stream ID")
    entries = b"".join(bytes((0x24, sid, 0, 0)) for sid in video_stream_ids)
    if audio_stream_id is not None:
        entries += bytes((0x0F, audio_stream_id, 0, 0))
    body = b"\xe0\xff\x00\x00" + len(entries).to_bytes(2, "big") + entries
    header = b"\x00\x00\x01\xbc" + (len(body) + 4).to_bytes(2, "big") + body
    return header + _mpeg_crc32(header)


def app_timed_mpegps_payloads(
    frames: Iterable[AppTimedFrame], *, clock: AppPlaybackClock,
    video_stream_ids: tuple[int, ...] = (0xE0,), audio_stream_id: int | None = 0xC0,
) -> Iterator[bytes]:
    """Frame clear HEVC/ADTS access units as PS using an explicit playback clock.

    Input must be in native playback delivery order. No sorting of seek epochs
    occurs. PES continuation chunks reuse the same frame time; SCR is monotonic.
    This output is not byte-identical to native PS, but encoded bodies are copied.
    Sharing a clock across successive calls retains recording-cut continuity.
    """
    stream_map = _stream_map(video_stream_ids, audio_stream_id)
    allowed = {*video_stream_ids, audio_stream_id}
    scr = 0
    for frame in frames:
        if frame.stream_id not in allowed:
            raise PyEzvizError("App frame stream ID is not declared in the stream map")
        timestamp = clock.timestamp_ms(frame) * _TICKS_PER_MS
        scr = max(scr, timestamp)
        for offset in range(0, len(frame.data), _PES_CHUNK_BYTES):
            yield _pack_header(scr) + stream_map + _pes(
                timestamp, frame.stream_id, frame.data[offset:offset + _PES_CHUNK_BYTES],
            )


def copy_app_timed_frames_to_mpegts(
    frames: Iterable[AppTimedFrame], output: BinaryIO, *, clock: AppPlaybackClock,
    video_stream_ids: tuple[int, ...] = (0xE0,), audio_stream_id: int | None = 0xC0,
    ffmpeg_path: str = "ffmpeg",
) -> None:
    """Stream-copy selected clear frames to TS without changing capture defaults.

    This is an explicit parsed-frame API, not encrypted-PS parsing or automatic
    ``save_clip`` selection. Feed startup frames into the clock before selecting
    a later clip. FFmpeg is responsible for container framing, not clock repair.
    """
    payloads = app_timed_mpegps_payloads(
        frames, clock=clock, video_stream_ids=video_stream_ids, audio_stream_id=audio_stream_id,
    )
    first = next(payloads, None)
    if first is None:
        raise PyEzvizError("App timing requires at least one encoded frame")
    process = open_mpegts_remux_process(
        ffmpeg_path, input_format="mpeg", preserve_timestamps=True, map_all_streams=True, popen=subprocess.Popen,
    )

    def write_input(stdin: BinaryIO) -> None:
        for payload in chain((first,), payloads):
            stdin.write(payload)

    copy_remuxed_output(process, output, write_input=write_input)
