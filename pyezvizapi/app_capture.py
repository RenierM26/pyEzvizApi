"""Strict adapter from verified native RTP capture timing to the app profile."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from fractions import Fraction
from heapq import merge
from itertools import chain, groupby

from .app_timing import AppPlaybackClock, AppTimedFrame
from .exceptions import PyEzvizError
from .rtp import ANNEX_B_START_CODE, RtpAacStream, rtp_nal_units_have_vcl
from .rtp_timing import _audio_events, _pack_header, _pes, _program_stream_map

_CHUNK_BYTES = 60_000
_RTP_WRAP = 1 << 32
_VIDEO_TICKS_PER_MS = 90


def native_app_timed_payloads(
    nal_units: Iterable[bytes],
    timestamps: Iterable[int],
    *,
    audio: RtpAacStream | None,
    frame_rate: str,
) -> Iterator[bytes]:
    """Use genuine single-source HEVC/16kHz AAC clocks from full capture startup.

    Source identity and codec must be checked by the transport adapter. No
    startup trimming, picture renumbering, inferred rate or synthetic AAC clock
    is supported. Only container framing is duplicated, not the clock policy.
    """
    if (
        audio is None
        or audio.origin_timestamp is None
        or audio.sample_rate != 16000
        or audio.channels != 1
        or not audio.adts
        or audio.frame_count <= 0
        or len(set(audio.source_keys)) != 1
    ):
        raise PyEzvizError("app_relative_clock requires single-source timestamped mono 16kHz AAC")
    try:
        rate = Fraction(frame_rate)
        duration_ms = int(1000 / rate)
    except (ValueError, ZeroDivisionError) as error:
        raise PyEzvizError("app_relative_clock requires advertised native frame cadence") from error
    if rate <= 0 or duration_ms <= 0:
        raise PyEzvizError("app_relative_clock requires positive native frame cadence")
    clock = AppPlaybackClock(mode="live")
    video_timestamps = tuple(timestamps)
    # This is a bounded, fully collected capture. Reserve one counter range per
    # NAL so even repeated signed backward wraps cannot make source_ms negative.
    # A whole-millisecond shift cancels at origin subtraction and preserves the
    # original sub-ms phase; adding arbitrary 2**32 tick epochs would not.
    range_ms = (_RTP_WRAP + _VIDEO_TICKS_PER_MS - 1) // _VIDEO_TICKS_PER_MS
    video_epoch_ticks = len(video_timestamps) * range_ms * _VIDEO_TICKS_PER_MS

    def video_events() -> Iterator[tuple[int, int, bytes]]:
        previous: int | None = None
        unwrapped = 0
        pending: list[bytes] = []
        for raw, entries in groupby(
            zip(video_timestamps, nal_units, strict=True), key=lambda pair: pair[0]
        ):
            if type(raw) is not int or not 0 <= raw < _RTP_WRAP:
                raise PyEzvizError("app_relative_clock requires unsigned native RTP video counters")
            units = [unit for _, unit in entries]
            pending.extend(units)
            if not rtp_nal_units_have_vcl(units, codec="hevc"):
                continue
            if previous is None:
                unwrapped = video_epoch_ticks + raw
            else:
                delta = (raw - previous + _RTP_WRAP // 2) % _RTP_WRAP - _RTP_WRAP // 2
                unwrapped += delta
            previous = raw
            body = b"".join(ANNEX_B_START_CODE + unit for unit in pending)
            pending.clear()
            frame = AppTimedFrame(
                0xE0, "video", unwrapped // _VIDEO_TICKS_PER_MS, duration_ms, body, raw
            )
            yield clock.timestamp_ms(frame) * _VIDEO_TICKS_PER_MS, frame.stream_id, body

    def audio_events() -> Iterator[tuple[int, int, bytes]]:
        assert audio is not None and audio.origin_timestamp is not None
        for timestamp, stream_id, body in _audio_events(audio):
            # _audio_events uses rounded 90kHz offsets. 90kHz >16kHz, so
            # recover the exact integer source sample offset before ms conversion.
            samples = (timestamp * audio.sample_rate + 45000) // 90000
            source_ms = (audio.origin_timestamp + samples) * 1000 // audio.sample_rate
            frame = AppTimedFrame(
                stream_id, "audio", source_ms, 1024 * 1000 // audio.sample_rate, body
            )
            yield clock.timestamp_ms(frame) * _VIDEO_TICKS_PER_MS, stream_id, body

    video = video_events()
    sound = audio_events()
    first_video, first_audio = next(video, None), next(sound, None)
    if first_video is None or first_audio is None:
        raise PyEzvizError(
            "app_relative_clock requires complete source-timestamped HEVC and AAC frames"
        )
    events = merge(
        chain((first_video,), video), chain((first_audio,), sound), key=lambda event: event[0]
    )
    stream_map = _program_stream_map("hevc", audio=True)
    scr = 0
    for timestamp, stream_id, body in events:
        scr = max(scr, timestamp)
        for offset in range(0, len(body), _CHUNK_BYTES):
            yield (
                _pack_header(scr)
                + stream_map
                + _pes(timestamp, stream_id, body[offset : offset + _CHUNK_BYTES])
            )
