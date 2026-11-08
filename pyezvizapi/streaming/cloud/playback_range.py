"""Compatibility exports for route-neutral SD time and bounds helpers."""

from pyezvizapi.streaming.ranges import (
    DEFAULT_PLAYBACK_MAX_BYTES,
    DEFAULT_PLAYBACK_TRANSFER_TIMEOUT,
    MAX_PLAYBACK_RANGE_SECONDS,
    native_playback_range,
    playback_integer,
    playback_range,
    playback_timezone,
    positive_timeout,
    selected_playback_range,
)

__all__ = [
    "DEFAULT_PLAYBACK_MAX_BYTES",
    "DEFAULT_PLAYBACK_TRANSFER_TIMEOUT",
    "MAX_PLAYBACK_RANGE_SECONDS",
    "native_playback_range",
    "playback_integer",
    "playback_range",
    "playback_timezone",
    "positive_timeout",
    "selected_playback_range",
]
