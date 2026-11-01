"""Immutable selected-access-unit completion metadata; no host/transport policy."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class NativeTrackCompletion:
    """One admitted encoded track, counted after successful mux acceptance."""

    track_id: int
    index: int
    kind: Literal["video", "audio"]
    codec: str
    access_units: int


@dataclass(frozen=True, slots=True)
class NativeMediaCompletion:
    """Verified finite, joined, fully read output of one source/subscription.

    Source generation is opaque and owner-local, not camera identity or capture
    UTC. Track units describe original selected access units, not TS chunks or
    proprietary transport packets. A consumer must establish one-to-one unit
    correspondence through its container/relay before using these as host counts.
    """

    source_generation: str
    subscription_generation: int
    tracks: tuple[NativeTrackCompletion, ...]

    @property
    def video_units(self) -> int:
        """Return the selected video's accepted unit count."""
        return sum(track.access_units for track in self.tracks if track.kind == "video")

    @property
    def audio_units(self) -> int:
        """Return selected audio units, or zero for explicit video-only output."""
        return sum(track.access_units for track in self.tracks if track.kind == "audio")
