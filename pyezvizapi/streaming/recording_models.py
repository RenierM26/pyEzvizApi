"""Route-neutral, versioned UTC recording catalog values."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.ranges import playback_integer, playback_range, playback_timezone


@dataclass(frozen=True, order=True)
class StoredRecording:
    """A UTC SD interval, not a promise that the camera can play it."""

    begin_time: str
    end_time: str

    def __post_init__(self) -> None:
        playback_range(self.begin_time, self.end_time)


@dataclass(frozen=True)
class RecordingCatalog:
    """A bounded, deduplicated snapshot with an explicit discovery route."""

    serial: str
    channel: int
    timezone: str
    recordings: tuple[StoredRecording, ...]
    discovery: str = "cloud-sd-v2"

    def __post_init__(self) -> None:
        if not isinstance(self.serial, str) or not self.serial:
            raise PyEzvizError("Catalog requires a serial")
        if self.discovery not in ("cloud-sd-v2", "lan-hcnetsdk"):
            raise PyEzvizError("Unsupported catalog discovery route")
        playback_integer(self.channel, "catalog channel", minimum=0)
        playback_timezone(self.timezone)
        if not isinstance(self.recordings, tuple) or any(
            not isinstance(item, StoredRecording) for item in self.recordings
        ):
            raise PyEzvizError("Catalog recordings must be StoredRecording values")

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, **asdict(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RecordingCatalog:
        """Load only the versioned public catalog shape."""
        try:
            if value["version"] != 1 or value["discovery"] not in ("cloud-sd-v2", "lan-hcnetsdk"):
                raise ValueError
            return cls(
                value["serial"],
                value["channel"],
                value["timezone"],
                tuple(StoredRecording(**item) for item in value["recordings"]),
                discovery=value["discovery"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PyEzvizError("Invalid recording catalog") from error
