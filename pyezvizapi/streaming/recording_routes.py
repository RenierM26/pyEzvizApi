"""Typed recording routes; legacy save-clip adaptation is confined to this edge."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import HcNetSdkLanEndpoint
from pyezvizapi.streaming.local.playback import download_lan_sd_recording
from pyezvizapi.streaming.ranges import playback_integer, positive_timeout
from pyezvizapi.streaming.recording_models import RecordingCatalog, StoredRecording

# Existing clients and callers can supply the historical save_clip method. No
# untyped option dictionaries or synthesized keyword names cross the batch core.
type LegacyClipSaver = Callable[..., object]


@dataclass(frozen=True)
class RecordingBatchLimits:
    """Per-clip transfer bounds and the total catalog clip-count bound."""

    max_bytes: int = 128 * 1024 * 1024
    transfer_timeout: float = 60
    max_clips: int = 10000

    def __post_init__(self) -> None:
        playback_integer(self.max_bytes, "max_bytes")
        positive_timeout(self.transfer_timeout, "transfer_timeout")
        playback_integer(self.max_clips, "max_clips")


@dataclass(frozen=True)
class LanRecordingRoute:
    """One explicit native channel and device credential, with no account state."""

    channel: int
    host: str
    password: str | bytes = field(repr=False)
    username: str = "admin"
    source: Literal["local-playback"] = field(default="local-playback", init=False)
    decrypt: Literal[False] = field(default=False, init=False)

    def save(
        self,
        saver: LegacyClipSaver | None,
        catalog: RecordingCatalog,
        recording: StoredRecording,
        path: Path,
        limits: RecordingBatchLimits,
    ) -> None:
        if saver is None:
            download_lan_sd_recording(
                HcNetSdkLanEndpoint(serial=catalog.serial, host=self.host),
                self.password,
                path,
                recording.begin_time,
                recording.end_time,
                channel=self.channel,
                timezone=catalog.timezone,
                username=self.username,
                max_bytes=limits.max_bytes,
                transfer_timeout=limits.transfer_timeout,
            )
        else:
            saver(
                catalog.serial,
                path,
                source=self.source,
                output_format="mpegps",
                channel=self.channel,
                duration_seconds=None,
                local_playback_begin_time=recording.begin_time,
                local_playback_end_time=recording.end_time,
                local_playback_timezone=catalog.timezone,
                local_playback_max_bytes=limits.max_bytes,
                local_playback_transfer_timeout=limits.transfer_timeout,
                host=self.host,
                hcnetsdk_command_password=self.password,
                local_playback_username=self.username,
            )


@dataclass(frozen=True)
class CloudRecordingRoute:
    """An explicit cloud channel with the existing optional decryption profile."""

    channel: int
    media_key: str | bytes | None = field(default=None, repr=False)
    decrypt: bool = True
    source: Literal["cloud-playback"] = field(default="cloud-playback", init=False)

    def save(
        self,
        saver: LegacyClipSaver | None,
        catalog: RecordingCatalog,
        recording: StoredRecording,
        path: Path,
        limits: RecordingBatchLimits,
    ) -> None:
        if saver is None:
            raise PyEzvizError("Cloud batch requires an account client")
        saver(
            catalog.serial,
            path,
            source=self.source,
            output_format="mpegps",
            channel=self.channel,
            duration_seconds=None,
            cloud_playback_begin_time=recording.begin_time,
            cloud_playback_end_time=recording.end_time,
            cloud_playback_timezone=catalog.timezone,
            cloud_playback_max_bytes=limits.max_bytes,
            cloud_playback_transfer_timeout=limits.transfer_timeout,
            decrypt_video=self.decrypt,
            cloud_playback_decrypt_audio=self.decrypt,
            media_key=self.media_key,
        )


type RecordingRoute = LanRecordingRoute | CloudRecordingRoute
