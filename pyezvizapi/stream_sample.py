"""Finite encoded-media probes and stream-copy output for HA adapter development.

No player, camera discovery, listener, cloud fallback or implicit transcoding.
These functions consume already clear bytes, not encrypted SDK packets.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import math
import subprocess
from tempfile import TemporaryFile
from typing import TYPE_CHECKING, Any, BinaryIO, cast

from .clip import ClipOptions
from .exceptions import PyEzvizError

if TYPE_CHECKING:
    from .client import EzvizClient

MAX_SAMPLE_BYTES = 16 * 1024 * 1024
MAX_SAMPLE_PACKETS = 4096
MAX_PROBE_STREAMS = 64
MAX_PROBE_JSON_BYTES = 65536
MAX_REMUX_BYTES = 32 * 1024 * 1024


def validate_media_sample(data: bytes) -> None:
    """Reject oversized/non-byte samples before starting a subprocess."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_SAMPLE_BYTES:
        raise ValueError("Supply 1 byte to 16 MiB of clear encoded media")


def _validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("Sample timeout must be positive and at most 30 seconds")


def _input_args(data: bytes) -> list[str]:
    # Only pipe input is permitted. A playlist/sample must never dereference
    # network URLs or local files. No caller-provided command fragments.
    return [
        "-protocol_whitelist",
        "pipe",
        "-probesize",
        str(len(data)),
        "-analyzeduration",
        "5000000",
        "-max_streams",
        str(MAX_PROBE_STREAMS),
        "-i",
        "pipe:0",
    ]


def inspect_media_sample(
    data: bytes,
    *,
    timeout: float = 10.0,
    decode: bool = False,
    ffprobe_path: str = "ffprobe",
    ffmpeg_path: str = "ffmpeg",
) -> dict[str, Any]:
    """Observe tracks, optionally decode all A/V tracks; never claim HA proof.

    Output includes no paths, tags, extradata or subprocess diagnostic strings.
    Stream index identifies an encoded track, not a physical lens. HEVC browser
    support and audio/container compatibility require actual HA validation.
    """
    validate_media_sample(data)
    _validate_timeout(timeout)
    result: dict[str, Any] = {
        "status": "unknown",
        "error_type": None,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "tracks": [],
        "decode_status": "not_tested",
        "ha_verified": False,
    }
    fields = (
        "index,id,codec_type,codec_name,profile,width,height,pix_fmt,"
        "sample_rate,channels,r_frame_rate,avg_frame_rate,time_base"
    )
    try:
        probe = subprocess.run(
            [
                ffprobe_path,
                "-v",
                "quiet",
                *_input_args(data),
                "-show_entries",
                f"stream={fields}",
                "-of",
                "json",
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        if probe.returncode or len(probe.stdout) > MAX_PROBE_JSON_BYTES:
            result["error_type"] = "MediaProbeFailed"
            return result
        tracks = json.loads(probe.stdout).get("streams", [])
        if not isinstance(tracks, list) or not tracks or len(tracks) > MAX_PROBE_STREAMS:
            result["error_type"] = "NoMediaTracks"
            return result
        allowed = set(fields.split(","))
        result["tracks"] = [
            {key: value for key, value in track.items() if key in allowed} for track in tracks
        ]
        result["status"] = "observed"
        if decode:
            decoded = subprocess.run(
                [
                    ffmpeg_path,
                    "-v",
                    "quiet",
                    "-xerror",
                    "-abort_on",
                    "empty_output+empty_output_stream",
                    *_input_args(data),
                    "-map",
                    "0:v?",
                    "-map",
                    "0:a?",
                    "-f",
                    "null",
                    "-",
                ],
                input=data,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
            result["decode_status"] = "passed" if decoded.returncode == 0 else "failed"
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError, AttributeError) as err:
        result["error_type"] = type(err).__name__
        if result["status"] == "observed" and decode:
            result["decode_status"] = "unknown"
    return result


class _SampleBuffer(io.BytesIO):
    def write(self, data: Any) -> int:
        if self.tell() + len(data) > MAX_SAMPLE_BYTES:
            raise PyEzvizError("Encoded sample exceeds the 16 MiB output budget")
        return super().write(data)


def capture_media_sample(client: EzvizClient, serial: str, options: ClipOptions) -> bytes:
    """Explicit live acquisition using the existing typed capture API.

    Not called by fleet inventory. Requires duration AND packet bounds before
    opening anything. Source options still determine credentials/cloud policy;
    use supplied local credentials and disable registration/fallback for LAN.
    The byte budget bounds returned output, NOT encrypted transport bytes or
    intermediate allocations in existing native remux implementations.
    """
    duration = options.capture.duration_seconds
    packets = options.capture.max_packets
    if duration is None:
        raise ValueError("Sample acquisition requires a duration bound")
    _validate_timeout(duration)
    if (
        isinstance(packets, bool)
        or not isinstance(packets, int)
        or not 0 < packets <= MAX_SAMPLE_PACKETS
    ):
        raise ValueError("Sample acquisition requires 1 to 4096 packets")
    if options.capture.max_bytes is not None:
        raise ValueError("Typed clip capture does not support transport byte limits")
    with _SampleBuffer() as output:
        client.save_clip_with_options(serial, cast(BinaryIO, output), options)
        data = output.getvalue()
    validate_media_sample(data)
    return data


@dataclass(frozen=True)
class EncodedTrackSelection:
    """Absolute input stream indices; never implicitly choose/compose a lens."""

    video: int
    audio: int | None = None

    def __post_init__(self) -> None:
        if self.video is None:
            raise ValueError("Select a video track explicitly")
        for index in (self.video, self.audio):
            if index is not None and (
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 0 <= index < MAX_PROBE_STREAMS
            ):
                raise ValueError("Track indices must be integers between 0 and 63")
        if self.audio == self.video:
            raise ValueError("Video and audio must select different tracks")


def remux_media_sample(
    data: bytes,
    selection: EncodedTrackSelection,
    *,
    timeout: float = 10.0,
    ffmpeg_path: str = "ffmpeg",
    ffprobe_path: str = "ffprobe",
) -> bytes:
    """Stage a finite MPEG-TS stream-copy response for a headless adapter.

    Explicit H.264/HEVC video and optional AAC audio only. Reject other codecs
    rather than silently drop or transcode them. Original timestamps/encoded
    source NALs are retained; MPEG-TS may add access-unit delimiters and rescale
    timestamps, so whole demuxed packet hashes need not match. No frame pairing,
    timestamp repair or synthetic silence. This is NOT a continuous SDK URL.
    """
    validate_media_sample(data)
    _validate_timeout(timeout)
    evidence = inspect_media_sample(data, timeout=timeout, ffprobe_path=ffprobe_path)
    tracks = {track["index"]: track for track in evidence["tracks"]}
    video = tracks.get(selection.video, {})
    audio = tracks.get(selection.audio, {}) if selection.audio is not None else None
    if video.get("codec_type") != "video" or video.get("codec_name") not in {"h264", "hevc"}:
        raise PyEzvizError("Select an observed H.264 or HEVC video track")
    if audio is not None and (
        audio.get("codec_type") != "audio" or audio.get("codec_name") != "aac"
    ):
        raise PyEzvizError("Select an observed AAC audio track or explicitly omit audio")
    command = [ffmpeg_path, "-v", "quiet", *_input_args(data), "-map", f"0:{selection.video}"]
    if selection.audio is not None:
        command.extend(("-map", f"0:{selection.audio}"))
    command.extend(
        (
            "-c",
            "copy",
            "-copyts",
            "-mpegts_copyts",
            "1",
            "-muxdelay",
            "0",
            "-fs",
            str(MAX_REMUX_BYTES + 65536),
            "-f",
            "mpegts",
            "pipe:1",
        )
    )
    try:
        # FFmpeg's own output limit bounds staging; check before publishing any
        # bytes. No application writer thread survives cancellation or timeout.
        with TemporaryFile() as output:
            process = subprocess.run(
                command,
                input=data,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
            output.seek(0)
            result = output.read(MAX_REMUX_BYTES + 1)
        if process.returncode or not result or len(result) >= MAX_REMUX_BYTES:
            raise PyEzvizError("Encoded sample remux failed or exhausted its output budget")
    except (OSError, subprocess.TimeoutExpired) as err:
        raise PyEzvizError("Encoded sample remux could not complete") from err
    return result
