"""Explicit, read-only fleet inventory and bounded encoded-media evidence.

Camera configuration, advertised combinations, observed tracks and decoder
success are separate evidence. None of them certifies a Home Assistant client.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
import math
import ssl
from typing import Any

from .exceptions import PyEzvizError
from .hcnetsdk import (
    HcNetSdkLanEndpoint,
    HcNetSdkLoginCandidate,
    discover_hcnetsdk_stream_details_for_login,
)
from .hcnetsdk_parameters import normalize_hcnetsdk_parameters
from .stream_sample import inspect_media_sample, validate_media_sample

MAX_FLEET_TARGETS = 64
MAX_FLEET_SAMPLE_BYTES = 64 * 1024 * 1024


def _codec_choices(native_range: str | None, *, audio: bool = False) -> list[dict[str, Any]]:
    """Name enumerated IDs in their SDK namespace; never expand range syntax."""
    choices: list[dict[str, Any]] = []
    for raw_token in (native_range or "").split(","):
        token = raw_token.strip()
        if not token:
            continue
        try:
            code = int(token)
        except ValueError:
            # XML also permits textual labels (e.g. ambiguous G.711). Preserve
            # them visibly without guessing a variant or expanding range syntax.
            choices.append({"native_code": None, "codec": None, "advertised_value": token})
            continue
        normalized = normalize_hcnetsdk_parameters(
            video_encoding_type=-1 if audio else code,
            audio_encoding_type=code if audio else -1,
            video_frame_rate=-1,
            video_bitrate=-1,
            audio_sampling_rate=-1,
            format_type=-1,
        )
        choices.append(
            {
                "native_code": code,
                "codec": normalized.audio_codec if audio else normalized.video_codec,
            }
        )
    return choices


def _advertised_codecs(configuration: dict[str, Any]) -> dict[str, Any]:
    """Separate video/audio offers; no invented cross-product or lens mapping."""
    capabilities = configuration["capabilities"]
    video = []
    for channel in capabilities["video_channels"]:
        profiles = [
            ("main", channel["main_stream"]),
            *[("sub", sub) for sub in channel["sub_streams"]],
        ]
        for profile, stream in profiles:
            if stream is not None:
                video.append(
                    {
                        "channel": channel["channel_number"],
                        "profile": profile,
                        "profile_index": stream["index"],
                        "choices": _codec_choices(stream["video_encode_type_range"]),
                    }
                )
    audio = []
    for channel in capabilities["audio_channels"]:
        audio.append(
            {
                "channel": channel["channel_number"],
                "main": _codec_choices(channel["main_audio_encode_type_range"], audio=True),
                "sub": _codec_choices(channel["sub_audio_encode_type_range"], audio=True),
            }
        )
    return {"video": video, "audio": audio}


@dataclass(frozen=True)
class StreamCapabilityTarget:
    """One caller-selected native configuration channel and login, not a scan.

    ``channel`` is the 1-based configuration channel. It is NOT an SDK preview
    channel or a main/sub selector. Credentials/endpoints never enter reports.
    Use non-identifying aliases if the resulting report will be shared.
    """

    alias: str
    endpoint: HcNetSdkLanEndpoint = field(repr=False)
    login: HcNetSdkLoginCandidate = field(repr=False)
    channel: int = 1
    tls_context: ssl.SSLContext | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.alias, str)
            or not self.alias
            or len(self.alias) > 64
            or not all(char.isalnum() or char in "_-" for char in self.alias)
        ):
            raise ValueError("Use a nonempty camera alias of at most 64 letters, digits, _ or -")
        if (
            isinstance(self.channel, bool)
            or not isinstance(self.channel, int)
            or not 1 <= self.channel <= 255
        ):
            raise ValueError("Configuration channel must be an integer between 1 and 255")
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.endpoint.host, self.endpoint.serial)
        ):
            raise ValueError("Supply an explicit camera endpoint and serial")
        if self.login.api not in {"NET_DVR_Login_V30", "NET_DVR_Login_V40"}:
            raise ValueError("Select an explicit native V30 or V40 login profile")
        if not isinstance(self.login.https, bool) or (
            self.login.https and self.login.api != "NET_DVR_Login_V40"
        ):
            raise ValueError("Native TLS requires an explicit V40 login profile")
        if (
            isinstance(self.login.port, bool)
            or not isinstance(self.login.port, int)
            or not 1 <= self.login.port <= 65535
        ):
            raise ValueError("Supply a valid native login port")
        if any(
            not isinstance(value, str) or not value
            for value in (self.login.username, self.login.password)
        ):
            raise ValueError("Supply explicit local credentials")
        if self.tls_context is not None and not isinstance(self.tls_context, ssl.SSLContext):
            raise ValueError("Supply an SSLContext for TLS verification")
        if self.tls_context is not None and not self.login.https:
            raise ValueError("TLS context requires a TLS login profile")


@dataclass(frozen=True)
class StreamSampleEvidence:
    """Caller-attested source of a bounded, already decrypted media sample.

    ``profile`` is a label, never translated into a guessed channel number.
    A capture from an unknown profile must be labelled ``unknown``. Evidence
    belongs only to this sample, not every advertised codec/profile combination.
    """

    alias: str
    channel: int
    profile: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.channel, bool)
            or not isinstance(self.channel, int)
            or not 1 <= self.channel <= 255
        ):
            raise ValueError("Sample configuration channel must be between 1 and 255")
        if self.profile not in {"main", "sub", "unknown"}:
            raise ValueError("Sample profile must be main, sub or unknown")


def probe_stream_capabilities(
    targets: Sequence[StreamCapabilityTarget],
    *,
    timeout: float = 10.0,
    samples: Sequence[StreamSampleEvidence] = (),
    decode_samples: bool = False,
    ffprobe_path: str = "ffprobe",
    ffmpeg_path: str = "ffmpeg",
) -> dict[str, Any]:
    """Query supplied targets sequentially, with no preview or cloud calls.

    Each camera gets one explicit login and a finite network deadline. Failed
    authentication/transport/ability queries remain unknown, never unsupported.
    Optional saved samples are inspected locally, without reacquiring a camera.
    Exception messages, serials, addresses, credentials and packet bodies are
    deliberately omitted from the JSON-compatible result. Callers own aliases.
    """
    if isinstance(timeout, bool) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("Per-target timeout must be positive and at most 30 seconds")
    if not 0 < len(targets) <= MAX_FLEET_TARGETS:
        raise ValueError("Supply between 1 and 64 explicit targets per batch")
    identities = {(target.alias, target.channel) for target in targets}
    if len(identities) != len(targets):
        raise ValueError("Duplicate camera alias/configuration channel")
    sample_keys = [(sample.alias, sample.channel, sample.profile) for sample in samples]
    if len(set(sample_keys)) != len(sample_keys):
        raise ValueError("Duplicate sample identity/profile")
    if any((sample.alias, sample.channel) not in identities for sample in samples):
        raise ValueError("Sample identity does not match an explicit target")
    # Validate all sample budgets before the first network side effect.
    for sample in samples:
        validate_media_sample(sample.data)
    if sum(len(sample.data) for sample in samples) > MAX_FLEET_SAMPLE_BYTES:
        raise ValueError("Saved fleet samples exceed 64 MiB per batch")
    entries: list[dict[str, Any]] = []
    for target in targets:
        entry: dict[str, Any] = {
            "alias": target.alias,
            "configuration_channel": target.channel,
            "metadata_status": "unknown",
            "error_type": None,
            "configuration": None,
            "advertised_codecs": None,
            "samples": [],
            "ha_verified": False,
        }
        try:
            details = discover_hcnetsdk_stream_details_for_login(
                target.endpoint,
                target.login,
                channel=target.channel,
                tls_context=target.tls_context,
                timeout=timeout,
            )
        except (PyEzvizError, OSError, ValueError) as err:
            # Fleet isolation boundary: a rejected camera must not hide others.
            # KeyboardInterrupt/SystemExit intentionally propagate.
            entry["error_type"] = type(err).__name__
        else:
            configuration = details.as_dict()
            configuration.pop("reported_login_serial", None)
            entry["configuration"] = configuration
            entry["advertised_codecs"] = _advertised_codecs(configuration)
            entry["metadata_status"] = (
                "configured" if details.capabilities_error is not None else "advertised"
            )
        for sample in samples:
            if (sample.alias, sample.channel) == (target.alias, target.channel):
                entry["samples"].append(
                    {
                        "profile": sample.profile,
                        "association": "caller_supplied",
                        **inspect_media_sample(
                            sample.data,
                            timeout=timeout,
                            decode=decode_samples,
                            ffprobe_path=ffprobe_path,
                            ffmpeg_path=ffmpeg_path,
                        ),
                    }
                )
        entries.append(entry)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "live_acquisition": False,
        "targets": entries,
    }
