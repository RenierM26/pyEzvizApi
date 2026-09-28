"""Typed configuration for camera clip capture."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from .constants import LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT, MAX_RETRIES
from .local_stream_transport import (
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortMultiSocketPlan,
)
from .media import CaptureLimits, MediaDecodeOptions, MediaMuxOptions

ClipSource = Literal["local-sdk", "local-sdk-ecdh", "hcnetsdk-command-port", "cloud"]
ClipOutputFormat = Literal["mpegps", "mpegts"]


@dataclass(frozen=True)
class LocalSdkClipSource:
    """Connection options for the direct local SDK stream."""

    kind: Literal["local-sdk"] = field(default="local-sdk", init=False)
    cas_serial: str | None = None
    register_p2p_session: bool = True
    p2p_register_max_retries: int = MAX_RETRIES
    timeout: float | None = 10.0
    smscode: str | int | None = field(default=None, repr=False)


@dataclass(frozen=True)
class LocalSdkEcdhClipSource:
    """Connection options for the local SDK ECDH stream."""

    kind: Literal["local-sdk-ecdh"] = field(default="local-sdk-ecdh", init=False)
    cas_serial: str | None = None
    register_p2p_session: bool = True
    p2p_register_max_retries: int = MAX_RETRIES
    timeout: float | None = 10.0
    smscode: str | int | None = field(default=None, repr=False)
    receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
    send_init: bool = False
    max_prefix_bytes: int = 4096
    max_frames: int | None = None


@dataclass(frozen=True)
class HcNetSdkCommandPortClipSource:
    """Connection and bootstrap options for an HCNetSDK command stream."""

    kind: Literal["hcnetsdk-command-port"] = field(default="hcnetsdk-command-port", init=False)
    host: str | None = None
    command_port: int | None = None
    command_frames: Iterable[bytes] | None = field(default=None, repr=False)
    command_plan: HcNetSdkCommandPortMultiSocketPlan | None = field(default=None, repr=False)
    generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan | None = field(
        default=None, repr=False
    )
    command_password: str | bytes | None = field(default=None, repr=False)
    local_ip: str | None = None
    read_response_after_each: bool | Iterable[bool] = field(default=True, repr=False)
    metadata_callback: Callable[[Any], None] | None = field(default=None, repr=False, compare=False)
    timeout: float | None = 10.0


@dataclass(frozen=True)
class CloudClipSource:
    """Connection options for an EZVIZ VTM cloud stream."""

    kind: Literal["cloud"] = field(default="cloud", init=False)
    client_type: int = 9
    token_index: int = 0
    refresh_vtm: bool = True
    timeout: float | None = 10.0
    smscode: str | int | None = field(default=None, repr=False)


type ClipSourceOptions = (
    LocalSdkClipSource | LocalSdkEcdhClipSource | HcNetSdkCommandPortClipSource | CloudClipSource
)


@dataclass(frozen=True)
class ClipOptions:
    """Complete typed configuration for :meth:`EzvizClient.save_clip_with_options`."""

    source: ClipSourceOptions = field(default_factory=LocalSdkClipSource)
    capture: CaptureLimits = field(default_factory=lambda: CaptureLimits(duration_seconds=10.0))
    decode: MediaDecodeOptions = field(
        default_factory=lambda: MediaDecodeOptions(nalu_header_size=0)
    )
    mux: MediaMuxOptions | None = None
    channel: int = 1

    def resolved_mux(self) -> MediaMuxOptions:
        """Return explicit mux settings or the source-compatible default."""

        if self.mux is not None:
            return self.mux
        if isinstance(self.source, LocalSdkEcdhClipSource):
            return MediaMuxOptions(output_format="mpegps")
        return MediaMuxOptions()
