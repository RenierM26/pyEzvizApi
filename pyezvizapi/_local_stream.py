"""Local EZVIZ stream adapters with native MPEG-PS output."""

from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import ipaddress
from itertools import chain, pairwise
from pathlib import Path
import subprocess
import tempfile
from threading import Event, Lock, Thread
import time
from typing import Any, BinaryIO, Literal, cast

from Crypto.Cipher import AES

from .cas import CasDeviceSession, EzvizCAS
from .constants import (
    IDMX_DEFAULT_VIDEO_FRAME_RATE,
    IDMX_VIDEO_RTP_CLOCK_RATE,
    MAX_RETRIES,
)
from .exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from .hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoExAttrs,
    EzvizLocalSdkClient,
    EzvizLocalSdkStreamBootstrap,
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkCommandPortExchange,
    HcNetSdkCommandPortLoginSession,
    HcNetSdkCommandPortStreamBootstrap,
    HcNetSdkLanEndpoint,
    HcNetSdkRealDataPacket,
    SocketFactory,
    hcnetsdk_command_port_control_template_from_frame,
    hcnetsdk_command_port_rsa_key,
    iter_hcnetsdk_real_data_mpegps,
)
from .media import (
    LegacyPacketSource,
    MediaPacket,
    MediaPacketMetadata,
    MediaPacketSourceAdapter,
    has_positive_finite_capture_bound,
    is_positive_finite_duration_bound,
)
from .remux import (
    BoundedStderrTail,
    copy_remuxed_output,
    open_mpegts_remux_process,
    start_stderr_drain,
)
from .rtp import (
    DEFAULT_AAC_PAYLOAD_TYPES,
    RtpAacStream,
    RtpPacket,
    RtpRouteProfile,
    RtpStreamDescriptor,
    RtpVideoCodec,
    RtpVideoDepacketizer,
    decrypt_idmx_aac_packets,
    idmx_rtp_stream_descriptors,
    parse_rtp_packet,
    rtp_packet_has_valid_idmx_aac_frame,
    rtp_packet_is_idmx_aac,
    rtp_payload,
    rtp_payload_video_codec,
)
from .stream_media import (
    ANNEX_B_LONG_START_CODE,
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
    MPEG_PS_START_CODE,
    MPEG_START_CODE_PREFIX,
    _hikvision_aes_ecb_cipher,
    decrypt_hikvision_ps_video,
)

HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = "app-lan-live-view"

_COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS = {
    "Unsupported RTP version",
    "RTP packet is too short",
    "RTP CSRC header exceeds packet length",
    "RTP extension header exceeds packet length",
    "RTP extension payload exceeds packet length",
    "RTP padding set without payload",
    "Invalid RTP padding length",
}
_CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS = 16
_CLEAN_WINDOW_PROBE_PACKET_INTERVAL = 32
_CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL = 256
_CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES = 8
_FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS = 1
_FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS = 10
_FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND = 2_000_000

_HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL = bytes.fromhex(
    "000000083c417564696f566964656f436f6d7072657373496e666f3e"
    "3c566964656f4368616e6e656c4e756d6265723e313c2f566964656f"
    "4368616e6e656c4e756d6265723e3c2f417564696f566964656f436f"
    "6d7072657373496e666f3e"
)

_HCNETSDK_APP_LAN_PLAY_LOGIN_TAIL = bytes.fromhex(
    "00000001000000ff000000ff0000000000000000000000000000000000000000"
    "00000000000007ea000000050000001f000000000000000000000000000007ea"
    "000000050000001f000000170000003b0000003b000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000"
)


@dataclass(frozen=True)
class EzvizLocalStreamPacket:
    """One local SDK media packet converted to an MPEG-PS payload."""

    channel: int
    length: int
    body: bytes
    encrypted: bool = False
    prefix: bytes = b""


def local_stream_packet_to_media_packet(packet: EzvizLocalStreamPacket) -> MediaPacket:
    """Normalize a local SDK packet without changing its transport model."""

    return MediaPacket(
        body=packet.body,
        metadata=MediaPacketMetadata(
            source="local_sdk",
            channel=packet.channel,
            encrypted=packet.encrypted,
            attributes={"prefix_length": len(packet.prefix)},
        ),
    )


def local_media_packet_source(
    stream: LegacyPacketSource[EzvizLocalStreamPacket],
) -> MediaPacketSourceAdapter[EzvizLocalStreamPacket]:
    """Adapt an existing local SDK stream to the shared packet contract."""

    prepare_startup = getattr(stream, "prepare_startup", None)
    return MediaPacketSourceAdapter(
        stream,
        local_stream_packet_to_media_packet,
        duration_from_start=bool(
            getattr(stream, "supports_startup_deadline_iter_packets", False)
        ),
        prepare=prepare_startup if callable(prepare_startup) else None,
    )


@dataclass(frozen=True)
class HcNetSdkCommandPortKeepaliveEvent:
    """Safe timing metadata for one command-port keepalive send attempt."""

    index: int
    command_id: int | None
    elapsed_seconds: float
    sent: bool
    error: str | None = None


@dataclass(frozen=True)
class _H264CleanIdrProbeResult:
    """Result of probing partial H.264 Annex-B IDR windows."""

    start_offset: int | None
    idr_start_offset: int | None = None
    prefix: bytes = b""
    first_decode_error: str | None = None
    idr_count: int = 0
    sampled_window_count: int = 0
    complete_window_count: int = 0
    nal_count: int = 0
    codec_name: str = "H.264"
    window_name: str = "IDR"


@dataclass
class _RtpFragmentedNal:
    """In-progress fragmented NAL with RTP continuity state."""

    data: bytearray
    last_sequence: int | None
    rtp_timestamp: int | None


_IdmxAacStream = RtpAacStream


@dataclass(frozen=True)
class HcNetSdkCommandPortSocketStep:
    """One socket in an HCNetSDK command-port bootstrap plan.

    The EZVIZ app uses several short-lived command sockets before opening the
    long-lived media socket. A step marked ``media_socket`` is kept open and
    later used for interleaved media reads; other steps are closed after their
    command frames and expected responses have been exchanged.
    """

    command_frames: tuple[bytes, ...]
    read_response_after_each: bool | tuple[bool, ...] = True
    response_reads_after_each: int | tuple[int, ...] | None = None
    media_socket: bool = False
    read_first_media_immediately: bool = False
    delay_after_commands_seconds: float = 0.0
    drain_media_before_next_step_seconds: float = 0.0
    keepalive_frames: tuple[bytes, ...] = ()
    keepalive_interval_seconds: float = 5.0
    keepalive_initial_delay_seconds: float | None = None
    name: str | None = None


@dataclass(frozen=True)
class HcNetSdkCommandPortGeneratedSocketStep:
    """One generated command-port socket step before session-bound rendering."""

    control_templates: tuple[HcNetSdkCommandPortControlTemplate, ...]
    read_response_after_each: bool | tuple[bool, ...] = True
    response_reads_after_each: int | tuple[int, ...] | None = None
    media_socket: bool = False
    read_first_media_immediately: bool = False
    delay_after_commands_seconds: float = 0.0
    drain_media_before_next_step_seconds: float = 0.0
    keepalive_templates: tuple[HcNetSdkCommandPortControlTemplate, ...] = ()
    keepalive_interval_seconds: float = 5.0
    keepalive_initial_delay_seconds: float | None = None
    name: str | None = None

    def to_socket_step(
        self,
        *,
        session_id: bytes,
        auth_seed: int,
        key: bytes,
        local_ip: str,
    ) -> HcNetSdkCommandPortSocketStep:
        """Render this template step into executable command frames."""
        return HcNetSdkCommandPortSocketStep(
            command_frames=tuple(
                template.to_frame(
                    session_id=session_id,
                    auth_seed=auth_seed,
                    key=key,
                    local_ip=local_ip,
                )
                for template in self.control_templates
            ),
            read_response_after_each=self.read_response_after_each,
            response_reads_after_each=self.response_reads_after_each,
            media_socket=self.media_socket,
            read_first_media_immediately=self.read_first_media_immediately,
            delay_after_commands_seconds=self.delay_after_commands_seconds,
            drain_media_before_next_step_seconds=(
                self.drain_media_before_next_step_seconds
            ),
            keepalive_frames=tuple(
                template.to_frame(
                    session_id=session_id,
                    auth_seed=auth_seed,
                    key=key,
                    local_ip=local_ip,
                )
                for template in self.keepalive_templates
            ),
            keepalive_interval_seconds=self.keepalive_interval_seconds,
            keepalive_initial_delay_seconds=self.keepalive_initial_delay_seconds,
            name=self.name,
        )


@dataclass(frozen=True)
class HcNetSdkCommandPortMultiSocketPlan:
    """Native-style command-port socket sequence for port-8000 media."""

    steps: tuple[HcNetSdkCommandPortSocketStep, ...]

    def __post_init__(self) -> None:  # noqa: PLR0912
        if not self.steps:
            raise PyEzvizError("HCNetSDK command-port socket plan is empty")
        media_steps = [step for step in self.steps if step.media_socket]
        if len(media_steps) != 1:
            raise PyEzvizError(
                "HCNetSDK command-port socket plan requires exactly one media socket"
            )
        for step in self.steps:
            if not step.command_frames:
                raise PyEzvizError("HCNetSDK command-port socket step has no frames")
            if isinstance(step.read_response_after_each, tuple) and len(
                step.read_response_after_each
            ) != len(step.command_frames):
                raise PyEzvizError(
                    "HCNetSDK response-read policy length must match command frames"
                )
            if isinstance(step.response_reads_after_each, tuple) and len(
                step.response_reads_after_each
            ) != len(step.command_frames):
                raise PyEzvizError(
                    "HCNetSDK response-read count length must match command frames"
                )
            response_counts = _hcnetsdk_step_response_counts(step)
            if any(count < 0 for count in response_counts):
                raise PyEzvizError("HCNetSDK response-read count must be non-negative")
            if step.read_first_media_immediately and not step.media_socket:
                raise PyEzvizError(
                    "HCNetSDK immediate first-media read requires a media socket step"
                )
            if step.delay_after_commands_seconds < 0:
                raise PyEzvizError("HCNetSDK command step delay must be non-negative")
            if step.drain_media_before_next_step_seconds < 0:
                raise PyEzvizError("HCNetSDK command media drain must be non-negative")
            if (
                step.drain_media_before_next_step_seconds
                and not step.media_socket
            ):
                raise PyEzvizError(
                    "HCNetSDK command media drain requires a media socket step"
                )
            if step.keepalive_interval_seconds < 0:
                raise PyEzvizError("HCNetSDK keepalive interval must be non-negative")
            if (
                step.keepalive_initial_delay_seconds is not None
                and step.keepalive_initial_delay_seconds < 0
            ):
                raise PyEzvizError(
                    "HCNetSDK keepalive initial delay must be non-negative"
                )


@dataclass(frozen=True)
class HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Generated native-style command-port plan template."""

    steps: tuple[HcNetSdkCommandPortGeneratedSocketStep, ...]

    def to_socket_plan(
        self,
        *,
        session_id: bytes,
        auth_seed: int,
        key: bytes,
        local_ip: str,
    ) -> HcNetSdkCommandPortMultiSocketPlan:
        """Render this generated template with fresh login/session values."""
        return HcNetSdkCommandPortMultiSocketPlan(
            steps=tuple(
                step.to_socket_step(
                    session_id=session_id,
                    auth_seed=auth_seed,
                    key=key,
                    local_ip=local_ip,
                )
                for step in self.steps
            )
        )


def hcnetsdk_command_port_native_lan_live_view_plan(
    name: str = HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Return an app-observed generated port-8000 LAN live-view plan.

    The default plan mirrors the EZVIZ Android app's HCNetSDK LAN preview
    sequence observed against the Husky camera: capability probes, play-login,
    native-prefix media socket, bounded media keepalives, then an I-frame
    request. The media socket deliberately keeps the native 64-byte ``IMKH``
    response as prefix before the first media frame by not reading it as a
    control response.
    """
    if name != HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW:
        raise PyEzvizError(f"Unsupported HCNetSDK native command-port plan: {name}")
    return HcNetSdkCommandPortGeneratedMultiSocketPlan(
        steps=(
            _hcnetsdk_generated_step(
                "control-0",
                _hcnetsdk_template(0x11000, "00000001", addend_delta=0),
            ),
            _hcnetsdk_generated_step(
                "control-1",
                _hcnetsdk_template(
                    0x11000,
                    "000000113c5265636f72644162696c6974792076657273696f6e3d22322e30222f3e",
                    addend_delta=0,
                ),
            ),
            _hcnetsdk_generated_step(
                "control-2",
                _hcnetsdk_template(
                    0x11000,
                    "000000113c50545a4162696c6974792076657273696f6e3d22322e30223e"
                    "3c6368616e6e656c4e4f3e313c2f6368616e6e656c4e4f3e"
                    "3c2f50545a4162696c6974793e",
                    addend_delta=0,
                ),
            ),
            _hcnetsdk_generated_step(
                "control-3",
                HcNetSdkCommandPortControlTemplate(
                    command_id=0x11000,
                    body_tail=_HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL,
                    addend_delta=0,
                ),
            ),
            _hcnetsdk_generated_step(
                "control-4",
                HcNetSdkCommandPortControlTemplate(
                    command_id=0x11000,
                    body_tail=_HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL,
                    addend_delta=0,
                ),
            ),
            _hcnetsdk_generated_step(
                "control-5",
                HcNetSdkCommandPortControlTemplate(
                    command_id=0x11000,
                    body_tail=_HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL,
                    addend_delta=0,
                ),
            ),
            _hcnetsdk_generated_step(
                "control-111050",
                HcNetSdkCommandPortControlTemplate(
                    command_id=0x111050,
                    addend_delta=2,
                ),
            ),
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x111040,
                        body_tail=_HCNETSDK_APP_LAN_PLAY_LOGIN_TAIL,
                        addend_delta=4,
                        body_tail_transform="play_login_today",
                    ),
                ),
                response_reads_after_each=1,
                name="play-login",
            ),
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    _hcnetsdk_template(
                        0x30000,
                        "000000010000000000000401",
                        addend_delta=5,
                    ),
                ),
                read_response_after_each=False,
                media_socket=True,
                keepalive_templates=tuple(
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x30006,
                        addend_delta=delta,
                    )
                    for delta in (10, 16, 22, 28, 34, 40)
                ),
                keepalive_interval_seconds=5.0,
                name="media",
            ),
            _hcnetsdk_generated_step(
                "keyframe",
                _hcnetsdk_template(0x90100, "00000001", addend_delta=5),
            ),
        )
    )


def _hcnetsdk_generated_step(
    name: str,
    template: HcNetSdkCommandPortControlTemplate,
) -> HcNetSdkCommandPortGeneratedSocketStep:
    return HcNetSdkCommandPortGeneratedSocketStep((template,), name=name)


def _hcnetsdk_template(
    command_id: int,
    body_tail_hex: str,
    *,
    addend_delta: int,
) -> HcNetSdkCommandPortControlTemplate:
    return HcNetSdkCommandPortControlTemplate(
        command_id=command_id,
        body_tail=bytes.fromhex(body_tail_hex),
        addend_delta=addend_delta,
    )


def hcnetsdk_command_port_generated_plan_from_socket_plan(
    plan: HcNetSdkCommandPortMultiSocketPlan,
    *,
    auth_seed: int | None = None,
    key: bytes | None = None,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Extract a reusable generated plan from concrete ``0x63`` socket frames."""
    return HcNetSdkCommandPortGeneratedMultiSocketPlan(
        steps=tuple(
            HcNetSdkCommandPortGeneratedSocketStep(
                control_templates=tuple(
                    hcnetsdk_command_port_control_template_from_frame(
                        frame,
                        auth_seed=auth_seed,
                        key=key,
                    )
                    for frame in step.command_frames
                ),
                read_response_after_each=step.read_response_after_each,
                response_reads_after_each=step.response_reads_after_each,
                media_socket=step.media_socket,
                read_first_media_immediately=step.read_first_media_immediately,
                delay_after_commands_seconds=step.delay_after_commands_seconds,
                drain_media_before_next_step_seconds=(
                    step.drain_media_before_next_step_seconds
                ),
                keepalive_templates=tuple(
                    hcnetsdk_command_port_control_template_from_frame(
                        frame,
                        auth_seed=auth_seed,
                        key=key,
                    )
                    for frame in step.keepalive_frames
                ),
                keepalive_interval_seconds=step.keepalive_interval_seconds,
                keepalive_initial_delay_seconds=step.keepalive_initial_delay_seconds,
                name=step.name,
            )
            for step in plan.steps
        )
    )


def _hcnetsdk_step_response_counts(
    step: HcNetSdkCommandPortSocketStep,
) -> tuple[int, ...]:
    """Return response-frame reads expected after each command frame."""
    if step.response_reads_after_each is not None:
        if isinstance(step.response_reads_after_each, int):
            return (step.response_reads_after_each,) * len(step.command_frames)
        return step.response_reads_after_each
    if isinstance(step.read_response_after_each, bool):
        count = 1 if step.read_response_after_each else 0
        return (count,) * len(step.command_frames)
    return tuple(1 if flag else 0 for flag in step.read_response_after_each)


def _hcnetsdk_command_port_frame_with_client_ip(
    frame: bytes,
    local_ip: str | None,
) -> bytes:
    """Patch the little-endian client IPv4 word in observed command frames."""
    if local_ip is None:
        return frame
    try:
        encoded_ip = ipaddress.IPv4Address(local_ip).packed[::-1]
    except ipaddress.AddressValueError as err:
        raise PyEzvizError("HCNetSDK local IP must be an IPv4 address") from err

    if len(frame) < 8:
        return frame
    command_family = frame[4]
    if command_family == 0x63 and len(frame) >= 20:
        patched = bytearray(frame)
        patched[16:20] = encoded_ip
        return bytes(patched)
    if command_family == 0x5A and len(frame) >= 28:
        patched = bytearray(frame)
        patched[24:28] = encoded_ip
        return bytes(patched)
    return frame


def _hcnetsdk_command_port_step_context(
    step: HcNetSdkCommandPortSocketStep,
    *,
    step_index: int,
    frame_index: int | None = None,
    frame: bytes | None = None,
) -> str:
    """Return concise context for command-port socket-plan errors."""
    parts = [f"step {step_index + 1}"]
    if step.name:
        parts.append(f"'{step.name}'")
    if frame_index is not None:
        parts.append(f"frame {frame_index + 1}")
    if frame is not None and len(frame) >= 16:
        parts.append(f"command 0x{int.from_bytes(frame[12:16], 'big'):x}")
    return " ".join(parts)


@dataclass(frozen=True)
class EzvizLocalSdkCredentials:
    """Credentials and endpoint data needed for direct-local SDK streaming."""

    endpoint: HcNetSdkLanEndpoint
    device_info: EzvizCasDeviceInfo = field(repr=False)
    media_key: str | bytes | None = field(default=None, repr=False)

    def as_dict(self, *, include_media_key: bool = False) -> dict[str, Any]:
        """Return a JSON-friendly representation for explicit inspection flows."""
        result: dict[str, Any] = {
            "serial": self.device_info.serial,
            "endpoint": {
                "host": self.endpoint.host,
                "command_port": self.endpoint.command_port,
                "stream_port": self.endpoint.stream_port,
            },
            "cas": {
                "operation_code": self.device_info.operation_code,
                "key": self.device_info.key,
                "encrypt_type": self.device_info.encrypt_type,
            },
        }
        if include_media_key and self.media_key is not None:
            if isinstance(self.media_key, bytes):
                result["media_key_hex"] = self.media_key.hex()
            else:
                result["media_key"] = self.media_key
        return result


LocalSdkOutputFormat = Literal["mpegps", "mpegts"]
_INTERRUPTED_LOCAL_STREAM_MESSAGE = (
    "Local stream cannot resume after a capture deadline interrupted a frame read"
)


def _remaining_capture_timeout(
    deadline: float | None,
    monotonic: Callable[[], float],
) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise EzvizLocalSdkDeadlineExpired(
            "Local stream capture exceeded its deadline"
        )
    return remaining


class EzvizLocalSdkMediaStream:
    """Direct-local SDK media stream compatible with the cloud stream dump path.

    This adapter is for the CAS/local-SDK socket family, where Python can
    bootstrap ``0x2011``/``0x3105`` and then read interleaved RTP frames from
    the stream socket. It intentionally does not claim to implement the
    proprietary HCNetSDK command protocol on port 8000.
    """

    supports_deadline_iter_packets = True
    supports_startup_deadline_iter_packets = True

    def __init__(
        self,
        sdk_client: EzvizLocalSdkClient,
        preview_request: EzvizLocalPreviewRequest,
        *,
        pre_start_body: bytes | str | None = None,
        pre_start_sequence: int = 0,
        preview_sequence: int = 0,
        stream_setup_sequence: int = 0,
        stream_rate: str | int = 0,
        stream_mode: str | int = 0,
        max_prefix_bytes: int = 4096,
    ) -> None:
        self.sdk_client = sdk_client
        self.preview_request = preview_request
        self.pre_start_body = pre_start_body
        self.pre_start_sequence = pre_start_sequence
        self.preview_sequence = preview_sequence
        self.stream_setup_sequence = stream_setup_sequence
        self.stream_rate = stream_rate
        self.stream_mode = stream_mode
        self.max_prefix_bytes = max_prefix_bytes
        self.bootstrap: EzvizLocalSdkStreamBootstrap | None = None
        self._first_media: EzvizInterleavedRtpFrameWithPrefix | None = None
        self._read_interrupted = False

    def __enter__(self) -> EzvizLocalSdkMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying local SDK sockets."""
        self.sdk_client.close()

    def start(
        self,
        *,
        read_first_media: bool = True,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap preview setup and read the first local RTP media frame."""
        self.bootstrap = self.sdk_client.bootstrap_preview_from_fields(
            preview_request=self.preview_request,
            pre_start_body=self.pre_start_body,
            pre_start_sequence=self.pre_start_sequence,
            preview_sequence=self.preview_sequence,
            stream_setup_sequence=self.stream_setup_sequence,
            stream_rate=self.stream_rate,
            stream_mode=self.stream_mode,
            read_first_media=read_first_media,
            max_prefix_bytes=self.max_prefix_bytes,
            deadline=deadline,
            monotonic=monotonic,
        )
        self._first_media = self.bootstrap.first_media
        if read_first_media and self._first_media is None:
            raise PyEzvizError("EZVIZ local stream did not return a first media frame")
        return self.bootstrap

    def iter_packets(  # noqa: PLR0912
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield local RTP payloads as MPEG-PS packet bodies."""
        if max_packets is not None and max_packets <= 0:
            return
        if duration_seconds is not None and duration_seconds <= 0:
            return
        if self._read_interrupted:
            raise PyEzvizError(_INTERRUPTED_LOCAL_STREAM_MESSAGE)

        deadline = (
            monotonic() + duration_seconds
            if duration_from_start and duration_seconds is not None
            else None
        )
        if self.bootstrap is None:
            try:
                self.start(
                    read_first_media=not duration_from_start,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                return

        emitted = 0
        if self._first_media is not None:
            if duration_seconds is not None and deadline is None:
                deadline = monotonic() + duration_seconds
            first_media = self._first_media
            self._first_media = None
            yield _local_media_packet(first_media)
            emitted += 1

        while max_packets is None or emitted < max_packets:
            remaining = None
            if deadline is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
            try:
                if remaining is None:
                    media = self.sdk_client.read_stream_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                    )
                else:
                    media = self.sdk_client.read_stream_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                        timeout=remaining,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                break
            if deadline is None and duration_seconds is not None:
                deadline = monotonic() + duration_seconds
            yield _local_media_packet(media)
            emitted += 1


class HcNetSdkCommandPortMediaStream:
    """Port-8000 HCNetSDK media stream using caller-supplied command frames."""

    supports_deadline_iter_packets = True
    supports_startup_deadline_iter_packets = True

    def __init__(
        self,
        command_client: HcNetSdkCommandPortClient,
        command_frames: Iterable[bytes],
        *,
        read_response_after_each: bool | Iterable[bool] = True,
        read_first_media: bool = True,
        max_prefix_bytes: int = 4096,
        local_ip: str | None = None,
    ) -> None:
        self.command_client = command_client
        self.command_frames = tuple(
            _hcnetsdk_command_port_frame_with_client_ip(frame, local_ip)
            for frame in command_frames
        )
        self.read_response_after_each = read_response_after_each
        self.read_first_media = read_first_media
        self.max_prefix_bytes = max_prefix_bytes
        self.bootstrap: HcNetSdkCommandPortStreamBootstrap | None = None
        self._first_media: EzvizInterleavedRtpFrameWithPrefix | None = None
        self._read_interrupted = False

    def __enter__(self) -> HcNetSdkCommandPortMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying command-port socket."""
        self.command_client.close()

    def start(
        self,
        *,
        read_first_media: bool | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortStreamBootstrap:
        """Send bootstrap frames and read the first media frame."""
        should_read_first_media = (
            self.read_first_media if read_first_media is None else read_first_media
        )
        self.bootstrap = self.command_client.bootstrap_media_stream(
            self.command_frames,
            read_response_after_each=self.read_response_after_each,
            read_first_media=should_read_first_media,
            max_prefix_bytes=self.max_prefix_bytes,
            deadline=deadline,
            monotonic=monotonic,
        )
        self._first_media = self.bootstrap.first_media
        if should_read_first_media and self._first_media is None:
            raise PyEzvizError("HCNetSDK command-port stream did not return media")
        return self.bootstrap

    def iter_packets(  # noqa: PLR0912
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield command-port RTP payloads as MPEG-PS or IDMX packet bodies."""
        if max_packets is not None and max_packets <= 0:
            return
        if duration_seconds is not None and duration_seconds <= 0:
            return
        if self._read_interrupted:
            raise PyEzvizError(_INTERRUPTED_LOCAL_STREAM_MESSAGE)

        deadline = (
            monotonic() + duration_seconds
            if duration_from_start and duration_seconds is not None
            else None
        )
        if self.bootstrap is None:
            try:
                self.start(
                    read_first_media=None if not duration_from_start else False,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                return

        emitted = 0
        if self._first_media is not None:
            if duration_seconds is not None and deadline is None:
                deadline = monotonic() + duration_seconds
            first_media = self._first_media
            self._first_media = None
            yield _hcnetsdk_command_port_media_packet(first_media)
            emitted += 1

        while max_packets is None or emitted < max_packets:
            remaining = None
            if deadline is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
            try:
                if remaining is None:
                    media = self.command_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                    )
                else:
                    media = self.command_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                        timeout=remaining,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                break
            if deadline is None and duration_seconds is not None:
                deadline = monotonic() + duration_seconds
            yield _hcnetsdk_command_port_media_packet(media)
            emitted += 1


class HcNetSdkCommandPortMultiSocketMediaStream:
    """Port-8000 stream using the app's native multi-socket command pattern."""

    supports_deadline_iter_packets = True
    supports_startup_deadline_iter_packets = True

    def __init__(
        self,
        endpoint: HcNetSdkLanEndpoint,
        plan: HcNetSdkCommandPortMultiSocketPlan,
        *,
        timeout: float | None = 10.0,
        socket_factory: SocketFactory | None = None,
        read_first_media: bool = True,
        max_prefix_bytes: int = 4096,
        local_ip: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.plan = plan
        self.timeout = timeout
        self.socket_factory = socket_factory
        self.read_first_media = read_first_media
        self.max_prefix_bytes = max_prefix_bytes
        self.local_ip = local_ip
        self.bootstrap: HcNetSdkCommandPortStreamBootstrap | None = None
        self._first_media: EzvizInterleavedRtpFrameWithPrefix | None = None
        self._drained_media: list[EzvizInterleavedRtpFrameWithPrefix] = []
        self._media_client: HcNetSdkCommandPortClient | None = None
        self._clients: list[HcNetSdkCommandPortClient] = []
        self._keepalive_stop = Event()
        self._keepalive_thread: Thread | None = None
        self._keepalive_deadline_lock = Lock()
        self._keepalive_deadline: float | None = None
        self._keepalive_monotonic: Callable[[], float] = time.monotonic
        self._keepalive_deadline_expired = Event()
        self.keepalive_events: list[HcNetSdkCommandPortKeepaliveEvent] = []
        self._read_interrupted = False

    def __enter__(self) -> HcNetSdkCommandPortMultiSocketMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close all command-port sockets opened by the plan."""
        self._keepalive_stop.set()
        self._set_keepalive_deadline(None, time.monotonic)
        for client in reversed(self._clients):
            client.shutdown()
        self._clients.clear()
        self._media_client = None
        if self._keepalive_thread is not None:
            self._keepalive_thread.join(timeout=2.0)
            self._keepalive_thread = None

    def _new_client(
        self,
        *,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortClient:
        _remaining_capture_timeout(deadline, monotonic)
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.socket_factory is not None:
            kwargs["socket_factory"] = self.socket_factory
        client = HcNetSdkCommandPortClient(self.endpoint, **kwargs)
        self._clients.append(client)
        return client

    def _run_socket_step(
        self,
        client: HcNetSdkCommandPortClient,
        step: HcNetSdkCommandPortSocketStep,
        *,
        step_index: int,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortStreamBootstrap:
        exchanges: list[HcNetSdkCommandPortExchange] = []
        for frame_index, (frame, response_count) in enumerate(
            zip(
                step.command_frames,
                _hcnetsdk_step_response_counts(step),
                strict=True,
            )
        ):
            context = _hcnetsdk_command_port_step_context(
                step,
                step_index=step_index,
                frame_index=frame_index,
                frame=frame,
            )
            frame_to_send = _hcnetsdk_command_port_frame_with_client_ip(
                frame,
                self.local_ip,
            )
            try:
                client.send_command_frame(
                    frame_to_send,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                raise
            except (OSError, PyEzvizError) as err:
                raise PyEzvizError(
                    f"HCNetSDK command-port {context} send failed: {err}"
                ) from err
            if response_count <= 0:
                exchanges.append(HcNetSdkCommandPortExchange(frame, None))
                continue
            try:
                first_response = client.read_tcp_frame(
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                raise
            except (OSError, PyEzvizError) as err:
                raise PyEzvizError(
                    f"HCNetSDK command-port {context} response 1 failed: {err}"
                ) from err
            exchanges.append(HcNetSdkCommandPortExchange(frame, first_response))
            for response_index in range(1, response_count):
                try:
                    response = client.read_tcp_frame(
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                except EzvizLocalSdkDeadlineExpired:
                    raise
                except (OSError, PyEzvizError) as err:
                    raise PyEzvizError(
                        "HCNetSDK command-port "
                        f"{context} response {response_index + 1} failed: {err}"
                    ) from err
                exchanges.append(HcNetSdkCommandPortExchange(b"", response))
        return HcNetSdkCommandPortStreamBootstrap(
            exchanges=tuple(exchanges),
            first_media=None,
        )

    def _start_keepalives(
        self,
        step: HcNetSdkCommandPortSocketStep,
        *,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if self._media_client is None or not step.keepalive_frames:
            return
        self._set_keepalive_deadline(deadline, monotonic)
        if self._keepalive_thread is not None:
            return
        media_client = self._media_client

        def send_keepalives() -> None:
            started_at = time.monotonic()
            initial_delay = (
                step.keepalive_interval_seconds
                if step.keepalive_initial_delay_seconds is None
                else step.keepalive_initial_delay_seconds
            )
            if initial_delay > 0 and self._keepalive_stop.wait(initial_delay):
                return
            for index, frame in enumerate(step.keepalive_frames):
                if self._keepalive_stop.is_set():
                    return
                command_id = (
                    int.from_bytes(frame[12:16], "big") if len(frame) >= 16 else None
                )
                try:
                    with self._keepalive_deadline_lock:
                        send_deadline = self._keepalive_deadline
                        send_monotonic = self._keepalive_monotonic
                    media_client.send_command_frame(
                        _hcnetsdk_command_port_frame_with_client_ip(
                            frame,
                            self.local_ip,
                        ),
                        deadline=send_deadline,
                        monotonic=send_monotonic,
                    )
                except Exception as err:
                    deadline_failure = (
                        send_deadline is not None
                        and isinstance(err, EzvizLocalSdkDeadlineExpired)
                    )
                    if deadline_failure:
                        self._keepalive_deadline_expired.set()
                        media_client.shutdown()
                    self.keepalive_events.append(
                        HcNetSdkCommandPortKeepaliveEvent(
                            index=index,
                            command_id=command_id,
                            elapsed_seconds=time.monotonic() - started_at,
                            sent=False,
                            error=str(err),
                        )
                    )
                    if deadline_failure:
                        return
                else:
                    self.keepalive_events.append(
                        HcNetSdkCommandPortKeepaliveEvent(
                            index=index,
                            command_id=command_id,
                            elapsed_seconds=time.monotonic() - started_at,
                            sent=True,
                        )
                    )
                if index == len(step.keepalive_frames) - 1:
                    return
                if (
                    step.keepalive_interval_seconds > 0
                    and self._keepalive_stop.wait(step.keepalive_interval_seconds)
                ):
                    return

        self._keepalive_thread = Thread(target=send_keepalives, daemon=True)
        self._keepalive_thread.start()

    def _set_keepalive_deadline(
        self,
        deadline: float | None,
        monotonic: Callable[[], float],
    ) -> None:
        """Update the deadline applied to future background keepalive writes."""
        with self._keepalive_deadline_lock:
            if deadline is not None:
                self._keepalive_deadline_expired.clear()
            self._keepalive_deadline = deadline
            self._keepalive_monotonic = monotonic

    def _read_first_media(
        self,
        step: HcNetSdkCommandPortSocketStep,
        *,
        step_index: int,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Read and retain the first media frame from the active media socket."""
        if self._media_client is None:
            raise PyEzvizError("HCNetSDK command-port media socket is closed")
        try:
            self._first_media = self._media_client.read_media_frame_after_prefix(
                max_prefix_bytes=self.max_prefix_bytes,
                deadline=deadline,
                monotonic=monotonic,
            )
        except EzvizLocalSdkDeadlineExpired:
            raise
        except (OSError, PyEzvizError) as err:
            context = _hcnetsdk_command_port_step_context(
                step,
                step_index=step_index,
            )
            raise PyEzvizError(
                "HCNetSDK command-port "
                f"{context} first media read failed: {err}"
            ) from err
        if self._first_media is None:
            raise PyEzvizError("HCNetSDK command-port stream did not return media")

    def _drain_media_before_next_step(
        self,
        step: HcNetSdkCommandPortSocketStep,
        *,
        step_index: int,
        capture_deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Drain and preserve media packets before continuing later socket steps."""
        if not step.drain_media_before_next_step_seconds:
            return
        if self._media_client is None:
            raise PyEzvizError("HCNetSDK command-port media socket is closed")
        clock = monotonic if capture_deadline is not None else time.monotonic
        drain_deadline = clock() + step.drain_media_before_next_step_seconds
        if capture_deadline is not None:
            drain_deadline = min(drain_deadline, capture_deadline)
        while clock() < drain_deadline:
            try:
                if capture_deadline is None:
                    media = self._media_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                    )
                else:
                    media = self._media_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                        deadline=drain_deadline,
                        monotonic=clock,
                        invalidate_on_deadline=drain_deadline >= capture_deadline,
                    )
            except EzvizLocalSdkDeadlineExpired:
                if (
                    (capture_deadline is None or drain_deadline < capture_deadline)
                    and self._media_client.connected
                ):
                    break
                raise
            except (OSError, PyEzvizError) as err:
                context = _hcnetsdk_command_port_step_context(
                    step,
                    step_index=step_index,
                )
                raise PyEzvizError(
                    "HCNetSDK command-port "
                    f"{context} media drain failed: {err}"
                ) from err
            self._drained_media.append(media)

    def start(
        self,
        *,
        read_first_media: bool | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortStreamBootstrap:
        """Execute all socket steps and read the first media frame."""
        if self.bootstrap is not None:
            return self.bootstrap

        exchanges: list[HcNetSdkCommandPortExchange] = []
        media_step: HcNetSdkCommandPortSocketStep | None = None
        media_step_index: int | None = None
        should_read_first_media = (
            self.read_first_media if read_first_media is None else read_first_media
        )
        for step_index, step in enumerate(self.plan.steps):
            client = self._new_client(deadline=deadline, monotonic=monotonic)
            step_bootstrap = self._run_socket_step(
                client,
                step,
                step_index=step_index,
                deadline=deadline,
                monotonic=monotonic,
            )
            exchanges.extend(step_bootstrap.exchanges)
            if step.delay_after_commands_seconds:
                remaining = _remaining_capture_timeout(deadline, monotonic)
                delay = step.delay_after_commands_seconds
                if remaining is not None:
                    delay = min(delay, remaining)
                time.sleep(delay)
                _remaining_capture_timeout(deadline, monotonic)
            if step.media_socket:
                self._media_client = client
                media_step = step
                media_step_index = step_index
                if step.drain_media_before_next_step_seconds:
                    self._start_keepalives(
                        step,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                if should_read_first_media and step.read_first_media_immediately:
                    self._read_first_media(
                        step,
                        step_index=step_index,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
                self._drain_media_before_next_step(
                    step,
                    step_index=step_index,
                    capture_deadline=deadline,
                    monotonic=monotonic,
                )
            else:
                client.close()

        if self._media_client is None or media_step is None or media_step_index is None:
            raise PyEzvizError("HCNetSDK command-port socket plan has no media socket")

        self._start_keepalives(
            media_step,
            deadline=deadline,
            monotonic=monotonic,
        )
        self.bootstrap = HcNetSdkCommandPortStreamBootstrap(
            exchanges=tuple(exchanges),
            first_media=None,
        )
        if (
            should_read_first_media
            and self._first_media is None
            and not self._drained_media
        ):
            self._read_first_media(
                media_step,
                step_index=media_step_index,
                deadline=deadline,
                monotonic=monotonic,
            )
        self.bootstrap = HcNetSdkCommandPortStreamBootstrap(
            exchanges=tuple(exchanges),
            first_media=self._first_media,
        )
        return self.bootstrap

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield command-port RTP payloads from the media socket."""
        if max_packets is not None and max_packets <= 0:
            return
        if duration_seconds is not None and duration_seconds <= 0:
            return
        if self._read_interrupted:
            raise PyEzvizError(_INTERRUPTED_LOCAL_STREAM_MESSAGE)

        deadline = (
            monotonic() + duration_seconds
            if duration_from_start and duration_seconds is not None
            else None
        )
        if self.bootstrap is None:
            try:
                self.start(
                    read_first_media=None if not duration_from_start else False,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                return
        if self._media_client is None:
            raise PyEzvizError("HCNetSDK command-port media socket is closed")

        self._set_keepalive_deadline(deadline, monotonic)
        try:
            yield from self._iter_started_packets(
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                deadline=deadline,
                monotonic=monotonic,
            )
        finally:
            self._set_keepalive_deadline(None, time.monotonic)

    def _iter_started_packets(  # noqa: PLR0912
        self,
        *,
        max_packets: int | None,
        duration_seconds: float | None,
        deadline: float | None,
        monotonic: Callable[[], float],
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield packets after startup while keeping background I/O in budget."""
        assert self._media_client is not None
        emitted = 0
        if self._first_media is not None:
            if duration_seconds is not None and deadline is None:
                deadline = monotonic() + duration_seconds
                self._set_keepalive_deadline(deadline, monotonic)
            first_media = self._first_media
            self._first_media = None
            yield _hcnetsdk_command_port_media_packet(first_media)
            emitted += 1
        while self._drained_media and (max_packets is None or emitted < max_packets):
            if deadline is None and duration_seconds is not None:
                deadline = monotonic() + duration_seconds
                self._set_keepalive_deadline(deadline, monotonic)
            if deadline is not None and monotonic() >= deadline:
                break
            yield _hcnetsdk_command_port_media_packet(self._drained_media.pop(0))
            emitted += 1

        while max_packets is None or emitted < max_packets:
            remaining = None
            if deadline is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
            try:
                if remaining is None:
                    media = self._media_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                    )
                else:
                    media = self._media_client.read_media_frame_after_prefix(
                        max_prefix_bytes=self.max_prefix_bytes,
                        timeout=remaining,
                        deadline=deadline,
                        monotonic=monotonic,
                    )
            except EzvizLocalSdkDeadlineExpired:
                self._read_interrupted = True
                self.close()
                break
            except (OSError, PyEzvizError) as err:
                if deadline is not None and (
                    monotonic() >= deadline
                    or self._keepalive_deadline_expired.is_set()
                ):
                    self._read_interrupted = True
                    self.close()
                    break
                raise PyEzvizError(
                    f"HCNetSDK command-port media packet read failed: {err}"
                ) from err
            if deadline is None and duration_seconds is not None:
                deadline = monotonic() + duration_seconds
                self._set_keepalive_deadline(deadline, monotonic)
            yield _hcnetsdk_command_port_media_packet(media)
            emitted += 1


class HcNetSdkCommandPortGeneratedMultiSocketMediaStream:
    """Port-8000 stream that logs in and renders a generated socket plan."""

    supports_deadline_iter_packets = True
    supports_startup_deadline_iter_packets = True

    def __init__(
        self,
        endpoint: HcNetSdkLanEndpoint,
        generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan,
        *,
        password: str | bytes,
        username: str = "admin",
        timeout: float | None = 10.0,
        socket_factory: SocketFactory | None = None,
        read_first_media: bool = True,
        max_prefix_bytes: int = 4096,
        local_ip: str | None = None,
        rsa_key: Any | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.generated_plan = generated_plan
        self.password = password
        self.username = username
        self.timeout = timeout
        self.socket_factory = socket_factory
        self.read_first_media = read_first_media
        self.max_prefix_bytes = max_prefix_bytes
        self.local_ip = local_ip
        self.rsa_key = rsa_key
        self.login_session: HcNetSdkCommandPortLoginSession | None = None
        self.bootstrap: HcNetSdkCommandPortStreamBootstrap | None = None
        self._stream: HcNetSdkCommandPortMultiSocketMediaStream | None = None

    def __enter__(self) -> HcNetSdkCommandPortGeneratedMultiSocketMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the rendered multi-socket media stream."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def prepare_startup(self) -> None:
        """Cache startup work that must not consume a capture deadline."""
        if self.bootstrap is None and self.rsa_key is None:
            self.rsa_key = hcnetsdk_command_port_rsa_key()

    def _login_client(
        self,
        *,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortClient:
        _remaining_capture_timeout(deadline, monotonic)
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.socket_factory is not None:
            kwargs["socket_factory"] = self.socket_factory
        return HcNetSdkCommandPortClient(self.endpoint, **kwargs)

    @staticmethod
    def _client_local_ip(client: HcNetSdkCommandPortClient) -> str:
        try:
            return str(client.sock.getsockname()[0])
        except (AttributeError, OSError, TypeError) as err:
            raise PyEzvizError(
                "HCNetSDK generated command-port plan requires local_ip when "
                "the socket does not expose getsockname()"
            ) from err

    def start(
        self,
        *,
        read_first_media: bool | None = None,
        deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> HcNetSdkCommandPortStreamBootstrap:
        """Run command-port login, render the plan, and read first media."""
        if self.bootstrap is not None:
            return self.bootstrap

        login_client = self._login_client(deadline=deadline, monotonic=monotonic)
        login_client.connect(
            timeout=_remaining_capture_timeout(deadline, monotonic),
            deadline_limited=deadline is not None,
            deadline=deadline,
            monotonic=monotonic,
        )
        with login_client:
            local_ip = self.local_ip or self._client_local_ip(login_client)
            self.login_session = login_client.login(
                password=self.password,
                username=self.username,
                local_ip=local_ip,
                rsa_key=self.rsa_key,
                deadline=deadline,
                monotonic=monotonic,
            )

        rendered_plan = self.generated_plan.to_socket_plan(
            session_id=self.login_session.session_id,
            auth_seed=self.login_session.auth_seed,
            key=self.login_session.challenge,
            local_ip=local_ip,
        )
        self._stream = HcNetSdkCommandPortMultiSocketMediaStream(
            self.endpoint,
            rendered_plan,
            timeout=self.timeout,
            socket_factory=self.socket_factory,
            read_first_media=self.read_first_media,
            max_prefix_bytes=self.max_prefix_bytes,
            local_ip=None,
        )
        try:
            self.bootstrap = self._stream.start(
                read_first_media=read_first_media,
                deadline=deadline,
                monotonic=monotonic,
            )
        except PyEzvizError:
            self.bootstrap = self._stream.bootstrap
            raise
        return self.bootstrap

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        duration_seconds: float | None = None,
        duration_from_start: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalStreamPacket]:
        """Yield command-port RTP payloads from the rendered media socket."""
        if max_packets is not None and max_packets <= 0:
            return
        if duration_seconds is not None and duration_seconds <= 0:
            return
        self.prepare_startup()
        deadline = (
            monotonic() + duration_seconds
            if duration_from_start and duration_seconds is not None
            else None
        )
        if self.bootstrap is None:
            try:
                self.start(
                    read_first_media=None if not duration_from_start else False,
                    deadline=deadline,
                    monotonic=monotonic,
                )
            except EzvizLocalSdkDeadlineExpired:
                self.close()
                return
        if self._stream is None:
            raise PyEzvizError("HCNetSDK generated command-port stream is closed")
        try:
            remaining = _remaining_capture_timeout(deadline, monotonic)
        except EzvizLocalSdkDeadlineExpired:
            self.close()
            return
        yield from self._stream.iter_packets(
            max_packets=max_packets,
            duration_seconds=(
                duration_seconds if remaining is None else remaining
            ),
            duration_from_start=duration_from_start,
            monotonic=monotonic,
        )

    @property
    def keepalive_events(self) -> tuple[HcNetSdkCommandPortKeepaliveEvent, ...]:
        """Return keepalive send-attempt metadata from the rendered stream."""
        if self._stream is None:
            return ()
        return tuple(self._stream.keepalive_events)


def open_local_sdk_stream(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    device_info: EzvizCasDeviceInfo,
    preview_request: EzvizLocalPreviewRequest,
    *,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    pre_start_body: bytes | str | None = None,
    pre_start_sequence: int = 0,
    preview_sequence: int = 0,
    stream_setup_sequence: int = 0,
    stream_rate: str | int = 0,
    stream_mode: str | int = 0,
    max_prefix_bytes: int = 4096,
    command_source_port: int | None = None,
) -> EzvizLocalSdkMediaStream:
    """Return a direct-local SDK media stream ready for native packet reads."""
    if socket_factory is None:
        sdk_client = EzvizLocalSdkClient(
            endpoint,
            device_info,
            timeout=timeout,
            command_source_port=command_source_port,
        )
    else:
        sdk_client = EzvizLocalSdkClient(
            endpoint,
            device_info,
            timeout=timeout,
            socket_factory=socket_factory,
            command_source_port=command_source_port,
        )
    return EzvizLocalSdkMediaStream(
        sdk_client,
        preview_request,
        pre_start_body=pre_start_body,
        pre_start_sequence=pre_start_sequence,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
    )


def open_hcnetsdk_command_port_stream(
    endpoint: HcNetSdkLanEndpoint,
    command_frames: Iterable[bytes],
    *,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    read_response_after_each: bool | Iterable[bool] = True,
    read_first_media: bool = True,
    max_prefix_bytes: int = 4096,
    local_ip: str | None = None,
) -> HcNetSdkCommandPortMediaStream:
    """Return a command-port media stream for explicit bootstrap frames."""
    if socket_factory is None:
        command_client = HcNetSdkCommandPortClient(endpoint, timeout=timeout)
    else:
        command_client = HcNetSdkCommandPortClient(
            endpoint,
            timeout=timeout,
            socket_factory=socket_factory,
        )
    return HcNetSdkCommandPortMediaStream(
        command_client,
        command_frames,
        read_response_after_each=read_response_after_each,
        read_first_media=read_first_media,
        max_prefix_bytes=max_prefix_bytes,
        local_ip=local_ip,
    )


def open_hcnetsdk_command_port_multi_socket_stream(
    endpoint: HcNetSdkLanEndpoint,
    plan: HcNetSdkCommandPortMultiSocketPlan,
    *,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    read_first_media: bool = True,
    max_prefix_bytes: int = 4096,
    local_ip: str | None = None,
) -> HcNetSdkCommandPortMultiSocketMediaStream:
    """Return a command-port media stream for a native-style socket plan."""
    return HcNetSdkCommandPortMultiSocketMediaStream(
        endpoint,
        plan,
        timeout=timeout,
        socket_factory=socket_factory,
        read_first_media=read_first_media,
        max_prefix_bytes=max_prefix_bytes,
        local_ip=local_ip,
    )


def open_hcnetsdk_command_port_generated_multi_socket_stream(
    endpoint: HcNetSdkLanEndpoint,
    generated_plan: HcNetSdkCommandPortGeneratedMultiSocketPlan,
    *,
    password: str | bytes,
    username: str = "admin",
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    read_first_media: bool = True,
    max_prefix_bytes: int = 4096,
    local_ip: str | None = None,
    rsa_key: Any | None = None,
) -> HcNetSdkCommandPortGeneratedMultiSocketMediaStream:
    """Return a command-port stream that logs in before rendering a plan."""
    return HcNetSdkCommandPortGeneratedMultiSocketMediaStream(
        endpoint,
        generated_plan,
        password=password,
        username=username,
        timeout=timeout,
        socket_factory=socket_factory,
        read_first_media=read_first_media,
        max_prefix_bytes=max_prefix_bytes,
        local_ip=local_ip,
        rsa_key=rsa_key,
    )


def open_local_sdk_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    *,
    channel: int = 1,
    cas_serial: str | None = None,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    receiver_port: int = 10101,
    receiver_stream_type: str = "MAIN",
    receiver_server_type: int = 1,
    receiver_new_stream_type: int = 1,
    receiver_trans_proto: str = "TCP",
    receiver_ex_port: int = 10101,
    auth_biz_code: str = "biz=1",
    auth_interval: int = 180,
    is_encrypt: str = "TRUE",
    uuid: str | None = None,
    timestamp: str | None = None,
    preview_sequence: int = 16,
    stream_setup_sequence: int = 17,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    max_prefix_bytes: int = 4096,
) -> EzvizLocalSdkMediaStream:
    """Return a direct-local stream using an authenticated EZVIZ client.

    This convenience wrapper fetches the LAN endpoint from get_device_infos
    and the CAS tuple from EzvizCAS.cas_get_encryption. It is still the
    direct-local 9010/9020 SDK path; it does not implement the proprietary
    HCNetSDK command protocol used on port 8000.
    """
    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        fetch_media_key=False,
        register_p2p_session=register_p2p_session,
        p2p_register_max_retries=p2p_register_max_retries,
    )
    preview_request = _local_sdk_preview_request_from_credentials(
        credentials,
        channel=channel,
        receiver_port=receiver_port,
        receiver_stream_type=receiver_stream_type,
        receiver_server_type=receiver_server_type,
        receiver_new_stream_type=receiver_new_stream_type,
        receiver_trans_proto=receiver_trans_proto,
        receiver_ex_port=receiver_ex_port,
        auth_biz_code=auth_biz_code,
        auth_interval=auth_interval,
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )
    return open_local_sdk_stream(
        credentials.endpoint,
        credentials.device_info,
        preview_request,
        timeout=timeout,
        socket_factory=socket_factory,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
        command_source_port=receiver_port,
    )


def copy_local_sdk_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    output_format: LocalSdkOutputFormat = "mpegts",
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    nalu_header_size: int | None = 0,
    channel: int = 1,
    cas_serial: str | None = None,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory | None = None,
    receiver_port: int = 10101,
    receiver_stream_type: str = "MAIN",
    receiver_server_type: int = 1,
    receiver_new_stream_type: int = 1,
    receiver_trans_proto: str = "TCP",
    receiver_ex_port: int = 10101,
    auth_biz_code: str = "biz=1",
    auth_interval: int = 180,
    is_encrypt: str = "TRUE",
    uuid: str | None = None,
    timestamp: str | None = None,
    preview_sequence: int = 16,
    stream_setup_sequence: int = 17,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    max_prefix_bytes: int = 4096,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    ffmpeg_path: str = "ffmpeg",
    monotonic: Callable[[], float] = time.monotonic,
    smscode: str | int | None = None,
    cam_key_max_retries: int = 1,
) -> EzvizLocalSdkCredentials:
    """Open a direct-local SDK stream from an authenticated client and copy bytes.

    This is the public convenience path for integrations that want local
    9010/9020 media without wiring the CAS lookup, preview bootstrap, MPEG-PS
    collection, optional video decrypt, and MPEG-TS remux steps by hand.
    """
    if output_format not in ("mpegps", "mpegts"):
        raise PyEzvizError("output_format must be 'mpegps' or 'mpegts'")
    if decrypt_video:
        _require_bounded_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )

    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        fetch_media_key=decrypt_video and media_key is None,
        register_p2p_session=register_p2p_session,
        p2p_register_max_retries=p2p_register_max_retries,
        smscode=smscode,
        cam_key_max_retries=cam_key_max_retries,
    )
    selected_media_key = media_key if media_key is not None else credentials.media_key
    if decrypt_video and selected_media_key is None:
        raise PyEzvizError("decrypt_video requires a media_key or fetchable camera media key")

    preview_request = _local_sdk_preview_request_from_credentials(
        credentials,
        channel=channel,
        receiver_port=receiver_port,
        receiver_stream_type=receiver_stream_type,
        receiver_server_type=receiver_server_type,
        receiver_new_stream_type=receiver_new_stream_type,
        receiver_trans_proto=receiver_trans_proto,
        receiver_ex_port=receiver_ex_port,
        auth_biz_code=auth_biz_code,
        auth_interval=auth_interval,
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )
    with open_local_sdk_stream(
        credentials.endpoint,
        credentials.device_info,
        preview_request,
        timeout=timeout,
        socket_factory=socket_factory,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
        command_source_port=receiver_port,
    ) as stream:
        if output_format == "mpegps":
            if decrypt_video:
                copy_local_stream_to_decrypted_mpegps(
                    stream,
                    output,
                    cast(str | bytes, selected_media_key),
                    nalu_header_size=nalu_header_size,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
            else:
                copy_local_stream_to_mpegps(
                    stream,
                    output,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
        elif decrypt_video:
            copy_local_stream_to_decrypted_mpegts(
                stream,
                output,
                cast(str | bytes, selected_media_key),
                ffmpeg_path=ffmpeg_path,
                nalu_header_size=nalu_header_size,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
        else:
            copy_local_stream_to_mpegts(
                stream,
                output,
                ffmpeg_path=ffmpeg_path,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
            )
    return credentials


def get_local_sdk_stream_credentials_from_client(
    client: Any,
    serial: str,
    *,
    cas_serial: str | None = None,
    fetch_media_key: bool = True,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    smscode: str | int | None = None,
    cam_key_max_retries: int = 1,
) -> EzvizLocalSdkCredentials:
    """Fetch LAN endpoint, CAS tuple and optional media key from EZVIZ services."""
    endpoint = _local_sdk_endpoint_from_client(client, serial)
    if register_p2p_session:
        _register_p2p_session_for_client(
            client,
            max_retries=p2p_register_max_retries,
        )
    cas_session = CasDeviceSession.from_response(
        EzvizCAS(client.export_token()).cas_get_encryption(cas_serial or serial)
    )
    media_key: str | bytes | None = None
    if fetch_media_key:
        if smscode is None:
            media_key = client.get_cam_key(serial, max_retries=cam_key_max_retries)
        else:
            media_key = client.get_cam_key(
                serial,
                smscode=smscode,
                max_retries=cam_key_max_retries,
            )
        if media_key is not None:
            media_key = str(media_key)

    return EzvizLocalSdkCredentials(
        endpoint=endpoint,
        device_info=EzvizCasDeviceInfo(
            serial=serial,
            operation_code=cas_session.operation_code,
            key=cas_session.key,
            encrypt_type=cas_session.encrypt_type,
        ),
        media_key=media_key,
    )


def _register_p2p_session_for_client(
    client: Any,
    *,
    max_retries: int = MAX_RETRIES,
) -> None:
    """Call an EzvizClient-style P2P registration hook when available."""

    register = getattr(client, "register_p2p_session", None)
    if callable(register):
        register(max_retries=max_retries)


def _local_sdk_preview_request_from_credentials(  # noqa: PLR0913
    credentials: EzvizLocalSdkCredentials,
    *,
    channel: int,
    receiver_port: int,
    receiver_stream_type: str,
    receiver_server_type: int,
    receiver_new_stream_type: int,
    receiver_trans_proto: str,
    receiver_ex_port: int,
    auth_biz_code: str,
    auth_interval: int,
    is_encrypt: str,
    uuid: str | None,
    timestamp: str | None,
) -> EzvizLocalPreviewRequest:
    return EzvizLocalPreviewRequest(
        operation_code=credentials.device_info.operation_code,
        channel=channel,
        receiver_info=EzvizLocalReceiverInfoAttrs(
            port=receiver_port,
            server_type=receiver_server_type,
            stream_type=receiver_stream_type,
            new_stream_type=receiver_new_stream_type,
            trans_proto=receiver_trans_proto,
        ),
        receiver_info_ex=EzvizLocalReceiverInfoExAttrs(port=receiver_ex_port),
        authentication=EzvizLocalAuthenticationAttrs(
            biz_code=auth_biz_code,
            interval=auth_interval,
        ),
        is_encrypt=is_encrypt,
        uuid=uuid,
        timestamp=timestamp,
    )


def copy_local_stream_to_mpegps(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Write local MPEG-PS payloads directly without an FFmpeg subprocess."""
    _write_local_stream_payloads(
        stream,
        output,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )


def collect_local_stream_mpegps(
    stream: Any,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> bytes:
    """Collect bounded local MPEG-PS payloads into memory.

    This is intended for transforms, such as the EZVIZ encrypted-video NAL
    decrypt pass, that need complete MPEG-PS packet context across local RTP
    packet boundaries.
    """
    return b"".join(
        _iter_local_stream_payloads(
            stream,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )
    )


def copy_local_stream_to_decrypted_mpegps(
    stream: Any,
    output: BinaryIO,
    media_key: str | bytes,
    *,
    nalu_header_size: int | None = None,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Collect, decrypt and write local MPEG-PS payloads.

    Decryption is deliberately bounded by max_packets or duration_seconds
    because the MPEG-PS/NAL transform is stateful across packet splits and must
    operate on an in-memory capture.
    """
    _require_bounded_decrypt_capture(
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    )
    packets = collect_local_stream_media_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    if _local_stream_packets_are_idmx(packets):
        raise _unsupported_idmx_local_payload_error()
    payload = b"".join(packets)
    output.write(
        decrypt_hikvision_ps_video(
            payload,
            media_key,
            nalu_header_size=nalu_header_size,
        )
    )
    output.flush()


def copy_local_stream_to_decrypted_mpegts(  # noqa: PLR0912, PLR0913, PLR0915
    stream: Any,
    output: BinaryIO,
    media_key: str | bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    nalu_header_size: int | None = None,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    h264_skip_initial_idr_windows: int = 0,
    h264_trim_to_clean_idr_window: bool = False,
    h264_clean_idr_preroll_seconds: float = 0.0,
    h264_clean_idr_max_windows: int = 32,
    h264_wait_for_clean_idr_window: bool = False,
    h264_clean_idr_wait_seconds: float = 60.0,
    decrypt_hevc_parameter_sets: bool = False,
) -> None:
    """Collect, decrypt, remux and write local MPEG-TS bytes."""
    if h264_wait_for_clean_idr_window:
        _, payload_duration_seconds = h264_clean_idr_capture_budgets(
            duration_seconds=duration_seconds,
            h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
            h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
            h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
            h264_clean_idr_max_windows=h264_clean_idr_max_windows,
            h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
            h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
        )
        _require_bounded_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=payload_duration_seconds,
        )
        payloads = _iter_local_stream_payloads(
            stream,
            max_packets=max_packets,
            duration_seconds=payload_duration_seconds,
            monotonic=monotonic,
        )
        recorded_packets: list[bytes] = []

        def record_payloads() -> Iterator[bytes]:
            for payload in payloads:
                recorded_packets.append(payload)
                yield payload

        annexb = collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(
            record_payloads(),
            media_key,
            nalu_header_size=nalu_header_size,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
            ffmpeg_path=ffmpeg_path,
            max_windows=h264_clean_idr_max_windows,
            wait_seconds=h264_clean_idr_wait_seconds,
        )
        full_annexb = _decrypt_idmx_local_packets_to_annexb(
            recorded_packets,
            media_key,
            nalu_header_size=nalu_header_size,
        )
        stream_is_clear = False
        with suppress(PyEzvizError):
            clear_annexb = _idmx_local_packets_to_h264_annexb(recorded_packets)
            if _annexb_contains_selected_vcl(
                clear_annexb,
                annexb,
                video_input_format="h264",
            ):
                full_annexb = clear_annexb
                stream_is_clear = True
        selected_packets = _idmx_h264_packets_from_selected_annexb(
            recorded_packets,
            full_annexb=full_annexb,
            selected_annexb=annexb,
            media_key=media_key,
            nalu_header_size=nalu_header_size,
            stream_is_clear=stream_is_clear,
        )
        audio_metadata = _idmx_audio_metadata(recorded_packets, media_key)
        audio_payload_types = _idmx_audio_payload_types(recorded_packets)
        audio = _decrypt_idmx_local_packets_to_adts_aac(
            selected_packets,
            media_key,
            audio_metadata=audio_metadata,
            audio_payload_types=audio_payload_types,
        )
        if audio is not None:
            _copy_idmx_audio_video_to_mpegts(
                annexb,
                audio,
                output,
                ffmpeg_path=ffmpeg_path,
                video_input_format="h264",
                video_frame_rate=None,
            )
            return
        process = _open_local_h264_mpegts_remux_process(ffmpeg_path)
        _copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return

    capture_duration_seconds, _ = h264_clean_idr_capture_budgets(
        duration_seconds=duration_seconds,
        h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
        h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
        h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
        h264_clean_idr_max_windows=h264_clean_idr_max_windows,
        h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
        h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
    )
    _require_bounded_decrypt_capture(
        max_packets=max_packets,
        duration_seconds=capture_duration_seconds,
    )
    packets = collect_local_stream_media_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=capture_duration_seconds,
        monotonic=monotonic,
    )
    if _local_stream_packets_are_idmx(packets):
        annexb, authoritative_video_codec = (
            _decrypt_idmx_local_packets_to_annexb_with_codec(
                packets,
                media_key,
                nalu_header_size=nalu_header_size,
                decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
            )
        )
        full_annexb = annexb
        if authoritative_video_codec == "h264" or (
            authoritative_video_codec is None and _annexb_has_h264_vcl(annexb)
        ):
            annexb = skip_h264_annexb_initial_idr_windows(
                annexb,
                h264_skip_initial_idr_windows,
            )
            if h264_trim_to_clean_idr_window or h264_wait_for_clean_idr_window:
                annexb = trim_h264_annexb_to_first_clean_idr_window(
                    annexb,
                    ffmpeg_path=ffmpeg_path,
                    max_windows=h264_clean_idr_max_windows,
                )
            video_input_format = "h264"
            video_frame_rate = None
        elif authoritative_video_codec == "hevc" or _annexb_looks_like_hevc(annexb):
            annexb = skip_hevc_annexb_initial_irap_windows(
                annexb,
                h264_skip_initial_idr_windows,
            )
            if h264_trim_to_clean_idr_window:
                annexb = trim_hevc_annexb_to_first_clean_irap_window(
                    annexb,
                    ffmpeg_path=ffmpeg_path,
                    max_windows=h264_clean_idr_max_windows,
                )
            video_input_format = "hevc"
            video_frame_rate = _idmx_local_video_frame_rate(packets)
        elif _annexb_looks_like_h264(annexb):
            video_input_format = "h264"
            video_frame_rate = None
        else:
            raise PyEzvizError("EZVIZ local IDMX stream did not include video frames")
        audio = None
        if _idmx_local_packets_have_aac(packets):
            selected_packets = _idmx_packets_from_selected_annexb(
                packets,
                full_annexb=full_annexb,
                selected_annexb=annexb,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
                video_input_format=video_input_format,
            )
            audio = _decrypt_idmx_local_packets_to_adts_aac(
                selected_packets,
                media_key,
                audio_metadata=_idmx_audio_metadata(packets, media_key),
                audio_payload_types=_idmx_audio_payload_types(packets),
            )
        if audio is not None:
            _copy_idmx_audio_video_to_mpegts(
                annexb,
                audio,
                output,
                ffmpeg_path=ffmpeg_path,
                video_input_format=video_input_format,
                video_frame_rate=video_frame_rate,
            )
            return
        if video_input_format == "hevc":
            process = _open_local_hevc_mpegts_remux_process(
                ffmpeg_path,
                frame_rate=video_frame_rate or str(IDMX_DEFAULT_VIDEO_FRAME_RATE),
            )
        else:
            process = _open_local_h264_mpegts_remux_process(ffmpeg_path)
        _copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return
    if (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_wait_for_clean_idr_window
    ):
        raise PyEzvizError(
            "H.264 startup trim options require a decrypted H.264 IDMX stream"
        )
    decrypted = decrypt_hikvision_ps_video(
        b"".join(packets),
        media_key,
        nalu_header_size=nalu_header_size,
    )
    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts([decrypted], output, process=process)


def _require_bounded_decrypt_capture(
    *,
    max_packets: int | None,
    duration_seconds: float | None,
) -> None:
    if not has_positive_finite_capture_bound(
        max_packets=max_packets,
        duration_seconds=duration_seconds,
    ):
        raise PyEzvizError(
            "Encrypted local stream decrypt requires a positive finite "
            "duration_seconds or max_packets"
        )


def _require_bounded_idmx_capture(
    *,
    max_packets: int | None,
    duration_seconds: float | None,
) -> None:
    if max_packets is None and duration_seconds is None:
        raise PyEzvizError(
            "EZVIZ local IDMX stream remux requires duration_seconds or max_packets"
        )


def copy_local_stream_to_mpegts(  # noqa: PLR0912, PLR0913
    stream: Any,
    output: BinaryIO,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    h264_skip_initial_idr_windows: int = 0,
    h264_trim_to_clean_idr_window: bool = False,
    h264_clean_idr_preroll_seconds: float = 0.0,
    h264_clean_idr_max_windows: int = 32,
    h264_wait_for_clean_idr_window: bool = False,
    h264_clean_idr_wait_seconds: float = 60.0,
) -> None:
    """Pipe local media payloads through FFmpeg and write MPEG-TS bytes."""
    _, payload_duration_seconds = h264_clean_idr_capture_budgets(
        duration_seconds=duration_seconds,
        h264_skip_initial_idr_windows=h264_skip_initial_idr_windows,
        h264_trim_to_clean_idr_window=h264_trim_to_clean_idr_window,
        h264_clean_idr_preroll_seconds=h264_clean_idr_preroll_seconds,
        h264_clean_idr_max_windows=h264_clean_idr_max_windows,
        h264_wait_for_clean_idr_window=h264_wait_for_clean_idr_window,
        h264_clean_idr_wait_seconds=h264_clean_idr_wait_seconds,
    )
    payloads = _iter_local_stream_payloads(
        stream,
        max_packets=max_packets,
        duration_seconds=payload_duration_seconds,
        monotonic=monotonic,
    )
    try:
        first_payload = next(payloads)
    except StopIteration:
        output.flush()
        return

    while _is_ignorable_leading_stream_payload(first_payload):
        try:
            first_payload = next(payloads)
        except StopIteration:
            output.flush()
            return

    if _looks_like_idmx_local_payload(first_payload):
        _require_bounded_idmx_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )
        is_h264_startup_options = bool(
            h264_skip_initial_idr_windows or h264_trim_to_clean_idr_window
        )
        annexb_codec: str | None = None
        annexb_is_h264 = False
        if h264_wait_for_clean_idr_window:
            annexb, annexb_codec = collect_idmx_annexb_after_first_clean_video_window(
                chain((first_payload,), payloads),
                duration_seconds=duration_seconds,
                monotonic=monotonic,
                ffmpeg_path=ffmpeg_path,
                max_windows=h264_clean_idr_max_windows,
                wait_seconds=h264_clean_idr_wait_seconds,
            )
            annexb_is_h264 = annexb_codec == "h264"
        else:
            packets = list(chain((first_payload,), payloads))
            if is_h264_startup_options:
                annexb, annexb_codec = _idmx_local_packets_to_h264_annexb_with_codec(
                    packets
                )
                annexb_is_h264 = annexb_codec == "h264"
            else:
                annexb, annexb_codec = _idmx_local_packets_to_annexb_with_codec(
                    packets
                )
                annexb_is_h264 = annexb_codec == "h264"
        if (
            not annexb_is_h264
            and _annexb_looks_like_hevc(annexb)
        ):
            if not h264_wait_for_clean_idr_window:
                annexb = skip_hevc_annexb_initial_irap_windows(
                    annexb,
                    h264_skip_initial_idr_windows,
                )
                if h264_trim_to_clean_idr_window:
                    annexb = trim_hevc_annexb_to_first_clean_irap_window(
                        annexb,
                        ffmpeg_path=ffmpeg_path,
                        max_windows=h264_clean_idr_max_windows,
                    )
            process = _open_local_hevc_mpegts_remux_process(ffmpeg_path)
        else:
            annexb = skip_h264_annexb_initial_idr_windows(
                annexb,
                h264_skip_initial_idr_windows,
            )
            if h264_trim_to_clean_idr_window:
                annexb = trim_h264_annexb_to_first_clean_idr_window(
                    annexb,
                    ffmpeg_path=ffmpeg_path,
                    max_windows=h264_clean_idr_max_windows,
                )
            process = _open_local_h264_mpegts_remux_process(ffmpeg_path)
        _copy_mpegps_payloads_to_mpegts([annexb], output, process=process)
        return
    if (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_wait_for_clean_idr_window
    ):
        raise PyEzvizError(
            "H.264 startup trim options require a clear H.264 IDMX stream"
        )
    if not first_payload.startswith(MPEG_PS_START_CODE):
        raise PyEzvizError(
            "Unsupported EZVIZ local stream payload format: expected MPEG-PS payload"
        )

    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts(
        chain((first_payload,), payloads),
        output,
        process=process,
    )


def h264_clean_idr_capture_budgets(
    *,
    duration_seconds: float | None,
    h264_skip_initial_idr_windows: int,
    h264_trim_to_clean_idr_window: bool,
    h264_clean_idr_preroll_seconds: float,
    h264_clean_idr_max_windows: int,
    h264_wait_for_clean_idr_window: bool,
    h264_clean_idr_wait_seconds: float,
) -> tuple[float | None, float | None]:
    """Validate H.264 trim settings and return capture and payload budgets."""

    if h264_skip_initial_idr_windows < 0:
        raise PyEzvizError("h264_skip_initial_idr_windows cannot be negative")
    if h264_clean_idr_max_windows <= 0:
        raise PyEzvizError("h264_clean_idr_max_windows must be positive")
    if h264_clean_idr_preroll_seconds < 0:
        raise PyEzvizError("h264_clean_idr_preroll_seconds cannot be negative")
    if h264_clean_idr_wait_seconds < 0:
        raise PyEzvizError("h264_clean_idr_wait_seconds cannot be negative")
    if h264_wait_for_clean_idr_window and duration_seconds is None:
        raise PyEzvizError(
            "h264_wait_for_clean_idr_window requires duration_seconds"
        )
    if h264_wait_for_clean_idr_window and (
        h264_skip_initial_idr_windows
        or h264_trim_to_clean_idr_window
        or h264_clean_idr_preroll_seconds
    ):
        raise PyEzvizError(
            "h264_wait_for_clean_idr_window cannot be combined with H.264 "
            "startup trim options"
        )
    if h264_clean_idr_preroll_seconds and not h264_trim_to_clean_idr_window:
        raise PyEzvizError(
            "h264_clean_idr_preroll_seconds requires "
            "h264_trim_to_clean_idr_window"
        )
    if h264_clean_idr_preroll_seconds and duration_seconds is None:
        raise PyEzvizError(
            "h264_clean_idr_preroll_seconds requires duration_seconds"
        )
    capture_duration_seconds = duration_seconds
    payload_duration_seconds = duration_seconds
    if h264_trim_to_clean_idr_window and h264_clean_idr_preroll_seconds:
        assert duration_seconds is not None
        capture_duration_seconds = _checked_h264_duration_sum(
            duration_seconds,
            h264_clean_idr_preroll_seconds,
            context="capture",
        )
        payload_duration_seconds = capture_duration_seconds
    if h264_wait_for_clean_idr_window:
        assert duration_seconds is not None
        payload_duration_seconds = _checked_h264_duration_sum(
            duration_seconds,
            h264_clean_idr_wait_seconds,
            context="payload",
        )
    return capture_duration_seconds, payload_duration_seconds


def _checked_h264_duration_sum(
    duration_seconds: float,
    extension_seconds: float,
    *,
    context: str,
) -> float:
    """Add one startup window without allowing deadline overflow."""

    try:
        combined = duration_seconds + extension_seconds
    except OverflowError as err:
        raise PyEzvizError(
            f"H.264 clean-IDR {context} duration must be finite"
        ) from err
    if not is_positive_finite_duration_bound(combined):
        raise PyEzvizError(f"H.264 clean-IDR {context} duration must be finite")
    return combined


def _is_ignorable_leading_stream_payload(payload: bytes) -> bool:
    """Return True for tiny command-port blips before the first media record."""
    return bool(payload) and len(payload) < len(MPEG_PS_START_CODE)


def copy_hcnetsdk_real_data_to_mpegts(
    packets: Iterable[HcNetSdkRealDataPacket],
    output: BinaryIO,
    *,
    ffmpeg_path: str = "ffmpeg",
) -> None:
    """Remux HCNetSDK real-play MPEG-PS callback packets to MPEG-TS."""
    process = _open_local_mpegts_remux_process(ffmpeg_path)
    _copy_mpegps_payloads_to_mpegts(
        iter_hcnetsdk_real_data_mpegps(packets),
        output,
        process=process,
    )


def _local_media_packet(
    media: EzvizInterleavedRtpFrameWithPrefix,
) -> EzvizLocalStreamPacket:
    body = _strip_local_sdk_payload_header(rtp_payload(media.frame.payload))
    return EzvizLocalStreamPacket(
        channel=media.frame.header.channel,
        length=len(body),
        body=body,
        prefix=media.prefix,
    )


def _hcnetsdk_command_port_media_packet(
    media: EzvizInterleavedRtpFrameWithPrefix,
) -> EzvizLocalStreamPacket:
    body = _strip_hcnetsdk_command_port_media_payload_header(
        _hcnetsdk_command_port_media_payload(media.frame.payload)
    )
    return EzvizLocalStreamPacket(
        channel=media.frame.header.channel,
        length=len(body),
        body=body,
        encrypted=_looks_like_idmx_local_payload(body),
        prefix=media.prefix,
    )


def _strip_hcnetsdk_command_port_media_payload_header(payload: bytes) -> bytes:
    if (
        _idmx_local_frame_header_size(payload) is not None
        or _looks_like_length_prefixed_idmx_local_payload(payload)
    ):
        return payload
    return _strip_local_sdk_payload_header(payload)


def _hcnetsdk_command_port_media_payload(payload: bytes) -> bytes:
    if (
        _idmx_local_frame_header_size(payload) is not None
        or _looks_like_length_prefixed_idmx_local_payload(payload)
    ):
        return payload
    hrudp_payload = _hcnetsdk_hrudp_video_payload(payload)
    if hrudp_payload is not None:
        return hrudp_payload
    try:
        unwrapped = rtp_payload(payload)
    except PyEzvizError as err:
        if str(err) not in _COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS:
            raise
        return payload
    hrudp_payload = _hcnetsdk_hrudp_video_payload(unwrapped)
    if hrudp_payload is not None:
        return hrudp_payload
    if _looks_like_hcnetsdk_wrapped_media_payload(unwrapped):
        return unwrapped
    return unwrapped


def _hcnetsdk_hrudp_video_payload(payload: bytes) -> bytes | None:
    """Return media bytes from the HCPreview HRUDP video wrapper when present."""

    if len(payload) < HCNETSDK_HRUDP_FRAME_HEADER_SIZE:
        return None
    for byte_order in ("little", "big"):
        payload_length = int.from_bytes(payload[0:4], byte_order)
        frame_type = int.from_bytes(payload[4:8], byte_order)
        if (
            frame_type != HCNETSDK_HRUDP_VIDEO_FRAME_TYPE
            or payload_length + HCNETSDK_HRUDP_FRAME_HEADER_SIZE != len(payload)
        ):
            continue
        candidate = payload[HCNETSDK_HRUDP_FRAME_HEADER_SIZE:]
        if _looks_like_hcnetsdk_wrapped_media_payload(candidate):
            return candidate
    return None


def _looks_like_hcnetsdk_wrapped_media_payload(payload: bytes) -> bool:
    if payload.startswith(MPEG_PS_START_CODE):
        return True
    if _looks_like_idmx_local_payload(payload):
        return True
    return _strip_local_sdk_payload_header(payload).startswith(MPEG_PS_START_CODE)


def _strip_local_sdk_payload_header(payload: bytes) -> bytes:
    """Remove the 2-byte EZVIZ local stream fragment header before MPEG-PS.

    The direct-local 9020 path wraps every RTP payload body with a small
    fragment marker. Observed local-SDK values are 1c80 for the first fragment
    of a PS packet and 1c00 for continuations. FFmpeg expects concatenated
    MPEG-PS bytes, so callers should not see this local transport marker.
    """
    if len(payload) >= 2 and payload[0] == 0x1C:
        return payload[2:]
    return payload


def _local_sdk_endpoint_from_client(client: Any, serial: str) -> HcNetSdkLanEndpoint:
    devices = client.get_device_infos(serial)
    device = None
    if isinstance(devices, dict):
        if isinstance(devices.get(serial), dict):
            device = devices[serial]
        elif isinstance(devices.get("CONNECTION"), dict):
            device = devices
    if not isinstance(device, dict):
        raise PyEzvizError(f"EZVIZ device {serial!r} was not found")
    connection = device.get("CONNECTION")
    if not isinstance(connection, dict):
        raise PyEzvizError(f"EZVIZ device {serial!r} does not include CONNECTION data")
    return HcNetSdkLanEndpoint.from_connection(serial, connection)


def _open_local_mpegts_remux_process(ffmpeg_path: str) -> subprocess.Popen[bytes]:
    return open_mpegts_remux_process(ffmpeg_path, popen=subprocess.Popen)


def _open_local_hevc_mpegts_remux_process(
    ffmpeg_path: str,
    *,
    frame_rate: str = str(IDMX_DEFAULT_VIDEO_FRAME_RATE),
) -> subprocess.Popen[bytes]:
    return open_mpegts_remux_process(
        ffmpeg_path,
        input_format="hevc",
        frame_rate=frame_rate,
        popen=subprocess.Popen,
    )


def _open_local_h264_mpegts_remux_process(
    ffmpeg_path: str,
) -> subprocess.Popen[bytes]:
    return open_mpegts_remux_process(
        ffmpeg_path,
        input_format="h264",
        popen=subprocess.Popen,
    )


def _open_local_idmx_audio_video_mpegts_remux_process(
    ffmpeg_path: str,
    *,
    video_input_format: str,
    audio_path: str,
    video_frame_rate: str | None,
) -> subprocess.Popen[bytes]:
    return open_mpegts_remux_process(
        ffmpeg_path,
        input_format=video_input_format,
        frame_rate=video_frame_rate,
        audio_path=audio_path,
        popen=subprocess.Popen,
    )


IDMX_LOCAL_FRAME_SENTINEL = b"\x55\x66\x77\x88"
IDMX_LOCAL_FRAME_HEADER_SIZE = 13
IDMX_LOCAL_FRAME_SENTINEL_OFFSETS = (8, 9)
H264_NAL_HEADER_SIZE = 1
HEVC_NAL_HEADER_SIZE = 2
IDMX_H264_RTP_PAYLOAD_TYPE = 96
IDMX_AAC_RTP_PAYLOAD_TYPE = 104
H264_FU_A_NAL_TYPE = 28
IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET = 12
IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX = b"\x24\0"
HCNETSDK_HRUDP_FRAME_HEADER_SIZE = 12
HCNETSDK_HRUDP_VIDEO_FRAME_TYPE = 3


def collect_local_stream_media_packets(
    stream: Any,
    *,
    max_packets: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[bytes]:
    """Collect bounded local media payloads while preserving RTP packet boundaries."""

    return list(
        _iter_local_stream_payloads(
            stream,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )
    )


def summarize_idmx_h264_local_packets(
    packets: Iterable[bytes],
    *,
    max_frames: int = 64,
) -> dict[str, Any]:
    """Return sanitized IDMX/H.264 frame-shape metadata for local media packets."""

    payloads = list(packets)
    summary: dict[str, Any] = {
        "packet_count": len(payloads),
        "payload_bytes": sum(len(payload) for payload in payloads),
        "looks_like_idmx": _local_stream_packets_are_idmx(payloads),
        "frame_count": 0,
        "sample_limit": max_frames,
        "samples": [],
        "h264": {
            "clear_nal": 0,
            "fu_a": 0,
            "fu_a_start": 0,
            "fu_a_end": 0,
            "non_idr": 0,
            "idr": 0,
            "sei": 0,
            "sps": 0,
            "pps": 0,
            "aud": 0,
            "unknown": 0,
        },
        "hevc": {
            "parameter": 0,
            "media": 0,
        },
        "packet_shapes": _summarize_idmx_packet_shapes(
            payloads,
            max_samples=max_frames,
        ),
        "rtp_profile": _idmx_route_diagnostics(payloads),
        "h264_nal_units": {
            "sample_limit": max_frames,
            "samples": [],
            "truncated": False,
            "incomplete_fu_a": 0,
            "discarded_fu_a_fragments": 0,
            "sequence_gap_count": 0,
            "timestamp_change_count": 0,
            "restart_count": 0,
        },
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    h264_payload_types = _idmx_local_video_payload_types(payloads, codec="h264")
    active_h264_fu: dict[str, Any] | None = None
    for frame_index, frame in enumerate(_iter_idmx_local_packet_frames(payloads)):
        summary["frame_count"] = frame_index + 1
        frame_summary = _summarize_idmx_h264_local_frame(
            frame,
            frame_index,
            h264_payload_types=h264_payload_types,
        )
        _merge_idmx_h264_frame_summary(summary, frame_summary)
        active_h264_fu = _record_idmx_h264_nal_unit_summary(
            summary,
            frame,
            frame_summary,
            active_fu=active_h264_fu,
            h264_payload_types=h264_payload_types,
        )
        if len(samples) < max_frames:
            samples.append(frame_summary)
    if active_h264_fu is not None:
        _increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _append_idmx_h264_nal_unit_sample(
            summary,
            active_h264_fu,
            complete=False,
            end_frame_index=None,
        )
    return summary


def _idmx_route_diagnostics(packets: list[bytes]) -> dict[str, object]:
    """Return sanitized codec/ownership metadata for a local IDMX capture."""

    parsed: list[RtpPacket] = []
    profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            parsed.append(packet)
            profile.absorb(packet)
    for packet in parsed:
        if profile.media_kind(packet) in {"video", "audio"}:
            profile.mark_media(packet, absorb=False)
    return profile.diagnostics()


def _summarize_idmx_packet_shapes(
    packets: list[bytes],
    *,
    max_samples: int,
) -> dict[str, Any]:
    """Return bounded packet-wrapper diagnostics for IDMX captures."""

    summary: dict[str, Any] = {
        "sample_limit": max_samples,
        "samples": [],
        "truncated": False,
        "idmx_at_offset_0": 0,
        "length_prefixed_idmx": 0,
        "contains_idmx": 0,
        "possible_hrudp_wrapped": 0,
        "possible_hrudp_video": 0,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)
    for packet_index, packet in enumerate(packets):
        shape = _summarize_idmx_packet_shape(packet, packet_index)
        if shape["idmx_offset"] == 0:
            summary["idmx_at_offset_0"] = int(summary["idmx_at_offset_0"]) + 1
        if shape.get("length_prefix") is not None:
            summary["length_prefixed_idmx"] = int(summary["length_prefixed_idmx"]) + 1
        if shape["idmx_offset"] is not None:
            summary["contains_idmx"] = int(summary["contains_idmx"]) + 1
        hrdp_shape = shape.get("possible_hrudp")
        if isinstance(hrdp_shape, dict):
            summary["possible_hrudp_wrapped"] = (
                int(summary["possible_hrudp_wrapped"]) + 1
            )
            if hrdp_shape.get("frame_type") == HCNETSDK_HRUDP_VIDEO_FRAME_TYPE:
                summary["possible_hrudp_video"] = int(summary["possible_hrudp_video"]) + 1
        if len(samples) >= max_samples:
            summary["truncated"] = True
            continue
        samples.append(shape)
    return summary


def _summarize_idmx_packet_shape(packet: bytes, packet_index: int) -> dict[str, Any]:
    """Return sanitized shape metadata for one sampled command-port packet."""

    idmx_offset = packet.find(IDMX_LOCAL_FRAME_SENTINEL)
    if idmx_offset >= 0:
        frame_offsets: list[tuple[int, int]] = []
        for sentinel_offset in IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
            frame_offset = idmx_offset - sentinel_offset
            if frame_offset < 0:
                continue
            header_size = _idmx_local_frame_header_size(packet[frame_offset:])
            header_score = _idmx_local_frame_header_score(
                packet[frame_offset:],
                header_size,
            )
            if header_score is not None:
                frame_offsets.append((frame_offset, header_score))
        idmx_frame_offset = (
            min(frame_offsets, key=lambda item: (item[1], item[0]))[0]
            if frame_offsets
            else None
        )
    else:
        idmx_frame_offset = None

    shape: dict[str, Any] = {
        "index": packet_index,
        "packet_length": len(packet),
        "sha256": hashlib.sha256(packet).hexdigest(),
        "idmx_offset": idmx_frame_offset,
    }
    if idmx_frame_offset is not None and idmx_frame_offset >= 4:
        prefixed_length = int.from_bytes(
            packet[idmx_frame_offset - 4 : idmx_frame_offset],
            "little",
        )
        if (
            prefixed_length >= IDMX_LOCAL_FRAME_HEADER_SIZE
            and idmx_frame_offset + prefixed_length <= len(packet)
        ):
            shape["length_prefix"] = prefixed_length

    hrdp_shape = _possible_hcnetsdk_hrudp_packet_shape(packet)
    if hrdp_shape is not None:
        shape["possible_hrudp"] = hrdp_shape
    else:
        try:
            unwrapped = rtp_payload(packet)
        except PyEzvizError:
            pass
        else:
            hrdp_shape = _possible_hcnetsdk_hrudp_packet_shape(unwrapped)
            if hrdp_shape is not None:
                hrdp_shape = dict(hrdp_shape)
                hrdp_shape["rtp_wrapped"] = True
                shape["possible_hrudp"] = hrdp_shape
    return shape


def _possible_hcnetsdk_hrudp_packet_shape(packet: bytes) -> dict[str, Any] | None:
    """Return likely HCPreview HRUDP wrapper fields when a packet is self-bounded."""

    if len(packet) < HCNETSDK_HRUDP_FRAME_HEADER_SIZE:
        return None
    for byte_order in ("little", "big"):
        payload_length = int.from_bytes(packet[0:4], byte_order)
        if payload_length + HCNETSDK_HRUDP_FRAME_HEADER_SIZE != len(packet):
            continue
        frame_type = int.from_bytes(packet[4:8], byte_order)
        sequence = int.from_bytes(packet[8:12], byte_order)
        if frame_type > 16:
            continue
        return {
            "byte_order": byte_order,
            "payload_length": payload_length,
            "frame_type": frame_type,
            "sequence": sequence,
            "payload_starts_with_idmx": _idmx_local_frame_header_size(
                packet[HCNETSDK_HRUDP_FRAME_HEADER_SIZE:]
            )
            is not None,
            "payload_contains_idmx": IDMX_LOCAL_FRAME_SENTINEL
            in packet[HCNETSDK_HRUDP_FRAME_HEADER_SIZE:],
        }
    return None


def summarize_h264_annexb_units(
    data: bytes,
    *,
    max_units: int = 64,
) -> dict[str, Any]:
    """Return sanitized H.264 Annex-B NAL-unit metadata."""

    summary: dict[str, Any] = {
        "byte_count": len(data),
        "nal_count": 0,
        "sample_limit": max_units,
        "samples": [],
        "truncated": False,
        "h264": {
            "non_idr": 0,
            "idr": 0,
            "sei": 0,
            "sps": 0,
            "pps": 0,
            "aud": 0,
            "unknown": 0,
        },
    }
    samples = summary["samples"]
    h264 = summary["h264"]
    assert isinstance(samples, list)
    assert isinstance(h264, dict)

    for index, (start_code_offset, nal_start, end) in enumerate(
        _h264_annexb_nal_spans(data),
    ):
        nal = data[nal_start:end]
        nal_type = _h264_nal_type(nal)
        summary["nal_count"] = index + 1
        _increment_h264_nal_type_count(h264, nal_type)
        if len(samples) >= max_units:
            summary["truncated"] = True
            continue
        samples.append(
            {
                "index": index,
                "start_code_offset": start_code_offset,
                "nal_offset": nal_start,
                "end_offset": end,
                "nal_type": nal_type,
                "payload_bytes": len(nal),
                "sha256": hashlib.sha256(nal).hexdigest(),
            }
        )
    return summary


def summarize_h264_annexb_idr_windows(
    data: bytes,
    *,
    max_windows: int = 16,
) -> dict[str, Any]:
    """Return sanitized IDR-started H.264 Annex-B window metadata."""

    spans = _h264_annexb_nal_spans(data)
    nal_types = [_h264_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    idr_indexes = [index for index, nal_type in enumerate(nal_types) if nal_type == 5]
    summary: dict[str, Any] = {
        "byte_count": len(data),
        "nal_count": len(spans),
        "idr_count": len(idr_indexes),
        "sample_limit": max_windows,
        "samples": [],
        "truncated": False,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)

    for sample_index, idr_nal_index in enumerate(idr_indexes):
        if len(samples) >= max_windows:
            summary["truncated"] = True
            break
        start_nal_index = _h264_annexb_idr_window_start_index(nal_types, idr_nal_index)
        next_idr_nal_index = (
            idr_indexes[sample_index + 1]
            if sample_index + 1 < len(idr_indexes)
            else None
        )
        next_window_start_nal_index = (
            _h264_annexb_idr_window_start_index(nal_types, next_idr_nal_index)
            if next_idr_nal_index is not None
            else None
        )
        end_nal_index = (
            next_window_start_nal_index
            if next_window_start_nal_index is not None
            else len(spans)
        )
        start_offset = spans[start_nal_index][0]
        end_offset = (
            spans[next_window_start_nal_index][0]
            if next_window_start_nal_index is not None
            else len(data)
        )
        idr_start_code_offset, idr_nal_offset, idr_end_offset = spans[idr_nal_index]
        samples.append(
            {
                "index": sample_index,
                "start_nal_index": start_nal_index,
                "idr_nal_index": idr_nal_index,
                "end_nal_index": end_nal_index,
                "start_code_offset": start_offset,
                "idr_start_code_offset": idr_start_code_offset,
                "end_offset": end_offset,
                "window_bytes": max(end_offset - start_offset, 0),
                "leading_nal_types": nal_types[start_nal_index:idr_nal_index],
                "idr_payload_bytes": max(idr_end_offset - idr_nal_offset, 0),
                "idr_sha256": hashlib.sha256(data[idr_nal_offset:idr_end_offset]).hexdigest(),
                "window_sha256": hashlib.sha256(data[start_offset:end_offset]).hexdigest(),
            }
        )
    return summary


def summarize_hevc_annexb_irap_windows(
    data: bytes,
    *,
    max_windows: int = 16,
) -> dict[str, Any]:
    """Return sanitized IRAP-started HEVC Annex-B window metadata."""

    spans = _h264_annexb_nal_spans(data)
    nal_types = [_hevc_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    irap_indexes = [
        index for index, nal_type in enumerate(nal_types) if 16 <= nal_type <= 21
    ]
    summary: dict[str, Any] = {
        "byte_count": len(data),
        "nal_count": len(spans),
        "irap_count": len(irap_indexes),
        "sample_limit": max_windows,
        "samples": [],
        "truncated": False,
    }
    samples = summary["samples"]
    assert isinstance(samples, list)

    for sample_index, irap_nal_index in enumerate(irap_indexes):
        if len(samples) >= max_windows:
            summary["truncated"] = True
            break
        start_nal_index = _hevc_annexb_irap_window_start_index(
            nal_types,
            irap_nal_index,
        )
        next_irap_nal_index = (
            irap_indexes[sample_index + 1]
            if sample_index + 1 < len(irap_indexes)
            else None
        )
        next_window_start_nal_index = (
            _hevc_annexb_irap_window_start_index(nal_types, next_irap_nal_index)
            if next_irap_nal_index is not None
            else None
        )
        end_nal_index = (
            next_window_start_nal_index
            if next_window_start_nal_index is not None
            else len(spans)
        )
        start_offset = spans[start_nal_index][0]
        end_offset = (
            spans[next_window_start_nal_index][0]
            if next_window_start_nal_index is not None
            else len(data)
        )
        irap_start_code_offset, irap_nal_offset, irap_end_offset = spans[irap_nal_index]
        samples.append(
            {
                "index": sample_index,
                "start_nal_index": start_nal_index,
                "irap_nal_index": irap_nal_index,
                "end_nal_index": end_nal_index,
                "start_code_offset": start_offset,
                "irap_start_code_offset": irap_start_code_offset,
                "end_offset": end_offset,
                "window_bytes": max(end_offset - start_offset, 0),
                "leading_nal_types": nal_types[start_nal_index:irap_nal_index],
                "irap_payload_bytes": max(irap_end_offset - irap_nal_offset, 0),
                "irap_sha256": hashlib.sha256(
                    data[irap_nal_offset:irap_end_offset]
                ).hexdigest(),
                "window_sha256": hashlib.sha256(data[start_offset:end_offset]).hexdigest(),
            }
        )
    return summary


def skip_h264_annexb_initial_idr_windows(data: bytes, count: int) -> bytes:
    """Return Annex-B bytes starting at the requested IDR window."""

    if count < 0:
        raise PyEzvizError("H.264 IDR-window skip count cannot be negative")
    if count == 0:
        return data
    spans = _h264_annexb_nal_spans(data)
    nal_types = [_h264_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    idr_indexes = [index for index, nal_type in enumerate(nal_types) if nal_type == 5]
    if count >= len(idr_indexes):
        raise PyEzvizError(
            "H.264 stream did not contain enough IDR windows to skip "
            f"{count} startup window(s)"
        )
    start_index = _h264_annexb_idr_window_start_index(nal_types, idr_indexes[count])
    return data[spans[start_index][0] :]


def skip_hevc_annexb_initial_irap_windows(data: bytes, count: int) -> bytes:
    """Return HEVC Annex-B bytes starting at the requested IRAP window."""

    if count < 0:
        raise PyEzvizError("HEVC IRAP-window skip count cannot be negative")
    if count == 0:
        return data
    spans = _h264_annexb_nal_spans(data)
    nal_types = [_hevc_nal_type(data[nal_start:end]) for _, nal_start, end in spans]
    irap_indexes = [
        index for index, nal_type in enumerate(nal_types) if 16 <= nal_type <= 21
    ]
    if count >= len(irap_indexes):
        raise PyEzvizError(
            "HEVC stream did not contain enough IRAP windows to skip "
            f"{count} startup window(s)"
        )
    start_index = _hevc_annexb_irap_window_start_index(nal_types, irap_indexes[count])
    return data[spans[start_index][0] :]


def collect_h264_idmx_annexb_after_first_clean_idr_window(  # noqa: PLR0912, PLR0915
    packets: Iterable[bytes],
    *,
    duration_seconds: float | None,
    monotonic: Callable[[], float] = time.monotonic,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
    wait_seconds: float = 60.0,
) -> bytes:
    """Collect IDMX packets from the first clean IDR window onward.

    This is a streaming-friendly variant of post-capture clean-IDR trimming:
    startup packets may be discarded for up to ``wait_seconds``, and the
    requested ``duration_seconds`` window starts only after a decodable IDR
    window is found.
    """

    if duration_seconds is None:
        raise PyEzvizError("duration_seconds is required when waiting for clean IDR")
    if wait_seconds < 0:
        raise PyEzvizError("wait_seconds cannot be negative")
    if max_windows <= 0:
        raise PyEzvizError("max_windows must be positive")

    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_idr_time: float | None = None
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0

    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _h264_clean_idr_timeout_suffix(
                first_decode_error=first_decode_error,
                probe=last_probe,
            )
            raise PyEzvizError(
                "Timed out waiting for a clean H.264 IDR window" + suffix
            )
        if (
            clean_start_offset is not None
            and capture_deadline is not None
            and clean_idr_time is not None
            and now >= capture_deadline
            and last_suffix_probe_packet_count == 0
        ):
            deadline_packets = [
                packet
                for packet, packet_time in zip(collected, packet_times, strict=True)
                if packet_time < capture_deadline or packet_time == clean_idr_time
            ]
            deadline_packet_times = packet_times[: len(deadline_packets)]
            annexb = _idmx_local_packets_to_h264_annexb(deadline_packets)
            try:
                return trim_h264_annexb_to_first_error_free_suffix(
                    annexb[clean_start_offset:],
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                    accept_start_offset=_requested_duration_h264_suffix_predicate(
                        packets=deadline_packets,
                        packet_times=deadline_packet_times,
                        base_offset=clean_start_offset,
                        now=capture_deadline,
                        duration_seconds=duration_seconds,
                    ),
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _should_probe_clean_window(
                packet_count=len(collected),
                last_probe_packet_count=last_clean_probe_packet_count,
            ):
                continue
            last_clean_probe_packet_count = len(collected)
            probe = _try_first_clean_h264_annexb_idr_window_offset(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            last_probe = probe
            clean_start_offset = probe.start_offset
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="H.264 stream did not contain a clean IDR window",
            )
            if clean_start_offset is not None:
                clean_idr_packet_index = _h264_annexb_packet_index_for_offset(
                    collected,
                    offset=getattr(probe, "idr_start_offset", None)
                    or clean_start_offset,
                )
                clean_idr_time = packet_times[clean_idr_packet_index]
                capture_deadline = clean_idr_time + duration_seconds
            continue
        if (
            capture_deadline is not None
            and now >= capture_deadline
            and (
                len(collected) - last_suffix_probe_packet_count
                >= _CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL
            )
        ):
            annexb = _idmx_local_packets_to_h264_annexb(collected)
            try:
                return trim_h264_annexb_to_first_error_free_suffix(
                    annexb[clean_start_offset:],
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                    accept_start_offset=_requested_duration_h264_suffix_predicate(
                        packets=collected,
                        packet_times=packet_times,
                        base_offset=clean_start_offset,
                        now=now,
                        duration_seconds=duration_seconds,
                    ),
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise PyEzvizError(
                        "Timed out waiting for a clean final H.264 suffix: "
                        + str(err)
                    ) from err

    if clean_start_offset is None:
        if collected and last_clean_probe_packet_count != len(collected):
            probe = _try_first_clean_h264_annexb_idr_window_offset(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            last_probe = probe
            clean_start_offset = probe.start_offset
            if first_decode_error is None and probe.first_decode_error is not None:
                first_decode_error = probe.first_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="H.264 stream did not contain a clean IDR window",
            )
        suffix = _h264_clean_idr_timeout_suffix(
            first_decode_error=first_decode_error,
            probe=last_probe,
        )
        if clean_start_offset is None:
            raise PyEzvizError(
                "H.264 stream ended before a clean IDR window was found" + suffix
            )
    annexb = _idmx_local_packets_to_h264_annexb(collected)
    try:
        return trim_h264_annexb_to_first_error_free_suffix(
            annexb[clean_start_offset:],
            ffmpeg_path=ffmpeg_path,
            max_windows=max_windows,
            accept_start_offset=_requested_duration_h264_suffix_predicate(
                packets=collected,
                packet_times=packet_times,
                base_offset=clean_start_offset,
                now=packet_times[-1] if packet_times else 0.0,
                duration_seconds=duration_seconds,
            ),
        )
    except PyEzvizError as err:
        if final_decode_error:
            raise PyEzvizError(final_decode_error) from err
        raise


def _hevc_prefixed_suffix_accept_start_offset(
    accept_start_offset: Callable[[int], bool],
    *,
    prefix_length: int,
) -> Callable[[int], bool]:
    """Map offsets in a parameter-prefixed HEVC suffix back to the original suffix."""

    if prefix_length <= 0:
        return accept_start_offset

    def accepts(offset: int) -> bool:
        return accept_start_offset(max(0, offset - prefix_length))

    return accepts


def collect_idmx_annexb_after_first_clean_video_window(  # noqa: PLR0912, PLR0915
    packets: Iterable[bytes],
    *,
    duration_seconds: float | None,
    monotonic: Callable[[], float] = time.monotonic,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
    wait_seconds: float = 60.0,
) -> tuple[bytes, str]:
    """Collect clear IDMX video from the first clean H.264 IDR or HEVC IRAP."""

    if duration_seconds is None:
        raise PyEzvizError("duration_seconds is required when waiting for clean video")
    if wait_seconds < 0:
        raise PyEzvizError("wait_seconds cannot be negative")
    if max_windows <= 0:
        raise PyEzvizError("max_windows must be positive")

    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_codec: str | None = None
    clean_prefix = b""
    clean_window_time: float | None = None
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0

    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _h264_clean_idr_timeout_suffix(
                first_decode_error=first_decode_error,
                probe=last_probe,
            )
            raise PyEzvizError("Timed out waiting for a clean video window" + suffix)
        if (
            clean_start_offset is not None
            and clean_codec is not None
            and capture_deadline is not None
            and clean_window_time is not None
            and now >= capture_deadline
            and last_suffix_probe_packet_count == 0
        ):
            deadline_packets = [
                packet
                for packet, packet_time in zip(collected, packet_times, strict=True)
                if packet_time < capture_deadline or packet_time == clean_window_time
            ]
            if clean_codec == "h264":
                annexb = _idmx_local_packets_to_h264_annexb(deadline_packets)
                trim = trim_h264_annexb_to_first_error_free_suffix
            else:
                annexb = _idmx_local_packets_to_hevc_annexb(deadline_packets)
                trim = trim_hevc_annexb_to_first_error_free_suffix
                annexb = clean_prefix + annexb[clean_start_offset:]
                accept_start_offset = _hevc_prefixed_suffix_accept_start_offset(
                    _requested_duration_idmx_suffix_predicate(
                        packets=deadline_packets,
                        packet_times=packet_times[: len(deadline_packets)],
                        codec=clean_codec,
                        base_offset=clean_start_offset,
                        now=capture_deadline,
                        duration_seconds=duration_seconds,
                    ),
                    prefix_length=len(clean_prefix),
                )
            if clean_codec == "h264":
                annexb = annexb[clean_start_offset:]
                accept_start_offset = _requested_duration_idmx_suffix_predicate(
                    packets=deadline_packets,
                    packet_times=packet_times[: len(deadline_packets)],
                    codec=clean_codec,
                    base_offset=clean_start_offset,
                    now=capture_deadline,
                    duration_seconds=duration_seconds,
                )
            try:
                return (
                    trim(
                        annexb,
                        ffmpeg_path=ffmpeg_path,
                        max_windows=max_windows,
                        accept_start_offset=accept_start_offset,
                    ),
                    clean_codec,
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _should_probe_clean_window(
                packet_count=len(collected),
                last_probe_packet_count=last_clean_probe_packet_count,
            ):
                continue
            last_clean_probe_packet_count = len(collected)
            (
                probe_start_offset,
                probe_codec,
                probe_decode_error,
                last_probe,
            ) = _probe_first_clean_idmx_video_window(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            if first_decode_error is None and probe_decode_error is not None:
                first_decode_error = probe_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=last_probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="IDMX stream did not contain a clean video window",
            )
            if probe_start_offset is not None and probe_codec is not None:
                clean_start_offset = probe_start_offset
                clean_codec = probe_codec
                clean_prefix = (
                    getattr(last_probe, "prefix", b"") if probe_codec == "hevc" else b""
                )
                clean_packet_index = _idmx_annexb_packet_index_for_offset(
                    collected,
                    codec=probe_codec,
                    offset=getattr(last_probe, "idr_start_offset", None)
                    or clean_start_offset,
                )
                clean_window_time = packet_times[clean_packet_index]
                capture_deadline = clean_window_time + duration_seconds
            continue

        if (
            capture_deadline is not None
            and now >= capture_deadline
            and (
                len(collected) - last_suffix_probe_packet_count
                >= _CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL
            )
        ):
            assert clean_codec is not None
            if clean_codec == "h264":
                annexb = _idmx_local_packets_to_h264_annexb(collected)
                trim = trim_h264_annexb_to_first_error_free_suffix
            else:
                annexb = _idmx_local_packets_to_hevc_annexb(collected)
                trim = trim_hevc_annexb_to_first_error_free_suffix
                annexb = clean_prefix + annexb[clean_start_offset:]
                accept_start_offset = _hevc_prefixed_suffix_accept_start_offset(
                    _requested_duration_idmx_suffix_predicate(
                        packets=collected,
                        packet_times=packet_times,
                        codec=clean_codec,
                        base_offset=clean_start_offset,
                        now=now,
                        duration_seconds=duration_seconds,
                    ),
                    prefix_length=len(clean_prefix),
                )
            if clean_codec == "h264":
                annexb = annexb[clean_start_offset:]
                accept_start_offset = _requested_duration_idmx_suffix_predicate(
                    packets=collected,
                    packet_times=packet_times,
                    codec=clean_codec,
                    base_offset=clean_start_offset,
                    now=now,
                    duration_seconds=duration_seconds,
                )
            try:
                return (
                    trim(
                        annexb,
                        ffmpeg_path=ffmpeg_path,
                        max_windows=max_windows,
                        accept_start_offset=accept_start_offset,
                    ),
                    clean_codec,
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise PyEzvizError(
                        f"Timed out waiting for a clean final {clean_codec.upper()} suffix: "
                        + str(err)
                    ) from err

    if clean_start_offset is None or clean_codec is None:
        if collected and last_clean_probe_packet_count != len(collected):
            (
                probe_start_offset,
                probe_codec,
                probe_decode_error,
                last_probe,
            ) = _probe_first_clean_idmx_video_window(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            if first_decode_error is None and probe_decode_error is not None:
                first_decode_error = probe_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=last_probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="IDMX stream did not contain a clean video window",
            )
            if probe_start_offset is not None and probe_codec is not None:
                clean_start_offset = probe_start_offset
                clean_codec = probe_codec
                clean_prefix = (
                    getattr(last_probe, "prefix", b"") if probe_codec == "hevc" else b""
                )
        suffix = _h264_clean_idr_timeout_suffix(
            first_decode_error=first_decode_error,
            probe=last_probe,
        )
        if clean_start_offset is None or clean_codec is None:
            raise PyEzvizError(
                "IDMX stream ended before a clean video window was found" + suffix
            )

    if clean_codec == "h264":
        annexb = _idmx_local_packets_to_h264_annexb(collected)
        annexb = trim_h264_annexb_to_first_error_free_suffix(
            annexb[clean_start_offset:],
            ffmpeg_path=ffmpeg_path,
            max_windows=max_windows,
            accept_start_offset=_requested_duration_idmx_suffix_predicate(
                packets=collected,
                packet_times=packet_times,
                codec="h264",
                base_offset=clean_start_offset,
                now=packet_times[-1] if packet_times else 0.0,
                duration_seconds=duration_seconds,
            ),
        )
        return annexb, clean_codec
    else:
        annexb = _idmx_local_packets_to_hevc_annexb(collected)
        try:
            annexb = trim_hevc_annexb_to_first_error_free_suffix(
                clean_prefix + annexb[clean_start_offset:],
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
                accept_start_offset=_hevc_prefixed_suffix_accept_start_offset(
                    _requested_duration_idmx_suffix_predicate(
                        packets=collected,
                        packet_times=packet_times,
                        codec="hevc",
                        base_offset=clean_start_offset,
                        now=packet_times[-1] if packet_times else 0.0,
                        duration_seconds=duration_seconds,
                    ),
                    prefix_length=len(clean_prefix),
                ),
            )
        except PyEzvizError as err:
            if final_decode_error:
                raise PyEzvizError(final_decode_error) from err
            raise
    return annexb, clean_codec


def _probe_first_clean_idmx_video_window(
    packets: list[bytes],
    *,
    ffmpeg_path: str,
    max_windows: int,
) -> tuple[int | None, str | None, str | None, _H264CleanIdrProbeResult]:
    h264_probe = _try_first_clean_h264_annexb_idr_window_offset(
        packets,
        ffmpeg_path=ffmpeg_path,
        max_windows=max_windows,
    )
    if h264_probe.start_offset is not None:
        return (
            h264_probe.start_offset,
            "h264",
            h264_probe.first_decode_error,
            h264_probe,
        )

    hevc_probe = _try_first_clean_hevc_annexb_irap_window_offset(
        packets,
        ffmpeg_path=ffmpeg_path,
        max_windows=max_windows,
    )
    return (
        hevc_probe.start_offset,
        "hevc" if hevc_probe.start_offset is not None else None,
        h264_probe.first_decode_error or hevc_probe.first_decode_error,
        hevc_probe if hevc_probe.nal_count or hevc_probe.idr_count else h264_probe,
    )


def collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window(  # noqa: PLR0912, PLR0915
    packets: Iterable[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None = None,
    duration_seconds: float | None,
    monotonic: Callable[[], float] = time.monotonic,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
    wait_seconds: float = 60.0,
) -> bytes:
    """Collect decrypted IDMX H.264 from the first clean IDR window onward."""

    if duration_seconds is None:
        raise PyEzvizError("duration_seconds is required when waiting for clean IDR")
    if wait_seconds < 0:
        raise PyEzvizError("wait_seconds cannot be negative")
    if max_windows <= 0:
        raise PyEzvizError("max_windows must be positive")

    wait_deadline = monotonic() + wait_seconds
    capture_deadline: float | None = None
    collected: list[bytes] = []
    packet_times: list[float] = []
    clean_start_offset: int | None = None
    clean_idr_time: float | None = None
    clean_stream_is_clear = False
    first_decode_error: str | None = None
    final_decode_error: str | None = None
    last_suffix_probe_packet_count = 0
    last_probe = _H264CleanIdrProbeResult(start_offset=None)
    last_clean_probe_packet_count = 0

    for packet in packets:
        now = monotonic()
        if clean_start_offset is None and now >= wait_deadline:
            suffix = _h264_clean_idr_timeout_suffix(
                first_decode_error=first_decode_error,
                probe=last_probe,
            )
            raise PyEzvizError(
                "Timed out waiting for a clean H.264 IDR window" + suffix
            )
        if (
            clean_start_offset is not None
            and capture_deadline is not None
            and clean_idr_time is not None
            and now >= capture_deadline
            and last_suffix_probe_packet_count == 0
        ):
            deadline_packets = [
                packet
                for packet, packet_time in zip(collected, packet_times, strict=True)
                if packet_time < capture_deadline or packet_time == clean_idr_time
            ]
            if clean_stream_is_clear:
                annexb = _idmx_local_packets_to_h264_annexb(deadline_packets)
            else:
                annexb = _decrypt_idmx_local_packets_to_annexb(
                    deadline_packets,
                    media_key,
                    nalu_header_size=nalu_header_size,
                )
            try:
                return trim_h264_annexb_to_first_error_free_suffix(
                    annexb[clean_start_offset:],
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                    accept_start_offset=_requested_duration_decrypted_h264_suffix_predicate(
                        packets=deadline_packets,
                        packet_times=packet_times[: len(deadline_packets)],
                        media_key=media_key,
                        nalu_header_size=nalu_header_size,
                        stream_is_clear=clean_stream_is_clear,
                        base_offset=clean_start_offset,
                        now=capture_deadline,
                        duration_seconds=duration_seconds,
                    ),
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
        collected.append(packet)
        packet_times.append(now)
        if clean_start_offset is None:
            if not _should_probe_clean_window(
                packet_count=len(collected),
                last_probe_packet_count=last_clean_probe_packet_count,
            ):
                continue
            last_clean_probe_packet_count = len(collected)
            clear_probe = _try_first_clean_h264_annexb_idr_window_offset(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            if clear_probe.start_offset is not None:
                probe = clear_probe
                clean_stream_is_clear = True
            else:
                probe = _try_first_clean_decrypted_h264_annexb_idr_window_offset(
                    collected,
                    media_key,
                    nalu_header_size=nalu_header_size,
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                )
            if (
                first_decode_error is None
                and clear_probe.first_decode_error is not None
            ):
                first_decode_error = clear_probe.first_decode_error
            if (
                first_decode_error is None
                and probe.first_decode_error is not None
            ):
                first_decode_error = probe.first_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="H.264 stream did not contain a clean IDR window",
            )
            last_probe = probe
            clean_start_offset = probe.start_offset
            if clean_start_offset is not None:
                clean_idr_packet_index = (
                    _h264_annexb_packet_index_for_offset(
                        collected,
                        offset=probe.idr_start_offset or clean_start_offset,
                    )
                    if clean_stream_is_clear
                    else _decrypted_h264_annexb_packet_index_for_offset(
                        collected,
                        media_key,
                        nalu_header_size=nalu_header_size,
                        offset=probe.idr_start_offset or clean_start_offset,
                    )
                )
                clean_idr_time = packet_times[clean_idr_packet_index]
                capture_deadline = clean_idr_time + duration_seconds
            continue
        if (
            capture_deadline is not None
            and now >= capture_deadline
            and (
                len(collected) - last_suffix_probe_packet_count
                >= _CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL
            )
        ):
            if clean_stream_is_clear:
                annexb = _idmx_local_packets_to_h264_annexb(collected)
            else:
                annexb = _decrypt_idmx_local_packets_to_annexb(
                    collected,
                    media_key,
                    nalu_header_size=nalu_header_size,
                )
            try:
                return trim_h264_annexb_to_first_error_free_suffix(
                    annexb[clean_start_offset:],
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                    accept_start_offset=_requested_duration_decrypted_h264_suffix_predicate(
                        packets=collected,
                        packet_times=packet_times,
                        media_key=media_key,
                        nalu_header_size=nalu_header_size,
                        stream_is_clear=clean_stream_is_clear,
                        base_offset=clean_start_offset,
                        now=now,
                        duration_seconds=duration_seconds,
                    ),
                )
            except PyEzvizError as err:
                final_decode_error = final_decode_error or str(err)
                last_suffix_probe_packet_count = len(collected)
                if now >= capture_deadline + wait_seconds:
                    raise PyEzvizError(
                        "Timed out waiting for a clean final H.264 suffix: "
                        + str(err)
                    ) from err

    if clean_start_offset is None:
        if collected and last_clean_probe_packet_count != len(collected):
            clear_probe = _try_first_clean_h264_annexb_idr_window_offset(
                collected,
                ffmpeg_path=ffmpeg_path,
                max_windows=max_windows,
            )
            if clear_probe.start_offset is not None:
                probe = clear_probe
                clean_stream_is_clear = True
            else:
                probe = _try_first_clean_decrypted_h264_annexb_idr_window_offset(
                    collected,
                    media_key,
                    nalu_header_size=nalu_header_size,
                    ffmpeg_path=ffmpeg_path,
                    max_windows=max_windows,
                )
            if (
                first_decode_error is None
                and clear_probe.first_decode_error is not None
            ):
                first_decode_error = clear_probe.first_decode_error
            if (
                first_decode_error is None
                and probe.first_decode_error is not None
            ):
                first_decode_error = probe.first_decode_error
            _raise_if_clean_window_probe_exhausted(
                probe=probe,
                max_windows=max_windows,
                first_decode_error=first_decode_error,
                message="H.264 stream did not contain a clean IDR window",
            )
            last_probe = probe
            clean_start_offset = probe.start_offset
        suffix = _h264_clean_idr_timeout_suffix(
            first_decode_error=first_decode_error,
            probe=last_probe,
        )
        if clean_start_offset is None:
            raise PyEzvizError(
                "H.264 stream ended before a clean IDR window was found" + suffix
            )
    if clean_stream_is_clear:
        annexb = _idmx_local_packets_to_h264_annexb(collected)
    else:
        annexb = _decrypt_idmx_local_packets_to_annexb(
            collected,
            media_key,
            nalu_header_size=nalu_header_size,
        )
    try:
        return trim_h264_annexb_to_first_error_free_suffix(
            annexb[clean_start_offset:],
            ffmpeg_path=ffmpeg_path,
            max_windows=max_windows,
            accept_start_offset=_requested_duration_decrypted_h264_suffix_predicate(
                packets=collected,
                packet_times=packet_times,
                media_key=media_key,
                nalu_header_size=nalu_header_size,
                stream_is_clear=clean_stream_is_clear,
                base_offset=clean_start_offset,
                now=packet_times[-1] if packet_times else 0.0,
                duration_seconds=duration_seconds,
            ),
        )
    except PyEzvizError as err:
        if final_decode_error:
            raise PyEzvizError(final_decode_error) from err
        raise


def _h264_clean_idr_timeout_suffix(
    *,
    first_decode_error: str | None,
    probe: _H264CleanIdrProbeResult,
) -> str:
    """Return concise diagnostic context for a failed clean-IDR wait."""

    details = (
        f"checked {probe.complete_window_count} complete sampled "
        f"{probe.window_name} windows from {probe.idr_count} "
        f"{probe.window_name}s/{probe.nal_count} {probe.codec_name} NALs"
    )
    if first_decode_error:
        return f": {details}; first decode error: {first_decode_error}"
    if probe.idr_count or probe.nal_count:
        return f": {details}"
    return ""


def _raise_if_clean_window_probe_exhausted(
    *,
    probe: _H264CleanIdrProbeResult,
    max_windows: int,
    first_decode_error: str | None,
    message: str,
) -> None:
    """Stop streaming probes once the requested clean-window budget is spent."""

    if (
        getattr(probe, "start_offset", None) is not None
        or int(getattr(probe, "complete_window_count", 0) or 0) < max_windows
    ):
        return
    suffix = _h264_clean_idr_timeout_suffix(
        first_decode_error=first_decode_error,
        probe=probe,
    )
    raise PyEzvizError(message + suffix)


def _should_probe_clean_window(
    *,
    packet_count: int,
    last_probe_packet_count: int,
) -> bool:
    """Avoid rebuilding and decoding the growing packet buffer every packet."""

    if packet_count < _CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS:
        return True
    return (
        packet_count - last_probe_packet_count
        >= _CLEAN_WINDOW_PROBE_PACKET_INTERVAL
    )


def _requested_duration_h264_suffix_predicate(
    *,
    packets: list[bytes],
    packet_times: list[float],
    base_offset: int,
    now: float,
    duration_seconds: float,
) -> Callable[[int], bool]:
    """Return a suffix-start guard that preserves useful post-IDR duration."""

    latest_start_time = now - duration_seconds
    packet_end_offsets = _h264_annexb_packet_end_offsets(packets)

    def accept_start_offset(start_offset: int) -> bool:
        if not packet_times:
            return False
        packet_index = bisect.bisect_right(packet_end_offsets, base_offset + start_offset)
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time

    return accept_start_offset


def _requested_duration_idmx_suffix_predicate(
    *,
    packets: list[bytes],
    packet_times: list[float],
    codec: str,
    base_offset: int,
    now: float,
    duration_seconds: float,
) -> Callable[[int], bool]:
    """Return a suffix-start guard for clear H.264/HEVC IDMX Annex-B."""

    latest_start_time = now - duration_seconds
    if codec == "h264":
        packet_end_offsets = _h264_annexb_packet_end_offsets(packets)
    elif codec == "hevc":
        packet_end_offsets = _hevc_annexb_packet_end_offsets(packets)
    else:
        packet_end_offsets = []

    def accept_start_offset(start_offset: int) -> bool:
        if not packet_times:
            return False
        packet_index = (
            bisect.bisect_right(packet_end_offsets, base_offset + start_offset)
            if packet_end_offsets
            else max(len(packet_times) - 1, 0)
        )
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time

    return accept_start_offset


def _requested_duration_decrypted_h264_suffix_predicate(
    *,
    packets: list[bytes],
    packet_times: list[float],
    media_key: str | bytes,
    nalu_header_size: int | None,
    stream_is_clear: bool,
    base_offset: int,
    now: float,
    duration_seconds: float,
) -> Callable[[int], bool]:
    """Return a suffix-start guard for clear-first or encrypted H.264 IDMX."""

    latest_start_time = now - duration_seconds

    def accept_start_offset(start_offset: int) -> bool:
        if stream_is_clear:
            packet_index = _h264_annexb_packet_index_for_offset(
                packets,
                offset=base_offset + start_offset,
            )
        else:
            packet_index = _decrypted_h264_annexb_packet_index_for_offset(
                packets,
                media_key,
                nalu_header_size=nalu_header_size,
                offset=base_offset + start_offset,
            )
        if not packet_times:
            return False
        packet_index = min(packet_index, len(packet_times) - 1)
        return packet_times[packet_index] <= latest_start_time

    return accept_start_offset


def trim_h264_annexb_to_first_clean_idr_window(
    data: bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
) -> bytes:
    """Return Annex-B bytes from the first IDR window that decodes cleanly."""

    idr_summary = summarize_h264_annexb_idr_windows(data, max_windows=max_windows)
    samples = idr_summary.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PyEzvizError("H.264 stream did not contain IDR windows")
    first_error: str | None = None
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get("start_code_offset")
        if not isinstance(start_offset, int):
            continue
        end_offset = sample.get("end_offset")
        if not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        window = data[start_offset:end_offset]
        stderr_lines = _ffmpeg_h264_decode_errors(
            window,
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not stderr_lines:
            return data[start_offset:]
        if first_error is None and stderr_lines:
            first_error = stderr_lines[0]
    suffix = f": {first_error}" if first_error else ""
    raise PyEzvizError(
        "H.264 stream did not contain a clean sampled IDR window" + suffix
    )


def trim_h264_annexb_to_first_error_free_suffix(
    data: bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
    accept_start_offset: Callable[[int], bool] | None = None,
) -> bytes:
    """Return the earliest IDR-started suffix that decodes without errors."""

    if not data:
        return data
    initial_errors = _ffmpeg_h264_decode_errors(
        data,
        ffmpeg_path=ffmpeg_path,
        accept_success_with_stderr=False,
    )
    if not initial_errors and (
        accept_start_offset is None or accept_start_offset(0)
    ):
        return data

    idr_summary = summarize_h264_annexb_idr_windows(data, max_windows=max_windows)
    samples = idr_summary.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PyEzvizError(
            "H.264 stream did not contain a clean decodable suffix: "
            + (
                initial_errors[0]
                if initial_errors
                else "clean suffix starts too late for requested duration"
            )
        )
    first_error = (
        initial_errors[0]
        if initial_errors
        else "clean suffix starts too late for requested duration"
    )
    candidate_samples: list[tuple[dict[str, Any], int]] = []
    for sample in samples[1:]:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get("start_code_offset")
        if not isinstance(start_offset, int):
            continue
        if accept_start_offset is not None and not accept_start_offset(start_offset):
            continue
        candidate_samples.append((sample, start_offset))
    if len(candidate_samples) > _CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:
        candidate_samples = candidate_samples[-_CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:]
    for _sample, start_offset in candidate_samples:
        suffix = data[start_offset:]
        decode_errors = _ffmpeg_h264_decode_errors(
            suffix,
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not decode_errors:
            return suffix
        if not first_error and decode_errors:
            first_error = decode_errors[0]
    raise PyEzvizError(
        "H.264 stream did not contain a clean decodable suffix: " + first_error
    )


def trim_hevc_annexb_to_first_clean_irap_window(
    data: bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
) -> bytes:
    """Return Annex-B bytes from the first IRAP window that decodes cleanly."""

    irap_summary = summarize_hevc_annexb_irap_windows(data, max_windows=max_windows)
    samples = irap_summary.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PyEzvizError("HEVC stream did not contain IRAP windows")
    first_error: str | None = None
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get("start_code_offset")
        if not isinstance(start_offset, int):
            continue
        end_offset = sample.get("end_offset")
        if not isinstance(end_offset, int) or end_offset <= start_offset:
            continue
        prefix = _hevc_annexb_parameter_prefix_for_suffix(
            data,
            start_offset=start_offset,
            leading_nal_types=sample.get("leading_nal_types"),
        )
        window = prefix + data[start_offset:end_offset]
        stderr_lines = _ffmpeg_hevc_decode_errors(
            window,
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not stderr_lines:
            suffix = prefix + data[start_offset:]
            suffix_errors = _ffmpeg_hevc_decode_errors(
                suffix,
                ffmpeg_path=ffmpeg_path,
                accept_success_with_stderr=False,
            )
            if not suffix_errors:
                return suffix
            if first_error is None:
                first_error = suffix_errors[0]
            continue
        if first_error is None and stderr_lines:
            first_error = stderr_lines[0]
    error_suffix = f": {first_error}" if first_error else ""
    raise PyEzvizError(
        "HEVC stream did not contain a clean sampled IRAP window" + error_suffix
    )


def trim_hevc_annexb_to_first_error_free_suffix(
    data: bytes,
    *,
    ffmpeg_path: str = "ffmpeg",
    max_windows: int = 32,
    accept_start_offset: Callable[[int], bool] | None = None,
) -> bytes:
    """Return the earliest IRAP-started suffix that decodes without errors."""

    if not data:
        return data
    initial_errors = _ffmpeg_hevc_decode_errors(
        data,
        ffmpeg_path=ffmpeg_path,
        accept_success_with_stderr=False,
    )
    if not initial_errors and (
        accept_start_offset is None or accept_start_offset(0)
    ):
        return data

    irap_summary = summarize_hevc_annexb_irap_windows(data, max_windows=max_windows)
    samples = irap_summary.get("samples")
    if not isinstance(samples, list) or not samples:
        raise PyEzvizError(
            "HEVC stream did not contain a clean decodable suffix: "
            + (
                initial_errors[0]
                if initial_errors
                else "clean suffix starts too late for requested duration"
            )
        )
    first_error = (
        initial_errors[0]
        if initial_errors
        else "clean suffix starts too late for requested duration"
    )
    candidate_samples: list[tuple[dict[str, Any], int]] = []
    for sample in samples[1:]:
        if not isinstance(sample, dict):
            continue
        start_offset = sample.get("start_code_offset")
        if not isinstance(start_offset, int):
            continue
        if accept_start_offset is not None and not accept_start_offset(start_offset):
            continue
        candidate_samples.append((sample, start_offset))
    if len(candidate_samples) > _CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:
        candidate_samples = candidate_samples[-_CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES:]
    for sample, start_offset in candidate_samples:
        prefix = _hevc_annexb_parameter_prefix_for_suffix(
            data,
            start_offset=start_offset,
            leading_nal_types=sample.get("leading_nal_types"),
        )
        suffix = data[start_offset:]
        decode_errors = _ffmpeg_hevc_decode_errors(
            prefix + suffix,
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not decode_errors:
            return prefix + suffix
        if not first_error and decode_errors:
            first_error = decode_errors[0]
    raise PyEzvizError(
        "HEVC stream did not contain a clean decodable suffix: " + first_error
    )


def _hevc_annexb_parameter_prefix_for_suffix(
    data: bytes,
    *,
    start_offset: int,
    leading_nal_types: object,
) -> bytes:
    """Return prior VPS/SPS/PPS when a recovered IRAP lacks local parameters."""

    required_types = {32, 33, 34}
    local_types = (
        {item for item in leading_nal_types if isinstance(item, int)}
        if isinstance(leading_nal_types, list)
        else set()
    )
    missing_types = required_types - local_types
    if not missing_types:
        return b""
    latest: dict[int, bytes] = {}
    for start_code_offset, nal_start, end in _h264_annexb_nal_spans(
        data[:start_offset]
    ):
        nal_type = _hevc_nal_type(data[nal_start:end])
        if nal_type in missing_types:
            latest[nal_type] = data[start_code_offset:end]
    if not missing_types.issubset(latest):
        return b""
    return b"".join(latest[nal_type] for nal_type in (32, 33, 34) if nal_type in latest)


def _try_first_clean_h264_annexb_idr_window_offset(
    packets: list[bytes],
    *,
    ffmpeg_path: str,
    max_windows: int,
) -> _H264CleanIdrProbeResult:
    """Return the first clean IDR window offset for partial IDMX packets."""

    try:
        annexb = _idmx_local_packets_to_h264_annexb(packets)
    except PyEzvizError:
        return _H264CleanIdrProbeResult(start_offset=None)
    return _try_first_clean_h264_annexb_idr_window_offset_from_annexb(
        annexb,
        ffmpeg_path=ffmpeg_path,
        max_windows=max_windows,
    )


def _try_first_clean_decrypted_h264_annexb_idr_window_offset(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    ffmpeg_path: str,
    max_windows: int,
) -> _H264CleanIdrProbeResult:
    """Return the first clean IDR offset for partial encrypted IDMX packets."""

    try:
        annexb = _decrypt_idmx_local_packets_to_annexb(
            packets,
            media_key,
            nalu_header_size=nalu_header_size,
        )
    except PyEzvizError:
        return _H264CleanIdrProbeResult(start_offset=None)
    return _try_first_clean_h264_annexb_idr_window_offset_from_annexb(
        annexb,
        ffmpeg_path=ffmpeg_path,
        max_windows=max_windows,
    )


def _try_first_clean_hevc_annexb_irap_window_offset(
    packets: list[bytes],
    *,
    ffmpeg_path: str,
    max_windows: int,
) -> _H264CleanIdrProbeResult:
    """Return the first clean HEVC IRAP window offset for partial IDMX packets."""

    try:
        annexb = _idmx_local_packets_to_hevc_annexb(packets)
    except PyEzvizError:
        return _H264CleanIdrProbeResult(
            start_offset=None,
            codec_name="HEVC",
            window_name="IRAP",
        )

    irap_summary = summarize_hevc_annexb_irap_windows(annexb, max_windows=max_windows)
    samples = irap_summary.get("samples")
    if not isinstance(samples, list):
        return _H264CleanIdrProbeResult(
            start_offset=None,
            idr_count=int(irap_summary.get("irap_count", 0)),
            nal_count=int(irap_summary.get("nal_count", 0)),
            codec_name="HEVC",
            window_name="IRAP",
        )
    first_decode_error: str | None = None
    complete_window_count = 0
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        end_nal_index = sample.get("end_nal_index")
        if (
            not isinstance(end_nal_index, int)
            or end_nal_index >= int(irap_summary["nal_count"])
        ):
            continue
        start_offset = sample.get("start_code_offset")
        end_offset = sample.get("end_offset")
        if (
            not isinstance(start_offset, int)
            or not isinstance(end_offset, int)
            or end_offset <= start_offset
        ):
            continue
        complete_window_count += 1
        prefix = _hevc_annexb_parameter_prefix_for_suffix(
            annexb,
            start_offset=start_offset,
            leading_nal_types=sample.get("leading_nal_types"),
        )
        decode_errors = _ffmpeg_hevc_decode_errors(
            prefix + annexb[start_offset:end_offset],
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not decode_errors:
            return _H264CleanIdrProbeResult(
                start_offset=start_offset,
                idr_start_offset=int(sample["irap_start_code_offset"]),
                prefix=prefix,
                first_decode_error=first_decode_error,
                idr_count=int(irap_summary.get("irap_count", 0)),
                sampled_window_count=len(samples),
                complete_window_count=complete_window_count,
                nal_count=int(irap_summary.get("nal_count", 0)),
                codec_name="HEVC",
                window_name="IRAP",
            )
        if first_decode_error is None:
            first_decode_error = decode_errors[0]
    return _H264CleanIdrProbeResult(
        start_offset=None,
        first_decode_error=first_decode_error,
        idr_count=int(irap_summary.get("irap_count", 0)),
        sampled_window_count=len(samples),
        complete_window_count=complete_window_count,
        nal_count=int(irap_summary.get("nal_count", 0)),
        codec_name="HEVC",
        window_name="IRAP",
    )


def _decrypted_h264_annexb_packet_index_for_offset(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    offset: int,
) -> int:
    """Return the packet index that first contributes the given Annex-B offset."""

    _annexb, spans = _idmx_h264_annexb_packet_spans(
        packets,
        media_key,
        nalu_header_size=nalu_header_size,
        stream_is_clear=False,
    )
    for span in spans:
        if span[0] <= offset < span[1]:
            return span[2]
    return max(len(packets) - 1, 0)


def _decrypted_hevc_annexb_packet_index_for_offset(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    offset: int,
) -> int:
    """Return the first packet contributing the HEVC NAL at ``offset``."""

    _annexb, spans = _idmx_hevc_annexb_packet_spans(packets, media_key)
    for span in spans:
        if span[0] <= offset < span[1]:
            return span[2]
    return max(len(packets) - 1, 0)


def _idmx_h264_annexb_packet_spans(  # noqa: PLR0912, PLR0915
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None,
    stream_is_clear: bool,
) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int]]]:
    """Assemble H.264 while recording each NAL's contributing packet span."""

    output = bytearray()
    spans: list[tuple[int, int, int, int, int, int, int]] = []
    active_fu: _RtpFragmentedNal | None = None
    active_start_packet: int | None = None
    active_start_frame: int | None = None
    aes_key = _local_media_aes_key(media_key)
    header_size = H264_NAL_HEADER_SIZE if nalu_header_size is None else nalu_header_size
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="h264")
    route_epoch_profile = RtpRouteProfile()
    for packet_index, packet in enumerate(packets):
        for frame_index, frame in enumerate(
            _iter_idmx_local_packet_frame(
                packet,
                video_payload_types=routed_payload_types,
            )
        ):
            frame_header_size = _idmx_local_frame_header_size(frame)
            if frame_header_size is None:
                continue
            rtp_packet = _idmx_local_frame_rtp_packet(frame, frame_header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if (
                rtp_packet is None
                or rtp_packet.payload_type not in routed_payload_types
            ):
                continue
            body = _idmx_local_frame_media_body(frame, frame_header_size)
            if not _rtp_packet_matches_codec_epoch(
                route_epoch_profile,
                rtp_packet,
                "h264",
            ):
                continue
            if _looks_like_idmx_h264_fu_a_frame(body):
                is_start = bool(body[1] & 0x80)
                nal_type = body[1] & 0x1F
                if is_start:
                    active_start_packet = packet_index
                    active_start_frame = frame_index
                nal_start_packet = active_start_packet
                nal_start_frame = active_start_frame
                start_offset = len(output)
                active_fu = _append_idmx_h264_fu_a_payload(
                    output,
                    body,
                    active_fu=active_fu,
                    sequence_number=_idmx_local_frame_sequence_number(
                        frame,
                        frame_header_size,
                    ),
                    rtp_timestamp=_idmx_local_frame_rtp_timestamp(
                        frame,
                        frame_header_size,
                    ),
                    aes_key=None if stream_is_clear else aes_key,
                    nalu_header_size=header_size,
                )
                if len(output) > start_offset:
                    spans.append(
                        (
                            start_offset,
                            len(output),
                            nal_start_packet
                            if nal_start_packet is not None
                            else packet_index,
                            packet_index,
                            nal_type,
                            nal_start_frame
                            if nal_start_frame is not None
                            else frame_index,
                            frame_index,
                        )
                    )
                if active_fu is None:
                    active_start_packet = None
                    active_start_frame = None
                continue
            decrypted_body: bytes | None = None
            if not _looks_like_idmx_h264_clear_nal(body):
                if stream_is_clear or header_size != 0 or not body:
                    continue
                decrypted_body = _decrypt_h264_nal_prefix(
                    body,
                    aes_key,
                    nalu_header_size=header_size,
                )
            active_fu = None
            active_start_packet = None
            active_start_frame = None
            start_offset = len(output)
            if stream_is_clear:
                _append_h264_nal(output, body)
                nal_type = _h264_nal_type(body)
            elif decrypted_body is not None:
                _append_h264_nal(output, decrypted_body)
                nal_type = _h264_nal_type(decrypted_body)
            else:
                _append_decrypted_h264_nal(
                    output,
                    body,
                    aes_key,
                    nalu_header_size=header_size,
                )
                nal_type = _h264_nal_type(body)
            spans.append(
                (
                    start_offset,
                    len(output),
                    packet_index,
                    packet_index,
                    nal_type,
                    frame_index,
                    frame_index,
                )
            )
    return bytes(output), spans


def _idmx_hevc_annexb_packet_spans(  # noqa: PLR0912, PLR0915
    packets: list[bytes],
    media_key: str | bytes,
) -> tuple[bytes, list[tuple[int, int, int, int, int, int, int]]]:
    """Assemble decrypted HEVC while recording each NAL's packet span."""

    output = bytearray()
    spans: list[tuple[int, int, int, int, int, int, int]] = []
    active_fu: _RtpFragmentedNal | None = None
    active_start_packet: int | None = None
    active_start_frame: int | None = None
    active_end_packet: int | None = None
    active_end_frame: int | None = None
    active_nal_type: int | None = None
    hevc_evidence_seen = False
    aes_key = _local_media_aes_key(media_key)
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="hevc")
    routed_h264_payload_types = _idmx_local_video_payload_types(
        packets,
        codec="h264",
    )
    authoritative_hevc_route = bool(
        routed_payload_types and not routed_h264_payload_types
    )
    route_epoch_profile = RtpRouteProfile()
    for packet_index, packet in enumerate(packets):
        for frame_index, frame in enumerate(
            _iter_idmx_local_packet_frame(
                packet,
                video_payload_types=routed_payload_types,
            )
        ):
            frame_header_size = _idmx_local_frame_header_size(frame)
            if frame_header_size is None:
                continue
            body = _idmx_local_frame_media_body(frame, frame_header_size)
            rtp_packet = _idmx_local_frame_rtp_packet(frame, frame_header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            active_route_descriptor = next(
                (
                    descriptor
                    for descriptor in route_epoch_profile.descriptors
                    if rtp_packet is not None
                    and descriptor.payload_type == rtp_packet.payload_type
                ),
                None,
            )
            routed_transport = bool(
                rtp_packet is not None
                and rtp_packet.payload_type in routed_payload_types
            )
            hevc_epoch_compatible = bool(
                active_route_descriptor is None
                or active_route_descriptor.codec == "hevc"
            )
            conflicting_h264_route = bool(
                rtp_packet is not None
                and rtp_packet.payload_type
                in route_epoch_profile.codec_payload_types("h264")
            )
            wrapped_media = (
                routed_transport
                and hevc_epoch_compatible
                and _looks_like_idmx_hevc_media_frame(body)
            )
            direct_media = routed_transport and hevc_epoch_compatible and (
                authoritative_hevc_route
                or hevc_evidence_seen
                or _looks_like_idmx_hevc_evidence_frame(body)
            ) and _idmx_hevc_direct_frame_matches_route(
                body,
                authoritative_hevc=authoritative_hevc_route,
                conflicting_h264_route=conflicting_h264_route,
            )
            if wrapped_media:
                hevc_evidence_seen = True
                payload = body[IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET:]
                decrypt_parameter_sets = True
            elif direct_media:
                hevc_evidence_seen = True
                payload = body
                decrypt_parameter_sets = False
            else:
                continue
            if len(payload) < HEVC_NAL_HEADER_SIZE:
                continue
            nal_type = _hevc_nal_type(payload)
            if nal_type == 49 and len(payload) >= 3:
                if payload[2] & 0x80:
                    active_start_packet = packet_index
                    active_start_frame = frame_index
                    active_nal_type = payload[2] & 0x3F
                nal_start_packet = active_start_packet
                nal_start_frame = active_start_frame
                emitted_nal_type = active_nal_type
            else:
                nal_start_packet = packet_index
                nal_start_frame = frame_index
                emitted_nal_type = nal_type
            start_offset = len(output)
            active_fu = _append_idmx_hevc_media_payload(
                output,
                payload,
                aes_key,
                active_fu=active_fu,
                sequence_number=_idmx_local_frame_sequence_number(
                    frame,
                    frame_header_size,
                ),
                rtp_timestamp=_idmx_local_frame_rtp_timestamp(
                    frame,
                    frame_header_size,
                ),
                rtp_marker=_idmx_local_frame_rtp_marker(frame, frame_header_size),
                decrypt_parameter_sets=decrypt_parameter_sets,
            )
            if nal_type == 49 and active_fu is not None:
                active_end_packet = packet_index
                active_end_frame = frame_index
            if len(output) > start_offset:
                spans.append(
                    (
                        start_offset,
                        len(output),
                        nal_start_packet
                        if nal_start_packet is not None
                        else packet_index,
                        packet_index,
                        emitted_nal_type if emitted_nal_type is not None else nal_type,
                        nal_start_frame
                        if nal_start_frame is not None
                        else frame_index,
                        frame_index,
                    )
                )
            if active_fu is None:
                active_start_packet = None
                active_start_frame = None
                active_end_packet = None
                active_end_frame = None
                active_nal_type = None
    if active_fu is not None:
        start_offset = len(output)
        _append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
        end_packet = (
            active_end_packet
            if active_end_packet is not None
            else max(len(packets) - 1, 0)
        )
        end_frame = active_end_frame if active_end_frame is not None else 0
        spans.append(
            (
                start_offset,
                len(output),
                active_start_packet
                if active_start_packet is not None
                else end_packet,
                end_packet,
                active_nal_type
                if active_nal_type is not None
                else _hevc_nal_type(bytes(active_fu.data)),
                active_start_frame
                if active_start_frame is not None
                else end_frame,
                end_frame,
            )
        )
    return bytes(output), spans


def _idmx_h264_packets_from_selected_annexb(
    packets: list[bytes],
    *,
    full_annexb: bytes,
    selected_annexb: bytes,
    media_key: str | bytes,
    nalu_header_size: int | None,
    stream_is_clear: bool,
) -> list[bytes]:
    """Return the packet interval contributing selected H.264 VCL NALs."""

    _annexb, spans = _idmx_h264_annexb_packet_spans(
        packets,
        media_key,
        nalu_header_size=nalu_header_size,
        stream_is_clear=stream_is_clear,
    )
    return _idmx_packets_for_selected_vcl_spans(
        packets,
        spans=spans,
        full_annexb=full_annexb,
        selected_annexb=selected_annexb,
        video_input_format="h264",
    )


def _annexb_vcl_bounds(
    data: bytes,
    *,
    video_input_format: str,
) -> tuple[int, int] | None:
    bounds: list[tuple[int, int]] = []
    for start_code_offset, nal_start, end in _h264_annexb_nal_spans(data):
        nal = data[nal_start:end]
        if video_input_format == "h264":
            is_vcl = 1 <= _h264_nal_type(nal) <= 5
        elif video_input_format == "hevc":
            is_vcl = _hevc_nal_type(nal) <= 31
        else:
            raise PyEzvizError(
                f"Unsupported IDMX video input format: {video_input_format}"
            )
        if is_vcl:
            bounds.append((start_code_offset, end))
    return (bounds[0][0], bounds[-1][1]) if bounds else None


def _idmx_packet_frame_slice(
    packet: bytes,
    start: int,
    stop: int,
    *,
    video_payload_types: frozenset[int],
) -> bytes:
    frames = list(
        _iter_idmx_local_packet_frame(
            packet,
            video_payload_types=video_payload_types,
        )
    )
    if start == 0 and stop == len(frames):
        return packet
    return b"".join(
        len(frame).to_bytes(4, "little") + frame for frame in frames[start:stop]
    )


def _idmx_packets_for_selected_vcl_spans(
    packets: list[bytes],
    *,
    spans: list[tuple[int, int, int, int, int, int, int]],
    full_annexb: bytes,
    selected_annexb: bytes,
    video_input_format: str,
) -> list[bytes]:
    """Return packets and aggregate frames bounded by selected VCL NALs."""

    selected_bounds = _annexb_vcl_bounds(
        selected_annexb,
        video_input_format=video_input_format,
    )
    if selected_bounds is None:
        raise PyEzvizError("Trimmed IDMX stream did not include a video frame")
    first_vcl_offset, last_vcl_end = selected_bounds
    retained_tail = selected_annexb[first_vcl_offset:]
    retained_tail_offset = full_annexb.rfind(retained_tail)
    if retained_tail_offset >= 0:
        selected_start = retained_tail_offset
        selected_end = retained_tail_offset + last_vcl_end - first_vcl_offset
    else:
        first_vcl = selected_annexb[first_vcl_offset:last_vcl_end]
        selected_start = full_annexb.rfind(first_vcl)
        selected_end = selected_start + len(first_vcl)
    if selected_start < 0:
        raise PyEzvizError("Could not align trimmed IDMX video with its RTP packets")
    selected_spans = [
        span
        for span in spans
        if span[0] >= selected_start
        and span[1] <= selected_end
        and (
            1 <= span[4] <= 5
            if video_input_format == "h264"
            else span[4] <= 31
        )
    ]
    if not selected_spans:
        raise PyEzvizError("Could not align trimmed IDMX video with its RTP packets")
    first_span = selected_spans[0]
    last_span = selected_spans[-1]
    start_packet = first_span[2]
    end_packet = last_span[3]
    video_payload_types = _idmx_local_video_payload_types(
        packets,
        codec=cast(RtpVideoCodec, video_input_format),
    )
    if start_packet == end_packet:
        return [
            _idmx_packet_frame_slice(
                packets[start_packet],
                first_span[5],
                last_span[6] + 1,
                video_payload_types=video_payload_types,
            )
        ]
    selected_packets = [
        _idmx_packet_frame_slice(
            packets[start_packet],
            first_span[5],
            len(
                list(
                    _iter_idmx_local_packet_frame(
                        packets[start_packet],
                        video_payload_types=video_payload_types,
                    )
                )
            ),
            video_payload_types=video_payload_types,
        ),
        *packets[start_packet + 1 : end_packet],
        _idmx_packet_frame_slice(
            packets[end_packet],
            0,
            last_span[6] + 1,
            video_payload_types=video_payload_types,
        ),
    ]
    return [packet for packet in selected_packets if packet]


def _annexb_first_vcl_unit(data: bytes, *, video_input_format: str) -> bytes | None:
    for start_code_offset, nal_start, end in _h264_annexb_nal_spans(data):
        nal = data[nal_start:end]
        if video_input_format == "h264":
            is_vcl = 1 <= _h264_nal_type(nal) <= 5
        elif video_input_format == "hevc":
            is_vcl = _hevc_nal_type(nal) <= 31
        else:
            raise PyEzvizError(
                f"Unsupported IDMX video input format: {video_input_format}"
            )
        if is_vcl:
            return data[start_code_offset:end]
    return None


def _annexb_contains_selected_vcl(
    full_annexb: bytes,
    selected_annexb: bytes,
    *,
    video_input_format: str,
) -> bool:
    """Return whether a full stream contains the selected suffix or first VCL."""

    if selected_annexb in full_annexb:
        return True
    first_vcl = _annexb_first_vcl_unit(
        selected_annexb,
        video_input_format=video_input_format,
    )
    return first_vcl is not None and first_vcl in full_annexb


def _idmx_packets_from_selected_annexb(
    packets: list[bytes],
    *,
    full_annexb: bytes,
    selected_annexb: bytes,
    media_key: str | bytes,
    nalu_header_size: int | None,
    video_input_format: str,
) -> list[bytes]:
    """Keep packets from the first selected VCL NAL for aligned audio muxing."""

    if video_input_format == "h264":
        _annexb, spans = _idmx_h264_annexb_packet_spans(
            packets,
            media_key,
            nalu_header_size=nalu_header_size,
            stream_is_clear=False,
        )
    else:
        _annexb, spans = _idmx_hevc_annexb_packet_spans(packets, media_key)
    return _idmx_packets_for_selected_vcl_spans(
        packets,
        spans=spans,
        full_annexb=full_annexb,
        selected_annexb=selected_annexb,
        video_input_format=video_input_format,
    )


def _h264_annexb_packet_index_for_offset(
    packets: list[bytes],
    *,
    offset: int,
) -> int:
    """Return the packet index that first contributes the clear Annex-B offset."""

    end_offsets = _h264_annexb_packet_end_offsets(packets)
    index = bisect.bisect_right(end_offsets, offset)
    return min(index, max(len(packets) - 1, 0))


def _hevc_annexb_packet_index_for_offset(
    packets: list[bytes],
    *,
    offset: int,
) -> int:
    """Return the packet index that first contributes the clear HEVC Annex-B offset."""

    end_offsets = _hevc_annexb_packet_end_offsets(packets)
    index = bisect.bisect_right(end_offsets, offset)
    return min(index, max(len(packets) - 1, 0))


def _idmx_annexb_packet_index_for_offset(
    packets: list[bytes],
    *,
    codec: str,
    offset: int,
) -> int:
    if codec == "h264":
        return _h264_annexb_packet_index_for_offset(packets, offset=offset)
    if codec == "hevc":
        return _hevc_annexb_packet_index_for_offset(packets, offset=offset)
    return max(len(packets) - 1, 0)


def _try_first_clean_h264_annexb_idr_window_offset_from_annexb(
    annexb: bytes,
    *,
    ffmpeg_path: str,
    max_windows: int,
) -> _H264CleanIdrProbeResult:
    """Return the first clean IDR window offset for Annex-B H.264 bytes."""

    idr_summary = summarize_h264_annexb_idr_windows(annexb, max_windows=max_windows)
    samples = idr_summary.get("samples")
    if not isinstance(samples, list):
        return _H264CleanIdrProbeResult(
            start_offset=None,
            idr_count=int(idr_summary.get("idr_count", 0)),
            nal_count=int(idr_summary.get("nal_count", 0)),
        )
    first_decode_error: str | None = None
    complete_window_count = 0
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        end_nal_index = sample.get("end_nal_index")
        if (
            not isinstance(end_nal_index, int)
            or end_nal_index >= int(idr_summary["nal_count"])
        ):
            continue
        start_offset = sample.get("start_code_offset")
        end_offset = sample.get("end_offset")
        if (
            not isinstance(start_offset, int)
            or not isinstance(end_offset, int)
            or end_offset <= start_offset
        ):
            continue
        complete_window_count += 1
        decode_errors = _ffmpeg_h264_decode_errors(
            annexb[start_offset:end_offset],
            ffmpeg_path=ffmpeg_path,
            accept_success_with_stderr=False,
        )
        if not decode_errors:
            return _H264CleanIdrProbeResult(
                start_offset=start_offset,
                idr_start_offset=int(sample["idr_start_code_offset"]),
                first_decode_error=first_decode_error,
                idr_count=int(idr_summary.get("idr_count", 0)),
                sampled_window_count=len(samples),
                complete_window_count=complete_window_count,
                nal_count=int(idr_summary.get("nal_count", 0)),
            )
        if first_decode_error is None:
            first_decode_error = decode_errors[0]
    return _H264CleanIdrProbeResult(
        start_offset=None,
        first_decode_error=first_decode_error,
        idr_count=int(idr_summary.get("idr_count", 0)),
        sampled_window_count=len(samples),
        complete_window_count=complete_window_count,
        nal_count=int(idr_summary.get("nal_count", 0)),
    )


def _ffmpeg_h264_decode_errors(
    data: bytes,
    *,
    ffmpeg_path: str,
    accept_success_with_stderr: bool = True,
) -> list[str]:
    lines = _ffmpeg_video_decode_errors(
        data,
        ffmpeg_path=ffmpeg_path,
        input_format="h264",
        accept_success_with_stderr=accept_success_with_stderr,
    )
    if accept_success_with_stderr:
        return lines
    saw_missing_picture_probe = any(
        "missing picture in access unit" in line or "no frame!" in line
        for line in lines
    )
    return [
        line
        for line in lines
        if "missing picture in access unit" not in line
        and "no frame!" not in line
        and not (
            saw_missing_picture_probe
            and "Decoding error: Invalid data found when processing input" in line
        )
    ]


def _ffmpeg_hevc_decode_errors(
    data: bytes,
    *,
    ffmpeg_path: str,
    accept_success_with_stderr: bool = True,
) -> list[str]:
    return _ffmpeg_video_decode_errors(
        data,
        ffmpeg_path=ffmpeg_path,
        input_format="hevc",
        accept_success_with_stderr=accept_success_with_stderr,
    )


def _ffmpeg_video_decode_errors(
    data: bytes,
    *,
    ffmpeg_path: str,
    input_format: str,
    accept_success_with_stderr: bool = False,
) -> list[str]:
    timeout_seconds = _ffmpeg_video_decode_probe_timeout_seconds(data)
    try:
        completed = subprocess.run(
            [
                ffmpeg_path,
                "-v",
                "error",
                "-f",
                input_format,
                "-i",
                "pipe:0",
                "-f",
                "null",
                "-",
            ],
            input=data,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except OSError as err:
        raise PyEzvizError(f"Could not launch FFmpeg at {ffmpeg_path!r}: {err}") from err
    except subprocess.TimeoutExpired:
        return [
            "ffmpeg video decode check timed out after "
            f"{timeout_seconds}s"
        ]
    stderr_text = completed.stderr.decode("utf-8", errors="replace")
    lines = [line for line in stderr_text.splitlines() if line]
    if completed.returncode == 0 and accept_success_with_stderr:
        return []
    if completed.returncode != 0 and not lines:
        lines.append(f"ffmpeg exited with status {completed.returncode}")
    return lines[:8]


def _ffmpeg_video_decode_probe_timeout_seconds(data: bytes) -> int:
    """Keep tiny decode probes quick while allowing full suffix checks to finish."""

    extra_seconds = len(data) // _FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND
    return min(
        _FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS,
        _FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS + extra_seconds,
    )


def _h264_annexb_idr_window_start_index(
    nal_types: list[int],
    idr_nal_index: int,
) -> int:
    start = idr_nal_index
    while start > 0 and nal_types[start - 1] in {6, 7, 8, 9}:
        start -= 1
    return start


def _hevc_annexb_irap_window_start_index(
    nal_types: list[int],
    irap_nal_index: int,
) -> int:
    start = irap_nal_index
    while start > 0 and nal_types[start - 1] in {32, 33, 34, 35, 39, 40}:
        start -= 1
    return start


def _is_complete_idmx_rtp_frame(frame: bytes) -> bool:
    """Return whether ``frame`` is one complete standards-shaped IDMX RTP packet."""

    if len(frame) < 12 or frame[0] >> 6 != 2 or frame[8:12] != IDMX_LOCAL_FRAME_SENTINEL:
        return False
    try:
        parse_rtp_packet(frame)
    except PyEzvizError:
        return False
    return True


def _idmx_local_frame_media_body(frame: bytes, header_size: int) -> bytes:
    """Return media bytes after RTP extensions/padding or a legacy IDMX header."""

    if _is_complete_idmx_rtp_frame(frame):
        return rtp_payload(frame)
    return _strip_idmx_command_h264_record_trailer(frame[header_size:])


def _idmx_local_frame_rtp_packet(frame: bytes, header_size: int) -> RtpPacket | None:
    """Normalize standards-shaped and legacy IDMX headers into one RTP model."""

    if _is_complete_idmx_rtp_frame(frame):
        return parse_rtp_packet(frame)
    transport = _idmx_local_frame_transport_fields(frame, header_size)
    payload_type = transport.get("rtp_payload_type")
    sequence = transport.get("sequence_number")
    timestamp = transport.get("rtp_timestamp")
    if not all(isinstance(value, int) for value in (payload_type, sequence, timestamp)):
        return None
    return RtpPacket(
        payload=_idmx_local_frame_media_body(frame, header_size),
        payload_type=cast(int, payload_type),
        sequence=cast(int, sequence),
        timestamp=cast(int, timestamp),
        ssrc=0,
        marker=bool(transport.get("rtp_marker")),
    )


def _summarize_idmx_h264_local_frame(  # noqa: PLR0911
    frame: bytes,
    frame_index: int,
    *,
    h264_payload_types: frozenset[int],
) -> dict[str, Any]:
    header_size = _idmx_local_frame_header_size(frame)
    sample: dict[str, Any] = {
        "index": frame_index,
        "frame_length": len(frame),
        "header_size": header_size,
    }
    if header_size is None:
        sample["kind"] = "unknown"
        sample["body_length"] = len(frame)
        sample["body_sha256"] = hashlib.sha256(frame).hexdigest()
        return sample

    transport = _idmx_local_frame_transport_fields(frame, header_size)
    sample.update(transport)
    body = _idmx_local_frame_media_body(frame, header_size)
    sample["body_length"] = len(body)
    sample["body_sha256"] = hashlib.sha256(body).hexdigest()
    is_h264_transport = _idmx_local_frame_is_h264_transport(
        frame,
        header_size,
        payload_types=h264_payload_types,
    )
    if is_h264_transport and _looks_like_idmx_h264_fu_a_frame(body):
        fu_header = body[1]
        sample["kind"] = "h264_fu_a"
        sample["nal_type"] = fu_header & 0x1F
        sample["fu_start"] = bool(fu_header & 0x80)
        sample["fu_end"] = bool(fu_header & 0x40)
        return sample
    if is_h264_transport and _looks_like_idmx_h264_clear_nal(body):
        sample["kind"] = "h264_nal"
        sample["nal_type"] = _h264_nal_type(body)
        return sample
    if _looks_like_idmx_hevc_parameter_frame(body):
        sample["kind"] = "hevc_parameter"
        return sample
    if _looks_like_idmx_hevc_media_frame(body):
        sample["kind"] = "hevc_media"
        return sample
    if is_h264_transport and _looks_like_idmx_hevc_direct_frame(body):
        sample["kind"] = "hevc_media"
        sample["hevc_nal_type"] = _hevc_nal_type(body)
        return sample
    sample["kind"] = "unknown"
    return sample


def _idmx_local_frame_transport_fields(
    frame: bytes,
    header_size: int,
) -> dict[str, Any]:
    """Return sanitized RTP-like fields from an IDMX local frame header."""

    if _is_complete_idmx_rtp_frame(frame):
        packet = parse_rtp_packet(frame)
        return {
            "rtp_marker": packet.marker,
            "rtp_payload_type": packet.payload_type,
            "sequence_number": packet.sequence,
            "rtp_timestamp": packet.timestamp,
        }

    sentinel_offset = header_size - len(IDMX_LOCAL_FRAME_SENTINEL)
    rtp_header_offset = sentinel_offset - 8
    if rtp_header_offset < 0 or len(frame) < sentinel_offset:
        return {}
    header = frame[rtp_header_offset:sentinel_offset]
    if len(header) < 8:
        return {}
    return {
        "rtp_marker": bool(header[1] & 0x80),
        "rtp_payload_type": header[1] & 0x7F,
        "sequence_number": int.from_bytes(header[2:4], "big"),
        "rtp_timestamp": int.from_bytes(header[4:8], "big"),
    }


def _idmx_local_frame_is_h264_transport(
    frame: bytes,
    header_size: int,
    *,
    payload_types: frozenset[int] = frozenset({IDMX_H264_RTP_PAYLOAD_TYPE}),
) -> bool:
    transport = _idmx_local_frame_transport_fields(frame, header_size)
    return transport.get("rtp_payload_type") in payload_types


def _idmx_local_frame_sequence_number(frame: bytes, header_size: int) -> int | None:
    value = _idmx_local_frame_transport_fields(frame, header_size).get(
        "sequence_number"
    )
    return value if isinstance(value, int) else None


def _idmx_local_frame_rtp_timestamp(frame: bytes, header_size: int) -> int | None:
    value = _idmx_local_frame_transport_fields(frame, header_size).get(
        "rtp_timestamp"
    )
    return value if isinstance(value, int) else None


def _idmx_local_frame_rtp_marker(frame: bytes, header_size: int) -> bool:
    return bool(_idmx_local_frame_transport_fields(frame, header_size).get("rtp_marker"))


def _idmx_rtp_extension(frame: bytes) -> tuple[int, bytes] | None:
    """Return the profile and bytes from a complete RTP header extension."""

    if not _is_complete_idmx_rtp_frame(frame):
        return None
    packet = parse_rtp_packet(frame)
    if packet.extension_profile is None:
        return None
    return packet.extension_profile, packet.extension_data


def _idmx_audio_descriptor(packets: list[bytes]) -> tuple[int, int] | None:
    """Read sample rate and channels from an IDMX 0x43 audio descriptor."""

    profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile.audio_metadata


def _idmx_audio_metadata(
    packets: list[bytes],
    _media_key: str | bytes,
) -> tuple[int, int] | None:
    """Return authoritative AAC metadata from the native stream descriptor."""

    return _idmx_audio_descriptor(packets)


def _idmx_audio_payload_types(packets: list[bytes]) -> frozenset[int]:
    """Return the AAC payload route advertised by startup stream metadata."""

    profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile.codec_payload_types(
        "aac",
        fallback_payload_types=DEFAULT_AAC_PAYLOAD_TYPES,
    )


def _idmx_local_packets_have_aac(packets: list[bytes]) -> bool:
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None and rtp_packet_is_idmx_aac(packet):
            return True
    return False


def _idmx_local_video_frame_rate(packets: list[bytes]) -> str:
    """Estimate video frame rate from the standard 90 kHz RTP timestamp clock."""

    rtp_packets: list[RtpPacket] = []
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            rtp_packets.append(packet)
    routed_video_payload_types = _idmx_local_video_payload_types(packets)
    route_epoch_profile = RtpRouteProfile()
    timestamps: list[int] = []
    for packet in rtp_packets:
        route_epoch_profile.absorb(packet)
        active_route_descriptor = _rtp_packet_route_descriptor(
            route_epoch_profile,
            packet,
        )
        if (
            packet.payload_type in routed_video_payload_types
            and (
                active_route_descriptor is None
                or active_route_descriptor.media_kind == "video"
            )
        ) and (
            not timestamps or timestamps[-1] != packet.timestamp
        ):
            timestamps.append(packet.timestamp)
    deltas = sorted(
        delta
        for previous, current in pairwise(timestamps)
        if 0 < (delta := (current - previous) & 0xFFFFFFFF) <= IDMX_VIDEO_RTP_CLOCK_RATE
    )
    if not deltas:
        return str(IDMX_DEFAULT_VIDEO_FRAME_RATE)
    median_delta = deltas[len(deltas) // 2]
    rate = Fraction(IDMX_VIDEO_RTP_CLOCK_RATE, median_delta).limit_denominator(1001)
    return str(rate.numerator) if rate.denominator == 1 else f"{rate.numerator}/{rate.denominator}"


def _rtp_fragment_continues(
    active_fu: _RtpFragmentedNal | None,
    *,
    sequence_number: int | None,
    rtp_timestamp: int | None,
) -> bool:
    if active_fu is None:
        return False
    if (
        active_fu.rtp_timestamp is not None
        and rtp_timestamp is not None
        and active_fu.rtp_timestamp != rtp_timestamp
    ):
        return False
    return not (
        active_fu.last_sequence is not None
        and sequence_number is not None
        and ((active_fu.last_sequence + 1) & 0xFFFF) != sequence_number
    )


def _merge_idmx_h264_frame_summary(
    summary: dict[str, Any],
    frame_summary: dict[str, Any],
) -> None:
    h264 = summary["h264"]
    hevc = summary["hevc"]
    assert isinstance(h264, dict)
    assert isinstance(hevc, dict)

    kind = frame_summary.get("kind")
    if kind == "h264_fu_a":
        h264["fu_a"] = int(h264["fu_a"]) + 1
        if frame_summary.get("fu_start"):
            h264["fu_a_start"] = int(h264["fu_a_start"]) + 1
        if frame_summary.get("fu_end"):
            h264["fu_a_end"] = int(h264["fu_a_end"]) + 1
        _increment_h264_nal_type_count(h264, frame_summary.get("nal_type"))
        return
    if kind == "h264_nal":
        h264["clear_nal"] = int(h264["clear_nal"]) + 1
        _increment_h264_nal_type_count(h264, frame_summary.get("nal_type"))
        return
    if kind == "hevc_parameter":
        hevc["parameter"] = int(hevc["parameter"]) + 1
        return
    if kind == "hevc_media":
        hevc["media"] = int(hevc["media"]) + 1
        return
    h264["unknown"] = int(h264["unknown"]) + 1


def _increment_h264_nal_type_count(h264: dict[str, Any], nal_type: Any) -> None:
    names = {
        1: "non_idr",
        5: "idr",
        6: "sei",
        7: "sps",
        8: "pps",
        9: "aud",
    }
    name = names.get(nal_type)
    if name is None:
        h264["unknown"] = int(h264["unknown"]) + 1
        return
    h264[name] = int(h264[name]) + 1


def _record_idmx_h264_nal_unit_summary(  # noqa: PLR0911, PLR0912
    summary: dict[str, Any],
    frame: bytes,
    frame_summary: dict[str, Any],
    *,
    active_fu: dict[str, Any] | None,
    h264_payload_types: frozenset[int],
) -> dict[str, Any] | None:
    header_size = frame_summary.get("header_size")
    if not isinstance(header_size, int):
        return active_fu
    if not _idmx_local_frame_is_h264_transport(
        frame,
        header_size,
        payload_types=h264_payload_types,
    ):
        return active_fu
    body = _idmx_local_frame_media_body(frame, header_size)
    if _looks_like_idmx_h264_clear_nal(body):
        _append_idmx_h264_nal_unit_sample(
            summary,
            {
                "nal_type": _h264_nal_type(body),
                "start_frame_index": frame_summary["index"],
                "start_sequence": frame_summary.get("sequence_number"),
                "end_sequence": frame_summary.get("sequence_number"),
                "rtp_timestamp": frame_summary.get("rtp_timestamp"),
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(body),
                "sha256": hashlib.sha256(body),
            },
            complete=True,
            end_frame_index=frame_summary["index"],
        )
        return None
    if not _looks_like_idmx_h264_fu_a_frame(body):
        return active_fu

    fu_header = body[1]
    is_start = bool(fu_header & 0x80)
    is_end = bool(fu_header & 0x40)
    nal_type = fu_header & 0x1F
    sequence_number = frame_summary.get("sequence_number")
    rtp_timestamp = frame_summary.get("rtp_timestamp")
    if not is_start and active_fu is None:
        _increment_idmx_h264_nal_unit_counter(summary, "discarded_fu_a_fragments")
        return None
    if is_start and active_fu is not None:
        _increment_idmx_h264_nal_unit_counter(summary, "restart_count")
        _increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _append_idmx_h264_nal_unit_sample(
            summary,
            active_fu,
            complete=False,
            end_frame_index=None,
        )
        active_fu = None
    if active_fu is not None and not _rtp_fragment_continues(
        _RtpFragmentedNal(
            data=bytearray(),
            last_sequence=(
                active_fu.get("last_sequence")
                if isinstance(active_fu.get("last_sequence"), int)
                else None
            ),
            rtp_timestamp=(
                active_fu.get("rtp_timestamp")
                if isinstance(active_fu.get("rtp_timestamp"), int)
                else None
            ),
        ),
        sequence_number=sequence_number if isinstance(sequence_number, int) else None,
        rtp_timestamp=rtp_timestamp if isinstance(rtp_timestamp, int) else None,
    ):
        if (
            isinstance(active_fu.get("last_sequence"), int)
            and isinstance(sequence_number, int)
            and ((int(active_fu["last_sequence"]) + 1) & 0xFFFF) != sequence_number
        ):
            active_fu["sequence_gap_count"] = int(active_fu["sequence_gap_count"]) + 1
            _increment_idmx_h264_nal_unit_counter(summary, "sequence_gap_count")
        if (
            isinstance(active_fu.get("rtp_timestamp"), int)
            and isinstance(rtp_timestamp, int)
            and int(active_fu["rtp_timestamp"]) != rtp_timestamp
        ):
            _increment_idmx_h264_nal_unit_counter(summary, "timestamp_change_count")
        _increment_idmx_h264_nal_unit_counter(summary, "incomplete_fu_a")
        _append_idmx_h264_nal_unit_sample(
            summary,
            active_fu,
            complete=False,
            end_frame_index=None,
        )
        _increment_idmx_h264_nal_unit_counter(summary, "discarded_fu_a_fragments")
        return None
    if is_start:
        reconstructed_header = bytes([(body[0] & 0xE0) | nal_type])
        active_fu = {
            "nal_type": nal_type,
            "start_frame_index": frame_summary["index"],
            "start_sequence": sequence_number,
            "end_sequence": sequence_number,
            "rtp_timestamp": rtp_timestamp,
            "last_sequence": None,
            "sequence_gap_count": 0,
            "fragment_count": 0,
            "payload_bytes": len(reconstructed_header),
            "sha256": hashlib.sha256(reconstructed_header),
        }
    if active_fu is None:
        return None
    if isinstance(sequence_number, int):
        active_fu["last_sequence"] = sequence_number
        active_fu["end_sequence"] = sequence_number
    hasher = active_fu["sha256"]
    assert hasattr(hasher, "update")
    hasher.update(body[2:])
    active_fu["fragment_count"] = int(active_fu["fragment_count"]) + 1
    active_fu["payload_bytes"] = int(active_fu["payload_bytes"]) + max(
        len(body) - 2,
        0,
    )
    if is_end:
        _append_idmx_h264_nal_unit_sample(
            summary,
            active_fu,
            complete=True,
            end_frame_index=frame_summary["index"],
        )
        return None
    return active_fu


def _increment_idmx_h264_nal_unit_counter(
    summary: dict[str, Any],
    name: str,
) -> None:
    nal_units = summary["h264_nal_units"]
    assert isinstance(nal_units, dict)
    nal_units[name] = int(nal_units.get(name, 0)) + 1


def _append_idmx_h264_nal_unit_sample(
    summary: dict[str, Any],
    unit: dict[str, Any],
    *,
    complete: bool,
    end_frame_index: Any,
) -> None:
    nal_units = summary["h264_nal_units"]
    assert isinstance(nal_units, dict)
    samples = nal_units["samples"]
    assert isinstance(samples, list)
    if len(samples) >= int(nal_units["sample_limit"]):
        nal_units["truncated"] = True
        return
    hasher = unit["sha256"]
    assert hasattr(hasher, "hexdigest")
    samples.append(
        {
            "nal_type": unit["nal_type"],
            "start_frame_index": unit["start_frame_index"],
            "end_frame_index": end_frame_index,
            "start_sequence": unit.get("start_sequence"),
            "end_sequence": unit.get("end_sequence"),
            "rtp_timestamp": unit.get("rtp_timestamp"),
            "sequence_gap_count": unit.get("sequence_gap_count"),
            "fragment_count": unit["fragment_count"],
            "payload_bytes": unit["payload_bytes"],
            "complete": complete,
            "sha256": hasher.hexdigest(),
        }
    )


def _looks_like_idmx_local_payload(payload: bytes) -> bool:
    return _idmx_local_frame_header_size(payload) is not None or any(
        _iter_idmx_local_frames(payload)
    )


def _looks_like_length_prefixed_idmx_local_payload(payload: bytes) -> bool:
    if len(payload) < 4:
        return False
    prefixed_length = int.from_bytes(payload[:4], "little")
    frame = payload[4:]
    header_size = _idmx_local_frame_header_size(frame)
    return (
        header_size is not None
        and prefixed_length >= header_size
        and prefixed_length <= len(frame)
        and _idmx_local_frame_header_score(frame, header_size) is not None
    )


def _idmx_local_frame_header_size(payload: bytes) -> int | None:
    for sentinel_offset in IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
        header_size = sentinel_offset + len(IDMX_LOCAL_FRAME_SENTINEL)
        if (
            len(payload) >= header_size
            and payload[sentinel_offset:header_size] == IDMX_LOCAL_FRAME_SENTINEL
        ):
            return header_size
    return None


def _iter_idmx_local_frames(payload: bytes) -> Iterator[bytes]:  # noqa: PLR0912
    search_start = 0
    while True:
        sentinel_offset = payload.find(IDMX_LOCAL_FRAME_SENTINEL, search_start)
        if sentinel_offset < 0:
            break

        valid_frame_starts: list[tuple[int, int]] = []
        prefixed_frames: list[tuple[int, int, int]] = []
        for local_sentinel_offset in IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
            frame_start = sentinel_offset - local_sentinel_offset
            if frame_start < 0:
                continue
            header_size = _idmx_local_frame_header_size(payload[frame_start:])
            header_score = _idmx_local_frame_header_score(
                payload[frame_start:],
                header_size,
            )
            if header_size is None or header_score is None:
                continue
            prefix_start = frame_start - 4
            if prefix_start >= 0:
                prefixed_length = int.from_bytes(
                    payload[prefix_start:frame_start],
                    "little",
                )
                frame_end = frame_start + prefixed_length
                if prefixed_length >= header_size and frame_end <= len(payload):
                    prefixed_frames.append((frame_start, frame_end, header_score))
                else:
                    valid_frame_starts.append((frame_start, header_score))
            else:
                valid_frame_starts.append((frame_start, header_score))

        if prefixed_frames:
            frame_start, frame_end, _score = min(
                prefixed_frames,
                key=lambda item: (item[1], item[2]),
            )
            yield from _iter_idmx_local_frame_or_nested(payload[frame_start:frame_end])
            search_start = frame_end
            continue

        if valid_frame_starts:
            frame_start, _score = min(valid_frame_starts, key=lambda item: item[1])
            next_sentinel_offset = payload.find(
                IDMX_LOCAL_FRAME_SENTINEL,
                sentinel_offset + 1,
            )
            if next_sentinel_offset < 0:
                yield payload[frame_start:]
                break

            frame_end = next_sentinel_offset
            next_frame_starts: list[tuple[int, int]] = []
            for local_sentinel_offset in IDMX_LOCAL_FRAME_SENTINEL_OFFSETS:
                next_frame_start = next_sentinel_offset - local_sentinel_offset
                next_header_size = _idmx_local_frame_header_size(
                    payload[next_frame_start:]
                )
                next_header_score = _idmx_local_frame_header_score(
                    payload[next_frame_start:],
                    next_header_size,
                )
                if (
                    next_frame_start > frame_start
                    and next_header_size is not None
                    and next_header_score is not None
                ):
                    next_frame_starts.append((next_frame_start, next_header_score))
            if next_frame_starts:
                next_frame_start, _score = min(
                    next_frame_starts,
                    key=lambda item: (item[1], item[0]),
                )
                frame_end = _idmx_frame_end_before_next_prefix(payload, next_frame_start)

            yield from _iter_idmx_local_frame_or_nested(payload[frame_start:frame_end])
            search_start = frame_end
            continue

        search_start = sentinel_offset + 1


def _idmx_local_frame_header_score(
    payload: bytes,
    header_size: int | None,
) -> int | None:
    if header_size is None or len(payload) < header_size:
        return None
    lead = payload[0]
    if header_size == 13 and lead in {0x0D, 0xFA}:
        return 0
    if header_size == 12 and lead in {0x80, 0x90, 0xA0}:
        return 0
    if header_size == 13 and payload[1] in {0x80, 0x90, 0xA0}:
        return 1
    return None


def _iter_idmx_local_frame_or_nested(
    frame: bytes,
    *,
    video_payload_types: frozenset[int] = frozenset(),
) -> Iterator[bytes]:
    """Yield one IDMX frame, or nested frames from command-port aggregate records."""
    header_size = _idmx_local_frame_header_size(frame)
    if header_size is None:
        yield frame
        return
    body = frame[header_size:]
    if not body.startswith(b"\x00\x10") or not body.count(IDMX_LOCAL_FRAME_SENTINEL):
        yield frame
        return
    nested_frames = tuple(_iter_idmx_local_frames(body))
    contains_media = _idmx_local_frames_contain_routed_media(
        nested_frames,
        video_payload_types=video_payload_types,
    )
    contains_descriptors = any(
        idmx_rtp_stream_descriptors((packet,))
        for nested in nested_frames
        if (nested_header_size := _idmx_local_frame_header_size(nested)) is not None
        if (packet := _idmx_local_frame_rtp_packet(nested, nested_header_size))
        is not None
    )
    if not contains_media and not contains_descriptors:
        yield frame
        return
    yield from nested_frames


def _iter_idmx_local_packet_frame(
    packet: bytes,
    *,
    video_payload_types: frozenset[int] = frozenset(),
) -> Iterator[bytes]:
    if len(packet) >= 4:
        prefixed_length = int.from_bytes(packet[:4], "little")
        prefixed_frame = packet[4 : 4 + prefixed_length]
        prefixed_header_size = _idmx_local_frame_header_size(prefixed_frame)
        if (
            prefixed_length == len(packet) - 4
            and prefixed_header_size is not None
            and _idmx_local_frame_header_score(
                prefixed_frame,
                prefixed_header_size,
            )
            is not None
        ):
            yield from _iter_idmx_local_frame_or_nested(
                prefixed_frame,
                video_payload_types=video_payload_types,
            )
            return
    if (
        _is_complete_idmx_rtp_frame(packet)
        and not _idmx_local_packet_contains_aggregate_media_frame(
            packet,
            video_payload_types=video_payload_types,
        )
        and not _idmx_local_packet_contains_aggregate_descriptors(packet)
    ):
        yield packet
        return
    header_size = _idmx_local_frame_header_size(packet)
    if (
        header_size is not None
        and _idmx_local_frame_header_score(packet, header_size) is not None
    ):
        if _idmx_local_packet_contains_aggregate_media_frame(
            packet,
            video_payload_types=video_payload_types,
        ):
            yield from _iter_idmx_local_frames(packet)
            return
        yield from _iter_idmx_local_frame_or_nested(
            packet,
            video_payload_types=video_payload_types,
        )
        return
    for frame in _iter_idmx_local_frames(packet):
        yield from _iter_idmx_local_frame_or_nested(
            frame,
            video_payload_types=video_payload_types,
        )


def _idmx_local_packet_contains_aggregate_media_frame(
    packet: bytes,
    *,
    video_payload_types: frozenset[int] = frozenset(),
) -> bool:
    frames = tuple(_iter_idmx_local_frames(packet))
    if len(frames) <= 1:
        return False
    previous_sequence = _idmx_local_packet_frame_sequence_number(frames[0])
    for frame in frames[1:]:
        sequence = _idmx_local_packet_frame_sequence_number(frame)
        if (
            previous_sequence is None
            or sequence is None
            or sequence != ((previous_sequence + 1) & 0xFFFF)
        ):
            return False
        previous_sequence = sequence
    return _idmx_local_frames_contain_routed_media(
        frames,
        video_payload_types=video_payload_types,
    )


def _idmx_local_packet_contains_aggregate_descriptors(packet: bytes) -> bool:
    frames = tuple(_iter_idmx_local_frames(packet))
    if len(frames) <= 1:
        return False
    return any(
        idmx_rtp_stream_descriptors((parsed,))
        for frame in frames[1:]
        if (header_size := _idmx_local_frame_header_size(frame)) is not None
        if (parsed := _idmx_local_frame_rtp_packet(frame, header_size)) is not None
    )


def _idmx_local_frames_contain_routed_media(
    frames: tuple[bytes, ...],
    *,
    video_payload_types: frozenset[int] = frozenset(),
) -> bool:
    """Return whether nested frames contain video under their final route profile."""

    parsed: list[tuple[RtpPacket, bytes]] = []
    profile = RtpRouteProfile()
    for frame in frames:
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is None:
            continue
        parsed.append((packet, _idmx_local_frame_media_body(frame, header_size)))
        profile.absorb(packet)
    return any(
        (profile.media_kind(packet) == "video" or packet.payload_type in video_payload_types)
        and (
            _looks_like_idmx_hevc_direct_frame(body)
            or _looks_like_idmx_h264_fu_a_frame(body)
            or _looks_like_idmx_h264_clear_nal(body)
        )
        for packet, body in parsed
    ) or any(_idmx_local_frame_contains_media(frame) for frame in frames)


def _idmx_local_packet_frame_sequence_number(frame: bytes) -> int | None:
    header_size = _idmx_local_frame_header_size(frame)
    if header_size is None:
        return None
    return _idmx_local_frame_sequence_number(frame, header_size)


def _iter_idmx_local_packet_frames(packets: list[bytes]) -> Iterator[bytes]:
    profile = RtpRouteProfile()
    for packet in packets:
        for frame in _iter_idmx_local_packet_frame(packet):
            header_size = _idmx_local_frame_header_size(frame)
            if header_size is not None:
                parsed = _idmx_local_frame_rtp_packet(frame, header_size)
                if parsed is not None:
                    profile.absorb(parsed)
    video_payload_types = frozenset(
        descriptor.payload_type
        for descriptor in profile.descriptors
        if descriptor.media_kind == "video"
    )
    for packet in packets:
        yield from _iter_idmx_local_packet_frame(
            packet,
            video_payload_types=video_payload_types,
        )


def _idmx_local_frame_contains_media(frame: bytes) -> bool:
    header_size = _idmx_local_frame_header_size(frame)
    if header_size is None:
        return False
    body = _idmx_local_frame_media_body(frame, header_size)
    h264_transport = _idmx_local_frame_is_h264_transport(frame, header_size)
    return (
        _looks_like_idmx_hevc_parameter_frame(body)
        or _looks_like_idmx_hevc_media_frame(body)
        or (h264_transport and _looks_like_idmx_hevc_direct_frame(body))
        or (h264_transport and _looks_like_idmx_h264_fu_a_frame(body))
        or (h264_transport and _looks_like_idmx_h264_clear_nal(body))
    )


def _idmx_frame_end_before_next_prefix(payload: bytes, next_frame_start: int) -> int:
    prefix_start = next_frame_start - 4
    if prefix_start < 0:
        return next_frame_start
    prefixed_length = int.from_bytes(payload[prefix_start:next_frame_start], "little")
    remaining_after_prefix = len(payload) - next_frame_start
    if 0 < prefixed_length <= remaining_after_prefix:
        return prefix_start
    return next_frame_start


def _local_stream_packets_are_idmx(packets: list[bytes]) -> bool:
    return bool(packets) and _looks_like_idmx_local_payload(packets[0])


def _unsupported_idmx_local_payload_error() -> PyEzvizError:
    return PyEzvizError(
        "Unsupported encrypted EZVIZ local IDMX stream payload: decrypt-video is required"
    )


def _decrypt_idmx_local_packets_to_annexb(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None = None,
    decrypt_hevc_parameter_sets: bool = False,
) -> bytes:
    annexb, _authoritative_codec = _decrypt_idmx_local_packets_to_annexb_with_codec(
        packets,
        media_key,
        nalu_header_size=nalu_header_size,
        decrypt_hevc_parameter_sets=decrypt_hevc_parameter_sets,
    )
    return annexb


def _decrypt_idmx_local_packets_to_annexb_with_codec(  # noqa: PLR0912, PLR0915
    packets: list[bytes],
    media_key: str | bytes,
    *,
    nalu_header_size: int | None = None,
    decrypt_hevc_parameter_sets: bool = False,
) -> tuple[bytes, RtpVideoCodec | None]:
    """Decrypt local video and retain an authoritative descriptor codec."""

    routed_h264_payload_types, routed_hevc_payload_types = (
        _idmx_local_supported_video_payload_types(packets)
    )
    if (
        routed_h264_payload_types
        and routed_hevc_payload_types
        and routed_h264_payload_types != routed_hevc_payload_types
    ):
        raise PyEzvizError(
            "Conflicting H.264 and HEVC routes in encrypted EZVIZ local stream"
        )
    final_route_is_authoritative_hevc = bool(
        routed_hevc_payload_types and not routed_h264_payload_types
    )
    authoritative_codec: RtpVideoCodec | None = None
    if final_route_is_authoritative_hevc:
        authoritative_codec = "hevc"
    elif routed_h264_payload_types and not routed_hevc_payload_types:
        authoritative_codec = "h264"
    aes_key = _local_media_aes_key(media_key)
    h264_nalu_header_size = (
        H264_NAL_HEADER_SIZE if nalu_header_size is None else nalu_header_size
    )
    output = bytearray()
    active_fu: _RtpFragmentedNal | None = None
    active_h264_fu: _RtpFragmentedNal | None = None
    hevc_evidence_seen = False
    route_epoch_profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            raise PyEzvizError("Mixed EZVIZ local stream payload formats are unsupported")
        body = _idmx_local_frame_media_body(frame, header_size)
        rtp_packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if rtp_packet is not None:
            route_epoch_profile.absorb(rtp_packet)
        active_route_descriptor = next(
            (
                descriptor
                for descriptor in route_epoch_profile.descriptors
                if rtp_packet is not None
                and descriptor.payload_type == rtp_packet.payload_type
            ),
            None,
        )
        h264_transport = bool(
            rtp_packet is not None
            and rtp_packet.payload_type in routed_h264_payload_types
        )
        hevc_transport = bool(
            rtp_packet is not None
            and rtp_packet.payload_type in routed_hevc_payload_types
        )
        hevc_codec_compatible = bool(
            hevc_transport
            and (
                active_route_descriptor is None
                or active_route_descriptor.codec == "hevc"
            )
        )
        h264_codec_compatible = bool(
            h264_transport
            and not final_route_is_authoritative_hevc
            and (
                active_route_descriptor is None
                or active_route_descriptor.codec == "h264"
            )
        )
        if _looks_like_idmx_hevc_parameter_frame(body):
            # Live PlayCtrl takes parameter sets from the media-wrapper frames below;
            # the short sidecar-looking 00 01/00 02 records are not fed to FFmpeg.
            continue
        if hevc_codec_compatible and _looks_like_idmx_hevc_media_frame(body):
            hevc_evidence_seen = True
            active_fu = _append_idmx_hevc_media_payload(
                output,
                body[IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET:],
                aes_key,
                active_fu=active_fu,
                sequence_number=_idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_idmx_local_frame_rtp_timestamp(frame, header_size),
                rtp_marker=_idmx_local_frame_rtp_marker(frame, header_size),
            )
            continue
        if (
            h264_codec_compatible
            and not hevc_evidence_seen
            and _looks_like_idmx_h264_fu_a_frame(body)
        ):
            active_h264_fu = _append_idmx_h264_fu_a_payload(
                output,
                body,
                active_fu=active_h264_fu,
                sequence_number=_idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_idmx_local_frame_rtp_timestamp(frame, header_size),
                aes_key=aes_key,
                nalu_header_size=h264_nalu_header_size,
            )
            continue
        if (
            h264_codec_compatible
            and not hevc_evidence_seen
            and _looks_like_idmx_h264_clear_nal(body)
        ):
            active_h264_fu = None
            _append_decrypted_h264_nal(
                output,
                body,
                aes_key,
                nalu_header_size=h264_nalu_header_size,
            )
            continue
        hevc_direct_evidence = _looks_like_idmx_hevc_evidence_frame(body)
        conflicting_h264_route = bool(
            rtp_packet is not None
            and rtp_packet.payload_type
            in route_epoch_profile.codec_payload_types("h264")
        )
        if hevc_codec_compatible and (
            final_route_is_authoritative_hevc
            or hevc_evidence_seen
            or hevc_direct_evidence
        ) and _idmx_hevc_direct_frame_matches_route(
            body,
            authoritative_hevc=final_route_is_authoritative_hevc,
            conflicting_h264_route=conflicting_h264_route,
        ):
            hevc_evidence_seen = True
            active_fu = _append_idmx_hevc_media_payload(
                output,
                body,
                aes_key,
                active_fu=active_fu,
                sequence_number=_idmx_local_frame_sequence_number(frame, header_size),
                rtp_timestamp=_idmx_local_frame_rtp_timestamp(frame, header_size),
                rtp_marker=_idmx_local_frame_rtp_marker(frame, header_size),
                decrypt_parameter_sets=decrypt_hevc_parameter_sets,
            )
            continue
        if h264_codec_compatible and h264_nalu_header_size == 0 and body:
            active_h264_fu = None
            _append_decrypted_h264_nal(
                output,
                body,
                aes_key,
                nalu_header_size=h264_nalu_header_size,
            )
            continue
    if active_fu is not None:
        _append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
    if not output:
        raise PyEzvizError("EZVIZ local IDMX stream did not include media frames")
    return bytes(output), authoritative_codec


def _decrypt_idmx_local_packets_to_adts_aac(
    packets: list[bytes],
    media_key: str | bytes,
    *,
    audio_metadata: tuple[int, int] | None = None,
    audio_payload_types: frozenset[int] | None = None,
    require_contiguous: bool = True,
) -> _IdmxAacStream | None:
    """Return supported encrypted IDMX AAC as ADTS, or None for other audio."""

    final_profile = _idmx_local_route_profile(packets)
    descriptor_aac_payload_types = final_profile.codec_payload_types("aac")
    selected_audio_payload_types = (
        audio_payload_types
        if audio_payload_types is not None
        else final_profile.codec_payload_types(
            "aac",
            fallback_payload_types=DEFAULT_AAC_PAYLOAD_TYPES,
        )
    )
    rtp_packets: list[RtpPacket] = []
    route_epoch_profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None or not _is_complete_idmx_rtp_frame(frame):
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is None:
            continue
        route_epoch_profile.absorb(packet)
        if packet.payload_type not in selected_audio_payload_types:
            rtp_packets.append(packet)
            continue
        if (
            packet.payload_type in descriptor_aac_payload_types
            and not _rtp_packet_matches_codec_epoch(
                route_epoch_profile,
                packet,
                "aac",
            )
        ):
            continue
        if (
            packet.payload_type in descriptor_aac_payload_types
            and _rtp_packet_route_descriptor(route_epoch_profile, packet) is None
            and not rtp_packet_has_valid_idmx_aac_frame(packet)
        ):
            continue
        rtp_packets.append(packet)
    return decrypt_idmx_aac_packets(
        rtp_packets,
        media_key,
        audio_metadata=audio_metadata,
        audio_payload_types=selected_audio_payload_types,
        require_contiguous=require_contiguous,
    )


def _idmx_local_packets_to_h264_annexb(packets: list[bytes]) -> bytes:
    output = bytearray()
    depacketizer = RtpVideoDepacketizer("h264")
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="h264")
    route_epoch_profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            route_epoch_profile.absorb(packet)
        if packet is None or packet.payload_type not in routed_payload_types:
            continue
        if not _rtp_packet_matches_codec_epoch(
            route_epoch_profile,
            packet,
            "h264",
        ):
            continue
        if not (
            _looks_like_idmx_h264_fu_a_frame(packet.payload)
            or _looks_like_idmx_h264_clear_nal(packet.payload)
        ):
            continue
        for nal in depacketizer.push(packet):
            _append_h264_nal(output, nal)
    if not output:
        raise PyEzvizError("EZVIZ local IDMX stream did not include clear H.264 media frames")
    return _trim_trailing_h264_non_vcl_nals(bytes(output))


def _h264_annexb_packet_end_offsets(packets: list[bytes]) -> list[int]:
    output = bytearray()
    depacketizer = RtpVideoDepacketizer("h264")
    end_offsets: list[int] = []
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="h264")
    route_epoch_profile = RtpRouteProfile()
    for packet in packets:
        for frame in _iter_idmx_local_packet_frame(
            packet,
            video_payload_types=routed_payload_types,
        ):
            header_size = _idmx_local_frame_header_size(frame)
            if header_size is None:
                continue
            rtp_packet = _idmx_local_frame_rtp_packet(frame, header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if (
                rtp_packet is None
                or rtp_packet.payload_type not in routed_payload_types
            ):
                continue
            if not _rtp_packet_matches_codec_epoch(
                route_epoch_profile,
                rtp_packet,
                "h264",
            ):
                continue
            if not (
                _looks_like_idmx_h264_fu_a_frame(rtp_packet.payload)
                or _looks_like_idmx_h264_clear_nal(rtp_packet.payload)
            ):
                continue
            for nal in depacketizer.push(rtp_packet):
                _append_h264_nal(output, nal)
        end_offsets.append(len(output))
    return end_offsets


def _idmx_local_packets_to_hevc_annexb(
    packets: list[bytes],
    *,
    trim_trailing_non_vcl: bool = True,
) -> bytes:
    output = bytearray()
    depacketizer = RtpVideoDepacketizer(
        "hevc",
        allow_ezviz_headerless_hevc_fu=True,
    )
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="hevc")
    route_epoch_profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            route_epoch_profile.absorb(packet)
        if packet is None or packet.payload_type not in routed_payload_types:
            continue
        if (
            not _rtp_packet_matches_codec_epoch(
                route_epoch_profile,
                packet,
                "hevc",
            )
            or rtp_payload_video_codec(packet.payload) == "h264"
            or not _looks_like_idmx_hevc_direct_frame(packet.payload)
        ):
            continue
        for nal in depacketizer.push(packet):
            _append_hevc_nal(output, nal)
    if not output:
        raise PyEzvizError("EZVIZ local IDMX stream did not include clear HEVC media frames")
    annexb = bytes(output)
    if trim_trailing_non_vcl:
        return _trim_trailing_hevc_non_vcl_nals(annexb)
    return annexb


def _hevc_annexb_packet_end_offsets(packets: list[bytes]) -> list[int]:
    output = bytearray()
    depacketizer = RtpVideoDepacketizer(
        "hevc",
        allow_ezviz_headerless_hevc_fu=True,
    )
    end_offsets: list[int] = []
    routed_payload_types = _idmx_local_video_payload_types(packets, codec="hevc")
    route_epoch_profile = RtpRouteProfile()
    for packet in packets:
        for frame in _iter_idmx_local_packet_frame(
            packet,
            video_payload_types=routed_payload_types,
        ):
            header_size = _idmx_local_frame_header_size(frame)
            if header_size is None:
                continue
            rtp_packet = _idmx_local_frame_rtp_packet(frame, header_size)
            if rtp_packet is not None:
                route_epoch_profile.absorb(rtp_packet)
            if (
                rtp_packet is None
                or rtp_packet.payload_type not in routed_payload_types
                or not _rtp_packet_matches_codec_epoch(
                    route_epoch_profile,
                    rtp_packet,
                    "hevc",
                )
                or rtp_payload_video_codec(rtp_packet.payload) == "h264"
                or not _looks_like_idmx_hevc_direct_frame(rtp_packet.payload)
            ):
                continue
            for nal in depacketizer.push(rtp_packet):
                _append_hevc_nal(output, nal)
        end_offsets.append(len(output))
    return end_offsets


def _idmx_local_video_payload_types(
    packets: list[bytes],
    *,
    codec: RtpVideoCodec | None = None,
) -> frozenset[int]:
    """Return descriptor-owned local video routes with legacy PT 96 fallback."""

    profile = _idmx_local_route_profile(packets)
    if codec is not None:
        if any(descriptor.media_kind == "video" for descriptor in profile.descriptors):
            return profile.codec_payload_types(codec)
        return profile.codec_payload_types(
            codec,
            fallback_payload_types=frozenset({IDMX_H264_RTP_PAYLOAD_TYPE}),
        )
    descriptor_video_payload_types = frozenset(
        descriptor.payload_type
        for descriptor in profile.descriptors
        if descriptor.media_kind == "video"
    )
    if descriptor_video_payload_types:
        return descriptor_video_payload_types
    assigned = frozenset(descriptor.payload_type for descriptor in profile.descriptors)
    return frozenset({IDMX_H264_RTP_PAYLOAD_TYPE}) - assigned


def _idmx_local_route_profile(packets: list[bytes]) -> RtpRouteProfile:
    """Return the final authoritative route snapshot for local IDMX packets."""

    profile = RtpRouteProfile()
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        packet = _idmx_local_frame_rtp_packet(frame, header_size)
        if packet is not None:
            profile.absorb(packet)
    return profile


def _rtp_packet_route_descriptor(
    profile: RtpRouteProfile,
    packet: RtpPacket,
) -> RtpStreamDescriptor | None:
    """Return the descriptor active for one packet, or None before discovery."""

    return next(
        (
            descriptor
            for descriptor in profile.descriptors
            if descriptor.payload_type == packet.payload_type
        ),
        None,
    )


def _rtp_packet_matches_codec_epoch(
    profile: RtpRouteProfile,
    packet: RtpPacket,
    codec: str,
) -> bool:
    """Accept one codec only in its active or genuinely unclassified epoch."""

    descriptor = _rtp_packet_route_descriptor(profile, packet)
    return descriptor is None or descriptor.codec == codec


def _idmx_local_supported_video_payload_types(
    packets: list[bytes],
) -> tuple[frozenset[int], frozenset[int]]:
    """Return H.264/HEVC routes, rejecting unsupported-only video profiles."""

    profile = _idmx_local_route_profile(packets)
    video_descriptors = tuple(
        descriptor
        for descriptor in profile.descriptors
        if descriptor.media_kind == "video"
    )
    if video_descriptors:
        h264_payload_types = profile.codec_payload_types("h264")
        hevc_payload_types = profile.codec_payload_types("hevc")
    else:
        fallback_payload_types = frozenset({IDMX_H264_RTP_PAYLOAD_TYPE})
        h264_payload_types = profile.codec_payload_types(
            "h264",
            fallback_payload_types=fallback_payload_types,
        )
        hevc_payload_types = profile.codec_payload_types(
            "hevc",
            fallback_payload_types=fallback_payload_types,
        )
    if video_descriptors and not (h264_payload_types or hevc_payload_types):
        codecs = ", ".join(sorted({descriptor.codec for descriptor in video_descriptors}))
        raise PyEzvizError(
            f"Unsupported encrypted EZVIZ local video codec: {codecs}"
        )
    return h264_payload_types, hevc_payload_types


def _idmx_local_packets_to_annexb(packets: list[bytes]) -> bytes:
    annexb, _codec = _idmx_local_packets_to_annexb_with_codec(packets)
    return annexb


def _idmx_local_packets_to_annexb_with_codec(
    packets: list[bytes],
) -> tuple[bytes, str]:
    route_profile = _idmx_local_route_profile(packets)
    authoritative_hevc = any(
        descriptor.media_kind == "video" and descriptor.codec == "hevc"
        for descriptor in route_profile.descriptors
    )
    try:
        h264_annexb = _idmx_local_packets_to_h264_annexb(packets)
    except PyEzvizError as h264_error:
        try:
            return _idmx_local_packets_to_hevc_annexb(packets), "hevc"
        except PyEzvizError as hevc_error:
            raise h264_error from hevc_error
    if _annexb_has_h264_vcl(h264_annexb):
        return h264_annexb, "h264"
    try:
        hevc_annexb = _idmx_local_packets_to_hevc_annexb(packets)
    except PyEzvizError:
        return h264_annexb, "h264"
    if (
        authoritative_hevc
        or _idmx_local_packets_have_direct_hevc_media(packets)
        or _annexb_looks_like_hevc(hevc_annexb)
    ):
        return hevc_annexb, "hevc"
    return h264_annexb, "h264"


def _idmx_local_packets_to_h264_annexb_with_codec(
    packets: list[bytes],
) -> tuple[bytes, str]:
    try:
        h264_annexb = _idmx_local_packets_to_h264_annexb(packets)
    except PyEzvizError:
        return _idmx_local_packets_to_annexb_with_codec(packets)
    if _annexb_has_h264_vcl(h264_annexb):
        return h264_annexb, "h264"
    return _idmx_local_packets_to_annexb_with_codec(packets)


def _idmx_local_packets_have_direct_hevc_media(packets: list[bytes]) -> bool:
    for frame in _iter_idmx_local_packet_frames(packets):
        header_size = _idmx_local_frame_header_size(frame)
        if header_size is None:
            continue
        body = _idmx_local_frame_media_body(frame, header_size)
        if not _idmx_local_frame_is_h264_transport(frame, header_size):
            continue
        if _looks_like_idmx_hevc_evidence_frame(body):
            return True
    return False


def _local_media_aes_key(media_key: str | bytes) -> bytes:
    key_bytes = media_key.encode() if isinstance(media_key, str) else media_key
    return key_bytes.ljust(16, b"\0")[:16]


def _looks_like_idmx_hevc_parameter_frame(body: bytes) -> bool:
    return len(body) > 4 and body[:2] in (
        b"\x00\x01",
        b"\x00\x02",
    )


def _looks_like_idmx_hevc_media_frame(body: bytes) -> bool:
    return (
        len(body) > IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET
        and body.startswith(b"\x40\x00\x00\x02\x80\x06")
    )


def _looks_like_idmx_hevc_direct_frame(body: bytes) -> bool:
    if len(body) < HEVC_NAL_HEADER_SIZE or body[0] & 0x80 or body[1] & 0x07 == 0:
        return False
    nal_type = _hevc_nal_type(body)
    return 0 <= nal_type <= 40 or nal_type == 49


def _idmx_hevc_direct_frame_matches_route(
    body: bytes,
    *,
    authoritative_hevc: bool,
    conflicting_h264_route: bool = False,
) -> bool:
    if not _looks_like_idmx_hevc_direct_frame(body):
        return False
    return not authoritative_hevc or (
        not conflicting_h264_route and rtp_payload_video_codec(body) != "h264"
    )


def _looks_like_idmx_hevc_evidence_frame(body: bytes) -> bool:
    if not _looks_like_idmx_hevc_direct_frame(body):
        return False
    nal_type = _hevc_nal_type(body)
    if nal_type in {32, 33, 34}:
        return body[1] & 0xF8 == 0
    return nal_type == 49


def _looks_like_idmx_h264_fu_a_frame(body: bytes) -> bool:
    return len(body) > 2 and body[0] & 0x1F == H264_FU_A_NAL_TYPE


def _looks_like_idmx_h264_clear_nal(body: bytes) -> bool:
    if not body:
        return False
    return (body[0] & 0x1F) in {1, 5, 6, 7, 8, 9}


def _strip_idmx_command_h264_record_trailer(body: bytes) -> bytes:
    if len(body) <= 4:
        return body
    if not (
        _looks_like_idmx_h264_fu_a_frame(body)
        or _looks_like_idmx_h264_clear_nal(body)
        or _looks_like_idmx_hevc_direct_frame(body)
    ):
        return body
    if body[-3:-1] == IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX:
        return body[:-3]
    if body[-4:-2] == IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX:
        return body[:-4]
    return body


def _append_idmx_hevc_media_payload(
    output: bytearray,
    payload: bytes,
    aes_key: bytes,
    *,
    active_fu: _RtpFragmentedNal | None,
    sequence_number: int | None = None,
    rtp_timestamp: int | None = None,
    rtp_marker: bool = False,
    decrypt_parameter_sets: bool = True,
) -> _RtpFragmentedNal | None:
    if len(payload) < HEVC_NAL_HEADER_SIZE:
        return active_fu
    nal_type = (payload[0] >> 1) & 0x3F
    if nal_type != 49:
        if _is_plausible_hevc_nal(payload):
            if not decrypt_parameter_sets and nal_type in {32, 33, 34, 39, 40}:
                _append_hevc_nal(output, payload)
            else:
                _append_decrypted_hevc_nal(output, payload, aes_key)
        return active_fu
    if len(payload) < 3:
        return active_fu

    fu_header = payload[2]
    is_start = bool(fu_header & 0x80)
    original_type = fu_header & 0x3F
    if not is_start and not _rtp_fragment_continues(
        active_fu,
        sequence_number=sequence_number,
        rtp_timestamp=rtp_timestamp,
    ):
        return None
    reconstructed_header = bytes(
        [
            (payload[0] & 0x81) | (original_type << 1),
            payload[1],
        ]
    )
    if is_start:
        active_fu = _RtpFragmentedNal(
            data=bytearray(reconstructed_header),
            last_sequence=sequence_number,
            rtp_timestamp=rtp_timestamp,
        )
    assert active_fu is not None
    active_original_type = _hevc_nal_type(bytes(active_fu.data[:HEVC_NAL_HEADER_SIZE]))
    # EZVIZ RTP HEVC continuations sometimes use the reconstructed NAL header's
    # first byte, optionally ORed with the FU end bit, where a standard FU
    # header would normally repeat the original NAL type.
    active_header0 = active_fu.data[0] if active_fu.data else 0
    has_ezviz_pseudo_header = fu_header in {active_header0, active_header0 | 0x40}
    has_fu_header = (
        is_start or original_type == active_original_type or has_ezviz_pseudo_header
    )
    active_fu.data.extend(payload[3:] if has_fu_header else payload[2:])
    active_fu.last_sequence = sequence_number
    active_fu.rtp_timestamp = rtp_timestamp
    if (has_fu_header and bool(fu_header & 0x40)) or (
        not has_fu_header and rtp_marker
    ):
        _append_decrypted_hevc_nal(output, bytes(active_fu.data), aes_key)
        return None
    return active_fu


def _append_idmx_h264_fu_a_payload(
    output: bytearray,
    payload: bytes,
    *,
    active_fu: _RtpFragmentedNal | None,
    sequence_number: int | None = None,
    rtp_timestamp: int | None = None,
    aes_key: bytes | None = None,
    nalu_header_size: int = H264_NAL_HEADER_SIZE,
) -> _RtpFragmentedNal | None:
    fu_header = payload[1]
    is_start = bool(fu_header & 0x80)
    is_end = bool(fu_header & 0x40)
    if not is_start and not _rtp_fragment_continues(
        active_fu,
        sequence_number=sequence_number,
        rtp_timestamp=rtp_timestamp,
    ):
        return None
    reconstructed_header = bytes([(payload[0] & 0xE0) | (fu_header & 0x1F)])
    if is_start:
        active_fu = _RtpFragmentedNal(
            data=bytearray(reconstructed_header),
            last_sequence=sequence_number,
            rtp_timestamp=rtp_timestamp,
        )
    assert active_fu is not None
    active_fu.data.extend(payload[2:])
    active_fu.last_sequence = sequence_number
    active_fu.rtp_timestamp = rtp_timestamp
    if is_end:
        if aes_key is None:
            _append_h264_nal(output, bytes(active_fu.data))
        else:
            _append_decrypted_h264_nal(
                output,
                bytes(active_fu.data),
                aes_key,
                nalu_header_size=max(nalu_header_size, H264_NAL_HEADER_SIZE),
            )
        return None
    return active_fu


def _append_decrypted_hevc_nal(
    output: bytearray,
    nal: bytes,
    aes_key: bytes,
) -> None:
    if not _is_plausible_hevc_nal(nal):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(_decrypt_hevc_nal_prefix(nal, aes_key))


def _append_h264_nal(output: bytearray, nal: bytes) -> None:
    if not _is_plausible_h264_nal(nal):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(nal)


def _append_decrypted_h264_nal(
    output: bytearray,
    nal: bytes,
    aes_key: bytes,
    *,
    nalu_header_size: int = H264_NAL_HEADER_SIZE,
) -> None:
    if nalu_header_size != 0 and not _is_plausible_h264_nal(nal):
        return
    if _is_plausible_h264_nal(nal) and _h264_nal_type(nal) not in {1, 5}:
        output.extend(ANNEX_B_LONG_START_CODE)
        output.extend(nal)
        return
    decrypted = _decrypt_h264_nal_prefix(
        nal,
        aes_key,
        nalu_header_size=nalu_header_size,
    )
    if not _is_plausible_h264_nal(decrypted):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(decrypted)


def _append_hevc_nal(output: bytearray, nal: bytes) -> None:
    if not _is_plausible_hevc_nal(nal):
        return
    output.extend(ANNEX_B_LONG_START_CODE)
    output.extend(nal)


def _is_plausible_hevc_nal(nal: bytes) -> bool:
    nal_type = _hevc_nal_type(nal)
    return (
        len(nal) >= HEVC_NAL_HEADER_SIZE
        and not nal[0] & 0x80
        and nal[1] & 0x07 != 0
        and 0 <= nal_type <= 40
    )


def _is_plausible_h264_nal(nal: bytes) -> bool:
    return len(nal) >= 3 and nal[0] & 0x80 == 0 and _h264_nal_type(nal) in {
        1,
        5,
        6,
        7,
        8,
        9,
    }


def _h264_nal_type(nal: bytes) -> int:
    return nal[0] & 0x1F if nal else 0


def _h264_annexb_nal_spans(data: bytes) -> list[tuple[int, int, int]]:
    spans: list[tuple[int, int, int]] = []
    start = 0
    while True:
        start_code = _find_h264_annexb_start_code(data, start)
        if start_code is None:
            break
        offset, nal_start = start_code
        spans.append((offset, nal_start, len(data)))
        start = nal_start
    if not spans:
        return spans
    return [
        (offset, nal_start, spans[index + 1][0] if index + 1 < len(spans) else len(data))
        for index, (offset, nal_start, _end) in enumerate(spans)
    ]


def _find_h264_annexb_start_code(data: bytes, start: int) -> tuple[int, int] | None:
    offset = data.find(MPEG_START_CODE_PREFIX, start)
    if offset < 0:
        return None
    if offset > 0 and data[offset - 1] == 0:
        return offset - 1, offset + len(MPEG_START_CODE_PREFIX)
    return offset, offset + len(MPEG_START_CODE_PREFIX)


def _trim_trailing_h264_non_vcl_nals(data: bytes) -> bytes:
    spans = _h264_annexb_nal_spans(data)
    if not spans:
        return data
    last_vcl_end: int | None = None
    last_vcl_index: int | None = None
    for index, (_offset, nal_start, end) in enumerate(spans):
        nal_type = _h264_nal_type(data[nal_start:end])
        if nal_type in {1, 5}:
            last_vcl_end = end
            last_vcl_index = index
    if last_vcl_end is None:
        return data
    if last_vcl_index == len(spans) - 1:
        return data
    return data[:last_vcl_end]


def _trim_trailing_hevc_non_vcl_nals(data: bytes) -> bytes:
    spans = _h264_annexb_nal_spans(data)
    if not spans:
        return data
    last_vcl_end: int | None = None
    last_vcl_index: int | None = None
    for index, (_offset, nal_start, end) in enumerate(spans):
        nal_type = _hevc_nal_type(data[nal_start:end])
        if 0 <= nal_type <= 31:
            last_vcl_end = end
            last_vcl_index = index
    if last_vcl_end is None:
        return data
    if last_vcl_index == len(spans) - 1:
        return data
    return data[:last_vcl_end]


def _annexb_looks_like_h264(data: bytes) -> bool:
    return any(
        _h264_nal_type(data[nal_start:end]) in {1, 5, 6, 7, 8, 9}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _annexb_has_h264_vcl(data: bytes) -> bool:
    return any(
        _h264_nal_type(data[nal_start:end]) in {1, 5}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _annexb_looks_like_hevc(data: bytes) -> bool:
    return any(
        _is_plausible_hevc_nal(data[nal_start:end])
        and _hevc_nal_type(data[nal_start:end])
        in {16, 17, 18, 19, 20, 21, 32, 33, 34, 39, 40}
        for _offset, nal_start, end in _h264_annexb_nal_spans(data)
    )


def _hevc_nal_type(nal: bytes) -> int:
    return (nal[0] >> 1) & 0x3F if nal else 0


def _decrypt_hevc_nal_prefix(nal: bytes, aes_key: bytes) -> bytes:
    # PlayCtrl's live HEVC path passes encLenInfo=null and decrypts a fixed
    # 4096-byte AES-ECB prefix after the clear HEVC NAL header. For fragmented
    # units, we reconstruct the full NAL first so the prefix spans fragments.
    frame = bytearray(nal)
    decrypt_length = min(
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        len(frame) - HEVC_NAL_HEADER_SIZE,
    )
    decrypt_length -= decrypt_length % AES.block_size
    if decrypt_length > 0:
        cipher = _hikvision_aes_ecb_cipher(  # codeql[py/weak-cryptographic-algorithm]
            aes_key
        )
        decrypt_end = HEVC_NAL_HEADER_SIZE + decrypt_length
        frame[HEVC_NAL_HEADER_SIZE:decrypt_end] = cipher.decrypt(  # codeql[py/weak-cryptographic-algorithm]
            bytes(frame[HEVC_NAL_HEADER_SIZE:decrypt_end])
        )  # codeql[py/weak-cryptographic-algorithm] lgtm[py/weak-cryptographic-algorithm]
    return bytes(frame)


def _decrypt_h264_nal_prefix(
    nal: bytes,
    aes_key: bytes,
    *,
    nalu_header_size: int = H264_NAL_HEADER_SIZE,
) -> bytes:
    # H.264 local IDMX uses the same fixed encrypted-prefix scheme as HEVC.
    # Some streams keep the one-byte H.264 NAL header clear, while C6C command
    # streams encrypt the NAL header too; the caller selects the preserved size.
    frame = bytearray(nal)
    decrypt_length = min(
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        len(frame) - nalu_header_size,
    )
    decrypt_length -= decrypt_length % AES.block_size
    if decrypt_length > 0:
        cipher = _hikvision_aes_ecb_cipher(  # codeql[py/weak-cryptographic-algorithm]
            aes_key
        )
        decrypt_end = nalu_header_size + decrypt_length
        frame[nalu_header_size:decrypt_end] = cipher.decrypt(  # codeql[py/weak-cryptographic-algorithm]
            bytes(frame[nalu_header_size:decrypt_end])
        )  # codeql[py/weak-cryptographic-algorithm] lgtm[py/weak-cryptographic-algorithm]
    return bytes(frame)


def _iter_local_stream_payloads(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float],
) -> Iterator[bytes]:
    if getattr(stream, "supports_deadline_iter_packets", False):
        for packet in stream.iter_packets(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        ):
            yield packet.body
        return

    deadline: float | None = None
    for packet in stream.iter_packets(max_packets=max_packets):
        if duration_seconds is not None:
            now = monotonic()
            if deadline is None:
                deadline = now + duration_seconds
            elif now >= deadline:
                break
        yield packet.body


def _copy_mpegps_payloads_to_mpegts(
    payloads: Iterable[bytes],
    output: BinaryIO,
    *,
    process: subprocess.Popen[bytes],
) -> None:
    def _write_input(stdin: BinaryIO) -> None:
        for payload in payloads:
            stdin.write(payload)
            stdin.flush()

    copy_remuxed_output(process, output, write_input=_write_input)


def _copy_idmx_audio_video_to_mpegts(
    annexb: bytes,
    audio: _IdmxAacStream,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    video_input_format: str,
    video_frame_rate: str | None,
) -> None:
    """Mux decrypted IDMX elementary video and AAC into MPEG-TS."""

    with tempfile.TemporaryDirectory(prefix="pyezvizapi-idmx-") as directory:
        audio_path = Path(directory) / "audio.aac"
        audio_path.write_bytes(audio.adts)
        process = _open_local_idmx_audio_video_mpegts_remux_process(
            ffmpeg_path,
            video_input_format=video_input_format,
            audio_path=str(audio_path),
            video_frame_rate=video_frame_rate,
        )
        _copy_mpegps_payloads_to_mpegts([annexb], output, process=process)


def _start_ffmpeg_stderr_drain(
    process: subprocess.Popen[bytes],
    *,
    max_bytes: int = 65536,
) -> tuple[BoundedStderrTail, Thread | None]:
    tail, reader = start_stderr_drain(process, max_bytes=max_bytes)
    return tail, reader


def _ffmpeg_stderr_tail(
    chunks: list[bytes] | BoundedStderrTail,
    *,
    max_chars: int = 1200,
) -> str:
    if isinstance(chunks, BoundedStderrTail):
        return chunks.text(max_chars=max_chars)
    text = b"".join(chunks).decode("utf-8", errors="replace").strip()
    return text[-max_chars:]


def _write_local_stream_payloads(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float],
) -> None:
    for payload in _iter_local_stream_payloads(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    ):
        output.write(payload)
        output.flush()


__all__ = [name for name in globals() if not name.startswith("_")]
