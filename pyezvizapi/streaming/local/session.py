"""Local EZVIZ stream adapters with native MPEG-PS output."""

from __future__ import annotations

import bisect
from collections.abc import Callable, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field, replace
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

from pyezvizapi.streaming.local import packets as _local_stream_packets
from pyezvizapi.streaming.local.packets import H264_FU_A_NAL_TYPE, HEVC_NAL_HEADER_SIZE, IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX, IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET, IDMX_LOCAL_FRAME_SENTINEL, IDMX_LOCAL_FRAME_SENTINEL_OFFSETS, _annexb_contains_selected_vcl, _annexb_first_vcl_unit, _annexb_has_h264_vcl, _annexb_looks_like_h264, _annexb_looks_like_hevc, _annexb_vcl_bounds, _append_h264_nal, _find_h264_annexb_start_code, _h264_annexb_idr_window_start_index, _h264_annexb_nal_spans, _h264_clean_idr_timeout_suffix, _h264_nal_type, _H264CleanIdrProbeResult, _hevc_nal_type, _idmx_frame_end_before_next_prefix, _idmx_local_frame_header_score, _idmx_local_frame_header_size, _idmx_local_frame_media_body, _idmx_local_rtp_frame, _is_complete_idmx_rtp_frame, _is_plausible_h264_nal, _is_plausible_hevc_nal, _looks_like_idmx_h264_clear_nal, _looks_like_idmx_h264_fu_a_frame, _looks_like_idmx_hevc_direct_frame, _looks_like_idmx_hevc_evidence_frame, _looks_like_idmx_hevc_media_frame, _looks_like_idmx_hevc_parameter_frame, _rtp_fragment_continues, _rtp_packet_matches_codec_epoch, _rtp_packet_route_descriptor, _RtpFragmentedNal, _strip_idmx_command_h264_record_trailer, _strip_legacy_idmx_video_wrapper
from pyezvizapi.streaming.app_capture import native_app_timed_payloads
from pyezvizapi.cloud.cas import CasDeviceSession, EzvizCAS
from pyezvizapi.constants import IDMX_DEFAULT_VIDEO_FRAME_RATE, IDMX_VIDEO_RTP_CLOCK_RATE, MAX_RETRIES
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, EzvizNoMediaError, EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import EzvizCasDeviceInfo, EzvizInterleavedRtpFrameWithPrefix, EzvizLocalAuthenticationAttrs, EzvizLocalPreviewRequest, EzvizLocalReceiverInfoAttrs, EzvizLocalReceiverInfoExAttrs, EzvizLocalSdkClient, EzvizLocalSdkStreamBootstrap, HcNetSdkCommandPortClient, HcNetSdkCommandPortControlTemplate, HcNetSdkCommandPortExchange, HcNetSdkCommandPortLoginSession, HcNetSdkCommandPortStreamBootstrap, HcNetSdkLanEndpoint, HcNetSdkRealDataPacket, SocketFactory, hcnetsdk_command_port_control_template_from_frame, hcnetsdk_command_port_rsa_key, iter_hcnetsdk_real_data_mpegps
from pyezvizapi.streaming.media.models import LegacyPacketSource, MediaPacket, MediaPacketMetadata, MediaPacketSourceAdapter, _app_remux_options, _hevc_parameter_options, _native_timing_options, has_positive_finite_capture_bound, is_positive_finite_duration_bound
from pyezvizapi.streaming.media.remux import BoundedStderrTail, copy_remuxed_output, open_mpegts_remux_process, start_stderr_drain, write_aac_remux_input
from pyezvizapi.streaming.media.rtp import DEFAULT_AAC_PAYLOAD_TYPES, DEFAULT_VIDEO_PAYLOAD_TYPES, RtpAacStream, RtpPacket, RtpRouteProfile, RtpSequenceKey, RtpVideoCodec, RtpVideoDepacketizer, _rtp_nal_starts_picture, _rtp_sequence_key, decrypt_idmx_aac_packets, detect_rtp_video_codec, idmx_rtp_stream_descriptors, idmx_video_frame_rate, parse_rtp_packet, rtp_nal_units_have_vcl, rtp_packet_has_valid_idmx_aac_frame, rtp_packet_is_idmx_aac, rtp_packets_to_nal_units, rtp_payload, rtp_payload_video_codec
from pyezvizapi.streaming.media.rtp_timing import timed_rtp_mpegps_payloads
from pyezvizapi.streaming.media.containers import ANNEX_B_LONG_START_CODE, HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH, MPEG_PS_START_CODE, MPEG_START_CODE_PREFIX, _hikvision_aes_ecb_cipher, _is_mpeg_ps_packet_start_id, decrypt_hikvision_ps_video

# Historical support-type import remains available through local_stream.
RtpStreamDescriptor = _local_stream_packets.RtpStreamDescriptor

HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = "app-lan-live-view"

_COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS = {
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
_FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS = 180
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
    credentials: EzvizLocalSdkCredentials | None = None,
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
        credentials=credentials,
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


@dataclass
class _NonemptyLocalMediaStream:
    """Count nonempty media independently from a bounded input allowance."""
    stream: Any
    max_frames: int | None
    supports_deadline_iter_packets = True
    supports_startup_deadline_iter_packets = True

    def iter_packets(
        self, *, max_packets: int | None = None, duration_seconds: float | None = None,
        duration_from_start: bool = True, monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalStreamPacket]:
        del duration_from_start
        emitted = 0
        for packet in self.stream.iter_packets(
            max_packets=self.max_frames, duration_seconds=duration_seconds,
            duration_from_start=True, monotonic=monotonic,
        ):
            if not packet.body:
                continue
            if max_packets is not None and emitted >= max_packets:
                return
            emitted += 1
            yield packet
            if max_packets is not None and emitted >= max_packets:
                return


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
    credentials: EzvizLocalSdkCredentials | None = None,
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
    skip_empty_packets: bool = False,
    native_shared_clock: bool = False,
    app_relative_clock: bool = False,
    decrypt_hevc_parameter_sets: bool = False,
) -> EzvizLocalSdkCredentials:
    """Open a direct-local SDK stream from an authenticated client and copy bytes.

    This is the public convenience path for integrations that want local
    9010/9020 media without wiring the CAS lookup, preview bootstrap, MPEG-PS
    collection, optional video decrypt, and MPEG-TS remux steps by hand.
    """
    if output_format not in ("mpegps", "mpegts"):
        raise PyEzvizError("output_format must be 'mpegps' or 'mpegts'")
    if decrypt_hevc_parameter_sets and (not decrypt_video or output_format != "mpegts"):
        raise PyEzvizError("HEVC parameter-set decryption requires decrypted MPEG-TS output")
    if native_shared_clock or app_relative_clock:
        if output_format != "mpegts" or receiver_trans_proto.upper() != "TCP":
            raise PyEzvizError(f"{'app_relative_clock' if app_relative_clock else 'native_shared_clock'} requires MPEG-TS over native TCP")
        _require_bounded_idmx_capture(max_packets=max_packets, duration_seconds=duration_seconds)
    if decrypt_video:
        _require_bounded_decrypt_capture(
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )

    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        credentials=credentials,
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
        media_stream: Any = (
            _NonemptyLocalMediaStream(stream, None if max_packets is None else max_packets + 1024)
            if skip_empty_packets else stream
        )
        if output_format == "mpegps":
            if decrypt_video:
                copy_local_stream_to_decrypted_mpegps(
                    media_stream,
                    output,
                    cast(str | bytes, selected_media_key),
                    nalu_header_size=nalu_header_size,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
            else:
                copy_local_stream_to_mpegps(
                    media_stream,
                    output,
                    max_packets=max_packets,
                    duration_seconds=duration_seconds,
                    monotonic=monotonic,
                )
        elif decrypt_video:
            copy_local_stream_to_decrypted_mpegts(
                media_stream,
                output,
                cast(str | bytes, selected_media_key),
                ffmpeg_path=ffmpeg_path,
                nalu_header_size=nalu_header_size,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
                **_hevc_parameter_options(decrypt_hevc_parameter_sets),
                **_native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock),
            )
        else:
            copy_local_stream_to_mpegts(
                media_stream,
                output,
                ffmpeg_path=ffmpeg_path,
                max_packets=max_packets,
                duration_seconds=duration_seconds,
                monotonic=monotonic,
                **_native_timing_options(native_shared_clock, app_relative_clock=app_relative_clock),
            )
    return credentials


def get_local_sdk_stream_credentials_from_client(
    client: Any,
    serial: str,
    *,
    credentials: EzvizLocalSdkCredentials | None = None,
    endpoint: HcNetSdkLanEndpoint | None = None,
    cas_serial: str | None = None,
    fetch_media_key: bool = True,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    smscode: str | int | None = None,
    cam_key_max_retries: int = 1,
) -> EzvizLocalSdkCredentials:
    """Fetch LAN endpoint, CAS tuple and optional media key from EZVIZ services."""
    if credentials is not None:
        if credentials.device_info.serial != serial:
            raise PyEzvizError("Local credentials do not match the requested camera")
        if fetch_media_key and credentials.media_key is None:
            raise PyEzvizError("Supplied local credentials require a media_key; no cloud refresh is performed")
        return credentials
    endpoint = endpoint or _local_sdk_endpoint_from_client(client, serial)
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


from pyezvizapi.streaming.local.capture import copy_local_stream_to_mpegps as copy_local_stream_to_mpegps


from pyezvizapi.streaming.local.capture import collect_local_stream_mpegps as collect_local_stream_mpegps


from pyezvizapi.streaming.local.capture import copy_local_stream_to_decrypted_mpegps as copy_local_stream_to_decrypted_mpegps


from pyezvizapi.streaming.local.capture import copy_local_stream_to_decrypted_mpegts as copy_local_stream_to_decrypted_mpegts


from pyezvizapi.streaming.local.capture import _require_bounded_decrypt_capture as _require_bounded_decrypt_capture


from pyezvizapi.streaming.local.capture import _require_bounded_idmx_capture as _require_bounded_idmx_capture


from pyezvizapi.streaming.local.capture import copy_local_stream_to_mpegts as copy_local_stream_to_mpegts


from pyezvizapi.streaming.local.capture import _clear_native_rtp_packets_with_legacy_indices as _clear_native_rtp_packets_with_legacy_indices


from pyezvizapi.streaming.local.capture import _copy_clear_native_idmx_timed_av as _copy_clear_native_idmx_timed_av


from pyezvizapi.streaming.local.capture import _clear_native_selected_timeline as _clear_native_selected_timeline


from pyezvizapi.streaming.local.capture import _copy_decrypted_native_idmx_timed_av as _copy_decrypted_native_idmx_timed_av


from pyezvizapi.streaming.local.capture import _native_decrypted_rtp_timeline as _native_decrypted_rtp_timeline


from pyezvizapi.streaming.local.capture import _native_decrypted_picture_timeline as _native_decrypted_picture_timeline

from pyezvizapi.streaming.local.capture import h264_clean_idr_capture_budgets as h264_clean_idr_capture_budgets


from pyezvizapi.streaming.local.capture import _checked_h264_duration_sum as _checked_h264_duration_sum


from pyezvizapi.streaming.local.capture import _is_ignorable_leading_stream_payload as _is_ignorable_leading_stream_payload


from pyezvizapi.streaming.local.capture import copy_hcnetsdk_real_data_to_mpegts as copy_hcnetsdk_real_data_to_mpegts


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
        invalid_rtp_version = (
            isinstance(err, EzvizUnsupportedMediaError)
            and err.reason == "invalid_rtp_version"
        )
        if not invalid_rtp_version and str(err) not in _COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS:
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
    if _looks_like_idmx_local_payload(payload):
        return True
    normalized = _strip_local_sdk_payload_header(payload)
    return (
        len(normalized) >= 4
        and normalized.startswith(MPEG_START_CODE_PREFIX)
        and _is_mpeg_ps_packet_start_id(normalized[3])
    )


def _strip_local_sdk_payload_header(payload: bytes) -> bytes:
    """Remove native EZVIZ local transport markers before MPEG-PS.

    The direct-local 9020 path wraps every RTP payload body with a small
    fragment marker. Observed values are 1c80 for the first fragment, 1c00 for
    continuations, and 1c40 for the final fragment. Unfragmented PS records,
    including audio PES packets, instead use a one-byte 0d marker. Strip that
    marker only before a recognized PS packet start, not arbitrary media bytes.
    """
    if len(payload) >= 2 and payload[0] == 0x1C:
        return payload[2:]
    if (
        len(payload) >= 5
        and payload[:4] == b"\x0d" + MPEG_START_CODE_PREFIX
        and _is_mpeg_ps_packet_start_id(payload[4])
    ):
        return payload[1:]
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
    frame_rate: str | None = str(IDMX_DEFAULT_VIDEO_FRAME_RATE),
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


IDMX_LOCAL_FRAME_HEADER_SIZE = 13
H264_NAL_HEADER_SIZE = 1
IDMX_H264_RTP_PAYLOAD_TYPE = 96
IDMX_AAC_RTP_PAYLOAD_TYPE = 104
HCNETSDK_HRUDP_FRAME_HEADER_SIZE = 12
HCNETSDK_HRUDP_VIDEO_FRAME_TYPE = 3


from pyezvizapi.streaming.local.diagnostics import collect_local_stream_media_packets as collect_local_stream_media_packets


from pyezvizapi.streaming.local.diagnostics import summarize_idmx_h264_local_packets as summarize_idmx_h264_local_packets


from pyezvizapi.streaming.local.diagnostics import _idmx_route_diagnostics as _idmx_route_diagnostics


from pyezvizapi.streaming.local.diagnostics import _summarize_idmx_packet_shapes as _summarize_idmx_packet_shapes


from pyezvizapi.streaming.local.diagnostics import _summarize_idmx_packet_shape as _summarize_idmx_packet_shape


from pyezvizapi.streaming.local.diagnostics import _possible_hcnetsdk_hrudp_packet_shape as _possible_hcnetsdk_hrudp_packet_shape


from pyezvizapi.streaming.local.diagnostics import summarize_h264_annexb_units as summarize_h264_annexb_units


from pyezvizapi.streaming.local.diagnostics import summarize_h264_annexb_idr_windows as summarize_h264_annexb_idr_windows


from pyezvizapi.streaming.local.diagnostics import summarize_hevc_annexb_irap_windows as summarize_hevc_annexb_irap_windows


from pyezvizapi.streaming.local.diagnostics import skip_h264_annexb_initial_idr_windows as skip_h264_annexb_initial_idr_windows


from pyezvizapi.streaming.local.diagnostics import skip_hevc_annexb_initial_irap_windows as skip_hevc_annexb_initial_irap_windows


from pyezvizapi.streaming.local.windows import collect_h264_idmx_annexb_after_first_clean_idr_window as collect_h264_idmx_annexb_after_first_clean_idr_window


from pyezvizapi.streaming.local.windows import _hevc_prefixed_suffix_accept_start_offset as _hevc_prefixed_suffix_accept_start_offset


from pyezvizapi.streaming.local.windows import collect_idmx_annexb_after_first_clean_video_window as collect_idmx_annexb_after_first_clean_video_window


from pyezvizapi.streaming.local.windows import _probe_first_clean_idmx_video_window as _probe_first_clean_idmx_video_window


from pyezvizapi.streaming.local.windows import collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window as collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window


from pyezvizapi.streaming.local.windows import _raise_if_clean_window_probe_exhausted as _raise_if_clean_window_probe_exhausted


from pyezvizapi.streaming.local.windows import _should_probe_clean_window as _should_probe_clean_window


from pyezvizapi.streaming.local.windows import _requested_duration_h264_suffix_predicate as _requested_duration_h264_suffix_predicate


from pyezvizapi.streaming.local.windows import _requested_duration_idmx_suffix_predicate as _requested_duration_idmx_suffix_predicate


from pyezvizapi.streaming.local.windows import _requested_duration_decrypted_h264_suffix_predicate as _requested_duration_decrypted_h264_suffix_predicate


from pyezvizapi.streaming.local.windows import trim_h264_annexb_to_first_clean_idr_window as trim_h264_annexb_to_first_clean_idr_window


from pyezvizapi.streaming.local.windows import trim_h264_annexb_to_first_error_free_suffix as trim_h264_annexb_to_first_error_free_suffix


from pyezvizapi.streaming.local.windows import trim_hevc_annexb_to_first_clean_irap_window as trim_hevc_annexb_to_first_clean_irap_window


from pyezvizapi.streaming.local.windows import trim_hevc_annexb_to_first_error_free_suffix as trim_hevc_annexb_to_first_error_free_suffix


from pyezvizapi.streaming.local.windows import _hevc_annexb_parameter_prefix_for_suffix as _hevc_annexb_parameter_prefix_for_suffix


from pyezvizapi.streaming.local.windows import _try_first_clean_h264_annexb_idr_window_offset as _try_first_clean_h264_annexb_idr_window_offset


from pyezvizapi.streaming.local.windows import _try_first_clean_decrypted_h264_annexb_idr_window_offset as _try_first_clean_decrypted_h264_annexb_idr_window_offset


from pyezvizapi.streaming.local.windows import _try_first_clean_hevc_annexb_irap_window_offset as _try_first_clean_hevc_annexb_irap_window_offset


from pyezvizapi.streaming.local.windows import _decrypted_h264_annexb_packet_index_for_offset as _decrypted_h264_annexb_packet_index_for_offset


from pyezvizapi.streaming.local.windows import _decrypted_hevc_annexb_packet_index_for_offset as _decrypted_hevc_annexb_packet_index_for_offset


from pyezvizapi.streaming.local.windows import _idmx_h264_annexb_packet_spans as _idmx_h264_annexb_packet_spans


from pyezvizapi.streaming.local.windows import _idmx_hevc_annexb_packet_spans as _idmx_hevc_annexb_packet_spans


from pyezvizapi.streaming.local.windows import _idmx_h264_packets_from_selected_annexb as _idmx_h264_packets_from_selected_annexb


from pyezvizapi.streaming.local.windows import _idmx_packet_frame_slice as _idmx_packet_frame_slice


from pyezvizapi.streaming.local.windows import _idmx_packets_for_selected_vcl_spans as _idmx_packets_for_selected_vcl_spans


from pyezvizapi.streaming.local.windows import _idmx_packets_from_selected_annexb as _idmx_packets_from_selected_annexb


from pyezvizapi.streaming.local.windows import _h264_annexb_packet_index_for_offset as _h264_annexb_packet_index_for_offset


from pyezvizapi.streaming.local.windows import _hevc_annexb_packet_index_for_offset as _hevc_annexb_packet_index_for_offset


from pyezvizapi.streaming.local.windows import _idmx_annexb_packet_index_for_offset as _idmx_annexb_packet_index_for_offset


from pyezvizapi.streaming.local.windows import _try_first_clean_h264_annexb_idr_window_offset_from_annexb as _try_first_clean_h264_annexb_idr_window_offset_from_annexb


from pyezvizapi.streaming.local.windows import _ffmpeg_h264_decode_errors as _ffmpeg_h264_decode_errors


from pyezvizapi.streaming.local.windows import _ffmpeg_hevc_decode_errors as _ffmpeg_hevc_decode_errors


from pyezvizapi.streaming.local.windows import _ffmpeg_video_decode_errors as _ffmpeg_video_decode_errors


from pyezvizapi.streaming.local.windows import _ffmpeg_video_decode_probe_timeout_seconds as _ffmpeg_video_decode_probe_timeout_seconds


from pyezvizapi.streaming.local.windows import _hevc_annexb_irap_window_start_index as _hevc_annexb_irap_window_start_index


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_rtp_packet as _idmx_local_frame_rtp_packet


from pyezvizapi.streaming.local.payloads import _summarize_idmx_h264_local_frame as _summarize_idmx_h264_local_frame


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_transport_fields as _idmx_local_frame_transport_fields


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_is_h264_transport as _idmx_local_frame_is_h264_transport


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_sequence_number as _idmx_local_frame_sequence_number


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_rtp_timestamp as _idmx_local_frame_rtp_timestamp


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_rtp_marker as _idmx_local_frame_rtp_marker


from pyezvizapi.streaming.local.payloads import _idmx_rtp_extension as _idmx_rtp_extension


from pyezvizapi.streaming.local.payloads import _idmx_audio_descriptor as _idmx_audio_descriptor


from pyezvizapi.streaming.local.payloads import _idmx_audio_metadata as _idmx_audio_metadata


from pyezvizapi.streaming.local.payloads import _idmx_audio_payload_types as _idmx_audio_payload_types


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_have_aac as _idmx_local_packets_have_aac


from pyezvizapi.streaming.local.payloads import _idmx_local_video_frame_rate as _idmx_local_video_frame_rate


from pyezvizapi.streaming.local.payloads import _merge_idmx_h264_frame_summary as _merge_idmx_h264_frame_summary


from pyezvizapi.streaming.local.payloads import _increment_h264_nal_type_count as _increment_h264_nal_type_count


from pyezvizapi.streaming.local.payloads import _record_idmx_h264_nal_unit_summary as _record_idmx_h264_nal_unit_summary


from pyezvizapi.streaming.local.payloads import _increment_idmx_h264_nal_unit_counter as _increment_idmx_h264_nal_unit_counter


from pyezvizapi.streaming.local.payloads import _append_idmx_h264_nal_unit_sample as _append_idmx_h264_nal_unit_sample


from pyezvizapi.streaming.local.payloads import _looks_like_idmx_local_payload as _looks_like_idmx_local_payload


from pyezvizapi.streaming.local.payloads import _looks_like_length_prefixed_idmx_local_payload as _looks_like_length_prefixed_idmx_local_payload


from pyezvizapi.streaming.local.payloads import _iter_idmx_local_frames as _iter_idmx_local_frames


from pyezvizapi.streaming.local.payloads import _iter_idmx_local_frame_or_nested as _iter_idmx_local_frame_or_nested


from pyezvizapi.streaming.local.payloads import _iter_idmx_local_packet_frame as _iter_idmx_local_packet_frame


from pyezvizapi.streaming.local.payloads import _idmx_local_packet_contains_aggregate_media_frame as _idmx_local_packet_contains_aggregate_media_frame


from pyezvizapi.streaming.local.payloads import _idmx_local_packet_contains_aggregate_descriptors as _idmx_local_packet_contains_aggregate_descriptors


from pyezvizapi.streaming.local.payloads import _idmx_local_frames_contain_routed_media as _idmx_local_frames_contain_routed_media


from pyezvizapi.streaming.local.payloads import _idmx_local_packet_frame_sequence_number as _idmx_local_packet_frame_sequence_number


from pyezvizapi.streaming.local.payloads import _iter_idmx_local_packet_frames as _iter_idmx_local_packet_frames


from pyezvizapi.streaming.local.payloads import _idmx_local_frame_contains_media as _idmx_local_frame_contains_media


from pyezvizapi.streaming.local.payloads import _local_stream_packets_are_idmx as _local_stream_packets_are_idmx


from pyezvizapi.streaming.local.payloads import _unsupported_idmx_local_payload_error as _unsupported_idmx_local_payload_error


from pyezvizapi.streaming.local.payloads import _decrypt_idmx_local_packets_to_annexb as _decrypt_idmx_local_packets_to_annexb


from pyezvizapi.streaming.local.payloads import _decrypt_idmx_local_packets_to_annexb_with_codec as _decrypt_idmx_local_packets_to_annexb_with_codec


from pyezvizapi.streaming.local.payloads import _decrypt_idmx_local_packets_to_adts_aac as _decrypt_idmx_local_packets_to_adts_aac


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_to_h264_annexb as _idmx_local_packets_to_h264_annexb


from pyezvizapi.streaming.local.payloads import _h264_annexb_packet_end_offsets as _h264_annexb_packet_end_offsets


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_to_hevc_annexb as _idmx_local_packets_to_hevc_annexb


from pyezvizapi.streaming.local.payloads import _hevc_annexb_packet_end_offsets as _hevc_annexb_packet_end_offsets


from pyezvizapi.streaming.local.payloads import _idmx_local_video_payload_types as _idmx_local_video_payload_types


from pyezvizapi.streaming.local.payloads import _idmx_local_route_profile as _idmx_local_route_profile


from pyezvizapi.streaming.local.payloads import _idmx_local_supported_video_payload_types as _idmx_local_supported_video_payload_types


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_to_annexb as _idmx_local_packets_to_annexb


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_to_annexb_with_codec as _idmx_local_packets_to_annexb_with_codec


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_to_h264_annexb_with_codec as _idmx_local_packets_to_h264_annexb_with_codec


from pyezvizapi.streaming.local.payloads import _idmx_local_packets_have_direct_hevc_media as _idmx_local_packets_have_direct_hevc_media


from pyezvizapi.streaming.local.payloads import _local_media_aes_key as _local_media_aes_key


from pyezvizapi.streaming.local.payloads import _idmx_hevc_direct_frame_matches_route as _idmx_hevc_direct_frame_matches_route


from pyezvizapi.streaming.local.payloads import _append_idmx_hevc_media_payload as _append_idmx_hevc_media_payload


from pyezvizapi.streaming.local.payloads import _append_idmx_h264_fu_a_payload as _append_idmx_h264_fu_a_payload


from pyezvizapi.streaming.local.payloads import _append_decrypted_hevc_nal as _append_decrypted_hevc_nal


from pyezvizapi.streaming.local.payloads import _append_decrypted_h264_nal as _append_decrypted_h264_nal


from pyezvizapi.streaming.local.payloads import _append_hevc_nal as _append_hevc_nal


from pyezvizapi.streaming.local.payloads import _trim_trailing_h264_non_vcl_nals as _trim_trailing_h264_non_vcl_nals


from pyezvizapi.streaming.local.payloads import _trim_trailing_hevc_non_vcl_nals as _trim_trailing_hevc_non_vcl_nals


from pyezvizapi.streaming.local.payloads import _decrypt_hevc_nal_prefix as _decrypt_hevc_nal_prefix


from pyezvizapi.streaming.local.payloads import _decrypt_h264_nal_prefix as _decrypt_h264_nal_prefix


from pyezvizapi.streaming.local.payloads import _iter_local_stream_payloads as _iter_local_stream_payloads


from pyezvizapi.streaming.local.payloads import _copy_mpegps_payloads_to_mpegts as _copy_mpegps_payloads_to_mpegts


from pyezvizapi.streaming.local.payloads import _copy_idmx_audio_video_to_mpegts as _copy_idmx_audio_video_to_mpegts


from pyezvizapi.streaming.local.payloads import _start_ffmpeg_stderr_drain as _start_ffmpeg_stderr_drain


from pyezvizapi.streaming.local.payloads import _ffmpeg_stderr_tail as _ffmpeg_stderr_tail


from pyezvizapi.streaming.local.payloads import _write_local_stream_payloads as _write_local_stream_payloads


__all__ = [name for name in globals() if not name.startswith("_")]
