"""Read camera-reported stream configuration and supported profiles offline.

This is HCNetSDK command-port discovery, not ECDH support inference. It never
starts preview, changes configuration, discovers credentials or calls cloud APIs.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import closing
from dataclasses import asdict, dataclass, field
import math
import socket
import time
from typing import Any

from .exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from .hcnetsdk import (
    HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    EzvizLanAudioVideoCompressInfo,
    EzvizLanCompressionConfig,
    EzvizLanCompressionInfoV30,
    EzvizLanVideoResolution,
    HcNetSdkCommandPortClient,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkCommandPortLoginSession,
    HcNetSdkLanEndpoint,
    HcNetSdkTcpFrame,
    SocketFactory,
    ezviz_lan_audio_video_compress_info,
    ezviz_lan_audio_video_compress_info_ability_request,
    ezviz_lan_compression_config,
    ezviz_lan_video_coding_get_config_request,
    hcnetsdk_command_port_response_payload,
    hcnetsdk_command_port_rsa_key,
    hcnetsdk_device_ability_command_port_template,
    hcnetsdk_dvr_config_command_port_template,
)


@dataclass(frozen=True)
class HcNetSdkStreamDetails:
    """One fresh camera snapshot: current configuration is not observed media."""

    channel: int
    configuration: EzvizLanCompressionConfig = field(repr=False)
    capabilities: EzvizLanAudioVideoCompressInfo
    reported_login_serial: str = field(default="", repr=False)

    def configured_resolution(self, *, sub_stream: bool = False) -> EzvizLanVideoResolution | None:
        """Resolve a configured SDK index using this camera's own resolution list."""
        block = self.configuration.network if sub_stream else self.configuration.normal_record
        if block is None:
            return None
        channels = [c for c in self.capabilities.video_channels if c.channel_number == self.channel]
        if len(channels) != 1:
            return None
        channel = channels[0]
        if sub_stream:
            profiles = [p for p in channel.sub_streams if p.index == 1]
            profile = profiles[0] if len(profiles) == 1 else None
        else:
            profile = channel.main_stream
        if profile is None:
            return None
        matches = [r for r in profile.resolutions if r.index == block.resolution]
        return matches[0] if len(matches) == 1 else None

    def as_dict(self) -> dict[str, Any]:
        """Return configuration and capability fields without raw replies/auth data."""
        def configured(block: EzvizLanCompressionInfoV30 | None) -> dict[str, Any] | None:
            if block is None:
                return None
            return {key: value for key, value in asdict(block).items() if key != "raw"}
        return {
            "channel": self.channel,
            "reported_login_serial": self.reported_login_serial,
            "source": "hcnetsdk_command_port",
            "observed_media": False,
            "transport_protocol": None,
            "main": configured(self.configuration.normal_record),
            "sub": configured(self.configuration.network),
            "main_resolution": asdict(r) if (r := self.configured_resolution()) is not None else None,
            "sub_resolution": asdict(r) if (r := self.configured_resolution(sub_stream=True)) is not None else None,
            "capabilities": asdict(self.capabilities),
        }


def discover_hcnetsdk_stream_details(
    endpoint: HcNetSdkLanEndpoint,
    password: str | bytes,
    *,
    channel: int = 1,
    username: str = HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    local_ip: str | None = None,
    timeout: float | None = 10.0,
    socket_factory: SocketFactory = socket.create_connection,
    rsa_key: Any | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    max_response_bytes: int = 524_288,
) -> HcNetSdkStreamDetails:
    """Login once and issue native GET1040 and ability8 queries on fresh sockets.

    Supplied credentials only: never renew or retry authentication. The finite
    network deadline covers login and both reads; RSA generation precedes it.
    Native frame-rate/resolution/codec IDs are preserved, not guessed as FPS or
    encryption protocols. Unsupported/malformed/authentication errors propagate.
    """
    if not isinstance(channel, int) or isinstance(channel, bool) or not 1 <= channel <= 255:
        raise PyEzvizError("Stream discovery channel must be between 1 and 255")
    if timeout is None or not math.isfinite(timeout) or timeout <= 0:
        raise PyEzvizError("Stream discovery requires a positive finite timeout")
    if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 16:
        raise PyEzvizError("Discovery response limit must include the 16-byte header")
    if not password:
        raise PyEzvizError("Stream discovery requires supplied local credentials")
    key = rsa_key if rsa_key is not None else hcnetsdk_command_port_rsa_key()
    deadline = monotonic() + timeout
    with closing(HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        sock = client.connect(deadline=deadline, monotonic=monotonic)
        address = local_ip if local_ip is not None else str(sock.getsockname()[0])
        session = client.login(password=password, username=username, local_ip=address,
                               rsa_key=key, max_frame_bytes=max_response_bytes, deadline=deadline, monotonic=monotonic)
    config_template = hcnetsdk_dvr_config_command_port_template(ezviz_lan_video_coding_get_config_request(1, channel))
    ability_template = hcnetsdk_device_ability_command_port_template(ezviz_lan_audio_video_compress_info_ability_request(1, channel))
    config = _query(endpoint, config_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
    configuration = ezviz_lan_compression_config(config.body)
    ability = _query(endpoint, ability_template, session, address, timeout, socket_factory, deadline, monotonic, max_response_bytes)
    capabilities = ezviz_lan_audio_video_compress_info(hcnetsdk_command_port_response_payload(ability))
    if not capabilities.success:
        raise PyEzvizError("Camera did not return audio/video compression capabilities")
    if monotonic() >= deadline:
        raise EzvizLocalSdkDeadlineExpired("Camera stream discovery exhausted its deadline")
    return HcNetSdkStreamDetails(channel, configuration, capabilities, session.serial)


def _query(
    endpoint: HcNetSdkLanEndpoint, template: HcNetSdkCommandPortControlTemplate,
    session: HcNetSdkCommandPortLoginSession, address: str, timeout: float,
    socket_factory: SocketFactory, deadline: float, monotonic: Callable[[], float],
    max_response_bytes: int,
) -> HcNetSdkTcpFrame:
    request = template.to_frame(session_id=session.session_id, auth_seed=session.auth_seed,
                                key=session.challenge, local_ip=address)
    with closing(HcNetSdkCommandPortClient(endpoint, timeout=timeout, socket_factory=socket_factory)) as client:
        client.send_command_frame(request, deadline=deadline, monotonic=monotonic)
        return client.read_tcp_frame(deadline=deadline, monotonic=monotonic, max_frame_bytes=max_response_bytes)
