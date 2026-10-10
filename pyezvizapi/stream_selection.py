"""Metadata-first streaming with a strictly cloud-free offline policy."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
import json
import time
from typing import Any

from .clip import AutoClipSource, CloudClipSource, LocalSdkClipSource, LocalSdkEcdhClipSource
from .cloud_stream import open_cloud_stream
from .exceptions import (
    EzvizLocalSdkDeadlineExpired,
    EzvizLocalSdkStreamClosed,
    EzvizNoMediaError,
    EzvizUnsupportedMediaError,
    PyEzvizError,
)
from .hcnetsdk import HcNetSdkLanEndpoint
from .local_stream_ecdh import (
    local_ecdh_media_packet_source,
    open_local_sdk_ecdh_stream_from_client,
)
from .local_stream_transport import (
    get_local_sdk_stream_credentials_from_client,
    local_media_packet_source,
    open_local_sdk_stream_from_client,
)
from .media import CaptureLimits, MediaPacket, MediaPacketSource
from .stream_transport import vtm_media_packet_source

type SelectedClipSource = LocalSdkClipSource | LocalSdkEcdhClipSource | CloudClipSource


def _live_ecdh_support(device: Mapping[str, Any]) -> bool | None:  # noqa: PLR0911
    """Capability 519 member 1 enables owned live view in the official app.

    A missing capability in an otherwise populated supportExt means legacy.
    Absent/malformed metadata, and parent-device cases, need stream verification.
    """
    info = device.get("deviceInfos")
    if not isinstance(info, Mapping):
        return None
    if info.get("parentSerial") or info.get("superDeviceSerial"):
        return None
    support = info.get("supportExt")
    if isinstance(support, str):
        try:
            support = json.loads(support)
        except ValueError:
            return None
    if not isinstance(support, Mapping) or not support:
        return None
    if "519" not in support:
        return False
    value = support.get("519")
    if not isinstance(value, str):
        return None
    return "1" in {item.strip() for item in value.split(",")}


def select_stream_source(
    client: Any,
    serial: str,
    options: AutoClipSource,
    *,
    fetch_media_key: bool = False,
) -> SelectedClipSource:
    """Resolve one playback candidate, never fetching account data offline."""
    device = options.device
    if device is None and options.mode == "auto":
        response = client.get_device_infos(serial)
        if not isinstance(response, dict):
            raise PyEzvizError("Invalid device metadata for automatic playback")
        if (
            serial not in response
            and "deviceInfos" not in response
            and "CONNECTION" not in response
        ):
            raise PyEzvizError("Requested camera was not found in device metadata")
        device = response.get(serial, response)
        if not isinstance(device, dict):
            raise PyEzvizError("Invalid device metadata for automatic playback")
    device = device or {}
    credentials = options.credentials
    if credentials is None:
        connection = device.get("CONNECTION")
        if not isinstance(connection, dict) or not connection.get("localIp"):
            if options.mode == "auto" and options.allow_cloud_fallback:
                return CloudClipSource(timeout=options.timeout, smscode=options.smscode)
            raise PyEzvizError("No local endpoint is available for automatic playback")
        endpoint = HcNetSdkLanEndpoint.from_connection(serial, connection)
        credentials = get_local_sdk_stream_credentials_from_client(
            client,
            serial,
            endpoint=endpoint,
            fetch_media_key=fetch_media_key,
            smscode=options.smscode,
        )
    else:
        # Validate identity and required keys without registration or renewal.
        credentials = get_local_sdk_stream_credentials_from_client(
            client,
            serial,
            credentials=credentials,
            fetch_media_key=fetch_media_key,
        )
    if _live_ecdh_support(device) is False:
        return LocalSdkClipSource(
            credentials=credentials, timeout=options.timeout, receiver_port=options.receiver_port
        )
    return LocalSdkEcdhClipSource(
        credentials=credentials,
        timeout=options.timeout,
        receiver_port=options.receiver_port,
    )


def fallback_stream_source(
    source: SelectedClipSource,
    options: AutoClipSource,
    error: Exception,
) -> SelectedClipSource | None:
    """Permit only evidenced mismatch or connection failure before output."""
    if (
        isinstance(source, LocalSdkEcdhClipSource)
        and isinstance(error, EzvizUnsupportedMediaError)
        and error.reason == "protocol_mismatch"
    ):
        return LocalSdkClipSource(
            credentials=source.credentials,
            timeout=source.timeout,
            receiver_port=options.receiver_port,
        )
    if (
        not isinstance(source, CloudClipSource)
        and options.mode == "auto"
        and options.allow_cloud_fallback
        and isinstance(
            error,
            (
                ConnectionError,
                TimeoutError,
                EzvizLocalSdkDeadlineExpired,
                EzvizLocalSdkStreamClosed,
            ),
        )
    ):
        return CloudClipSource(timeout=options.timeout, smscode=options.smscode)
    return None


class AutoMediaStream:
    """Lazy, context-managed automatic packet source for live integrations.

    Transport packets are normalized, not video-decrypted or remuxed. ECDH
    link authentication is verified by its existing transport decoder. The
    selected source is exposed without credentials. Never switches after yield.
    """

    def __init__(
        self,
        client: Any,
        serial: str,
        options: AutoClipSource,
        *,
        channel: int = 1,
    ) -> None:
        self._client = client
        self._serial = serial
        self._options = options
        self._channel = channel
        self._stream: Any = None
        self._closed = False
        self._started = False
        self.source_kind: str | None = None

    def __enter__(self) -> AutoMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Cancel the active transport; close is idempotent."""
        self._closed = True
        if self._stream is not None:
            self._stream.close()

    def iter_media_packets(  # noqa: PLR0912, PLR0915
        self,
        *,
        limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Select once and stream within one duration budget, including fallback."""
        if self._closed or self._started:
            raise PyEzvizError("Automatic stream is closed or already consumed")
        self._started = True
        selected_limits = limits or CaptureLimits()
        source = select_stream_source(self._client, self._serial, self._options)
        # Account discovery is separate; subsequent LAN/cloud startup and retries
        # share the requested capture duration rather than restarting its budget.
        deadline = (
            monotonic() + selected_limits.duration_seconds
            if selected_limits.duration_seconds is not None
            else None
        )
        emitted = False
        ecdh_rate = 1
        try:
            while not self._closed:
                remaining = None if deadline is None else deadline - monotonic()
                if remaining is not None and remaining <= 0:
                    return
                self.source_kind = source.kind
                try:
                    adapter: MediaPacketSource
                    if isinstance(source, LocalSdkEcdhClipSource):
                        self._stream = open_local_sdk_ecdh_stream_from_client(
                            self._client,
                            self._serial,
                            credentials=source.credentials,
                            channel=self._channel,
                            receiver_port=source.receiver_port,
                            stream_rate=ecdh_rate,
                            timeout=source.timeout,
                        )
                        adapter = local_ecdh_media_packet_source(self._stream)
                    elif isinstance(source, LocalSdkClipSource):
                        self._stream = open_local_sdk_stream_from_client(
                            self._client,
                            self._serial,
                            credentials=source.credentials,
                            channel=self._channel,
                            receiver_port=self._options.receiver_port,
                            receiver_ex_port=self._options.receiver_port,
                            timeout=source.timeout,
                        )
                        adapter = local_media_packet_source(self._stream)
                    else:
                        self._stream = open_cloud_stream(
                            self._client,
                            self._serial,
                            channel=self._channel,
                            timeout=source.timeout,
                        )
                        cloud_deadline = monotonic() + self._options.timeout
                        if deadline is not None:
                            cloud_deadline = min(cloud_deadline, deadline)
                        self._stream.start(deadline=cloud_deadline, monotonic=monotonic)
                        adapter = vtm_media_packet_source(self._stream)
                    startup_deadline = monotonic() + self._options.timeout
                    if deadline is not None:
                        startup_deadline = min(startup_deadline, deadline)
                    if not isinstance(source, CloudClipSource):
                        self._stream.start(
                            read_first_media=False, deadline=startup_deadline, monotonic=monotonic
                        )
                    remaining = None if deadline is None else deadline - monotonic()
                    if remaining is not None and remaining <= 0:
                        raise EzvizLocalSdkDeadlineExpired(
                            "Automatic stream startup exhausted capture deadline"
                        )
                    for packet in adapter.iter_media_packets(
                        limits=replace(selected_limits, duration_seconds=remaining),
                        monotonic=monotonic,
                    ):
                        if self._closed or (deadline is not None and monotonic() >= deadline):
                            return
                        emitted = True
                        yield packet
                    if not emitted and selected_limits.max_bytes is None:
                        raise EzvizNoMediaError("Automatic stream did not contain media")
                    return
                except Exception as error:
                    if (
                        not emitted
                        and isinstance(source, LocalSdkEcdhClipSource)
                        and isinstance(error, EzvizLocalSdkStreamClosed)
                        and ecdh_rate == 1
                    ):
                        # Same protocol retry mirrors the tested C8W copy path.
                        ecdh_rate = 0
                        continue
                    fallback = (
                        None if emitted else fallback_stream_source(source, self._options, error)
                    )
                    if fallback is None:
                        raise
                    source = fallback
                finally:
                    if self._stream is not None:
                        self._stream.close()
                        self._stream = None
        finally:
            self.close()
