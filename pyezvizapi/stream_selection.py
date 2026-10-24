"""Metadata-first streaming with a strictly cloud-free offline policy."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
import errno
from functools import partial
import hashlib
import json
from threading import Lock
import time
from typing import Any

from ._local_stream import _NonemptyLocalMediaStream
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
    _BoundedEcdhMediaStream,
    local_ecdh_media_packet_source,
    open_local_sdk_ecdh_stream_from_client,
)
from .local_stream_transport import (
    fresh_local_sdk_receiver_port as fresh_receiver_port,
    get_local_sdk_stream_credentials_from_client,
    local_media_packet_source,
    open_local_sdk_stream_from_client,
)
from .media import CaptureLimits, MediaPacket, MediaPacketSource
from .stream_discovery import LocalStreamDiscovery
from .stream_header import EzvizStreamHeader
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
    channel: int = 1,
    _discovery_keys: list[str] | None = None,
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
    receiver_port = options.receiver_port or fresh_receiver_port()
    cached = None
    if options.discovery_cache is not None:
        key = _discovery_key(credentials, replace(options, device=device), channel)
        if _discovery_keys is not None:
            _discovery_keys.append(key)
        cached = options.discovery_cache.get(key)
    if (cached is not None and cached.source_kind == "local-sdk") or (
        cached is None and _live_ecdh_support(device) is False
    ):
        return LocalSdkClipSource(
            credentials=credentials, timeout=options.timeout, receiver_port=receiver_port
        )
    return LocalSdkEcdhClipSource(
        credentials=credentials,
        timeout=options.timeout,
        receiver_port=receiver_port,
        fresh_retry_port=True,
    )


def _discovery_key(credentials: Any, options: AutoClipSource, channel: int) -> str:
    """Hash identity/generation without retaining authentication in the cache."""
    identity = {
        "credentials": credentials.as_dict(include_media_key=True),
        "channel": channel, "generation": options.discovery_generation,
        "device": options.device,
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def _connection_failure(error: Exception) -> bool:
    """Recognize TCP/network reachability errors without hiding file errors."""
    return isinstance(error, (
        ConnectionError, TimeoutError, EzvizLocalSdkDeadlineExpired, EzvizLocalSdkStreamClosed,
    )) or (
        isinstance(error, OSError)
        and error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN}
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
            receiver_port=fresh_receiver_port(),
        )
    if (
        not isinstance(source, CloudClipSource)
        and options.mode == "auto"
        and options.allow_cloud_fallback
        and _connection_failure(error)
    ):
        return CloudClipSource(timeout=options.timeout, smscode=options.smscode)
    return None


def _live_input_frame_limit(limits: CaptureLimits) -> int | None:
    """Allow bounded negotiation input independently of emitted packets/bytes."""
    counts = [value for value in (limits.max_packets, limits.max_bytes) if value is not None]
    return min(counts) + 1024 if counts else None


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
        channel: int | None = None,
    ) -> None:
        self._client = client
        self._serial = serial
        self._options = options
        self._channel = channel
        self._stream: Any = None
        self._transport_lock = Lock()
        self._transport_close_lock = Lock()
        self._starting = self._startup_cancel_close = False
        self._transports_released = 0
        self._closed = False
        self._started = False
        self.source_kind: str | None = None
        self.discovery: LocalStreamDiscovery | None = None
        self._discovery_keys: list[str] = []
        self._stop_reason: str | None = None
        self._error_type: str | None = None
        self._cleanup_error_types: list[str] = []
        self._packets_yielded = self._bytes_yielded = self._transport_attempts = 0
        self._transports_opened = self._transport_close_attempts = self._transport_close_successes = 0

    @property
    def capture_result(self) -> dict[str, Any]:
        """Return a sanitized snapshot; source exhaustion is never protocol EOF."""
        status = ("failed" if self._error_type or self._cleanup_error_types else
                  "stopped" if self._stop_reason is not None else
                  "running" if self._started else "not_started")
        return dict(profile="automatic-media-capture-v1", status=status,
            stop_reason=self._stop_reason, source_kind=self.source_kind,
            packets_yielded=self._packets_yielded, bytes_yielded=self._bytes_yielded,
            transport_attempts=self._transport_attempts, transports_opened=self._transports_opened,
            transport_close_attempts=self._transport_close_attempts,
            transport_close_successes=self._transport_close_successes,
            transports_released=self._transports_released, startup_in_progress=self._starting,
            transport_closure_verified=(self._stream is None and not self._starting
                and self._transports_released == self._transports_opened),
            owner_closed=self._closed,
            transport_owned=self._stream is not None, error_type=self._error_type,
            cleanup_error_types=list(self._cleanup_error_types),
            network_eof_verified=False, caller_client_owned=False)

    def _stop(self, reason: str) -> None:
        if self._stop_reason is None:
            self._stop_reason = reason

    @contextmanager
    def _cleanup_scope(self, cleanup: Callable[[bool], Any]) -> Iterator[None]:
        try:
            yield
        except BaseException:
            cleanup(True)
            raise
        else:
            cleanup(False)

    def _cleanup(self, close: Callable[[], Any], primary: bool) -> bool:
        try:
            close()
            return True
        except Exception as error:
            self._cleanup_error_types.append(type(error).__name__)
            if not primary:
                raise PyEzvizError("Automatic stream cleanup failed") from error
            return False

    def _close_packets(self, packets: Iterator[MediaPacket], primary: bool) -> None:
        close = getattr(packets, "close", None)
        if callable(close):
            self._cleanup(close, primary)

    def _close_transport(self, primary: bool = False) -> None:
        # Serialize physical closes without holding the state lock over IO.
        # During startup an interrupt close cannot release ownership: connect()
        # may acquire/attach a socket after that close has already returned.
        with self._transport_close_lock:
            with self._transport_lock:
                stream = self._stream
                if stream is None or (self._starting and self._startup_cancel_close):
                    return
                interrupt = self._starting
                if interrupt:
                    self._startup_cancel_close = True
                else:
                    self._stream = None
                self._transport_close_attempts += 1
            if self._cleanup(stream.close, primary):
                with self._transport_lock:
                    self._transport_close_successes += 1
                    if not interrupt:
                        self._transports_released += 1

    def _start_transport(self, **kwargs: Any) -> bool:
        with self._transport_lock:
            stream = self._stream
            if self._closed or stream is None:
                return False
            self._starting = True
            self._startup_cancel_close = False
        try:
            stream.start(**kwargs)
        finally:
            with self._transport_lock:
                self._starting = False
        return not self._closed

    def __enter__(self) -> AutoMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self._close_owner(bool(args and args[0] is not None))

    def close(self) -> None:
        """Cancel the active transport; close is idempotent."""
        self._close_owner(False)

    def _close_owner(self, primary: bool) -> None:
        self._closed = True
        self._stop("consumer_closed" if self._started else "closed_before_start")
        self._close_transport(primary)

    def iter_media_packets(
        self, *, limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Select once, report a local stop reason, and own iterator/transport cleanup."""
        if self._closed or self._started:
            raise PyEzvizError("Automatic stream is closed or already consumed")
        self._started = True
        with self._cleanup_scope(self._close_owner):
            try:
                yield from self._iter_selected_packets(limits=limits, monotonic=monotonic)
            except GeneratorExit:
                self._stop("consumer_closed")
                raise
            except BaseException as error:
                self._error_type = type(error).__name__
                self._stop("timeout" if isinstance(error, TimeoutError | EzvizLocalSdkDeadlineExpired) else "error")
                raise

    def _iter_selected_packets(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        *,
        limits: CaptureLimits | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[MediaPacket]:
        """Select once and stream within one duration budget, including fallback."""
        selected_limits = limits or CaptureLimits()
        source = select_stream_source(self._client, self._serial, self._options,
                                      channel=1 if self._channel is None else self._channel,
                                      _discovery_keys=self._discovery_keys)
        # Account discovery is separate; subsequent LAN/cloud startup and retries
        # share the requested capture duration rather than restarting its budget.
        deadline = (
            monotonic() + selected_limits.duration_seconds
            if selected_limits.duration_seconds is not None
            else None
        )
        emitted = False
        ecdh_rate = 1
        while not self._closed:
            remaining = None if deadline is None else deadline - monotonic()
            if remaining is not None and remaining <= 0:
                self._stop("duration_limit")
                return
            self.source_kind = source.kind
            with self._cleanup_scope(self._close_transport):
                try:
                    adapter: MediaPacketSource
                    self._transport_attempts += 1
                    if isinstance(source, LocalSdkEcdhClipSource):
                        self._stream = open_local_sdk_ecdh_stream_from_client(
                            self._client,
                            self._serial,
                            credentials=source.credentials,
                            channel=1 if self._channel is None else self._channel,
                            receiver_port=source.receiver_port,
                            stream_rate=ecdh_rate,
                            timeout=source.timeout,
                        )
                        self._transports_opened += 1
                        adapter = local_ecdh_media_packet_source(_BoundedEcdhMediaStream(
                            self._stream,
                            _live_input_frame_limit(selected_limits),
                            None, monotonic,
                        ))
                    elif isinstance(source, LocalSdkClipSource):
                        self._stream = open_local_sdk_stream_from_client(
                            self._client,
                            self._serial,
                            credentials=source.credentials,
                            channel=1 if self._channel is None else self._channel,
                            receiver_port=source.receiver_port,
                            receiver_ex_port=source.receiver_port,
                            timeout=source.timeout,
                        )
                        self._transports_opened += 1
                        adapter = local_media_packet_source(_NonemptyLocalMediaStream(
                            self._stream,
                            _live_input_frame_limit(selected_limits),
                        ))
                    else:
                        cloud_deadline = monotonic() + self._options.timeout
                        if deadline is not None:
                            cloud_deadline = min(cloud_deadline, deadline)
                        self._stream = open_cloud_stream(
                            self._client,
                            self._serial,
                            channel=self._channel,
                            timeout=source.timeout,
                            capture_deadline=cloud_deadline,
                            monotonic=monotonic,
                        )
                        self._transports_opened += 1
                        if self._closed:
                            return
                        if not self._start_transport(deadline=cloud_deadline, monotonic=monotonic):
                            return
                        adapter = vtm_media_packet_source(self._stream)
                    if self._closed:
                        return
                    startup_deadline = monotonic() + self._options.timeout
                    if deadline is not None:
                        startup_deadline = min(startup_deadline, deadline)
                    if (not isinstance(source, CloudClipSource) and not self._start_transport(
                            read_first_media=False, deadline=startup_deadline, monotonic=monotonic)):
                        return
                    remaining = None if deadline is None else deadline - monotonic()
                    if remaining is not None and remaining <= 0:
                        raise EzvizLocalSdkDeadlineExpired(
                            "Automatic stream startup exhausted capture deadline"
                        )
                    negotiated_header: EzvizStreamHeader | None = None
                    header_valid = True
                    if not isinstance(source, CloudClipSource):
                        bootstrap = getattr(self._stream, "bootstrap", None)
                        if bootstrap is not None:
                            try:
                                negotiated_header = bootstrap.stream_header
                            except PyEzvizError:
                                header_valid = False
                                # Unsupported/malformed optional metadata must not
                                # turn a playable session into a transport failure.
                                if self._options.discovery_cache is not None:
                                    self._options.discovery_cache.invalidate(self._discovery_keys[-1])
                        self.discovery = LocalStreamDiscovery(source.kind, negotiated_header)
                    packets = adapter.iter_media_packets(
                        # Enforce normalized bytes here so the crossing packet
                        # has an explicit stop reason rather than hidden EOF.
                        limits=replace(selected_limits, duration_seconds=remaining, max_bytes=None),
                        monotonic=monotonic,
                    )
                    with self._cleanup_scope(partial(self._close_packets, packets)):
                        for packet in packets:
                            if self._closed:
                                self._stop("consumer_closed")
                                return
                            if deadline is not None and monotonic() >= deadline:
                                self._stop("duration_limit")
                                return
                            if not packet.body:
                                continue
                            if (selected_limits.max_bytes is not None
                                    and self._bytes_yielded + packet.length > selected_limits.max_bytes):
                                self._stop("byte_limit")
                                return
                            if not emitted and header_valid and self.discovery is not None and self._options.discovery_cache is not None and not isinstance(source, CloudClipSource):
                                self._options.discovery_cache.remember(self._discovery_keys[-1], self.discovery)
                            emitted = True
                            self._packets_yielded += 1
                            self._bytes_yielded += packet.length
                            yield packet
                            if (selected_limits.max_packets is not None
                                    and self._packets_yielded >= selected_limits.max_packets):
                                self._stop("packet_limit")
                                return
                    if deadline is not None and monotonic() >= deadline:
                        self._stop("duration_limit")
                        return
                    if not emitted and selected_limits.max_bytes is None:
                        raise EzvizNoMediaError("Automatic stream did not contain media")
                    self._stop("upstream_ended")
                    return
                except Exception as error:
                    self.discovery = None
                    if self._options.discovery_cache is not None and not isinstance(source, CloudClipSource):
                        self._options.discovery_cache.invalidate(self._discovery_keys[-1])
                    if (
                        not emitted
                        and isinstance(source, LocalSdkEcdhClipSource)
                        and isinstance(error, EzvizLocalSdkStreamClosed)
                        and ecdh_rate == 1
                    ):
                        # Same protocol retry mirrors the tested C8W copy path.
                        ecdh_rate = 0
                        source = replace(source, receiver_port=fresh_receiver_port())
                        continue
                    fallback = (
                        None if emitted else fallback_stream_source(source, self._options, error)
                    )
                    if fallback is None:
                        raise
                    source = fallback
