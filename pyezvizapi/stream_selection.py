# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.selection`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import selection as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.selection as _compat_module_0

    Any = _compat_module_0.Any
    AutoClipSource = _compat_module_0.AutoClipSource
    AutoMediaStream = _compat_module_0.AutoMediaStream
    Callable = _compat_module_0.Callable
    CaptureLimits = _compat_module_0.CaptureLimits
    CloudClipSource = _compat_module_0.CloudClipSource
    EzvizLocalSdkDeadlineExpired = _compat_module_0.EzvizLocalSdkDeadlineExpired
    EzvizLocalSdkStreamClosed = _compat_module_0.EzvizLocalSdkStreamClosed
    EzvizNoMediaError = _compat_module_0.EzvizNoMediaError
    EzvizStreamHeader = _compat_module_0.EzvizStreamHeader
    EzvizUnsupportedMediaError = _compat_module_0.EzvizUnsupportedMediaError
    HcNetSdkLanEndpoint = _compat_module_0.HcNetSdkLanEndpoint
    Iterator = _compat_module_0.Iterator
    LocalSdkClipSource = _compat_module_0.LocalSdkClipSource
    LocalSdkEcdhClipSource = _compat_module_0.LocalSdkEcdhClipSource
    LocalStreamDiscovery = _compat_module_0.LocalStreamDiscovery
    Lock = _compat_module_0.Lock
    Mapping = _compat_module_0.Mapping
    MediaPacket = _compat_module_0.MediaPacket
    MediaPacketSource = _compat_module_0.MediaPacketSource
    PyEzvizError = _compat_module_0.PyEzvizError
    SelectedClipSource = _compat_module_0.SelectedClipSource
    _BoundedEcdhMediaStream = _compat_module_0._BoundedEcdhMediaStream
    _connection_failure = _compat_module_0._connection_failure
    _discovery_key = _compat_module_0._discovery_key
    _live_ecdh_support = _compat_module_0._live_ecdh_support
    _live_input_frame_limit = _compat_module_0._live_input_frame_limit
    _NonemptyLocalMediaStream = _compat_module_0._NonemptyLocalMediaStream
    annotations = _compat_module_0.annotations
    contextmanager = _compat_module_0.contextmanager
    errno = _compat_module_0.errno
    fallback_stream_source = _compat_module_0.fallback_stream_source
    fresh_receiver_port = _compat_module_0.fresh_receiver_port
    get_local_sdk_stream_credentials_from_client = (
        _compat_module_0.get_local_sdk_stream_credentials_from_client
    )
    hashlib = _compat_module_0.hashlib
    json = _compat_module_0.json
    local_ecdh_media_packet_source = _compat_module_0.local_ecdh_media_packet_source
    local_media_packet_source = _compat_module_0.local_media_packet_source
    open_cloud_stream = _compat_module_0.open_cloud_stream
    open_local_sdk_ecdh_stream_from_client = _compat_module_0.open_local_sdk_ecdh_stream_from_client
    open_local_sdk_stream_from_client = _compat_module_0.open_local_sdk_stream_from_client
    partial = _compat_module_0.partial
    replace = _compat_module_0.replace
    select_stream_source = _compat_module_0.select_stream_source
    time = _compat_module_0.time
    vtm_media_packet_source = _compat_module_0.vtm_media_packet_source

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        Any,
        AutoClipSource,
        AutoMediaStream,
        Callable,
        CaptureLimits,
        CloudClipSource,
        EzvizLocalSdkDeadlineExpired,
        EzvizLocalSdkStreamClosed,
        EzvizNoMediaError,
        EzvizStreamHeader,
        EzvizUnsupportedMediaError,
        HcNetSdkLanEndpoint,
        Iterator,
        LocalSdkClipSource,
        LocalSdkEcdhClipSource,
        LocalStreamDiscovery,
        Lock,
        Mapping,
        MediaPacket,
        MediaPacketSource,
        PyEzvizError,
        SelectedClipSource,
        _BoundedEcdhMediaStream,
        _connection_failure,
        _discovery_key,
        _live_ecdh_support,
        _live_input_frame_limit,
        _NonemptyLocalMediaStream,
        annotations,
        contextmanager,
        errno,
        fallback_stream_source,
        fresh_receiver_port,
        get_local_sdk_stream_credentials_from_client,
        hashlib,
        json,
        local_ecdh_media_packet_source,
        local_media_packet_source,
        open_cloud_stream,
        open_local_sdk_ecdh_stream_from_client,
        open_local_sdk_stream_from_client,
        partial,
        replace,
        select_stream_source,
        time,
        vtm_media_packet_source,
    )

sys.modules[__name__] = _implementation
