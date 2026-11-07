"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.selection`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming import selection as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.selection import (
    Any as Any,
    AutoClipSource as AutoClipSource,
    AutoMediaStream as AutoMediaStream,
    Callable as Callable,
    CaptureLimits as CaptureLimits,
    CloudClipSource as CloudClipSource,
    EzvizLocalSdkDeadlineExpired as EzvizLocalSdkDeadlineExpired,
    EzvizLocalSdkStreamClosed as EzvizLocalSdkStreamClosed,
    EzvizNoMediaError as EzvizNoMediaError,
    EzvizStreamHeader as EzvizStreamHeader,
    EzvizUnsupportedMediaError as EzvizUnsupportedMediaError,
    HcNetSdkLanEndpoint as HcNetSdkLanEndpoint,
    Iterator as Iterator,
    LocalSdkClipSource as LocalSdkClipSource,
    LocalSdkEcdhClipSource as LocalSdkEcdhClipSource,
    LocalStreamDiscovery as LocalStreamDiscovery,
    Lock as Lock,
    Mapping as Mapping,
    MediaPacket as MediaPacket,
    MediaPacketSource as MediaPacketSource,
    PyEzvizError as PyEzvizError,
    SelectedClipSource as SelectedClipSource,
    _BoundedEcdhMediaStream as _BoundedEcdhMediaStream,
    _NonemptyLocalMediaStream as _NonemptyLocalMediaStream,
    _connection_failure as _connection_failure,
    _discovery_key as _discovery_key,
    _live_ecdh_support as _live_ecdh_support,
    _live_input_frame_limit as _live_input_frame_limit,
    annotations as annotations,
    contextmanager as contextmanager,
    errno as errno,
    fallback_stream_source as fallback_stream_source,
    fresh_receiver_port as fresh_receiver_port,
    get_local_sdk_stream_credentials_from_client as get_local_sdk_stream_credentials_from_client,
    hashlib as hashlib,
    json as json,
    local_ecdh_media_packet_source as local_ecdh_media_packet_source,
    local_media_packet_source as local_media_packet_source,
    open_cloud_stream as open_cloud_stream,
    open_local_sdk_ecdh_stream_from_client as open_local_sdk_ecdh_stream_from_client,
    open_local_sdk_stream_from_client as open_local_sdk_stream_from_client,
    partial as partial,
    replace as replace,
    select_stream_source as select_stream_source,
    time as time,
    vtm_media_packet_source as vtm_media_packet_source,
    )

sys.modules[__name__] = _implementation
