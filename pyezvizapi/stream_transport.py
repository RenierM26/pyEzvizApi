# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.cloud.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.cloud import transport as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.cloud.transport as _compat_module_0
    CLOUD_REPLAY_HEADER_SIZE = _compat_module_0.CLOUD_REPLAY_HEADER_SIZE
    CLOUD_REPLAY_HEARTBEAT_CMD = _compat_module_0.CLOUD_REPLAY_HEARTBEAT_CMD
    CLOUD_REPLAY_MAGIC = _compat_module_0.CLOUD_REPLAY_MAGIC
    CLOUD_REPLAY_OPEN_CMD = _compat_module_0.CLOUD_REPLAY_OPEN_CMD
    SocketFactory = _compat_module_0.SocketFactory
    StopStreamResponse = _compat_module_0.StopStreamResponse
    StreamInfoResponse = _compat_module_0.StreamInfoResponse
    StreamTransport = _compat_module_0.StreamTransport
    VtduInfoResponse = _compat_module_0.VtduInfoResponse
    VtduStreamResponse = _compat_module_0.VtduStreamResponse
    VtmChannel = _compat_module_0.VtmChannel
    VtmMessageCode = _compat_module_0.VtmMessageCode
    VtmPacket = _compat_module_0.VtmPacket
    VtmStreamClient = _compat_module_0.VtmStreamClient
    VtmTraceEvent = _compat_module_0.VtmTraceEvent
    build_get_vtdu_info_request = _compat_module_0.build_get_vtdu_info_request
    build_peer_stream_request = _compat_module_0.build_peer_stream_request
    build_start_stream_request = _compat_module_0.build_start_stream_request
    build_stop_stream_request = _compat_module_0.build_stop_stream_request
    build_stream_info_request = _compat_module_0.build_stream_info_request
    build_stream_keepalive_request = _compat_module_0.build_stream_keepalive_request
    build_vtm_url = _compat_module_0.build_vtm_url
    decode_vtm_header = _compat_module_0.decode_vtm_header
    decode_vtm_packet = _compat_module_0.decode_vtm_packet
    download_ezviz_cloud_replay = _compat_module_0.download_ezviz_cloud_replay
    encode_vtm_packet = _compat_module_0.encode_vtm_packet
    parse_get_vtdu_info_response = _compat_module_0.parse_get_vtdu_info_response
    parse_peer_stream_response = _compat_module_0.parse_peer_stream_response
    parse_start_stream_response = _compat_module_0.parse_start_stream_response
    parse_stop_stream_response = _compat_module_0.parse_stop_stream_response
    parse_stream_info_response = _compat_module_0.parse_stream_info_response
    parse_vtm_url = _compat_module_0.parse_vtm_url
    summarize_vtm_packet = _compat_module_0.summarize_vtm_packet
    vtm_media_packet_source = _compat_module_0.vtm_media_packet_source
    vtm_packet_to_media_packet = _compat_module_0.vtm_packet_to_media_packet

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        CLOUD_REPLAY_HEADER_SIZE,
        CLOUD_REPLAY_HEARTBEAT_CMD,
        CLOUD_REPLAY_MAGIC,
        CLOUD_REPLAY_OPEN_CMD,
        SocketFactory,
        StopStreamResponse,
        StreamInfoResponse,
        StreamTransport,
        VtduInfoResponse,
        VtduStreamResponse,
        VtmChannel,
        VtmMessageCode,
        VtmPacket,
        VtmStreamClient,
        VtmTraceEvent,
        build_get_vtdu_info_request,
        build_peer_stream_request,
        build_start_stream_request,
        build_stop_stream_request,
        build_stream_info_request,
        build_stream_keepalive_request,
        build_vtm_url,
        decode_vtm_header,
        decode_vtm_packet,
        download_ezviz_cloud_replay,
        encode_vtm_packet,
        parse_get_vtdu_info_response,
        parse_peer_stream_response,
        parse_start_stream_response,
        parse_stop_stream_response,
        parse_stream_info_response,
        parse_vtm_url,
        summarize_vtm_packet,
        vtm_media_packet_source,
        vtm_packet_to_media_packet,
    )

sys.modules[__name__] = _implementation
