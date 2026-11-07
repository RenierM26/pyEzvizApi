# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.cloud.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.cloud import transport as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.cloud.transport import (
    CLOUD_REPLAY_HEADER_SIZE as CLOUD_REPLAY_HEADER_SIZE,
    CLOUD_REPLAY_HEARTBEAT_CMD as CLOUD_REPLAY_HEARTBEAT_CMD,
    CLOUD_REPLAY_MAGIC as CLOUD_REPLAY_MAGIC,
    CLOUD_REPLAY_OPEN_CMD as CLOUD_REPLAY_OPEN_CMD,
    SocketFactory as SocketFactory,
    StopStreamResponse as StopStreamResponse,
    StreamInfoResponse as StreamInfoResponse,
    StreamTransport as StreamTransport,
    VtduInfoResponse as VtduInfoResponse,
    VtduStreamResponse as VtduStreamResponse,
    VtmChannel as VtmChannel,
    VtmMessageCode as VtmMessageCode,
    VtmPacket as VtmPacket,
    VtmStreamClient as VtmStreamClient,
    VtmTraceEvent as VtmTraceEvent,
    build_get_vtdu_info_request as build_get_vtdu_info_request,
    build_peer_stream_request as build_peer_stream_request,
    build_start_stream_request as build_start_stream_request,
    build_stop_stream_request as build_stop_stream_request,
    build_stream_info_request as build_stream_info_request,
    build_stream_keepalive_request as build_stream_keepalive_request,
    build_vtm_url as build_vtm_url,
    decode_vtm_header as decode_vtm_header,
    decode_vtm_packet as decode_vtm_packet,
    download_ezviz_cloud_replay as download_ezviz_cloud_replay,
    encode_vtm_packet as encode_vtm_packet,
    parse_get_vtdu_info_response as parse_get_vtdu_info_response,
    parse_peer_stream_response as parse_peer_stream_response,
    parse_start_stream_response as parse_start_stream_response,
    parse_stop_stream_response as parse_stop_stream_response,
    parse_stream_info_response as parse_stream_info_response,
    parse_vtm_url as parse_vtm_url,
    summarize_vtm_packet as summarize_vtm_packet,
    vtm_media_packet_source as vtm_media_packet_source,
    vtm_packet_to_media_packet as vtm_packet_to_media_packet,
    )

sys.modules[__name__] = _implementation
