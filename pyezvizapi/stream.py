"""Compatibility alias for the former combined stream module.

New code should import cloud protocol helpers from :mod:`stream_transport` and
MPEG/decryption helpers from :mod:`stream_media`.
"""

import sys
from typing import TYPE_CHECKING

from . import _stream as _implementation

if TYPE_CHECKING:
    from .rtp import rtp_payload  # codeql[py/unused-import]
    from .stream_media import (  # codeql[py/unused-import]
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        decrypt_hikvision_ps_video,
        detect_hikvision_ps_video_nalu_header_size,
        detect_transport,
        mpeg_ps_complete_prefix_length,
        mpeg_ps_decryptable_prefix_length,
    )
    from .stream_transport import (  # codeql[py/unused-import]
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
    def _declare_compatibility_exports(*exports: object) -> None:
        """Make compatibility re-exports visible to static analyzers."""

        if not exports:
            raise AssertionError("compatibility exports must not be empty")

    _declare_compatibility_exports(
        rtp_payload,
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        decrypt_hikvision_ps_video,
        detect_hikvision_ps_video_nalu_header_size,
        detect_transport,
        mpeg_ps_complete_prefix_length,
        mpeg_ps_decryptable_prefix_length,
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
