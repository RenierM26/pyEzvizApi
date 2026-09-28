"""Compatibility alias for the former combined local-stream module.

New code should import session helpers from :mod:`local_stream_transport`,
media helpers from :mod:`local_stream_media`, and ECDH helpers from
:mod:`local_stream_ecdh`.
"""

# ruff: noqa: F401, F403, PLC0414

import sys

from . import _local_stream as _implementation
from ._local_stream import *
from ._local_stream import (
    _decrypt_idmx_local_packets_to_adts_aac as _decrypt_idmx_local_packets_to_adts_aac,
    _ffmpeg_h264_decode_errors as _ffmpeg_h264_decode_errors,
    _ffmpeg_stderr_tail as _ffmpeg_stderr_tail,
    _h264_annexb_packet_end_offsets as _h264_annexb_packet_end_offsets,
    _hcnetsdk_command_port_media_packet as _hcnetsdk_command_port_media_packet,
    _hcnetsdk_command_port_media_payload as _hcnetsdk_command_port_media_payload,
    _idmx_audio_metadata as _idmx_audio_metadata,
    _idmx_h264_packets_from_selected_annexb as _idmx_h264_packets_from_selected_annexb,
    _idmx_hevc_annexb_packet_spans as _idmx_hevc_annexb_packet_spans,
    _idmx_local_packets_to_annexb_with_codec as _idmx_local_packets_to_annexb_with_codec,
    _idmx_local_video_frame_rate as _idmx_local_video_frame_rate,
    _idmx_packets_from_selected_annexb as _idmx_packets_from_selected_annexb,
    _iter_local_stream_payloads as _iter_local_stream_payloads,
    _start_ffmpeg_stderr_drain as _start_ffmpeg_stderr_drain,
    _try_first_clean_hevc_annexb_irap_window_offset as _try_first_clean_hevc_annexb_irap_window_offset,
)
from .constants import (
    LOCAL_SDK_ECDH_CONTROL_PORT,
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    LOCAL_SDK_ECDH_STREAM_PORT,
)
from .local_stream_ecdh import (
    EzvizLocalSdkEcdhDataPacket,
    EzvizLocalSdkEcdhHandshakePacket,
    EzvizLocalSdkEcdhKeyPair,
    EzvizLocalSdkEcdhMediaStream,
    EzvizLocalSdkEcdhStreamDecoder,
    EzvizLocalSdkEcdhStreamPacket,
    build_ezviz_local_sdk_ecdh_init_request_body,
    copy_local_sdk_ecdh_stream_from_client,
    copy_local_sdk_ecdh_stream_to_mpegps,
    decrypt_ezviz_local_sdk_ecdh_data_packet,
    derive_ezviz_local_sdk_ecdh_chacha20_key,
    derive_ezviz_local_sdk_ecdh_shared_secret,
    ezviz_local_sdk_ecdh_chacha20_nonce,
    generate_ezviz_local_sdk_ecdh_keypair,
    local_ecdh_media_packet_source,
    local_ecdh_packet_to_media_packet,
    open_local_sdk_ecdh_stream,
    open_local_sdk_ecdh_stream_from_client,
    parse_ezviz_local_sdk_ecdh_data_packet,
    parse_ezviz_local_sdk_ecdh_handshake_packet,
    transform_ezviz_local_sdk_ecdh_nonce,
)

_ECDH_EXPORTS = (
    "EzvizLocalSdkEcdhDataPacket",
    "EzvizLocalSdkEcdhHandshakePacket",
    "EzvizLocalSdkEcdhKeyPair",
    "EzvizLocalSdkEcdhMediaStream",
    "EzvizLocalSdkEcdhStreamDecoder",
    "EzvizLocalSdkEcdhStreamPacket",
    "build_ezviz_local_sdk_ecdh_init_request_body",
    "copy_local_sdk_ecdh_stream_from_client",
    "copy_local_sdk_ecdh_stream_to_mpegps",
    "decrypt_ezviz_local_sdk_ecdh_data_packet",
    "derive_ezviz_local_sdk_ecdh_chacha20_key",
    "derive_ezviz_local_sdk_ecdh_shared_secret",
    "ezviz_local_sdk_ecdh_chacha20_nonce",
    "generate_ezviz_local_sdk_ecdh_keypair",
    "local_ecdh_media_packet_source",
    "local_ecdh_packet_to_media_packet",
    "open_local_sdk_ecdh_stream",
    "open_local_sdk_ecdh_stream_from_client",
    "parse_ezviz_local_sdk_ecdh_data_packet",
    "parse_ezviz_local_sdk_ecdh_handshake_packet",
    "transform_ezviz_local_sdk_ecdh_nonce",
)

for _name in _ECDH_EXPORTS:
    setattr(_implementation, _name, globals()[_name])

for _name, _value in {
    "LOCAL_SDK_ECDH_CONTROL_PORT": LOCAL_SDK_ECDH_CONTROL_PORT,
    "LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT": LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    "LOCAL_SDK_ECDH_STREAM_PORT": LOCAL_SDK_ECDH_STREAM_PORT,
}.items():
    setattr(_implementation, _name, _value)

sys.modules[__name__] = _implementation
