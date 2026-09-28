"""Compatibility alias for the former combined local-stream module.

New code should import session helpers from :mod:`local_stream_transport`,
media helpers from :mod:`local_stream_media`, and ECDH helpers from
:mod:`local_stream_ecdh`.
"""

# ruff: noqa: F401

import sys
from typing import TYPE_CHECKING

from . import _local_stream as _implementation
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

if TYPE_CHECKING:
    from .local_stream_media import (  # codeql[py/unused-import]
        LocalSdkOutputFormat,
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window,
        collect_h264_idmx_annexb_after_first_clean_idr_window,
        collect_idmx_annexb_after_first_clean_video_window,
        collect_local_stream_media_packets,
        collect_local_stream_mpegps,
        copy_hcnetsdk_real_data_to_mpegts,
        copy_local_stream_to_decrypted_mpegps,
        copy_local_stream_to_decrypted_mpegts,
        copy_local_stream_to_mpegps,
        copy_local_stream_to_mpegts,
        skip_h264_annexb_initial_idr_windows,
        skip_hevc_annexb_initial_irap_windows,
        summarize_h264_annexb_idr_windows,
        summarize_h264_annexb_units,
        summarize_hevc_annexb_irap_windows,
        summarize_idmx_h264_local_packets,
        trim_h264_annexb_to_first_clean_idr_window,
        trim_h264_annexb_to_first_error_free_suffix,
        trim_hevc_annexb_to_first_clean_irap_window,
        trim_hevc_annexb_to_first_error_free_suffix,
    )
    from .local_stream_transport import (  # codeql[py/unused-import]
        HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
        EzvizLocalSdkCredentials,
        EzvizLocalSdkMediaStream,
        EzvizLocalStreamPacket,
        HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
        HcNetSdkCommandPortGeneratedMultiSocketPlan,
        HcNetSdkCommandPortGeneratedSocketStep,
        HcNetSdkCommandPortKeepaliveEvent,
        HcNetSdkCommandPortMediaStream,
        HcNetSdkCommandPortMultiSocketMediaStream,
        HcNetSdkCommandPortMultiSocketPlan,
        HcNetSdkCommandPortSocketStep,
        copy_local_sdk_stream_from_client,
        get_local_sdk_stream_credentials_from_client,
        hcnetsdk_command_port_generated_plan_from_socket_plan,
        hcnetsdk_command_port_native_lan_live_view_plan,
        local_media_packet_source,
        local_stream_packet_to_media_packet,
        open_hcnetsdk_command_port_generated_multi_socket_stream,
        open_hcnetsdk_command_port_multi_socket_stream,
        open_hcnetsdk_command_port_stream,
        open_local_sdk_stream,
        open_local_sdk_stream_from_client,
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
