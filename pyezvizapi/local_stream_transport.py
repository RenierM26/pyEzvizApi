"""Local SDK and HCNetSDK transport/session helpers."""

import socket as _socket

from ._local_stream import (  # noqa: F401
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


def fresh_local_sdk_receiver_port() -> int:
    """Reserve a kernel-selected loopback port for a new local SDK session.

    Does not connect or listen. The subsequent SDK bind remains authoritative
    if another local process wins the brief allocation race.
    """
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


__all__ = [name for name in globals() if not name.startswith("_")]
