"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import transport as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.transport import (
    EzvizLocalSdkCredentials as EzvizLocalSdkCredentials,
    EzvizLocalSdkMediaStream as EzvizLocalSdkMediaStream,
    EzvizLocalStreamPacket as EzvizLocalStreamPacket,
    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW as HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
    HcNetSdkCommandPortGeneratedMultiSocketMediaStream as HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
    HcNetSdkCommandPortGeneratedMultiSocketPlan as HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortGeneratedSocketStep as HcNetSdkCommandPortGeneratedSocketStep,
    HcNetSdkCommandPortKeepaliveEvent as HcNetSdkCommandPortKeepaliveEvent,
    HcNetSdkCommandPortMediaStream as HcNetSdkCommandPortMediaStream,
    HcNetSdkCommandPortMultiSocketMediaStream as HcNetSdkCommandPortMultiSocketMediaStream,
    HcNetSdkCommandPortMultiSocketPlan as HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep as HcNetSdkCommandPortSocketStep,
    _socket as _socket,
    copy_local_sdk_stream_from_client as copy_local_sdk_stream_from_client,
    fresh_local_sdk_receiver_port as fresh_local_sdk_receiver_port,
    get_local_sdk_stream_credentials_from_client as get_local_sdk_stream_credentials_from_client,
    hcnetsdk_command_port_generated_plan_from_socket_plan as hcnetsdk_command_port_generated_plan_from_socket_plan,
    hcnetsdk_command_port_native_lan_live_view_plan as hcnetsdk_command_port_native_lan_live_view_plan,
    local_media_packet_source as local_media_packet_source,
    local_stream_packet_to_media_packet as local_stream_packet_to_media_packet,
    open_hcnetsdk_command_port_generated_multi_socket_stream as open_hcnetsdk_command_port_generated_multi_socket_stream,
    open_hcnetsdk_command_port_multi_socket_stream as open_hcnetsdk_command_port_multi_socket_stream,
    open_hcnetsdk_command_port_stream as open_hcnetsdk_command_port_stream,
    open_local_sdk_stream as open_local_sdk_stream,
    open_local_sdk_stream_from_client as open_local_sdk_stream_from_client,
    )

sys.modules[__name__] = _implementation
