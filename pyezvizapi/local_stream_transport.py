# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import transport as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.transport as _compat_module_0

    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = (
        _compat_module_0.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW
    )
    EzvizLocalSdkCredentials = _compat_module_0.EzvizLocalSdkCredentials
    EzvizLocalSdkMediaStream = _compat_module_0.EzvizLocalSdkMediaStream
    EzvizLocalStreamPacket = _compat_module_0.EzvizLocalStreamPacket
    HcNetSdkCommandPortGeneratedMultiSocketMediaStream = (
        _compat_module_0.HcNetSdkCommandPortGeneratedMultiSocketMediaStream
    )
    HcNetSdkCommandPortGeneratedMultiSocketPlan = (
        _compat_module_0.HcNetSdkCommandPortGeneratedMultiSocketPlan
    )
    HcNetSdkCommandPortGeneratedSocketStep = _compat_module_0.HcNetSdkCommandPortGeneratedSocketStep
    HcNetSdkCommandPortKeepaliveEvent = _compat_module_0.HcNetSdkCommandPortKeepaliveEvent
    HcNetSdkCommandPortMediaStream = _compat_module_0.HcNetSdkCommandPortMediaStream
    HcNetSdkCommandPortMultiSocketMediaStream = (
        _compat_module_0.HcNetSdkCommandPortMultiSocketMediaStream
    )
    HcNetSdkCommandPortMultiSocketPlan = _compat_module_0.HcNetSdkCommandPortMultiSocketPlan
    HcNetSdkCommandPortSocketStep = _compat_module_0.HcNetSdkCommandPortSocketStep
    _socket = _compat_module_0._socket
    copy_local_sdk_stream_from_client = _compat_module_0.copy_local_sdk_stream_from_client
    fresh_local_sdk_receiver_port = _compat_module_0.fresh_local_sdk_receiver_port
    get_local_sdk_stream_credentials_from_client = (
        _compat_module_0.get_local_sdk_stream_credentials_from_client
    )
    hcnetsdk_command_port_generated_plan_from_socket_plan = (
        _compat_module_0.hcnetsdk_command_port_generated_plan_from_socket_plan
    )
    hcnetsdk_command_port_native_lan_live_view_plan = (
        _compat_module_0.hcnetsdk_command_port_native_lan_live_view_plan
    )
    local_media_packet_source = _compat_module_0.local_media_packet_source
    local_stream_packet_to_media_packet = _compat_module_0.local_stream_packet_to_media_packet
    open_hcnetsdk_command_port_generated_multi_socket_stream = (
        _compat_module_0.open_hcnetsdk_command_port_generated_multi_socket_stream
    )
    open_hcnetsdk_command_port_multi_socket_stream = (
        _compat_module_0.open_hcnetsdk_command_port_multi_socket_stream
    )
    open_hcnetsdk_command_port_stream = _compat_module_0.open_hcnetsdk_command_port_stream
    open_local_sdk_stream = _compat_module_0.open_local_sdk_stream
    open_local_sdk_stream_from_client = _compat_module_0.open_local_sdk_stream_from_client

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
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
        _socket,
        copy_local_sdk_stream_from_client,
        fresh_local_sdk_receiver_port,
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

sys.modules[__name__] = _implementation
