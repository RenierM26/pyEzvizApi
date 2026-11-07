# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.arguments`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import arguments as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cli.arguments as _compat_module_0

    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = (
        _compat_module_0.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW
    )
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = _compat_module_0.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
    Any = _compat_module_0.Any
    BatteryCameraWorkMode = _compat_module_0.BatteryCameraWorkMode
    _parse_args = _compat_module_0._parse_args
    _parse_duration_seconds = _compat_module_0._parse_duration_seconds
    add_camera_arguments = _compat_module_0.add_camera_arguments
    add_cloud_video_decrypt_arguments = _compat_module_0.add_cloud_video_decrypt_arguments
    add_cloud_video_download_arguments = _compat_module_0.add_cloud_video_download_arguments
    add_cloud_videos_arguments = _compat_module_0.add_cloud_videos_arguments
    add_device_infos_arguments = _compat_module_0.add_device_infos_arguments
    add_devices_arguments = _compat_module_0.add_devices_arguments
    add_devices_light_arguments = _compat_module_0.add_devices_light_arguments
    add_home_defence_mode_arguments = _compat_module_0.add_home_defence_mode_arguments
    add_light_arguments = _compat_module_0.add_light_arguments
    add_mqtt_arguments = _compat_module_0.add_mqtt_arguments
    add_pagelist_arguments = _compat_module_0.add_pagelist_arguments
    add_save_arguments = _compat_module_0.add_save_arguments
    add_save_clip_arguments = _compat_module_0.add_save_clip_arguments
    add_save_image_arguments = _compat_module_0.add_save_image_arguments
    add_sdcard_videos_arguments = _compat_module_0.add_sdcard_videos_arguments
    add_stream_arguments = _compat_module_0.add_stream_arguments
    add_stream_dump_arguments = _compat_module_0.add_stream_dump_arguments
    add_stream_h264_annexb_summary_arguments = (
        _compat_module_0.add_stream_h264_annexb_summary_arguments
    )
    add_stream_hcnetsdk_command_dump_summary_arguments = (
        _compat_module_0.add_stream_hcnetsdk_command_dump_summary_arguments
    )
    add_stream_hcnetsdk_command_plan_generate_arguments = (
        _compat_module_0.add_stream_hcnetsdk_command_plan_generate_arguments
    )
    add_stream_local_sdk_dump_arguments = _compat_module_0.add_stream_local_sdk_dump_arguments
    add_stream_local_sdk_keys_arguments = _compat_module_0.add_stream_local_sdk_keys_arguments
    add_stream_proxy_arguments = _compat_module_0.add_stream_proxy_arguments
    add_stream_trace_arguments = _compat_module_0.add_stream_trace_arguments
    add_unifiedmsg_arguments = _compat_module_0.add_unifiedmsg_arguments
    annotations = _compat_module_0.annotations
    argparse = _compat_module_0.argparse
    build_parser = _compat_module_0.build_parser

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
        LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        Any,
        BatteryCameraWorkMode,
        _parse_args,
        _parse_duration_seconds,
        add_camera_arguments,
        add_cloud_video_decrypt_arguments,
        add_cloud_video_download_arguments,
        add_cloud_videos_arguments,
        add_device_infos_arguments,
        add_devices_arguments,
        add_devices_light_arguments,
        add_home_defence_mode_arguments,
        add_light_arguments,
        add_mqtt_arguments,
        add_pagelist_arguments,
        add_save_arguments,
        add_save_clip_arguments,
        add_save_image_arguments,
        add_sdcard_videos_arguments,
        add_stream_arguments,
        add_stream_dump_arguments,
        add_stream_h264_annexb_summary_arguments,
        add_stream_hcnetsdk_command_dump_summary_arguments,
        add_stream_hcnetsdk_command_plan_generate_arguments,
        add_stream_local_sdk_dump_arguments,
        add_stream_local_sdk_keys_arguments,
        add_stream_proxy_arguments,
        add_stream_trace_arguments,
        add_unifiedmsg_arguments,
        annotations,
        argparse,
        build_parser,
    )

sys.modules[__name__] = _implementation
