# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.arguments`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import arguments as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cli.arguments import (
        HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW as HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
        LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT as LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        Any as Any,
        BatteryCameraWorkMode as BatteryCameraWorkMode,
        _parse_args as _parse_args,
        _parse_duration_seconds as _parse_duration_seconds,
        add_camera_arguments as add_camera_arguments,
        add_cloud_video_decrypt_arguments as add_cloud_video_decrypt_arguments,
        add_cloud_video_download_arguments as add_cloud_video_download_arguments,
        add_cloud_videos_arguments as add_cloud_videos_arguments,
        add_device_infos_arguments as add_device_infos_arguments,
        add_devices_arguments as add_devices_arguments,
        add_devices_light_arguments as add_devices_light_arguments,
        add_home_defence_mode_arguments as add_home_defence_mode_arguments,
        add_light_arguments as add_light_arguments,
        add_mqtt_arguments as add_mqtt_arguments,
        add_pagelist_arguments as add_pagelist_arguments,
        add_save_arguments as add_save_arguments,
        add_save_clip_arguments as add_save_clip_arguments,
        add_save_image_arguments as add_save_image_arguments,
        add_sdcard_videos_arguments as add_sdcard_videos_arguments,
        add_stream_arguments as add_stream_arguments,
        add_stream_dump_arguments as add_stream_dump_arguments,
        add_stream_h264_annexb_summary_arguments as add_stream_h264_annexb_summary_arguments,
        add_stream_hcnetsdk_command_dump_summary_arguments as add_stream_hcnetsdk_command_dump_summary_arguments,
        add_stream_hcnetsdk_command_plan_generate_arguments as add_stream_hcnetsdk_command_plan_generate_arguments,
        add_stream_local_sdk_dump_arguments as add_stream_local_sdk_dump_arguments,
        add_stream_local_sdk_keys_arguments as add_stream_local_sdk_keys_arguments,
        add_stream_proxy_arguments as add_stream_proxy_arguments,
        add_stream_trace_arguments as add_stream_trace_arguments,
        add_unifiedmsg_arguments as add_unifiedmsg_arguments,
        annotations as annotations,
        argparse as argparse,
        build_parser as build_parser,
    )

sys.modules[__name__] = _implementation
