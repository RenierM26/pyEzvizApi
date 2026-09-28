from __future__ import annotations

import pyezvizapi
from pyezvizapi.clip import ClipOptions
from pyezvizapi.local_stream import (
    EzvizLocalSdkEcdhStreamDecoder as LegacyEcdhDecoder,
)
from pyezvizapi.local_stream_ecdh import EzvizLocalSdkEcdhStreamDecoder
from pyezvizapi.local_stream_media import copy_local_stream_to_mpegts
from pyezvizapi.local_stream_transport import EzvizLocalSdkMediaStream
from pyezvizapi.stream import VtmStreamClient as LegacyVtmStreamClient
from pyezvizapi.stream_media import decrypt_hikvision_ps_video
from pyezvizapi.stream_transport import VtmStreamClient


def test_package_all_exports_resolve() -> None:
    missing = []
    for name in pyezvizapi.__all__:
        try:
            getattr(pyezvizapi, name)
        except AttributeError:
            missing.append(name)

    assert missing == []


def test_command_port_helpers_are_runtime_exports() -> None:
    expected = {
        "HcNetSdkCommandPortClient",
        "HcNetSdkCommandPortControlTemplate",
        "HcNetSdkCommandPortExchange",
        "HcNetSdkCommandPortGeneratedMultiSocketPlan",
        "HcNetSdkCommandPortGeneratedMultiSocketMediaStream",
        "HcNetSdkCommandPortGeneratedSocketStep",
        "HcNetSdkCommandPortLoginChallenge",
        "HcNetSdkCommandPortLoginSession",
        "HcNetSdkCommandPortMediaStream",
        "HcNetSdkCommandPortMultiSocketMediaStream",
        "HcNetSdkCommandPortMultiSocketPlan",
        "HcNetSdkCommandPortSocketStep",
        "HcNetSdkCommandPortStreamBootstrap",
        "HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW",
        "open_hcnetsdk_command_port_generated_multi_socket_stream",
        "open_hcnetsdk_command_port_multi_socket_stream",
        "open_hcnetsdk_command_port_stream",
        "decode_hcnetsdk_command_port_login_challenge",
        "hcnetsdk_command_port_auth_word",
        "hcnetsdk_command_port_control_frame",
        "hcnetsdk_command_port_control_template_from_frame",
        "hcnetsdk_command_port_generated_plan_from_socket_plan",
        "hcnetsdk_command_port_native_lan_live_view_plan",
        "collect_h264_idmx_annexb_after_first_clean_idr_window",
        "hcnetsdk_command_port_login_proof",
        "hcnetsdk_command_port_login_proof_frame",
        "hcnetsdk_command_port_login_request_frame",
        "hcnetsdk_command_port_password_digest",
        "hcnetsdk_command_port_public_key_der",
        "parse_hcnetsdk_command_port_login_session",
        "read_hcnetsdk_command_port_interleaved_frame_after_prefix",
        "read_hcnetsdk_tcp_frame",
        "skip_h264_annexb_initial_idr_windows",
        "summarize_h264_annexb_idr_windows",
        "summarize_h264_annexb_units",
        "summarize_idmx_h264_local_packets",
        "trim_h264_annexb_to_first_clean_idr_window",
    }

    assert expected <= set(pyezvizapi.__all__)
    for name in expected:
        assert getattr(pyezvizapi, name) is not None


def test_cloud_stream_copy_helpers_are_runtime_exports() -> None:
    expected = {
        "copy_cloud_stream_to_mpegps",
        "copy_cloud_stream_to_mpegts",
    }

    assert expected <= set(pyezvizapi.__all__)
    for name in expected:
        assert getattr(pyezvizapi, name) is not None


def test_dir_includes_lazy_exports() -> None:
    exported = set(pyezvizapi.__all__)
    visible = set(dir(pyezvizapi))

    assert exported <= visible


def test_stream_exports_have_focused_runtime_owners() -> None:
    expected_exports = {
        "ClipOptions": ClipOptions,
        "VtmStreamClient": VtmStreamClient,
        "decrypt_hikvision_ps_video": decrypt_hikvision_ps_video,
        "EzvizLocalSdkMediaStream": EzvizLocalSdkMediaStream,
        "copy_local_stream_to_mpegts": copy_local_stream_to_mpegts,
        "EzvizLocalSdkEcdhStreamDecoder": EzvizLocalSdkEcdhStreamDecoder,
    }

    for name, expected in expected_exports.items():
        assert getattr(pyezvizapi, name) is expected


def test_legacy_stream_modules_keep_existing_imports() -> None:
    assert LegacyEcdhDecoder is EzvizLocalSdkEcdhStreamDecoder
    assert LegacyVtmStreamClient is VtmStreamClient
