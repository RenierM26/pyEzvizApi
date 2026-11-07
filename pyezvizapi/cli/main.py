"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, BinaryIO, cast
from urllib.parse import parse_qs, urlparse

from pyezvizapi.cli import arguments as _cli_arguments
from pyezvizapi.cloud.token_store import save_private_token
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.cloud.cas import CasDeviceSession, EzvizCAS
from pyezvizapi.client import EzvizClient
from pyezvizapi.streaming.cloud.bootstrap import _closing_unconnected_cloud_stream, cloud_rtp_packets_have_audio, copy_cloud_stream_packets_to_mpegts, copy_decrypted_cloud_stream_packets_to_mpegts, open_cloud_stream
from pyezvizapi.constants import MAX_RETRIES, PROFILE as PUSH_PROFILE, BatteryCameraWorkMode, DefenseModeType, DeviceSwitchType
from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizNoMediaError, PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import HCNETSDK_COMMAND_PORT_CONTROL_FAMILY, EzvizCasDeviceInfo, EzvizLocalAuthenticationAttrs, EzvizLocalPreviewRequest, EzvizLocalReceiverInfo, EzvizLocalReceiverInfoAttrs, EzvizLocalReceiverInfoEx, EzvizLocalReceiverInfoExAttrs, HcNetSdkCommandPortControlTemplate, HcNetSdkLanEndpoint, classify_ezviz_local_sdk_body, parse_hcnetsdk_tcp_frame
from pyezvizapi.devices.light_bulb import EzvizLightBulb
from pyezvizapi.streaming.local.ecdh import LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT, copy_local_sdk_ecdh_stream_to_media, open_local_sdk_ecdh_stream
from pyezvizapi.streaming.local.media import _idmx_local_packets_to_annexb_with_codec, copy_local_stream_to_decrypted_mpegps, copy_local_stream_to_decrypted_mpegts, copy_local_stream_to_mpegps, copy_local_stream_to_mpegts, summarize_h264_annexb_idr_windows, summarize_h264_annexb_units, summarize_hevc_annexb_irap_windows, summarize_idmx_h264_local_packets
from pyezvizapi.streaming.local.transport import HcNetSdkCommandPortGeneratedMultiSocketPlan, HcNetSdkCommandPortGeneratedSocketStep, HcNetSdkCommandPortMultiSocketPlan, HcNetSdkCommandPortSocketStep, get_local_sdk_stream_credentials_from_client, hcnetsdk_command_port_generated_plan_from_socket_plan, hcnetsdk_command_port_native_lan_live_view_plan, open_local_sdk_stream
from pyezvizapi.streaming.media.models import has_positive_finite_capture_bound
from pyezvizapi.streaming.media.remux import copy_remuxed_output, open_mpegts_remux_process, remux_bytes
from pyezvizapi.streaming.media.rtp import detect_rtp_video_codec, parse_rtp_packet, rtp_nal_units_have_vcl, rtp_packets_to_nal_units, rtp_payload_video_codec
from pyezvizapi.streaming.media.containers import decrypt_hikvision_ps_video, detect_hikvision_ps_video_nalu_header_size, detect_transport, mpeg_ps_decryptable_prefix_length
from pyezvizapi.streaming.cloud.transport import StreamTransport, VtmStreamClient, download_ezviz_cloud_replay

_LOGGER = logging.getLogger("pyezvizapi.__main__")
_REAL_EZVIZ_CLIENT = EzvizClient
HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS = 5.0


@dataclass(frozen=True)
class StreamProxyConfig:
    """Configuration for the experimental HTTP stream proxy."""

    serial: str
    channel: int | None
    client_type: int
    token_index: int
    refresh_vtm: bool
    timeout: float | None
    path: str
    ffmpeg_path: str
    allow_encrypted: bool
    decrypt_video: bool
    decrypt_codec: str
    max_packets: int | None
    media_key: str | bytes | None = field(default=None, repr=False)
    sms_code: str | None = field(default=None, repr=False)


class StreamProxyHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server that does not block CLI shutdown on active streams."""

    daemon_threads = True
    block_on_close = False


HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = _cli_arguments.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW

# Historical CLI parsing hooks retain their original implementation objects.
_parse_args = _cli_arguments._parse_args  # noqa: SLF001
_parse_duration_seconds = _cli_arguments._parse_duration_seconds  # noqa: SLF001


def _setup_logging(debug: bool) -> None:
    """Configure root logger for CLI usage."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, stream=sys.stderr, format="%(levelname)s: %(message)s")
    if debug:
        # Verbose requests logging in debug mode
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True


def _token_has_service_urls(token: dict[str, Any] | None) -> bool:
    """Return True when a saved token carries the CAS sysConf endpoint metadata."""

    service_urls = token.get("service_urls") if token else None
    if not isinstance(service_urls, dict):
        return False
    sys_conf = service_urls.get("sysConf")
    return (
        isinstance(sys_conf, (list, tuple))
        and len(sys_conf) > 16
        and bool(sys_conf[15])
        and bool(sys_conf[16])
    )


def _token_has_refresh_session(token: dict[str, Any] | None) -> bool:
    """Return True when a saved token can refresh itself without credentials."""

    return bool(
        token and token.get("session_id") and token.get("rf_session_id") and token.get("api_url")
    )


def _action_requires_service_urls(args: argparse.Namespace) -> bool:
    """Return True when the selected CLI path needs CAS service metadata."""

    return bool(
        (
            args.action == "stream"
            and (
                args.stream_action == "local-sdk-keys"
                or (args.stream_action == "local-sdk-dump" and args.fetch_cas)
            )
        )
        or (
            args.action == "save"
            and getattr(args, "save_action", None) == "clip"
            and getattr(args, "source", None) in {"auto", "local-sdk", "local-sdk-ecdh"}
        )
    )


def _ensure_client_service_urls(client: EzvizClient) -> None:
    """Refresh the client's token service metadata for CAS-only CLI paths."""

    token = client.export_token()
    if _token_has_service_urls(token):
        return
    service_urls = client.get_service_urls()
    if hasattr(client, "_token"):
        client._token["service_urls"] = service_urls  # noqa: SLF001
    if hasattr(client, "exported_token"):
        cast(Any, client).exported_token["service_urls"] = service_urls


def _login(
    client: EzvizClient,
    token: dict[str, Any] | None = None,
    *,
    require_service_urls: bool = False,
) -> None:
    """Login only when the saved token cannot satisfy the selected action."""
    if (
        token
        and token.get("session_id")
        and (not require_service_urls or _token_has_service_urls(token))
    ):
        return

    if not (client.account and client.password) and not _token_has_refresh_session(token):
        return

    logged_in = False
    if client.account and client.password:
        try:
            client.login()
        except EzvizAuthVerificationCode:
            mfa_code = input("MFA code required, please input MFA code.\n")
            try:
                code_int = int(mfa_code.strip())
            except ValueError:
                code_int = None
            client.login(sms_code=code_int)
        logged_in = True

    if not logged_in:
        client.login()

    if require_service_urls:
        _ensure_client_service_urls(client)


def _write_json(obj: Any) -> None:
    """Write an object to stdout as pretty JSON."""
    sys.stdout.write(json.dumps(obj, indent=2) + "\n")


def _format_cell(value: Any) -> str:
    """Return a compact printable representation for table cells."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _write_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    """Write rows to stdout as a simple fixed-width table."""
    if not rows:
        sys.stdout.write("No rows returned.\n")
        return

    widths = {column: len(column) for column in columns}
    formatted_rows: list[dict[str, str]] = []
    for row in rows:
        formatted = {column: _format_cell(row.get(column)) for column in columns}
        formatted_rows.append(formatted)
        for column, value in formatted.items():
            widths[column] = max(widths[column], len(value))

    header = "  ".join(column.ljust(widths[column]) for column in columns)
    separator = "  ".join("-" * widths[column] for column in columns)
    sys.stdout.write(header + "\n")
    sys.stdout.write(separator + "\n")
    for row in formatted_rows:
        sys.stdout.write("  ".join(row[column].ljust(widths[column]) for column in columns) + "\n")


def _handle_devices(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices` subcommands (device/status/switch/connection)."""
    if args.device_action == "device":
        _write_json(client.get_device())
        return 0

    if args.device_action == "status":
        data = client.load_cameras(refresh=getattr(args, "refresh", True))
        if args.json:
            _write_json(data)
        else:
            # Enrich with common switch flags when available
            for payload in data.values():
                sw = payload.get("SWITCH")
                if sw is None:
                    continue

                # Compute all switch flags present on the device
                flags: dict[str, bool] = {}
                if isinstance(sw, list):
                    for item in sw:
                        if not isinstance(item, dict):
                            continue
                        t = item.get("type")
                        en = item.get("enable")
                        if not isinstance(t, int) or not isinstance(en, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(en)
                elif isinstance(sw, dict):
                    for k, v in sw.items():
                        try:
                            t = int(k)
                        except (TypeError, ValueError):
                            continue
                        if not isinstance(v, (bool, int)):
                            continue
                        try:
                            name = DeviceSwitchType(t).name.lower()
                        except ValueError:
                            name = f"switch_{t}"
                        flags[name] = bool(v)

                if flags:
                    payload["switch_flags"] = flags

                # Keep legacy-friendly individual columns
                payload["sleep"] = flags.get("sleep")
                payload["privacy"] = flags.get("privacy")
                payload["audio"] = flags.get("sound")
                payload["ir_led"] = flags.get("infrared_light")
                payload["state_led"] = flags.get("light")

            columns = [
                "serial",
                "name",
                "status",
                "device_category",
                "device_sub_category",
                "sleep",
                "privacy",
                "audio",
                "ir_led",
                "state_led",
                "local_ip",
                "local_rtsp_port",
                "battery_level",
                "alarm_schedules_enabled",
                "alarm_notify",
                "Motion_Trigger",
            ]
            rows = [
                {"serial": serial, **payload}
                for serial, payload in data.items()
                if isinstance(payload, dict)
            ]
            _write_table(rows, columns)
        return 0

    if args.device_action == "switch":
        _write_json(client.get_switch())
        return 0

    if args.device_action == "connection":
        _write_json(client.get_connection())
        return 0

    _LOGGER.error("Action not implemented: %s", args.device_action)
    return 2


from pyezvizapi.cli.commands_devices import _handle_devices_light as _handle_devices_light


from pyezvizapi.cli.commands_devices import _handle_pagelist as _handle_pagelist


from pyezvizapi.cli.commands_devices import _handle_device_infos as _handle_device_infos


from pyezvizapi.cli.commands_devices import _handle_unifiedmsg as _handle_unifiedmsg


from pyezvizapi.cli.commands_devices import _decode_compressed_record_list as _decode_compressed_record_list


from pyezvizapi.cli.commands_devices import _first_record_list as _first_record_list


from pyezvizapi.cli.commands_devices import _handle_sdcard_videos as _handle_sdcard_videos


from pyezvizapi.cli.commands_recordings import _handle_cloud_videos as _handle_cloud_videos


from pyezvizapi.cli.commands_recordings import _handle_cloud_video_download as _handle_cloud_video_download


from pyezvizapi.cli.commands_recordings import _select_cloud_video_for_seq_id as _select_cloud_video_for_seq_id


from pyezvizapi.cli.commands_recordings import _extract_ticket as _extract_ticket


from pyezvizapi.cli.commands_recordings import _cloud_video_start_millis as _cloud_video_start_millis


from pyezvizapi.cli.commands_recordings import _cas_time_from_millis as _cas_time_from_millis


from pyezvizapi.cli.commands_recordings import _handle_cloud_video_decrypt as _handle_cloud_video_decrypt


from pyezvizapi.cli.commands_recordings import _write_save_result as _write_save_result


from pyezvizapi.cli.commands_recordings import _validate_shared_clip_args as _validate_shared_clip_args


from pyezvizapi.cli.commands_recordings import _handle_save_clip as _handle_save_clip


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_from_args as _hcnetsdk_command_plan_from_args


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_generated_plan_from_args as _hcnetsdk_command_generated_plan_from_args


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_from_json as _hcnetsdk_command_plan_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_generated_plan_from_json as _hcnetsdk_command_generated_plan_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_raw_steps as _hcnetsdk_command_plan_raw_steps


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_step_from_json as _hcnetsdk_command_plan_step_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_generated_plan_step_from_json as _hcnetsdk_command_generated_plan_step_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_templates_from_json as _hcnetsdk_command_plan_templates_from_json


from pyezvizapi.cli.commands_capture import _iter_hcnetsdk_command_template_values as _iter_hcnetsdk_command_template_values


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_template_from_json as _hcnetsdk_command_plan_template_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_int_required as _hcnetsdk_int_required


from pyezvizapi.cli.commands_capture import _hcnetsdk_optional_int as _hcnetsdk_optional_int


from pyezvizapi.cli.commands_capture import _hcnetsdk_bytes_from_json as _hcnetsdk_bytes_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_frames_from_json as _hcnetsdk_command_plan_frames_from_json


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_read_policy as _hcnetsdk_command_plan_read_policy


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_response_reads as _hcnetsdk_command_plan_response_reads


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_media_socket as _hcnetsdk_command_plan_media_socket


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_immediate_media_read as _hcnetsdk_command_plan_immediate_media_read


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_delay_after_commands as _hcnetsdk_command_plan_delay_after_commands


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_plan_drain_media_before_next as _hcnetsdk_command_plan_drain_media_before_next


from pyezvizapi.cli.commands_capture import _hcnetsdk_bool as _hcnetsdk_bool


from pyezvizapi.cli.commands_capture import _hcnetsdk_int as _hcnetsdk_int


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_frames_from_args as _hcnetsdk_command_frames_from_args


from pyezvizapi.cli.commands_capture import _hcnetsdk_command_frame_hex_values_from_file as _hcnetsdk_command_frame_hex_values_from_file


from pyezvizapi.cli.commands_capture import _iter_hcnetsdk_command_frame_hex_values as _iter_hcnetsdk_command_frame_hex_values


from pyezvizapi.cli.commands_capture import _bytes_from_hex_value as _bytes_from_hex_value


from pyezvizapi.cli.commands_capture import _hcnetsdk_read_response_policy as _hcnetsdk_read_response_policy


from pyezvizapi.cli.commands_capture import _handle_save_image as _handle_save_image


from pyezvizapi.cli.commands_capture import _handle_save as _handle_save


from pyezvizapi.cli.commands_capture import _handle_light as _handle_light


from pyezvizapi.cli.commands_capture import _handle_home_defence_mode as _handle_home_defence_mode


from pyezvizapi.cli.commands_capture import _handle_mqtt as _handle_mqtt


from pyezvizapi.cli.commands_capture import _write_stream_payloads as _write_stream_payloads


from pyezvizapi.cli.commands_push import _start_cli_cloud_stream as _start_cli_cloud_stream


from pyezvizapi.cli.commands_cloud_stream import _collect_stream_payloads as _collect_stream_payloads


from pyezvizapi.cli.commands_cloud_stream import _collect_stream_packets as _collect_stream_packets


from pyezvizapi.cli.commands_cloud_stream import _detect_stream_packets_transport as _detect_stream_packets_transport


from pyezvizapi.cli.commands_cloud_stream import _rtp_payload_video_codec as _rtp_payload_video_codec


from pyezvizapi.cli.commands_cloud_stream import _detect_rtp_video_codec as _detect_rtp_video_codec


from pyezvizapi.cli.commands_cloud_stream import _parse_rtp_packets as _parse_rtp_packets


from pyezvizapi.cli.commands_cloud_stream import _rtp_packets_to_annexb as _rtp_packets_to_annexb


from pyezvizapi.cli.commands_cloud_stream import _rtp_packets_to_annexb_units as _rtp_packets_to_annexb_units


from pyezvizapi.cli.commands_cloud_stream import _decrypt_annexb_video_bytes as _decrypt_annexb_video_bytes


from pyezvizapi.cli.commands_cloud_stream import _decrypt_rtp_annexb_units as _decrypt_rtp_annexb_units


from pyezvizapi.cli.commands_cloud_stream import _remux_elementary_video_bytes_to_mpegts as _remux_elementary_video_bytes_to_mpegts


from pyezvizapi.cli.commands_cloud_stream import _decrypt_stream_payload_bytes as _decrypt_stream_payload_bytes


from pyezvizapi.cli.commands_cloud_stream import _codec_nalu_header_size as _codec_nalu_header_size


class _BufferedStreamPayloadDecryptor:
    """Decrypt MPEG-PS payloads after buffering across VTM packet splits."""

    _MAX_AUTO_PROBE_BYTES = 8 * 1024 * 1024

    def __init__(self, key: str | bytes, *, codec: str) -> None:
        self._key = key
        self._nalu_header_size = _codec_nalu_header_size(codec)
        self._buffer = bytearray()

    def _decrypt_chunk(self, chunk: bytes) -> bytes:
        if self._nalu_header_size is None:
            detected_nalu_header_size = detect_hikvision_ps_video_nalu_header_size(
                chunk,
                self._key,
                default=None,
            )
            if detected_nalu_header_size is None:
                return decrypt_hikvision_ps_video(
                    chunk,
                    self._key,
                    nalu_header_size=2,
                )
            self._nalu_header_size = detected_nalu_header_size
        return decrypt_hikvision_ps_video(
            chunk,
            self._key,
            nalu_header_size=self._nalu_header_size,
        )

    def __call__(self, data: bytes) -> bytes:
        self._buffer.extend(data)
        complete_end = mpeg_ps_decryptable_prefix_length(self._buffer)
        if complete_end <= 0:
            if (
                self._nalu_header_size is None
                and len(self._buffer) > self._MAX_AUTO_PROBE_BYTES
            ):
                raise PyEzvizError("Could not detect MPEG-PS video encryption mode")
            return b""
        if self._nalu_header_size is None:
            detected = detect_hikvision_ps_video_nalu_header_size(
                bytes(self._buffer[:complete_end]),
                self._key,
                default=None,
            )
            if detected is None:
                if len(self._buffer) > self._MAX_AUTO_PROBE_BYTES:
                    raise PyEzvizError("Could not detect MPEG-PS video encryption mode")
                return b""
            self._nalu_header_size = detected
        chunk = bytes(self._buffer[:complete_end])
        del self._buffer[:complete_end]
        return self._decrypt_chunk(chunk)

    def flush(self) -> bytes:
        """Decrypt and return any buffered tail at stream end."""

        if not self._buffer:
            return b""
        chunk = bytes(self._buffer)
        self._buffer.clear()
        return self._decrypt_chunk(chunk)


from pyezvizapi.cli.commands_cloud_stream import _stream_payload_decryptor as _stream_payload_decryptor


from pyezvizapi.cli.commands_cloud_stream import _stream_payload_decryptors as _stream_payload_decryptors


from pyezvizapi.cli.commands_cloud_stream import _stream_payload_decryptors_with_key as _stream_payload_decryptors_with_key


from pyezvizapi.cli.commands_cloud_stream import _cloud_cli_media_key as _cloud_cli_media_key


from pyezvizapi.cli.commands_cloud_stream import _explicit_cloud_cli_media_key as _explicit_cloud_cli_media_key


from pyezvizapi.cli.commands_cloud_stream import _remux_mpegps_bytes_to_mpegts as _remux_mpegps_bytes_to_mpegts


from pyezvizapi.cli.commands_cloud_stream import _remux_stream_payloads_to_mpegts as _remux_stream_payloads_to_mpegts


from pyezvizapi.cli.commands_cloud_stream import _open_mpegts_remux_process as _open_mpegts_remux_process


from pyezvizapi.cli.commands_cloud_stream import _copy_stream_payloads_to_mpegts as _copy_stream_payloads_to_mpegts


from pyezvizapi.cli.commands_cloud_stream import _default_stream_proxy_path as _default_stream_proxy_path


from pyezvizapi.cli.commands_cloud_stream import _normalize_stream_proxy_path as _normalize_stream_proxy_path


from pyezvizapi.cli.commands_cloud_stream import _handle_stream_proxy_get as _handle_stream_proxy_get


from pyezvizapi.cli.commands_cloud_stream import _serve_stream_proxy as _serve_stream_proxy


from pyezvizapi.cli.commands_cloud_stream import _env_or_arg as _env_or_arg


from pyezvizapi.cli.commands_cloud_stream import os_environ_get as os_environ_get


from pyezvizapi.cli.commands_cloud_stream import _required_local_sdk_secret as _required_local_sdk_secret


from pyezvizapi.cli.commands_cloud_stream import _local_sdk_credentials_file as _local_sdk_credentials_file


from pyezvizapi.cli.commands_cloud_stream import _local_sdk_credentials_value as _local_sdk_credentials_value


from pyezvizapi.cli.commands_local_stream import _local_sdk_arg_or_credentials as _local_sdk_arg_or_credentials


from pyezvizapi.cli.commands_local_stream import _required_local_sdk_arg_or_credentials as _required_local_sdk_arg_or_credentials


from pyezvizapi.cli.commands_local_stream import _local_sdk_media_key as _local_sdk_media_key


from pyezvizapi.cli.commands_local_stream import _local_sdk_has_static_media_key as _local_sdk_has_static_media_key


from pyezvizapi.cli.commands_local_stream import _read_optional_binary_file as _read_optional_binary_file


from pyezvizapi.cli.commands_local_stream import _local_sdk_cas_device_info as _local_sdk_cas_device_info


from pyezvizapi.cli.commands_local_stream import _build_local_sdk_cli_stream as _build_local_sdk_cli_stream


from pyezvizapi.cli.commands_local_stream import _build_local_sdk_ecdh_cli_stream as _build_local_sdk_ecdh_cli_stream


from pyezvizapi.cli.commands_local_stream import _local_sdk_receiver_info_from_args as _local_sdk_receiver_info_from_args


from pyezvizapi.cli.commands_local_stream import _local_sdk_receiver_info_ex_from_args as _local_sdk_receiver_info_ex_from_args


from pyezvizapi.cli.commands_local_stream import _local_sdk_authentication_from_args as _local_sdk_authentication_from_args


from pyezvizapi.cli.commands_local_stream import _handle_local_sdk_stream_dump as _handle_local_sdk_stream_dump


from pyezvizapi.cli.commands_local_stream import _copy_local_sdk_ecdh_cli_stream as _copy_local_sdk_ecdh_cli_stream


from pyezvizapi.cli.commands_local_stream import _handle_local_sdk_keys as _handle_local_sdk_keys


from pyezvizapi.cli.commands_local_stream import _handle_h264_annexb_summary as _handle_h264_annexb_summary


from pyezvizapi.cli.commands_local_stream import _handle_hcnetsdk_command_dump_summary as _handle_hcnetsdk_command_dump_summary


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_command_frame_dump_summary as _hcnetsdk_command_frame_dump_summary


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_inbound_media_dump_summary as _hcnetsdk_inbound_media_dump_summary


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_playm4_input_dump_summary as _hcnetsdk_playm4_input_dump_summary


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_native_annexb_dump_summary as _hcnetsdk_native_annexb_dump_summary


from pyezvizapi.cli.commands_local_stream import _decode_native_annexb_chunk_windows as _decode_native_annexb_chunk_windows


from pyezvizapi.cli.commands_local_stream import _detect_native_annexb_codec as _detect_native_annexb_codec


from pyezvizapi.cli.commands_local_stream import _iter_annexb_nal_prefixes as _iter_annexb_nal_prefixes


from pyezvizapi.cli.commands_local_stream import _add_hcnetsdk_annexb_dump_summary as _add_hcnetsdk_annexb_dump_summary


from pyezvizapi.cli.commands_local_stream import _scan_hcnetsdk_command_port_media_frames as _scan_hcnetsdk_command_port_media_frames


from pyezvizapi.cli.commands_local_stream import _handle_hcnetsdk_command_plan_generate as _handle_hcnetsdk_command_plan_generate


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_generated_plan_to_json as _hcnetsdk_generated_plan_to_json


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_generated_plan_step_to_json as _hcnetsdk_generated_plan_step_to_json


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_command_template_to_json as _hcnetsdk_command_template_to_json


from pyezvizapi.cli.commands_local_stream import _decode_annexb_windows as _decode_annexb_windows


from pyezvizapi.cli.commands_local_stream import _decode_h264_annexb_idr_windows as _decode_h264_annexb_idr_windows


from pyezvizapi.cli.commands_local_stream import _write_local_sdk_metadata_output as _write_local_sdk_metadata_output


from pyezvizapi.cli.commands_local_stream import _write_hcnetsdk_sampled_packet_output as _write_hcnetsdk_sampled_packet_output


from pyezvizapi.cli.commands_local_stream import _local_sdk_stream_metadata as _local_sdk_stream_metadata


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_command_port_exchange_metadata as _hcnetsdk_command_port_exchange_metadata


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_command_port_body_word_samples as _hcnetsdk_command_port_body_word_samples


from pyezvizapi.cli.commands_local_stream import _hcnetsdk_command_port_body_tail_word_samples as _hcnetsdk_command_port_body_tail_word_samples


from pyezvizapi.cli.commands_local_stream import _handle_stream as _handle_stream


from pyezvizapi.cli.commands_stream import _handle_camera as _handle_camera


def _load_token_file(path: str | None) -> dict[str, Any] | None:
    """Load a token dictionary from `path` if it exists; else return None."""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return cast(dict[str, Any], json.loads(p.read_text(encoding="utf-8")))
    except (
        OSError,
        json.JSONDecodeError,
    ):  # pragma: no cover - tolerate malformed file
        _LOGGER.warning("Failed to read token file: %s", p)
        return None


def _save_token_file(path: str | None, token: dict[str, Any]) -> None:
    """Persist the token dictionary to `path` in JSON format."""
    if not path:
        return
    try:
        save_private_token(path, token)
    except OSError as err:
        raise PyEzvizError(f"Failed to save token file: {path}") from err


def _save_clip_can_run_without_cloud_credentials(args: argparse.Namespace) -> bool:
    return (
        args.action == "save"
        and getattr(args, "save_action", None) == "clip"
        and getattr(args, "source", None) == "hcnetsdk-command-port"
        and (not args.decrypt_video or _local_sdk_has_static_media_key(args))
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _setup_logging(args.debug)
    if args.action == "save" and args.save_action == "clip":
        try:
            _validate_shared_clip_args(args)
        except PyEzvizError as error:
            _LOGGER.error("%s", error)
            return 1

    if args.action == "mqtt" and not args.token_file:
        args.token_file = "ezviz_token.json"
    token = _load_token_file(args.token_file)
    has_session_token = bool(token and token.get("session_id"))
    if args.action == "cloud_video_decrypt" and args.key and not args.serial and not token:
        try:
            return _handle_cloud_video_decrypt(args, None)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if (
        args.action == "stream"
        and args.stream_action == "local-sdk-dump"
        and not args.fetch_cas
        and (not args.decrypt_video or _local_sdk_has_static_media_key(args))
    ):
        try:
            return _handle_local_sdk_stream_dump(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "h264-annexb-summary":
        try:
            return _handle_h264_annexb_summary(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "hcnetsdk-command-dump-summary":
        try:
            return _handle_hcnetsdk_command_dump_summary(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
    if args.action == "stream" and args.stream_action == "hcnetsdk-command-plan-generate":
        try:
            return _handle_hcnetsdk_command_plan_generate(args)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1

    client: EzvizClient | None = None
    if _save_clip_can_run_without_cloud_credentials(args):
        try:
            client = EzvizClient(args.username, args.password, args.region, token=token)
            return _handle_save(args, client)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
            return 1
        finally:
            if client is not None:
                client.close_session()

    if not has_session_token and (not args.username or not args.password):
        _LOGGER.error("Provide --token-file (existing) or --username/--password")
        return 2

    persist = (
        args.save_token
        or args.action == "mqtt"
        or bool(token and token.get("push_profile") == PUSH_PROFILE)
    )

    def save(snapshot: dict[str, Any]) -> None:
        _save_token_file(args.token_file, snapshot)

    try:
        client = EzvizClient(
            args.username,
            args.password,
            args.region,
            token=token,
            on_token_updated=save if persist else None,
        )
        if args.action == "mqtt":
            return _handle_mqtt(args, client)
        _login(
            client,
            token,
            require_service_urls=_action_requires_service_urls(args),
        )
        if args.save_token:
            save(client.export_token())

        if args.action == "devices":
            return _handle_devices(args, client)
        if args.action == "devices_light":
            return _handle_devices_light(args, client)
        if args.action == "light":
            return _handle_light(args, client)
        if args.action == "home_defence_mode":
            return _handle_home_defence_mode(args, client)
        if args.action == "stream":
            return _handle_stream(args, client)
        if args.action == "save":
            return _handle_save(args, client)
        if args.action == "camera":
            return _handle_camera(args, client)
        if args.action == "pagelist":
            return _handle_pagelist(client)
        if args.action == "device_infos":
            return _handle_device_infos(args, client)
        if args.action == "unifiedmsg":
            return _handle_unifiedmsg(args, client)
        if args.action == "sdcard_videos":
            return _handle_sdcard_videos(args, client)
        if args.action == "cloud_videos":
            return _handle_cloud_videos(args, client)
        if args.action == "cloud_video_download":
            return _handle_cloud_video_download(args, client)
        if args.action == "cloud_video_decrypt":
            return _handle_cloud_video_decrypt(args, client)

    except PyEzvizError as exp:
        _LOGGER.error("%s", exp)
        return 1
    except KeyboardInterrupt:
        _LOGGER.error("Interrupted")
        return 130
    else:
        _LOGGER.error("Action not implemented: %s", args.action)
        return 2
    finally:
        if client is not None:
            client.close_session()


# Match the earlier implicit wildcard surface while retaining named private hooks.
__all__ = [name for name in globals() if not name.startswith("_")]


if __name__ == "__main__":
    sys.exit(main())
