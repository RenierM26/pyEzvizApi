"""pyezvizapi command line.

Small utility CLI for testing and scripting Ezviz operations.
"""

from __future__ import annotations

import sys as _sys

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
from pyezvizapi.cli.commands.lan import handle_lan
from pyezvizapi.cli.commands.recording_batch import handle_recordings
from pyezvizapi.cloud.token_store import save_private_token
from pyezvizapi.devices.camera import EzvizCamera
from pyezvizapi.cloud.cas import CasDeviceSession, EzvizCAS
from pyezvizapi.client import EzvizClient
from pyezvizapi.streaming.cloud.bootstrap import (
    _closing_unconnected_cloud_stream,
    cloud_rtp_packets_have_audio,
    copy_cloud_stream_packets_to_mpegts,
    copy_decrypted_cloud_stream_packets_to_mpegts,
    open_cloud_stream,
)
from pyezvizapi.constants import (
    MAX_RETRIES,
    PROFILE as PUSH_PROFILE,
    BatteryCameraWorkMode,
    DefenseModeType,
    DeviceSwitchType,
)
from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizNoMediaError, PyEzvizError
from pyezvizapi.streaming.local.hcnetsdk.api import (
    HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
    EzvizCasDeviceInfo,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfo,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoEx,
    EzvizLocalReceiverInfoExAttrs,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    classify_ezviz_local_sdk_body,
    parse_hcnetsdk_tcp_frame,
)
from pyezvizapi.devices.light_bulb import EzvizLightBulb
from pyezvizapi.streaming.local.ecdh import (
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    copy_local_sdk_ecdh_stream_to_media,
    open_local_sdk_ecdh_stream,
)
from pyezvizapi.streaming.local.media import (
    _idmx_local_packets_to_annexb_with_codec,
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    summarize_h264_annexb_idr_windows,
    summarize_h264_annexb_units,
    summarize_hevc_annexb_irap_windows,
    summarize_idmx_h264_local_packets,
)
from pyezvizapi.streaming.local.transport import (
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortGeneratedSocketStep,
    HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep,
    get_local_sdk_stream_credentials_from_client,
    hcnetsdk_command_port_generated_plan_from_socket_plan,
    hcnetsdk_command_port_native_lan_live_view_plan,
    open_local_sdk_stream,
)
from pyezvizapi.streaming.media.models import has_positive_finite_capture_bound
from pyezvizapi.streaming.media.remux import (
    copy_remuxed_output,
    open_mpegts_remux_process,
    remux_bytes,
)
from pyezvizapi.streaming.media.rtp import (
    detect_rtp_video_codec,
    parse_rtp_packet,
    rtp_nal_units_have_vcl,
    rtp_packets_to_nal_units,
    rtp_payload_video_codec,
)
from pyezvizapi.streaming.media.containers import (
    decrypt_hikvision_ps_video,
    detect_hikvision_ps_video_nalu_header_size,
    detect_transport,
    mpeg_ps_decryptable_prefix_length,
)
from pyezvizapi.streaming.cloud.transport import (
    StreamTransport,
    VtmStreamClient,
    download_ezviz_cloud_replay,
)

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


HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = (
    _cli_arguments.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW
)

# Historical CLI parsing hooks retain their original implementation objects.
_parse_args = _cli_arguments._parse_args
_parse_duration_seconds = _cli_arguments._parse_duration_seconds


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
        client._token["service_urls"] = service_urls
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


from pyezvizapi.cli.commands import devices as _impl_devices


def _handle_devices_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `devices_light` subcommands (status)."""
    return _impl_devices._handle_devices_light(args, client, _owner=_sys.modules[__name__])


def _handle_pagelist(client: EzvizClient) -> int:
    """Output full pagelist (raw JSON) for exploration in editors like Notepad++."""
    return _impl_devices._handle_pagelist(client, _owner=_sys.modules[__name__])


def _handle_device_infos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Output device infos mapping (raw JSON), optionally filtered by serial."""
    return _impl_devices._handle_device_infos(args, client, _owner=_sys.modules[__name__])


def _handle_unifiedmsg(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch unified message list and optionally dump media URLs."""
    return _impl_devices._handle_unifiedmsg(args, client, _owner=_sys.modules[__name__])


from pyezvizapi.cli.commands import recordings as _impl_recordings


def _decode_compressed_record_list(value: str) -> list[Any]:
    """Decode the app's base64+zlib JSON record-list payload when present."""
    return _impl_recordings._decode_compressed_record_list(value, _owner=_sys.modules[__name__])


def _first_record_list(payload: Any) -> list[Any]:
    """Return the first plausible list of record dictionaries from an API response."""
    return _impl_recordings._first_record_list(payload, _owner=_sys.modules[__name__])


def _handle_sdcard_videos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch SD-card playback record descriptors."""
    return _impl_recordings._handle_sdcard_videos(args, client, _owner=_sys.modules[__name__])


def _handle_cloud_videos(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch cloud video descriptors and optionally hydrate details."""
    return _impl_recordings._handle_cloud_videos(args, client, _owner=_sys.modules[__name__])


def _handle_cloud_video_download(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch cloud video details, then download the selected media bytes."""
    return _impl_recordings._handle_cloud_video_download(
        args, client, _owner=_sys.modules[__name__]
    )


def _select_cloud_video_for_seq_id(
    client: EzvizClient,
    *,
    serial: str,
    channel: int,
    seq_id: str,
    limit: int,
    video_type: int,
    support_multi_channel_shared_service: int,
) -> dict[str, Any]:
    """Return a hydrated cloud video descriptor for a selected seqId."""
    return _impl_recordings._select_cloud_video_for_seq_id(
        client,
        serial=serial,
        channel=channel,
        seq_id=seq_id,
        limit=limit,
        video_type=video_type,
        support_multi_channel_shared_service=support_multi_channel_shared_service,
        _owner=_sys.modules[__name__],
    )


def _extract_ticket(ticket_response: dict[str, Any]) -> str:
    """Extract the ticket string from known EZVIZ ticketInfo response shapes."""
    return _impl_recordings._extract_ticket(ticket_response, _owner=_sys.modules[__name__])


def _cloud_video_start_millis(video: dict[str, Any]) -> int:
    """Return cloud clip start time in epoch milliseconds."""
    return _impl_recordings._cloud_video_start_millis(video, _owner=_sys.modules[__name__])


def _cas_time_from_millis(value: int) -> str:
    """Format epoch milliseconds as the CAS timestamp string used by the app."""
    return _impl_recordings._cas_time_from_millis(value, _owner=_sys.modules[__name__])


def _handle_cloud_video_decrypt(args: argparse.Namespace, client: EzvizClient | None) -> int:
    """Decrypt a cloud download .tmp file using the Python PS/NAL transform."""
    return _impl_recordings._handle_cloud_video_decrypt(args, client, _owner=_sys.modules[__name__])


from pyezvizapi.cli.commands import capture as _impl_capture


def _write_save_result(args: argparse.Namespace, result: Mapping[str, Any]) -> None:
    """Write a human or JSON result for save commands."""
    return _impl_capture._write_save_result(args, result, _owner=_sys.modules[__name__])


def _validate_shared_clip_args(args: argparse.Namespace) -> None:
    """Reject unsupported clock assertions before account or camera access."""
    return _impl_capture._validate_shared_clip_args(args, _owner=_sys.modules[__name__])


def _handle_save_clip(args: argparse.Namespace, client: EzvizClient) -> int:
    """Save a short direct-local camera clip to disk."""
    return _impl_capture._handle_save_clip(args, client, _owner=_sys.modules[__name__])


def _hcnetsdk_command_plan_from_args(
    args: argparse.Namespace,
) -> HcNetSdkCommandPortMultiSocketPlan | None:
    """Load a native-style multi-socket command plan from CLI args."""
    return _impl_capture._hcnetsdk_command_plan_from_args(args, _owner=_sys.modules[__name__])


def _hcnetsdk_command_generated_plan_from_args(
    args: argparse.Namespace,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan | None:
    """Load a generated multi-socket command plan from CLI args."""
    return _impl_capture._hcnetsdk_command_generated_plan_from_args(
        args, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_from_json(value: Any) -> HcNetSdkCommandPortMultiSocketPlan:
    """Build a command-port socket plan from simple JSON shapes."""
    return _impl_capture._hcnetsdk_command_plan_from_json(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_generated_plan_from_json(
    value: Any,
) -> HcNetSdkCommandPortGeneratedMultiSocketPlan:
    """Build a generated command-port socket plan from JSON."""
    return _impl_capture._hcnetsdk_command_generated_plan_from_json(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_raw_steps(value: Any) -> list[Any]:
    """Return raw socket step objects from concrete or generated JSON."""
    return _impl_capture._hcnetsdk_command_plan_raw_steps(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_plan_step_from_json(value: Any) -> HcNetSdkCommandPortSocketStep:
    """Build one socket step from a JSON object."""
    return _impl_capture._hcnetsdk_command_plan_step_from_json(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_generated_plan_step_from_json(
    value: Any,
) -> HcNetSdkCommandPortGeneratedSocketStep:
    """Build one generated socket step from a JSON object."""
    return _impl_capture._hcnetsdk_command_generated_plan_step_from_json(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_templates_from_json(
    value: Mapping[str, Any], keys: tuple[str, ...], *, required: bool = True
) -> tuple[HcNetSdkCommandPortControlTemplate, ...]:
    """Read generated control templates from one command-plan JSON step."""
    return _impl_capture._hcnetsdk_command_plan_templates_from_json(
        value, keys, required=required, _owner=_sys.modules[__name__]
    )


def _iter_hcnetsdk_command_template_values(value: Any) -> Iterator[Any]:
    """Yield generated command template objects from JSON."""
    return _impl_capture._iter_hcnetsdk_command_template_values(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_template_from_json(value: Any) -> HcNetSdkCommandPortControlTemplate:
    """Build one generated control template from a JSON object."""
    return _impl_capture._hcnetsdk_command_plan_template_from_json(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_int_required(value: Mapping[str, Any], keys: tuple[str, ...], message: str) -> int:
    """Read a required integer field from a JSON object."""
    return _impl_capture._hcnetsdk_int_required(value, keys, message, _owner=_sys.modules[__name__])


def _hcnetsdk_optional_int(value: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    """Read an optional integer field from a JSON object."""
    return _impl_capture._hcnetsdk_optional_int(value, keys, _owner=_sys.modules[__name__])


def _hcnetsdk_bytes_from_json(
    value: Mapping[str, Any], keys: tuple[str, ...], *, default: bytes = b""
) -> bytes:
    """Read an optional hex byte field from a JSON object."""
    return _impl_capture._hcnetsdk_bytes_from_json(
        value, keys, default=default, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_frames_from_json(
    value: Mapping[str, Any], keys: tuple[str, ...], *, required: bool = True
) -> tuple[bytes, ...]:
    """Read a frame list from one command-plan JSON step."""
    return _impl_capture._hcnetsdk_command_plan_frames_from_json(
        value, keys, required=required, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_read_policy(
    value: Mapping[str, Any], *, default: bool = True
) -> bool | tuple[bool, ...]:
    """Read the response policy for one command-plan step."""
    return _impl_capture._hcnetsdk_command_plan_read_policy(
        value, default=default, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_response_reads(value: Mapping[str, Any]) -> int | tuple[int, ...] | None:
    """Read optional response-frame counts for one command-plan step."""
    return _impl_capture._hcnetsdk_command_plan_response_reads(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_plan_media_socket(value: Mapping[str, Any]) -> bool:
    """Return whether a command-plan step is the media socket."""
    return _impl_capture._hcnetsdk_command_plan_media_socket(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_plan_immediate_media_read(value: Mapping[str, Any]) -> bool:
    """Return whether a media step should read first media before later steps."""
    return _impl_capture._hcnetsdk_command_plan_immediate_media_read(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_delay_after_commands(value: Mapping[str, Any]) -> float:
    """Return optional pacing delay after one command-plan step."""
    return _impl_capture._hcnetsdk_command_plan_delay_after_commands(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_plan_drain_media_before_next(value: Mapping[str, Any]) -> float:
    """Return optional media-drain duration before later command-plan steps."""
    return _impl_capture._hcnetsdk_command_plan_drain_media_before_next(
        value, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_bool(value: Any) -> bool:
    """Parse permissive boolean values from CLI JSON."""
    return _impl_capture._hcnetsdk_bool(value, _owner=_sys.modules[__name__])


def _hcnetsdk_int(value: Any) -> int:
    """Parse non-negative integer values from CLI JSON."""
    return _impl_capture._hcnetsdk_int(value, _owner=_sys.modules[__name__])


def _hcnetsdk_command_frames_from_args(args: argparse.Namespace) -> tuple[bytes, ...]:
    """Load complete command-port frames from CLI hex values or a file."""
    return _impl_capture._hcnetsdk_command_frames_from_args(args, _owner=_sys.modules[__name__])


def _hcnetsdk_command_frame_hex_values_from_file(path: str) -> list[str]:
    """Read command-frame hex values from JSON or text."""
    return _impl_capture._hcnetsdk_command_frame_hex_values_from_file(
        path, _owner=_sys.modules[__name__]
    )


def _iter_hcnetsdk_command_frame_hex_values(value: Any) -> Iterator[str]:
    """Yield command-frame hex strings from simple JSON shapes."""
    return _impl_capture._iter_hcnetsdk_command_frame_hex_values(
        value, _owner=_sys.modules[__name__]
    )


def _bytes_from_hex_value(value: str) -> bytes:
    """Decode a user-supplied hex byte string."""
    return _impl_capture._bytes_from_hex_value(value, _owner=_sys.modules[__name__])


def _hcnetsdk_read_response_policy(
    args: argparse.Namespace, frame_count: int
) -> bool | tuple[bool, ...]:
    """Return response-read policy for command-port bootstrapping."""
    return _impl_capture._hcnetsdk_read_response_policy(
        args, frame_count, _owner=_sys.modules[__name__]
    )


def _handle_save_image(args: argparse.Namespace, client: EzvizClient) -> int:
    """Save a camera image to disk, triggering capture when no URL is supplied."""
    return _impl_capture._handle_save_image(args, client, _owner=_sys.modules[__name__])


def _handle_save(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle person-friendly local save commands."""
    return _impl_capture._handle_save(args, client, _owner=_sys.modules[__name__])


def _handle_light(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `light` subcommands (toggle/status)."""
    return _impl_devices._handle_light(args, client, _owner=_sys.modules[__name__])


def _handle_home_defence_mode(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `home_defence_mode` subcommands (set mode)."""
    return _impl_devices._handle_home_defence_mode(args, client, _owner=_sys.modules[__name__])


from pyezvizapi.cli.commands import push as _impl_push


def _handle_mqtt(args: argparse.Namespace, client: EzvizClient) -> int:
    """Migrate the login and listen with durable channel-99 token storage."""
    return _impl_push._handle_mqtt(args, client, _owner=_sys.modules[__name__])


from pyezvizapi.cli.commands import cloud_stream as _impl_cloud_stream


def _write_stream_payloads(
    stream: Any,
    output: BinaryIO,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    first_packet_deadline: float | None = None,
    allow_encrypted: bool,
    transform_payload: Callable[[bytes], bytes] | None = None,
    flush_each: bool = False,
    monotonic: Any = time.monotonic,
) -> None:
    """Write VTM stream packet bodies to a binary file-like object."""
    return _impl_cloud_stream._write_stream_payloads(
        stream,
        output,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        first_packet_deadline=first_packet_deadline,
        allow_encrypted=allow_encrypted,
        transform_payload=transform_payload,
        flush_each=flush_each,
        monotonic=monotonic,
        _owner=_sys.modules[__name__],
    )


def _start_cli_cloud_stream(
    stream: Any,
    *,
    timeout: float | None,
    duration_seconds: float | None,
    monotonic: Callable[[], float] = time.monotonic,
) -> float | None:
    """Start a CLI VTM stream with one bounded negotiation deadline."""
    return _impl_cloud_stream._start_cli_cloud_stream(
        stream,
        timeout=timeout,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
        _owner=_sys.modules[__name__],
    )


def _collect_stream_payloads(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    monotonic: Any = time.monotonic,
) -> bytes:
    """Collect VTM stream packet bodies into memory."""
    return _impl_cloud_stream._collect_stream_payloads(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        allow_encrypted=allow_encrypted,
        monotonic=monotonic,
        _owner=_sys.modules[__name__],
    )


def _collect_stream_packets(
    stream: Any,
    *,
    max_packets: int | None,
    duration_seconds: float | None = None,
    first_packet_deadline: float | None = None,
    allow_encrypted: bool,
    monotonic: Any = time.monotonic,
) -> list[Any]:
    """Collect VTM stream packets while preserving packet boundaries."""
    return _impl_cloud_stream._collect_stream_packets(
        stream,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        first_packet_deadline=first_packet_deadline,
        allow_encrypted=allow_encrypted,
        monotonic=monotonic,
        _owner=_sys.modules[__name__],
    )


def _detect_stream_packets_transport(packets: list[Any]) -> StreamTransport:
    """Return the first known media transport from collected VTM packets."""
    return _impl_cloud_stream._detect_stream_packets_transport(
        packets, _owner=_sys.modules[__name__]
    )


def _rtp_payload_video_codec(payload: bytes) -> str | None:
    """Compatibility wrapper for the shared RTP codec detector."""
    return _impl_cloud_stream._rtp_payload_video_codec(payload, _owner=_sys.modules[__name__])


def _detect_rtp_video_codec(
    packets: list[Any], *, media_key: str | bytes | None = None, decrypt_codec: str = "auto"
) -> str:
    """Detect RTP video codec through the shared parser and router."""
    return _impl_cloud_stream._detect_rtp_video_codec(
        packets, media_key=media_key, decrypt_codec=decrypt_codec, _owner=_sys.modules[__name__]
    )


def _parse_rtp_packets(packets: list[Any]) -> list[Any]:
    """Parse valid RTP bodies while ignoring interleaved control data."""
    return _impl_cloud_stream._parse_rtp_packets(packets, _owner=_sys.modules[__name__])


def _rtp_packets_to_annexb(packets: list[Any], *, codec: str) -> bytes:
    """Convert RTP video through the shared continuity state machine."""
    return _impl_cloud_stream._rtp_packets_to_annexb(
        packets, codec=codec, _owner=_sys.modules[__name__]
    )


def _rtp_packets_to_annexb_units(
    packets: list[Any],
    *,
    codec: str,
    first_slice_key: str | bytes | None = None,
    decrypt_codec: str = "auto",
) -> tuple[bytes, ...]:
    """Return complete Annex-B units from the shared RTP continuity state machine."""
    return _impl_cloud_stream._rtp_packets_to_annexb_units(
        packets,
        codec=codec,
        first_slice_key=first_slice_key,
        decrypt_codec=decrypt_codec,
        _owner=_sys.modules[__name__],
    )


def _decrypt_annexb_video_bytes(
    client: EzvizClient, serial: str, data: bytes, *, codec: str
) -> bytes:
    """Decrypt Annex B video NAL payload bytes using the MPEG-PS transform."""
    return _impl_cloud_stream._decrypt_annexb_video_bytes(
        client, serial, data, codec=codec, _owner=_sys.modules[__name__]
    )


def _decrypt_rtp_annexb_units(
    client: EzvizClient,
    serial: str,
    units: tuple[bytes, ...],
    *,
    detected_codec: str,
    decrypt_codec: str,
    media_key: str | bytes | None = None,
) -> bytes:
    """Decrypt RTP Annex-B units with one camera-key lookup."""
    return _impl_cloud_stream._decrypt_rtp_annexb_units(
        client,
        serial,
        units,
        detected_codec=detected_codec,
        decrypt_codec=decrypt_codec,
        media_key=media_key,
        _owner=_sys.modules[__name__],
    )


def _remux_elementary_video_bytes_to_mpegts(
    data: bytes, output: BinaryIO, *, ffmpeg_path: str, codec: str
) -> None:
    """Remux Annex B HEVC/H.264 elementary stream bytes to MPEG-TS."""
    return _impl_cloud_stream._remux_elementary_video_bytes_to_mpegts(
        data, output, ffmpeg_path=ffmpeg_path, codec=codec, _owner=_sys.modules[__name__]
    )


def _decrypt_stream_payload_bytes(
    client: EzvizClient,
    serial: str,
    data: bytes,
    *,
    codec: str,
    media_key: str | bytes | None = None,
) -> bytes:
    """Decrypt captured MPEG-PS stream bytes using the camera encrypt key."""
    return _impl_cloud_stream._decrypt_stream_payload_bytes(
        client, serial, data, codec=codec, media_key=media_key, _owner=_sys.modules[__name__]
    )


def _codec_nalu_header_size(codec: str) -> int | None:
    """Return the Annex B NAL header length preserved by the decrypt transform."""
    return _impl_cloud_stream._codec_nalu_header_size(codec, _owner=_sys.modules[__name__])


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
            if self._nalu_header_size is None and len(self._buffer) > self._MAX_AUTO_PROBE_BYTES:
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


def _stream_payload_decryptor(
    client: EzvizClient, serial: str, *, codec: str
) -> Callable[[bytes], bytes]:
    """Return a buffered MPEG-PS decryptor using the camera encrypt key."""
    return _impl_cloud_stream._stream_payload_decryptor(
        client, serial, codec=codec, _owner=_sys.modules[__name__]
    )


def _stream_payload_decryptors(
    client: EzvizClient, serial: str, *, codec: str, media_key: str | bytes | None = None
) -> tuple[Callable[[bytes], bytes], Callable[[bytes, str], bytes]]:
    """Return MPEG-PS and RTP decryptors sharing one camera-key lookup."""
    return _impl_cloud_stream._stream_payload_decryptors(
        client, serial, codec=codec, media_key=media_key, _owner=_sys.modules[__name__]
    )


def _stream_payload_decryptors_with_key(
    client: EzvizClient, serial: str, *, codec: str, media_key: str | bytes | None = None
) -> tuple[Callable[[bytes], bytes], Callable[[bytes, str], bytes], str | bytes]:
    """Return streaming decryptors and their single fetched camera key."""
    return _impl_cloud_stream._stream_payload_decryptors_with_key(
        client, serial, codec=codec, media_key=media_key, _owner=_sys.modules[__name__]
    )


def _cloud_cli_media_key(args: argparse.Namespace, client: EzvizClient) -> str | bytes:
    """Resolve an explicit or cloud camera key without exposing it."""
    return _impl_cloud_stream._cloud_cli_media_key(args, client, _owner=_sys.modules[__name__])


def _explicit_cloud_cli_media_key(args: argparse.Namespace) -> str | bytes | None:
    """Resolve only a supplied key; proxy cloud lookup happens per request."""
    return _impl_cloud_stream._explicit_cloud_cli_media_key(args, _owner=_sys.modules[__name__])


def _remux_mpegps_bytes_to_mpegts(data: bytes, output: BinaryIO, *, ffmpeg_path: str) -> None:
    """Remux in-memory MPEG-PS bytes to MPEG-TS."""
    return _impl_cloud_stream._remux_mpegps_bytes_to_mpegts(
        data, output, ffmpeg_path=ffmpeg_path, _owner=_sys.modules[__name__]
    )


def _remux_stream_payloads_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    ffmpeg_path: str,
    max_packets: int | None,
    duration_seconds: float | None = None,
    first_packet_deadline: float | None = None,
    allow_encrypted: bool,
) -> None:
    """Route VTM media to MPEG-TS with optional encrypted-packet passthrough."""
    return _impl_cloud_stream._remux_stream_payloads_to_mpegts(
        stream,
        output,
        ffmpeg_path=ffmpeg_path,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        first_packet_deadline=first_packet_deadline,
        allow_encrypted=allow_encrypted,
        _owner=_sys.modules[__name__],
    )


def _open_mpegts_remux_process(
    ffmpeg_path: str, *, input_format: str = "mpeg"
) -> subprocess.Popen[bytes]:
    """Open an FFmpeg process ready to remux MPEG-PS stdin to MPEG-TS stdout."""
    return _impl_cloud_stream._open_mpegts_remux_process(
        ffmpeg_path, input_format=input_format, _owner=_sys.modules[__name__]
    )


def _copy_stream_payloads_to_mpegts(
    stream: Any,
    output: BinaryIO,
    *,
    process: subprocess.Popen[bytes],
    max_packets: int | None,
    duration_seconds: float | None = None,
    allow_encrypted: bool,
    transform_payload: Callable[[bytes], bytes] | None = None,
) -> None:
    """Copy stream payloads through an already-started FFmpeg remuxer."""
    return _impl_cloud_stream._copy_stream_payloads_to_mpegts(
        stream,
        output,
        process=process,
        max_packets=max_packets,
        duration_seconds=duration_seconds,
        allow_encrypted=allow_encrypted,
        transform_payload=transform_payload,
        _owner=_sys.modules[__name__],
    )


def _default_stream_proxy_path(serial: str) -> str:
    """Return the default HTTP path for a camera stream."""
    return _impl_cloud_stream._default_stream_proxy_path(serial, _owner=_sys.modules[__name__])


def _normalize_stream_proxy_path(path: str | None, serial: str) -> str:
    """Normalize a user-supplied proxy path."""
    return _impl_cloud_stream._normalize_stream_proxy_path(
        path, serial, _owner=_sys.modules[__name__]
    )


def _handle_stream_proxy_get(
    handler: BaseHTTPRequestHandler, config: StreamProxyConfig, client: EzvizClient
) -> None:
    """Handle one experimental VTM-to-MPEG-TS HTTP proxy request."""
    return _impl_cloud_stream._handle_stream_proxy_get(
        handler, config, client, _owner=_sys.modules[__name__]
    )


def _serve_stream_proxy(args: argparse.Namespace, client: EzvizClient) -> None:
    """Serve the experimental VTM-to-MPEG-TS HTTP proxy until interrupted."""
    return _impl_cloud_stream._serve_stream_proxy(args, client, _owner=_sys.modules[__name__])


from pyezvizapi.cli.commands import local_stream as _impl_local_stream


def _env_or_arg(args: argparse.Namespace, attr: str, env_name: str) -> str | None:
    """Return a CLI argument value or matching environment fallback."""
    return _impl_local_stream._env_or_arg(args, attr, env_name, _owner=_sys.modules[__name__])


def os_environ_get(name: str) -> str | None:
    """Small wrapper to make environment fallback easy to patch in tests."""
    return _impl_local_stream.os_environ_get(name, _owner=_sys.modules[__name__])


def _required_local_sdk_secret(args: argparse.Namespace, attr: str, env_name: str) -> str:
    """Read a required local-SDK secret without logging or persisting it."""
    return _impl_local_stream._required_local_sdk_secret(
        args, attr, env_name, _owner=_sys.modules[__name__]
    )


def _local_sdk_credentials_file(args: argparse.Namespace) -> dict[str, Any]:
    """Read a local-SDK credential bundle without logging secret values."""
    return _impl_local_stream._local_sdk_credentials_file(args, _owner=_sys.modules[__name__])


def _local_sdk_credentials_value(args: argparse.Namespace, path: tuple[str, ...]) -> Any:
    """Return a value from the optional local-SDK credential bundle."""
    return _impl_local_stream._local_sdk_credentials_value(
        args, path, _owner=_sys.modules[__name__]
    )


def _local_sdk_arg_or_credentials(
    args: argparse.Namespace, attr: str, path: tuple[str, ...]
) -> Any:
    """Return an explicit CLI value or matching credential-bundle value."""
    return _impl_local_stream._local_sdk_arg_or_credentials(
        args, attr, path, _owner=_sys.modules[__name__]
    )


def _required_local_sdk_arg_or_credentials(
    args: argparse.Namespace, attr: str, path: tuple[str, ...]
) -> Any:
    """Return a required direct-local field from args or credentials file."""
    return _impl_local_stream._required_local_sdk_arg_or_credentials(
        args, attr, path, _owner=_sys.modules[__name__]
    )


def _local_sdk_media_key(args: argparse.Namespace, client: EzvizClient | None) -> str | bytes:
    """Read the direct-local media decrypt key without logging or persisting it."""
    return _impl_local_stream._local_sdk_media_key(args, client, _owner=_sys.modules[__name__])


def _local_sdk_has_static_media_key(args: argparse.Namespace) -> bool:
    """Return True when local-sdk-dump can decrypt without cloud key lookup."""
    return _impl_local_stream._local_sdk_has_static_media_key(args, _owner=_sys.modules[__name__])


def _read_optional_binary_file(path: str | None) -> bytes | None:
    """Read an optional caller-owned binary body from disk."""
    return _impl_local_stream._read_optional_binary_file(path, _owner=_sys.modules[__name__])


def _local_sdk_cas_device_info(
    args: argparse.Namespace, client: EzvizClient | None
) -> EzvizCasDeviceInfo:
    """Build local CAS device info from explicit fields or cloud CAS."""
    return _impl_local_stream._local_sdk_cas_device_info(
        args, client, _owner=_sys.modules[__name__]
    )


def _build_local_sdk_cli_stream(args: argparse.Namespace, client: EzvizClient | None = None) -> Any:
    """Build the direct-local SDK stream from explicit CLI/environment fields."""
    return _impl_local_stream._build_local_sdk_cli_stream(
        args, client, _owner=_sys.modules[__name__]
    )


def _build_local_sdk_ecdh_cli_stream(
    args: argparse.Namespace, client: EzvizClient | None = None
) -> Any:
    """Build an encrypted local SDK ECDH stream."""
    return _impl_local_stream._build_local_sdk_ecdh_cli_stream(
        args, client, _owner=_sys.modules[__name__]
    )


def _local_sdk_receiver_info_from_args(
    args: argparse.Namespace,
) -> EzvizLocalReceiverInfo | EzvizLocalReceiverInfoAttrs:
    """Build the requested ReceiverInfo XML shape for local-SDK preview."""
    return _impl_local_stream._local_sdk_receiver_info_from_args(
        args, _owner=_sys.modules[__name__]
    )


def _local_sdk_receiver_info_ex_from_args(
    args: argparse.Namespace,
) -> EzvizLocalReceiverInfoEx | EzvizLocalReceiverInfoExAttrs:
    """Build the requested ReceiverInfoEx XML shape for local-SDK preview."""
    return _impl_local_stream._local_sdk_receiver_info_ex_from_args(
        args, _owner=_sys.modules[__name__]
    )


def _local_sdk_authentication_from_args(
    args: argparse.Namespace,
) -> EzvizLocalAuthenticationAttrs | None:
    """Return app-shaped Authentication only when that XML shape is requested."""
    return _impl_local_stream._local_sdk_authentication_from_args(
        args, _owner=_sys.modules[__name__]
    )


def _handle_local_sdk_stream_dump(
    args: argparse.Namespace, client: EzvizClient | None = None
) -> int:
    """Dump direct-local SDK media with caller-supplied local fields."""
    return _impl_local_stream._handle_local_sdk_stream_dump(
        args, client, _owner=_sys.modules[__name__]
    )


def _copy_local_sdk_ecdh_cli_stream(
    args: argparse.Namespace, client: EzvizClient | None, stream: Any, output: BinaryIO
) -> None:
    """Copy one CLI-selected ECDH stream to its requested container."""
    return _impl_local_stream._copy_local_sdk_ecdh_cli_stream(
        args, client, stream, output, _owner=_sys.modules[__name__]
    )


def _handle_local_sdk_keys(args: argparse.Namespace, client: EzvizClient) -> int:
    """Fetch and print direct-local SDK credentials for explicit setup flows."""
    return _impl_local_stream._handle_local_sdk_keys(args, client, _owner=_sys.modules[__name__])


def _handle_h264_annexb_summary(args: argparse.Namespace) -> int:
    """Summarize a local H.264 Annex-B elementary stream."""
    return _impl_local_stream._handle_h264_annexb_summary(args, _owner=_sys.modules[__name__])


def _handle_hcnetsdk_command_dump_summary(args: argparse.Namespace) -> int:
    """Summarize offline HCNetSDK command-port dump artifacts."""
    return _impl_local_stream._handle_hcnetsdk_command_dump_summary(
        args, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_frame_dump_summary(directory: Path, *, max_frames: int) -> dict[str, Any]:
    """Return sanitized metadata for dumped outbound command frames."""
    return _impl_local_stream._hcnetsdk_command_frame_dump_summary(
        directory, max_frames=max_frames, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_inbound_media_dump_summary(
    path: Path, *, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str
) -> dict[str, Any]:
    """Return sanitized metadata for raw dumped command-port inbound media bytes."""
    return _impl_local_stream._hcnetsdk_inbound_media_dump_summary(
        path,
        max_frames=max_frames,
        decode_idr_windows=decode_idr_windows,
        ffmpeg_path=ffmpeg_path,
        _owner=_sys.modules[__name__],
    )


def _hcnetsdk_playm4_input_dump_summary(
    directory: Path, *, max_frames: int, decode_idr_windows: bool, ffmpeg_path: str
) -> dict[str, Any]:
    """Return sanitized metadata for PlayM4 input dump chunks."""
    return _impl_local_stream._hcnetsdk_playm4_input_dump_summary(
        directory,
        max_frames=max_frames,
        decode_idr_windows=decode_idr_windows,
        ffmpeg_path=ffmpeg_path,
        _owner=_sys.modules[__name__],
    )


def _hcnetsdk_native_annexb_dump_summary(
    directory: Path,
    *,
    label: str,
    codec: str,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> dict[str, Any]:
    """Return sanitized metadata for native Annex-B Frida dump chunks."""
    return _impl_local_stream._hcnetsdk_native_annexb_dump_summary(
        directory,
        label=label,
        codec=codec,
        max_frames=max_frames,
        decode_idr_windows=decode_idr_windows,
        ffmpeg_path=ffmpeg_path,
        _owner=_sys.modules[__name__],
    )


def _decode_native_annexb_chunk_windows(
    paths: list[Path], *, codec: str, max_windows: int, ffmpeg_path: str
) -> list[dict[str, Any]]:
    """Decode sampled IDR/IRAP-bearing native dump chunks independently."""
    return _impl_local_stream._decode_native_annexb_chunk_windows(
        paths,
        codec=codec,
        max_windows=max_windows,
        ffmpeg_path=ffmpeg_path,
        _owner=_sys.modules[__name__],
    )


def _detect_native_annexb_codec(data: bytes, *, requested: str) -> str:
    """Return the requested or likely codec for Annex-B dump bytes."""
    return _impl_local_stream._detect_native_annexb_codec(
        data, requested=requested, _owner=_sys.modules[__name__]
    )


def _iter_annexb_nal_prefixes(data: bytes) -> Iterator[bytes]:
    """Yield the first bytes after Annex-B start codes."""
    return _impl_local_stream._iter_annexb_nal_prefixes(data, _owner=_sys.modules[__name__])


def _add_hcnetsdk_annexb_dump_summary(
    summary: dict[str, Any],
    packets: list[bytes],
    *,
    max_frames: int,
    decode_idr_windows: bool,
    ffmpeg_path: str,
) -> None:
    """Attach sanitized reconstructed Annex-B metadata to a dump summary."""
    return _impl_local_stream._add_hcnetsdk_annexb_dump_summary(
        summary,
        packets,
        max_frames=max_frames,
        decode_idr_windows=decode_idr_windows,
        ffmpeg_path=ffmpeg_path,
        _owner=_sys.modules[__name__],
    )


def _scan_hcnetsdk_command_port_media_frames(data: bytes, *, max_frames: int) -> dict[str, Any]:
    """Scan raw command-port bytes for little-endian ``$`` media frames."""
    return _impl_local_stream._scan_hcnetsdk_command_port_media_frames(
        data, max_frames=max_frames, _owner=_sys.modules[__name__]
    )


def _handle_hcnetsdk_command_plan_generate(args: argparse.Namespace) -> int:
    """Convert concrete port-8000 control frames into generated templates."""
    return _impl_local_stream._handle_hcnetsdk_command_plan_generate(
        args, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_generated_plan_to_json(
    plan: HcNetSdkCommandPortGeneratedMultiSocketPlan,
) -> dict[str, Any]:
    """Return the public JSON shape for a generated command-port plan."""
    return _impl_local_stream._hcnetsdk_generated_plan_to_json(plan, _owner=_sys.modules[__name__])


def _hcnetsdk_generated_plan_step_to_json(
    step: HcNetSdkCommandPortGeneratedSocketStep,
) -> dict[str, Any]:
    """Return JSON for one generated command-port socket step."""
    return _impl_local_stream._hcnetsdk_generated_plan_step_to_json(
        step, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_template_to_json(
    template: HcNetSdkCommandPortControlTemplate,
) -> dict[str, Any]:
    """Return JSON for one generated command-port control template."""
    return _impl_local_stream._hcnetsdk_command_template_to_json(
        template, _owner=_sys.modules[__name__]
    )


def _decode_annexb_windows(
    data: bytes, window_summary: Mapping[str, Any], *, ffmpeg_path: str, input_format: str
) -> list[dict[str, Any]]:
    """Return bounded ffmpeg decode results for sampled Annex-B windows."""
    return _impl_local_stream._decode_annexb_windows(
        data,
        window_summary,
        ffmpeg_path=ffmpeg_path,
        input_format=input_format,
        _owner=_sys.modules[__name__],
    )


def _decode_h264_annexb_idr_windows(
    data: bytes, idr_summary: Mapping[str, Any], *, ffmpeg_path: str
) -> list[dict[str, Any]]:
    """Return bounded ffmpeg decode results for sampled H.264 IDR windows."""
    return _impl_local_stream._decode_h264_annexb_idr_windows(
        data, idr_summary, ffmpeg_path=ffmpeg_path, _owner=_sys.modules[__name__]
    )


def _write_local_sdk_metadata_output(
    path: str | None, stream: Any, *, packet_output_path: str | None = None
) -> None:
    """Write safe stream metadata and optional bounded packet samples."""
    return _impl_local_stream._write_local_sdk_metadata_output(
        path, stream, packet_output_path=packet_output_path, _owner=_sys.modules[__name__]
    )


def _write_hcnetsdk_sampled_packet_output(path: str, stream: Any) -> None:
    """Write bounded sampled command-port packets as raw dump-compatible frames."""
    return _impl_local_stream._write_hcnetsdk_sampled_packet_output(
        path, stream, _owner=_sys.modules[__name__]
    )


def _local_sdk_stream_metadata(stream: Any) -> dict[str, Any]:
    """Return non-secret direct-local SDK bootstrap and media metadata."""
    return _impl_local_stream._local_sdk_stream_metadata(stream, _owner=_sys.modules[__name__])


def _hcnetsdk_command_port_exchange_metadata(exchange: Any) -> dict[str, Any]:
    """Return non-secret metadata for one command-port request/response."""
    return _impl_local_stream._hcnetsdk_command_port_exchange_metadata(
        exchange, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_port_body_word_samples(
    body: bytes, *, max_samples: int = 16
) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit body words for diagnostics."""
    return _impl_local_stream._hcnetsdk_command_port_body_word_samples(
        body, max_samples=max_samples, _owner=_sys.modules[__name__]
    )


def _hcnetsdk_command_port_body_tail_word_samples(
    tail: bytes, *, max_samples: int = 16
) -> list[dict[str, int]]:
    """Return bounded nonzero 32-bit request-tail words for diagnostics."""
    return _impl_local_stream._hcnetsdk_command_port_body_tail_word_samples(
        tail, max_samples=max_samples, _owner=_sys.modules[__name__]
    )


from pyezvizapi.cli.commands import stream as _impl_stream


def _handle_stream(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle experimental stream helpers."""
    return _impl_stream._handle_stream(args, client, _owner=_sys.modules[__name__])


def _handle_camera(args: argparse.Namespace, client: EzvizClient) -> int:
    """Handle `camera` subcommands (status/move/unlock/switch/alarm/select)."""
    return _impl_devices._handle_camera(args, client, _owner=_sys.modules[__name__])


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
        and getattr(args, "source", None) in {"hcnetsdk-command-port", "local-playback"}
        and (not args.decrypt_video or _local_sdk_has_static_media_key(args))
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _parse_args(argv)
    _setup_logging(args.debug)
    if args.action == "lan":
        return handle_lan(args)
    if args.action == "save" and args.save_action == "clip":
        try:
            _validate_shared_clip_args(args)
        except PyEzvizError as error:
            _LOGGER.error("%s", error)
            return 1

    local_batch = args.action == "recordings" and (
        (args.recordings_action == "download" and args.source == "local-playback")
        or (args.recordings_action == "list" and args.source == "lan-hcnetsdk")
    )
    if local_batch:
        try:
            return handle_recordings(args, None)
        except PyEzvizError as exp:
            _LOGGER.error("%s", exp)
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
        if args.action == "recordings":
            return handle_recordings(args, client)
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
