# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cli.main`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cli import main as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cli.main as _compat_module_0
    _LOGGER = _compat_module_0._LOGGER
    _REAL_EZVIZ_CLIENT = _compat_module_0._REAL_EZVIZ_CLIENT
    HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS = _compat_module_0.HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS
    HCNETSDK_COMMAND_PORT_CONTROL_FAMILY = _compat_module_0.HCNETSDK_COMMAND_PORT_CONTROL_FAMILY
    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = _compat_module_0.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = _compat_module_0.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
    MAX_RETRIES = _compat_module_0.MAX_RETRIES
    PUSH_PROFILE = _compat_module_0.PUSH_PROFILE
    Any = _compat_module_0.Any
    BaseHTTPRequestHandler = _compat_module_0.BaseHTTPRequestHandler
    BatteryCameraWorkMode = _compat_module_0.BatteryCameraWorkMode
    BinaryIO = _compat_module_0.BinaryIO
    BytesIO = _compat_module_0.BytesIO
    Callable = _compat_module_0.Callable
    CasDeviceSession = _compat_module_0.CasDeviceSession
    DefenseModeType = _compat_module_0.DefenseModeType
    DeviceSwitchType = _compat_module_0.DeviceSwitchType
    EzvizAuthVerificationCode = _compat_module_0.EzvizAuthVerificationCode
    EzvizCamera = _compat_module_0.EzvizCamera
    EzvizCAS = _compat_module_0.EzvizCAS
    EzvizCasDeviceInfo = _compat_module_0.EzvizCasDeviceInfo
    EzvizClient = _compat_module_0.EzvizClient
    EzvizLightBulb = _compat_module_0.EzvizLightBulb
    EzvizLocalAuthenticationAttrs = _compat_module_0.EzvizLocalAuthenticationAttrs
    EzvizLocalPreviewRequest = _compat_module_0.EzvizLocalPreviewRequest
    EzvizLocalReceiverInfo = _compat_module_0.EzvizLocalReceiverInfo
    EzvizLocalReceiverInfoAttrs = _compat_module_0.EzvizLocalReceiverInfoAttrs
    EzvizLocalReceiverInfoEx = _compat_module_0.EzvizLocalReceiverInfoEx
    EzvizLocalReceiverInfoExAttrs = _compat_module_0.EzvizLocalReceiverInfoExAttrs
    EzvizNoMediaError = _compat_module_0.EzvizNoMediaError
    HcNetSdkCommandPortControlTemplate = _compat_module_0.HcNetSdkCommandPortControlTemplate
    HcNetSdkCommandPortGeneratedMultiSocketPlan = _compat_module_0.HcNetSdkCommandPortGeneratedMultiSocketPlan
    HcNetSdkCommandPortGeneratedSocketStep = _compat_module_0.HcNetSdkCommandPortGeneratedSocketStep
    HcNetSdkCommandPortMultiSocketPlan = _compat_module_0.HcNetSdkCommandPortMultiSocketPlan
    HcNetSdkCommandPortSocketStep = _compat_module_0.HcNetSdkCommandPortSocketStep
    HcNetSdkLanEndpoint = _compat_module_0.HcNetSdkLanEndpoint
    Iterator = _compat_module_0.Iterator
    Mapping = _compat_module_0.Mapping
    Path = _compat_module_0.Path
    PyEzvizError = _compat_module_0.PyEzvizError
    StreamProxyConfig = _compat_module_0.StreamProxyConfig
    StreamProxyHTTPServer = _compat_module_0.StreamProxyHTTPServer
    StreamTransport = _compat_module_0.StreamTransport
    ThreadingHTTPServer = _compat_module_0.ThreadingHTTPServer
    VtmStreamClient = _compat_module_0.VtmStreamClient
    _action_requires_service_urls = _compat_module_0._action_requires_service_urls
    _add_hcnetsdk_annexb_dump_summary = _compat_module_0._add_hcnetsdk_annexb_dump_summary
    _BufferedStreamPayloadDecryptor = _compat_module_0._BufferedStreamPayloadDecryptor
    _build_local_sdk_cli_stream = _compat_module_0._build_local_sdk_cli_stream
    _build_local_sdk_ecdh_cli_stream = _compat_module_0._build_local_sdk_ecdh_cli_stream
    _bytes_from_hex_value = _compat_module_0._bytes_from_hex_value
    _cas_time_from_millis = _compat_module_0._cas_time_from_millis
    _cli_arguments = _compat_module_0._cli_arguments
    _closing_unconnected_cloud_stream = _compat_module_0._closing_unconnected_cloud_stream
    _cloud_cli_media_key = _compat_module_0._cloud_cli_media_key
    _cloud_video_start_millis = _compat_module_0._cloud_video_start_millis
    _codec_nalu_header_size = _compat_module_0._codec_nalu_header_size
    _collect_stream_packets = _compat_module_0._collect_stream_packets
    _collect_stream_payloads = _compat_module_0._collect_stream_payloads
    _copy_local_sdk_ecdh_cli_stream = _compat_module_0._copy_local_sdk_ecdh_cli_stream
    _copy_stream_payloads_to_mpegts = _compat_module_0._copy_stream_payloads_to_mpegts
    _decode_annexb_windows = _compat_module_0._decode_annexb_windows
    _decode_compressed_record_list = _compat_module_0._decode_compressed_record_list
    _decode_h264_annexb_idr_windows = _compat_module_0._decode_h264_annexb_idr_windows
    _decode_native_annexb_chunk_windows = _compat_module_0._decode_native_annexb_chunk_windows
    _decrypt_annexb_video_bytes = _compat_module_0._decrypt_annexb_video_bytes
    _decrypt_rtp_annexb_units = _compat_module_0._decrypt_rtp_annexb_units
    _decrypt_stream_payload_bytes = _compat_module_0._decrypt_stream_payload_bytes
    _default_stream_proxy_path = _compat_module_0._default_stream_proxy_path
    _detect_native_annexb_codec = _compat_module_0._detect_native_annexb_codec
    _detect_rtp_video_codec = _compat_module_0._detect_rtp_video_codec
    _detect_stream_packets_transport = _compat_module_0._detect_stream_packets_transport
    _ensure_client_service_urls = _compat_module_0._ensure_client_service_urls
    _env_or_arg = _compat_module_0._env_or_arg
    _explicit_cloud_cli_media_key = _compat_module_0._explicit_cloud_cli_media_key
    _extract_ticket = _compat_module_0._extract_ticket
    _first_record_list = _compat_module_0._first_record_list
    _format_cell = _compat_module_0._format_cell
    _handle_camera = _compat_module_0._handle_camera
    _handle_cloud_video_decrypt = _compat_module_0._handle_cloud_video_decrypt
    _handle_cloud_video_download = _compat_module_0._handle_cloud_video_download
    _handle_cloud_videos = _compat_module_0._handle_cloud_videos
    _handle_device_infos = _compat_module_0._handle_device_infos
    _handle_devices = _compat_module_0._handle_devices
    _handle_devices_light = _compat_module_0._handle_devices_light
    _handle_h264_annexb_summary = _compat_module_0._handle_h264_annexb_summary
    _handle_hcnetsdk_command_dump_summary = _compat_module_0._handle_hcnetsdk_command_dump_summary
    _handle_hcnetsdk_command_plan_generate = _compat_module_0._handle_hcnetsdk_command_plan_generate
    _handle_home_defence_mode = _compat_module_0._handle_home_defence_mode
    _handle_light = _compat_module_0._handle_light
    _handle_local_sdk_keys = _compat_module_0._handle_local_sdk_keys
    _handle_local_sdk_stream_dump = _compat_module_0._handle_local_sdk_stream_dump
    _handle_mqtt = _compat_module_0._handle_mqtt
    _handle_pagelist = _compat_module_0._handle_pagelist
    _handle_save = _compat_module_0._handle_save
    _handle_save_clip = _compat_module_0._handle_save_clip
    _handle_save_image = _compat_module_0._handle_save_image
    _handle_sdcard_videos = _compat_module_0._handle_sdcard_videos
    _handle_stream = _compat_module_0._handle_stream
    _handle_stream_proxy_get = _compat_module_0._handle_stream_proxy_get
    _handle_unifiedmsg = _compat_module_0._handle_unifiedmsg
    _hcnetsdk_bool = _compat_module_0._hcnetsdk_bool
    _hcnetsdk_bytes_from_json = _compat_module_0._hcnetsdk_bytes_from_json
    _hcnetsdk_command_frame_dump_summary = _compat_module_0._hcnetsdk_command_frame_dump_summary
    _hcnetsdk_command_frame_hex_values_from_file = _compat_module_0._hcnetsdk_command_frame_hex_values_from_file
    _hcnetsdk_command_frames_from_args = _compat_module_0._hcnetsdk_command_frames_from_args
    _hcnetsdk_command_generated_plan_from_args = _compat_module_0._hcnetsdk_command_generated_plan_from_args
    _hcnetsdk_command_generated_plan_from_json = _compat_module_0._hcnetsdk_command_generated_plan_from_json
    _hcnetsdk_command_generated_plan_step_from_json = _compat_module_0._hcnetsdk_command_generated_plan_step_from_json
    _hcnetsdk_command_plan_delay_after_commands = _compat_module_0._hcnetsdk_command_plan_delay_after_commands
    _hcnetsdk_command_plan_drain_media_before_next = _compat_module_0._hcnetsdk_command_plan_drain_media_before_next
    _hcnetsdk_command_plan_frames_from_json = _compat_module_0._hcnetsdk_command_plan_frames_from_json
    _hcnetsdk_command_plan_from_args = _compat_module_0._hcnetsdk_command_plan_from_args
    _hcnetsdk_command_plan_from_json = _compat_module_0._hcnetsdk_command_plan_from_json
    _hcnetsdk_command_plan_immediate_media_read = _compat_module_0._hcnetsdk_command_plan_immediate_media_read
    _hcnetsdk_command_plan_media_socket = _compat_module_0._hcnetsdk_command_plan_media_socket
    _hcnetsdk_command_plan_raw_steps = _compat_module_0._hcnetsdk_command_plan_raw_steps
    _hcnetsdk_command_plan_read_policy = _compat_module_0._hcnetsdk_command_plan_read_policy
    _hcnetsdk_command_plan_response_reads = _compat_module_0._hcnetsdk_command_plan_response_reads
    _hcnetsdk_command_plan_step_from_json = _compat_module_0._hcnetsdk_command_plan_step_from_json
    _hcnetsdk_command_plan_template_from_json = _compat_module_0._hcnetsdk_command_plan_template_from_json
    _hcnetsdk_command_plan_templates_from_json = _compat_module_0._hcnetsdk_command_plan_templates_from_json
    _hcnetsdk_command_port_body_tail_word_samples = _compat_module_0._hcnetsdk_command_port_body_tail_word_samples
    _hcnetsdk_command_port_body_word_samples = _compat_module_0._hcnetsdk_command_port_body_word_samples
    _hcnetsdk_command_port_exchange_metadata = _compat_module_0._hcnetsdk_command_port_exchange_metadata
    _hcnetsdk_command_template_to_json = _compat_module_0._hcnetsdk_command_template_to_json
    _hcnetsdk_generated_plan_step_to_json = _compat_module_0._hcnetsdk_generated_plan_step_to_json
    _hcnetsdk_generated_plan_to_json = _compat_module_0._hcnetsdk_generated_plan_to_json
    _hcnetsdk_inbound_media_dump_summary = _compat_module_0._hcnetsdk_inbound_media_dump_summary
    _hcnetsdk_int = _compat_module_0._hcnetsdk_int
    _hcnetsdk_int_required = _compat_module_0._hcnetsdk_int_required
    _hcnetsdk_native_annexb_dump_summary = _compat_module_0._hcnetsdk_native_annexb_dump_summary
    _hcnetsdk_optional_int = _compat_module_0._hcnetsdk_optional_int
    _hcnetsdk_playm4_input_dump_summary = _compat_module_0._hcnetsdk_playm4_input_dump_summary
    _hcnetsdk_read_response_policy = _compat_module_0._hcnetsdk_read_response_policy
    _idmx_local_packets_to_annexb_with_codec = _compat_module_0._idmx_local_packets_to_annexb_with_codec
    _iter_annexb_nal_prefixes = _compat_module_0._iter_annexb_nal_prefixes
    _iter_hcnetsdk_command_frame_hex_values = _compat_module_0._iter_hcnetsdk_command_frame_hex_values
    _iter_hcnetsdk_command_template_values = _compat_module_0._iter_hcnetsdk_command_template_values
    _load_token_file = _compat_module_0._load_token_file
    _local_sdk_arg_or_credentials = _compat_module_0._local_sdk_arg_or_credentials
    _local_sdk_authentication_from_args = _compat_module_0._local_sdk_authentication_from_args
    _local_sdk_cas_device_info = _compat_module_0._local_sdk_cas_device_info
    _local_sdk_credentials_file = _compat_module_0._local_sdk_credentials_file
    _local_sdk_credentials_value = _compat_module_0._local_sdk_credentials_value
    _local_sdk_has_static_media_key = _compat_module_0._local_sdk_has_static_media_key
    _local_sdk_media_key = _compat_module_0._local_sdk_media_key
    _local_sdk_receiver_info_ex_from_args = _compat_module_0._local_sdk_receiver_info_ex_from_args
    _local_sdk_receiver_info_from_args = _compat_module_0._local_sdk_receiver_info_from_args
    _local_sdk_stream_metadata = _compat_module_0._local_sdk_stream_metadata
    _login = _compat_module_0._login
    _normalize_stream_proxy_path = _compat_module_0._normalize_stream_proxy_path
    _open_mpegts_remux_process = _compat_module_0._open_mpegts_remux_process
    _parse_args = _compat_module_0._parse_args
    _parse_duration_seconds = _compat_module_0._parse_duration_seconds
    _parse_rtp_packets = _compat_module_0._parse_rtp_packets
    _read_optional_binary_file = _compat_module_0._read_optional_binary_file
    _remux_elementary_video_bytes_to_mpegts = _compat_module_0._remux_elementary_video_bytes_to_mpegts
    _remux_mpegps_bytes_to_mpegts = _compat_module_0._remux_mpegps_bytes_to_mpegts
    _remux_stream_payloads_to_mpegts = _compat_module_0._remux_stream_payloads_to_mpegts
    _required_local_sdk_arg_or_credentials = _compat_module_0._required_local_sdk_arg_or_credentials
    _required_local_sdk_secret = _compat_module_0._required_local_sdk_secret
    _rtp_packets_to_annexb = _compat_module_0._rtp_packets_to_annexb
    _rtp_packets_to_annexb_units = _compat_module_0._rtp_packets_to_annexb_units
    _rtp_payload_video_codec = _compat_module_0._rtp_payload_video_codec
    _save_clip_can_run_without_cloud_credentials = _compat_module_0._save_clip_can_run_without_cloud_credentials
    _save_token_file = _compat_module_0._save_token_file
    _scan_hcnetsdk_command_port_media_frames = _compat_module_0._scan_hcnetsdk_command_port_media_frames
    _select_cloud_video_for_seq_id = _compat_module_0._select_cloud_video_for_seq_id
    _serve_stream_proxy = _compat_module_0._serve_stream_proxy
    _setup_logging = _compat_module_0._setup_logging
    _start_cli_cloud_stream = _compat_module_0._start_cli_cloud_stream
    _stream_payload_decryptor = _compat_module_0._stream_payload_decryptor
    _stream_payload_decryptors = _compat_module_0._stream_payload_decryptors
    _stream_payload_decryptors_with_key = _compat_module_0._stream_payload_decryptors_with_key
    _token_has_refresh_session = _compat_module_0._token_has_refresh_session
    _token_has_service_urls = _compat_module_0._token_has_service_urls
    _validate_shared_clip_args = _compat_module_0._validate_shared_clip_args
    _write_hcnetsdk_sampled_packet_output = _compat_module_0._write_hcnetsdk_sampled_packet_output
    _write_json = _compat_module_0._write_json
    _write_local_sdk_metadata_output = _compat_module_0._write_local_sdk_metadata_output
    _write_save_result = _compat_module_0._write_save_result
    _write_stream_payloads = _compat_module_0._write_stream_payloads
    _write_table = _compat_module_0._write_table
    annotations = _compat_module_0.annotations
    argparse = _compat_module_0.argparse
    cast = _compat_module_0.cast
    classify_ezviz_local_sdk_body = _compat_module_0.classify_ezviz_local_sdk_body
    cloud_rtp_packets_have_audio = _compat_module_0.cloud_rtp_packets_have_audio
    copy_cloud_stream_packets_to_mpegts = _compat_module_0.copy_cloud_stream_packets_to_mpegts
    copy_decrypted_cloud_stream_packets_to_mpegts = _compat_module_0.copy_decrypted_cloud_stream_packets_to_mpegts
    copy_local_sdk_ecdh_stream_to_media = _compat_module_0.copy_local_sdk_ecdh_stream_to_media
    copy_local_stream_to_decrypted_mpegps = _compat_module_0.copy_local_stream_to_decrypted_mpegps
    copy_local_stream_to_decrypted_mpegts = _compat_module_0.copy_local_stream_to_decrypted_mpegts
    copy_local_stream_to_mpegps = _compat_module_0.copy_local_stream_to_mpegps
    copy_local_stream_to_mpegts = _compat_module_0.copy_local_stream_to_mpegts
    copy_remuxed_output = _compat_module_0.copy_remuxed_output
    dataclass = _compat_module_0.dataclass
    decrypt_hikvision_ps_video = _compat_module_0.decrypt_hikvision_ps_video
    detect_hikvision_ps_video_nalu_header_size = _compat_module_0.detect_hikvision_ps_video_nalu_header_size
    detect_rtp_video_codec = _compat_module_0.detect_rtp_video_codec
    detect_transport = _compat_module_0.detect_transport
    download_ezviz_cloud_replay = _compat_module_0.download_ezviz_cloud_replay
    dt = _compat_module_0.dt
    field = _compat_module_0.field
    get_local_sdk_stream_credentials_from_client = _compat_module_0.get_local_sdk_stream_credentials_from_client
    has_positive_finite_capture_bound = _compat_module_0.has_positive_finite_capture_bound
    hashlib = _compat_module_0.hashlib
    hcnetsdk_command_port_generated_plan_from_socket_plan = _compat_module_0.hcnetsdk_command_port_generated_plan_from_socket_plan
    hcnetsdk_command_port_native_lan_live_view_plan = _compat_module_0.hcnetsdk_command_port_native_lan_live_view_plan
    json = _compat_module_0.json
    logging = _compat_module_0.logging
    main = _compat_module_0.main
    mpeg_ps_decryptable_prefix_length = _compat_module_0.mpeg_ps_decryptable_prefix_length
    open_cloud_stream = _compat_module_0.open_cloud_stream
    open_local_sdk_ecdh_stream = _compat_module_0.open_local_sdk_ecdh_stream
    open_local_sdk_stream = _compat_module_0.open_local_sdk_stream
    open_mpegts_remux_process = _compat_module_0.open_mpegts_remux_process
    os = _compat_module_0.os
    os_environ_get = _compat_module_0.os_environ_get
    parse_hcnetsdk_tcp_frame = _compat_module_0.parse_hcnetsdk_tcp_frame
    parse_qs = _compat_module_0.parse_qs
    parse_rtp_packet = _compat_module_0.parse_rtp_packet
    remux_bytes = _compat_module_0.remux_bytes
    rtp_nal_units_have_vcl = _compat_module_0.rtp_nal_units_have_vcl
    rtp_packets_to_nal_units = _compat_module_0.rtp_packets_to_nal_units
    rtp_payload_video_codec = _compat_module_0.rtp_payload_video_codec
    save_private_token = _compat_module_0.save_private_token
    subprocess = _compat_module_0.subprocess
    summarize_h264_annexb_idr_windows = _compat_module_0.summarize_h264_annexb_idr_windows
    summarize_h264_annexb_units = _compat_module_0.summarize_h264_annexb_units
    summarize_hevc_annexb_irap_windows = _compat_module_0.summarize_hevc_annexb_irap_windows
    summarize_idmx_h264_local_packets = _compat_module_0.summarize_idmx_h264_local_packets
    suppress = _compat_module_0.suppress
    sys = _compat_module_0.sys
    time = _compat_module_0.time
    urlparse = _compat_module_0.urlparse

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _LOGGER,
        _REAL_EZVIZ_CLIENT,
        HCNETSDK_COMMAND_PLAN_DEFAULT_KEEPALIVE_INTERVAL_SECONDS,
        HCNETSDK_COMMAND_PORT_CONTROL_FAMILY,
        HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
        LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        MAX_RETRIES,
        PUSH_PROFILE,
        Any,
        BaseHTTPRequestHandler,
        BatteryCameraWorkMode,
        BinaryIO,
        BytesIO,
        Callable,
        CasDeviceSession,
        DefenseModeType,
        DeviceSwitchType,
        EzvizAuthVerificationCode,
        EzvizCamera,
        EzvizCAS,
        EzvizCasDeviceInfo,
        EzvizClient,
        EzvizLightBulb,
        EzvizLocalAuthenticationAttrs,
        EzvizLocalPreviewRequest,
        EzvizLocalReceiverInfo,
        EzvizLocalReceiverInfoAttrs,
        EzvizLocalReceiverInfoEx,
        EzvizLocalReceiverInfoExAttrs,
        EzvizNoMediaError,
        HcNetSdkCommandPortControlTemplate,
        HcNetSdkCommandPortGeneratedMultiSocketPlan,
        HcNetSdkCommandPortGeneratedSocketStep,
        HcNetSdkCommandPortMultiSocketPlan,
        HcNetSdkCommandPortSocketStep,
        HcNetSdkLanEndpoint,
        Iterator,
        Mapping,
        Path,
        PyEzvizError,
        StreamProxyConfig,
        StreamProxyHTTPServer,
        StreamTransport,
        ThreadingHTTPServer,
        VtmStreamClient,
        _action_requires_service_urls,
        _add_hcnetsdk_annexb_dump_summary,
        _BufferedStreamPayloadDecryptor,
        _build_local_sdk_cli_stream,
        _build_local_sdk_ecdh_cli_stream,
        _bytes_from_hex_value,
        _cas_time_from_millis,
        _cli_arguments,
        _closing_unconnected_cloud_stream,
        _cloud_cli_media_key,
        _cloud_video_start_millis,
        _codec_nalu_header_size,
        _collect_stream_packets,
        _collect_stream_payloads,
        _copy_local_sdk_ecdh_cli_stream,
        _copy_stream_payloads_to_mpegts,
        _decode_annexb_windows,
        _decode_compressed_record_list,
        _decode_h264_annexb_idr_windows,
        _decode_native_annexb_chunk_windows,
        _decrypt_annexb_video_bytes,
        _decrypt_rtp_annexb_units,
        _decrypt_stream_payload_bytes,
        _default_stream_proxy_path,
        _detect_native_annexb_codec,
        _detect_rtp_video_codec,
        _detect_stream_packets_transport,
        _ensure_client_service_urls,
        _env_or_arg,
        _explicit_cloud_cli_media_key,
        _extract_ticket,
        _first_record_list,
        _format_cell,
        _handle_camera,
        _handle_cloud_video_decrypt,
        _handle_cloud_video_download,
        _handle_cloud_videos,
        _handle_device_infos,
        _handle_devices,
        _handle_devices_light,
        _handle_h264_annexb_summary,
        _handle_hcnetsdk_command_dump_summary,
        _handle_hcnetsdk_command_plan_generate,
        _handle_home_defence_mode,
        _handle_light,
        _handle_local_sdk_keys,
        _handle_local_sdk_stream_dump,
        _handle_mqtt,
        _handle_pagelist,
        _handle_save,
        _handle_save_clip,
        _handle_save_image,
        _handle_sdcard_videos,
        _handle_stream,
        _handle_stream_proxy_get,
        _handle_unifiedmsg,
        _hcnetsdk_bool,
        _hcnetsdk_bytes_from_json,
        _hcnetsdk_command_frame_dump_summary,
        _hcnetsdk_command_frame_hex_values_from_file,
        _hcnetsdk_command_frames_from_args,
        _hcnetsdk_command_generated_plan_from_args,
        _hcnetsdk_command_generated_plan_from_json,
        _hcnetsdk_command_generated_plan_step_from_json,
        _hcnetsdk_command_plan_delay_after_commands,
        _hcnetsdk_command_plan_drain_media_before_next,
        _hcnetsdk_command_plan_frames_from_json,
        _hcnetsdk_command_plan_from_args,
        _hcnetsdk_command_plan_from_json,
        _hcnetsdk_command_plan_immediate_media_read,
        _hcnetsdk_command_plan_media_socket,
        _hcnetsdk_command_plan_raw_steps,
        _hcnetsdk_command_plan_read_policy,
        _hcnetsdk_command_plan_response_reads,
        _hcnetsdk_command_plan_step_from_json,
        _hcnetsdk_command_plan_template_from_json,
        _hcnetsdk_command_plan_templates_from_json,
        _hcnetsdk_command_port_body_tail_word_samples,
        _hcnetsdk_command_port_body_word_samples,
        _hcnetsdk_command_port_exchange_metadata,
        _hcnetsdk_command_template_to_json,
        _hcnetsdk_generated_plan_step_to_json,
        _hcnetsdk_generated_plan_to_json,
        _hcnetsdk_inbound_media_dump_summary,
        _hcnetsdk_int,
        _hcnetsdk_int_required,
        _hcnetsdk_native_annexb_dump_summary,
        _hcnetsdk_optional_int,
        _hcnetsdk_playm4_input_dump_summary,
        _hcnetsdk_read_response_policy,
        _idmx_local_packets_to_annexb_with_codec,
        _iter_annexb_nal_prefixes,
        _iter_hcnetsdk_command_frame_hex_values,
        _iter_hcnetsdk_command_template_values,
        _load_token_file,
        _local_sdk_arg_or_credentials,
        _local_sdk_authentication_from_args,
        _local_sdk_cas_device_info,
        _local_sdk_credentials_file,
        _local_sdk_credentials_value,
        _local_sdk_has_static_media_key,
        _local_sdk_media_key,
        _local_sdk_receiver_info_ex_from_args,
        _local_sdk_receiver_info_from_args,
        _local_sdk_stream_metadata,
        _login,
        _normalize_stream_proxy_path,
        _open_mpegts_remux_process,
        _parse_args,
        _parse_duration_seconds,
        _parse_rtp_packets,
        _read_optional_binary_file,
        _remux_elementary_video_bytes_to_mpegts,
        _remux_mpegps_bytes_to_mpegts,
        _remux_stream_payloads_to_mpegts,
        _required_local_sdk_arg_or_credentials,
        _required_local_sdk_secret,
        _rtp_packets_to_annexb,
        _rtp_packets_to_annexb_units,
        _rtp_payload_video_codec,
        _save_clip_can_run_without_cloud_credentials,
        _save_token_file,
        _scan_hcnetsdk_command_port_media_frames,
        _select_cloud_video_for_seq_id,
        _serve_stream_proxy,
        _setup_logging,
        _start_cli_cloud_stream,
        _stream_payload_decryptor,
        _stream_payload_decryptors,
        _stream_payload_decryptors_with_key,
        _token_has_refresh_session,
        _token_has_service_urls,
        _validate_shared_clip_args,
        _write_hcnetsdk_sampled_packet_output,
        _write_json,
        _write_local_sdk_metadata_output,
        _write_save_result,
        _write_stream_payloads,
        _write_table,
        annotations,
        argparse,
        cast,
        classify_ezviz_local_sdk_body,
        cloud_rtp_packets_have_audio,
        copy_cloud_stream_packets_to_mpegts,
        copy_decrypted_cloud_stream_packets_to_mpegts,
        copy_local_sdk_ecdh_stream_to_media,
        copy_local_stream_to_decrypted_mpegps,
        copy_local_stream_to_decrypted_mpegts,
        copy_local_stream_to_mpegps,
        copy_local_stream_to_mpegts,
        copy_remuxed_output,
        dataclass,
        decrypt_hikvision_ps_video,
        detect_hikvision_ps_video_nalu_header_size,
        detect_rtp_video_codec,
        detect_transport,
        download_ezviz_cloud_replay,
        dt,
        field,
        get_local_sdk_stream_credentials_from_client,
        has_positive_finite_capture_bound,
        hashlib,
        hcnetsdk_command_port_generated_plan_from_socket_plan,
        hcnetsdk_command_port_native_lan_live_view_plan,
        json,
        logging,
        main,
        mpeg_ps_decryptable_prefix_length,
        open_cloud_stream,
        open_local_sdk_ecdh_stream,
        open_local_sdk_stream,
        open_mpegts_remux_process,
        os,
        os_environ_get,
        parse_hcnetsdk_tcp_frame,
        parse_qs,
        parse_rtp_packet,
        remux_bytes,
        rtp_nal_units_have_vcl,
        rtp_packets_to_nal_units,
        rtp_payload_video_codec,
        save_private_token,
        subprocess,
        summarize_h264_annexb_idr_windows,
        summarize_h264_annexb_units,
        summarize_hevc_annexb_irap_windows,
        summarize_idmx_h264_local_packets,
        suppress,
        sys,
        time,
        urlparse,
    )

if __name__ == "__main__":
    sys.exit(_implementation.main())
else:
    sys.modules[__name__] = _implementation
