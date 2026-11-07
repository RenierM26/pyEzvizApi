# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.session`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import session as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher.AES as _compat_typed_AES
    AES = _compat_typed_AES

    import pyezvizapi.streaming.local.session as _compat_module_1
    _CLEAN_WINDOW_PROBE_PACKET_INTERVAL = _compat_module_1._CLEAN_WINDOW_PROBE_PACKET_INTERVAL
    _CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS = _compat_module_1._CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS
    _CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES = _compat_module_1._CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES
    _CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL = _compat_module_1._CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL
    _COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS = _compat_module_1._COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS
    _FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND = _compat_module_1._FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND
    _FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS = _compat_module_1._FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS
    _FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS = _compat_module_1._FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS
    _HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL = _compat_module_1._HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL
    _HCNETSDK_APP_LAN_PLAY_LOGIN_TAIL = _compat_module_1._HCNETSDK_APP_LAN_PLAY_LOGIN_TAIL
    _INTERRUPTED_LOCAL_STREAM_MESSAGE = _compat_module_1._INTERRUPTED_LOCAL_STREAM_MESSAGE
    ANNEX_B_LONG_START_CODE = _compat_module_1.ANNEX_B_LONG_START_CODE
    DEFAULT_AAC_PAYLOAD_TYPES = _compat_module_1.DEFAULT_AAC_PAYLOAD_TYPES
    DEFAULT_VIDEO_PAYLOAD_TYPES = _compat_module_1.DEFAULT_VIDEO_PAYLOAD_TYPES
    H264_FU_A_NAL_TYPE = _compat_module_1.H264_FU_A_NAL_TYPE
    H264_NAL_HEADER_SIZE = _compat_module_1.H264_NAL_HEADER_SIZE
    HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW = _compat_module_1.HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW
    HCNETSDK_HRUDP_FRAME_HEADER_SIZE = _compat_module_1.HCNETSDK_HRUDP_FRAME_HEADER_SIZE
    HCNETSDK_HRUDP_VIDEO_FRAME_TYPE = _compat_module_1.HCNETSDK_HRUDP_VIDEO_FRAME_TYPE
    HEVC_NAL_HEADER_SIZE = _compat_module_1.HEVC_NAL_HEADER_SIZE
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH = _compat_module_1.HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
    IDMX_AAC_RTP_PAYLOAD_TYPE = _compat_module_1.IDMX_AAC_RTP_PAYLOAD_TYPE
    IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX = _compat_module_1.IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX
    IDMX_DEFAULT_VIDEO_FRAME_RATE = _compat_module_1.IDMX_DEFAULT_VIDEO_FRAME_RATE
    IDMX_H264_RTP_PAYLOAD_TYPE = _compat_module_1.IDMX_H264_RTP_PAYLOAD_TYPE
    IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET = _compat_module_1.IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET
    IDMX_LOCAL_FRAME_HEADER_SIZE = _compat_module_1.IDMX_LOCAL_FRAME_HEADER_SIZE
    IDMX_LOCAL_FRAME_SENTINEL = _compat_module_1.IDMX_LOCAL_FRAME_SENTINEL
    IDMX_LOCAL_FRAME_SENTINEL_OFFSETS = _compat_module_1.IDMX_LOCAL_FRAME_SENTINEL_OFFSETS
    IDMX_VIDEO_RTP_CLOCK_RATE = _compat_module_1.IDMX_VIDEO_RTP_CLOCK_RATE
    MAX_RETRIES = _compat_module_1.MAX_RETRIES
    MPEG_PS_START_CODE = _compat_module_1.MPEG_PS_START_CODE
    MPEG_START_CODE_PREFIX = _compat_module_1.MPEG_START_CODE_PREFIX
    Any = _compat_module_1.Any
    BinaryIO = _compat_module_1.BinaryIO
    BoundedStderrTail = _compat_module_1.BoundedStderrTail
    Callable = _compat_module_1.Callable
    CasDeviceSession = _compat_module_1.CasDeviceSession
    Event = _compat_module_1.Event
    EzvizCAS = _compat_module_1.EzvizCAS
    EzvizCasDeviceInfo = _compat_module_1.EzvizCasDeviceInfo
    EzvizInterleavedRtpFrameWithPrefix = _compat_module_1.EzvizInterleavedRtpFrameWithPrefix
    EzvizLocalAuthenticationAttrs = _compat_module_1.EzvizLocalAuthenticationAttrs
    EzvizLocalPreviewRequest = _compat_module_1.EzvizLocalPreviewRequest
    EzvizLocalReceiverInfoAttrs = _compat_module_1.EzvizLocalReceiverInfoAttrs
    EzvizLocalReceiverInfoExAttrs = _compat_module_1.EzvizLocalReceiverInfoExAttrs
    EzvizLocalSdkClient = _compat_module_1.EzvizLocalSdkClient
    EzvizLocalSdkCredentials = _compat_module_1.EzvizLocalSdkCredentials
    EzvizLocalSdkDeadlineExpired = _compat_module_1.EzvizLocalSdkDeadlineExpired
    EzvizLocalSdkMediaStream = _compat_module_1.EzvizLocalSdkMediaStream
    EzvizLocalSdkStreamBootstrap = _compat_module_1.EzvizLocalSdkStreamBootstrap
    EzvizLocalStreamPacket = _compat_module_1.EzvizLocalStreamPacket
    EzvizNoMediaError = _compat_module_1.EzvizNoMediaError
    EzvizUnsupportedMediaError = _compat_module_1.EzvizUnsupportedMediaError
    Fraction = _compat_module_1.Fraction
    HcNetSdkCommandPortClient = _compat_module_1.HcNetSdkCommandPortClient
    HcNetSdkCommandPortControlTemplate = _compat_module_1.HcNetSdkCommandPortControlTemplate
    HcNetSdkCommandPortExchange = _compat_module_1.HcNetSdkCommandPortExchange
    HcNetSdkCommandPortGeneratedMultiSocketMediaStream = _compat_module_1.HcNetSdkCommandPortGeneratedMultiSocketMediaStream
    HcNetSdkCommandPortGeneratedMultiSocketPlan = _compat_module_1.HcNetSdkCommandPortGeneratedMultiSocketPlan
    HcNetSdkCommandPortGeneratedSocketStep = _compat_module_1.HcNetSdkCommandPortGeneratedSocketStep
    HcNetSdkCommandPortKeepaliveEvent = _compat_module_1.HcNetSdkCommandPortKeepaliveEvent
    HcNetSdkCommandPortLoginSession = _compat_module_1.HcNetSdkCommandPortLoginSession
    HcNetSdkCommandPortMediaStream = _compat_module_1.HcNetSdkCommandPortMediaStream
    HcNetSdkCommandPortMultiSocketMediaStream = _compat_module_1.HcNetSdkCommandPortMultiSocketMediaStream
    HcNetSdkCommandPortMultiSocketPlan = _compat_module_1.HcNetSdkCommandPortMultiSocketPlan
    HcNetSdkCommandPortSocketStep = _compat_module_1.HcNetSdkCommandPortSocketStep
    HcNetSdkCommandPortStreamBootstrap = _compat_module_1.HcNetSdkCommandPortStreamBootstrap
    HcNetSdkLanEndpoint = _compat_module_1.HcNetSdkLanEndpoint
    HcNetSdkRealDataPacket = _compat_module_1.HcNetSdkRealDataPacket
    Iterable = _compat_module_1.Iterable
    Iterator = _compat_module_1.Iterator
    LegacyPacketSource = _compat_module_1.LegacyPacketSource
    Literal = _compat_module_1.Literal
    LocalSdkOutputFormat = _compat_module_1.LocalSdkOutputFormat
    Lock = _compat_module_1.Lock
    MediaPacket = _compat_module_1.MediaPacket
    MediaPacketMetadata = _compat_module_1.MediaPacketMetadata
    MediaPacketSourceAdapter = _compat_module_1.MediaPacketSourceAdapter
    Path = _compat_module_1.Path
    PyEzvizError = _compat_module_1.PyEzvizError
    RtpAacStream = _compat_module_1.RtpAacStream
    RtpPacket = _compat_module_1.RtpPacket
    RtpRouteProfile = _compat_module_1.RtpRouteProfile
    RtpSequenceKey = _compat_module_1.RtpSequenceKey
    RtpStreamDescriptor = _compat_module_1.RtpStreamDescriptor
    RtpVideoCodec = _compat_module_1.RtpVideoCodec
    RtpVideoDepacketizer = _compat_module_1.RtpVideoDepacketizer
    SocketFactory = _compat_module_1.SocketFactory
    Thread = _compat_module_1.Thread
    _annexb_contains_selected_vcl = _compat_module_1._annexb_contains_selected_vcl
    _annexb_first_vcl_unit = _compat_module_1._annexb_first_vcl_unit
    _annexb_has_h264_vcl = _compat_module_1._annexb_has_h264_vcl
    _annexb_looks_like_h264 = _compat_module_1._annexb_looks_like_h264
    _annexb_looks_like_hevc = _compat_module_1._annexb_looks_like_hevc
    _annexb_vcl_bounds = _compat_module_1._annexb_vcl_bounds
    _app_remux_options = _compat_module_1._app_remux_options
    _append_decrypted_h264_nal = _compat_module_1._append_decrypted_h264_nal
    _append_decrypted_hevc_nal = _compat_module_1._append_decrypted_hevc_nal
    _append_h264_nal = _compat_module_1._append_h264_nal
    _append_hevc_nal = _compat_module_1._append_hevc_nal
    _append_idmx_h264_fu_a_payload = _compat_module_1._append_idmx_h264_fu_a_payload
    _append_idmx_h264_nal_unit_sample = _compat_module_1._append_idmx_h264_nal_unit_sample
    _append_idmx_hevc_media_payload = _compat_module_1._append_idmx_hevc_media_payload
    _checked_h264_duration_sum = _compat_module_1._checked_h264_duration_sum
    _clear_native_rtp_packets_with_legacy_indices = _compat_module_1._clear_native_rtp_packets_with_legacy_indices
    _clear_native_selected_timeline = _compat_module_1._clear_native_selected_timeline
    _copy_clear_native_idmx_timed_av = _compat_module_1._copy_clear_native_idmx_timed_av
    _copy_decrypted_native_idmx_timed_av = _compat_module_1._copy_decrypted_native_idmx_timed_av
    _copy_idmx_audio_video_to_mpegts = _compat_module_1._copy_idmx_audio_video_to_mpegts
    _copy_mpegps_payloads_to_mpegts = _compat_module_1._copy_mpegps_payloads_to_mpegts
    _decrypt_h264_nal_prefix = _compat_module_1._decrypt_h264_nal_prefix
    _decrypt_hevc_nal_prefix = _compat_module_1._decrypt_hevc_nal_prefix
    _decrypt_idmx_local_packets_to_adts_aac = _compat_module_1._decrypt_idmx_local_packets_to_adts_aac
    _decrypt_idmx_local_packets_to_annexb = _compat_module_1._decrypt_idmx_local_packets_to_annexb
    _decrypt_idmx_local_packets_to_annexb_with_codec = _compat_module_1._decrypt_idmx_local_packets_to_annexb_with_codec
    _decrypted_h264_annexb_packet_index_for_offset = _compat_module_1._decrypted_h264_annexb_packet_index_for_offset
    _decrypted_hevc_annexb_packet_index_for_offset = _compat_module_1._decrypted_hevc_annexb_packet_index_for_offset
    _ffmpeg_h264_decode_errors = _compat_module_1._ffmpeg_h264_decode_errors
    _ffmpeg_hevc_decode_errors = _compat_module_1._ffmpeg_hevc_decode_errors
    _ffmpeg_stderr_tail = _compat_module_1._ffmpeg_stderr_tail
    _ffmpeg_video_decode_errors = _compat_module_1._ffmpeg_video_decode_errors
    _ffmpeg_video_decode_probe_timeout_seconds = _compat_module_1._ffmpeg_video_decode_probe_timeout_seconds
    _find_h264_annexb_start_code = _compat_module_1._find_h264_annexb_start_code
    _h264_annexb_idr_window_start_index = _compat_module_1._h264_annexb_idr_window_start_index
    _h264_annexb_nal_spans = _compat_module_1._h264_annexb_nal_spans
    _h264_annexb_packet_end_offsets = _compat_module_1._h264_annexb_packet_end_offsets
    _h264_annexb_packet_index_for_offset = _compat_module_1._h264_annexb_packet_index_for_offset
    _h264_clean_idr_timeout_suffix = _compat_module_1._h264_clean_idr_timeout_suffix
    _h264_nal_type = _compat_module_1._h264_nal_type
    _H264CleanIdrProbeResult = _compat_module_1._H264CleanIdrProbeResult
    _hcnetsdk_command_port_frame_with_client_ip = _compat_module_1._hcnetsdk_command_port_frame_with_client_ip
    _hcnetsdk_command_port_media_packet = _compat_module_1._hcnetsdk_command_port_media_packet
    _hcnetsdk_command_port_media_payload = _compat_module_1._hcnetsdk_command_port_media_payload
    _hcnetsdk_command_port_step_context = _compat_module_1._hcnetsdk_command_port_step_context
    _hcnetsdk_generated_step = _compat_module_1._hcnetsdk_generated_step
    _hcnetsdk_hrudp_video_payload = _compat_module_1._hcnetsdk_hrudp_video_payload
    _hcnetsdk_step_response_counts = _compat_module_1._hcnetsdk_step_response_counts
    _hcnetsdk_template = _compat_module_1._hcnetsdk_template
    _hevc_annexb_irap_window_start_index = _compat_module_1._hevc_annexb_irap_window_start_index
    _hevc_annexb_packet_end_offsets = _compat_module_1._hevc_annexb_packet_end_offsets
    _hevc_annexb_packet_index_for_offset = _compat_module_1._hevc_annexb_packet_index_for_offset
    _hevc_annexb_parameter_prefix_for_suffix = _compat_module_1._hevc_annexb_parameter_prefix_for_suffix
    _hevc_nal_type = _compat_module_1._hevc_nal_type
    _hevc_parameter_options = _compat_module_1._hevc_parameter_options
    _hevc_prefixed_suffix_accept_start_offset = _compat_module_1._hevc_prefixed_suffix_accept_start_offset
    _hikvision_aes_ecb_cipher = _compat_module_1._hikvision_aes_ecb_cipher
    _idmx_annexb_packet_index_for_offset = _compat_module_1._idmx_annexb_packet_index_for_offset
    _idmx_audio_descriptor = _compat_module_1._idmx_audio_descriptor
    _idmx_audio_metadata = _compat_module_1._idmx_audio_metadata
    _idmx_audio_payload_types = _compat_module_1._idmx_audio_payload_types
    _idmx_frame_end_before_next_prefix = _compat_module_1._idmx_frame_end_before_next_prefix
    _idmx_h264_annexb_packet_spans = _compat_module_1._idmx_h264_annexb_packet_spans
    _idmx_h264_packets_from_selected_annexb = _compat_module_1._idmx_h264_packets_from_selected_annexb
    _idmx_hevc_annexb_packet_spans = _compat_module_1._idmx_hevc_annexb_packet_spans
    _idmx_hevc_direct_frame_matches_route = _compat_module_1._idmx_hevc_direct_frame_matches_route
    _idmx_local_frame_contains_media = _compat_module_1._idmx_local_frame_contains_media
    _idmx_local_frame_header_score = _compat_module_1._idmx_local_frame_header_score
    _idmx_local_frame_header_size = _compat_module_1._idmx_local_frame_header_size
    _idmx_local_frame_is_h264_transport = _compat_module_1._idmx_local_frame_is_h264_transport
    _idmx_local_frame_media_body = _compat_module_1._idmx_local_frame_media_body
    _idmx_local_frame_rtp_marker = _compat_module_1._idmx_local_frame_rtp_marker
    _idmx_local_frame_rtp_packet = _compat_module_1._idmx_local_frame_rtp_packet
    _idmx_local_frame_rtp_timestamp = _compat_module_1._idmx_local_frame_rtp_timestamp
    _idmx_local_frame_sequence_number = _compat_module_1._idmx_local_frame_sequence_number
    _idmx_local_frame_transport_fields = _compat_module_1._idmx_local_frame_transport_fields
    _idmx_local_frames_contain_routed_media = _compat_module_1._idmx_local_frames_contain_routed_media
    _idmx_local_packet_contains_aggregate_descriptors = _compat_module_1._idmx_local_packet_contains_aggregate_descriptors
    _idmx_local_packet_contains_aggregate_media_frame = _compat_module_1._idmx_local_packet_contains_aggregate_media_frame
    _idmx_local_packet_frame_sequence_number = _compat_module_1._idmx_local_packet_frame_sequence_number
    _idmx_local_packets_have_aac = _compat_module_1._idmx_local_packets_have_aac
    _idmx_local_packets_have_direct_hevc_media = _compat_module_1._idmx_local_packets_have_direct_hevc_media
    _idmx_local_packets_to_annexb = _compat_module_1._idmx_local_packets_to_annexb
    _idmx_local_packets_to_annexb_with_codec = _compat_module_1._idmx_local_packets_to_annexb_with_codec
    _idmx_local_packets_to_h264_annexb = _compat_module_1._idmx_local_packets_to_h264_annexb
    _idmx_local_packets_to_h264_annexb_with_codec = _compat_module_1._idmx_local_packets_to_h264_annexb_with_codec
    _idmx_local_packets_to_hevc_annexb = _compat_module_1._idmx_local_packets_to_hevc_annexb
    _idmx_local_route_profile = _compat_module_1._idmx_local_route_profile
    _idmx_local_rtp_frame = _compat_module_1._idmx_local_rtp_frame
    _idmx_local_supported_video_payload_types = _compat_module_1._idmx_local_supported_video_payload_types
    _idmx_local_video_frame_rate = _compat_module_1._idmx_local_video_frame_rate
    _idmx_local_video_payload_types = _compat_module_1._idmx_local_video_payload_types
    _idmx_packet_frame_slice = _compat_module_1._idmx_packet_frame_slice
    _idmx_packets_for_selected_vcl_spans = _compat_module_1._idmx_packets_for_selected_vcl_spans
    _idmx_packets_from_selected_annexb = _compat_module_1._idmx_packets_from_selected_annexb
    _idmx_route_diagnostics = _compat_module_1._idmx_route_diagnostics
    _idmx_rtp_extension = _compat_module_1._idmx_rtp_extension
    _IdmxAacStream = _compat_module_1._IdmxAacStream
    _increment_h264_nal_type_count = _compat_module_1._increment_h264_nal_type_count
    _increment_idmx_h264_nal_unit_counter = _compat_module_1._increment_idmx_h264_nal_unit_counter
    _is_complete_idmx_rtp_frame = _compat_module_1._is_complete_idmx_rtp_frame
    _is_ignorable_leading_stream_payload = _compat_module_1._is_ignorable_leading_stream_payload
    _is_mpeg_ps_packet_start_id = _compat_module_1._is_mpeg_ps_packet_start_id
    _is_plausible_h264_nal = _compat_module_1._is_plausible_h264_nal
    _is_plausible_hevc_nal = _compat_module_1._is_plausible_hevc_nal
    _iter_idmx_local_frame_or_nested = _compat_module_1._iter_idmx_local_frame_or_nested
    _iter_idmx_local_frames = _compat_module_1._iter_idmx_local_frames
    _iter_idmx_local_packet_frame = _compat_module_1._iter_idmx_local_packet_frame
    _iter_idmx_local_packet_frames = _compat_module_1._iter_idmx_local_packet_frames
    _iter_local_stream_payloads = _compat_module_1._iter_local_stream_payloads
    _local_media_aes_key = _compat_module_1._local_media_aes_key
    _local_media_packet = _compat_module_1._local_media_packet
    _local_sdk_endpoint_from_client = _compat_module_1._local_sdk_endpoint_from_client
    _local_sdk_preview_request_from_credentials = _compat_module_1._local_sdk_preview_request_from_credentials
    _local_stream_packets = _compat_module_1._local_stream_packets
    _local_stream_packets_are_idmx = _compat_module_1._local_stream_packets_are_idmx
    _looks_like_hcnetsdk_wrapped_media_payload = _compat_module_1._looks_like_hcnetsdk_wrapped_media_payload
    _looks_like_idmx_h264_clear_nal = _compat_module_1._looks_like_idmx_h264_clear_nal
    _looks_like_idmx_h264_fu_a_frame = _compat_module_1._looks_like_idmx_h264_fu_a_frame
    _looks_like_idmx_hevc_direct_frame = _compat_module_1._looks_like_idmx_hevc_direct_frame
    _looks_like_idmx_hevc_evidence_frame = _compat_module_1._looks_like_idmx_hevc_evidence_frame
    _looks_like_idmx_hevc_media_frame = _compat_module_1._looks_like_idmx_hevc_media_frame
    _looks_like_idmx_hevc_parameter_frame = _compat_module_1._looks_like_idmx_hevc_parameter_frame
    _looks_like_idmx_local_payload = _compat_module_1._looks_like_idmx_local_payload
    _looks_like_length_prefixed_idmx_local_payload = _compat_module_1._looks_like_length_prefixed_idmx_local_payload
    _merge_idmx_h264_frame_summary = _compat_module_1._merge_idmx_h264_frame_summary
    _native_decrypted_picture_timeline = _compat_module_1._native_decrypted_picture_timeline
    _native_decrypted_rtp_timeline = _compat_module_1._native_decrypted_rtp_timeline
    _native_timing_options = _compat_module_1._native_timing_options
    _NonemptyLocalMediaStream = _compat_module_1._NonemptyLocalMediaStream
    _open_local_h264_mpegts_remux_process = _compat_module_1._open_local_h264_mpegts_remux_process
    _open_local_hevc_mpegts_remux_process = _compat_module_1._open_local_hevc_mpegts_remux_process
    _open_local_idmx_audio_video_mpegts_remux_process = _compat_module_1._open_local_idmx_audio_video_mpegts_remux_process
    _open_local_mpegts_remux_process = _compat_module_1._open_local_mpegts_remux_process
    _possible_hcnetsdk_hrudp_packet_shape = _compat_module_1._possible_hcnetsdk_hrudp_packet_shape
    _probe_first_clean_idmx_video_window = _compat_module_1._probe_first_clean_idmx_video_window
    _raise_if_clean_window_probe_exhausted = _compat_module_1._raise_if_clean_window_probe_exhausted
    _record_idmx_h264_nal_unit_summary = _compat_module_1._record_idmx_h264_nal_unit_summary
    _register_p2p_session_for_client = _compat_module_1._register_p2p_session_for_client
    _remaining_capture_timeout = _compat_module_1._remaining_capture_timeout
    _requested_duration_decrypted_h264_suffix_predicate = _compat_module_1._requested_duration_decrypted_h264_suffix_predicate
    _requested_duration_h264_suffix_predicate = _compat_module_1._requested_duration_h264_suffix_predicate
    _requested_duration_idmx_suffix_predicate = _compat_module_1._requested_duration_idmx_suffix_predicate
    _require_bounded_decrypt_capture = _compat_module_1._require_bounded_decrypt_capture
    _require_bounded_idmx_capture = _compat_module_1._require_bounded_idmx_capture
    _rtp_fragment_continues = _compat_module_1._rtp_fragment_continues
    _rtp_nal_starts_picture = _compat_module_1._rtp_nal_starts_picture
    _rtp_packet_matches_codec_epoch = _compat_module_1._rtp_packet_matches_codec_epoch
    _rtp_packet_route_descriptor = _compat_module_1._rtp_packet_route_descriptor
    _rtp_sequence_key = _compat_module_1._rtp_sequence_key
    _RtpFragmentedNal = _compat_module_1._RtpFragmentedNal
    _should_probe_clean_window = _compat_module_1._should_probe_clean_window
    _start_ffmpeg_stderr_drain = _compat_module_1._start_ffmpeg_stderr_drain
    _strip_hcnetsdk_command_port_media_payload_header = _compat_module_1._strip_hcnetsdk_command_port_media_payload_header
    _strip_idmx_command_h264_record_trailer = _compat_module_1._strip_idmx_command_h264_record_trailer
    _strip_legacy_idmx_video_wrapper = _compat_module_1._strip_legacy_idmx_video_wrapper
    _strip_local_sdk_payload_header = _compat_module_1._strip_local_sdk_payload_header
    _summarize_idmx_h264_local_frame = _compat_module_1._summarize_idmx_h264_local_frame
    _summarize_idmx_packet_shape = _compat_module_1._summarize_idmx_packet_shape
    _summarize_idmx_packet_shapes = _compat_module_1._summarize_idmx_packet_shapes
    _trim_trailing_h264_non_vcl_nals = _compat_module_1._trim_trailing_h264_non_vcl_nals
    _trim_trailing_hevc_non_vcl_nals = _compat_module_1._trim_trailing_hevc_non_vcl_nals
    _try_first_clean_decrypted_h264_annexb_idr_window_offset = _compat_module_1._try_first_clean_decrypted_h264_annexb_idr_window_offset
    _try_first_clean_h264_annexb_idr_window_offset = _compat_module_1._try_first_clean_h264_annexb_idr_window_offset
    _try_first_clean_h264_annexb_idr_window_offset_from_annexb = _compat_module_1._try_first_clean_h264_annexb_idr_window_offset_from_annexb
    _try_first_clean_hevc_annexb_irap_window_offset = _compat_module_1._try_first_clean_hevc_annexb_irap_window_offset
    _unsupported_idmx_local_payload_error = _compat_module_1._unsupported_idmx_local_payload_error
    _write_local_stream_payloads = _compat_module_1._write_local_stream_payloads
    annotations = _compat_module_1.annotations
    bisect = _compat_module_1.bisect
    cast = _compat_module_1.cast
    chain = _compat_module_1.chain
    collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window = _compat_module_1.collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window
    collect_h264_idmx_annexb_after_first_clean_idr_window = _compat_module_1.collect_h264_idmx_annexb_after_first_clean_idr_window
    collect_idmx_annexb_after_first_clean_video_window = _compat_module_1.collect_idmx_annexb_after_first_clean_video_window
    collect_local_stream_media_packets = _compat_module_1.collect_local_stream_media_packets
    collect_local_stream_mpegps = _compat_module_1.collect_local_stream_mpegps
    copy_hcnetsdk_real_data_to_mpegts = _compat_module_1.copy_hcnetsdk_real_data_to_mpegts
    copy_local_sdk_stream_from_client = _compat_module_1.copy_local_sdk_stream_from_client
    copy_local_stream_to_decrypted_mpegps = _compat_module_1.copy_local_stream_to_decrypted_mpegps
    copy_local_stream_to_decrypted_mpegts = _compat_module_1.copy_local_stream_to_decrypted_mpegts
    copy_local_stream_to_mpegps = _compat_module_1.copy_local_stream_to_mpegps
    copy_local_stream_to_mpegts = _compat_module_1.copy_local_stream_to_mpegts
    copy_remuxed_output = _compat_module_1.copy_remuxed_output
    dataclass = _compat_module_1.dataclass
    decrypt_hikvision_ps_video = _compat_module_1.decrypt_hikvision_ps_video
    decrypt_idmx_aac_packets = _compat_module_1.decrypt_idmx_aac_packets
    detect_rtp_video_codec = _compat_module_1.detect_rtp_video_codec
    field = _compat_module_1.field
    get_local_sdk_stream_credentials_from_client = _compat_module_1.get_local_sdk_stream_credentials_from_client
    h264_clean_idr_capture_budgets = _compat_module_1.h264_clean_idr_capture_budgets
    has_positive_finite_capture_bound = _compat_module_1.has_positive_finite_capture_bound
    hashlib = _compat_module_1.hashlib
    hcnetsdk_command_port_control_template_from_frame = _compat_module_1.hcnetsdk_command_port_control_template_from_frame
    hcnetsdk_command_port_generated_plan_from_socket_plan = _compat_module_1.hcnetsdk_command_port_generated_plan_from_socket_plan
    hcnetsdk_command_port_native_lan_live_view_plan = _compat_module_1.hcnetsdk_command_port_native_lan_live_view_plan
    hcnetsdk_command_port_rsa_key = _compat_module_1.hcnetsdk_command_port_rsa_key
    idmx_rtp_stream_descriptors = _compat_module_1.idmx_rtp_stream_descriptors
    idmx_video_frame_rate = _compat_module_1.idmx_video_frame_rate
    ipaddress = _compat_module_1.ipaddress
    is_positive_finite_duration_bound = _compat_module_1.is_positive_finite_duration_bound
    iter_hcnetsdk_real_data_mpegps = _compat_module_1.iter_hcnetsdk_real_data_mpegps
    local_media_packet_source = _compat_module_1.local_media_packet_source
    local_stream_packet_to_media_packet = _compat_module_1.local_stream_packet_to_media_packet
    native_app_timed_payloads = _compat_module_1.native_app_timed_payloads
    open_hcnetsdk_command_port_generated_multi_socket_stream = _compat_module_1.open_hcnetsdk_command_port_generated_multi_socket_stream
    open_hcnetsdk_command_port_multi_socket_stream = _compat_module_1.open_hcnetsdk_command_port_multi_socket_stream
    open_hcnetsdk_command_port_stream = _compat_module_1.open_hcnetsdk_command_port_stream
    open_local_sdk_stream = _compat_module_1.open_local_sdk_stream
    open_local_sdk_stream_from_client = _compat_module_1.open_local_sdk_stream_from_client
    open_mpegts_remux_process = _compat_module_1.open_mpegts_remux_process
    pairwise = _compat_module_1.pairwise
    parse_rtp_packet = _compat_module_1.parse_rtp_packet
    replace = _compat_module_1.replace
    rtp_nal_units_have_vcl = _compat_module_1.rtp_nal_units_have_vcl
    rtp_packet_has_valid_idmx_aac_frame = _compat_module_1.rtp_packet_has_valid_idmx_aac_frame
    rtp_packet_is_idmx_aac = _compat_module_1.rtp_packet_is_idmx_aac
    rtp_packets_to_nal_units = _compat_module_1.rtp_packets_to_nal_units
    rtp_payload = _compat_module_1.rtp_payload
    rtp_payload_video_codec = _compat_module_1.rtp_payload_video_codec
    skip_h264_annexb_initial_idr_windows = _compat_module_1.skip_h264_annexb_initial_idr_windows
    skip_hevc_annexb_initial_irap_windows = _compat_module_1.skip_hevc_annexb_initial_irap_windows
    start_stderr_drain = _compat_module_1.start_stderr_drain
    subprocess = _compat_module_1.subprocess
    summarize_h264_annexb_idr_windows = _compat_module_1.summarize_h264_annexb_idr_windows
    summarize_h264_annexb_units = _compat_module_1.summarize_h264_annexb_units
    summarize_hevc_annexb_irap_windows = _compat_module_1.summarize_hevc_annexb_irap_windows
    summarize_idmx_h264_local_packets = _compat_module_1.summarize_idmx_h264_local_packets
    suppress = _compat_module_1.suppress
    tempfile = _compat_module_1.tempfile
    time = _compat_module_1.time
    timed_rtp_mpegps_payloads = _compat_module_1.timed_rtp_mpegps_payloads
    trim_h264_annexb_to_first_clean_idr_window = _compat_module_1.trim_h264_annexb_to_first_clean_idr_window
    trim_h264_annexb_to_first_error_free_suffix = _compat_module_1.trim_h264_annexb_to_first_error_free_suffix
    trim_hevc_annexb_to_first_clean_irap_window = _compat_module_1.trim_hevc_annexb_to_first_clean_irap_window
    trim_hevc_annexb_to_first_error_free_suffix = _compat_module_1.trim_hevc_annexb_to_first_error_free_suffix
    write_aac_remux_input = _compat_module_1.write_aac_remux_input

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        AES,
        _CLEAN_WINDOW_PROBE_PACKET_INTERVAL,
        _CLEAN_WINDOW_PROBE_THROTTLE_AFTER_PACKETS,
        _CLEAN_WINDOW_SUFFIX_PROBE_MAX_CANDIDATES,
        _CLEAN_WINDOW_SUFFIX_PROBE_PACKET_INTERVAL,
        _COMMAND_PORT_RTP_UNWRAP_FALLBACK_ERRORS,
        _FFMPEG_VIDEO_DECODE_PROBE_BYTES_PER_EXTRA_SECOND,
        _FFMPEG_VIDEO_DECODE_PROBE_MAX_TIMEOUT_SECONDS,
        _FFMPEG_VIDEO_DECODE_PROBE_TIMEOUT_SECONDS,
        _HCNETSDK_APP_LAN_AUDIO_VIDEO_COMPRESS_INFO_TAIL,
        _HCNETSDK_APP_LAN_PLAY_LOGIN_TAIL,
        _INTERRUPTED_LOCAL_STREAM_MESSAGE,
        ANNEX_B_LONG_START_CODE,
        DEFAULT_AAC_PAYLOAD_TYPES,
        DEFAULT_VIDEO_PAYLOAD_TYPES,
        H264_FU_A_NAL_TYPE,
        H264_NAL_HEADER_SIZE,
        HCNETSDK_COMMAND_PORT_NATIVE_PLAN_APP_LAN_LIVE_VIEW,
        HCNETSDK_HRUDP_FRAME_HEADER_SIZE,
        HCNETSDK_HRUDP_VIDEO_FRAME_TYPE,
        HEVC_NAL_HEADER_SIZE,
        HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH,
        IDMX_AAC_RTP_PAYLOAD_TYPE,
        IDMX_COMMAND_H264_RECORD_TRAILER_PREFIX,
        IDMX_DEFAULT_VIDEO_FRAME_RATE,
        IDMX_H264_RTP_PAYLOAD_TYPE,
        IDMX_HEVC_MEDIA_FRAME_NAL_OFFSET,
        IDMX_LOCAL_FRAME_HEADER_SIZE,
        IDMX_LOCAL_FRAME_SENTINEL,
        IDMX_LOCAL_FRAME_SENTINEL_OFFSETS,
        IDMX_VIDEO_RTP_CLOCK_RATE,
        MAX_RETRIES,
        MPEG_PS_START_CODE,
        MPEG_START_CODE_PREFIX,
        Any,
        BinaryIO,
        BoundedStderrTail,
        Callable,
        CasDeviceSession,
        Event,
        EzvizCAS,
        EzvizCasDeviceInfo,
        EzvizInterleavedRtpFrameWithPrefix,
        EzvizLocalAuthenticationAttrs,
        EzvizLocalPreviewRequest,
        EzvizLocalReceiverInfoAttrs,
        EzvizLocalReceiverInfoExAttrs,
        EzvizLocalSdkClient,
        EzvizLocalSdkCredentials,
        EzvizLocalSdkDeadlineExpired,
        EzvizLocalSdkMediaStream,
        EzvizLocalSdkStreamBootstrap,
        EzvizLocalStreamPacket,
        EzvizNoMediaError,
        EzvizUnsupportedMediaError,
        Fraction,
        HcNetSdkCommandPortClient,
        HcNetSdkCommandPortControlTemplate,
        HcNetSdkCommandPortExchange,
        HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
        HcNetSdkCommandPortGeneratedMultiSocketPlan,
        HcNetSdkCommandPortGeneratedSocketStep,
        HcNetSdkCommandPortKeepaliveEvent,
        HcNetSdkCommandPortLoginSession,
        HcNetSdkCommandPortMediaStream,
        HcNetSdkCommandPortMultiSocketMediaStream,
        HcNetSdkCommandPortMultiSocketPlan,
        HcNetSdkCommandPortSocketStep,
        HcNetSdkCommandPortStreamBootstrap,
        HcNetSdkLanEndpoint,
        HcNetSdkRealDataPacket,
        Iterable,
        Iterator,
        LegacyPacketSource,
        Literal,
        LocalSdkOutputFormat,
        Lock,
        MediaPacket,
        MediaPacketMetadata,
        MediaPacketSourceAdapter,
        Path,
        PyEzvizError,
        RtpAacStream,
        RtpPacket,
        RtpRouteProfile,
        RtpSequenceKey,
        RtpStreamDescriptor,
        RtpVideoCodec,
        RtpVideoDepacketizer,
        SocketFactory,
        Thread,
        _annexb_contains_selected_vcl,
        _annexb_first_vcl_unit,
        _annexb_has_h264_vcl,
        _annexb_looks_like_h264,
        _annexb_looks_like_hevc,
        _annexb_vcl_bounds,
        _app_remux_options,
        _append_decrypted_h264_nal,
        _append_decrypted_hevc_nal,
        _append_h264_nal,
        _append_hevc_nal,
        _append_idmx_h264_fu_a_payload,
        _append_idmx_h264_nal_unit_sample,
        _append_idmx_hevc_media_payload,
        _checked_h264_duration_sum,
        _clear_native_rtp_packets_with_legacy_indices,
        _clear_native_selected_timeline,
        _copy_clear_native_idmx_timed_av,
        _copy_decrypted_native_idmx_timed_av,
        _copy_idmx_audio_video_to_mpegts,
        _copy_mpegps_payloads_to_mpegts,
        _decrypt_h264_nal_prefix,
        _decrypt_hevc_nal_prefix,
        _decrypt_idmx_local_packets_to_adts_aac,
        _decrypt_idmx_local_packets_to_annexb,
        _decrypt_idmx_local_packets_to_annexb_with_codec,
        _decrypted_h264_annexb_packet_index_for_offset,
        _decrypted_hevc_annexb_packet_index_for_offset,
        _ffmpeg_h264_decode_errors,
        _ffmpeg_hevc_decode_errors,
        _ffmpeg_stderr_tail,
        _ffmpeg_video_decode_errors,
        _ffmpeg_video_decode_probe_timeout_seconds,
        _find_h264_annexb_start_code,
        _h264_annexb_idr_window_start_index,
        _h264_annexb_nal_spans,
        _h264_annexb_packet_end_offsets,
        _h264_annexb_packet_index_for_offset,
        _h264_clean_idr_timeout_suffix,
        _h264_nal_type,
        _H264CleanIdrProbeResult,
        _hcnetsdk_command_port_frame_with_client_ip,
        _hcnetsdk_command_port_media_packet,
        _hcnetsdk_command_port_media_payload,
        _hcnetsdk_command_port_step_context,
        _hcnetsdk_generated_step,
        _hcnetsdk_hrudp_video_payload,
        _hcnetsdk_step_response_counts,
        _hcnetsdk_template,
        _hevc_annexb_irap_window_start_index,
        _hevc_annexb_packet_end_offsets,
        _hevc_annexb_packet_index_for_offset,
        _hevc_annexb_parameter_prefix_for_suffix,
        _hevc_nal_type,
        _hevc_parameter_options,
        _hevc_prefixed_suffix_accept_start_offset,
        _hikvision_aes_ecb_cipher,
        _idmx_annexb_packet_index_for_offset,
        _idmx_audio_descriptor,
        _idmx_audio_metadata,
        _idmx_audio_payload_types,
        _idmx_frame_end_before_next_prefix,
        _idmx_h264_annexb_packet_spans,
        _idmx_h264_packets_from_selected_annexb,
        _idmx_hevc_annexb_packet_spans,
        _idmx_hevc_direct_frame_matches_route,
        _idmx_local_frame_contains_media,
        _idmx_local_frame_header_score,
        _idmx_local_frame_header_size,
        _idmx_local_frame_is_h264_transport,
        _idmx_local_frame_media_body,
        _idmx_local_frame_rtp_marker,
        _idmx_local_frame_rtp_packet,
        _idmx_local_frame_rtp_timestamp,
        _idmx_local_frame_sequence_number,
        _idmx_local_frame_transport_fields,
        _idmx_local_frames_contain_routed_media,
        _idmx_local_packet_contains_aggregate_descriptors,
        _idmx_local_packet_contains_aggregate_media_frame,
        _idmx_local_packet_frame_sequence_number,
        _idmx_local_packets_have_aac,
        _idmx_local_packets_have_direct_hevc_media,
        _idmx_local_packets_to_annexb,
        _idmx_local_packets_to_annexb_with_codec,
        _idmx_local_packets_to_h264_annexb,
        _idmx_local_packets_to_h264_annexb_with_codec,
        _idmx_local_packets_to_hevc_annexb,
        _idmx_local_route_profile,
        _idmx_local_rtp_frame,
        _idmx_local_supported_video_payload_types,
        _idmx_local_video_frame_rate,
        _idmx_local_video_payload_types,
        _idmx_packet_frame_slice,
        _idmx_packets_for_selected_vcl_spans,
        _idmx_packets_from_selected_annexb,
        _idmx_route_diagnostics,
        _idmx_rtp_extension,
        _IdmxAacStream,
        _increment_h264_nal_type_count,
        _increment_idmx_h264_nal_unit_counter,
        _is_complete_idmx_rtp_frame,
        _is_ignorable_leading_stream_payload,
        _is_mpeg_ps_packet_start_id,
        _is_plausible_h264_nal,
        _is_plausible_hevc_nal,
        _iter_idmx_local_frame_or_nested,
        _iter_idmx_local_frames,
        _iter_idmx_local_packet_frame,
        _iter_idmx_local_packet_frames,
        _iter_local_stream_payloads,
        _local_media_aes_key,
        _local_media_packet,
        _local_sdk_endpoint_from_client,
        _local_sdk_preview_request_from_credentials,
        _local_stream_packets,
        _local_stream_packets_are_idmx,
        _looks_like_hcnetsdk_wrapped_media_payload,
        _looks_like_idmx_h264_clear_nal,
        _looks_like_idmx_h264_fu_a_frame,
        _looks_like_idmx_hevc_direct_frame,
        _looks_like_idmx_hevc_evidence_frame,
        _looks_like_idmx_hevc_media_frame,
        _looks_like_idmx_hevc_parameter_frame,
        _looks_like_idmx_local_payload,
        _looks_like_length_prefixed_idmx_local_payload,
        _merge_idmx_h264_frame_summary,
        _native_decrypted_picture_timeline,
        _native_decrypted_rtp_timeline,
        _native_timing_options,
        _NonemptyLocalMediaStream,
        _open_local_h264_mpegts_remux_process,
        _open_local_hevc_mpegts_remux_process,
        _open_local_idmx_audio_video_mpegts_remux_process,
        _open_local_mpegts_remux_process,
        _possible_hcnetsdk_hrudp_packet_shape,
        _probe_first_clean_idmx_video_window,
        _raise_if_clean_window_probe_exhausted,
        _record_idmx_h264_nal_unit_summary,
        _register_p2p_session_for_client,
        _remaining_capture_timeout,
        _requested_duration_decrypted_h264_suffix_predicate,
        _requested_duration_h264_suffix_predicate,
        _requested_duration_idmx_suffix_predicate,
        _require_bounded_decrypt_capture,
        _require_bounded_idmx_capture,
        _rtp_fragment_continues,
        _rtp_nal_starts_picture,
        _rtp_packet_matches_codec_epoch,
        _rtp_packet_route_descriptor,
        _rtp_sequence_key,
        _RtpFragmentedNal,
        _should_probe_clean_window,
        _start_ffmpeg_stderr_drain,
        _strip_hcnetsdk_command_port_media_payload_header,
        _strip_idmx_command_h264_record_trailer,
        _strip_legacy_idmx_video_wrapper,
        _strip_local_sdk_payload_header,
        _summarize_idmx_h264_local_frame,
        _summarize_idmx_packet_shape,
        _summarize_idmx_packet_shapes,
        _trim_trailing_h264_non_vcl_nals,
        _trim_trailing_hevc_non_vcl_nals,
        _try_first_clean_decrypted_h264_annexb_idr_window_offset,
        _try_first_clean_h264_annexb_idr_window_offset,
        _try_first_clean_h264_annexb_idr_window_offset_from_annexb,
        _try_first_clean_hevc_annexb_irap_window_offset,
        _unsupported_idmx_local_payload_error,
        _write_local_stream_payloads,
        annotations,
        bisect,
        cast,
        chain,
        collect_decrypted_h264_idmx_annexb_after_first_clean_idr_window,
        collect_h264_idmx_annexb_after_first_clean_idr_window,
        collect_idmx_annexb_after_first_clean_video_window,
        collect_local_stream_media_packets,
        collect_local_stream_mpegps,
        copy_hcnetsdk_real_data_to_mpegts,
        copy_local_sdk_stream_from_client,
        copy_local_stream_to_decrypted_mpegps,
        copy_local_stream_to_decrypted_mpegts,
        copy_local_stream_to_mpegps,
        copy_local_stream_to_mpegts,
        copy_remuxed_output,
        dataclass,
        decrypt_hikvision_ps_video,
        decrypt_idmx_aac_packets,
        detect_rtp_video_codec,
        field,
        get_local_sdk_stream_credentials_from_client,
        h264_clean_idr_capture_budgets,
        has_positive_finite_capture_bound,
        hashlib,
        hcnetsdk_command_port_control_template_from_frame,
        hcnetsdk_command_port_generated_plan_from_socket_plan,
        hcnetsdk_command_port_native_lan_live_view_plan,
        hcnetsdk_command_port_rsa_key,
        idmx_rtp_stream_descriptors,
        idmx_video_frame_rate,
        ipaddress,
        is_positive_finite_duration_bound,
        iter_hcnetsdk_real_data_mpegps,
        local_media_packet_source,
        local_stream_packet_to_media_packet,
        native_app_timed_payloads,
        open_hcnetsdk_command_port_generated_multi_socket_stream,
        open_hcnetsdk_command_port_multi_socket_stream,
        open_hcnetsdk_command_port_stream,
        open_local_sdk_stream,
        open_local_sdk_stream_from_client,
        open_mpegts_remux_process,
        pairwise,
        parse_rtp_packet,
        replace,
        rtp_nal_units_have_vcl,
        rtp_packet_has_valid_idmx_aac_frame,
        rtp_packet_is_idmx_aac,
        rtp_packets_to_nal_units,
        rtp_payload,
        rtp_payload_video_codec,
        skip_h264_annexb_initial_idr_windows,
        skip_hevc_annexb_initial_irap_windows,
        start_stderr_drain,
        subprocess,
        summarize_h264_annexb_idr_windows,
        summarize_h264_annexb_units,
        summarize_hevc_annexb_irap_windows,
        summarize_idmx_h264_local_packets,
        suppress,
        tempfile,
        time,
        timed_rtp_mpegps_payloads,
        trim_h264_annexb_to_first_clean_idr_window,
        trim_h264_annexb_to_first_error_free_suffix,
        trim_hevc_annexb_to_first_clean_irap_window,
        trim_hevc_annexb_to_first_error_free_suffix,
        write_aac_remux_input,
    )

sys.modules[__name__] = _implementation
