# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.cloud.bootstrap`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.cloud import bootstrap as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.cloud.bootstrap as _compat_module_0
    _MAX_CLOUD_VIDEO_TIMESTAMP_GAP_SECONDS = _compat_module_0._MAX_CLOUD_VIDEO_TIMESTAMP_GAP_SECONDS
    _RTP_AUDIO_PROBE_MAX_PACKETS = _compat_module_0._RTP_AUDIO_PROBE_MAX_PACKETS
    _RTP_AUDIO_QUEUE_MAX_FRAMES = _compat_module_0._RTP_AUDIO_QUEUE_MAX_FRAMES
    _RTP_AUDIO_QUEUE_TIMEOUT_SECONDS = _compat_module_0._RTP_AUDIO_QUEUE_TIMEOUT_SECONDS
    _RTP_CODEC_PROBE_MAX_PACKETS = _compat_module_0._RTP_CODEC_PROBE_MAX_PACKETS
    _RTP_TIMING_PROBE_MAX_PACKETS = _compat_module_0._RTP_TIMING_PROBE_MAX_PACKETS
    ANNEX_B_START_CODE = _compat_module_0.ANNEX_B_START_CODE
    API_ENDPOINT_STREAMING_VTM = _compat_module_0.API_ENDPOINT_STREAMING_VTM
    API_ENDPOINT_VTDU_TOKEN_V2 = _compat_module_0.API_ENDPOINT_VTDU_TOKEN_V2
    DEFAULT_AAC_PAYLOAD_TYPES = _compat_module_0.DEFAULT_AAC_PAYLOAD_TYPES
    DEFAULT_VIDEO_PAYLOAD_TYPES = _compat_module_0.DEFAULT_VIDEO_PAYLOAD_TYPES
    MAX_RETRIES = _compat_module_0.MAX_RETRIES
    Any = _compat_module_0.Any
    BinaryIO = _compat_module_0.BinaryIO
    Callable = _compat_module_0.Callable
    Empty = _compat_module_0.Empty
    Event = _compat_module_0.Event
    EzvizIncompleteMediaError = _compat_module_0.EzvizIncompleteMediaError
    EzvizNoMediaError = _compat_module_0.EzvizNoMediaError
    Full = _compat_module_0.Full
    HTTPError = _compat_module_0.HTTPError
    Iterable = _compat_module_0.Iterable
    Iterator = _compat_module_0.Iterator
    JsonDict = _compat_module_0.JsonDict
    Lock = _compat_module_0.Lock
    NativeRtpPsMuxer = _compat_module_0.NativeRtpPsMuxer
    Path = _compat_module_0.Path
    PyEzvizError = _compat_module_0.PyEzvizError
    Queue = _compat_module_0.Queue
    RtpAacStream = _compat_module_0.RtpAacStream
    RtpPacket = _compat_module_0.RtpPacket
    RtpRouteProfile = _compat_module_0.RtpRouteProfile
    RtpStreamDescriptor = _compat_module_0.RtpStreamDescriptor
    RtpVideoCodec = _compat_module_0.RtpVideoCodec
    RtpVideoDepacketizer = _compat_module_0.RtpVideoDepacketizer
    SocketFactory = _compat_module_0.SocketFactory
    StreamTransport = _compat_module_0.StreamTransport
    Thread = _compat_module_0.Thread
    TypedDict = _compat_module_0.TypedDict
    UnsupportedRtpVideoCodecError = _compat_module_0.UnsupportedRtpVideoCodecError
    VtduTokenResponse = _compat_module_0.VtduTokenResponse
    VtmServerPublicKey = _compat_module_0.VtmServerPublicKey
    VtmStreamClient = _compat_module_0.VtmStreamClient
    _auth_base_url = _compat_module_0._auth_base_url
    _bounded_cloud_media_key = _compat_module_0._bounded_cloud_media_key
    _closing_unconnected_cloud_stream = _compat_module_0._closing_unconnected_cloud_stream
    _cloud_request_budget_options = _compat_module_0._cloud_request_budget_options
    _cloud_rtp_packet_matches_video_route = _compat_module_0._cloud_rtp_packet_matches_video_route
    _cloud_rtp_packet_nal_units = _compat_module_0._cloud_rtp_packet_nal_units
    _cloud_rtp_packets = _compat_module_0._cloud_rtp_packets
    _CloudRtpAudioInput = _compat_module_0._CloudRtpAudioInput
    _collect_cloud_stream_packets = _compat_module_0._collect_cloud_stream_packets
    _collect_cloud_stream_payloads = _compat_module_0._collect_cloud_stream_payloads
    _copy_cloud_rtp_packets_to_mpegts = _compat_module_0._copy_cloud_rtp_packets_to_mpegts
    _copy_cloud_stream_payloads_to_mpegps = _compat_module_0._copy_cloud_stream_payloads_to_mpegps
    _copy_probed_cloud_capture = _compat_module_0._copy_probed_cloud_capture
    _decrypt_cloud_rtp_nal_unit = _compat_module_0._decrypt_cloud_rtp_nal_unit
    _derive_auth_addr = _compat_module_0._derive_auth_addr
    _find_vtm_resource = _compat_module_0._find_vtm_resource
    _http_status_code = _compat_module_0._http_status_code
    _is_valid_mpegts_body = _compat_module_0._is_valid_mpegts_body
    _iter_bounded_cloud_packets = _compat_module_0._iter_bounded_cloud_packets
    _missing_auth_addr = _compat_module_0._missing_auth_addr
    _open_cloud_elementary_mpegts_remux_process = _compat_module_0._open_cloud_elementary_mpegts_remux_process
    _open_cloud_mpegts_remux_process = _compat_module_0._open_cloud_mpegts_remux_process
    _parse_cloud_rtp_packet = _compat_module_0._parse_cloud_rtp_packet
    _peek_cloud_transport = _compat_module_0._peek_cloud_transport
    _probe_cloud_video_duration = _compat_module_0._probe_cloud_video_duration
    _probe_cloud_video_frame_span = _compat_module_0._probe_cloud_video_frame_span
    _remaining_cloud_capture_duration = _compat_module_0._remaining_cloud_capture_duration
    _remux_cloud_elementary_av_bytes_to_mpegts = _compat_module_0._remux_cloud_elementary_av_bytes_to_mpegts
    _remux_cloud_elementary_bytes_to_mpegts = _compat_module_0._remux_cloud_elementary_bytes_to_mpegts
    _remux_cloud_mpegps_bytes_to_mpegts = _compat_module_0._remux_cloud_mpegps_bytes_to_mpegts
    _require_bounded_cloud_decrypt_capture = _compat_module_0._require_bounded_cloud_decrypt_capture
    _require_clear_cloud_packet = _compat_module_0._require_clear_cloud_packet
    _require_cloud_mpegps_video_duration = _compat_module_0._require_cloud_mpegps_video_duration
    _session_sign = _compat_module_0._session_sign
    _start_bounded_cloud_stream = _compat_module_0._start_bounded_cloud_stream
    _success_retcode = _compat_module_0._success_retcode
    _write_clear_cloud_packets = _compat_module_0._write_clear_cloud_packets
    _write_cloud_mpegts_packets = _compat_module_0._write_cloud_mpegts_packets
    _write_cloud_stream_payloads = _compat_module_0._write_cloud_stream_payloads
    annotations = _compat_module_0.annotations
    base64 = _compat_module_0.base64
    binascii = _compat_module_0.binascii
    build_vtm_url = _compat_module_0.build_vtm_url
    cast = _compat_module_0.cast
    chain = _compat_module_0.chain
    cloud_rtp_packets_have_audio = _compat_module_0.cloud_rtp_packets_have_audio
    contextmanager = _compat_module_0.contextmanager
    copy_cloud_stream_packets_to_mpegts = _compat_module_0.copy_cloud_stream_packets_to_mpegts
    copy_cloud_stream_to_mpegps = _compat_module_0.copy_cloud_stream_to_mpegps
    copy_cloud_stream_to_mpegts = _compat_module_0.copy_cloud_stream_to_mpegts
    copy_decrypted_cloud_stream_packets_to_mpegts = _compat_module_0.copy_decrypted_cloud_stream_packets_to_mpegts
    copy_remuxed_output = _compat_module_0.copy_remuxed_output
    csv = _compat_module_0.csv
    dataclass = _compat_module_0.dataclass
    decrypt_hikvision_ps_video = _compat_module_0.decrypt_hikvision_ps_video
    decrypt_idmx_aac_packets = _compat_module_0.decrypt_idmx_aac_packets
    detect_rtp_video_codec = _compat_module_0.detect_rtp_video_codec
    detect_transport = _compat_module_0.detect_transport
    get_cloud_stream_info = _compat_module_0.get_cloud_stream_info
    get_vtdu_token_v2 = _compat_module_0.get_vtdu_token_v2
    get_vtm_info = _compat_module_0.get_vtm_info
    get_vtm_page_list = _compat_module_0.get_vtm_page_list
    has_positive_finite_capture_bound = _compat_module_0.has_positive_finite_capture_bound
    idmx_rtp_stream_descriptors = _compat_module_0.idmx_rtp_stream_descriptors
    idmx_video_frame_rate = _compat_module_0.idmx_video_frame_rate
    is_positive_finite_duration_bound = _compat_module_0.is_positive_finite_duration_bound
    json = _compat_module_0.json
    math = _compat_module_0.math
    mpeg_ps_video_pts_span_seconds = _compat_module_0.mpeg_ps_video_pts_span_seconds
    open_cloud_stream = _compat_module_0.open_cloud_stream
    open_mpegts_remux_process = _compat_module_0.open_mpegts_remux_process
    parse_rtp_packet = _compat_module_0.parse_rtp_packet
    parse_vtm_server_public_key = _compat_module_0.parse_vtm_server_public_key
    remux_bytes = _compat_module_0.remux_bytes
    request_deadline = _compat_module_0.request_deadline
    rtp_codec_payload_types = _compat_module_0.rtp_codec_payload_types
    rtp_media_kind = _compat_module_0.rtp_media_kind
    rtp_nal_units_have_vcl = _compat_module_0.rtp_nal_units_have_vcl
    rtp_packet_has_valid_idmx_aac_frame = _compat_module_0.rtp_packet_has_valid_idmx_aac_frame
    rtp_packets_to_nal_units = _compat_module_0.rtp_packets_to_nal_units
    rtp_payload_video_codec = _compat_module_0.rtp_payload_video_codec
    shutil = _compat_module_0.shutil
    socket = _compat_module_0.socket
    subprocess = _compat_module_0.subprocess
    suppress = _compat_module_0.suppress
    tempfile = _compat_module_0.tempfile
    time = _compat_module_0.time
    timed_rtp_mpegps_payloads = _compat_module_0.timed_rtp_mpegps_payloads
    urlparse = _compat_module_0.urlparse
    write_aac_remux_input = _compat_module_0.write_aac_remux_input

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _MAX_CLOUD_VIDEO_TIMESTAMP_GAP_SECONDS,
        _RTP_AUDIO_PROBE_MAX_PACKETS,
        _RTP_AUDIO_QUEUE_MAX_FRAMES,
        _RTP_AUDIO_QUEUE_TIMEOUT_SECONDS,
        _RTP_CODEC_PROBE_MAX_PACKETS,
        _RTP_TIMING_PROBE_MAX_PACKETS,
        ANNEX_B_START_CODE,
        API_ENDPOINT_STREAMING_VTM,
        API_ENDPOINT_VTDU_TOKEN_V2,
        DEFAULT_AAC_PAYLOAD_TYPES,
        DEFAULT_VIDEO_PAYLOAD_TYPES,
        MAX_RETRIES,
        Any,
        BinaryIO,
        Callable,
        Empty,
        Event,
        EzvizIncompleteMediaError,
        EzvizNoMediaError,
        Full,
        HTTPError,
        Iterable,
        Iterator,
        JsonDict,
        Lock,
        NativeRtpPsMuxer,
        Path,
        PyEzvizError,
        Queue,
        RtpAacStream,
        RtpPacket,
        RtpRouteProfile,
        RtpStreamDescriptor,
        RtpVideoCodec,
        RtpVideoDepacketizer,
        SocketFactory,
        StreamTransport,
        Thread,
        TypedDict,
        UnsupportedRtpVideoCodecError,
        VtduTokenResponse,
        VtmServerPublicKey,
        VtmStreamClient,
        _auth_base_url,
        _bounded_cloud_media_key,
        _closing_unconnected_cloud_stream,
        _cloud_request_budget_options,
        _cloud_rtp_packet_matches_video_route,
        _cloud_rtp_packet_nal_units,
        _cloud_rtp_packets,
        _CloudRtpAudioInput,
        _collect_cloud_stream_packets,
        _collect_cloud_stream_payloads,
        _copy_cloud_rtp_packets_to_mpegts,
        _copy_cloud_stream_payloads_to_mpegps,
        _copy_probed_cloud_capture,
        _decrypt_cloud_rtp_nal_unit,
        _derive_auth_addr,
        _find_vtm_resource,
        _http_status_code,
        _is_valid_mpegts_body,
        _iter_bounded_cloud_packets,
        _missing_auth_addr,
        _open_cloud_elementary_mpegts_remux_process,
        _open_cloud_mpegts_remux_process,
        _parse_cloud_rtp_packet,
        _peek_cloud_transport,
        _probe_cloud_video_duration,
        _probe_cloud_video_frame_span,
        _remaining_cloud_capture_duration,
        _remux_cloud_elementary_av_bytes_to_mpegts,
        _remux_cloud_elementary_bytes_to_mpegts,
        _remux_cloud_mpegps_bytes_to_mpegts,
        _require_bounded_cloud_decrypt_capture,
        _require_clear_cloud_packet,
        _require_cloud_mpegps_video_duration,
        _session_sign,
        _start_bounded_cloud_stream,
        _success_retcode,
        _write_clear_cloud_packets,
        _write_cloud_mpegts_packets,
        _write_cloud_stream_payloads,
        annotations,
        base64,
        binascii,
        build_vtm_url,
        cast,
        chain,
        cloud_rtp_packets_have_audio,
        contextmanager,
        copy_cloud_stream_packets_to_mpegts,
        copy_cloud_stream_to_mpegps,
        copy_cloud_stream_to_mpegts,
        copy_decrypted_cloud_stream_packets_to_mpegts,
        copy_remuxed_output,
        csv,
        dataclass,
        decrypt_hikvision_ps_video,
        decrypt_idmx_aac_packets,
        detect_rtp_video_codec,
        detect_transport,
        get_cloud_stream_info,
        get_vtdu_token_v2,
        get_vtm_info,
        get_vtm_page_list,
        has_positive_finite_capture_bound,
        idmx_rtp_stream_descriptors,
        idmx_video_frame_rate,
        is_positive_finite_duration_bound,
        json,
        math,
        mpeg_ps_video_pts_span_seconds,
        open_cloud_stream,
        open_mpegts_remux_process,
        parse_rtp_packet,
        parse_vtm_server_public_key,
        remux_bytes,
        request_deadline,
        rtp_codec_payload_types,
        rtp_media_kind,
        rtp_nal_units_have_vcl,
        rtp_packet_has_valid_idmx_aac_frame,
        rtp_packets_to_nal_units,
        rtp_payload_video_codec,
        shutil,
        socket,
        subprocess,
        suppress,
        tempfile,
        time,
        timed_rtp_mpegps_payloads,
        urlparse,
        write_aac_remux_input,
    )

sys.modules[__name__] = _implementation
