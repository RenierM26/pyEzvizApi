# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.cloud.legacy`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.cloud import legacy as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher.AES as _compat_typed_AES
    AES = _compat_typed_AES

    import pyezvizapi.streaming.cloud.protocol as _compat_module_1
    _PACK_HEADER_STREAM_ID = _compat_module_1._PACK_HEADER_STREAM_ID
    _PADDING_STREAM_ID = _compat_module_1._PADDING_STREAM_ID
    _PRIVATE_STREAM_1_ID = _compat_module_1._PRIVATE_STREAM_1_ID
    _PRIVATE_STREAM_2_ID = _compat_module_1._PRIVATE_STREAM_2_ID
    _PROGRAM_STREAM_MAP_ID = _compat_module_1._PROGRAM_STREAM_MAP_ID
    _SYSTEM_HEADER_STREAM_ID = _compat_module_1._SYSTEM_HEADER_STREAM_ID
    _XML_END_RE = _compat_module_1._XML_END_RE
    ANNEX_B_LONG_START_CODE = _compat_module_1.ANNEX_B_LONG_START_CODE
    CLOUD_REPLAY_HEADER_SIZE = _compat_module_1.CLOUD_REPLAY_HEADER_SIZE
    CLOUD_REPLAY_HEARTBEAT_CMD = _compat_module_1.CLOUD_REPLAY_HEARTBEAT_CMD
    CLOUD_REPLAY_MAGIC = _compat_module_1.CLOUD_REPLAY_MAGIC
    CLOUD_REPLAY_OPEN_CMD = _compat_module_1.CLOUD_REPLAY_OPEN_CMD
    HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH = _compat_module_1.HIKVISION_NAL_ENCRYPTED_PREFIX_LENGTH
    MPEG_PS_START_CODE = _compat_module_1.MPEG_PS_START_CODE
    MPEG_START_CODE_PREFIX = _compat_module_1.MPEG_START_CODE_PREFIX
    MPEG_TS_SYNC_BYTE = _compat_module_1.MPEG_TS_SYNC_BYTE
    VIDEO_PES_STREAM_ID = _compat_module_1.VIDEO_PES_STREAM_ID
    VTM_HEADER_SIZE = _compat_module_1.VTM_HEADER_SIZE
    VTM_MAGIC = _compat_module_1.VTM_MAGIC
    XML_PREFIX = _compat_module_1.XML_PREFIX
    Any = _compat_module_1.Any
    Callable = _compat_module_1.Callable
    DeadlineLegacyPacketSource = _compat_module_1.DeadlineLegacyPacketSource
    DeviceException = _compat_module_1.DeviceException
    IntEnum = _compat_module_1.IntEnum
    IPv6Address = _compat_module_1.IPv6Address
    Iterator = _compat_module_1.Iterator
    MediaPacket = _compat_module_1.MediaPacket
    MediaPacketMetadata = _compat_module_1.MediaPacketMetadata
    MediaPacketSourceAdapter = _compat_module_1.MediaPacketSourceAdapter
    ProtoValue = _compat_module_1.ProtoValue
    PyEzvizError = _compat_module_1.PyEzvizError
    SocketFactory = _compat_module_1.SocketFactory
    StopStreamResponse = _compat_module_1.StopStreamResponse
    StreamInfoResponse = _compat_module_1.StreamInfoResponse
    StreamTransport = _compat_module_1.StreamTransport
    VtduInfoResponse = _compat_module_1.VtduInfoResponse
    VtduStreamResponse = _compat_module_1.VtduStreamResponse
    VtmChannel = _compat_module_1.VtmChannel
    VtmMessageCode = _compat_module_1.VtmMessageCode
    VtmPacket = _compat_module_1.VtmPacket
    VtmStreamClient = _compat_module_1.VtmStreamClient
    VtmTraceEvent = _compat_module_1.VtmTraceEvent
    _build_cloud_replay_open_xml = _compat_module_1._build_cloud_replay_open_xml
    _cloud_replay_frame = _compat_module_1._cloud_replay_frame
    _cloud_replay_heartbeat_xml = _compat_module_1._cloud_replay_heartbeat_xml
    _cloud_replay_recv = _compat_module_1._cloud_replay_recv
    _cloud_xml_attr_int = _compat_module_1._cloud_xml_attr_int
    _cloud_xml_int = _compat_module_1._cloud_xml_int
    _CloudReplayMessage = _compat_module_1._CloudReplayMessage
    _decrypt_hikvision_ps_video_packets = _compat_module_1._decrypt_hikvision_ps_video_packets
    _encode_varint = _compat_module_1._encode_varint
    _enum_name = _compat_module_1._enum_name
    _ezviz_md5_hex = _compat_module_1._ezviz_md5_hex
    _find_h264_nal_start_codes = _compat_module_1._find_h264_nal_start_codes
    _find_hevc_nal_start_codes = _compat_module_1._find_hevc_nal_start_codes
    _find_nal_start_codes = _compat_module_1._find_nal_start_codes
    _format_url_host = _compat_module_1._format_url_host
    _h264_header_score = _compat_module_1._h264_header_score
    _h264_nal_type = _compat_module_1._h264_nal_type
    _has_non_video_pes_packet = _compat_module_1._has_non_video_pes_packet
    _hevc_header_score = _compat_module_1._hevc_header_score
    _hevc_nal_type = _compat_module_1._hevc_nal_type
    _hikvision_aes_ecb_cipher = _compat_module_1._hikvision_aes_ecb_cipher
    _is_mpeg2_pack_header = _compat_module_1._is_mpeg2_pack_header
    _is_mpeg_ps_metadata_stream_id = _compat_module_1._is_mpeg_ps_metadata_stream_id
    _is_mpeg_ps_packet_start_id = _compat_module_1._is_mpeg_ps_packet_start_id
    _is_plausible_h264_header = _compat_module_1._is_plausible_h264_header
    _is_plausible_hevc_header = _compat_module_1._is_plausible_hevc_header
    _is_plausible_hevc_header_bytes = _compat_module_1._is_plausible_hevc_header_bytes
    _is_video_pes_stream_id = _compat_module_1._is_video_pes_stream_id
    _is_zero_length_video_pes_start = _compat_module_1._is_zero_length_video_pes_start
    _maybe_int = _compat_module_1._maybe_int
    _maybe_str = _compat_module_1._maybe_str
    _mpeg_ps_anchored_recovery_start = _compat_module_1._mpeg_ps_anchored_recovery_start
    _mpeg_ps_complete_packet_ranges = _compat_module_1._mpeg_ps_complete_packet_ranges
    _mpeg_ps_packet_end = _compat_module_1._mpeg_ps_packet_end
    _mpeg_ps_packet_pts = _compat_module_1._mpeg_ps_packet_pts
    _mpeg_ps_video_decrypt_ranges = _compat_module_1._mpeg_ps_video_decrypt_ranges
    _MpegPsPacketRange = _compat_module_1._MpegPsPacketRange
    _MpegPsVideoDecryptState = _compat_module_1._MpegPsVideoDecryptState
    _next_complete_mpeg_ps_packet_start = _compat_module_1._next_complete_mpeg_ps_packet_start
    _next_mpeg_ps_packet_start = _compat_module_1._next_mpeg_ps_packet_start
    _next_unbounded_video_pes_boundary = _compat_module_1._next_unbounded_video_pes_boundary
    _parse_cloud_replay_stream_url = _compat_module_1._parse_cloud_replay_stream_url
    _parse_stream_biz_params = _compat_module_1._parse_stream_biz_params
    _parse_vtdu_stream_response = _compat_module_1._parse_vtdu_stream_response
    _pes_payload_start = _compat_module_1._pes_payload_start
    _proto_bytes = _compat_module_1._proto_bytes
    _proto_bytes_values = _compat_module_1._proto_bytes_values
    _proto_key = _compat_module_1._proto_key
    _proto_last_int = _compat_module_1._proto_last_int
    _proto_last_str = _compat_module_1._proto_last_str
    _proto_string = _compat_module_1._proto_string
    _proto_varint = _compat_module_1._proto_varint
    _read_cloud_replay_message = _compat_module_1._read_cloud_replay_message
    _read_proto_fields = _compat_module_1._read_proto_fields
    _read_varint = _compat_module_1._read_varint
    _rtp_payload = _compat_module_1._rtp_payload
    _video_pes_payload_ranges = _compat_module_1._video_pes_payload_ranges
    _VtmReadDeadlineExpired = _compat_module_1._VtmReadDeadlineExpired
    annotations = _compat_module_1.annotations
    asdict = _compat_module_1.asdict
    build_get_vtdu_info_request = _compat_module_1.build_get_vtdu_info_request
    build_peer_stream_request = _compat_module_1.build_peer_stream_request
    build_start_stream_request = _compat_module_1.build_start_stream_request
    build_stop_stream_request = _compat_module_1.build_stop_stream_request
    build_stream_info_request = _compat_module_1.build_stream_info_request
    build_stream_keepalive_request = _compat_module_1.build_stream_keepalive_request
    build_vtm_url = _compat_module_1.build_vtm_url
    cast = _compat_module_1.cast
    dataclass = _compat_module_1.dataclass
    decode_vtm_header = _compat_module_1.decode_vtm_header
    decode_vtm_packet = _compat_module_1.decode_vtm_packet
    decrypt_hikvision_ps_video = _compat_module_1.decrypt_hikvision_ps_video
    detect_hikvision_ps_video_nalu_header_size = _compat_module_1.detect_hikvision_ps_video_nalu_header_size
    detect_transport = _compat_module_1.detect_transport
    download_ezviz_cloud_replay = _compat_module_1.download_ezviz_cloud_replay
    encode_vtm_packet = _compat_module_1.encode_vtm_packet
    field = _compat_module_1.field
    hashlib = _compat_module_1.hashlib
    ip_address = _compat_module_1.ip_address
    is_positive_finite_duration_bound = _compat_module_1.is_positive_finite_duration_bound
    mpeg_ps_complete_prefix_length = _compat_module_1.mpeg_ps_complete_prefix_length
    mpeg_ps_decryptable_prefix_length = _compat_module_1.mpeg_ps_decryptable_prefix_length
    mpeg_ps_video_pts_span_seconds = _compat_module_1.mpeg_ps_video_pts_span_seconds
    pairwise = _compat_module_1.pairwise
    parse_get_vtdu_info_response = _compat_module_1.parse_get_vtdu_info_response
    parse_peer_stream_response = _compat_module_1.parse_peer_stream_response
    parse_qsl = _compat_module_1.parse_qsl
    parse_start_stream_response = _compat_module_1.parse_start_stream_response
    parse_stop_stream_response = _compat_module_1.parse_stop_stream_response
    parse_stream_info_response = _compat_module_1.parse_stream_info_response
    parse_vtm_url = _compat_module_1.parse_vtm_url
    re = _compat_module_1.re
    rtp_payload = _compat_module_1.rtp_payload
    socket = _compat_module_1.socket
    ssl = _compat_module_1.ssl
    struct = _compat_module_1.struct
    summarize_vtm_packet = _compat_module_1.summarize_vtm_packet
    time = _compat_module_1.time
    urlencode = _compat_module_1.urlencode
    urlparse = _compat_module_1.urlparse
    vtm_media_packet_source = _compat_module_1.vtm_media_packet_source
    vtm_packet_to_media_packet = _compat_module_1.vtm_packet_to_media_packet

sys.modules[__name__] = _implementation
