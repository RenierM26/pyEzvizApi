# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.media.rtp`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.media import rtp as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher as _compat_module_0
    AES = _compat_module_0.AES

    import pyezvizapi.streaming.media.rtp as _compat_module_1
    _IDMX_RTP_STREAM_TYPES = _compat_module_1._IDMX_RTP_STREAM_TYPES
    _IDMX_STATIC_VIDEO_PAYLOAD_CODECS = _compat_module_1._IDMX_STATIC_VIDEO_PAYLOAD_CODECS
    _STATIC_AUDIO_PROFILES = _compat_module_1._STATIC_AUDIO_PROFILES
    ANNEX_B_START_CODE = _compat_module_1.ANNEX_B_START_CODE
    DEFAULT_AAC_PAYLOAD_TYPES = _compat_module_1.DEFAULT_AAC_PAYLOAD_TYPES
    DEFAULT_METADATA_PAYLOAD_TYPES = _compat_module_1.DEFAULT_METADATA_PAYLOAD_TYPES
    DEFAULT_VIDEO_PAYLOAD_TYPES = _compat_module_1.DEFAULT_VIDEO_PAYLOAD_TYPES
    IDMX_AAC_ADTS_HEADER_SIZE = _compat_module_1.IDMX_AAC_ADTS_HEADER_SIZE
    IDMX_AAC_ADTS_MAX_FRAME_LENGTH = _compat_module_1.IDMX_AAC_ADTS_MAX_FRAME_LENGTH
    IDMX_AAC_AUDIO_SPECIFIC_CONFIG_OBJECT_TYPE = _compat_module_1.IDMX_AAC_AUDIO_SPECIFIC_CONFIG_OBJECT_TYPE
    IDMX_AAC_SAMPLE_RATES = _compat_module_1.IDMX_AAC_SAMPLE_RATES
    IDMX_AAC_SAMPLES_PER_FRAME = _compat_module_1.IDMX_AAC_SAMPLES_PER_FRAME
    IDMX_AUDIO_EXTENSION_VERSION = _compat_module_1.IDMX_AUDIO_EXTENSION_VERSION
    IDMX_RTP_SOURCE_MARKER = _compat_module_1.IDMX_RTP_SOURCE_MARKER
    KNOWN_AUDIO_PAYLOAD_TYPES = _compat_module_1.KNOWN_AUDIO_PAYLOAD_TYPES
    KNOWN_VIDEO_PAYLOAD_TYPES = _compat_module_1.KNOWN_VIDEO_PAYLOAD_TYPES
    MPEG_VIDEO_START_CODE_PREFIX = _compat_module_1.MPEG_VIDEO_START_CODE_PREFIX
    Callable = _compat_module_1.Callable
    EzvizUnsupportedMediaError = _compat_module_1.EzvizUnsupportedMediaError
    Fraction = _compat_module_1.Fraction
    Iterable = _compat_module_1.Iterable
    Literal = _compat_module_1.Literal
    PyEzvizError = _compat_module_1.PyEzvizError
    RtpAacStream = _compat_module_1.RtpAacStream
    RtpCodec = _compat_module_1.RtpCodec
    RtpContinuityStats = _compat_module_1.RtpContinuityStats
    RtpMediaKind = _compat_module_1.RtpMediaKind
    RtpPacket = _compat_module_1.RtpPacket
    RtpRouteProfile = _compat_module_1.RtpRouteProfile
    RtpSequenceKey = _compat_module_1.RtpSequenceKey
    RtpStreamDescriptor = _compat_module_1.RtpStreamDescriptor
    RtpVideoCodec = _compat_module_1.RtpVideoCodec
    RtpVideoDepacketizer = _compat_module_1.RtpVideoDepacketizer
    UnsupportedRtpVideoCodecError = _compat_module_1.UnsupportedRtpVideoCodecError
    _aac_adts_header = _compat_module_1._aac_adts_header
    _aac_timed_segments = _compat_module_1._aac_timed_segments
    _aac_timestamp_delta_is_supported = _compat_module_1._aac_timestamp_delta_is_supported
    _advertised_rtp_video_codec = _compat_module_1._advertised_rtp_video_codec
    _aggregation_units = _compat_module_1._aggregation_units
    _complete_fu_chain_indexes = _compat_module_1._complete_fu_chain_indexes
    _decrypt_idmx_aac_access_unit = _compat_module_1._decrypt_idmx_aac_access_unit
    _encrypted_aggregation_packet = _compat_module_1._encrypted_aggregation_packet
    _encrypted_fu_chain_is_fragmented_nal = _compat_module_1._encrypted_fu_chain_is_fragmented_nal
    _exp_golomb_code_complete = _compat_module_1._exp_golomb_code_complete
    _exp_golomb_code_end = _compat_module_1._exp_golomb_code_end
    _FragmentedNal = _compat_module_1._FragmentedNal
    _fu_signature = _compat_module_1._fu_signature
    _h264_slice_header_complete = _compat_module_1._h264_slice_header_complete
    _h264_slice_header_offset = _compat_module_1._h264_slice_header_offset
    _idmx_aac_access_unit = _compat_module_1._idmx_aac_access_unit
    _idmx_audio_extension_is_aac = _compat_module_1._idmx_audio_extension_is_aac
    _is_ambiguous_h264_hevc_payload = _compat_module_1._is_ambiguous_h264_hevc_payload
    _is_complete_aggregation_packet = _compat_module_1._is_complete_aggregation_packet
    _is_plausible_hevc_header = _compat_module_1._is_plausible_hevc_header
    _profile_codec_fields = _compat_module_1._profile_codec_fields
    _rtp_media_aes_key = _compat_module_1._rtp_media_aes_key
    _rtp_nal_starts_picture = _compat_module_1._rtp_nal_starts_picture
    _rtp_packet_matches_codec_epoch = _compat_module_1._rtp_packet_matches_codec_epoch
    _rtp_payload_matches_video_codec = _compat_module_1._rtp_payload_matches_video_codec
    _rtp_payload_unsupported_video_codec = _compat_module_1._rtp_payload_unsupported_video_codec
    _rtp_route_epochs = _compat_module_1._rtp_route_epochs
    _rtp_sequence_key = _compat_module_1._rtp_sequence_key
    _static_media_kind = _compat_module_1._static_media_kind
    _valid_rtp_nal_header = _compat_module_1._valid_rtp_nal_header
    annotations = _compat_module_1.annotations
    dataclass = _compat_module_1.dataclass
    decrypt_idmx_aac_packets = _compat_module_1.decrypt_idmx_aac_packets
    detect_rtp_video_codec = _compat_module_1.detect_rtp_video_codec
    idmx_aac_descriptor = _compat_module_1.idmx_aac_descriptor
    idmx_rtp_stream_descriptors = _compat_module_1.idmx_rtp_stream_descriptors
    idmx_video_frame_rate = _compat_module_1.idmx_video_frame_rate
    pairwise = _compat_module_1.pairwise
    parse_rtp_packet = _compat_module_1.parse_rtp_packet
    replace = _compat_module_1.replace
    rtp_codec_payload_types = _compat_module_1.rtp_codec_payload_types
    rtp_media_kind = _compat_module_1.rtp_media_kind
    rtp_nal_units_have_vcl = _compat_module_1.rtp_nal_units_have_vcl
    rtp_packet_has_valid_idmx_aac_frame = _compat_module_1.rtp_packet_has_valid_idmx_aac_frame
    rtp_packet_is_idmx_aac = _compat_module_1.rtp_packet_is_idmx_aac
    rtp_packets_to_annexb = _compat_module_1.rtp_packets_to_annexb
    rtp_packets_to_nal_units = _compat_module_1.rtp_packets_to_nal_units
    rtp_payload = _compat_module_1.rtp_payload
    rtp_payload_video_codec = _compat_module_1.rtp_payload_video_codec

sys.modules[__name__] = _implementation
