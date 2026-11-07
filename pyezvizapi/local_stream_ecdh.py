# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.ecdh`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import ecdh as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher.AES as _compat_typed_AES
    AES = _compat_typed_AES
    import Crypto.Cipher.ChaCha20 as _compat_typed_ChaCha20
    ChaCha20 = _compat_typed_ChaCha20

    import pyezvizapi.streaming.local.ecdh as _compat_module_1
    _IDMX_RTP_SSRC = _compat_module_1._IDMX_RTP_SSRC
    _MAX_UNRECOGNIZED_ECDH_MEDIA_RECORDS = _compat_module_1._MAX_UNRECOGNIZED_ECDH_MEDIA_RECORDS
    LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET = _compat_module_1.LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET
    LOCAL_SDK_ECDH_DATA_MARKER = _compat_module_1.LOCAL_SDK_ECDH_DATA_MARKER
    LOCAL_SDK_ECDH_DATA_NONCE_OFFSET = _compat_module_1.LOCAL_SDK_ECDH_DATA_NONCE_OFFSET
    LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH
    LOCAL_SDK_ECDH_DATA_TYPE = _compat_module_1.LOCAL_SDK_ECDH_DATA_TYPE
    LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION = _compat_module_1.LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION
    LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = _compat_module_1.LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT
    LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH
    LOCAL_SDK_ECDH_H264_SPS_3B = _compat_module_1.LOCAL_SDK_ECDH_H264_SPS_3B
    LOCAL_SDK_ECDH_H264_SPS_4B = _compat_module_1.LOCAL_SDK_ECDH_H264_SPS_4B
    LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET
    LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_LENGTH
    LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_MAGIC = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_MAGIC
    LOCAL_SDK_ECDH_HANDSHAKE_MARKER = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_MARKER
    LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET
    LOCAL_SDK_ECDH_HANDSHAKE_TYPE = _compat_module_1.LOCAL_SDK_ECDH_HANDSHAKE_TYPE
    LOCAL_SDK_ECDH_HEVC_VPS_3B = _compat_module_1.LOCAL_SDK_ECDH_HEVC_VPS_3B
    LOCAL_SDK_ECDH_HEVC_VPS_4B = _compat_module_1.LOCAL_SDK_ECDH_HEVC_VPS_4B
    LOCAL_SDK_ECDH_MAGIC = _compat_module_1.LOCAL_SDK_ECDH_MAGIC
    LOCAL_SDK_ECDH_MAX_PRE_KEYFRAME_BYTES = _compat_module_1.LOCAL_SDK_ECDH_MAX_PRE_KEYFRAME_BYTES
    LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER = _compat_module_1.LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER
    LOCAL_SDK_ECDH_NONCE_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_NONCE_LENGTH
    LOCAL_SDK_ECDH_PACKET_MARKER = _compat_module_1.LOCAL_SDK_ECDH_PACKET_MARKER
    LOCAL_SDK_ECDH_PACKET_WINDOW_SIZE = _compat_module_1.LOCAL_SDK_ECDH_PACKET_WINDOW_SIZE
    LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH
    LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH = _compat_module_1.LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH
    MAX_RETRIES = _compat_module_1.MAX_RETRIES
    RTP_FIXED_HEADER_LENGTH = _compat_module_1.RTP_FIXED_HEADER_LENGTH
    RTP_VERSION = _compat_module_1.RTP_VERSION
    Any = _compat_module_1.Any
    BinaryIO = _compat_module_1.BinaryIO
    Callable = _compat_module_1.Callable
    EzvizCasDeviceInfo = _compat_module_1.EzvizCasDeviceInfo
    EzvizInterleavedRtpFrameWithPrefix = _compat_module_1.EzvizInterleavedRtpFrameWithPrefix
    EzvizLocalAuthenticationAttrs = _compat_module_1.EzvizLocalAuthenticationAttrs
    EzvizLocalPreviewRequest = _compat_module_1.EzvizLocalPreviewRequest
    EzvizLocalReceiverInfoAttrs = _compat_module_1.EzvizLocalReceiverInfoAttrs
    EzvizLocalReceiverInfoExAttrs = _compat_module_1.EzvizLocalReceiverInfoExAttrs
    EzvizLocalSdkClient = _compat_module_1.EzvizLocalSdkClient
    EzvizLocalSdkCredentials = _compat_module_1.EzvizLocalSdkCredentials
    EzvizLocalSdkDeadlineExpired = _compat_module_1.EzvizLocalSdkDeadlineExpired
    EzvizLocalSdkEcdhDataPacket = _compat_module_1.EzvizLocalSdkEcdhDataPacket
    EzvizLocalSdkEcdhHandshakePacket = _compat_module_1.EzvizLocalSdkEcdhHandshakePacket
    EzvizLocalSdkEcdhKeyPair = _compat_module_1.EzvizLocalSdkEcdhKeyPair
    EzvizLocalSdkEcdhMediaStream = _compat_module_1.EzvizLocalSdkEcdhMediaStream
    EzvizLocalSdkEcdhStreamDecoder = _compat_module_1.EzvizLocalSdkEcdhStreamDecoder
    EzvizLocalSdkEcdhStreamPacket = _compat_module_1.EzvizLocalSdkEcdhStreamPacket
    EzvizLocalSdkStreamBootstrap = _compat_module_1.EzvizLocalSdkStreamBootstrap
    EzvizLocalSdkStreamClosed = _compat_module_1.EzvizLocalSdkStreamClosed
    EzvizUnsupportedMediaError = _compat_module_1.EzvizUnsupportedMediaError
    HcNetSdkLanEndpoint = _compat_module_1.HcNetSdkLanEndpoint
    Iterator = _compat_module_1.Iterator
    LegacyPacketSource = _compat_module_1.LegacyPacketSource
    LocalSdkProtocolDetector = _compat_module_1.LocalSdkProtocolDetector
    MediaPacket = _compat_module_1.MediaPacket
    MediaPacketMetadata = _compat_module_1.MediaPacketMetadata
    MediaPacketSourceAdapter = _compat_module_1.MediaPacketSourceAdapter
    PyEzvizError = _compat_module_1.PyEzvizError
    SocketFactory = _compat_module_1.SocketFactory
    UnsupportedAlgorithm = _compat_module_1.UnsupportedAlgorithm
    _BoundedEcdhMediaStream = _compat_module_1._BoundedEcdhMediaStream
    _ezviz_local_sdk_ecdh_verification_input = _compat_module_1._ezviz_local_sdk_ecdh_verification_input
    _is_complete_ecdh_rtp_packet = _compat_module_1._is_complete_ecdh_rtp_packet
    _is_parseable_rtp_packet = _compat_module_1._is_parseable_rtp_packet
    _validate_ecdh_copy_options = _compat_module_1._validate_ecdh_copy_options
    _verify_ezviz_local_sdk_ecdh_packet = _compat_module_1._verify_ezviz_local_sdk_ecdh_packet
    annotations = _compat_module_1.annotations
    base64 = _compat_module_1.base64
    build_ezviz_local_sdk_ecdh_init_request_body = _compat_module_1.build_ezviz_local_sdk_ecdh_init_request_body
    copy_local_sdk_ecdh_stream_from_client = _compat_module_1.copy_local_sdk_ecdh_stream_from_client
    copy_local_sdk_ecdh_stream_to_media = _compat_module_1.copy_local_sdk_ecdh_stream_to_media
    copy_local_sdk_ecdh_stream_to_mpegps = _compat_module_1.copy_local_sdk_ecdh_stream_to_mpegps
    copy_local_stream_to_decrypted_mpegps = _compat_module_1.copy_local_stream_to_decrypted_mpegps
    copy_local_stream_to_decrypted_mpegts = _compat_module_1.copy_local_stream_to_decrypted_mpegts
    copy_local_stream_to_mpegts = _compat_module_1.copy_local_stream_to_mpegts
    dataclass = _compat_module_1.dataclass
    decrypt_ezviz_local_sdk_ecdh_data_packet = _compat_module_1.decrypt_ezviz_local_sdk_ecdh_data_packet
    derive_ezviz_local_sdk_ecdh_chacha20_key = _compat_module_1.derive_ezviz_local_sdk_ecdh_chacha20_key
    derive_ezviz_local_sdk_ecdh_shared_secret = _compat_module_1.derive_ezviz_local_sdk_ecdh_shared_secret
    ec = _compat_module_1.ec
    ezviz_local_sdk_ecdh_chacha20_nonce = _compat_module_1.ezviz_local_sdk_ecdh_chacha20_nonce
    field = _compat_module_1.field
    fresh_local_sdk_receiver_port = _compat_module_1.fresh_local_sdk_receiver_port
    generate_ezviz_local_sdk_ecdh_keypair = _compat_module_1.generate_ezviz_local_sdk_ecdh_keypair
    get_local_sdk_stream_credentials_from_client = _compat_module_1.get_local_sdk_stream_credentials_from_client
    has_positive_finite_capture_bound = _compat_module_1.has_positive_finite_capture_bound
    hashlib = _compat_module_1.hashlib
    hmac = _compat_module_1.hmac
    local_ecdh_media_packet_source = _compat_module_1.local_ecdh_media_packet_source
    local_ecdh_packet_to_media_packet = _compat_module_1.local_ecdh_packet_to_media_packet
    open_local_sdk_ecdh_stream = _compat_module_1.open_local_sdk_ecdh_stream
    open_local_sdk_ecdh_stream_from_client = _compat_module_1.open_local_sdk_ecdh_stream_from_client
    parse_ezviz_local_sdk_ecdh_data_packet = _compat_module_1.parse_ezviz_local_sdk_ecdh_data_packet
    parse_ezviz_local_sdk_ecdh_handshake_packet = _compat_module_1.parse_ezviz_local_sdk_ecdh_handshake_packet
    rtp_payload = _compat_module_1.rtp_payload
    serialization = _compat_module_1.serialization
    socket = _compat_module_1.socket
    time = _compat_module_1.time
    transform_ezviz_local_sdk_ecdh_nonce = _compat_module_1.transform_ezviz_local_sdk_ecdh_nonce
    uuid_module = _compat_module_1.uuid_module
    xml_escape = _compat_module_1.xml_escape
    zlib = _compat_module_1.zlib

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        AES,
        ChaCha20,
        _IDMX_RTP_SSRC,
        _MAX_UNRECOGNIZED_ECDH_MEDIA_RECORDS,
        LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET,
        LOCAL_SDK_ECDH_DATA_MARKER,
        LOCAL_SDK_ECDH_DATA_NONCE_OFFSET,
        LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH,
        LOCAL_SDK_ECDH_DATA_TYPE,
        LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION,
        LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
        LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH,
        LOCAL_SDK_ECDH_H264_SPS_3B,
        LOCAL_SDK_ECDH_H264_SPS_4B,
        LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET,
        LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_LENGTH,
        LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_MAGIC,
        LOCAL_SDK_ECDH_HANDSHAKE_MARKER,
        LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET,
        LOCAL_SDK_ECDH_HANDSHAKE_TYPE,
        LOCAL_SDK_ECDH_HEVC_VPS_3B,
        LOCAL_SDK_ECDH_HEVC_VPS_4B,
        LOCAL_SDK_ECDH_MAGIC,
        LOCAL_SDK_ECDH_MAX_PRE_KEYFRAME_BYTES,
        LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER,
        LOCAL_SDK_ECDH_NONCE_LENGTH,
        LOCAL_SDK_ECDH_PACKET_MARKER,
        LOCAL_SDK_ECDH_PACKET_WINDOW_SIZE,
        LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH,
        LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH,
        MAX_RETRIES,
        RTP_FIXED_HEADER_LENGTH,
        RTP_VERSION,
        Any,
        BinaryIO,
        Callable,
        EzvizCasDeviceInfo,
        EzvizInterleavedRtpFrameWithPrefix,
        EzvizLocalAuthenticationAttrs,
        EzvizLocalPreviewRequest,
        EzvizLocalReceiverInfoAttrs,
        EzvizLocalReceiverInfoExAttrs,
        EzvizLocalSdkClient,
        EzvizLocalSdkCredentials,
        EzvizLocalSdkDeadlineExpired,
        EzvizLocalSdkEcdhDataPacket,
        EzvizLocalSdkEcdhHandshakePacket,
        EzvizLocalSdkEcdhKeyPair,
        EzvizLocalSdkEcdhMediaStream,
        EzvizLocalSdkEcdhStreamDecoder,
        EzvizLocalSdkEcdhStreamPacket,
        EzvizLocalSdkStreamBootstrap,
        EzvizLocalSdkStreamClosed,
        EzvizUnsupportedMediaError,
        HcNetSdkLanEndpoint,
        Iterator,
        LegacyPacketSource,
        LocalSdkProtocolDetector,
        MediaPacket,
        MediaPacketMetadata,
        MediaPacketSourceAdapter,
        PyEzvizError,
        SocketFactory,
        UnsupportedAlgorithm,
        _BoundedEcdhMediaStream,
        _ezviz_local_sdk_ecdh_verification_input,
        _is_complete_ecdh_rtp_packet,
        _is_parseable_rtp_packet,
        _validate_ecdh_copy_options,
        _verify_ezviz_local_sdk_ecdh_packet,
        annotations,
        base64,
        build_ezviz_local_sdk_ecdh_init_request_body,
        copy_local_sdk_ecdh_stream_from_client,
        copy_local_sdk_ecdh_stream_to_media,
        copy_local_sdk_ecdh_stream_to_mpegps,
        copy_local_stream_to_decrypted_mpegps,
        copy_local_stream_to_decrypted_mpegts,
        copy_local_stream_to_mpegts,
        dataclass,
        decrypt_ezviz_local_sdk_ecdh_data_packet,
        derive_ezviz_local_sdk_ecdh_chacha20_key,
        derive_ezviz_local_sdk_ecdh_shared_secret,
        ec,
        ezviz_local_sdk_ecdh_chacha20_nonce,
        field,
        fresh_local_sdk_receiver_port,
        generate_ezviz_local_sdk_ecdh_keypair,
        get_local_sdk_stream_credentials_from_client,
        has_positive_finite_capture_bound,
        hashlib,
        hmac,
        local_ecdh_media_packet_source,
        local_ecdh_packet_to_media_packet,
        open_local_sdk_ecdh_stream,
        open_local_sdk_ecdh_stream_from_client,
        parse_ezviz_local_sdk_ecdh_data_packet,
        parse_ezviz_local_sdk_ecdh_handshake_packet,
        rtp_payload,
        serialization,
        socket,
        time,
        transform_ezviz_local_sdk_ecdh_nonce,
        uuid_module,
        xml_escape,
        zlib,
    )

sys.modules[__name__] = _implementation
