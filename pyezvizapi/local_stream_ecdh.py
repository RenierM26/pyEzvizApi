"""Local SDK ECDH/ChaCha20 LAN stream helpers.

Some EZVIZ local SDK streams use the normal command socket for preview setup,
then wrap media frames in an ECDH/ChaCha20 layer on the local stream socket.
The packet layout is backed by the APK native ``libezstreamclient`` ECDH
symbols and observed local stream traffic:

* the preview request includes an ECDH public key in ``<PublicKey>``
* the first media chunk contains a ``$\x01`` ECDH handshake packet
* subsequent channel-1 chunks contain ``$\x02`` encrypted data packets
* the packet nonce is the 4-byte wire nonce reversed, padded to 12 bytes
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
import socket
import time
from typing import Any, BinaryIO
import uuid as uuid_module
from xml.sax.saxutils import escape as xml_escape

from Crypto.Cipher import AES, ChaCha20
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .constants import MAX_RETRIES
from .exceptions import PyEzvizError
from .hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalAuthenticationAttrs,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    EzvizLocalReceiverInfoExAttrs,
    EzvizLocalSdkClient,
    EzvizLocalSdkStreamBootstrap,
    HcNetSdkLanEndpoint,
    SocketFactory,
)
from .local_stream import get_local_sdk_stream_credentials_from_client

LOCAL_SDK_ECDH_CONTROL_PORT = 9010
LOCAL_SDK_ECDH_STREAM_PORT = 9020
LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT = 10105
LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION = 10011

LOCAL_SDK_ECDH_MAGIC = 0x24
LOCAL_SDK_ECDH_HANDSHAKE_TYPE = 0x01
LOCAL_SDK_ECDH_DATA_TYPE = 0x02
LOCAL_SDK_ECDH_PACKET_MARKER = 0x01
LOCAL_SDK_ECDH_HANDSHAKE_MARKER = b"\x24\x01"
LOCAL_SDK_ECDH_DATA_MARKER = b"\x24\x02"
LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET = 0x0B
LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET = 0x2B
LOCAL_SDK_ECDH_DATA_NONCE_OFFSET = 0x07
LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET = 0x0B
LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH = 32
LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH = 91
LOCAL_SDK_ECDH_NONCE_LENGTH = 4
LOCAL_SDK_ECDH_CHACHA20_NONCE_LENGTH = 12
LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH = 32
LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH = 4

LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER = b"\x00\x00\x01\xba"
LOCAL_SDK_ECDH_HEVC_VPS_4B = b"\x00\x00\x00\x01\x40\x01"
LOCAL_SDK_ECDH_HEVC_VPS_3B = b"\x00\x00\x01\x40\x01"
LOCAL_SDK_ECDH_H264_SPS_4B = b"\x00\x00\x00\x01\x67"
LOCAL_SDK_ECDH_H264_SPS_3B = b"\x00\x00\x01\x67"
LOCAL_SDK_ECDH_MAX_PACK_LOOKBACK_BEFORE_KEYFRAME = 64 * 1024
LOCAL_SDK_ECDH_MAX_PRE_KEYFRAME_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class EzvizLocalSdkEcdhKeyPair:
    """Ephemeral ECDH key pair for local SDK ECDH stream setup."""

    private_key: Any = field(repr=False)
    public_key_der: bytes
    public_key_b64: str


@dataclass(frozen=True)
class EzvizLocalSdkEcdhHandshakePacket:
    """Parsed ``$\x01`` ECDH handshake packet."""

    header_length: int
    payload_length: int
    subtype: int
    nonce_raw: bytes = field(repr=False)
    encrypted_key: bytes = field(repr=False)
    peer_public_key_der: bytes = field(repr=False)
    packet_offset: int


@dataclass(frozen=True)
class EzvizLocalSdkEcdhDataPacket:
    """Parsed ``$\x02`` encrypted data packet."""

    payload_length: int
    subtype: int
    nonce_raw: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    trailer: bytes = field(repr=False)
    outer_prefix: bytes = field(repr=False)


@dataclass(frozen=True)
class EzvizLocalSdkEcdhStreamPacket:
    """Decoded local SDK ECDH stream payload."""

    channel: int
    body: bytes = field(repr=False)

    @property
    def length(self) -> int:
        """Return the decoded payload length."""
        return len(self.body)


def generate_ezviz_local_sdk_ecdh_keypair() -> EzvizLocalSdkEcdhKeyPair:
    """Generate an APK-compatible P-256 ECDH key pair for ``<PublicKey>``."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return EzvizLocalSdkEcdhKeyPair(
        private_key=private_key,
        public_key_der=public_key_der,
        public_key_b64=base64.b64encode(public_key_der).decode("ascii"),
    )


def parse_ezviz_local_sdk_ecdh_handshake_packet(
    data: bytes,
) -> EzvizLocalSdkEcdhHandshakePacket | None:
    """Parse a local SDK ECDH ``$\x01`` handshake packet from a media payload."""
    packet_offset = data.find(LOCAL_SDK_ECDH_HANDSHAKE_MARKER)
    if packet_offset < 0:
        return None

    packet = data[packet_offset:]
    if len(packet) < LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET:
        return None
    if packet[0] != LOCAL_SDK_ECDH_MAGIC or packet[1] != LOCAL_SDK_ECDH_HANDSHAKE_TYPE:
        return None
    if len(packet) > 5 and packet[5] != LOCAL_SDK_ECDH_PACKET_MARKER:
        return None

    header_length = packet[2]
    encrypted_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET + header_length
    peer_public_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET + header_length
    peer_public_key_end = peer_public_key_offset + LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH
    encrypted_key_end = encrypted_key_offset + LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH
    if len(packet) < max(encrypted_key_end, peer_public_key_end):
        return None

    payload_length = int.from_bytes(packet[3:5], "big")
    return EzvizLocalSdkEcdhHandshakePacket(
        header_length=header_length,
        payload_length=payload_length,
        subtype=packet[6] if len(packet) > 6 else 0,
        nonce_raw=packet[7:11],
        encrypted_key=packet[encrypted_key_offset:encrypted_key_end],
        peer_public_key_der=packet[peer_public_key_offset:peer_public_key_end],
        packet_offset=packet_offset,
    )


def parse_ezviz_local_sdk_ecdh_data_packet(data: bytes) -> EzvizLocalSdkEcdhDataPacket | None:
    """Parse a local SDK ECDH ``$\x02`` encrypted data packet.

    The media payload usually has a 4-byte outer prefix before the inner ECDH
    packet.  Tests and live traces also accept a bare inner packet for easier
    fixture construction.
    """
    outer_prefix = b""
    packet = data
    if not packet.startswith(LOCAL_SDK_ECDH_DATA_MARKER):
        if len(packet) < LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH + 2:
            return None
        candidate = packet[LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH:]
        if not candidate.startswith(LOCAL_SDK_ECDH_DATA_MARKER):
            return None
        outer_prefix = packet[:LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH]
        packet = candidate

    if len(packet) < LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH:
        return None
    if packet[0] != LOCAL_SDK_ECDH_MAGIC or packet[1] != LOCAL_SDK_ECDH_DATA_TYPE:
        return None

    payload_length = int.from_bytes(packet[3:5], "big")
    ciphertext_offset = LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET
    ciphertext_end = ciphertext_offset + payload_length
    if len(packet) < ciphertext_end + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH:
        return None
    ciphertext = packet[ciphertext_offset:ciphertext_end]
    trailer = packet[ciphertext_end : ciphertext_end + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH]
    return EzvizLocalSdkEcdhDataPacket(
        payload_length=payload_length,
        subtype=packet[6],
        nonce_raw=packet[
            LOCAL_SDK_ECDH_DATA_NONCE_OFFSET : LOCAL_SDK_ECDH_DATA_NONCE_OFFSET
            + LOCAL_SDK_ECDH_NONCE_LENGTH
        ],
        ciphertext=ciphertext,
        trailer=trailer,
        outer_prefix=outer_prefix,
    )


def transform_ezviz_local_sdk_ecdh_nonce(nonce_raw: bytes) -> bytes:
    """Return the native local SDK ECDH 4-byte ChaCha20 nonce prefix."""
    if len(nonce_raw) != LOCAL_SDK_ECDH_NONCE_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH nonce must be 4 bytes")
    return nonce_raw[::-1]


def ezviz_local_sdk_ecdh_chacha20_nonce(nonce_raw: bytes) -> bytes:
    """Build the 12-byte ChaCha20 nonce used for each local SDK ECDH packet."""
    return transform_ezviz_local_sdk_ecdh_nonce(nonce_raw) + b"\x00" * 8


def derive_ezviz_local_sdk_ecdh_shared_secret(
    private_key: Any,
    peer_public_key_der: bytes,
) -> bytes:
    """Compute the raw ECDH P-256 shared secret."""
    peer_public_key = serialization.load_der_public_key(peer_public_key_der)
    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise PyEzvizError("EZVIZ local SDK ECDH peer public key is not elliptic-curve")
    return private_key.exchange(ec.ECDH(), peer_public_key)


def derive_ezviz_local_sdk_ecdh_chacha20_key(
    shared_secret: bytes,
    encrypted_key: bytes,
) -> bytes:
    """Decrypt the local SDK ECDH ChaCha20 session key with AES-256-ECB."""
    if len(shared_secret) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH shared secret must be 32 bytes")
    if len(encrypted_key) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH encrypted session key must be 32 bytes")
    return AES.new(shared_secret, AES.MODE_ECB).decrypt(encrypted_key)


def decrypt_ezviz_local_sdk_ecdh_data_packet(
    chacha20_key: bytes,
    packet: EzvizLocalSdkEcdhDataPacket,
) -> bytes:
    """Decrypt a parsed local SDK ECDH data packet."""
    if len(chacha20_key) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH ChaCha20 key must be 32 bytes")
    return ChaCha20.new(
        key=chacha20_key,
        nonce=ezviz_local_sdk_ecdh_chacha20_nonce(packet.nonce_raw),
    ).decrypt(packet.ciphertext)


class EzvizLocalSdkEcdhStreamDecoder:
    """Incremental local SDK ECDH media decoder for interleaved stream chunks."""

    def __init__(
        self,
        private_key: Any,
        *,
        data_channel: int = 1,
        require_keyframe: bool = True,
        max_pre_keyframe_bytes: int = LOCAL_SDK_ECDH_MAX_PRE_KEYFRAME_BYTES,
    ) -> None:
        self.private_key = private_key
        self.data_channel = data_channel
        self.require_keyframe = require_keyframe
        self.max_pre_keyframe_bytes = max_pre_keyframe_bytes
        self._chacha20_key: bytes | None = None
        self._mpeg_started = False
        self._pending = bytearray()

    @property
    def keys_derived(self) -> bool:
        """Return whether the handshake has yielded a ChaCha20 key."""
        return self._chacha20_key is not None

    def feed_interleaved_frame(
        self,
        frame: EzvizInterleavedRtpFrameWithPrefix,
    ) -> bytes:
        """Feed one local SDK media frame and return decoded MPEG-PS bytes."""
        return self.feed_payload(frame.frame.header.channel, frame.frame.payload)

    def feed_payload(self, channel: int, payload: bytes) -> bytes:
        """Feed one local SDK ECDH media payload and return decoded MPEG-PS bytes."""
        if self._chacha20_key is None:
            handshake = parse_ezviz_local_sdk_ecdh_handshake_packet(payload)
            if handshake is None:
                return b""
            shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
                self.private_key,
                handshake.peer_public_key_der,
            )
            self._chacha20_key = derive_ezviz_local_sdk_ecdh_chacha20_key(
                shared_secret,
                handshake.encrypted_key,
            )
            return b""

        if channel != self.data_channel:
            return b""
        packet = parse_ezviz_local_sdk_ecdh_data_packet(payload)
        if packet is None:
            return b""
        plain = decrypt_ezviz_local_sdk_ecdh_data_packet(self._chacha20_key, packet)
        return self._absorb_plain(plain)

    @staticmethod
    def _find_keyframe(data: bytes) -> int:
        candidates = (
            data.find(LOCAL_SDK_ECDH_HEVC_VPS_4B),
            data.find(LOCAL_SDK_ECDH_HEVC_VPS_3B),
            data.find(LOCAL_SDK_ECDH_H264_SPS_4B),
            data.find(LOCAL_SDK_ECDH_H264_SPS_3B),
        )
        valid = [candidate for candidate in candidates if candidate >= 0]
        return min(valid) if valid else -1

    def _absorb_plain(self, plain: bytes) -> bytes:
        if not plain:
            return b""
        if self._mpeg_started or not self.require_keyframe:
            self._mpeg_started = True
            return plain

        self._pending.extend(plain)
        buffered = bytes(self._pending)
        keyframe_offset = self._find_keyframe(buffered)
        if keyframe_offset >= 0:
            pack_offset = buffered.rfind(LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER, 0, keyframe_offset)
            if (
                pack_offset >= 0
                and keyframe_offset - pack_offset <= LOCAL_SDK_ECDH_MAX_PACK_LOOKBACK_BEFORE_KEYFRAME
            ):
                start = pack_offset
            else:
                start = keyframe_offset
            self._mpeg_started = True
            self._pending.clear()
            return buffered[start:]

        if len(self._pending) > self.max_pre_keyframe_bytes:
            self._mpeg_started = True
            out = bytes(self._pending)
            self._pending.clear()
            return out
        return b""


class EzvizLocalSdkEcdhMediaStream:
    """Local SDK media stream that decrypts ECDH/ChaCha20 frames."""

    def __init__(
        self,
        sdk_client: EzvizLocalSdkClient,
        preview_request: EzvizLocalPreviewRequest,
        key_pair: EzvizLocalSdkEcdhKeyPair,
        *,
        pre_start_body: bytes | str | None = None,
        pre_start_sequence: int = 0,
        preview_sequence: int = 0,
        stream_setup_sequence: int = 0,
        stream_rate: str | int = 1,
        stream_mode: str | int = -1,
        max_prefix_bytes: int = 4096,
    ) -> None:
        self.sdk_client = sdk_client
        self.preview_request = preview_request
        self.key_pair = key_pair
        self.pre_start_body = pre_start_body
        self.pre_start_sequence = pre_start_sequence
        self.preview_sequence = preview_sequence
        self.stream_setup_sequence = stream_setup_sequence
        self.stream_rate = stream_rate
        self.stream_mode = stream_mode
        self.max_prefix_bytes = max_prefix_bytes
        self.decoder = EzvizLocalSdkEcdhStreamDecoder(key_pair.private_key)
        self.bootstrap: EzvizLocalSdkStreamBootstrap | None = None
        self._first_media: EzvizInterleavedRtpFrameWithPrefix | None = None

    def __enter__(self) -> EzvizLocalSdkEcdhMediaStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying local SDK sockets."""
        self.sdk_client.close()

    def start(self) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap local SDK ECDH preview setup and read the first media frame."""
        self.bootstrap = self.sdk_client.bootstrap_preview_from_fields(
            preview_request=self.preview_request,
            pre_start_body=self.pre_start_body,
            pre_start_sequence=self.pre_start_sequence,
            preview_sequence=self.preview_sequence,
            stream_setup_sequence=self.stream_setup_sequence,
            stream_rate=self.stream_rate,
            stream_mode=self.stream_mode,
            read_first_media=True,
            max_prefix_bytes=self.max_prefix_bytes,
        )
        self._first_media = self.bootstrap.first_media
        if self._first_media is None:
            raise PyEzvizError("EZVIZ local SDK ECDH stream did not return a first media frame")
        return self.bootstrap

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
        max_frames: int | None = None,
        duration_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[EzvizLocalSdkEcdhStreamPacket]:
        """Yield decoded local SDK ECDH MPEG-PS payloads."""
        if max_packets is not None and max_packets <= 0:
            return
        if max_frames is not None and max_frames <= 0:
            return
        if duration_seconds is not None and duration_seconds <= 0:
            return
        deadline = monotonic() + duration_seconds if duration_seconds is not None else None
        if self.bootstrap is None:
            self.start()

        emitted = 0
        read_frames = 0
        if self._first_media is not None:
            read_frames += 1
            body = self.decoder.feed_interleaved_frame(self._first_media)
            self._first_media = None
            if body:
                emitted += 1
                yield EzvizLocalSdkEcdhStreamPacket(channel=1, body=body)

        while (max_packets is None or emitted < max_packets) and (
            max_frames is None or read_frames < max_frames
        ):
            if deadline is not None and monotonic() >= deadline:
                break
            media = self.sdk_client.read_stream_frame_after_prefix(
                max_prefix_bytes=self.max_prefix_bytes,
            )
            read_frames += 1
            body = self.decoder.feed_interleaved_frame(media)
            if body:
                emitted += 1
                yield EzvizLocalSdkEcdhStreamPacket(channel=media.frame.header.channel, body=body)


def build_ezviz_local_sdk_ecdh_init_request_body(
    *,
    operation_code: str,
    session: str | int = LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION,
) -> bytes:
    """Build the local SDK ECDH 0x2013 INIT request body."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<Request>\n"
        f"\t<OperationCode>{xml_escape(str(operation_code))}</OperationCode>\n"
        f"\t<Session>{xml_escape(str(session))}</Session>\n"
        "</Request>\n"
    ).encode()


def open_local_sdk_ecdh_stream(  # noqa: PLR0913
    endpoint: HcNetSdkLanEndpoint,
    device_info: EzvizCasDeviceInfo,
    *,
    key_pair: EzvizLocalSdkEcdhKeyPair | None = None,
    channel: int = 1,
    receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    send_init: bool = False,
    pre_start_sequence: int | None = None,
    preview_sequence: int | None = None,
    stream_setup_sequence: int | None = None,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    timeout: float | None = 5.0,
    socket_factory: SocketFactory | None = None,
    max_prefix_bytes: int = 4096,
) -> EzvizLocalSdkEcdhMediaStream:
    """Open a local SDK ECDH stream from caller-supplied LAN credentials.

    Some firmware sends a 0x2013 INIT before preview setup.  Other local SDK
    ECDH paths can reject that pre-start command, so callers opt in with
    ``send_init=True`` only when their device needs it.
    """
    key_pair = key_pair or generate_ezviz_local_sdk_ecdh_keypair()
    resolved_pre_start_sequence = (
        pre_start_sequence if pre_start_sequence is not None else (1 if send_init else 0)
    )
    resolved_preview_sequence = (
        preview_sequence if preview_sequence is not None else (2 if send_init else 1)
    )
    resolved_stream_setup_sequence = (
        stream_setup_sequence if stream_setup_sequence is not None else (3 if send_init else 2)
    )
    preview_request = EzvizLocalPreviewRequest(
        operation_code=device_info.operation_code,
        channel=channel,
        receiver_info=EzvizLocalReceiverInfoAttrs(
            port=receiver_port,
            stream_type="MAIN",
            server_type=1,
            new_stream_type=1,
            trans_proto="TCP",
        ),
        receiver_info_ex=EzvizLocalReceiverInfoExAttrs(port=receiver_port),
        authentication=EzvizLocalAuthenticationAttrs(),
        is_encrypt="TRUE",
        uuid=str(uuid_module.uuid4()),
        timestamp=int(time.time() * 1000),
        public_key=key_pair.public_key_b64,
    )
    pre_start_body = (
        build_ezviz_local_sdk_ecdh_init_request_body(
            operation_code=device_info.operation_code,
            session=LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION,
        )
        if send_init
        else None
    )
    sdk_client = EzvizLocalSdkClient(
        endpoint,
        device_info,
        timeout=timeout,
        socket_factory=socket_factory or socket.create_connection,
        command_source_port=receiver_port,
    )
    return EzvizLocalSdkEcdhMediaStream(
        sdk_client,
        preview_request,
        key_pair,
        pre_start_body=pre_start_body,
        pre_start_sequence=resolved_pre_start_sequence,
        preview_sequence=resolved_preview_sequence,
        stream_setup_sequence=resolved_stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        max_prefix_bytes=max_prefix_bytes,
    )


def open_local_sdk_ecdh_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    *,
    cas_serial: str | None = None,
    key_pair: EzvizLocalSdkEcdhKeyPair | None = None,
    channel: int = 1,
    receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    send_init: bool = False,
    pre_start_sequence: int | None = None,
    preview_sequence: int | None = None,
    stream_setup_sequence: int | None = None,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    timeout: float | None = 5.0,
    socket_factory: SocketFactory | None = None,
    max_prefix_bytes: int = 4096,
) -> EzvizLocalSdkEcdhMediaStream:
    """Open a local SDK ECDH stream using an ``EzvizClient`` credential source."""
    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        fetch_media_key=False,
        register_p2p_session=register_p2p_session,
        p2p_register_max_retries=p2p_register_max_retries,
    )
    return open_local_sdk_ecdh_stream(
        credentials.endpoint,
        credentials.device_info,
        key_pair=key_pair,
        channel=channel,
        receiver_port=receiver_port,
        send_init=send_init,
        pre_start_sequence=pre_start_sequence,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        timeout=timeout,
        socket_factory=socket_factory,
        max_prefix_bytes=max_prefix_bytes,
    )


def copy_local_sdk_ecdh_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    cas_serial: str | None = None,
    channel: int = 1,
    receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    send_init: bool = False,
    pre_start_sequence: int | None = None,
    preview_sequence: int | None = None,
    stream_setup_sequence: int | None = None,
    stream_rate: str | int = 1,
    stream_mode: str | int = -1,
    register_p2p_session: bool = True,
    p2p_register_max_retries: int = MAX_RETRIES,
    timeout: float | None = 5.0,
    socket_factory: SocketFactory | None = None,
    max_prefix_bytes: int = 4096,
    max_packets: int | None = None,
    max_frames: int | None = None,
    duration_seconds: float | None = None,
) -> None:
    """Write decoded local SDK ECDH MPEG-PS bytes using an ``EzvizClient``."""
    with open_local_sdk_ecdh_stream_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        channel=channel,
        receiver_port=receiver_port,
        send_init=send_init,
        pre_start_sequence=pre_start_sequence,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        register_p2p_session=register_p2p_session,
        p2p_register_max_retries=p2p_register_max_retries,
        timeout=timeout,
        socket_factory=socket_factory,
        max_prefix_bytes=max_prefix_bytes,
    ) as stream:
        copy_local_sdk_ecdh_stream_to_mpegps(
            stream,
            output,
            max_packets=max_packets,
            max_frames=max_frames,
            duration_seconds=duration_seconds,
        )


def copy_local_sdk_ecdh_stream_to_mpegps(
    stream: EzvizLocalSdkEcdhMediaStream,
    output: BinaryIO,
    *,
    max_packets: int | None = None,
    max_frames: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Write decoded local SDK ECDH MPEG-PS payloads to ``output``."""
    for packet in stream.iter_packets(
        max_packets=max_packets,
        max_frames=max_frames,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    ):
        output.write(packet.body)
