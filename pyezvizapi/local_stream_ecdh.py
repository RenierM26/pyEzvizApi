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
import hashlib
import hmac
import socket
import time
from typing import Any, BinaryIO
import uuid as uuid_module
from xml.sax.saxutils import escape as xml_escape
import zlib

from Crypto.Cipher import AES, ChaCha20
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .constants import (
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
)
from .exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
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
from .local_stream import (
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegts,
    get_local_sdk_stream_credentials_from_client,
)


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
    ciphertext: bytes = field(repr=False)
    trailer: bytes = field(repr=False)
    authenticated_header: bytes = field(repr=False)
    outer_prefix: bytes = field(repr=False)
    packet_offset: int


@dataclass(frozen=True)
class EzvizLocalSdkEcdhDataPacket:
    """Parsed ``$\x02`` encrypted data packet."""

    header_length: int
    payload_length: int
    subtype: int
    nonce_raw: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    trailer: bytes = field(repr=False)
    authenticated_header: bytes = field(repr=False)
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


def parse_ezviz_local_sdk_ecdh_handshake_packet(  # noqa: PLR0911
    data: bytes,
) -> EzvizLocalSdkEcdhHandshakePacket | None:
    """Parse a local SDK ECDH ``$\x01`` handshake packet from a media payload."""
    packet_offsets: tuple[int, ...] = (0, LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH)
    if data.startswith(LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_MAGIC):
        packet_offsets += (LOCAL_SDK_ECDH_HANDSHAKE_ENVELOPE_LENGTH,)
    packet_offset = next(
        (
            offset
            for offset in packet_offsets
            if data[offset:].startswith(LOCAL_SDK_ECDH_HANDSHAKE_MARKER)
        ),
        None,
    )
    if packet_offset is None:
        return None

    packet = data[packet_offset:]
    if len(packet) < LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET:
        return None
    if packet[0] != LOCAL_SDK_ECDH_MAGIC or packet[1] != LOCAL_SDK_ECDH_HANDSHAKE_TYPE:
        return None

    header_length = packet[2]
    header_base = header_length
    encrypted_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET + header_base
    peer_public_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET + header_base
    peer_public_key_end = peer_public_key_offset + LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH
    encrypted_key_end = encrypted_key_offset + LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH
    if len(packet) < peer_public_key_end + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH:
        return None
    if packet[header_base + 5] != LOCAL_SDK_ECDH_PACKET_MARKER:
        return None
    payload_length = int.from_bytes(packet[header_base + 3 : header_base + 5], "big")
    ciphertext_end = peer_public_key_end + payload_length
    packet_end = ciphertext_end + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH
    if len(packet) != packet_end:
        return None
    return EzvizLocalSdkEcdhHandshakePacket(
        header_length=header_length,
        payload_length=payload_length,
        subtype=packet[header_base + 6],
        nonce_raw=packet[header_base + 7 : header_base + 11],
        encrypted_key=packet[encrypted_key_offset:encrypted_key_end],
        peer_public_key_der=packet[peer_public_key_offset:peer_public_key_end],
        ciphertext=packet[peer_public_key_end:ciphertext_end],
        trailer=packet[ciphertext_end:packet_end],
        authenticated_header=packet[:peer_public_key_end],
        outer_prefix=data[:packet_offset],
        packet_offset=packet_offset,
    )


def parse_ezviz_local_sdk_ecdh_data_packet(  # noqa: PLR0911
    data: bytes,
) -> EzvizLocalSdkEcdhDataPacket | None:
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

    header_length = packet[2]
    header_base = header_length
    ciphertext_offset = LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET + header_base
    if len(packet) < ciphertext_offset + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH:
        return None
    payload_length = int.from_bytes(packet[header_base + 3 : header_base + 5], "big")
    ciphertext_end = ciphertext_offset + payload_length
    packet_end = ciphertext_end + LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH
    if len(packet) != packet_end:
        return None
    ciphertext = packet[ciphertext_offset:ciphertext_end]
    trailer = packet[ciphertext_end:packet_end]
    return EzvizLocalSdkEcdhDataPacket(
        header_length=header_length,
        payload_length=payload_length,
        subtype=packet[header_base + 6],
        nonce_raw=packet[
            LOCAL_SDK_ECDH_DATA_NONCE_OFFSET + header_base : LOCAL_SDK_ECDH_DATA_NONCE_OFFSET
            + header_base
            + LOCAL_SDK_ECDH_NONCE_LENGTH
        ],
        ciphertext=ciphertext,
        trailer=trailer,
        authenticated_header=packet[:ciphertext_offset],
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
    try:
        peer_public_key = serialization.load_der_public_key(peer_public_key_der)
    except (UnsupportedAlgorithm, ValueError) as err:
        raise PyEzvizError("EZVIZ local SDK ECDH peer public key is invalid") from err
    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise PyEzvizError("EZVIZ local SDK ECDH peer public key is not elliptic-curve")
    try:
        return private_key.exchange(ec.ECDH(), peer_public_key)
    except (UnsupportedAlgorithm, ValueError) as err:
        raise PyEzvizError(
            "EZVIZ local SDK ECDH peer public key is incompatible"
        ) from err


def derive_ezviz_local_sdk_ecdh_chacha20_key(
    shared_secret: bytes,
    encrypted_key: bytes,
) -> bytes:
    """Decrypt the local SDK ECDH ChaCha20 session key with AES-256-ECB."""
    if len(shared_secret) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH shared secret must be 32 bytes")
    if len(encrypted_key) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH encrypted session key must be 32 bytes")
    # codeql[py/weak-cryptographic-algorithm]
    cipher = AES.new(
        shared_secret,
        AES.MODE_ECB,
    )
    # codeql[py/weak-cryptographic-algorithm]
    return cipher.decrypt(encrypted_key)


def _ezviz_local_sdk_ecdh_verification_input(
    authenticated_header: bytes,
    ciphertext: bytes,
) -> bytes:
    """Build the native eight-byte HMAC input from the two packet CRC32s."""
    crc_text = f"{zlib.crc32(authenticated_header)}{zlib.crc32(ciphertext)}".encode()
    # The Android native library passes exactly eight bytes to HMAC-SHA256,
    # including NUL padding when the decimal CRC text is shorter.  Keep this
    # wire-compatible rather than silently strengthening a protocol peer
    # would not be able to reproduce.
    return crc_text[:8].ljust(8, b"\x00")


def _verify_ezviz_local_sdk_ecdh_packet(
    key: bytes,
    authenticated_header: bytes,
    ciphertext: bytes,
    trailer: bytes,
) -> None:
    """Verify the native HMAC-SHA256 packet trailer before decryption."""
    if len(key) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH verification key must be 32 bytes")
    expected = hmac.new(
        key,
        _ezviz_local_sdk_ecdh_verification_input(authenticated_header, ciphertext),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(trailer, expected):
        raise PyEzvizError("EZVIZ local SDK ECDH packet authentication failed")


def decrypt_ezviz_local_sdk_ecdh_data_packet(
    chacha20_key: bytes,
    packet: EzvizLocalSdkEcdhDataPacket,
) -> bytes:
    """Authenticate and decrypt a parsed local SDK ECDH data packet."""
    if len(chacha20_key) != LOCAL_SDK_ECDH_ENCRYPTED_KEY_LENGTH:
        raise PyEzvizError("EZVIZ local SDK ECDH ChaCha20 key must be 32 bytes")
    _verify_ezviz_local_sdk_ecdh_packet(
        chacha20_key,
        packet.authenticated_header,
        packet.ciphertext,
        packet.trailer,
    )
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
        self._highest_sequence: int | None = None
        self._seen_sequences: set[int] = set()

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
            _verify_ezviz_local_sdk_ecdh_packet(
                shared_secret,
                handshake.authenticated_header,
                handshake.ciphertext,
                handshake.trailer,
            )
            chacha20_key = derive_ezviz_local_sdk_ecdh_chacha20_key(
                shared_secret, handshake.encrypted_key
            )
            self._chacha20_key = chacha20_key
            if not handshake.ciphertext:
                return b""
            plain = ChaCha20.new(
                key=chacha20_key,
                nonce=ezviz_local_sdk_ecdh_chacha20_nonce(handshake.nonce_raw),
            ).decrypt(handshake.ciphertext)
            return self._absorb_plain(plain)

        if channel != self.data_channel:
            return b""
        packet = parse_ezviz_local_sdk_ecdh_data_packet(payload)
        if packet is None:
            return b""
        plain = decrypt_ezviz_local_sdk_ecdh_data_packet(self._chacha20_key, packet)
        self._record_sequence(packet.nonce_raw)
        return self._absorb_plain(plain)

    def _record_sequence(self, nonce_raw: bytes) -> None:
        """Apply the native four-packet acceptance window to an authenticated packet."""
        sequence = int.from_bytes(nonce_raw, "big")
        if sequence == 0:
            raise PyEzvizError("EZVIZ local SDK ECDH packet sequence is zero")
        if self._highest_sequence is None:
            self._highest_sequence = sequence
            self._seen_sequences = {sequence}
            return

        highest = self._highest_sequence
        if sequence > highest:
            self._highest_sequence = sequence
            self._seen_sequences = {
                seen
                for seen in self._seen_sequences
                if sequence - seen < LOCAL_SDK_ECDH_PACKET_WINDOW_SIZE
            }
        elif highest - sequence >= LOCAL_SDK_ECDH_PACKET_WINDOW_SIZE:
            raise PyEzvizError("EZVIZ local SDK ECDH packet sequence is outside the window")
        elif sequence in self._seen_sequences:
            raise PyEzvizError("EZVIZ local SDK ECDH packet sequence was replayed")
        self._seen_sequences.add(sequence)

    @staticmethod
    def _find_keyframe(data: bytes, start: int = 0) -> int:
        candidates = (
            data.find(LOCAL_SDK_ECDH_HEVC_VPS_4B, start),
            data.find(LOCAL_SDK_ECDH_HEVC_VPS_3B, start),
            data.find(LOCAL_SDK_ECDH_H264_SPS_4B, start),
            data.find(LOCAL_SDK_ECDH_H264_SPS_3B, start),
        )
        valid = [candidate for candidate in candidates if candidate >= 0]
        return min(valid) if valid else -1

    def _absorb_plain(self, plain: bytes) -> bytes:
        if not plain:
            return b""
        if len(plain) >= 12 and plain[0] >> 6 == 2:
            # Some ECDH devices return one complete IDMX/RTP packet per
            # authenticated ChaCha20 record. Preserve that packet boundary for
            # the IDMX demux/media-key layer instead of buffering for MPEG-PS.
            return plain
        if self._mpeg_started or not self.require_keyframe:
            self._mpeg_started = True
            return plain

        self._pending.extend(plain)
        buffered = bytes(self._pending)
        first_pack_offset = buffered.find(LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER)
        if first_pack_offset >= 0:
            keyframe_offset = self._find_keyframe(
                buffered,
                first_pack_offset + len(LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER),
            )
            if keyframe_offset >= 0:
                pack_offset = buffered.rfind(
                    LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER, 0, keyframe_offset
                )
                self._mpeg_started = True
                self._pending.clear()
                return buffered[pack_offset:]

        if len(self._pending) > self.max_pre_keyframe_bytes:
            self._pending.clear()
            raise PyEzvizError(
                "EZVIZ local SDK ECDH stream did not contain an MPEG-PS pack "
                "header followed by an H.264/HEVC keyframe within the configured limit"
            )
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
        self.media_key: str | bytes | None = None
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

    def start(
        self,
        *,
        read_first_media: bool = True,
    ) -> EzvizLocalSdkStreamBootstrap:
        """Bootstrap local SDK ECDH preview setup."""
        self.bootstrap = self.sdk_client.bootstrap_preview_from_fields(
            preview_request=self.preview_request,
            pre_start_body=self.pre_start_body,
            pre_start_sequence=self.pre_start_sequence,
            preview_sequence=self.preview_sequence,
            stream_setup_sequence=self.stream_setup_sequence,
            stream_rate=self.stream_rate,
            stream_mode=self.stream_mode,
            read_first_media=read_first_media,
            max_prefix_bytes=self.max_prefix_bytes,
        )
        self._first_media = self.bootstrap.first_media if read_first_media else None
        if read_first_media and self._first_media is None:
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
            self.start(read_first_media=deadline is None)

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
            remaining = None
            if deadline is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    break
            try:
                media = self.sdk_client.read_stream_frame_after_prefix(
                    max_prefix_bytes=self.max_prefix_bytes,
                    timeout=remaining,
                )
            except EzvizLocalSdkDeadlineExpired:
                break
            read_frames += 1
            body = self.decoder.feed_interleaved_frame(media)
            if body:
                emitted += 1
                yield EzvizLocalSdkEcdhStreamPacket(channel=media.frame.header.channel, body=body)


@dataclass
class _BoundedEcdhMediaStream:
    """Adapt ECDH input-frame/deadline bounds to generic media helpers."""

    stream: EzvizLocalSdkEcdhMediaStream
    max_frames: int | None
    duration_seconds: float | None
    monotonic: Callable[[], float] = time.monotonic

    def iter_packets(
        self,
        *,
        max_packets: int | None = None,
    ) -> Iterator[EzvizLocalSdkEcdhStreamPacket]:
        return self.stream.iter_packets(
            max_packets=max_packets,
            max_frames=self.max_frames,
            duration_seconds=self.duration_seconds,
            monotonic=self.monotonic,
        )


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
    identifier: str | None = None,
    uuid: str | None = None,
    timestamp: str | int | None = None,
    send_init: bool = False,
    pre_start_body: bytes | str | None = None,
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
    ``send_init=True`` only when their device needs it. A caller-supplied
    ``pre_start_body`` takes precedence over the generated INIT body.
    """
    key_pair = key_pair or generate_ezviz_local_sdk_ecdh_keypair()
    has_pre_start = pre_start_body is not None or send_init
    resolved_pre_start_sequence = (
        pre_start_sequence if pre_start_sequence is not None else (1 if has_pre_start else 0)
    )
    resolved_preview_sequence = (
        preview_sequence if preview_sequence is not None else (2 if has_pre_start else 1)
    )
    resolved_stream_setup_sequence = (
        stream_setup_sequence
        if stream_setup_sequence is not None
        else (3 if has_pre_start else 2)
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
        identifier=identifier,
        uuid=uuid if uuid is not None else str(uuid_module.uuid4()),
        timestamp=timestamp if timestamp is not None else int(time.time() * 1000),
        public_key=key_pair.public_key_b64,
    )
    resolved_pre_start_body = pre_start_body
    if resolved_pre_start_body is None and send_init:
        resolved_pre_start_body = build_ezviz_local_sdk_ecdh_init_request_body(
            operation_code=device_info.operation_code,
            session=LOCAL_SDK_ECDH_DEFAULT_INIT_SESSION,
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
        pre_start_body=resolved_pre_start_body,
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
    identifier: str | None = None,
    uuid: str | None = None,
    timestamp: str | int | None = None,
    send_init: bool = False,
    pre_start_body: bytes | str | None = None,
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
    fetch_media_key: bool = False,
    smscode: str | int | None = None,
) -> EzvizLocalSdkEcdhMediaStream:
    """Open a local SDK ECDH stream using an ``EzvizClient`` credential source."""
    credential_options: dict[str, Any] = {
        "cas_serial": cas_serial,
        "fetch_media_key": fetch_media_key,
        "register_p2p_session": register_p2p_session,
        "p2p_register_max_retries": p2p_register_max_retries,
    }
    if smscode is not None:
        credential_options["smscode"] = smscode
    credentials = get_local_sdk_stream_credentials_from_client(
        client,
        serial,
        **credential_options,
    )
    stream = open_local_sdk_ecdh_stream(
        credentials.endpoint,
        credentials.device_info,
        key_pair=key_pair,
        channel=channel,
        receiver_port=receiver_port,
        identifier=identifier,
        uuid=uuid,
        timestamp=timestamp,
        send_init=send_init,
        pre_start_body=pre_start_body,
        pre_start_sequence=pre_start_sequence,
        preview_sequence=preview_sequence,
        stream_setup_sequence=stream_setup_sequence,
        stream_rate=stream_rate,
        stream_mode=stream_mode,
        timeout=timeout,
        socket_factory=socket_factory,
        max_prefix_bytes=max_prefix_bytes,
    )
    stream.media_key = credentials.media_key
    return stream


def copy_local_sdk_ecdh_stream_from_client(  # noqa: PLR0913
    client: Any,
    serial: str,
    output: BinaryIO,
    *,
    cas_serial: str | None = None,
    channel: int = 1,
    receiver_port: int = LOCAL_SDK_ECDH_DEFAULT_RECEIVER_PORT,
    identifier: str | None = None,
    uuid: str | None = None,
    timestamp: str | int | None = None,
    send_init: bool = False,
    pre_start_body: bytes | str | None = None,
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
    output_format: str = "mpegps",
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    ffmpeg_path: str = "ffmpeg",
    nalu_header_size: int | None = None,
    smscode: str | int | None = None,
) -> None:
    """Write authenticated local SDK ECDH media using an ``EzvizClient``."""
    with open_local_sdk_ecdh_stream_from_client(
        client,
        serial,
        cas_serial=cas_serial,
        channel=channel,
        receiver_port=receiver_port,
        identifier=identifier,
        uuid=uuid,
        timestamp=timestamp,
        send_init=send_init,
        pre_start_body=pre_start_body,
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
        fetch_media_key=decrypt_video and media_key is None,
        smscode=smscode,
    ) as stream:
        selected_media_key = media_key
        if decrypt_video and selected_media_key is None:
            selected_media_key = stream.media_key
            if selected_media_key is None:
                raise PyEzvizError(
                    "decrypt_video requires a media_key or fetchable camera media key"
                )
        copy_local_sdk_ecdh_stream_to_media(
            stream,
            output,
            output_format=output_format,
            decrypt_video=decrypt_video,
            media_key=selected_media_key,
            ffmpeg_path=ffmpeg_path,
            nalu_header_size=nalu_header_size,
            max_packets=max_packets,
            max_frames=max_frames,
            duration_seconds=duration_seconds,
        )


def copy_local_sdk_ecdh_stream_to_media(  # noqa: PLR0913
    stream: EzvizLocalSdkEcdhMediaStream,
    output: BinaryIO,
    *,
    output_format: str = "mpegps",
    decrypt_video: bool = False,
    media_key: str | bytes | None = None,
    ffmpeg_path: str = "ffmpeg",
    nalu_header_size: int | None = None,
    max_packets: int | None = None,
    max_frames: int | None = None,
    duration_seconds: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Copy one ECDH stream while enforcing bounds on encrypted input frames."""
    if output_format not in {"mpegps", "mpegts"}:
        raise PyEzvizError(f"Unsupported local SDK ECDH output format: {output_format}")
    if decrypt_video and media_key is None:
        raise PyEzvizError("decrypt_video requires a media_key or fetchable camera media key")
    if output_format == "mpegps" and not decrypt_video:
        copy_local_sdk_ecdh_stream_to_mpegps(
            stream,
            output,
            max_packets=max_packets,
            max_frames=max_frames,
            duration_seconds=duration_seconds,
            monotonic=monotonic,
        )
        return

    bounded_stream = _BoundedEcdhMediaStream(
        stream,
        max_frames=max_frames,
        duration_seconds=duration_seconds,
        monotonic=monotonic,
    )
    if output_format == "mpegps":
        assert media_key is not None
        copy_local_stream_to_decrypted_mpegps(
            bounded_stream,
            output,
            media_key,
            nalu_header_size=nalu_header_size,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
        )
    elif decrypt_video:
        assert media_key is not None
        copy_local_stream_to_decrypted_mpegts(
            bounded_stream,
            output,
            media_key,
            ffmpeg_path=ffmpeg_path,
            nalu_header_size=nalu_header_size,
            max_packets=max_packets,
            duration_seconds=duration_seconds,
            decrypt_hevc_parameter_sets=True,
        )
    else:
        copy_local_stream_to_mpegts(
            bounded_stream,
            output,
            ffmpeg_path=ffmpeg_path,
            max_packets=max_packets,
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
    output.flush()
