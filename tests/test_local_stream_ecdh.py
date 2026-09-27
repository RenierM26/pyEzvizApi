from __future__ import annotations

import hashlib
import hmac
from io import BytesIO
from typing import Any, cast
import zlib

from Crypto.Cipher import AES, ChaCha20
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from pyezvizapi import (
    EzvizLocalSdkEcdhStreamDecoder as PackageLocalSdkEcdhStreamDecoder,
    generate_ezviz_local_sdk_ecdh_keypair as package_generate_local_sdk_ecdh_keypair,
)
from pyezvizapi.exceptions import (
    DeviceException,
    EzvizLocalSdkDeadlineExpired,
    PyEzvizError,
)
from pyezvizapi.hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
    EzvizLocalSdkStreamBootstrap,
    HcNetSdkLanEndpoint,
)
from pyezvizapi.local_stream import (
    EzvizLocalSdkCredentials,
    EzvizLocalSdkEcdhStreamDecoder as LocalStreamEcdhStreamDecoder,
    generate_ezviz_local_sdk_ecdh_keypair as local_stream_generate_ecdh_keypair,
)
from pyezvizapi.local_stream_ecdh import (
    LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET,
    LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH,
    LOCAL_SDK_ECDH_H264_SPS_4B,
    LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET,
    LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET,
    LOCAL_SDK_ECDH_HEVC_VPS_4B,
    LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER,
    LOCAL_SDK_ECDH_NONCE_LENGTH,
    LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH,
    LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH,
    EzvizLocalSdkEcdhMediaStream,
    EzvizLocalSdkEcdhStreamDecoder,
    EzvizLocalSdkEcdhStreamPacket,
    build_ezviz_local_sdk_ecdh_init_request_body,
    copy_local_sdk_ecdh_stream_from_client,
    copy_local_sdk_ecdh_stream_to_mpegps,
    decrypt_ezviz_local_sdk_ecdh_data_packet,
    derive_ezviz_local_sdk_ecdh_chacha20_key,
    derive_ezviz_local_sdk_ecdh_shared_secret,
    ezviz_local_sdk_ecdh_chacha20_nonce,
    generate_ezviz_local_sdk_ecdh_keypair,
    open_local_sdk_ecdh_stream,
    open_local_sdk_ecdh_stream_from_client,
    parse_ezviz_local_sdk_ecdh_data_packet,
    parse_ezviz_local_sdk_ecdh_handshake_packet,
    transform_ezviz_local_sdk_ecdh_nonce,
)

TEST_NONCE = b"\x01\x02\x03\x04"
TEST_REVERSED_NONCE = b"\x04\x03\x02\x01"
TEST_HANDSHAKE_NONCE = b"\x10\x20\x30\x40"
TEST_OUTER_PREFIX = b"\x00\x00\x00\x00"
TEST_CIPHERTEXT = b"encrypted"
EMPTY_BYTES = b""
EXPECTED_LOCAL_SDK_ECDH_INIT_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op&amp;code</OperationCode>\n"
    b"\t<Session>10011</Session>\n"
    b"</Request>\n"
)
LOCAL_SDK_ECDH_TEST_MPEGPS_PAYLOAD = b"mpegps"
LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY = b"custom-pre-start"
NATIVE_VECTOR_PLAINTEXT = b"hello"
REPLAY_PACKET_1 = b"packet-1"
REPLAY_PACKET_10 = b"packet-10"
REPLAY_PACKET_8 = b"packet-8"


def test_local_stream_namespace_reexports_ecdh_helpers() -> None:
    assert LocalStreamEcdhStreamDecoder is EzvizLocalSdkEcdhStreamDecoder
    assert PackageLocalSdkEcdhStreamDecoder is EzvizLocalSdkEcdhStreamDecoder
    assert local_stream_generate_ecdh_keypair is generate_ezviz_local_sdk_ecdh_keypair
    assert package_generate_local_sdk_ecdh_keypair is generate_ezviz_local_sdk_ecdh_keypair


def _public_key_der(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _encrypt_session_key(shared_secret: bytes, session_key: bytes) -> bytes:
    # codeql[py/weak-cryptographic-algorithm]
    cipher = AES.new(
        shared_secret,
        AES.MODE_ECB,
    )
    # codeql[py/weak-cryptographic-algorithm]
    return cipher.encrypt(session_key)


def _handshake_payload(
    *,
    encrypted_key: bytes,
    peer_public_key_der: bytes,
    header_length: int = 2,
    nonce: bytes = TEST_NONCE,
    ciphertext: bytes = b"",
    verification_key: bytes | None = None,
    outer_prefix: bytes = b"IMKH",
) -> bytes:
    encrypted_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET + header_length
    peer_public_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET + header_length
    authenticated_header_end = peer_public_key_offset + len(peer_public_key_der)
    packet = bytearray(authenticated_header_end)
    packet[0:2] = b"\x24\x01"
    packet[2] = header_length
    packet[header_length + 3 : header_length + 5] = len(ciphertext).to_bytes(2, "big")
    packet[header_length + 5] = 1
    packet[header_length + 6] = 2
    packet[header_length + 7 : header_length + 11] = nonce
    packet[encrypted_key_offset : encrypted_key_offset + len(encrypted_key)] = encrypted_key
    packet[peer_public_key_offset : peer_public_key_offset + len(peer_public_key_der)] = (
        peer_public_key_der
    )
    trailer = (
        _native_trailer(verification_key, bytes(packet), ciphertext)
        if verification_key is not None
        else b"T" * LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH
    )
    return outer_prefix + bytes(packet) + ciphertext + trailer


def _native_trailer(key: bytes, authenticated_header: bytes, ciphertext: bytes) -> bytes:
    crc_text = f"{zlib.crc32(authenticated_header)}{zlib.crc32(ciphertext)}".encode()
    return hmac.new(key, crc_text[:8].ljust(8, b"\x00"), hashlib.sha256).digest()


def _data_payload(
    *,
    nonce: bytes,
    ciphertext: bytes,
    outer_prefix: bytes = b"\x00\x00\x00\x00",
    header_length: int = 0,
    verification_key: bytes | None = None,
) -> bytes:
    packet = bytearray(LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET + header_length)
    packet[0:2] = b"\x24\x02"
    packet[2] = header_length
    packet[header_length + 3 : header_length + 5] = len(ciphertext).to_bytes(2, "big")
    packet[header_length + 5] = 0
    packet[header_length + 6] = 0
    packet[header_length + 7 : header_length + 11] = nonce
    trailer = (
        _native_trailer(verification_key, bytes(packet), ciphertext)
        if verification_key is not None
        else b"T" * LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH
    )
    return outer_prefix + bytes(packet) + ciphertext + trailer


def test_generate_ezviz_local_sdk_ecdh_keypair_returns_p256_spki_public_key() -> None:
    key_pair = generate_ezviz_local_sdk_ecdh_keypair()

    assert len(key_pair.public_key_der) == LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH
    assert key_pair.public_key_b64.isascii()
    assert key_pair.public_key_b64
    assert serialization.load_der_public_key(key_pair.public_key_der)


def test_transform_ezviz_local_sdk_ecdh_nonce_reverses_wire_nonce() -> None:
    assert transform_ezviz_local_sdk_ecdh_nonce(TEST_NONCE) == TEST_REVERSED_NONCE
    assert ezviz_local_sdk_ecdh_chacha20_nonce(TEST_NONCE) == (TEST_REVERSED_NONCE + b"\x00" * 8)

    with pytest.raises(PyEzvizError, match="nonce"):
        transform_ezviz_local_sdk_ecdh_nonce(b"\x01" * (LOCAL_SDK_ECDH_NONCE_LENGTH - 1))


def test_ezviz_local_sdk_ecdh_key_derivation_matches_native_shape() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)

    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    encrypted_key = _encrypt_session_key(shared_secret, bytes(range(32)))

    client_public_key = serialization.load_der_public_key(client_key_pair.public_key_der)
    assert isinstance(client_public_key, ec.EllipticCurvePublicKey)
    assert camera_private_key.exchange(ec.ECDH(), client_public_key) == shared_secret
    assert derive_ezviz_local_sdk_ecdh_chacha20_key(shared_secret, encrypted_key) == bytes(
        range(32)
    )


def test_ezviz_local_sdk_ecdh_shared_secret_rejects_invalid_peer_key() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(PyEzvizError, match="peer public key is invalid"):
        derive_ezviz_local_sdk_ecdh_shared_secret(private_key, b"invalid")


def test_ezviz_local_sdk_ecdh_shared_secret_rejects_incompatible_curve() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_public_key_der = _public_key_der(ec.generate_private_key(ec.SECP384R1()))

    with pytest.raises(PyEzvizError, match="peer public key is incompatible"):
        derive_ezviz_local_sdk_ecdh_shared_secret(private_key, peer_public_key_der)


def test_parse_ezviz_local_sdk_ecdh_handshake_packet_uses_header_relative_offsets() -> None:
    encrypted_key = b"E" * 32
    peer_public_key_der = _public_key_der(ec.generate_private_key(ec.SECP256R1()))
    payload = _handshake_payload(
        encrypted_key=encrypted_key,
        peer_public_key_der=peer_public_key_der,
        header_length=4,
        nonce=TEST_HANDSHAKE_NONCE,
    )

    packet = parse_ezviz_local_sdk_ecdh_handshake_packet(payload)

    assert packet is not None
    assert packet.packet_offset == 4
    assert packet.header_length == 4
    assert packet.subtype == 2
    assert packet.nonce_raw == TEST_HANDSHAKE_NONCE
    assert packet.encrypted_key == encrypted_key
    assert packet.peer_public_key_der == peer_public_key_der


def test_parse_ezviz_local_sdk_ecdh_data_packet_accepts_outer_prefixed_payload() -> None:
    payload = _data_payload(nonce=TEST_NONCE, ciphertext=TEST_CIPHERTEXT)

    packet = parse_ezviz_local_sdk_ecdh_data_packet(payload)

    assert packet is not None
    assert packet.outer_prefix == TEST_OUTER_PREFIX
    assert packet.nonce_raw == TEST_NONCE
    assert packet.ciphertext == TEST_CIPHERTEXT
    assert packet.trailer == b"T" * LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH


def test_local_sdk_ecdh_packet_reprs_redact_raw_bytes() -> None:
    encrypted_key = b"E" * 32
    peer_public_key_der = _public_key_der(ec.generate_private_key(ec.SECP256R1()))
    handshake = parse_ezviz_local_sdk_ecdh_handshake_packet(
        _handshake_payload(
            encrypted_key=encrypted_key,
            peer_public_key_der=peer_public_key_der,
            nonce=TEST_HANDSHAKE_NONCE,
        )
    )
    data_packet = parse_ezviz_local_sdk_ecdh_data_packet(
        _data_payload(nonce=TEST_NONCE, ciphertext=TEST_CIPHERTEXT)
    )
    stream_packet = EzvizLocalSdkEcdhStreamPacket(channel=1, body=b"media-bytes")

    assert handshake is not None
    assert data_packet is not None
    combined_repr = repr((handshake, data_packet, stream_packet))

    assert repr(encrypted_key) not in combined_repr
    assert repr(TEST_HANDSHAKE_NONCE) not in combined_repr
    assert repr(TEST_CIPHERTEXT) not in combined_repr
    assert repr(TEST_OUTER_PREFIX) not in combined_repr
    assert repr(b"media-bytes") not in combined_repr


def test_parse_ezviz_local_sdk_ecdh_data_packet_rejects_truncated_length() -> None:
    payload = _data_payload(nonce=TEST_NONCE, ciphertext=TEST_CIPHERTEXT)

    assert parse_ezviz_local_sdk_ecdh_data_packet(payload[:-1]) is None
    assert parse_ezviz_local_sdk_ecdh_data_packet(payload + b"extra") is None


def test_parse_ezviz_local_sdk_ecdh_packets_reject_embedded_or_unknown_markers() -> None:
    camera_public_key_der = _public_key_der(ec.generate_private_key(ec.SECP256R1()))
    handshake_payload = bytearray(
        _handshake_payload(
            encrypted_key=b"E" * 32,
            peer_public_key_der=camera_public_key_der,
        )
    )
    handshake_payload[LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH + 2 + 6] = 3
    assert parse_ezviz_local_sdk_ecdh_handshake_packet(bytes(handshake_payload)) is None

    assert (
        parse_ezviz_local_sdk_ecdh_handshake_packet(
            b"unexpected-prefix" + b"\x24\x01" + b"\x00" * 200
        )
        is None
    )


def test_parse_ezviz_local_sdk_ecdh_data_packet_uses_header_relative_offsets() -> None:
    key = b"K" * 32
    plaintext = b"header-relative"
    nonce = b"\x00\x00\x00\x02"
    ciphertext = ChaCha20.new(
        key=key,
        nonce=ezviz_local_sdk_ecdh_chacha20_nonce(nonce),
    ).encrypt(plaintext)
    packet = parse_ezviz_local_sdk_ecdh_data_packet(
        _data_payload(
            nonce=nonce,
            ciphertext=ciphertext,
            header_length=3,
            verification_key=key,
        )
    )

    assert packet is not None
    assert packet.header_length == 3
    assert packet.nonce_raw == nonce
    assert decrypt_ezviz_local_sdk_ecdh_data_packet(key, packet) == plaintext


def test_decrypt_ezviz_local_sdk_ecdh_data_packet_uses_reversed_nonce() -> None:
    key = b"K" * 32
    nonce = TEST_NONCE
    plaintext = b"plain data"
    ciphertext = ChaCha20.new(
        key=key,
        nonce=TEST_REVERSED_NONCE + b"\x00" * 8,
    ).encrypt(plaintext)
    packet = parse_ezviz_local_sdk_ecdh_data_packet(
        _data_payload(nonce=nonce, ciphertext=ciphertext, verification_key=key)
    )

    assert packet is not None
    assert decrypt_ezviz_local_sdk_ecdh_data_packet(key, packet) == plaintext


def test_decrypt_ezviz_local_sdk_ecdh_data_packet_matches_native_fixed_vector() -> None:
    packet = parse_ezviz_local_sdk_ecdh_data_packet(
        bytes.fromhex(
            "00000000"
            "2402000005000000000001"
            "b05d97653c"
            "9327c13cedc7113659c06e439064bcab47f233bbafaabdb8cb780f817747f258"
        )
    )

    assert packet is not None
    assert (
        decrypt_ezviz_local_sdk_ecdh_data_packet(bytes(range(32)), packet)
        == NATIVE_VECTOR_PLAINTEXT
    )


@pytest.mark.parametrize("mutated_part", ["header", "trailer"])
def test_decrypt_ezviz_local_sdk_ecdh_data_packet_rejects_tampering(
    mutated_part: str,
) -> None:
    key = b"A" * 32
    payload = bytearray(
        _data_payload(
            nonce=b"\x00\x00\x00\x03",
            ciphertext=b"ciphertext",
            verification_key=key,
        )
    )
    if mutated_part == "header":
        payload[LOCAL_SDK_ECDH_STREAM_OUTER_PREFIX_LENGTH + 5] ^= 1
    else:
        payload[-1] ^= 1
    packet = parse_ezviz_local_sdk_ecdh_data_packet(bytes(payload))

    assert packet is not None
    with pytest.raises(PyEzvizError, match="authentication failed"):
        decrypt_ezviz_local_sdk_ecdh_data_packet(key, packet)


def test_ezviz_local_sdk_ecdh_stream_decoder_derives_key_and_waits_for_keyframe() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    chacha20_key = b"C" * 32
    encrypted_key = _encrypt_session_key(shared_secret, chacha20_key)
    decoder = EzvizLocalSdkEcdhStreamDecoder(client_key_pair.private_key)
    handshake = _handshake_payload(
        encrypted_key=encrypted_key,
        peer_public_key_der=camera_public_key_der,
        verification_key=shared_secret,
    )
    nonce = b"\xaa\xbb\xcc\xdd"
    plaintext = (
        b"preface"
        + LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER
        + b"\x00" * 8
        + LOCAL_SDK_ECDH_HEVC_VPS_4B
        + b"frame"
    )
    ciphertext = ChaCha20.new(
        key=chacha20_key,
        nonce=ezviz_local_sdk_ecdh_chacha20_nonce(nonce),
    ).encrypt(plaintext)

    assert decoder.feed_payload(0, handshake) == EMPTY_BYTES
    assert decoder.keys_derived is True
    assert decoder.feed_payload(
        1,
        _data_payload(nonce=nonce, ciphertext=ciphertext, verification_key=chacha20_key),
    ) == (LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER + b"\x00" * 8 + LOCAL_SDK_ECDH_HEVC_VPS_4B + b"frame")


def test_ezviz_local_sdk_ecdh_stream_decoder_rejects_handshake_tampering() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    payload = bytearray(
        _handshake_payload(
            encrypted_key=_encrypt_session_key(shared_secret, b"S" * 32),
            peer_public_key_der=camera_public_key_der,
            verification_key=shared_secret,
        )
    )
    payload[-1] ^= 1

    with pytest.raises(PyEzvizError, match="authentication failed"):
        EzvizLocalSdkEcdhStreamDecoder(client_key_pair.private_key).feed_payload(0, bytes(payload))


def test_ezviz_local_sdk_ecdh_stream_decoder_rejects_replay_and_stale_sequence() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    chacha20_key = b"R" * 32
    decoder = EzvizLocalSdkEcdhStreamDecoder(client_key_pair.private_key, require_keyframe=False)
    decoder.feed_payload(
        0,
        _handshake_payload(
            encrypted_key=_encrypt_session_key(shared_secret, chacha20_key),
            peer_public_key_der=camera_public_key_der,
            nonce=b"\x00\x00\x00\x01",
            verification_key=shared_secret,
        ),
    )

    def encrypted_payload(sequence: int) -> bytes:
        nonce = sequence.to_bytes(4, "big")
        ciphertext = ChaCha20.new(
            key=chacha20_key,
            nonce=ezviz_local_sdk_ecdh_chacha20_nonce(nonce),
        ).encrypt(f"packet-{sequence}".encode())
        return _data_payload(
            nonce=nonce,
            ciphertext=ciphertext,
            verification_key=chacha20_key,
        )

    assert decoder.feed_payload(1, encrypted_payload(1)) == REPLAY_PACKET_1
    newest = encrypted_payload(10)
    assert decoder.feed_payload(1, newest) == REPLAY_PACKET_10
    assert decoder.feed_payload(1, encrypted_payload(8)) == REPLAY_PACKET_8
    with pytest.raises(PyEzvizError, match="replayed"):
        decoder.feed_payload(1, newest)
    with pytest.raises(PyEzvizError, match="outside the window"):
        decoder.feed_payload(1, encrypted_payload(6))


def test_ezviz_local_sdk_ecdh_stream_decoder_accepts_h264_keyframe() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    chacha20_key = b"H" * 32
    encrypted_key = _encrypt_session_key(shared_secret, chacha20_key)
    decoder = EzvizLocalSdkEcdhStreamDecoder(client_key_pair.private_key)
    nonce = b"\x10\x11\x12\x13"
    plaintext = b"lead" + LOCAL_SDK_ECDH_H264_SPS_4B + b"frame"
    ciphertext = ChaCha20.new(
        key=chacha20_key,
        nonce=ezviz_local_sdk_ecdh_chacha20_nonce(nonce),
    ).encrypt(plaintext)

    decoder.feed_payload(
        0,
        _handshake_payload(
            encrypted_key=encrypted_key,
            peer_public_key_der=camera_public_key_der,
            verification_key=shared_secret,
        ),
    )
    assert (
        decoder.feed_payload(
            1,
            _data_payload(nonce=nonce, ciphertext=ciphertext, verification_key=chacha20_key),
        )
        == EMPTY_BYTES
    )
    next_nonce = b"\x10\x11\x12\x14"
    next_plaintext = (
        LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER
        + b"\x00" * 8
        + LOCAL_SDK_ECDH_H264_SPS_4B
        + b"next-frame"
    )
    next_ciphertext = ChaCha20.new(
        key=chacha20_key,
        nonce=ezviz_local_sdk_ecdh_chacha20_nonce(next_nonce),
    ).encrypt(next_plaintext)
    assert decoder.feed_payload(
        1,
        _data_payload(
            nonce=next_nonce,
            ciphertext=next_ciphertext,
            verification_key=chacha20_key,
        ),
    ) == (
        LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER
        + b"\x00" * 8
        + LOCAL_SDK_ECDH_H264_SPS_4B
        + b"next-frame"
    )


def test_ezviz_local_sdk_ecdh_stream_decoder_rejects_missing_mpegps_boundary() -> None:
    decoder = EzvizLocalSdkEcdhStreamDecoder(
        ec.generate_private_key(ec.SECP256R1()),
        max_pre_keyframe_bytes=8,
    )

    with pytest.raises(PyEzvizError, match="MPEG-PS pack header"):
        decoder._absorb_plain(  # noqa: SLF001
            LOCAL_SDK_ECDH_H264_SPS_4B + b"frame"
        )


def test_build_ezviz_local_sdk_ecdh_init_request_body_uses_operation_code_and_session() -> None:
    assert (
        build_ezviz_local_sdk_ecdh_init_request_body(
            operation_code="op&code",
            session=10011,
        )
        == EXPECTED_LOCAL_SDK_ECDH_INIT_XML
    )


def test_open_local_sdk_ecdh_stream_prefers_custom_pre_start_body() -> None:
    stream = open_local_sdk_ecdh_stream(
        HcNetSdkLanEndpoint(
            serial="CAM123",
            host="192.0.2.10",
            command_port=9010,
            stream_port=9020,
        ),
        EzvizCasDeviceInfo(
            serial="CAM123",
            operation_code="0123456",
            key="1234567890abcdef",
        ),
        send_init=True,
        pre_start_body=LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY,
        identifier="preview-id",
        uuid="preview-uuid",
        timestamp="123456",
    )

    assert stream.pre_start_body == LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY
    assert stream.preview_request.identifier == "preview-id"
    assert stream.preview_request.uuid == "preview-uuid"
    assert stream.preview_request.timestamp == "123456"
    assert stream.pre_start_sequence == 1
    assert stream.preview_sequence == 2
    assert stream.stream_setup_sequence == 3


def test_open_local_sdk_ecdh_stream_from_client_skips_media_key_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def fake_credentials(client: object, serial: str, **kwargs: object) -> object:
        calls.append({"client": client, "serial": serial, **kwargs})
        return EzvizLocalSdkCredentials(
            endpoint=HcNetSdkLanEndpoint(
                serial="CAM123",
                host="192.0.2.10",
                command_port=9010,
                stream_port=9020,
            ),
            device_info=EzvizCasDeviceInfo(
                serial="CAM123",
                operation_code="0123456",
                key="1234567890abcdef",
            ),
            media_key=None,
        )

    monkeypatch.setattr(
        "pyezvizapi.local_stream_ecdh.get_local_sdk_stream_credentials_from_client",
        fake_credentials,
    )

    client = object()
    stream = open_local_sdk_ecdh_stream_from_client(
        client,
        "CAM123",
        cas_serial="CAMALT",
        register_p2p_session=False,
        p2p_register_max_retries=1,
        pre_start_body=LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY,
        identifier="preview-id",
        uuid="preview-uuid",
        timestamp="123456",
        pre_start_sequence=27,
        preview_sequence=28,
        stream_setup_sequence=29,
        stream_rate=3,
        stream_mode=4,
        max_prefix_bytes=8192,
    )

    assert calls == [
        {
            "client": client,
            "serial": "CAM123",
            "cas_serial": "CAMALT",
            "fetch_media_key": False,
            "register_p2p_session": False,
            "p2p_register_max_retries": 1,
        }
    ]
    assert stream.preview_request.public_key == stream.key_pair.public_key_b64
    assert stream.pre_start_body == LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY
    assert stream.preview_request.identifier == "preview-id"
    assert stream.preview_request.uuid == "preview-uuid"
    assert stream.preview_request.timestamp == "123456"
    assert stream.pre_start_sequence == 27
    assert stream.preview_sequence == 28
    assert stream.stream_setup_sequence == 29
    assert stream.stream_rate == 3
    assert stream.stream_mode == 4
    assert stream.max_prefix_bytes == 8192


def test_copy_local_sdk_ecdh_stream_from_client_writes_decoded_packets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copied: list[dict[str, object]] = []

    class FakeStream:
        def __enter__(self) -> FakeStream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_packets(self, **kwargs: object) -> list[object]:
            copied.append(kwargs)
            return [
                type("Packet", (), {"body": LOCAL_SDK_ECDH_TEST_MPEGPS_PAYLOAD})(),
            ]

    def fake_open(*args: object, **kwargs: object) -> FakeStream:
        copied.append({"args": args, **kwargs})
        return FakeStream()

    monkeypatch.setattr(
        "pyezvizapi.local_stream_ecdh.open_local_sdk_ecdh_stream_from_client",
        fake_open,
    )

    output = BytesIO()
    duration_seconds = 0.5
    copy_local_sdk_ecdh_stream_from_client(
        object(),
        "CAM123",
        output,
        cas_serial="CAMALT",
        channel=2,
        send_init=True,
        pre_start_body=LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY,
        identifier="preview-id",
        uuid="preview-uuid",
        timestamp="123456",
        pre_start_sequence=27,
        preview_sequence=28,
        stream_setup_sequence=29,
        stream_rate=3,
        stream_mode=4,
        register_p2p_session=False,
        p2p_register_max_retries=1,
        max_prefix_bytes=8192,
        max_packets=1,
        max_frames=3,
        duration_seconds=duration_seconds,
    )

    assert output.getvalue() == LOCAL_SDK_ECDH_TEST_MPEGPS_PAYLOAD
    assert copied[0]["cas_serial"] == "CAMALT"
    assert copied[0]["channel"] == 2
    assert copied[0]["send_init"] is True
    assert copied[0]["pre_start_body"] == LOCAL_SDK_ECDH_CUSTOM_PRE_START_BODY
    assert copied[0]["identifier"] == "preview-id"
    assert copied[0]["uuid"] == "preview-uuid"
    assert copied[0]["timestamp"] == "123456"
    assert copied[0]["pre_start_sequence"] == 27
    assert copied[0]["preview_sequence"] == 28
    assert copied[0]["stream_setup_sequence"] == 29
    assert copied[0]["stream_rate"] == 3
    assert copied[0]["stream_mode"] == 4
    assert copied[0]["register_p2p_session"] is False
    assert copied[0]["p2p_register_max_retries"] == 1
    assert copied[0]["max_prefix_bytes"] == 8192
    assert copied[1]["max_packets"] == 1
    assert copied[1]["max_frames"] == 3
    assert copied[1]["duration_seconds"] == duration_seconds
    assert callable(copied[1]["monotonic"])


def test_copy_local_sdk_ecdh_stream_to_mpegps_flushes_output() -> None:
    class FlushTrackingOutput(BytesIO):
        flush_calls = 0

        def flush(self) -> None:
            self.flush_calls += 1
            super().flush()

    class FakeStream:
        def iter_packets(self, **_kwargs: object) -> list[object]:
            return [
                type("Packet", (), {"body": LOCAL_SDK_ECDH_TEST_MPEGPS_PAYLOAD})(),
            ]

    output = FlushTrackingOutput()
    copy_local_sdk_ecdh_stream_to_mpegps(cast(Any, FakeStream()), output)

    assert output.getvalue() == LOCAL_SDK_ECDH_TEST_MPEGPS_PAYLOAD
    assert output.flush_calls == 1


def test_ezviz_local_sdk_ecdh_stream_iter_packets_can_bound_input_frames() -> None:
    class FakeSdkClient:
        def bootstrap_preview_from_fields(self, **_kwargs: object) -> object:
            return EzvizLocalSdkStreamBootstrap(
                preview=cast(Any, object()),
                stream_setup=cast(Any, object()),
                first_media=EzvizInterleavedRtpFrameWithPrefix(
                    prefix=b"",
                    frame=EzvizInterleavedRtpFrame(
                        header=EzvizInterleavedRtpFrameHeader(
                            channel=1,
                            payload_length=11,
                        ),
                        payload=b"not-local_sdk_ecdh",
                    ),
                ),
            )

        def read_stream_frame_after_prefix(self, **_kwargs: object) -> object:
            raise AssertionError("max_frames should stop before reading again")

        def close(self) -> None:
            return None

    stream = EzvizLocalSdkEcdhMediaStream(
        cast(Any, FakeSdkClient()),
        EzvizLocalPreviewRequest(
            operation_code="0123456",
            channel=1,
            receiver_info="receiver",
            receiver_info_ex="receiver-ex",
        ),
        generate_ezviz_local_sdk_ecdh_keypair(),
    )

    assert list(stream.iter_packets(max_packets=1, max_frames=1)) == []


def test_ezviz_local_sdk_ecdh_stream_iter_packets_can_bound_suppressed_frames_by_duration() -> None:
    class FakeSdkClient:
        def __init__(self) -> None:
            self.reads = 0

        def bootstrap_preview_from_fields(self, **_kwargs: object) -> object:
            return EzvizLocalSdkStreamBootstrap(
                preview=cast(Any, object()),
                stream_setup=cast(Any, object()),
                first_media=EzvizInterleavedRtpFrameWithPrefix(
                    prefix=b"",
                    frame=EzvizInterleavedRtpFrame(
                        header=EzvizInterleavedRtpFrameHeader(
                            channel=1,
                            payload_length=11,
                        ),
                        payload=b"not-local_sdk_ecdh",
                    ),
                ),
            )

        def read_stream_frame_after_prefix(self, **_kwargs: object) -> object:
            self.reads += 1
            return EzvizInterleavedRtpFrameWithPrefix(
                prefix=b"",
                frame=EzvizInterleavedRtpFrame(
                    header=EzvizInterleavedRtpFrameHeader(
                        channel=1,
                        payload_length=11,
                    ),
                    payload=b"not-local_sdk_ecdh",
                ),
            )

        def close(self) -> None:
            return None

    ticks = iter([0.0, 0.1, 0.4, 1.1])
    sdk_client = FakeSdkClient()
    stream = EzvizLocalSdkEcdhMediaStream(
        cast(Any, sdk_client),
        EzvizLocalPreviewRequest(
            operation_code="0123456",
            channel=1,
            receiver_info="receiver",
            receiver_info_ex="receiver-ex",
        ),
        generate_ezviz_local_sdk_ecdh_keypair(),
    )

    packets = list(
        stream.iter_packets(
            max_packets=1,
            duration_seconds=1.0,
            monotonic=lambda: next(ticks),
        ),
    )

    assert packets == []
    assert sdk_client.reads == 2


def test_ezviz_local_sdk_ecdh_stream_applies_duration_before_first_media_read() -> None:
    class FakeSdkClient:
        def __init__(self) -> None:
            self.read_first_media: bool | None = None
            self.reads = 0

        def bootstrap_preview_from_fields(self, **kwargs: object) -> object:
            self.read_first_media = cast(bool, kwargs["read_first_media"])
            return EzvizLocalSdkStreamBootstrap(
                preview=cast(Any, object()),
                stream_setup=cast(Any, object()),
                first_media=None,
            )

        def read_stream_frame_after_prefix(self, **_kwargs: object) -> object:
            self.reads += 1
            raise AssertionError("duration should stop before the first media read")

        def close(self) -> None:
            return None

    ticks = iter([0.0, 1.1])
    sdk_client = FakeSdkClient()
    stream = EzvizLocalSdkEcdhMediaStream(
        cast(Any, sdk_client),
        EzvizLocalPreviewRequest(
            operation_code="0123456",
            channel=1,
            receiver_info="receiver",
            receiver_info_ex="receiver-ex",
        ),
        generate_ezviz_local_sdk_ecdh_keypair(),
    )

    packets = list(
        stream.iter_packets(
            max_packets=1,
            duration_seconds=1.0,
            monotonic=lambda: next(ticks),
        ),
    )

    assert packets == []
    assert sdk_client.read_first_media is False
    assert sdk_client.reads == 0


def test_ezviz_local_sdk_ecdh_stream_bounds_blocking_read_by_duration() -> None:
    class FakeSdkClient:
        def __init__(self) -> None:
            self.read_timeout: float | None = None
            self.timeout = 5.0

        def bootstrap_preview_from_fields(self, **_kwargs: object) -> object:
            return EzvizLocalSdkStreamBootstrap(
                preview=cast(Any, object()),
                stream_setup=cast(Any, object()),
                first_media=None,
            )

        def read_stream_frame_after_prefix(self, **kwargs: object) -> object:
            self.read_timeout = cast(float, kwargs["timeout"])
            raise EzvizLocalSdkDeadlineExpired("timed out")

        def close(self) -> None:
            return None

    ticks = iter([0.0, 0.25])
    sdk_client = FakeSdkClient()
    stream = EzvizLocalSdkEcdhMediaStream(
        cast(Any, sdk_client),
        EzvizLocalPreviewRequest(
            operation_code="0123456",
            channel=1,
            receiver_info="receiver",
            receiver_info_ex="receiver-ex",
        ),
        generate_ezviz_local_sdk_ecdh_keypair(),
    )

    assert (
        list(
            stream.iter_packets(
                max_packets=1,
                duration_seconds=1.0,
                monotonic=lambda: next(ticks),
            )
        )
        == []
    )
    assert sdk_client.read_timeout == pytest.approx(0.75)


def test_ezviz_local_sdk_ecdh_stream_preserves_earlier_socket_timeout() -> None:
    class FakeSdkClient:
        timeout = 0.25

        def bootstrap_preview_from_fields(self, **_kwargs: object) -> object:
            return EzvizLocalSdkStreamBootstrap(
                preview=cast(Any, object()),
                stream_setup=cast(Any, object()),
                first_media=None,
            )

        def read_stream_frame_after_prefix(self, **_kwargs: object) -> object:
            raise DeviceException("timed out")

        def close(self) -> None:
            return None

    ticks = iter([0.0, 0.1])
    stream = EzvizLocalSdkEcdhMediaStream(
        cast(Any, FakeSdkClient()),
        EzvizLocalPreviewRequest(
            operation_code="0123456",
            channel=1,
            receiver_info="receiver",
            receiver_info_ex="receiver-ex",
        ),
        generate_ezviz_local_sdk_ecdh_keypair(),
    )

    with pytest.raises(DeviceException, match="timed out"):
        list(
            stream.iter_packets(
                max_packets=1,
                duration_seconds=1.0,
                monotonic=lambda: next(ticks),
            )
        )
