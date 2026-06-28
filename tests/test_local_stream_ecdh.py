from __future__ import annotations

from io import BytesIO
from typing import Any, cast

from Crypto.Cipher import AES, ChaCha20
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from pyezvizapi import (
    EzvizLocalSdkEcdhStreamDecoder as PackageLocalSdkEcdhStreamDecoder,
    generate_ezviz_local_sdk_ecdh_keypair as package_generate_local_sdk_ecdh_keypair,
)
from pyezvizapi.exceptions import PyEzvizError
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
    EzvizLocalSdkEcdhMediaStream,
    EzvizLocalSdkEcdhStreamDecoder,
    EzvizLocalSdkEcdhStreamPacket,
    build_ezviz_local_sdk_ecdh_init_request_body,
    copy_local_sdk_ecdh_stream_from_client,
    decrypt_ezviz_local_sdk_ecdh_data_packet,
    derive_ezviz_local_sdk_ecdh_chacha20_key,
    derive_ezviz_local_sdk_ecdh_shared_secret,
    ezviz_local_sdk_ecdh_chacha20_nonce,
    generate_ezviz_local_sdk_ecdh_keypair,
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


def _handshake_payload(
    *,
    encrypted_key: bytes,
    peer_public_key_der: bytes,
    header_length: int = 2,
    nonce: bytes = TEST_NONCE,
) -> bytes:
    encrypted_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_ENCRYPTED_KEY_OFFSET + header_length
    peer_public_key_offset = LOCAL_SDK_ECDH_HANDSHAKE_PEER_PUBLIC_KEY_OFFSET + header_length
    packet = bytearray(peer_public_key_offset + len(peer_public_key_der))
    packet[0:2] = b"\x24\x01"
    packet[2] = header_length
    packet[3:5] = b"\x00\x00"
    packet[5] = 1
    packet[6] = 2
    packet[7:11] = nonce
    packet[encrypted_key_offset : encrypted_key_offset + len(encrypted_key)] = (
        encrypted_key
    )
    packet[
        peer_public_key_offset : peer_public_key_offset + len(peer_public_key_der)
    ] = peer_public_key_der
    return b"IMKH" + bytes(packet)


def _data_payload(
    *,
    nonce: bytes,
    ciphertext: bytes,
    outer_prefix: bytes = b"\x00\x00\x00\x00",
) -> bytes:
    packet = bytearray(LOCAL_SDK_ECDH_DATA_CIPHERTEXT_OFFSET)
    packet[0:2] = b"\x24\x02"
    packet[3:5] = len(ciphertext).to_bytes(2, "big")
    packet[5] = 0
    packet[6] = 2
    packet[7:11] = nonce
    return (
        outer_prefix
        + bytes(packet)
        + ciphertext
        + (b"T" * LOCAL_SDK_ECDH_DATA_TRAILER_LENGTH)
    )


def test_generate_ezviz_local_sdk_ecdh_keypair_returns_p256_spki_public_key() -> None:
    key_pair = generate_ezviz_local_sdk_ecdh_keypair()

    assert len(key_pair.public_key_der) == LOCAL_SDK_ECDH_PUBLIC_KEY_DER_LENGTH
    assert key_pair.public_key_b64.isascii()
    assert key_pair.public_key_b64
    assert serialization.load_der_public_key(key_pair.public_key_der)


def test_transform_ezviz_local_sdk_ecdh_nonce_reverses_wire_nonce() -> None:
    assert transform_ezviz_local_sdk_ecdh_nonce(TEST_NONCE) == TEST_REVERSED_NONCE
    assert ezviz_local_sdk_ecdh_chacha20_nonce(TEST_NONCE) == (
        TEST_REVERSED_NONCE + b"\x00" * 8
    )

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
    encrypted_key = AES.new(shared_secret, AES.MODE_ECB).encrypt(bytes(range(32)))

    client_public_key = serialization.load_der_public_key(client_key_pair.public_key_der)
    assert isinstance(client_public_key, ec.EllipticCurvePublicKey)
    assert camera_private_key.exchange(ec.ECDH(), client_public_key) == shared_secret
    assert derive_ezviz_local_sdk_ecdh_chacha20_key(shared_secret, encrypted_key) == bytes(
        range(32)
    )


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


def test_decrypt_ezviz_local_sdk_ecdh_data_packet_uses_reversed_nonce() -> None:
    key = b"K" * 32
    nonce = TEST_NONCE
    plaintext = b"plain data"
    ciphertext = ChaCha20.new(
        key=key,
        nonce=TEST_REVERSED_NONCE + b"\x00" * 8,
    ).encrypt(plaintext)
    packet = parse_ezviz_local_sdk_ecdh_data_packet(
        _data_payload(nonce=nonce, ciphertext=ciphertext)
    )

    assert packet is not None
    assert decrypt_ezviz_local_sdk_ecdh_data_packet(key, packet) == plaintext


def test_ezviz_local_sdk_ecdh_stream_decoder_derives_key_and_waits_for_keyframe() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    chacha20_key = b"C" * 32
    encrypted_key = AES.new(shared_secret, AES.MODE_ECB).encrypt(chacha20_key)
    decoder = EzvizLocalSdkEcdhStreamDecoder(client_key_pair.private_key)
    handshake = _handshake_payload(
        encrypted_key=encrypted_key,
        peer_public_key_der=camera_public_key_der,
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
    assert decoder.feed_payload(1, _data_payload(nonce=nonce, ciphertext=ciphertext)) == (
        LOCAL_SDK_ECDH_MPEG_PS_PACK_HEADER + b"\x00" * 8 + LOCAL_SDK_ECDH_HEVC_VPS_4B + b"frame"
    )


def test_ezviz_local_sdk_ecdh_stream_decoder_accepts_h264_keyframe() -> None:
    client_key_pair = generate_ezviz_local_sdk_ecdh_keypair()
    camera_private_key = ec.generate_private_key(ec.SECP256R1())
    camera_public_key_der = _public_key_der(camera_private_key)
    shared_secret = derive_ezviz_local_sdk_ecdh_shared_secret(
        client_key_pair.private_key,
        camera_public_key_der,
    )
    chacha20_key = b"H" * 32
    encrypted_key = AES.new(shared_secret, AES.MODE_ECB).encrypt(chacha20_key)
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
        ),
    )
    assert decoder.feed_payload(1, _data_payload(nonce=nonce, ciphertext=ciphertext)) == (
        LOCAL_SDK_ECDH_H264_SPS_4B + b"frame"
    )


def test_build_ezviz_local_sdk_ecdh_init_request_body_uses_operation_code_and_session() -> None:
    assert build_ezviz_local_sdk_ecdh_init_request_body(
        operation_code="op&code",
        session=10011,
    ) == EXPECTED_LOCAL_SDK_ECDH_INIT_XML


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
    assert stream.pre_start_body is None
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
