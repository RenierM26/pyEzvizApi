from __future__ import annotations

from collections.abc import Callable
import hashlib

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
    EZVIZ_HCNETUTIL_LOGIN_V40,
    EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
    EZVIZ_LAN_MAIN_STREAM_TYPE,
    EZVIZ_LAN_MAIN_VIDEO_LEVEL,
    EZVIZ_LAN_SUB_STREAM_TYPE,
    EZVIZ_LAN_SUB_VIDEO_LEVEL,
    EZVIZ_LOCAL_SDK_PRE_START_COMMAND,
    EZVIZ_LOCAL_SDK_PREVIEW_COMMAND,
    EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
    EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE,
    EZVIZ_PLAYER_EXTRA_CHANNEL_NO,
    EZVIZ_PLAYER_EXTRA_DEVICE_ID,
    EZVIZ_PLAYER_EXTRA_LAN_FLAG,
    EZVIZ_PLAYER_EXTRA_LAN_USERID,
    EZVIZ_PLAYER_EXTRA_WIFI_SSID,
    EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
    EZVIZ_PREPLAY_SPS_TYPE,
    EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
    EZVIZ_STREAM_INHIBIT_LAN,
    EZVIZ_STREAM_SOURCE_LIVE_MINE,
    EZVIZ_STREAM_TIMEOUT_MS,
    HCNETSDK_COMMAND_CANDIDATE_CONTROL,
    HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN,
    HCNETSDK_DEFAULT_RTSP_PORT,
    HCNETSDK_DEFAULT_SERVER_PORT,
    HCNETSDK_DEFAULT_TLS_PORT,
    HCNETSDK_EZVIZ_DEFAULT_USERNAME,
    HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX,
    HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX,
    HCNETSDK_EZVIZ_LOCAL_USERNAME,
    HCNETSDK_EZVIZ_SERVICES_SWITCH_GET,
    HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT,
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR,
    HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR,
    HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE,
    HCNETSDK_MAKE_KEYFRAME_MAIN,
    HCNETSDK_MAKE_KEYFRAME_SUB,
    HCNETSDK_REALDATA_CALLBACK_V30,
    HCNETSDK_REALPLAY_V30,
    HCNETSDK_TCP_HEADER_LENGTH,
    EzvizCasDeviceInfo,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfo,
    EzvizLocalReceiverInfoEx,
    EzvizLocalSdkClient,
    HcNetSdkClientInfo,
    HcNetSdkDvrCommand,
    HcNetSdkLanEndpoint,
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
    build_encrypted_ezviz_local_sdk_frame,
    build_ezviz_cas_encrypted_local_sdk_frame,
    build_ezviz_cas_ssl_local_sdk_frame,
    build_ezviz_interleaved_rtp_frame_header,
    build_ezviz_local_preview_request_body,
    build_ezviz_local_sdk_frame,
    build_ezviz_local_sdk_frame_header,
    build_ezviz_local_sdk_ssl_frame,
    build_ezviz_local_stream_setup_request_body,
    build_hcnetsdk_tcp_frame,
    classify_ezviz_local_sdk_body,
    classify_hcnetsdk_real_data_payload,
    classify_hcnetsdk_tcp_payload,
    decrypt_ezviz_local_sdk_body_aes_cbc,
    encrypt_ezviz_local_sdk_body_aes_cbc,
    ezviz_lan_complete_playback_path,
    ezviz_lan_live_view_params,
    ezviz_lan_local_user_password,
    ezviz_lan_login_candidates,
    ezviz_lan_password_store_key,
    ezviz_lan_password_store_name,
    ezviz_lan_play_device_login,
    ezviz_lan_play_device_login_succeeded,
    ezviz_lan_playback_intent,
    ezviz_lan_preview_plan,
    ezviz_lan_services_switch_payload,
    ezviz_lan_services_switch_put_request,
    ezviz_lan_services_switch_succeeded,
    ezviz_lan_settings_channel_number,
    ezviz_lan_settings_error_clears_password,
    ezviz_lan_settings_error_code,
    ezviz_lan_settings_login_candidates,
    ezviz_lan_settings_login_succeeded,
    ezviz_lan_settings_updates_services_switch,
    ezviz_lan_video_qualities,
   ezviz_local_sdk_iv,
    ezviz_local_sdk_ssl_iv,
   ezviz_native_video_level,
    hcnetsdk_command_candidate_role,
    hcnetsdk_real_data_type_is_media,
    hcnetsdk_real_play_request,
    iter_hcnetsdk_real_data_mpegps,
    iter_hcnetsdk_tcp_frame_shapes,
    parse_ezviz_interleaved_rtp_frame_header,
    parse_ezviz_local_device,
    parse_ezviz_local_sdk_frame,
    parse_ezviz_local_sdk_frame_header,
    parse_ezviz_local_sdk_xml_fields,
    parse_hcnetsdk_semantic_log_line,
    parse_hcnetsdk_tcp_frame,
    parse_hcnetsdk_tcp_frame_header,
    parse_hcnetsdk_tcp_shape_log_line,
    parse_sadp_response,
    read_ezviz_interleaved_rtp_frame,
    read_ezviz_interleaved_rtp_frame_after_prefix,
    read_ezviz_local_sdk_frame,
    summarize_hcnetsdk_command_trace,
)

LOCAL_SDK_TEST_KEY = b"1234567890abcdef"
LOCAL_SDK_TEST_IV = b"CAM1234560123456"
LOCAL_SDK_SSL_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
LOCAL_SDK_RESPONSE_TRAILER = b"0" * 32
HCNETSDK_TCP_MIN_PRINTABLE_RATIO = 0.5
HCNETSDK_TCP_LOG_PRINTABLE_RATIO = 0.21
HCNETSDK_TCP_LOG_NULL_RATIO = 0.10
HCNETSDK_TCP_LOG_HIGH_BIT_RATIO = 0.48
HCNETSDK_TCP_TEST_BODY = b"payload"
STREAM_SETUP_BODY = b"<Request><Session>1</Session></Request>"
EXPECTED_PREVIEW_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op&amp;code</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<ReceiverInfo>receiver&lt;info&gt;</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<ReceiverInfoEx>receiver-ex</ReceiverInfoEx>\n"
    b"\t<Authentication>auth</Authentication>\n"
    b"\t<Uuid>uuid</Uuid>\n"
    b"\t<Timestamp>123456</Timestamp>\n"
    b"</Request>\n"
)
EXPECTED_STRUCTURED_PREVIEW_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<Identifier>ident</Identifier>\n"
    b"\t<ReceiverInfo>\n"
        b"\t\t<NatAddress>192.0.2.10</NatAddress>\n"
    b"\t\t<NatPort>9010</NatPort>\n"
    b"\t\t<UPnPAddress></UPnPAddress>\n"
    b"\t\t<UPnPPort>0</UPnPPort>\n"
        b"\t\t<InnerAddress>192.0.2.20</InnerAddress>\n"
    b"\t\t<InnerPort>9020</InnerPort>\n"
    b"\t\t<StreamType>MAIN</StreamType>\n"
    b"\t</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<Udt>1</Udt>\n"
    b"\t<Nat>2</Nat>\n"
    b"\t<PortGuessType>5</PortGuessType>\n"
    b"\t<Timeout>30</Timeout>\n"
    b"\t<HeartbeatInterval>10</HeartbeatInterval>\n"
    b"\t<ReceiverInfoEx>receiver-ex</ReceiverInfoEx>\n"
    b"</Request>\n"
)
EXPECTED_STRUCTURED_PREVIEW_EX_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<OperationCode>op</OperationCode>\n"
    b"\t<Channel>1</Channel>\n"
    b"\t<ReceiverInfo>receiver</ReceiverInfo>\n"
    b"\t<IsEncrypt>TRUE</IsEncrypt>\n"
    b"\t<ReceiverInfoEx>\n"
    b"\t\t<Authentication>\n"
    b"\t\t\t<Uuid>uuid</Uuid>\n"
    b"\t\t\t<Timestamp>123456</Timestamp>\n"
    b"\t\t</Authentication>\n"
    b"\t</ReceiverInfoEx>\n"
    b"</Request>\n"
)
EXPECTED_STREAM_SETUP_XML = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b"<Request>\n"
    b"\t<Session>1</Session>\n"
    b"\t<Rate>0</Rate>\n"
    b"\t<Mode>1</Mode>\n"
    b"</Request>\n"
)


def test_lan_endpoint_from_connection_uses_ezviz_ports() -> None:
    endpoint = HcNetSdkLanEndpoint.from_connection(
        "CAM123",
        {
            "localIp": " 192.0.2.10 ",
            "localCmdPort": "9010",
            "localStreamPort": 9020,
            "netIp": "203.0.113.10",
            "netCmdPort": 8010,
            "netStreamPort": 9030,
            "localRtspPort": 0,
        },
    )

    assert endpoint.serial == "CAM123"
    assert endpoint.host == "192.0.2.10"
    assert endpoint.net_host == "203.0.113.10"
    assert endpoint.command_port == 9010
    assert endpoint.net_command_port == 8010
    assert endpoint.stream_port == 9020
    assert endpoint.net_stream_port == 9030
    assert endpoint.rtsp_port == HCNETSDK_DEFAULT_RTSP_PORT
    assert endpoint.sdk_tls_port == HCNETSDK_DEFAULT_TLS_PORT


def test_lan_endpoint_from_connection_defaults_command_port() -> None:
    endpoint = HcNetSdkLanEndpoint.from_connection(
        "CAM123",
        {"localIp": "192.0.2.10"},
    )

    assert endpoint.command_port == HCNETSDK_DEFAULT_SERVER_PORT


def test_lan_endpoint_requires_local_ip() -> None:
    with pytest.raises(PyEzvizError, match="localIp"):
        HcNetSdkLanEndpoint.from_connection("CAM123", {"localCmdPort": 9010})


def test_parse_sadp_response_extracts_common_fields() -> None:
    info = parse_sadp_response(
        b"\x00\x00<ProbeMatch>"
        b"<DeviceSN>CAM123456</DeviceSN>"
        b"<IPv4Address>192.0.2.10</IPv4Address>"
        b"<CommandPort>9010</CommandPort>"
        b"</ProbeMatch>\x00"
    )

    assert info.serial == "CAM123456"
    assert info.ipv4_address == "192.0.2.10"
    assert info.command_port == 9010


def test_parse_sadp_response_rejects_non_xml() -> None:
    with pytest.raises(PyEzvizError, match="XML"):
        parse_sadp_response(b"not xml")


def test_parse_ezviz_local_sdk_frame_header_from_local_trace() -> None:
    header = bytes.fromhex(
        "9e ba ac e9 01 00 00 00 00 00 00 15 00 00 00 00 "
        "00 00 31 05 ff ff ff ff 00 00 00 80 00 00 00 00"
    )

    parsed = parse_ezviz_local_sdk_frame_header(header)

    assert parsed.magic == bytes.fromhex("9e ba ac e9")
    assert parsed.version == 0x01000000
    assert parsed.sequence == 0x15
    assert parsed.marker == 0
    assert parsed.command == 0x3105
    assert parsed.status == 0xFFFFFFFF
    assert parsed.body_length == 0x80
    assert parsed.reserved == 0


def test_build_ezviz_local_sdk_frame_header_matches_local_shape() -> None:
    header = build_ezviz_local_sdk_frame_header(
        command=0x3105,
        body_length=0x80,
        sequence=0x15,
    )

    assert header == bytes.fromhex(
        "9e ba ac e9 01 00 00 00 00 00 00 15 00 00 00 00 "
        "00 00 31 05 ff ff ff ff 00 00 00 80 00 00 00 00"
    )


def test_build_and_parse_ezviz_local_sdk_frame_round_trips_body() -> None:
    body = b"<Request><Channel>1</Channel></Request>"

    frame = build_ezviz_local_sdk_frame(
        command=0x2011,
        body=body,
        sequence=7,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x2011
    assert parsed.header.sequence == 7
    assert parsed.header.body_length == len(parsed.body)
    assert parsed.body == body


def test_encrypt_ezviz_local_sdk_body_aes_cbc_round_trips() -> None:
    key = b"0123456789abcdef"
    iv = b"abcdef0123456789"
    body = b"<Request><Session>7</Session></Request>"

    encrypted = encrypt_ezviz_local_sdk_body_aes_cbc(body, key=key, iv=iv)

    assert len(encrypted) % 16 == 0
    assert encrypted != body
    assert decrypt_ezviz_local_sdk_body_aes_cbc(encrypted, key=key, iv=iv) == body


def test_build_encrypted_ezviz_local_sdk_frame_wraps_encrypted_body() -> None:
    body = b"<Request/>"
    frame = build_encrypted_ezviz_local_sdk_frame(
        command=0x3105,
        body=body,
        key="0123456789abcdef",
        iv="abcdef0123456789",
        sequence=19,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x3105
    assert parsed.header.sequence == 19
    assert parsed.header.body_length == 16
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key="0123456789abcdef",
        iv="abcdef0123456789",
    ) == body


def test_build_ezviz_local_sdk_ssl_frame_appends_ciphertext_md5_trailer() -> None:
    body = b"<Request/>"
    frame = build_ezviz_local_sdk_ssl_frame(
        command=0x2011,
        body=body,
        key=LOCAL_SDK_TEST_KEY,
        iv=LOCAL_SDK_SSL_IV,
        sequence=16,
    )

    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == 0x2011
    assert parsed.header.sequence == 16
    assert parsed.header.body_length == 16
    assert parsed.trailer == hashlib.md5(
        parsed.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert len(frame) == 32 + parsed.header.body_length + 32
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=LOCAL_SDK_TEST_KEY,
        iv=LOCAL_SDK_SSL_IV,
    ) == body


def test_ezviz_cas_device_info_derives_local_sdk_iv() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
        encrypt_type=2,
    )

    assert device_info.key_bytes == LOCAL_SDK_TEST_KEY
    assert device_info.iv_bytes == LOCAL_SDK_TEST_IV
    assert ezviz_local_sdk_iv("CAM123456", "0123456") == LOCAL_SDK_TEST_IV


def test_ezviz_cas_device_info_accepts_base64_local_sdk_key() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="MTIzNDU2Nzg5MGFiY2RlZg==",
        encrypt_type=2,
    )

    assert device_info.key_bytes == LOCAL_SDK_TEST_KEY


def test_ezviz_local_sdk_ssl_iv_uses_app_prefix_and_zero_tail() -> None:
    iv = ezviz_local_sdk_ssl_iv()

    assert iv == b"01234567" + bytes(8)


def test_build_ezviz_cas_encrypted_local_sdk_frame_uses_device_info() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )
    body = "<Request><Session>1</Session></Request>"

    frame = build_ezviz_cas_encrypted_local_sdk_frame(
        command=EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
        body=body,
        device_info=device_info,
        sequence=21,
    )
    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert parsed.header.sequence == 21
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=device_info.key_bytes,
        iv=device_info.iv_bytes,
    ) == body.encode()


def test_build_ezviz_cas_ssl_local_sdk_frame_uses_cas_key_and_md5_trailer() -> None:
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )
    body = "<Request><Session>1</Session></Request>"

    frame = build_ezviz_cas_ssl_local_sdk_frame(
        command=EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND,
        body=body,
        device_info=device_info,
        iv=LOCAL_SDK_SSL_IV,
        sequence=17,
    )
    parsed = parse_ezviz_local_sdk_frame(frame)

    assert parsed.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert parsed.header.sequence == 17
    assert parsed.trailer == hashlib.md5(
        parsed.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        parsed.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == body.encode()


def test_build_ezviz_local_preview_request_body_uses_observed_tag_order() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op&code",
        channel=1,
        receiver_info="receiver<info>",
        receiver_info_ex="receiver-ex",
        authentication="auth",
        uuid="uuid",
        timestamp=123456,
    )

    assert body == EXPECTED_PREVIEW_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "ReceiverInfo",
        "IsEncrypt",
        "ReceiverInfoEx",
        "Authentication",
        "Uuid",
        "Timestamp",
    )


def test_build_ezviz_local_preview_request_body_supports_structured_receiver_info() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=1,
        identifier="ident",
        receiver_info=EzvizLocalReceiverInfo(
            nat_address="192.0.2.10",
            nat_port=9010,
            upnp_address="",
            upnp_port=0,
            inner_address="192.0.2.20",
            inner_port=9020,
            stream_type="MAIN",
        ),
        receiver_info_ex="receiver-ex",
        udt=1,
        nat=2,
        port_guess_type=5,
        timeout=30,
        heartbeat_interval=10,
    )

    assert body == EXPECTED_STRUCTURED_PREVIEW_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "Identifier",
        "ReceiverInfo",
        "NatAddress",
        "NatPort",
        "UPnPAddress",
        "UPnPPort",
        "InnerAddress",
        "InnerPort",
        "StreamType",
        "IsEncrypt",
        "Udt",
        "Nat",
        "PortGuessType",
        "Timeout",
        "HeartbeatInterval",
        "ReceiverInfoEx",
    )


def test_ezviz_local_receiver_info_rejects_negative_ports() -> None:
    request = EzvizLocalPreviewRequest(
        operation_code="op",
        channel=1,
        receiver_info=EzvizLocalReceiverInfo(nat_port=-1),
        receiver_info_ex="receiver-ex",
    )

    with pytest.raises(PyEzvizError, match="nat_port"):
        request.to_xml()


def test_build_ezviz_local_preview_request_body_supports_structured_receiver_info_ex() -> None:
    body = build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=1,
        receiver_info="receiver",
        receiver_info_ex=EzvizLocalReceiverInfoEx(uuid="uuid", timestamp=123456),
    )

    assert body == EXPECTED_STRUCTURED_PREVIEW_EX_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "OperationCode",
        "Channel",
        "ReceiverInfo",
        "IsEncrypt",
        "ReceiverInfoEx",
        "Authentication",
        "Uuid",
        "Timestamp",
    )


def test_ezviz_local_preview_request_to_xml_matches_builder() -> None:
    request = EzvizLocalPreviewRequest(
        operation_code="op",
        channel=2,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )

    assert request.to_xml() == build_ezviz_local_preview_request_body(
        operation_code="op",
        channel=2,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )


def test_build_ezviz_local_stream_setup_request_body_uses_observed_shape() -> None:
    body = build_ezviz_local_stream_setup_request_body(session="1", rate=0, mode=1)

    assert body == EXPECTED_STREAM_SETUP_XML
    assert classify_ezviz_local_sdk_body(body).xml_tags == (
        "Request",
        "Session",
        "Rate",
        "Mode",
    )


def test_parse_ezviz_local_sdk_xml_fields_extracts_response_values() -> None:
    frame = build_ezviz_local_sdk_frame(
        command=0x2012,
        body=(
            "<Response><Result>0</Result><Session>765</Session>"
            "<StreamHeader>header</StreamHeader></Response>"
        ),
    )

    fields = parse_ezviz_local_sdk_xml_fields(parse_ezviz_local_sdk_frame(frame))

    assert fields == {
        "Result": "0",
        "Session": "765",
        "StreamHeader": "header",
    }


def test_encrypt_ezviz_local_sdk_body_aes_cbc_rejects_bad_key_length() -> None:
    with pytest.raises(PyEzvizError, match="key"):
        encrypt_ezviz_local_sdk_body_aes_cbc(b"body", key=b"short", iv=b"0" * 16)


def test_ezviz_local_sdk_iv_rejects_bad_length() -> None:
    with pytest.raises(PyEzvizError, match="16 bytes"):
        ezviz_local_sdk_iv("CAM123", "short")


def test_read_ezviz_local_sdk_frame_handles_fragmented_socket_reads() -> None:
    body = b"<Response/>"
    frame = build_ezviz_local_sdk_frame(command=0x2012, body=body)
    sock = _FragmentedSocket([frame[:5], frame[5:33], frame[33:]])

    parsed = read_ezviz_local_sdk_frame(sock)

    assert parsed.header.command == 0x2012
    assert parsed.body == body


def test_classify_ezviz_local_sdk_body_detects_xml_tags_only() -> None:
    shape = classify_ezviz_local_sdk_body(
        b'<?xml version="1.0"?><Response><Result>0</Result></Response>'
    )

    assert shape.kind == "xml"
    assert shape.length > 0
    assert shape.xml_offset == 0
    assert shape.xml_tags == ("Response", "Result")
    assert shape.printable_ratio == 1.0


def test_classify_ezviz_local_sdk_body_detects_prefixed_xml() -> None:
    shape = classify_ezviz_local_sdk_body(
        b"\x01\x02\x00\x00<?xml version=\"1.0\"?><Response/>"
    )

    assert shape.kind == "prefixed_xml"
    assert shape.xml_offset == 4
    assert shape.xml_tags == ("Response",)


def test_classify_ezviz_local_sdk_body_detects_opaque_binary() -> None:
    shape = classify_ezviz_local_sdk_body(bytes(range(128, 256)))

    assert shape.kind == "opaque_binary"
    assert shape.xml_offset is None
    assert shape.xml_tags == ()
    assert shape.high_bit_ratio == 1.0


def test_classify_ezviz_local_sdk_body_detects_empty_body() -> None:
    shape = classify_ezviz_local_sdk_body(b"")

    assert shape.kind == "empty"
    assert shape.length == 0
    assert shape.entropy_bits_per_byte == 0.0


def test_classify_hcnetsdk_tcp_payload_detects_tls_records() -> None:
    shape = classify_hcnetsdk_tcp_payload(bytes.fromhex("16 03 01 00 04 01 02 03 04"))

    assert shape.kind == "tls_record"
    assert shape.length == 9
    assert shape.u16be_0 == 0x1603
    assert shape.u32be_0 == 0x16030100


def test_classify_hcnetsdk_tcp_payload_detects_length_prefixed_binary() -> None:
    payload = len(b"\x00\x00\x00\x0cabcdefgh").to_bytes(4, "big") + b"abcdefgh"

    shape = classify_hcnetsdk_tcp_payload(payload)

    assert shape.kind == "length_prefixed_binary"
    assert shape.declared_length_offset == 0
    assert shape.declared_length == len(payload)
    assert shape.u32be_0 == len(payload)
    assert shape.u32be_4 == int.from_bytes(b"abcd", "big")
    assert shape.u32le_4 == int.from_bytes(b"abcd", "little")
    assert shape.printable_ratio > HCNETSDK_TCP_MIN_PRINTABLE_RATIO


def test_classify_hcnetsdk_tcp_payload_detects_local_sdk_frame() -> None:
    frame = build_ezviz_local_sdk_frame(command=EZVIZ_LOCAL_SDK_PREVIEW_COMMAND)

    shape = classify_hcnetsdk_tcp_payload(frame)

    assert shape.kind == "ezviz_local_sdk_frame"
    assert shape.u32be_0 == 0x9EBAACE9


def test_parse_hcnetsdk_tcp_shape_log_line_from_narrow_hook() -> None:
    line = (
        "[hcnetsdk-send] fd=42 192.0.2.10:8000 "
        "tcpKind=opaque_binary tcpLen=84 captured=84 fp128=84:0123abcd "
        f"printable={HCNETSDK_TCP_LOG_PRINTABLE_RATIO} "
        f"nulls={HCNETSDK_TCP_LOG_NULL_RATIO} "
        f"high={HCNETSDK_TCP_LOG_HIGH_BIT_RATIO} "
        "u16be0=0x1234 u16le0=0x3412 u32be0=0x12345678 u32le0=0x78563412 "
        "u32be4=0x00000054 u32le4=0x54000000 "
        "u32be8=0x00000001 u32le8=0x01000000 "
        "u32be12=0x00000100 u32le12=0x00010000 "
        "lengthCandidates=u32be@4=84,u16le@12=80"
    )

    record = parse_hcnetsdk_tcp_shape_log_line(line)

    assert record is not None
    assert record.direction == "send"
    assert record.fd == 42
    assert record.host == "192.0.2.10"
    assert record.port == 8000
    assert record.shape.kind == "opaque_binary"
    assert record.shape.length == 84
    assert record.shape.printable_ratio == HCNETSDK_TCP_LOG_PRINTABLE_RATIO
    assert record.shape.null_ratio == HCNETSDK_TCP_LOG_NULL_RATIO
    assert record.shape.high_bit_ratio == HCNETSDK_TCP_LOG_HIGH_BIT_RATIO
    assert record.shape.u16be_0 == 0x1234
    assert record.shape.u16le_0 == 0x3412
    assert record.shape.u32be_0 == 0x12345678
    assert record.shape.u32le_0 == 0x78563412
    assert record.shape.u32be_4 == 84
    assert record.shape.u32le_4 == 0x54000000
    assert record.shape.u32be_8 == 1
    assert record.shape.u32le_8 == 0x01000000
    assert record.shape.u32be_12 == 256
    assert record.shape.u32le_12 == 0x00010000
    assert record.shape.declared_length_offset == 4
    assert record.shape.declared_length == 84
    assert record.captured_length == 84
    assert record.fingerprint == "84:0123abcd"
    assert record.length_candidates == {"u32be@4": 84, "u16le@12": 80}


def test_parse_hcnetsdk_tcp_shape_log_line_ignores_other_lines() -> None:
    assert parse_hcnetsdk_tcp_shape_log_line("[hcnetsdk-connect] fd=1 ret=0") is None


def test_parse_hcnetsdk_semantic_log_line_from_login_event() -> None:
    event = parse_hcnetsdk_semantic_log_line(
        "[hcnetsdk-semantic] HCNETUtil.s enter "
        "ip=192.0.2.10 port=8000 user=admin pwdLen=6"
    )

    assert event is not None
    assert event.name == "HCNETUtil.s"
    assert event.phase == "enter"
    assert event.fields == {
        "ip": "192.0.2.10",
        "port": "8000",
        "user": "admin",
        "pwdLen": "6",
    }


def test_parse_hcnetsdk_semantic_log_line_from_keyframe_event() -> None:
    event = parse_hcnetsdk_semantic_log_line(
        "[hcnetsdk-semantic] Java HCNetSDK.NET_DVR_MakeKeyFrame leave ret=true"
    )

    assert event is not None
    assert event.name == "Java HCNetSDK.NET_DVR_MakeKeyFrame"
    assert event.phase == "leave"
    assert event.fields == {"ret": "true"}


def test_parse_hcnetsdk_semantic_log_line_ignores_other_lines() -> None:
    assert parse_hcnetsdk_semantic_log_line("[hcnetsdk-send] fd=1") is None
    assert (
        parse_hcnetsdk_semantic_log_line(
            "[hcnetsdk-semantic] waiting for Core_SimpleCommandToDvr "
            "symbol=Core_SimpleCommandToDvr"
        )
        is None
    )
    assert (
        parse_hcnetsdk_semantic_log_line(
            "[hcnetsdk-semantic] Java HCNetSDK login hooks unavailable "
            "TypeError: cannot read property 'overloads' of undefined"
        )
        is None
    )


def test_summarize_hcnetsdk_command_trace_correlates_semantic_boundaries() -> None:
    summary = summarize_hcnetsdk_command_trace(
        [
            (
                "[hcnetsdk-semantic] HCNETUtil.s enter "
                "ip=192.0.2.10 port=8000 user=admin pwdLen=6"
            ),
            (
                "[hcnetsdk-send] fd=296 192.0.2.10:8000 "
                "tcpKind=opaque_binary tcpLen=224 captured=224 fp128=128:93276c8d "
                "printable=0.28 nulls=0.30 high=0.30 "
                "u32be0=0xe0 u32le0=0xe0000000 "
                "u32be4=0x5a000000 u32le4=0x5a "
                "lengthCandidates=u32be@0=224,u32le@4=90"
            ),
            (
                "[hcnetsdk-send] fd=296 192.0.2.10:8000 "
                "tcpKind=binary tcpLen=84 captured=84 fp128=84:b0b0718e "
                "printable=0.24 nulls=0.46 high=0.19 "
                "u32be0=0x54 u32le0=0x54000000 "
                "u32be4=0x5a000000 u32le4=0x5a "
                "lengthCandidates=u32be@0=84,u32le@4=90"
            ),
            "[hcnetsdk-semantic] HCNETUtil.s leave ret=0",
            (
                "[hcnetsdk-send] fd=231 192.0.2.10:8000 "
                "tcpKind=binary tcpLen=36 captured=36 fp128=36:11b54ed7 "
                "printable=0.11 nulls=0.53 high=0.14 "
                "u32be0=0x24 u32le0=0x24000000 "
                "u32be4=0x63000000 u32le4=0x63 "
                "lengthCandidates=u32be@0=36,u32le@4=99"
            ),
            (
                "[hcnetsdk-recv] fd=240 192.0.2.10:8000 "
                "tcpKind=interleaved_media tcpLen=1448 captured=512 "
                "fp128=128:abc printable=0.20 nulls=0.10 high=0.50 "
                "u32be0=0x24000000 u32le0=0x24"
            ),
            "[hcnetsdk-semantic] DeviceInfoEx.loginPlayDevice leave ret=0",
            "[hcnetsdk-semantic] Java HCNetSDK.NET_DVR_MakeKeyFrame leave ret=true",
        ]
    )

    assert summary.settings_login_commands == (90, 90)
    assert summary.followup_commands == (99,)
    assert summary.settings_login_success is True
    assert summary.play_device_login_success is True
    assert summary.keyframe_requested is True
    assert summary.media_on_command_socket is True


def test_iter_hcnetsdk_tcp_frame_shapes_pairs_split_response() -> None:
    lines = [
        (
            "[hcnetsdk-recv] fd=250 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=16 captured=16 fp128=16:ae3f80bf "
            "printable=0.25 nulls=0.56 high=0.06 "
            "u32be0=0xd0 u32le0=0xd0000000 "
            "u32be4=0x00000001 u32le4=0x01000000 "
            "u32be8=0x00000001 u32le8=0x01000000 "
            "u32be12=0x00000000 u32le12=0x00000000 "
            "lengthCandidates=u32be@0=208"
        ),
        (
            "[hcnetsdk-recv] fd=250 192.0.2.10:8000 "
            "tcpKind=opaque_binary tcpLen=192 captured=192 fp128=128:60a94981 "
            "printable=0.59 nulls=0.01 high=0.33 "
            "u32be0=0x2cf7bfa5 u32le0=0xa5bff72c"
        ),
    ]
    records = [parse_hcnetsdk_tcp_shape_log_line(line) for line in lines]

    frames = list(iter_hcnetsdk_tcp_frame_shapes(record for record in records if record))

    assert len(frames) == 1
    assert frames[0].direction == "recv"
    assert frames[0].fd == 250
    assert frames[0].total_length == 208
    assert frames[0].body_length == 192
    assert frames[0].header_shape.u32be_4 == 1
    assert frames[0].header_shape.u32be_8 == 1
    assert frames[0].body_shape is not None
    assert frames[0].body_shape.kind == "opaque_binary"
    assert frames[0].body_shape.length == 192


def test_iter_hcnetsdk_tcp_frame_shapes_yields_whole_write_shape() -> None:
    record = parse_hcnetsdk_tcp_shape_log_line(
        "[hcnetsdk-send] fd=250 192.0.2.10:8000 "
        "tcpKind=opaque_binary tcpLen=224 captured=224 fp128=128:93276c8d "
        "printable=0.28 nulls=0.30 high=0.30 "
        "u32be0=0xe0 u32le0=0xe0000000 "
        "u32be4=0x5a000000 u32le4=0x0000005a "
        "u32be8=0x00000000 u32le8=0x00000000 "
        "u32be12=0x00000100 u32le12=0x00010000 "
        "lengthCandidates=u32be@0=224,u32le@4=90,u32le@12=256"
    )

    frames = list(iter_hcnetsdk_tcp_frame_shapes([record] if record else []))

    assert len(frames) == 1
    assert frames[0].direction == "send"
    assert frames[0].total_length == 224
    assert frames[0].body_length == 208
    assert frames[0].header_shape.u32le_4 == 90
    assert frames[0].write_command_candidate == 90
    assert frames[0].header_shape.u32be_12 == 256
    assert frames[0].body_shape is None
    assert frames[0].write_command_role == "settings_login"


def test_hcnetsdk_command_candidate_role_labels_observed_values() -> None:
    assert (
        hcnetsdk_command_candidate_role(HCNETSDK_COMMAND_CANDIDATE_SETTINGS_LOGIN)
        == "settings_login"
    )
    assert hcnetsdk_command_candidate_role(HCNETSDK_COMMAND_CANDIDATE_CONTROL) == "control"
    assert hcnetsdk_command_candidate_role(None) is None
    assert hcnetsdk_command_candidate_role(12345) is None


def test_iter_hcnetsdk_tcp_frame_shapes_uses_header_word_when_candidate_missing() -> None:
    records = [
        parse_hcnetsdk_tcp_shape_log_line(
            "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=16 captured=16 fp128=16:fa807bfd "
            "printable=0.00 nulls=0.75 high=0.13 "
            "u32be0=0x12a8 u32le0=0xa8120000 "
            "u32be4=0x000000ab u32le4=0xab000000 "
            "u32be8=0x00000001 u32le8=0x01000000 "
            "u32be12=0x00000000 u32le12=0x00000000 "
            "lengthCandidates=u32be@4=171,u32be@8=1"
        ),
        parse_hcnetsdk_tcp_shape_log_line(
            "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
            "tcpKind=binary tcpLen=4760 captured=512 fp128=128:c849f99f "
            "printable=0.00 nulls=1.00 high=0.00 "
            "u32be0=0x1298 u32le0=0x98120000 "
            "lengthCandidates=u32be@0=4760"
        ),
    ]

    frames = list(iter_hcnetsdk_tcp_frame_shapes(record for record in records if record))

    assert len(frames) == 1
    assert frames[0].total_length == 4776
    assert frames[0].body_length == 4760
    assert frames[0].header_shape.u32be_4 == 171
    assert frames[0].write_command_candidate is None
    assert frames[0].body_shape is not None
    assert frames[0].body_shape.length == 4760


def test_iter_hcnetsdk_tcp_frame_shapes_skips_body_like_recv_record() -> None:
    record = parse_hcnetsdk_tcp_shape_log_line(
        "[hcnetsdk-recv] fd=266 192.0.2.10:8000 "
        "tcpKind=binary tcpLen=4760 captured=512 fp128=128:c849f99f "
        "printable=0.00 nulls=1.00 high=0.00 "
        "u32be0=0x1298 u32le0=0x98120000 "
        "lengthCandidates=u32be@0=4760"
    )

    frames = list(iter_hcnetsdk_tcp_frame_shapes([record] if record else []))

    assert frames == []


def test_parse_hcnetsdk_tcp_frame_header_matches_split_response() -> None:
    header = parse_hcnetsdk_tcp_frame_header(
        bytes.fromhex("00 00 00 d0 00 00 00 01 00 00 00 01 00 00 00 00")
    )

    assert HCNETSDK_TCP_HEADER_LENGTH == 16
    assert header.total_length == 208
    assert header.body_length == 192
    assert header.field_4 == 1
    assert header.field_8 == 1
    assert header.field_12 == 0


def test_parse_hcnetsdk_tcp_frame_round_trips_generic_wrapper() -> None:
    frame_bytes = build_hcnetsdk_tcp_frame(
        HCNETSDK_TCP_TEST_BODY, field_4=99, field_8=1
    )

    frame = parse_hcnetsdk_tcp_frame(frame_bytes)

    assert frame.header.total_length == HCNETSDK_TCP_HEADER_LENGTH + len(
        HCNETSDK_TCP_TEST_BODY
    )
    assert frame.header.field_4 == 99
    assert frame.header.field_8 == 1
    assert frame.header.field_12 == 0
    assert frame.body == HCNETSDK_TCP_TEST_BODY
    assert frame.to_bytes() == frame_bytes


def test_parse_hcnetsdk_tcp_frame_rejects_truncated_body() -> None:
    with pytest.raises(PyEzvizError, match="truncated"):
        parse_hcnetsdk_tcp_frame(bytes.fromhex("00 00 00 20") + (b"\x00" * 12))


def test_classify_hcnetsdk_tcp_payload_detects_interleaved_media() -> None:
    shape = classify_hcnetsdk_tcp_payload(bytes.fromhex("24 00 00 01 80"))

    assert shape.kind == "interleaved_media"
    assert shape.u16be_0 == 0x2400


def test_parse_hcnetsdk_tcp_shape_log_line_from_media_trace() -> None:
    line = (
        "[hcnetsdk-recv] fd=240 192.0.2.10:8000 "
        "tcpKind=interleaved_media tcpLen=7988 captured=512 fp128=128:1aeb56e5 "
        "printable=0.37 nulls=0.02 high=0.46 "
        "u16be0=0x2400 u16le0=0x24 u32be0=0x24000001 u32le0=0x1000024"
    )

    record = parse_hcnetsdk_tcp_shape_log_line(line)

    assert record is not None
    assert record.direction == "recv"
    assert record.fd == 240
    assert record.shape.kind == "interleaved_media"
    assert record.shape.length == 7988
    assert record.captured_length == 512
    assert record.fingerprint == "128:1aeb56e5"
    assert record.shape.u16be_0 == 0x2400


def test_parse_ezviz_local_sdk_frame_header_rejects_bad_magic() -> None:
    with pytest.raises(PyEzvizError, match="magic"):
        parse_ezviz_local_sdk_frame_header(b"bad" + (b"x" * 29))


def test_parse_ezviz_interleaved_rtp_frame_header_from_local_trace() -> None:
    parsed = parse_ezviz_interleaved_rtp_frame_header(bytes.fromhex("24 00 05 86"))

    assert parsed.channel == 0
    assert parsed.payload_length == 1414


def test_build_ezviz_interleaved_rtp_frame_header_round_trips() -> None:
    header = build_ezviz_interleaved_rtp_frame_header(
        channel=2,
        payload_length=188,
    )

    parsed = parse_ezviz_interleaved_rtp_frame_header(header)

    assert header == bytes.fromhex("24 02 00 bc")
    assert parsed.channel == 2
    assert parsed.payload_length == 188


def test_read_ezviz_interleaved_rtp_frame_handles_fragmented_socket_reads() -> None:
    payload = b"rtp!"
    sock = _FragmentedSocket(
        [
            bytes.fromhex("24"),
            bytes.fromhex("00 00"),
            bytes.fromhex("04"),
            payload[:2],
            payload[2:],
        ]
    )

    frame = read_ezviz_interleaved_rtp_frame(sock)

    assert frame.header.channel == 0
    assert frame.header.payload_length == 4
    assert frame.payload == payload


def test_read_ezviz_interleaved_rtp_frame_after_prefix_keeps_local_preface() -> None:
    prefix = bytes.fromhex(
        "01 00 01 01 00 28 00 00 00 00 27 29 45 38 37 32"
    )
    payload = b"rtp-payload"
    sock = _FragmentedSocket(
        [
            prefix[:3],
            prefix[3:],
            bytes.fromhex("24 00"),
            len(payload).to_bytes(2, "big"),
            payload,
        ]
    )

    read = read_ezviz_interleaved_rtp_frame_after_prefix(sock)

    assert read.prefix == prefix
    assert read.frame.header.channel == 0
    assert read.frame.header.payload_length == len(payload)
    assert read.frame.payload == payload


def test_read_ezviz_interleaved_rtp_frame_after_prefix_rejects_long_preface() -> None:
    sock = _FragmentedSocket([b"abcdef"])

    with pytest.raises(PyEzvizError, match="prefix exceeded"):
        read_ezviz_interleaved_rtp_frame_after_prefix(sock, max_prefix_bytes=3)


def test_ezviz_local_sdk_client_bootstraps_preview_and_first_media() -> None:
    pre_start_response = build_ezviz_local_sdk_frame(
        command=0x2014,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>0</Result><Session>1</Session></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    stream_response = build_ezviz_local_sdk_frame(
        command=0x3106,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    media_prefix = bytes.fromhex("01 00 01 01")
    media_payload = b"rtp-payload"
    command_sock = _FakeSocket([pre_start_response, command_response])
    stream_sock = _FakeSocket(
        [
            stream_response,
            media_prefix,
            bytes.fromhex("24 00"),
            len(media_payload).to_bytes(2, "big"),
            media_payload,
        ]
    )
    connect_calls: list[tuple[tuple[str, int], float | None]] = []

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        connect_calls.append((address, timeout))
        if address[1] == 9010:
            return command_sock
        return stream_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        timeout=3.0,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client:
        result = client.bootstrap_preview(
            preview_body="<Request><OperationCode>0123456</OperationCode></Request>",
            stream_setup_body=STREAM_SETUP_BODY,
            pre_start_body="<Request/>",
            pre_start_sequence=27,
            preview_sequence=28,
            stream_setup_sequence=29,
            read_first_media=True,
        )

    assert connect_calls == [
        (("192.0.2.10", 9010), 3.0),
        (("192.0.2.10", 9020), 3.0),
    ]
    assert result.pre_start is not None
    assert result.pre_start.response.header.command == 0x2014
    assert result.preview.response.header.command == 0x2012
    assert result.stream_setup.response.header.command == 0x3106
    assert result.first_media is not None
    assert result.first_media.prefix == media_prefix
    assert result.first_media.frame.payload == media_payload

    pre_start_request = parse_ezviz_local_sdk_frame(command_sock.sent[0])
    preview_request = parse_ezviz_local_sdk_frame(command_sock.sent[1])
    stream_request = parse_ezviz_local_sdk_frame(stream_sock.sent[0])
    assert pre_start_request.header.command == EZVIZ_LOCAL_SDK_PRE_START_COMMAND
    assert pre_start_request.header.sequence == 27
    assert preview_request.header.command == EZVIZ_LOCAL_SDK_PREVIEW_COMMAND
    assert preview_request.header.sequence == 28
    assert stream_request.header.command == EZVIZ_LOCAL_SDK_STREAM_SETUP_COMMAND
    assert stream_request.header.sequence == 29
    assert stream_request.trailer == hashlib.md5(
        stream_request.body, usedforsecurity=False
    ).hexdigest().encode("ascii")
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        stream_request.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == STREAM_SETUP_BODY
    assert command_sock.closed is True
    assert stream_sock.closed is True


def test_ezviz_local_sdk_client_builds_stream_setup_from_preview_session() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>0</Result><Session>765</Session></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    stream_response = build_ezviz_local_sdk_frame(
        command=0x3106,
        body="<Response><Result>0</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])
    stream_sock = _FakeSocket([stream_response])

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        return command_sock if address[1] == 9010 else stream_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client:
        result = client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            ),
            preview_sequence=31,
            stream_setup_sequence=32,
            stream_rate=2,
            stream_mode=1,
        )

    assert result.pre_start is None
    assert result.preview.response.header.command == 0x2012
    assert result.stream_setup.response.header.command == 0x3106
    stream_request = parse_ezviz_local_sdk_frame(stream_sock.sent[0])
    assert stream_request.header.sequence == 32
    assert decrypt_ezviz_local_sdk_body_aes_cbc(
        stream_request.body,
        key=device_info.key_bytes,
        iv=LOCAL_SDK_SSL_IV,
    ) == build_ezviz_local_stream_setup_request_body(
        session="765",
        rate=2,
        mode=1,
    )


def test_ezviz_local_sdk_client_can_bind_command_source_port() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>257</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])
    connect_calls: list[tuple[tuple[str, int], float | None, tuple[str, int] | None]] = []

    def socket_factory(
        address: tuple[str, int],
        timeout: float | None,
        source_address: tuple[str, int] | None = None,
    ) -> _FakeSocket:
        connect_calls.append((address, timeout, source_address))
        return command_sock

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=socket_factory,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
        command_source_port=10103,
    ) as client, pytest.raises(PyEzvizError, match="Result=257"):
        client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            )
        )

    assert connect_calls == [(("192.0.2.10", 9010), 5.0, ("", 10103))]


def test_ezviz_local_sdk_client_missing_session_reports_result() -> None:
    command_response = build_ezviz_local_sdk_frame(
        command=0x2012,
        body="<Response><Result>257</Result></Response>",
    ) + LOCAL_SDK_RESPONSE_TRAILER
    command_sock = _FakeSocket([command_response])

    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123456",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )
    device_info = EzvizCasDeviceInfo(
        serial="CAM123456",
        operation_code="0123456",
        key="1234567890abcdef",
    )

    with EzvizLocalSdkClient(
        endpoint,
        device_info,
        socket_factory=lambda _address, _timeout: command_sock,
        iv_factory=lambda _size: LOCAL_SDK_SSL_IV,
    ) as client, pytest.raises(
        PyEzvizError, match=r"missing Session \(Result=257\)"
    ):
        client.bootstrap_preview_from_fields(
            preview_request=EzvizLocalPreviewRequest(
                operation_code="0123456",
                channel=1,
                receiver_info="receiver",
                receiver_info_ex="receiver-ex",
            ),
        )


def test_apk_observed_command_ids_are_named() -> None:
    assert HcNetSdkDvrCommand.GET_WIFI_CFG == 307
    assert HcNetSdkDvrCommand.SET_WIFI_CFG == 306
    assert HcNetSdkDvrCommand.GET_HD_CFG == 1054
    assert HcNetSdkDvrCommand.GET_CAMERA_PARAM_CFG == 1067
    assert HcNetSdkDvrCommand.GET_COMPRESSION_CFG_V30 == 1040


def test_ezviz_lan_login_candidates_match_apk_order() -> None:
    candidates = ezviz_lan_login_candidates(" ABCDEF ", command_port=9010)

    assert candidates[0].api == "NET_DVR_Login_V40"
    assert candidates[0].username == HCNETSDK_EZVIZ_DEFAULT_USERNAME
    assert candidates[0].password == "ABCDEF"
    assert candidates[0].port == HCNETSDK_DEFAULT_TLS_PORT
    assert candidates[0].https is True

    assert candidates[1].api == "NET_DVR_Login_V30"
    assert candidates[1].username == HCNETSDK_EZVIZ_DEFAULT_USERNAME
    assert candidates[1].password == "ABCDEF"
    assert candidates[1].port == 9010

    assert candidates[2].api == "NET_DVR_Login_V30"
    assert candidates[2].username == HCNETSDK_EZVIZ_LOCAL_USERNAME
    assert candidates[2].password == "22a5028b9808c7bf"
    assert candidates[2].port == 9010


def test_ezviz_lan_settings_login_candidates_can_match_scanned_tls_only_path() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=True,
    )

    assert [(candidate.api, candidate.port) for candidate in candidates] == [
        ("NET_DVR_Login_V40", HCNETSDK_DEFAULT_TLS_PORT),
    ]


def test_ezviz_lan_settings_login_candidates_can_skip_tls_for_compatibility() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=False,
    )

    assert [(candidate.username, candidate.api, candidate.port) for candidate in candidates] == [
        (HCNETSDK_EZVIZ_DEFAULT_USERNAME, "NET_DVR_Login_V40", 9010),
        (HCNETSDK_EZVIZ_LOCAL_USERNAME, "NET_DVR_Login_V40", 9010),
    ]
    assert [candidate.https for candidate in candidates] == [False, False]


def test_ezviz_lan_settings_login_candidates_try_v40_command_fallback() -> None:
    candidates = ezviz_lan_settings_login_candidates(
        "ABCDEF",
        command_port=9010,
        login_with_8443=None,
    )

    assert [(candidate.api, candidate.port, candidate.https) for candidate in candidates] == [
        ("NET_DVR_Login_V40", HCNETSDK_DEFAULT_TLS_PORT, True),
        ("NET_DVR_Login_V40", 9010, False),
        ("NET_DVR_Login_V40", 9010, False),
    ]


@pytest.mark.parametrize(
    ("login_with_8443", "login_port", "open_8000", "updates"),
    (
        (True, HCNETSDK_DEFAULT_TLS_PORT, True, True),
        (None, HCNETSDK_DEFAULT_TLS_PORT, False, True),
        (False, HCNETSDK_DEFAULT_TLS_PORT, True, False),
        (None, 9010, True, False),
        (True, HCNETSDK_DEFAULT_TLS_PORT, None, False),
    ),
)
def test_ezviz_lan_settings_updates_services_switch_matches_presenter(
    login_with_8443: bool | None,
    login_port: int,
    open_8000: bool | None,
    updates: bool,
) -> None:
    assert (
        ezviz_lan_settings_updates_services_switch(
            login_with_8443=login_with_8443,
            login_port=login_port,
            open_8000=open_8000,
        )
        is updates
    )


def test_ezviz_lan_local_user_password_matches_add_md5_util() -> None:
    assert ezviz_lan_local_user_password("ABCDEF") == "22a5028b9808c7bf"


def test_ezviz_lan_password_store_names_match_dev_pwd_util() -> None:
    assert (
        ezviz_lan_password_store_name(" user123 ")
        == f"user123{HCNETSDK_EZVIZ_LAN_PASSWORD_PREF_SUFFIX}"
    )
    assert (
        ezviz_lan_password_store_key(" CAM123456 ")
        == f"{HCNETSDK_EZVIZ_LAN_PASSWORD_KEY_PREFIX}CAM123456"
    )


@pytest.mark.parametrize(
    ("func", "value"),
    (
        (ezviz_lan_password_store_name, " "),
        (ezviz_lan_password_store_key, ""),
    ),
)
def test_ezviz_lan_password_store_rejects_empty_values(
    func: Callable[[str], str], value: str
) -> None:
    with pytest.raises(PyEzvizError):
        func(value)


def test_ezviz_lan_services_switch_payload_matches_settings_checkbox() -> None:
    payload = ezviz_lan_services_switch_payload(
        {"servicesSwitch": {"hiksdk": 0, "web": 0, "rtsp": 1}, "other": 2},
        enabled=True,
    )

    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_GET == (
        "GET /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
    )
    assert payload == {
        "servicesSwitch": {"hiksdk": 1, "web": 1, "rtsp": 1},
        "other": 2,
    }


def test_ezviz_lan_services_switch_payload_can_disable_missing_block() -> None:
    assert ezviz_lan_services_switch_payload(None, enabled=False) == {
        "servicesSwitch": {"hiksdk": 0, "web": 0},
    }


def test_ezviz_lan_services_switch_put_request_matches_hcnetutil() -> None:
    payload = {"servicesSwitch": {"hiksdk": 1, "web": 1}, "other": 2}

    assert HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT == (
        "PUT /ISAPI/EZVIZ/IPC/System/servicesSwitch?format=json\\r\\n"
    )
    assert ezviz_lan_services_switch_put_request(payload) == (
        HCNETSDK_EZVIZ_SERVICES_SWITCH_PUT
        + '{"servicesSwitch":{"hiksdk":1,"web":1},"other":2}'
        + "\\r\\n"
    )


@pytest.mark.parametrize(
    ("response", "succeeded"),
    (
        ({"statusCode": 1}, True),
        ({"statusCode": 0}, False),
        ('{"statusCode":1}', True),
    ),
)
def test_ezviz_lan_services_switch_succeeded_matches_hcnetutil(
    response: dict[str, int] | str, succeeded: bool
) -> None:
    assert ezviz_lan_services_switch_succeeded(response) is succeeded


def test_ezviz_lan_services_switch_succeeded_rejects_invalid_json() -> None:
    with pytest.raises(PyEzvizError):
        ezviz_lan_services_switch_succeeded("not-json")


def test_ezviz_lan_settings_error_code_matches_presenter_offset() -> None:
    assert HCNETSDK_EZVIZ_SETTINGS_ERROR_BASE == 0x50910
    assert ezviz_lan_settings_error_code(1) == 0x50911
    assert ezviz_lan_settings_error_code(1100) == 0x50D5C


def test_ezviz_lan_settings_error_clears_password_for_account_errors() -> None:
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_ERROR
        )
        is True
    )
    assert (
        ezviz_lan_settings_error_clears_password(
            HCNETSDK_EZVIZ_SETTINGS_ACCOUNT_PASSWORD_LOCKED_ERROR
        )
        is True
    )
    assert ezviz_lan_settings_error_clears_password(0x50912) is False


def test_ezviz_lan_settings_login_succeeded_accepts_zero_login_id() -> None:
    assert ezviz_lan_settings_login_succeeded(0) is True
    assert ezviz_lan_settings_login_succeeded(42) is True
    assert ezviz_lan_settings_login_succeeded(-1) is False


def test_ezviz_lan_play_device_login_models_player_owned_login() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=8000,
        stream_port=9020,
    )

    login = ezviz_lan_play_device_login(endpoint)

    assert login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert login.facade_api == EZVIZ_PLAY_DATA_INFO_LOGIN_PLAY_DEVICE
    assert login.check_last_login_status is False
    assert login.to_device_param_hint() == {
        "serial": "CAM123",
        "deviceLocalIp": "192.0.2.10",
        "localCmdPort": 8000,
        "localStreamPort": 9020,
    }
    assert ezviz_lan_play_device_login_succeeded(0) is True
    assert ezviz_lan_play_device_login_succeeded(-1) is False


def test_hcnetsdk_real_data_payload_classification() -> None:
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xbaabc") == "mpeg_ps"
    assert classify_hcnetsdk_real_data_payload(b"\x00\x00\x01\xe0abc") == "mpeg_ps_start"
    assert classify_hcnetsdk_real_data_payload(b"Gabc") == "mpeg_ts"
    assert classify_hcnetsdk_real_data_payload(b"HKMIabc") == "hik_hkmi"
    assert classify_hcnetsdk_real_data_payload(b"@@@@abc") == "hik_private"
    assert classify_hcnetsdk_real_data_payload(b"") == "empty"
    assert classify_hcnetsdk_real_data_payload(b"abc") == "unknown"


def test_hcnetsdk_real_data_media_type_detection() -> None:
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.STREAM_DATA) is True
    assert hcnetsdk_real_data_type_is_media(HcNetSdkRealDataType.SYSTEM_HEADER) is False


def test_hcnetsdk_real_play_request_matches_v30_client_info_shape() -> None:
    request = hcnetsdk_real_play_request(
        7,
        channel_number=2,
        link_mode=1,
        blocked=True,
        multicast_ip="239.0.0.1",
    )

    assert request.api == HCNETSDK_REALPLAY_V30
    assert request.callback_api == HCNETSDK_REALDATA_CALLBACK_V30
    assert request.client_info.to_native_dict() == {
        "lChannel": 2,
        "lLinkMode": 1,
        "sMultiCastIP": "239.0.0.1",
    }
    assert request.to_native_args_hint() == {
        "api": HCNETSDK_REALPLAY_V30,
        "login_id": 7,
        "client_info": {
            "lChannel": 2,
            "lLinkMode": 1,
            "sMultiCastIP": "239.0.0.1",
        },
        "callback": HCNETSDK_REALDATA_CALLBACK_V30,
        "blocked": 1,
    }


def test_hcnetsdk_real_play_request_rejects_failed_login() -> None:
    request = hcnetsdk_real_play_request(-1)

    with pytest.raises(PyEzvizError, match="successful login id"):
        request.to_native_args_hint()


def test_hcnetsdk_client_info_rejects_negative_channel() -> None:
    with pytest.raises(PyEzvizError, match="channel"):
        HcNetSdkClientInfo(channel=-1).to_native_dict()


def test_iter_hcnetsdk_real_data_mpegps_filters_callback_packets() -> None:
    packets = [
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"syshead"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"\x00\x00\x01\xbaabc"),
        HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.AUDIO_STREAM_DATA, b"opaque"),
        HcNetSdkRealDataPacket(1, 999, b"\x00\x00\x01\xbadef"),
    ]

    assert list(iter_hcnetsdk_real_data_mpegps(packets)) == [b"\x00\x00\x01\xbaabc"]


def test_ezviz_lan_settings_channel_number_matches_activity_handoff() -> None:
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 1
    )
    assert (
        ezviz_lan_settings_channel_number(
            analog_channel_count=0,
            digital_channel_count=1,
            analog_start_channel=1,
            digital_start_channel=33,
        )
        == 33
    )


@pytest.mark.parametrize(
    ("analog_channel_count", "digital_channel_count"),
    (
        (0, 0),
        (1, 1),
    ),
)
def test_ezviz_lan_settings_channel_number_rejects_non_single_preview(
    analog_channel_count: int, digital_channel_count: int
) -> None:
    with pytest.raises(PyEzvizError, match="one channel"):
        ezviz_lan_settings_channel_number(
            analog_channel_count=analog_channel_count,
            digital_channel_count=digital_channel_count,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_playback_intent_matches_preview_back_navigation() -> None:
    intent = ezviz_lan_playback_intent(
        " CS-CV310-A0-1B2WFR0120200927CCRRTEST123456 ",
        channel_number=1,
        netsdk_login_id=0,
        ssid=None,
    )

    assert intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }


def test_ezviz_lan_playback_intent_can_forward_explicit_lan_user_id() -> None:
    intent = ezviz_lan_playback_intent(
        "CAM123",
        channel_number=1,
        netsdk_login_id=0,
        ssid="123",
    )

    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_LAN_USERID] == 123
    assert intent.to_extra_dict()[EZVIZ_PLAYER_EXTRA_WIFI_SSID] == "123"


def test_ezviz_lan_playback_intent_rejects_failed_login_id() -> None:
    with pytest.raises(PyEzvizError, match="successful login id"):
        ezviz_lan_playback_intent("CAM123", channel_number=1, netsdk_login_id=-1)


def test_parse_ezviz_local_device_decodes_device_content() -> None:
    device = parse_ezviz_local_device(
        {
            "deviceSerial": "CAM123",
            "deviceName": "Test Camera",
            "deviceModel": "C8C",
            "category": "IPC",
            "deviceCategory": "IPC",
            "groupId": "-1",
            "deviceContent": (
                '{"deviceIP":"192.0.2.44","deviceType":1,'
                '"deviceEncType":2,"isLowPower":0,'
                '"deviceMaxActLimit":30,"deviceSdkVersion":4,'
                '"deviceRand":"abc","deviceRoleType":5}'
            ),
        }
    )

    assert device.serial == "CAM123"
    assert device.name == "Test Camera"
    assert device.group_id == -1
    assert device.content is not None
    assert device.content.device_ip == "192.0.2.44"
    assert device.content.device_enc_type == 2
    assert device.endpoint is not None
    assert device.endpoint.host == "192.0.2.44"


def test_ezviz_lan_live_view_params_match_player_lan_shape() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        net_host="203.0.113.10",
        command_port=9010,
        net_command_port=8010,
        stream_port=9020,
        net_stream_port=9030,
    )

    params = ezviz_lan_live_view_params(
        endpoint,
        channel_number=2,
        channel_serial="CAM123-CH2",
        channel_index="2",
        channel_count=4,
        netsdk_login_id=42,
    )

    assert params.channel_serial == "CAM123-CH2"
    assert params.channel_index == "2"
    assert params.channel_count == 4
    assert params.preplay_sps_type == EZVIZ_PREPLAY_SPS_TYPE
    assert params.stream_source == EZVIZ_STREAM_SOURCE_LIVE_MINE
    assert params.stream_inhibit == EZVIZ_STREAM_INHIBIT_LAN
    assert params.stream_timeout_ms == EZVIZ_STREAM_TIMEOUT_MS
    assert params.stream_type == 1
    assert params.video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert params.device_ip == "203.0.113.10"
    assert params.device_local_ip == "192.0.2.10"
    assert params.device_cmd_port == 8010
    assert params.device_cmd_local_port == 9010
    assert params.device_stream_local_port == 9020
    assert params.device_stream_port == 9030
    assert params.netsdk_login_id == 42
    assert params.netsdk_channel_number == 2
    assert params.to_init_param_dict() == {
        "szDevSerial": "CAM123",
        "szChnlSerial": "CAM123-CH2",
        "szChnlIndex": "2",
        "szDevIP": "203.0.113.10",
        "szDevLocalIP": "192.0.2.10",
        "iDevCmdPort": 8010,
        "iDevCmdLocalPort": 9010,
        "iDevStreamPort": 9030,
        "iDevStreamLocalPort": 9020,
        "iChannelCount": 4,
        "iP2PSPS": EZVIZ_PREPLAY_SPS_TYPE,
        "iStreamInhibit": EZVIZ_STREAM_INHIBIT_LAN,
        "iStreamSource": EZVIZ_STREAM_SOURCE_LIVE_MINE,
        "iStreamType": 1,
        "iStreamTimeOut": EZVIZ_STREAM_TIMEOUT_MS,
        "iVideoLevel": 0,
        "iChannelNumber": 2,
        "iNetSDKUserId": 42,
        "iNetSDKChannelNumber": 2,
    }


def test_ezviz_lan_preview_plan_matches_native_call_sequence() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CAM123",
        host="192.0.2.10",
        command_port=9010,
        stream_port=9020,
    )

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=1,
        stream_type=1,
        netsdk_login_id=7,
    )

    assert plan.login_candidates[0].api == "NET_DVR_Login_V40"
    assert plan.login_candidates[0].port == HCNETSDK_DEFAULT_TLS_PORT
    assert plan.login_candidates[1].port == 9010
    assert plan.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.real_play_request is not None
    assert plan.real_play_request.to_native_args_hint()["login_id"] == 7
    assert plan.real_play_request.client_info.to_native_dict()["lChannel"] == 1
    assert plan.play_device_login is not None
    assert plan.play_device_login.api == EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_models_app_flow() -> None:
    endpoint = HcNetSdkLanEndpoint(
        serial="CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        host="192.0.2.10",
        command_port=8000,
        stream_port=0,
    )

    path = ezviz_lan_complete_playback_path(
        endpoint,
        "ABCDEF",
        settings_login_id=0,
        play_device_login_id=7,
        analog_channel_count=1,
        digital_channel_count=0,
        analog_start_channel=1,
        digital_start_channel=33,
        stream_type=EZVIZ_LAN_MAIN_STREAM_TYPE,
    )

    assert path.settings_login_candidates[0].api == "NET_DVR_Login_V40"
    assert path.settings_login_candidates[0].https is True
    assert path.settings_login_candidates[1].port == 8000
    assert path.settings_login_id == 0
    assert path.channel_number == 1
    assert path.playback_intent.to_extra_dict() == {
        EZVIZ_PLAYER_EXTRA_DEVICE_ID: "CS-CV310-A0-1B2WFR0120200927CCRRTEST123456",
        EZVIZ_PLAYER_EXTRA_CHANNEL_NO: 1,
        EZVIZ_PLAYER_EXTRA_LAN_FLAG: EZVIZ_PLAYER_LAN_FLAG_HCNETSDK,
        EZVIZ_PLAYER_EXTRA_LAN_USERID: -1,
        EZVIZ_PLAYER_EXTRA_WIFI_SSID: "",
    }
    assert path.play_device_login_id == 7
    assert path.live_view.to_init_param_dict()["iNetSDKUserId"] == 7
    assert path.live_view.to_init_param_dict()["iNetSDKChannelNumber"] == 1
    assert path.post_start_keyframe_request is not None
    assert path.post_start_keyframe_request.api == HCNETSDK_MAKE_KEYFRAME_MAIN
    assert path.call_sequence() == (
        EZVIZ_HCNETUTIL_LOGIN_V40,
        EZVIZ_LAN_ACTIVITY_CHANNEL_HANDOFF,
        EZVIZ_PREVIEW_BACK_START_LAN_VIDEO_PLAY,
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
        HCNETSDK_MAKE_KEYFRAME_MAIN,
    )


def test_ezviz_lan_complete_playback_path_requires_play_device_login() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    with pytest.raises(PyEzvizError, match="play-device login"):
        ezviz_lan_complete_playback_path(
            endpoint,
            "ABCDEF",
            settings_login_id=0,
            play_device_login_id=-1,
            analog_channel_count=1,
            digital_channel_count=0,
            analog_start_channel=1,
            digital_start_channel=33,
        )


def test_ezviz_lan_preview_plan_forwards_channel_identity() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        channel_number=3,
        channel_serial="CAM123-CH3",
        channel_index="3",
        channel_count=4,
    )

    init_param = plan.live_view.to_init_param_dict()
    assert init_param["szChnlSerial"] == "CAM123-CH3"
    assert init_param["szChnlIndex"] == "3"
    assert init_param["iChannelCount"] == 4
    assert init_param["iP2PSPS"] == EZVIZ_PREPLAY_SPS_TYPE


def test_ezviz_lan_video_qualities_match_lan_item_holder() -> None:
    qualities = ezviz_lan_video_qualities()

    assert qualities[0].stream_type == EZVIZ_LAN_MAIN_STREAM_TYPE
    assert qualities[0].video_level == EZVIZ_LAN_MAIN_VIDEO_LEVEL
    assert qualities[0].native_video_level == 0
    assert qualities[1].stream_type == EZVIZ_LAN_SUB_STREAM_TYPE
    assert qualities[1].video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert qualities[1].native_video_level == 2


def test_ezviz_native_video_level_matches_player_conversion() -> None:
    assert ezviz_native_video_level(-1) == 3
    assert ezviz_native_video_level(0) == 2
    assert ezviz_native_video_level(1) == 1
    assert ezviz_native_video_level(2) == 0
    assert ezviz_native_video_level(3) == 4
    assert ezviz_native_video_level(4) == 5


def test_ezviz_lan_preview_plan_uses_sub_keyframe_for_sub_stream() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        netsdk_login_id=7,
    )

    assert plan.post_start_keyframe_api == HCNETSDK_MAKE_KEYFRAME_SUB
    assert plan.post_start_keyframe_request is not None
    assert plan.post_start_keyframe_request.netsdk_login_id == 7
    assert plan.post_start_keyframe_request.netsdk_channel_number == 1
    assert plan.live_view.video_level == EZVIZ_LAN_SUB_VIDEO_LEVEL
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 2


def test_ezviz_lan_preview_plan_allows_explicit_video_level() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(
        endpoint,
        "ABCDEF",
        stream_type=2,
        video_level=3,
    )

    assert plan.live_view.video_level == 3
    assert plan.live_view.to_init_param_dict()["iVideoLevel"] == 4


def test_ezviz_lan_preview_plan_skips_keyframe_without_login_id() -> None:
    endpoint = HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10")

    plan = ezviz_lan_preview_plan(endpoint, "ABCDEF")

    assert plan.post_start_keyframe_api is None
    assert plan.real_play_request is None
    assert plan.native_call_sequence() == (
        EZVIZ_DEVICE_INFO_EX_LOGIN_PLAY_DEVICE,
        "NativeApi.createClient",
        "NativeApi.startPreview",
    )


class _FragmentedSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self._buffer = b"".join(chunks)

    def recv(self, length: int) -> bytes:
        chunk = self._buffer[:length]
        self._buffer = self._buffer[length:]
        return chunk


class _FakeSocket(_FragmentedSocket):
    def __init__(self, chunks: list[bytes]) -> None:
        super().__init__(chunks)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
