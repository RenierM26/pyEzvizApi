from __future__ import annotations

import io
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    HcNetSdkLanEndpoint,
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
)
from pyezvizapi.local_stream import (
    EzvizLocalSdkMediaStream,
    collect_local_stream_mpegps,
    copy_hcnetsdk_real_data_to_mpegts,
    copy_local_sdk_stream_from_client,
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    get_local_sdk_stream_credentials_from_client,
    open_local_sdk_stream,
    open_local_sdk_stream_from_client,
)

FIRST_PREFIX = b"preface"
STREAM_TIMEOUT = 3.0
REMUXED_PAYLOAD = b"abcdef"
MPEG_PS_PAYLOAD = b"\x00\x00\x01\xbaabc\x00\x00\x01\xbadef"
LOCAL_ENCRYPTED_PAYLOAD = b"encrypted-payload"
LOCAL_DECRYPTED_PAYLOAD = b"decrypted"
LOCAL_DECRYPTED_TS_PAYLOAD = b"ts:decrypted"
LOCAL_DECRYPTED_WITH_KEY_PAYLOAD = b"decrypted:encrypted-payload:media-secret"


def _rtp_packet(payload: bytes, *, sequence: int = 1) -> bytes:
    return (
        b"\x80\x60"
        + sequence.to_bytes(2, "big")
        + b"\x00\x00\x00\x01"
        + b"\x01\x02\x03\x04"
        + payload
    )


def _media(
    payload: bytes,
    *,
    channel: int = 0,
    prefix: bytes = b"",
    sequence: int = 1,
) -> EzvizInterleavedRtpFrameWithPrefix:
    rtp = _rtp_packet(payload, sequence=sequence)
    return EzvizInterleavedRtpFrameWithPrefix(
        prefix=prefix,
        frame=EzvizInterleavedRtpFrame(
            header=EzvizInterleavedRtpFrameHeader(
                channel=channel,
                payload_length=len(rtp),
            ),
            payload=rtp,
        ),
    )


def _preview_request() -> EzvizLocalPreviewRequest:
    return EzvizLocalPreviewRequest(
        operation_code="op",
        channel=1,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )


class _FakeSdkClient:
    def __init__(self, *media: EzvizInterleavedRtpFrameWithPrefix) -> None:
        self.media = list(media)
        self.bootstrap_calls: list[dict[str, Any]] = []
        self.read_prefix_limits: list[int] = []
        self.closed = False

    def bootstrap_preview_from_fields(self, **kwargs: Any) -> Any:
        self.bootstrap_calls.append(kwargs)
        return SimpleNamespace(first_media=self.media.pop(0))

    def read_stream_frame_after_prefix(self, *, max_prefix_bytes: int) -> Any:
        self.read_prefix_limits.append(max_prefix_bytes)
        return self.media.pop(0)

    def close(self) -> None:
        self.closed = True


def test_local_sdk_media_stream_yields_mpeg_ps_payloads() -> None:
    first_payload = b"\x00\x00\x01\xbaabc"
    second_payload = b"\x00\x00\x01\xbadef"
    sdk = _FakeSdkClient(
        _media(first_payload, prefix=FIRST_PREFIX, sequence=1),
        _media(second_payload, sequence=2),
    )
    stream = EzvizLocalSdkMediaStream(
        sdk,  # type: ignore[arg-type]
        _preview_request(),
        preview_sequence=7,
        stream_setup_sequence=8,
        stream_rate=1,
        stream_mode=2,
        max_prefix_bytes=128,
    )

    packets = list(stream.iter_packets(max_packets=2))

    assert [packet.body for packet in packets] == [first_payload, second_payload]
    assert packets[0].prefix == FIRST_PREFIX
    assert packets[0].encrypted is False
    assert sdk.bootstrap_calls[0]["preview_sequence"] == 7
    assert sdk.bootstrap_calls[0]["pre_start_body"] is None
    assert sdk.bootstrap_calls[0]["pre_start_sequence"] == 0
    assert sdk.bootstrap_calls[0]["stream_setup_sequence"] == 8
    assert sdk.bootstrap_calls[0]["stream_rate"] == 1
    assert sdk.bootstrap_calls[0]["stream_mode"] == 2
    assert sdk.bootstrap_calls[0]["read_first_media"] is True
    assert sdk.bootstrap_calls[0]["max_prefix_bytes"] == 128
    assert sdk.read_prefix_limits == [128]


def test_local_sdk_media_stream_strips_ezviz_fragment_headers() -> None:
    first_payload = b"\x1c\x80\x00\x00\x01\xbaabc"
    second_payload = b"\x1c\x00def"
    sdk = _FakeSdkClient(
        _media(first_payload, sequence=1),
        _media(second_payload, sequence=2),
    )
    stream = EzvizLocalSdkMediaStream(sdk, _preview_request())  # type: ignore[arg-type]

    packets = list(stream.iter_packets(max_packets=2))

    assert [packet.body for packet in packets] == [
        b"\x00\x00\x01\xbaabc",
        b"def",
    ]


def test_local_sdk_media_stream_respects_zero_packet_limit() -> None:
    sdk = _FakeSdkClient(_media(b"\x00\x00\x01\xbaabc"))
    stream = EzvizLocalSdkMediaStream(sdk, _preview_request())  # type: ignore[arg-type]

    assert list(stream.iter_packets(max_packets=0)) == []
    assert sdk.bootstrap_calls == []


def test_local_sdk_media_stream_respects_one_packet_limit() -> None:
    sdk = _FakeSdkClient(
        _media(b"\x00\x00\x01\xbaabc"),
        _media(b"\x00\x00\x01\xbadef", sequence=2),
    )
    stream = EzvizLocalSdkMediaStream(sdk, _preview_request())  # type: ignore[arg-type]

    packets = list(stream.iter_packets(max_packets=1))

    assert [packet.body for packet in packets] == [b"\x00\x00\x01\xbaabc"]
    assert sdk.read_prefix_limits == []


def test_local_sdk_media_stream_context_closes_client() -> None:
    sdk = _FakeSdkClient(_media(b"\x00\x00\x01\xbaabc"))

    with EzvizLocalSdkMediaStream(sdk, _preview_request()):  # type: ignore[arg-type]
        pass

    assert sdk.closed is True


def test_open_local_sdk_stream_builds_media_stream() -> None:
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

    stream = open_local_sdk_stream(
        endpoint,
        device_info,
        _preview_request(),
        timeout=STREAM_TIMEOUT,
        pre_start_body="pre-start",
        pre_start_sequence=6,
        max_prefix_bytes=64,
    )

    assert isinstance(stream, EzvizLocalSdkMediaStream)
    assert stream.sdk_client.endpoint == endpoint
    assert stream.sdk_client.device_info == device_info
    assert stream.sdk_client.timeout == STREAM_TIMEOUT
    assert stream.pre_start_body == "pre-start"
    assert stream.pre_start_sequence == 6
    assert stream.max_prefix_bytes == 64


def test_open_local_sdk_stream_from_client_fetches_endpoint_and_cas(monkeypatch) -> None:
    calls: list[Any] = []

    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            calls.append(("infos", serial))
            return {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": 9010,
                        "localStreamPort": 9020,
                    }
                }
            }

        def export_token(self) -> dict[str, str]:
            calls.append(("token",))
            return {"session_id": "session"}

    class FakeCas:
        def __init__(self, token: dict[str, str]) -> None:
            calls.append(("cas-init", token))

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append(("cas", serial))
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "1",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    stream = open_local_sdk_stream_from_client(
        FakeClient(),
        "CAM123456",
        channel=2,
        cas_serial="FULLCAM123456",
        timeout=STREAM_TIMEOUT,
        receiver_port=12000,
        receiver_ex_port=12001,
        uuid="uuid",
        timestamp="123",
    )

    assert stream.sdk_client.endpoint.host == "192.0.2.10"
    assert stream.sdk_client.timeout == STREAM_TIMEOUT
    assert stream.sdk_client.command_source_port == 12000
    assert stream.sdk_client.device_info.operation_code == "0123456"
    assert stream.sdk_client.device_info.key == "1234567890abcdef"
    assert stream.preview_request.channel == 2
    assert stream.preview_request.uuid == "uuid"
    assert stream.preview_request.timestamp == "123"
    assert calls == [
        ("infos", "CAM123456"),
        ("token",),
        ("cas-init", {"session_id": "session"}),
        ("cas", "FULLCAM123456"),
    ]


def test_open_local_sdk_stream_from_client_requires_connection() -> None:
    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            return {serial: {}}

    with pytest.raises(PyEzvizError, match="CONNECTION"):
        open_local_sdk_stream_from_client(FakeClient(), "CAM123456")


def test_get_local_sdk_stream_credentials_from_client_fetches_media_key(monkeypatch) -> None:
    calls: list[Any] = []

    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            calls.append(("infos", serial))
            return {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": 9010,
                        "localStreamPort": 9020,
                    }
                }
            }

        def export_token(self) -> dict[str, str]:
            calls.append(("token",))
            return {"session_id": "session"}

        def get_cam_key(self, serial: str, *, max_retries: int = 0) -> str:
            calls.append(("media-key", serial, max_retries))
            return "media-secret"

    class FakeCas:
        def __init__(self, token: dict[str, str]) -> None:
            calls.append(("cas-init", token))

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append(("cas", serial))
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "1",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    credentials = get_local_sdk_stream_credentials_from_client(
        FakeClient(),
        "CAM123456",
        cas_serial="FULLCAM123456",
    )

    assert credentials.endpoint.host == "192.0.2.10"
    assert credentials.endpoint.command_port == 9010
    assert credentials.endpoint.stream_port == 9020
    assert credentials.device_info.operation_code == "0123456"
    assert credentials.device_info.key == "1234567890abcdef"
    assert credentials.media_key == "media-secret"
    assert credentials.as_dict() == {
        "serial": "CAM123456",
        "endpoint": {
            "host": "192.0.2.10",
            "command_port": 9010,
            "stream_port": 9020,
        },
        "cas": {
            "operation_code": "0123456",
            "key": "1234567890abcdef",
            "encrypt_type": 1,
        },
    }
    assert credentials.as_dict(include_media_key=True) == {
        "serial": "CAM123456",
        "endpoint": {
            "host": "192.0.2.10",
            "command_port": 9010,
            "stream_port": 9020,
        },
        "cas": {
            "operation_code": "0123456",
            "key": "1234567890abcdef",
            "encrypt_type": 1,
        },
        "media_key": "media-secret",
    }
    assert calls == [
        ("infos", "CAM123456"),
        ("token",),
        ("cas-init", {"session_id": "session"}),
        ("cas", "FULLCAM123456"),
        ("media-key", "CAM123456", 1),
    ]
    assert "0123456" not in repr(credentials)
    assert "1234567890abcdef" not in repr(credentials)
    assert "media-secret" not in repr(credentials)


def test_copy_local_sdk_stream_from_client_copies_decrypted_mpegps(monkeypatch) -> None:
    calls: list[Any] = []

    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            calls.append(("infos", serial))
            return {
                "CAM123456": {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": 9010,
                        "localStreamPort": 9020,
                    }
                }
            }

        def export_token(self) -> dict[str, str]:
            calls.append(("token",))
            return {"session_id": "session"}

        def get_cam_key(
            self,
            serial: str,
            *,
            smscode: str | int | None = None,
            max_retries: int = 0,
        ) -> str:
            calls.append(("media-key", serial, smscode, max_retries))
            return "media-secret"

    class FakeCas:
        def __init__(self, token: dict[str, str]) -> None:
            calls.append(("cas-init", token))

        def cas_get_encryption(self, serial: str) -> dict[str, Any]:
            calls.append(("cas", serial))
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                        "@EncryptType": "1",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)
    monkeypatch.setattr(
        "pyezvizapi.local_stream.decrypt_hikvision_ps_video",
        lambda data, key, *, nalu_header_size: (
            b"decrypted:" + data + b":" + (key.encode() if isinstance(key, str) else key)
        ),
    )
    fake_sdk = _FakeSdkClient(
        _media(b"encrypted-", sequence=1),
        _media(b"payload", sequence=2),
    )
    created_streams: list[EzvizLocalSdkMediaStream] = []

    def fake_open_local_sdk_stream(
        endpoint: HcNetSdkLanEndpoint,
        device_info: EzvizCasDeviceInfo,
        preview_request: EzvizLocalPreviewRequest,
        **kwargs: Any,
    ) -> EzvizLocalSdkMediaStream:
        assert endpoint.host == "192.0.2.10"
        assert device_info.operation_code == "0123456"
        assert kwargs["command_source_port"] == 12000
        stream = EzvizLocalSdkMediaStream(
            fake_sdk,  # type: ignore[arg-type]
            preview_request,
            preview_sequence=kwargs["preview_sequence"],
            stream_setup_sequence=kwargs["stream_setup_sequence"],
            stream_rate=kwargs["stream_rate"],
            stream_mode=kwargs["stream_mode"],
            max_prefix_bytes=kwargs["max_prefix_bytes"],
        )
        created_streams.append(stream)
        return stream

    monkeypatch.setattr(
        "pyezvizapi.local_stream.open_local_sdk_stream",
        fake_open_local_sdk_stream,
    )
    output = io.BytesIO()

    credentials = copy_local_sdk_stream_from_client(
        FakeClient(),
        "CAM123456",
        output,
        output_format="mpegps",
        decrypt_video=True,
        max_packets=2,
        nalu_header_size=0,
        receiver_port=12000,
        uuid="uuid",
        timestamp="123",
        smscode="123456",
        cam_key_max_retries=2,
    )

    assert output.getvalue() == LOCAL_DECRYPTED_WITH_KEY_PAYLOAD
    assert credentials.endpoint.host == "192.0.2.10"
    assert credentials.media_key == "media-secret"
    assert fake_sdk.closed is True
    assert created_streams[0].preview_request.uuid == "uuid"
    assert created_streams[0].preview_request.timestamp == "123"
    receiver_info = cast(
        EzvizLocalReceiverInfoAttrs,
        created_streams[0].preview_request.receiver_info,
    )
    assert receiver_info.port == 12000
    assert calls == [
        ("infos", "CAM123456"),
        ("token",),
        ("cas-init", {"session_id": "session"}),
        ("cas", "CAM123456"),
        ("media-key", "CAM123456", "123456", 2),
    ]


def test_copy_local_sdk_stream_from_client_rejects_bad_output_format() -> None:
    with pytest.raises(PyEzvizError, match="output_format"):
        copy_local_sdk_stream_from_client(
            object(),
            "CAM123456",
            io.BytesIO(),
            output_format="mp4",  # type: ignore[arg-type]
        )


def test_copy_local_sdk_stream_from_client_rejects_unbounded_decrypt_early() -> None:
    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            raise AssertionError("should not fetch device info for invalid decrypt bounds")

    with pytest.raises(PyEzvizError, match="duration_seconds or max_packets"):
        copy_local_sdk_stream_from_client(
            FakeClient(),
            "CAM123456",
            io.BytesIO(),
            decrypt_video=True,
        )


def test_copy_local_stream_to_mpegps_writes_payloads_without_ffmpeg() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"\x00\x00\x01\xbaabc"),
                SimpleNamespace(body=b"\x00\x00\x01\xbadef"),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegps(FakeStream(), output, max_packets=2)

    assert output.getvalue() == MPEG_PS_PAYLOAD


def test_collect_local_stream_mpegps_honors_duration() -> None:
    clock_calls = 0

    def fake_monotonic() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return float(clock_calls)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets is None
            return [
                SimpleNamespace(body=b"abc"),
                SimpleNamespace(body=b"def"),
                SimpleNamespace(body=b"ghi"),
            ]

    assert collect_local_stream_mpegps(
        FakeStream(),
        duration_seconds=1.5,
        monotonic=fake_monotonic,
    ) == MPEG_PS_PAYLOAD[4:7]


def test_copy_local_stream_to_decrypted_mpegps_collects_and_decrypts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decrypt_calls: list[dict[str, Any]] = []

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"encrypted-"),
                SimpleNamespace(body=b"payload"),
            ]

    def fake_decrypt(
        data: bytes,
        key: str | bytes,
        *,
        nalu_header_size: int | None,
    ) -> bytes:
        decrypt_calls.append(
            {"data": data, "key": key, "nalu_header_size": nalu_header_size}
        )
        return LOCAL_DECRYPTED_PAYLOAD

    monkeypatch.setattr(
        "pyezvizapi.local_stream.decrypt_hikvision_ps_video",
        fake_decrypt,
    )
    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegps(
        FakeStream(),
        output,
        b"0123456789abcdef",
        nalu_header_size=0,
        max_packets=2,
    )

    assert output.getvalue() == LOCAL_DECRYPTED_PAYLOAD
    assert decrypt_calls == [
        {
            "data": LOCAL_ENCRYPTED_PAYLOAD,
            "key": b"0123456789abcdef",
            "nalu_header_size": 0,
        }
    ]


def test_copy_local_stream_to_decrypted_mpegps_requires_bounded_capture() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("unbounded decrypt should fail before reading")

    with pytest.raises(PyEzvizError, match="duration_seconds or max_packets"):
        copy_local_stream_to_decrypted_mpegps(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
        )


def test_copy_local_stream_to_decrypted_mpegts_remuxes_decrypted_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=b"encrypted")]

    monkeypatch.setattr(
        "pyezvizapi.local_stream.decrypt_hikvision_ps_video",
        lambda data, key, *, nalu_header_size: LOCAL_DECRYPTED_PAYLOAD,
    )
    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        "media-secret",
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == LOCAL_DECRYPTED_TS_PAYLOAD


def test_copy_local_stream_to_decrypted_mpegts_rejects_idmx_payload() -> None:
    idmx_frame = (
        b"\x0d\x90\xf0\x50\x37\x03\xb5\xea\xee\x55\x66\x77\x88"
        b"\x00\x01\x00\x0c"
        b"\x40\x0eencrypted-vps"
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame)]

    output = io.BytesIO()

    with pytest.raises(PyEzvizError, match="native PlayCtrl frame transform"):
        copy_local_stream_to_decrypted_mpegts(
            FakeStream(),
            output,
            "media-secret",
            max_packets=1,
        )


def test_copy_local_stream_to_decrypted_mpegps_rejects_idmx_payload() -> None:
    idmx_frame = (
        b"\x0d\xb0\xf0\x50\x37\x03\xb5\xea\xee\x55\x66\x77\x88"
        b"encrypted-playctrl-frame"
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame)]

    output = io.BytesIO()

    with pytest.raises(PyEzvizError, match="native PlayCtrl frame transform"):
        copy_local_stream_to_decrypted_mpegps(
            FakeStream(),
            output,
            "media-secret",
            max_packets=1,
        )

    assert not output.getvalue()


def test_copy_local_stream_to_decrypted_mpegts_rejects_idmx_before_ffmpeg(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "ffmpeg"
    fake_ffmpeg.write_text("#!/bin/sh\nexit 42\n")
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=b"\x0d\x90\x00\x00\x00\x00\x00\x00\x00\x55\x66\x77\x88"
                )
            ]

    with pytest.raises(PyEzvizError, match="native PlayCtrl frame transform"):
        copy_local_stream_to_decrypted_mpegts(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
            ffmpeg_path=str(fake_ffmpeg),
            max_packets=1,
        )


def test_copy_local_stream_to_decrypted_mpegts_requires_bounded_capture() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("unbounded decrypt should fail before reading")

    with pytest.raises(PyEzvizError, match="duration_seconds or max_packets"):
        copy_local_stream_to_decrypted_mpegts(
            FakeStream(),
            io.BytesIO(),
            "media-secret",
        )


def test_copy_local_stream_to_mpegts_pipes_payloads(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=b"\x00\x00\x01\xbaabc"),
                SimpleNamespace(body=b"\x00\x00\x01\xbadef"),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD


def test_copy_local_stream_to_mpegts_rejects_idmx_payload_without_decrypt() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=b"\x0d\x90\x00\x00\x00\x00\x00\x00\x00\x55\x66\x77\x88"
                )
            ]

    output = io.BytesIO()

    with pytest.raises(PyEzvizError, match="native PlayCtrl frame transform"):
        copy_local_stream_to_mpegts(FakeStream(), output, max_packets=1)


def test_copy_hcnetsdk_real_data_to_mpegts_filters_and_pipes_payloads(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)

    output = io.BytesIO()

    copy_hcnetsdk_real_data_to_mpegts(
        [
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.SYSTEM_HEADER, b"sys"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"abc"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.STREAM_DATA, b"\x00\x00\x01\xbaabc"),
            HcNetSdkRealDataPacket(1, HcNetSdkRealDataType.AUDIO_STREAM_DATA, b"\x00\x00\x01\xbadef"),
        ],
        output,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD
