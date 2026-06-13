from __future__ import annotations

from collections.abc import Iterator
import io
import time
from types import SimpleNamespace
from typing import Any, cast

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pytest

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    HcNetSdkRealDataPacket,
    HcNetSdkRealDataType,
    build_hcnetsdk_tcp_frame,
    hcnetsdk_command_port_control_frame,
)
from pyezvizapi.local_stream import (
    EzvizLocalSdkMediaStream,
    HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortGeneratedSocketStep,
    HcNetSdkCommandPortMediaStream,
    HcNetSdkCommandPortMultiSocketMediaStream,
    HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep,
    collect_h264_idmx_annexb_after_first_clean_idr_window,
    collect_local_stream_mpegps,
    copy_hcnetsdk_real_data_to_mpegts,
    copy_local_sdk_stream_from_client,
    copy_local_stream_to_decrypted_mpegps,
    copy_local_stream_to_decrypted_mpegts,
    copy_local_stream_to_mpegps,
    copy_local_stream_to_mpegts,
    get_local_sdk_stream_credentials_from_client,
    hcnetsdk_command_port_generated_plan_from_socket_plan,
    open_hcnetsdk_command_port_generated_multi_socket_stream,
    open_local_sdk_stream,
    open_local_sdk_stream_from_client,
    skip_h264_annexb_initial_idr_windows,
    summarize_h264_annexb_idr_windows,
    summarize_h264_annexb_units,
    summarize_idmx_h264_local_packets,
    time as local_stream_time,
    trim_h264_annexb_to_first_clean_idr_window,
)

FIRST_PREFIX = b"preface"
STREAM_TIMEOUT = 3.0
REMUXED_PAYLOAD = b"abcdef"
MPEG_PS_PAYLOAD = b"\x00\x00\x01\xbaabc\x00\x00\x01\xbadef"
LOCAL_ENCRYPTED_PAYLOAD = b"encrypted-payload"
HCNETSDK_COMMAND_PORT_TEST_KEY = bytes.fromhex(
    "3630343531663636393865353862623134313139323936386361333030663431"
)
HCNETSDK_PLAN_STEP_DELAY = 0.25
HCNETSDK_PLAN_EXTRACTED_STEP_DELAY = 0.75
LOCAL_DECRYPTED_PAYLOAD = b"decrypted"
LOCAL_DECRYPTED_TS_PAYLOAD = b"ts:decrypted"
LOCAL_DECRYPTED_WITH_KEY_PAYLOAD = b"decrypted:encrypted-payload:media-secret"
IDMX_MEDIA_KEY = b"0123456789abcdef"


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


class _FakeCommandPortClient:
    def __init__(self, *media: EzvizInterleavedRtpFrameWithPrefix) -> None:
        self.media = list(media)
        self.bootstrap_calls: list[dict[str, Any]] = []
        self.read_prefix_limits: list[int] = []
        self.closed = False

    def bootstrap_media_stream(
        self,
        command_frames: tuple[bytes, ...],
        **kwargs: Any,
    ) -> Any:
        self.bootstrap_calls.append(
            {
                "command_frames": command_frames,
                **kwargs,
            }
        )
        return SimpleNamespace(first_media=self.media.pop(0))

    def read_media_frame_after_prefix(self, *, max_prefix_bytes: int) -> Any:
        self.read_prefix_limits.append(max_prefix_bytes)
        return self.media.pop(0)

    def close(self) -> None:
        self.closed = True


class _FakeSocket:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        name: str | None = None,
        events: list[str] | None = None,
    ) -> None:
        self._buffer = b"".join(chunks)
        self.sent: list[bytes] = []
        self.closed = False
        self.name = name
        self.events = events

    def recv(self, length: int) -> bytes:
        if self.name is not None and self.events is not None:
            self.events.append(f"{self.name}.recv")
        chunk = self._buffer[:length]
        self._buffer = self._buffer[length:]
        return chunk

    def sendall(self, data: bytes) -> None:
        if self.name is not None and self.events is not None:
            self.events.append(f"{self.name}.send")
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True


def _command_port_media_frame(payload: bytes, *, sequence: int = 1) -> bytes:
    rtp = _rtp_packet(payload, sequence=sequence)
    return b"\x24\x00" + (len(rtp) + 4).to_bytes(2, "little") + rtp


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


def test_hcnetsdk_multi_socket_stream_runs_control_then_media_socket() -> None:
    control_request = build_hcnetsdk_tcp_frame(b"auth", field_4=90)
    preview_request = build_hcnetsdk_tcp_frame(b"preview", field_4=99)
    keyframe_request = build_hcnetsdk_tcp_frame(b"keyframe", field_4=99)
    control_response = build_hcnetsdk_tcp_frame(b"auth-ok")
    keyframe_response = build_hcnetsdk_tcp_frame(b"keyframe-ok")
    first_payload = b"\x00\x00\x01\xbaabc"
    second_payload = b"\x00\x00\x01\xbadef"
    control_socket = _FakeSocket([control_response])
    media_socket = _FakeSocket(
        [
            FIRST_PREFIX,
            _command_port_media_frame(first_payload, sequence=1),
            _command_port_media_frame(second_payload, sequence=2),
        ]
    )
    keyframe_socket = _FakeSocket([keyframe_response])
    sockets = [control_socket, media_socket, keyframe_socket]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == STREAM_TIMEOUT
        return sockets.pop(0)

    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep((control_request,)),
            HcNetSdkCommandPortSocketStep(
                (preview_request,),
                read_response_after_each=False,
                media_socket=True,
            ),
            HcNetSdkCommandPortSocketStep((keyframe_request,)),
        )
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        timeout=STREAM_TIMEOUT,
        socket_factory=socket_factory,
        max_prefix_bytes=16,
    )

    packets = list(stream.iter_packets(max_packets=2))
    stream.close()

    assert [packet.body for packet in packets] == [first_payload, second_payload]
    assert packets[0].prefix == FIRST_PREFIX
    assert control_socket.sent == [control_request]
    assert media_socket.sent == [preview_request]
    assert keyframe_socket.sent == [keyframe_request]
    assert control_socket.closed is True
    assert keyframe_socket.closed is True
    assert media_socket.closed is True


def test_hcnetsdk_multi_socket_stream_can_read_first_media_before_later_steps() -> None:
    control_request = build_hcnetsdk_tcp_frame(b"auth", field_4=90)
    preview_request = build_hcnetsdk_tcp_frame(b"preview", field_4=99)
    keyframe_request = build_hcnetsdk_tcp_frame(b"keyframe", field_4=99)
    control_response = build_hcnetsdk_tcp_frame(b"auth-ok")
    keyframe_response = build_hcnetsdk_tcp_frame(b"keyframe-ok")
    first_payload = b"\x00\x00\x01\xbaabc"
    events: list[str] = []
    control_socket = _FakeSocket([control_response], name="control", events=events)
    media_socket = _FakeSocket(
        [FIRST_PREFIX, _command_port_media_frame(first_payload, sequence=1)],
        name="media",
        events=events,
    )
    keyframe_socket = _FakeSocket(
        [keyframe_response],
        name="keyframe",
        events=events,
    )
    sockets = [control_socket, media_socket, keyframe_socket]

    def socket_factory(_address: tuple[str, int], _timeout: float | None) -> _FakeSocket:
        return sockets.pop(0)

    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep((control_request,)),
            HcNetSdkCommandPortSocketStep(
                (preview_request,),
                read_response_after_each=False,
                media_socket=True,
                read_first_media_immediately=True,
            ),
            HcNetSdkCommandPortSocketStep((keyframe_request,)),
        )
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        socket_factory=socket_factory,
        max_prefix_bytes=16,
    )

    packets = list(stream.iter_packets(max_packets=1))
    stream.close()

    assert [packet.body for packet in packets] == [first_payload]
    assert packets[0].prefix == FIRST_PREFIX
    assert events.index("media.recv") < events.index("keyframe.send")


def test_hcnetsdk_multi_socket_stream_can_drain_media_before_later_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preview_request = build_hcnetsdk_tcp_frame(b"preview", field_4=99)
    keyframe_request = build_hcnetsdk_tcp_frame(b"keyframe", field_4=99)
    keyframe_response = build_hcnetsdk_tcp_frame(b"keyframe-ok")
    first_payload = b"\x00\x00\x01\xbaabc"
    second_payload = b"\x00\x00\x01\xbadef"
    events: list[str] = []
    media_socket = _FakeSocket(
        [
            FIRST_PREFIX,
            _command_port_media_frame(first_payload, sequence=1),
            _command_port_media_frame(second_payload, sequence=2),
        ],
        name="media",
        events=events,
    )
    keyframe_socket = _FakeSocket(
        [keyframe_response],
        name="keyframe",
        events=events,
    )
    sockets = [media_socket, keyframe_socket]
    monotonic_values = iter((0.0, 0.0, 1.0))
    monkeypatch.setattr(
        local_stream_time,
        "monotonic",
        lambda: next(monotonic_values),
    )

    def socket_factory(_address: tuple[str, int], _timeout: float | None) -> _FakeSocket:
        return sockets.pop(0)

    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep(
                (preview_request,),
                read_response_after_each=False,
                media_socket=True,
                drain_media_before_next_step_seconds=0.5,
            ),
            HcNetSdkCommandPortSocketStep((keyframe_request,)),
        )
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        socket_factory=socket_factory,
        max_prefix_bytes=16,
    )

    packets = list(stream.iter_packets(max_packets=2))
    stream.close()

    assert [packet.body for packet in packets] == [first_payload, second_payload]
    assert events.index("media.recv") < events.index("keyframe.send")


def test_hcnetsdk_multi_socket_stream_records_keepalive_events() -> None:
    preview_request = build_hcnetsdk_tcp_frame(b"preview", field_12=0x30000)
    keepalive_request = build_hcnetsdk_tcp_frame(b"keepalive", field_12=0x30006)
    first_payload = b"\x00\x00\x01\xbaabc"
    media_socket = _FakeSocket(
        [FIRST_PREFIX, _command_port_media_frame(first_payload, sequence=1)]
    )

    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep(
                (preview_request,),
                read_response_after_each=False,
                media_socket=True,
                keepalive_frames=(keepalive_request,),
                keepalive_initial_delay_seconds=0.0,
            ),
        )
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        socket_factory=lambda _address, _timeout: media_socket,
        max_prefix_bytes=16,
    )

    stream.start()
    for _ in range(100):
        if stream.keepalive_events:
            break
        time.sleep(0.001)
    stream.close()

    assert media_socket.sent == [preview_request, keepalive_request]
    assert len(stream.keepalive_events) == 1
    assert stream.keepalive_events[0].command_id == 0x30006
    assert stream.keepalive_events[0].sent is True
    assert stream.keepalive_events[0].error is None
    assert stream.keepalive_events[0].elapsed_seconds >= 0.0


def test_hcnetsdk_multi_socket_plan_rejects_immediate_read_without_media_socket() -> None:
    with pytest.raises(PyEzvizError, match="requires a media socket"):
        HcNetSdkCommandPortMultiSocketPlan(
            steps=(
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"control"),),
                    read_first_media_immediately=True,
                ),
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"media"),),
                    media_socket=True,
                ),
            )
        )


def test_hcnetsdk_multi_socket_plan_rejects_negative_step_delay() -> None:
    with pytest.raises(PyEzvizError, match="delay must be non-negative"):
        HcNetSdkCommandPortMultiSocketPlan(
            steps=(
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"control"),),
                    delay_after_commands_seconds=-0.1,
                ),
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"media"),),
                    media_socket=True,
                ),
            )
        )


def test_hcnetsdk_multi_socket_plan_rejects_negative_keepalive_initial_delay() -> None:
    with pytest.raises(PyEzvizError, match="keepalive initial delay"):
        HcNetSdkCommandPortMultiSocketPlan(
            steps=(
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"control"),),
                ),
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"media"),),
                    media_socket=True,
                    keepalive_frames=(build_hcnetsdk_tcp_frame(b"keepalive"),),
                    keepalive_initial_delay_seconds=-0.1,
                ),
            )
        )


def test_hcnetsdk_generated_multi_socket_plan_renders_fresh_session_frames() -> None:
    plan = HcNetSdkCommandPortGeneratedMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x111050,
                        addend=0x71F872B9,
                    ),
                ),
                name="control",
            ),
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x30000,
                        body_tail=b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x01",
                        addend=0x71F872BC,
                    ),
                ),
                media_socket=True,
                read_first_media_immediately=True,
                read_response_after_each=False,
                response_reads_after_each=0,
                delay_after_commands_seconds=HCNETSDK_PLAN_STEP_DELAY,
                keepalive_templates=(
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x30006,
                        addend=0x71F872C0,
                    ),
                ),
                keepalive_initial_delay_seconds=0.0,
                name="media",
            ),
        )
    )

    rendered = plan.to_socket_plan(
        session_id=bytes.fromhex("71f872b7"),
        auth_seed=0x143D7840,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
        local_ip="172.18.0.3",
    )

    assert len(rendered.steps) == 2
    assert rendered.steps[0].name == "control"
    assert rendered.steps[0].command_frames[0] == bytes.fromhex(
        "0000002063000000bbd883cc00111050030012ac71f872b70000000000000000"
    )
    assert rendered.steps[1].media_socket is True
    assert rendered.steps[1].read_first_media_immediately is True
    assert rendered.steps[1].response_reads_after_each == 0
    assert rendered.steps[1].delay_after_commands_seconds == HCNETSDK_PLAN_STEP_DELAY
    assert rendered.steps[1].keepalive_initial_delay_seconds == 0.0
    assert rendered.steps[1].command_frames[0][16:28] == bytes.fromhex(
        "030012ac71f872b700000000"
    )
    assert rendered.steps[1].command_frames[0].endswith(
        b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x01"
    )
    assert len(rendered.steps[1].keepalive_frames) == 1


def test_hcnetsdk_generated_plan_extracts_from_concrete_socket_plan() -> None:
    session_id = bytes.fromhex("71f872b7")
    command_frame = hcnetsdk_command_port_control_frame(
        session_id=session_id,
        auth_seed=0x143D7840,
        command_id=0x111050,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
        local_ip="172.18.0.3",
        addend=0x71F872B9,
    )
    keepalive_frame = hcnetsdk_command_port_control_frame(
        session_id=session_id,
        auth_seed=0x143D7840,
        command_id=0x30006,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
        local_ip="172.18.0.3",
        addend=0x71F872C0,
    )
    concrete = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep((command_frame,), name="control"),
            HcNetSdkCommandPortSocketStep(
                (command_frame,),
                read_response_after_each=False,
                response_reads_after_each=0,
                media_socket=True,
                delay_after_commands_seconds=HCNETSDK_PLAN_EXTRACTED_STEP_DELAY,
                keepalive_frames=(keepalive_frame,),
                keepalive_initial_delay_seconds=0.0,
                name="media",
            ),
        )
    )

    generated = hcnetsdk_command_port_generated_plan_from_socket_plan(
        concrete,
        auth_seed=0x143D7840,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
    )
    rendered = generated.to_socket_plan(
        session_id=bytes.fromhex("12345678"),
        auth_seed=0x143D7840,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
        local_ip="192.168.1.56",
    )

    assert generated.steps[0].name == "control"
    assert generated.steps[0].control_templates[0].addend_delta == 2
    assert generated.steps[1].keepalive_templates[0].addend_delta == 9
    assert generated.steps[1].keepalive_initial_delay_seconds == 0.0
    assert (
        generated.steps[1].delay_after_commands_seconds
        == HCNETSDK_PLAN_EXTRACTED_STEP_DELAY
    )
    assert rendered.steps[1].media_socket is True
    assert rendered.steps[1].response_reads_after_each == 0
    assert (
        rendered.steps[1].delay_after_commands_seconds
        == HCNETSDK_PLAN_EXTRACTED_STEP_DELAY
    )
    assert rendered.steps[1].keepalive_initial_delay_seconds == 0.0
    assert rendered.steps[0].command_frames[0] == hcnetsdk_command_port_control_frame(
        session_id=bytes.fromhex("12345678"),
        auth_seed=0x143D7840,
        command_id=0x111050,
        key=HCNETSDK_COMMAND_PORT_TEST_KEY,
        local_ip="192.168.1.56",
        addend=0x1234567A,
    )


def test_hcnetsdk_generated_multi_socket_stream_logs_in_and_renders_plan() -> None:
    rsa_key = RSA.generate(1024)
    session_id = bytes.fromhex("71f872b7")
    challenge = b"0123456789abcdef0123456789abcdef"
    encrypted_challenge = PKCS1_v1_5.new(rsa_key.publickey()).encrypt(challenge)
    seed = b"s" * 64
    first_response = build_hcnetsdk_tcp_frame(encrypted_challenge + seed)
    second_response = build_hcnetsdk_tcp_frame(
        session_id + b"CS-CV310-A0-1B2WFR0120200927CCRRE87288805\x00",
        field_4=0x143D7840,
    )
    control_response = build_hcnetsdk_tcp_frame(b"ok")
    first_payload = b"\x00\x00\x01\xbaabc"
    login_socket = _FakeSocket([first_response, second_response])
    control_socket = _FakeSocket([control_response])
    keyframe_response = build_hcnetsdk_tcp_frame(b"keyframe-ok")
    media_socket = _FakeSocket([FIRST_PREFIX, _command_port_media_frame(first_payload)])
    keyframe_socket = _FakeSocket([keyframe_response])
    sockets = [login_socket, control_socket, media_socket, keyframe_socket]

    def socket_factory(address: tuple[str, int], timeout: float | None) -> _FakeSocket:
        assert address == ("192.0.2.10", 8000)
        assert timeout == STREAM_TIMEOUT
        return sockets.pop(0)

    generated_plan = HcNetSdkCommandPortGeneratedMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x111050,
                        addend_delta=2,
                    ),
                ),
                name="control",
            ),
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x30000,
                        body_tail=b"\x00\x00\x00\x01",
                        addend_delta=3,
                    ),
                ),
                response_reads_after_each=0,
                media_socket=True,
                name="media",
            ),
            HcNetSdkCommandPortGeneratedSocketStep(
                (
                    HcNetSdkCommandPortControlTemplate(
                        command_id=0x90100,
                        body_tail=b"\x00\x00\x00\x01",
                        addend_delta=3,
                    ),
                ),
                name="keyframe",
            ),
        )
    )
    stream = open_hcnetsdk_command_port_generated_multi_socket_stream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        generated_plan,
        password=b"123456",
        timeout=STREAM_TIMEOUT,
        socket_factory=socket_factory,
        local_ip="192.168.1.56",
        rsa_key=rsa_key,
    )

    assert isinstance(stream, HcNetSdkCommandPortGeneratedMultiSocketMediaStream)
    packets = list(stream.iter_packets(max_packets=1))
    stream.close()

    assert packets[0].body == first_payload
    assert packets[0].prefix == FIRST_PREFIX
    assert stream.login_session is not None
    assert stream.login_session.session_id == session_id
    assert len(login_socket.sent) == 2
    assert control_socket.sent == [
        hcnetsdk_command_port_control_frame(
            session_id=session_id,
            auth_seed=0x143D7840,
            command_id=0x111050,
            key=challenge,
            local_ip="192.168.1.56",
            addend=0x71F872B9,
        )
    ]
    assert media_socket.sent == [
        hcnetsdk_command_port_control_frame(
            session_id=session_id,
            auth_seed=0x143D7840,
            command_id=0x30000,
            key=challenge,
            local_ip="192.168.1.56",
            body_tail=b"\x00\x00\x00\x01",
            addend=0x71F872BA,
        )
    ]
    assert keyframe_socket.sent == [
        hcnetsdk_command_port_control_frame(
            session_id=session_id,
            auth_seed=0x143D7840,
            command_id=0x90100,
            key=challenge,
            local_ip="192.168.1.56",
            body_tail=b"\x00\x00\x00\x01",
            addend=0x71F872BA,
        )
    ]
    assert login_socket.closed is True
    assert control_socket.closed is True
    assert media_socket.closed is True
    assert keyframe_socket.closed is True


def test_hcnetsdk_multi_socket_stream_reports_response_step_context() -> None:
    request = build_hcnetsdk_tcp_frame(
        field_4=0x63000000,
        field_12=0x111050,
    )
    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep((request,), name="play-login"),
            HcNetSdkCommandPortSocketStep(
                (request,),
                response_reads_after_each=0,
                media_socket=True,
                name="media",
            ),
        )
    )
    socket = _FakeSocket([])
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        timeout=STREAM_TIMEOUT,
        socket_factory=lambda _address, _timeout: socket,
    )

    with pytest.raises(
        PyEzvizError,
        match=r"step 1 'play-login' frame 1 command 0x111050 response 1 failed",
    ):
        stream.start()
    stream.close()


def test_hcnetsdk_multi_socket_stream_reports_first_media_step_context() -> None:
    request = build_hcnetsdk_tcp_frame(
        field_4=0x63000000,
        field_12=0x30000,
    )
    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep(
                (request,),
                response_reads_after_each=0,
                media_socket=True,
                name="media",
            ),
        )
    )
    socket = _FakeSocket([])
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
        timeout=STREAM_TIMEOUT,
        socket_factory=lambda _address, _timeout: socket,
    )

    with pytest.raises(
        PyEzvizError,
        match=r"step 1 'media' first media read failed",
    ):
        stream.start()
    assert stream.bootstrap is not None
    assert len(stream.bootstrap.exchanges) == 1
    assert stream.bootstrap.exchanges[0].request == request
    assert stream.bootstrap.first_media is None
    stream.close()


def test_hcnetsdk_command_port_stream_patches_local_ip_word() -> None:
    original_frame = bytes.fromhex(
        "0000002463000000be25d671000110003801a8c052d056e2000000000000000000000001"
    )
    first_payload = b"\x00\x00\x01\xbaabc"
    sdk = _FakeCommandPortClient(_media(first_payload, sequence=1))
    stream = HcNetSdkCommandPortMediaStream(
        sdk,  # type: ignore[arg-type]
        (original_frame,),
        read_response_after_each=False,
        local_ip="192.168.1.26",
    )

    packets = list(stream.iter_packets(max_packets=1))

    sent_frame = sdk.bootstrap_calls[0]["command_frames"][0]
    assert sent_frame[16:20] == bytes.fromhex("1a01a8c0")
    assert packets[0].body == first_payload


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


def test_hcnetsdk_command_port_media_stream_strips_rtp_continuation_fragments() -> None:
    first_payload = b"\x1c\x80\x00\x00\x01\xbaabc"
    continuation_payload = b"\x1c\x00def"
    command_client = _FakeCommandPortClient(
        _media(first_payload, sequence=1),
        _media(continuation_payload, sequence=2),
    )
    stream = HcNetSdkCommandPortMediaStream(
        command_client,  # type: ignore[arg-type]
        (b"preview-start",),
        max_prefix_bytes=128,
    )

    packets = list(stream.iter_packets(max_packets=2))

    assert [packet.body for packet in packets] == [
        b"\x00\x00\x01\xbaabc",
        b"def",
    ]
    assert command_client.read_prefix_limits == [128]


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
    times = iter([10.0, 10.5, 11.6])

    def fake_monotonic() -> float:
        return next(times)

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
    ) == REMUXED_PAYLOAD


def test_collect_local_stream_mpegps_starts_duration_at_first_packet() -> None:
    times = iter([105.0, 105.5, 106.6])

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=b"abc")
            yield SimpleNamespace(body=b"def")
            yield SimpleNamespace(body=b"ghi")

    assert collect_local_stream_mpegps(
        FakeStream(),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
    ) == REMUXED_PAYLOAD


def test_copy_local_stream_to_mpegts_starts_duration_at_first_packet(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    times = iter([105.0, 105.5, 106.6])

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=b"\x00\x00\x01\xbaabc")
            yield SimpleNamespace(body=b"\x00\x00\x01\xbadef")
            yield SimpleNamespace(body=b"\x00\x00\x01\xbaghi")

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
    )

    assert output.getvalue() == MPEG_PS_PAYLOAD


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


def test_copy_local_stream_to_decrypted_mpegts_decrypts_idmx_payload(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "codec = sys.argv[sys.argv.index('-f') + 1]\n"
        "sys.stdout.buffer.write(codec.encode() + b':' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    vps_plain = b"\x40\x01" + b"vps-plain-123456"
    vps_cipher = bytes.fromhex("0ac29ce603f96a3e7b95e63df730b0ad")
    slice_plain = b"slice-plain-1234"
    slice_cipher = bytes.fromhex("7a51a826f29068d1a992b0d6c59a5be9")
    ignored_parameter_frame = (
        b"\x0d\x90\xf0\x50\x37\x03\xb5\xea\xee\x55\x66\x77\x88"
        b"\x00\x01\x00\x0cignored"
    )
    vps_frame = (
        b"\x0d\x90\x60\x77\xb2\x0f\x93\x78\xfe\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
        + vps_plain[:2]
        + vps_cipher
    )
    media_frame = (
        b"\x0d\xb0\x60\x77\xb5\x0f\x93\x78\xfe\x55\x66\x77\x88"
        b"\x40\x00\x00\x02\x80\x06\x00\x01\x11\x21\x02\x01"
        b"\x62\x01\x93"
        + slice_cipher
    )

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 3
            return [
                SimpleNamespace(body=ignored_parameter_frame),
                SimpleNamespace(body=vps_frame),
                SimpleNamespace(body=media_frame),
            ]

    output = io.BytesIO()

    copy_local_stream_to_decrypted_mpegts(
        FakeStream(),
        output,
        IDMX_MEDIA_KEY,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=3,
    )

    assert output.getvalue() == (
        b"hevc:\x00\x00\x00\x01"
        + vps_plain
        + b"\x00\x00\x00\x01"
        + b"\x26\x01"
        + slice_plain
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

    with pytest.raises(PyEzvizError, match="decrypt-video is required"):
        copy_local_stream_to_decrypted_mpegps(
            FakeStream(),
            output,
            "media-secret",
            max_packets=1,
        )

    assert not output.getvalue()


def test_copy_local_stream_to_decrypted_mpegts_rejects_unknown_idmx_before_ffmpeg(
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

    with pytest.raises(PyEzvizError, match="did not include media frames"):
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


def test_copy_local_stream_to_mpegts_rejects_unbounded_clear_idmx_payload() -> None:
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    frame = idmx_header + sps
    idmx_packet = len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            yield SimpleNamespace(body=idmx_packet)
            raise AssertionError("clear IDMX remux should require a bounded capture")

    with pytest.raises(PyEzvizError, match="IDMX stream remux requires"):
        copy_local_stream_to_mpegts(FakeStream(), io.BytesIO())


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


def test_copy_local_stream_to_mpegts_remuxes_clear_h264_idmx_payload(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(sps)),
                SimpleNamespace(body=idmx_frame(pps)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01" + sps + b"\x00\x00\x00\x01" + pps
    )


def test_copy_local_stream_to_mpegts_ignores_h264_shaped_non_h264_idmx_payload(
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
    non_h264_header = b"\x80\xe8\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    h264_header = b"\x80\x60\x02\x04\x04\x05\x06\x07\x55\x66\x77\x88"
    h264_shaped_sidecar = b"\x65sidecar"
    sps = b"\x67\x4d\x00"

    def idmx_frame(header: bytes, body: bytes) -> bytes:
        frame = header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 2
            return [
                SimpleNamespace(body=idmx_frame(non_h264_header, h264_shaped_sidecar)),
                SimpleNamespace(body=idmx_frame(h264_header, sps)),
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=2,
    )

    assert output.getvalue() == b"ts:\x00\x00\x00\x01" + sps


def test_copy_local_stream_to_mpegts_can_skip_initial_h264_idr_windows(
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
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    aud = b"\x09\xf0"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    idr_bad = b"\x65bad"
    non_idr = b"\x41delta"
    idr_good = b"\x65good"

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 7
            return [
                SimpleNamespace(body=idmx_frame(body))
                for body in (aud, sps, pps, idr_bad, non_idr, aud, idr_good)
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=7,
        h264_skip_initial_idr_windows=1,
    )

    assert output.getvalue() == b"ts:\x00\x00\x00\x01" + idr_good


def test_copy_local_stream_to_mpegts_can_preroll_before_clean_idr_trim(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    idr = b"\x65clean"
    late_non_idr = b"\x41late"
    times = iter([100.0, 101.0, 102.0, 103.1])

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            for body in (sps, pps, idr, late_non_idr):
                yield SimpleNamespace(body=idmx_frame(body))

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
        h264_trim_to_clean_idr_window=True,
        h264_clean_idr_preroll_seconds=2.0,
    )

    assert output.getvalue() == (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
    )


def test_copy_local_stream_to_mpegts_can_wait_for_clean_idr_before_duration(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "else:\n"
        "    sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    bad_idr = b"\x65bad"
    sps = b"\x67\x4d\x00"
    pps = b"\x68\xee\x38"
    clean_idr = b"\x65clean"
    late_non_idr = b"\x41late"
    second_idr = b"\x65second"
    times = iter(
        [
            0.0,
            0.5,
            1.0,
            1.5,
            2.0,
            2.25,
            2.5,
            6.0,
            6.75,
            7.0,
            7.25,
            7.5,
            7.75,
            8.0,
            8.25,
            8.5,
            8.75,
            9.0,
        ]
    )

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> Iterator[Any]:
            assert max_packets is None
            for body in (bad_idr, sps, pps, clean_idr, late_non_idr, second_idr):
                yield SimpleNamespace(body=idmx_frame(body))

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=1.0,
        monotonic=lambda: next(times),
        h264_wait_for_clean_idr_window=True,
        h264_clean_idr_wait_seconds=10.0,
    )

    assert output.getvalue() == (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + clean_idr
        + b"\x00\x00\x00\x01"
        + late_non_idr
        + b"\x00\x00\x00\x01"
        + second_idr
    )


def test_copy_local_stream_to_mpegts_wait_for_clean_idr_bounds_payloads(
    monkeypatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    seen: dict[str, Any] = {}
    clean_annexb = b"\x00\x00\x00\x01\x65clean"

    def fake_iter_payloads(
        stream: Any,
        *,
        max_packets: int | None,
        duration_seconds: float | None,
        monotonic: Any,
    ) -> Iterator[bytes]:
        seen["stream"] = stream
        seen["max_packets"] = max_packets
        seen["duration_seconds"] = duration_seconds
        seen["monotonic"] = monotonic
        yield b"idmx-payload"

    def fake_collect(
        packets: Iterator[bytes],
        *,
        duration_seconds: float | None,
        monotonic: Any,
        ffmpeg_path: str,
        max_windows: int,
        wait_seconds: float,
    ) -> bytes:
        seen["collect_packets"] = list(packets)
        seen["collect_duration_seconds"] = duration_seconds
        seen["collect_wait_seconds"] = wait_seconds
        seen["collect_max_windows"] = max_windows
        return clean_annexb

    monkeypatch.setattr(
        "pyezvizapi.local_stream._iter_local_stream_payloads",
        fake_iter_payloads,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream._looks_like_idmx_local_payload",
        lambda payload: True,
    )
    monkeypatch.setattr(
        "pyezvizapi.local_stream.collect_h264_idmx_annexb_after_first_clean_idr_window",
        fake_collect,
    )
    output = io.BytesIO()
    stream = object()
    duration_seconds = 2.5
    wait_seconds = 4.0

    copy_local_stream_to_mpegts(
        stream,
        output,
        ffmpeg_path=str(fake_ffmpeg),
        duration_seconds=duration_seconds,
        max_packets=7,
        h264_wait_for_clean_idr_window=True,
        h264_clean_idr_wait_seconds=wait_seconds,
        h264_clean_idr_max_windows=11,
    )

    assert output.getvalue() == clean_annexb
    assert seen["stream"] is stream
    assert seen["max_packets"] == 7
    assert seen["duration_seconds"] == duration_seconds + wait_seconds
    assert seen["collect_packets"] == [b"idmx-payload"]
    assert seen["collect_duration_seconds"] == duration_seconds
    assert seen["collect_wait_seconds"] == wait_seconds
    assert seen["collect_max_windows"] == 11


def test_collect_h264_idmx_annexb_after_clean_idr_excludes_deadline_packet(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n"
        "else:\n"
        "    sys.stdout.buffer.write(data)\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    expected_annexb = (
        b"\x00\x00\x00\x01\x67\x4d\x00"
        b"\x00\x00\x00\x01\x68\xee\x38"
        b"\x00\x00\x00\x01\x65clean"
        b"\x00\x00\x00\x01\x41inside-window"
        b"\x00\x00\x00\x01\x65next-idr"
    )
    post_deadline_body = b"\x41at-deadline"

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    annexb = collect_h264_idmx_annexb_after_first_clean_idr_window(
        (
            idmx_frame(body)
            for body in (
                b"\x65bad",
                b"\x67\x4d\x00",
                b"\x68\xee\x38",
                b"\x65clean",
                b"\x41inside-window",
                b"\x65next-idr",
                post_deadline_body,
            )
        ),
        duration_seconds=1.0,
        monotonic=iter([0.0, 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 2.5]).__next__,
        ffmpeg_path=str(fake_ffmpeg),
        wait_seconds=10.0,
    )

    assert annexb == expected_annexb
    assert post_deadline_body not in annexb


def test_collect_h264_idmx_annexb_after_clean_idr_times_out(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stderr.write('decode failed\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    with pytest.raises(PyEzvizError) as exc_info:
        collect_h264_idmx_annexb_after_first_clean_idr_window(
            (
                idmx_frame(body)
                for body in (b"\x65bad", b"\x65second-idr", b"\x41late")
            ),
            duration_seconds=1.0,
            monotonic=iter([0.0, 0.25, 0.5, 1.5]).__next__,
            ffmpeg_path=str(fake_ffmpeg),
            wait_seconds=1.0,
        )
    message = str(exc_info.value)
    assert "Timed out waiting" in message
    assert "checked" in message
    assert "complete sampled IDR windows" in message
    assert "decode failed" in message


def test_copy_local_stream_to_mpegts_wait_for_clean_idr_requires_duration() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid wait settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires duration_seconds"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_wait_for_clean_idr_window=True,
        )


def test_copy_local_stream_to_mpegts_wait_for_clean_idr_rejects_trim_combo() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid wait settings should fail before reading")

    with pytest.raises(PyEzvizError, match="cannot be combined"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_wait_for_clean_idr_window=True,
            h264_trim_to_clean_idr_window=True,
        )


def test_copy_local_stream_to_mpegts_wait_for_clean_idr_rejects_mpegps() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets is None
            return [SimpleNamespace(body=MPEG_PS_PAYLOAD)]

    with pytest.raises(PyEzvizError, match=r"require a clear H\.264 IDMX stream"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_wait_for_clean_idr_window=True,
        )


def test_copy_local_stream_to_mpegts_preroll_requires_clean_idr_trim() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid preroll settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires h264_trim_to_clean_idr_window"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            duration_seconds=1.0,
            h264_clean_idr_preroll_seconds=2.0,
        )


def test_copy_local_stream_to_mpegts_preroll_requires_duration() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid preroll settings should fail before reading")

    with pytest.raises(PyEzvizError, match="requires duration_seconds"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_trim_to_clean_idr_window=True,
            h264_clean_idr_preroll_seconds=2.0,
        )


def test_copy_local_stream_to_mpegts_passes_clean_idr_max_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x02\x03\x04\x05\x06\x07\x55\x66\x77\x88"
    idr = b"\x65clean"
    calls: list[dict[str, Any]] = []

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    def fake_trim(data: bytes, *, ffmpeg_path: str, max_windows: int) -> bytes:
        calls.append(
            {
                "data": data,
                "ffmpeg_path": ffmpeg_path,
                "max_windows": max_windows,
            }
        )
        return data

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=idmx_frame(idr))]

    monkeypatch.setattr(
        "pyezvizapi.local_stream.trim_h264_annexb_to_first_clean_idr_window",
        fake_trim,
    )
    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
        h264_trim_to_clean_idr_window=True,
        h264_clean_idr_max_windows=64,
    )

    assert calls[0]["ffmpeg_path"] == str(fake_ffmpeg)
    assert calls[0]["max_windows"] == 64
    assert output.getvalue() == b"\x00\x00\x00\x01" + idr


def test_copy_local_stream_to_mpegts_rejects_invalid_clean_idr_max_windows() -> None:
    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            raise AssertionError("invalid max windows should fail before reading")

    with pytest.raises(PyEzvizError, match="must be positive"):
        copy_local_stream_to_mpegts(
            FakeStream(),
            io.BytesIO(),
            h264_clean_idr_max_windows=0,
        )


def test_skip_h264_annexb_initial_idr_windows_requires_enough_idrs() -> None:
    with pytest.raises(PyEzvizError, match="did not contain enough IDR"):
        skip_h264_annexb_initial_idr_windows(b"\x00\x00\x00\x01\x65only", 1)


def test_trim_h264_annexb_to_first_clean_idr_window_uses_ffmpeg(
    tmp_path,
) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "if b'bad' in data:\n"
        "    sys.stderr.write('decode failed\\n')\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    data = (
        b"\x00\x00\x00\x01\x67sps"
        b"\x00\x00\x00\x01\x68pps"
        b"\x00\x00\x00\x01\x65bad"
        b"\x00\x00\x00\x01\x41delta"
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )
    clean_window = (
        b"\x00\x00\x00\x01\x67sps2"
        b"\x00\x00\x00\x01\x68pps2"
        b"\x00\x00\x00\x01\x65good"
    )

    trimmed = trim_h264_annexb_to_first_clean_idr_window(
        data,
        ffmpeg_path=str(fake_ffmpeg),
    )

    assert trimmed == clean_window


def test_copy_local_stream_to_mpegts_models_command_port_h264_fu_a(tmp_path) -> None:
    fake_ffmpeg = tmp_path / "fake-ffmpeg"
    fake_ffmpeg.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdout.buffer.write(b'ts:' + sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    fake_ffmpeg.chmod(0o755)
    idmx_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    first_fu = b"\x7c\x85\x88\x80\x00\x00\x1a\x48native-first"
    next_fu = b"\x7c\x05native-middle"
    last_fu = b"\x7c\x45native-last"

    def idmx_frame(body: bytes) -> bytes:
        frame = idmx_header + body
        return len(frame).to_bytes(4, "little") + frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [
                SimpleNamespace(
                    body=idmx_frame(first_fu)
                    + idmx_frame(next_fu)
                    + idmx_frame(last_fu)
                )
            ]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        b"\x65"
        + first_fu[2:]
        + next_fu[2:]
        + last_fu[2:]
    )


def test_copy_local_stream_to_mpegts_flattens_command_port_idmx_aggregates(
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
    outer_header = b"\x80\x60\x5d\x5c\x7d\x52\x2a\x3e\x55\x66\x77\x88"
    inner_header = b"\xa0\x60\xb7\x12\x16\x54\x77\xeb\x55\x66\x77\x88"
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    first_fu = b"\x7c\x85aggregate-first"
    last_fu = b"\x7c\x45aggregate-last"

    def inner_frame(body: bytes) -> bytes:
        frame = inner_header + body
        return len(frame).to_bytes(4, "little") + frame

    aggregate_body = (
        b"\x00\x10aggregate-sidecar"
        + inner_frame(sps)
        + inner_frame(pps)
        + inner_frame(first_fu)
        + inner_frame(last_fu)
    )
    outer_frame = outer_header + aggregate_body
    packet = len(outer_frame).to_bytes(4, "little") + outer_frame

    class FakeStream:
        def iter_packets(self, *, max_packets: int | None = None) -> list[Any]:
            assert max_packets == 1
            return [SimpleNamespace(body=packet)]

    output = io.BytesIO()

    copy_local_stream_to_mpegts(
        FakeStream(),
        output,
        ffmpeg_path=str(fake_ffmpeg),
        max_packets=1,
    )

    assert output.getvalue() == (
        b"ts:\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01\x65"
        + first_fu[2:]
        + last_fu[2:]
    )


def test_summarize_idmx_h264_local_packets_reports_sanitized_frame_shapes() -> None:
    sequence_base = 0xB712
    rtp_timestamp = 0x165477EB
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    first_fu = b"\x7c\x85aggregate-first"
    last_fu = b"\x7c\x45aggregate-last"

    def frame(body: bytes, *, sequence: int) -> bytes:
        inner_header = (
            b"\x80\x60"
            + sequence.to_bytes(2, "big")
            + rtp_timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
        )
        idmx_frame = inner_header + body
        return len(idmx_frame).to_bytes(4, "little") + idmx_frame

    summary = summarize_idmx_h264_local_packets(
        [
            frame(sps, sequence=sequence_base),
            frame(pps, sequence=sequence_base + 1),
            frame(first_fu, sequence=sequence_base + 2),
            frame(last_fu, sequence=sequence_base + 3),
        ],
        max_frames=3,
    )

    assert summary["looks_like_idmx"] is True
    assert summary["frame_count"] == 4
    assert summary["sample_limit"] == 3
    assert [sample["kind"] for sample in summary["samples"]] == [
        "h264_nal",
        "h264_nal",
        "h264_fu_a",
    ]
    assert summary["samples"][0]["nal_type"] == 7
    assert summary["samples"][0]["rtp_payload_type"] == 96
    assert summary["samples"][0]["sequence_number"] == sequence_base
    assert summary["samples"][0]["rtp_timestamp"] == rtp_timestamp
    assert summary["samples"][0]["body_sha256"]
    assert summary["h264"] == {
        "clear_nal": 2,
        "fu_a": 2,
        "fu_a_start": 1,
        "fu_a_end": 1,
        "non_idr": 0,
        "idr": 2,
        "sei": 0,
        "sps": 1,
        "pps": 1,
        "aud": 0,
        "unknown": 0,
    }
    assert summary["h264_nal_units"] == {
        "sample_limit": 3,
        "samples": [
            {
                "nal_type": 7,
                "start_frame_index": 0,
                "end_frame_index": 0,
                "start_sequence": sequence_base,
                "end_sequence": sequence_base,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(sps),
                "complete": True,
                "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
            },
            {
                "nal_type": 8,
                "start_frame_index": 1,
                "end_frame_index": 1,
                "start_sequence": sequence_base + 1,
                "end_sequence": sequence_base + 1,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 1,
                "payload_bytes": len(pps),
                "complete": True,
                "sha256": "b93548b426689e9e47d544ea905fd47fe7450d55d2c37c54691c81ab583d080d",
            },
            {
                "nal_type": 5,
                "start_frame_index": 2,
                "end_frame_index": 3,
                "start_sequence": sequence_base + 2,
                "end_sequence": sequence_base + 3,
                "rtp_timestamp": rtp_timestamp,
                "sequence_gap_count": 0,
                "fragment_count": 2,
                "payload_bytes": 1 + len(first_fu[2:]) + len(last_fu[2:]),
                "complete": True,
                "sha256": "6e8dc59fcf7a0c7fb4b4cbe007426af35bfeabddf2cba6cb34e3a1c33822a8a7",
            },
        ],
        "truncated": False,
    }


def test_summarize_h264_annexb_units_reports_sanitized_nal_shapes() -> None:
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    idr = b"\x65idr"
    non_idr = b"\x41p"

    summary = summarize_h264_annexb_units(
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
        + b"\x00\x00\x00\x01"
        + non_idr,
        max_units=3,
    )

    assert summary == {
        "byte_count": 30,
        "nal_count": 4,
        "sample_limit": 3,
        "samples": [
            {
                "index": 0,
                "start_code_offset": 0,
                "nal_offset": 4,
                "end_offset": 8,
                "nal_type": 7,
                "payload_bytes": len(sps),
                "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
            },
            {
                "index": 1,
                "start_code_offset": 8,
                "nal_offset": 12,
                "end_offset": 16,
                "nal_type": 8,
                "payload_bytes": len(pps),
                "sha256": "b93548b426689e9e47d544ea905fd47fe7450d55d2c37c54691c81ab583d080d",
            },
            {
                "index": 2,
                "start_code_offset": 16,
                "nal_offset": 20,
                "end_offset": 24,
                "nal_type": 5,
                "payload_bytes": len(idr),
                "sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
            },
        ],
        "truncated": True,
        "h264": {
            "non_idr": 1,
            "idr": 1,
            "sei": 0,
            "sps": 1,
            "pps": 1,
            "aud": 0,
            "unknown": 0,
        },
    }


def test_summarize_h264_annexb_units_accepts_short_start_codes() -> None:
    sps = b"\x67\x4d\x00\x29"
    idr = b"\x65idr"
    data = b"\x00\x00\x01" + sps + b"\x00\x00\x00\x01" + idr

    summary = summarize_h264_annexb_units(data)

    assert summary["nal_count"] == 2
    assert summary["samples"] == [
        {
            "index": 0,
            "start_code_offset": 0,
            "nal_offset": 3,
            "end_offset": 7,
            "nal_type": 7,
            "payload_bytes": len(sps),
            "sha256": "1d2096f80a4fa6ab69fefbbc2fdf1bb1d4cf7e3d27cf9083bf77354c011cd191",
        },
        {
            "index": 1,
            "start_code_offset": 7,
            "nal_offset": 11,
            "end_offset": 15,
            "nal_type": 5,
            "payload_bytes": len(idr),
            "sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
        },
    ]


def test_summarize_h264_annexb_idr_windows_reports_sanitized_gops() -> None:
    sps = b"\x67\x4d\x00\x29"
    pps = b"\x68\xee\x38\x80"
    idr = b"\x65idr"
    non_idr = b"\x41p"
    second_idr = b"\x65idr2"
    data = (
        b"\x00\x00\x00\x01"
        + sps
        + b"\x00\x00\x00\x01"
        + pps
        + b"\x00\x00\x00\x01"
        + idr
        + b"\x00\x00\x00\x01"
        + non_idr
        + b"\x00\x00\x00\x01"
        + second_idr
    )

    summary = summarize_h264_annexb_idr_windows(data, max_windows=1)

    assert summary == {
        "byte_count": 39,
        "nal_count": 5,
        "idr_count": 2,
        "sample_limit": 1,
        "samples": [
            {
                "index": 0,
                "start_nal_index": 0,
                "idr_nal_index": 2,
                "end_nal_index": 4,
                "start_code_offset": 0,
                "idr_start_code_offset": 16,
                "end_offset": 30,
                "window_bytes": 30,
                "leading_nal_types": [7, 8],
                "idr_payload_bytes": len(idr),
                "idr_sha256": "a49bc921918ad4b8fbd220d813e3a73e72274ca219c839e4329716a9764ee4d9",
                "window_sha256": "9834dc06d539401ab4976915d354af8f60fac683120d879456e08d18f4aed766",
            },
        ],
        "truncated": True,
    }


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
