"""Tests for local stream transports, bootstrap plans, deadlines, and lifecycle."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import date
import io
from threading import Event
import time
from types import SimpleNamespace
from typing import Any, cast

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pytest

from pyezvizapi._local_stream import (
    EzvizLocalSdkMediaStream,
    EzvizLocalStreamPacket,
    HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
    HcNetSdkCommandPortGeneratedMultiSocketPlan,
    HcNetSdkCommandPortGeneratedSocketStep,
    HcNetSdkCommandPortMediaStream,
    HcNetSdkCommandPortMultiSocketMediaStream,
    HcNetSdkCommandPortMultiSocketPlan,
    HcNetSdkCommandPortSocketStep,
    _idmx_local_video_frame_rate,
    copy_local_sdk_stream_from_client,
    get_local_sdk_stream_credentials_from_client,
    hcnetsdk_command_port_generated_plan_from_socket_plan,
    hcnetsdk_command_port_native_lan_live_view_plan,
    local_media_packet_source,
    open_hcnetsdk_command_port_generated_multi_socket_stream,
    open_local_sdk_stream,
    open_local_sdk_stream_from_client,
    time as local_stream_time,
)
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from pyezvizapi.hcnetsdk import (
    EzvizCasDeviceInfo,
    EzvizInterleavedRtpFrame,
    EzvizInterleavedRtpFrameHeader,
    EzvizInterleavedRtpFrameWithPrefix,
    EzvizLocalPreviewRequest,
    EzvizLocalReceiverInfoAttrs,
    HcNetSdkCommandPortControlTemplate,
    HcNetSdkLanEndpoint,
    build_hcnetsdk_tcp_frame,
    hcnetsdk_command_port_control_frame,
    hcnetsdk_command_port_play_login_body_tail_for_today,
)
from pyezvizapi.media import CaptureLimits

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

def _sequential_idmx_frame_factory(
    header: bytes,
) -> Callable[[bytes], bytes]:
    sequence = int.from_bytes(header[2:4], "big")

    def idmx_frame(body: bytes) -> bytes:
        nonlocal sequence
        frame = header[:2] + sequence.to_bytes(2, "big") + header[4:] + body
        sequence = (sequence + 1) & 0xFFFF
        return len(frame).to_bytes(4, "little") + frame

    return idmx_frame

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

def _raw_media(
    payload: bytes,
    *,
    channel: int = 0,
    prefix: bytes = b"",
) -> EzvizInterleavedRtpFrameWithPrefix:
    return EzvizInterleavedRtpFrameWithPrefix(
        prefix=prefix,
        frame=EzvizInterleavedRtpFrame(
            header=EzvizInterleavedRtpFrameHeader(
                channel=channel,
                payload_length=len(payload),
            ),
            payload=payload,
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

def test_idmx_local_video_frame_rate_uses_rtp_timestamp_clock() -> None:
    def frame(timestamp: int, sequence: int) -> bytes:
        return (
            b"\x90\x60"
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + b"\x40\x00\x00\x00"
            + b"\x40\x01vps"
        )

    assert (
        _idmx_local_video_frame_rate(
            [
                frame(90_000, 1),
                frame(96_000, 2),
                frame(102_000, 3),
            ]
        )
        == "15"
    )


def test_idmx_local_video_frame_rate_honors_descriptor_reassignment() -> None:
    def frame(
        timestamp: int,
        sequence: int,
        *,
        payload_type: int,
        extension_data: bytes = b"",
    ) -> bytes:
        return (
            b"\x90"
            + bytes((payload_type,))
            + sequence.to_bytes(2, "big")
            + timestamp.to_bytes(4, "big")
            + b"\x55\x66\x77\x88"
            + b"\x00\x01"
            + (len(extension_data) // 4).to_bytes(2, "big")
            + extension_data
            + b"payload"
        )

    descriptors = b"\x45\x02\x90\x20\x45\x02\x24\x60"

    assert (
        _idmx_local_video_frame_rate(
            [
                frame(0, 1, payload_type=112, extension_data=descriptors),
                frame(100, 2, payload_type=32),
                frame(90_000, 3, payload_type=96),
                frame(200, 4, payload_type=32),
                frame(96_000, 5, payload_type=96),
                frame(300, 6, payload_type=32),
                frame(102_000, 7, payload_type=96),
            ]
        )
        == "15"
    )

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

def test_local_sdk_media_stream_bounds_blocking_read_after_first_packet() -> None:
    first_payload = b"\x00\x00\x01\xbaabc"

    class DeadlineSdkClient(_FakeSdkClient):
        read_timeout: float | None = None

        def read_stream_frame_after_prefix(self, **kwargs: Any) -> Any:
            self.read_timeout = kwargs.get("timeout")
            raise EzvizLocalSdkDeadlineExpired("deadline")

    sdk = DeadlineSdkClient(_media(first_payload, sequence=1))
    stream = EzvizLocalSdkMediaStream(sdk, _preview_request())  # type: ignore[arg-type]

    packets = list(
        stream.iter_packets(
            duration_seconds=1.0,
            monotonic=lambda: 10.0,
        )
    )

    assert [packet.body for packet in packets] == [first_payload]
    assert sdk.read_timeout == 1.0
    assert sdk.closed is True
    with pytest.raises(PyEzvizError, match=r"cannot resume after.*interrupted"):
        list(stream.iter_packets(max_packets=1))

def test_local_sdk_media_stream_can_include_startup_in_duration() -> None:
    """The shared adapter can bound startup without changing legacy defaults."""

    class StartupDeadlineSdkClient(_FakeSdkClient):
        read_called = False

        def bootstrap_preview_from_fields(self, **kwargs: Any) -> Any:
            self.bootstrap_calls.append(kwargs)
            return SimpleNamespace(first_media=None)

        def read_stream_frame_after_prefix(self, **kwargs: Any) -> Any:
            self.read_called = True
            return super().read_stream_frame_after_prefix(**kwargs)

    sdk = StartupDeadlineSdkClient(_media(b"\x00\x00\x01\xbaabc"))
    stream = EzvizLocalSdkMediaStream(sdk, _preview_request())  # type: ignore[arg-type]
    expected_deadline = 11.0
    times = iter((10.0, 10.0, 11.0))

    packets = list(
        local_media_packet_source(stream).iter_media_packets(
            limits=CaptureLimits(duration_seconds=1.0),
            monotonic=lambda: next(times),
        )
    )

    assert packets == []
    assert sdk.bootstrap_calls[0]["read_first_media"] is False
    assert sdk.bootstrap_calls[0]["deadline"] == expected_deadline
    assert sdk.read_called is False

@pytest.mark.parametrize(
    "stream_type",
    (
        EzvizLocalSdkMediaStream,
        HcNetSdkCommandPortMediaStream,
        HcNetSdkCommandPortMultiSocketMediaStream,
        HcNetSdkCommandPortGeneratedMultiSocketMediaStream,
    ),
)
def test_all_local_packet_sources_include_startup_in_shared_duration(
    stream_type: type[Any],
) -> None:
    """Every supported local source opts into the shared startup deadline."""

    stream = object.__new__(stream_type)

    assert local_media_packet_source(stream).duration_from_start is True

@pytest.mark.parametrize("stream_kind", ("direct", "command", "multi"))
def test_exact_byte_limit_commits_cached_first_packet(stream_kind: str) -> None:
    """Closing the adapter at an exact byte limit cannot replay cached media."""
    first_body = b"\x00\x00\x01\xbaabc"
    second_body = b"\x00\x00\x01\xbadef"
    first_media = _media(first_body)
    client = _FakeCommandPortClient(_media(second_body))

    if stream_kind == "direct":
        sdk_client = _FakeSdkClient(_media(second_body))
        stream: Any = EzvizLocalSdkMediaStream(sdk_client, _preview_request())  # type: ignore[arg-type]
    elif stream_kind == "command":
        stream = HcNetSdkCommandPortMediaStream(cast(Any, client), ())
    else:
        media_step = HcNetSdkCommandPortSocketStep(
            (build_hcnetsdk_tcp_frame(b"preview"),),
            response_reads_after_each=0,
            media_socket=True,
        )
        stream = HcNetSdkCommandPortMultiSocketMediaStream(
            HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
            HcNetSdkCommandPortMultiSocketPlan((media_step,)),
        )
        stream._media_client = cast(Any, client)  # noqa: SLF001

    stream.bootstrap = cast(Any, object())
    stream._first_media = first_media  # noqa: SLF001
    source = local_media_packet_source(stream)

    first = list(source.iter_media_packets(limits=CaptureLimits(max_bytes=len(first_body))))
    second = list(source.iter_media_packets(limits=CaptureLimits(max_packets=1)))

    assert [packet.body for packet in first] == [first_body]
    assert [packet.body for packet in second] == [second_body]

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

def test_hcnetsdk_multi_socket_short_drain_expiry_continues_bootstrap() -> None:
    class QuietMediaClient:
        def __init__(self) -> None:
            self.reads = 0
            self.invalidate_values: list[object] = []
            self.connected = True

        def read_media_frame_after_prefix(self, **kwargs: object) -> object:
            self.reads += 1
            self.invalidate_values.append(kwargs.get("invalidate_on_deadline"))
            raise EzvizLocalSdkDeadlineExpired("drain complete")

    step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"preview"),),
        response_reads_after_each=0,
        media_socket=True,
        drain_media_before_next_step_seconds=0.5,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    quiet_client = QuietMediaClient()
    stream._media_client = cast(Any, quiet_client)  # noqa: SLF001

    stream._drain_media_before_next_step(  # noqa: SLF001
        step,
        step_index=0,
        capture_deadline=10.0,
        monotonic=lambda: 0.0,
    )

    assert quiet_client.reads == 1
    assert quiet_client.invalidate_values == [False]

def test_hcnetsdk_multi_socket_partial_drain_expiry_aborts_bootstrap() -> None:
    class InvalidatedMediaClient:
        connected = False

        def read_media_frame_after_prefix(self, **_kwargs: object) -> object:
            raise EzvizLocalSdkDeadlineExpired("partial drain")

    step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"preview"),),
        response_reads_after_each=0,
        media_socket=True,
        drain_media_before_next_step_seconds=0.5,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    stream._media_client = cast(Any, InvalidatedMediaClient())  # noqa: SLF001

    with pytest.raises(EzvizLocalSdkDeadlineExpired, match="partial drain"):
        stream._drain_media_before_next_step(  # noqa: SLF001
            step,
            step_index=0,
            capture_deadline=10.0,
            monotonic=lambda: 0.0,
        )

def test_hcnetsdk_multi_socket_stream_checks_deadline_between_drained_media() -> None:
    first_payload = b"\x00\x00\x01\xbaabc"
    second_payload = b"\x00\x00\x01\xbadef"
    plan = HcNetSdkCommandPortMultiSocketPlan(
        steps=(
            HcNetSdkCommandPortSocketStep(
                (build_hcnetsdk_tcp_frame(b"preview"),),
                response_reads_after_each=0,
                media_socket=True,
            ),
        )
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        plan,
    )
    stream.bootstrap = SimpleNamespace()  # type: ignore[assignment]
    stream._media_client = cast(Any, object())  # noqa: SLF001
    stream._drained_media = [  # noqa: SLF001
        _media(first_payload, sequence=1),
        _media(second_payload, sequence=2),
    ]
    monotonic_values = iter((0.0, 0.0, 1.0, 1.0))

    packets = list(
        stream.iter_packets(
            max_packets=2,
            duration_seconds=1.0,
            monotonic=lambda: next(monotonic_values),
        )
    )

    assert [packet.body for packet in packets] == [first_payload]
    assert len(stream._drained_media) == 1  # noqa: SLF001

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

def test_hcnetsdk_background_keepalive_inherits_capture_deadline() -> None:
    deadline = 11.0
    sent: list[dict[str, object]] = []

    class FakeMediaClient:
        def send_command_frame(self, _frame: bytes, **kwargs: object) -> None:
            sent.append(kwargs)

    step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"preview"),),
        response_reads_after_each=0,
        media_socket=True,
        keepalive_frames=(build_hcnetsdk_tcp_frame(b"keepalive"),),
        keepalive_initial_delay_seconds=0.0,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    stream._media_client = cast(Any, FakeMediaClient())  # noqa: SLF001

    def clock() -> float:
        return 10.0

    stream._start_keepalives(  # noqa: SLF001
        step,
        deadline=deadline,
        monotonic=clock,
    )
    assert stream._keepalive_thread is not None  # noqa: SLF001
    stream._keepalive_thread.join(timeout=1.0)  # noqa: SLF001

    assert sent == [{"deadline": deadline, "monotonic": clock}]
    assert stream.keepalive_events[0].error is None
    assert stream.keepalive_events[0].elapsed_seconds >= 0.0

def test_hcnetsdk_background_keepalive_uses_updated_capture_deadline() -> None:
    first_sent = Event()
    release_first = Event()
    sent: list[dict[str, object]] = []

    class FakeMediaClient:
        def send_command_frame(self, _frame: bytes, **kwargs: object) -> None:
            sent.append(kwargs)
            if len(sent) == 1:
                first_sent.set()
                assert release_first.wait(timeout=1.0)

    step = HcNetSdkCommandPortSocketStep(
        (
            build_hcnetsdk_tcp_frame(b"keepalive-1"),
            build_hcnetsdk_tcp_frame(b"keepalive-2"),
        ),
        response_reads_after_each=0,
        media_socket=True,
        keepalive_frames=(
            build_hcnetsdk_tcp_frame(b"keepalive-1"),
            build_hcnetsdk_tcp_frame(b"keepalive-2"),
        ),
        keepalive_initial_delay_seconds=0.0,
        keepalive_interval_seconds=0.0,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    stream._media_client = cast(Any, FakeMediaClient())  # noqa: SLF001
    first_clock = lambda: 10.0  # noqa: E731
    second_clock = lambda: 20.0  # noqa: E731

    stream._start_keepalives(  # noqa: SLF001
        step,
        deadline=11.0,
        monotonic=first_clock,
    )
    assert first_sent.wait(timeout=1.0)
    stream._start_keepalives(  # noqa: SLF001
        step,
        deadline=21.0,
        monotonic=second_clock,
    )
    release_first.set()
    assert stream._keepalive_thread is not None  # noqa: SLF001
    stream._keepalive_thread.join(timeout=1.0)  # noqa: SLF001

    assert sent == [
        {"deadline": 11.0, "monotonic": first_clock},
        {"deadline": 21.0, "monotonic": second_clock},
    ]

def test_hcnetsdk_background_deadline_failure_invalidates_media_client() -> None:
    send_started = Event()
    release_send = Event()

    class DeadlineMediaClient:
        def __init__(self) -> None:
            self.shutdown_called = False

        def send_command_frame(self, _frame: bytes, **_kwargs: object) -> None:
            send_started.set()
            assert release_send.wait(timeout=1.0)
            raise EzvizLocalSdkDeadlineExpired("write deadline expired")

        def shutdown(self) -> None:
            self.shutdown_called = True

    step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"keepalive"),),
        response_reads_after_each=0,
        media_socket=True,
        keepalive_frames=(build_hcnetsdk_tcp_frame(b"keepalive"),),
        keepalive_initial_delay_seconds=0.0,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    client = DeadlineMediaClient()
    stream._media_client = cast(Any, client)  # noqa: SLF001
    stream._start_keepalives(  # noqa: SLF001
        step,
        deadline=11.0,
        monotonic=lambda: 10.0,
    )
    assert send_started.wait(timeout=1.0)

    stream._set_keepalive_deadline(None, time.monotonic)  # noqa: SLF001
    release_send.set()
    assert stream._keepalive_thread is not None  # noqa: SLF001
    stream._keepalive_thread.join(timeout=1.0)  # noqa: SLF001

    assert client.shutdown_called
    assert len(stream.keepalive_events) == 1
    assert stream.keepalive_events[0].sent is False

def test_hcnetsdk_keepalive_deadline_socket_close_ends_capture_normally() -> None:
    """A deadline-limited keepalive may close an in-flight media read."""

    class ClosedMediaClient:
        def read_media_frame_after_prefix(self, **_kwargs: object) -> Any:
            stream._keepalive_deadline_expired.set()  # noqa: SLF001
            raise OSError("socket closed by keepalive")

    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan(
            steps=(
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"preview"),),
                    response_reads_after_each=0,
                    media_socket=True,
                ),
            )
        ),
    )
    stream.bootstrap = cast(Any, object())
    stream._media_client = cast(Any, ClosedMediaClient())  # noqa: SLF001

    packets = list(
        stream.iter_packets(
            duration_seconds=1.0,
            duration_from_start=True,
            monotonic=lambda: 0.0,
        )
    )

    assert packets == []
    assert stream._read_interrupted is True  # noqa: SLF001

def test_hcnetsdk_unrelated_socket_close_before_deadline_still_fails() -> None:
    """An early socket failure is not hidden merely because capture is bounded."""

    class ClosedMediaClient:
        def read_media_frame_after_prefix(self, **_kwargs: object) -> Any:
            raise OSError("remote closed")

    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan(
            steps=(
                HcNetSdkCommandPortSocketStep(
                    (build_hcnetsdk_tcp_frame(b"preview"),),
                    response_reads_after_each=0,
                    media_socket=True,
                ),
            )
        ),
    )
    stream.bootstrap = cast(Any, object())
    stream._media_client = cast(Any, ClosedMediaClient())  # noqa: SLF001

    with pytest.raises(PyEzvizError, match="media packet read failed: remote closed"):
        list(
            stream.iter_packets(
                duration_seconds=1.0,
                duration_from_start=True,
                monotonic=lambda: 0.0,
            )
        )

def test_hcnetsdk_close_interrupts_in_flight_keepalive_before_join() -> None:
    send_started = Event()
    socket_closed = Event()
    max_elapsed = 0.5

    class BlockingMediaClient:
        def send_command_frame(self, _frame: bytes, **_kwargs: object) -> None:
            send_started.set()
            assert socket_closed.wait(timeout=1.0)

        def shutdown(self) -> None:
            socket_closed.set()

    step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"preview"),),
        response_reads_after_each=0,
        media_socket=True,
        keepalive_frames=(build_hcnetsdk_tcp_frame(b"keepalive"),),
        keepalive_initial_delay_seconds=0.0,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((step,)),
    )
    client = BlockingMediaClient()
    stream._media_client = cast(Any, client)  # noqa: SLF001
    stream._clients = [cast(Any, client)]  # noqa: SLF001
    stream._start_keepalives(step)  # noqa: SLF001
    assert send_started.wait(timeout=1.0)

    started_at = time.monotonic()
    stream.close()
    elapsed = time.monotonic() - started_at

    assert socket_closed.is_set()
    assert elapsed < max_elapsed
    assert stream._keepalive_thread is None  # noqa: SLF001

def test_hcnetsdk_packet_limited_capture_clears_keepalive_deadline() -> None:
    media_step = HcNetSdkCommandPortSocketStep(
        (build_hcnetsdk_tcp_frame(b"preview"),),
        response_reads_after_each=0,
        media_socket=True,
    )
    stream = HcNetSdkCommandPortMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortMultiSocketPlan((media_step,)),
    )
    stream.bootstrap = cast(Any, object())
    stream._media_client = cast(Any, object())  # noqa: SLF001
    stream._first_media = _media(b"\x00\x00\x01\xbaabc")  # noqa: SLF001

    packets = list(
        stream.iter_packets(
            max_packets=1,
            duration_seconds=10.0,
            duration_from_start=True,
            monotonic=lambda: 5.0,
        )
    )

    assert len(packets) == 1
    assert stream._keepalive_deadline is None  # noqa: SLF001

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

def test_hcnetsdk_native_lan_live_view_plan_matches_app_observed_shape() -> None:
    plan = hcnetsdk_command_port_native_lan_live_view_plan()

    assert len(plan.steps) == 10
    assert [step.name for step in plan.steps] == [
        "control-0",
        "control-1",
        "control-2",
        "control-3",
        "control-4",
        "control-5",
        "control-111050",
        "play-login",
        "media",
        "keyframe",
    ]
    assert plan.steps[7].control_templates[0].command_id == 0x111040
    assert len(plan.steps[7].control_templates[0].body_tail) == 148
    assert (
        plan.steps[7].control_templates[0].body_tail_transform
        == "play_login_today"
    )
    assert plan.steps[7].response_reads_after_each == 1
    patched_tail = hcnetsdk_command_port_play_login_body_tail_for_today(
        plan.steps[7].control_templates[0].body_tail,
        today=date(2026, 6, 13),
    )
    patched_words = {
        offset: int.from_bytes(patched_tail[offset : offset + 4], "big")
        for offset in range(0, len(patched_tail), 4)
    }
    assert patched_words[36] == 2026
    assert patched_words[40] == 6
    assert patched_words[44] == 13
    assert patched_words[48] == 0
    assert patched_words[60] == 2026
    assert patched_words[64] == 6
    assert patched_words[68] == 13
    assert patched_words[72] == 23
    assert patched_words[76] == 59
    assert patched_words[80] == 59
    assert patched_words[84] == 0

    media_step = plan.steps[8]
    assert media_step.media_socket is True
    assert media_step.read_response_after_each is False
    assert media_step.response_reads_after_each is None
    assert media_step.control_templates[0].command_id == 0x30000
    assert media_step.control_templates[0].body_tail == bytes.fromhex(
        "000000010000000000000401"
    )
    assert [template.addend_delta for template in media_step.keepalive_templates] == [
        10,
        16,
        22,
        28,
        34,
        40,
    ]

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

@pytest.mark.parametrize("duration_seconds", [0.0, -1.0])
def test_hcnetsdk_generated_multi_socket_stream_skips_start_for_empty_duration(
    duration_seconds: float,
) -> None:
    def unexpected_socket_factory(
        _address: tuple[str, int],
        _timeout: float | None,
    ) -> _FakeSocket:
        pytest.fail("empty capture must not open a socket")

    stream = HcNetSdkCommandPortGeneratedMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortGeneratedMultiSocketPlan(steps=()),
        password=b"123456",
        socket_factory=unexpected_socket_factory,
    )

    packets = list(stream.iter_packets(duration_seconds=duration_seconds))

    assert packets == []
    assert stream.bootstrap is None

def test_generated_stream_ends_normally_when_bootstrap_uses_capture_budget() -> None:
    class RenderedStream:
        closed = False

        def close(self) -> None:
            self.closed = True

        def iter_packets(self, **_kwargs: object) -> Iterator[EzvizLocalStreamPacket]:
            raise AssertionError("expired capture must not request a packet")

    rendered = RenderedStream()
    stream = object.__new__(HcNetSdkCommandPortGeneratedMultiSocketMediaStream)
    stream.bootstrap = cast(Any, object())
    vars(stream)["_stream"] = cast(Any, rendered)
    stream.rsa_key = object()
    ticks = iter((0.0, 1.0))

    packets = list(
        stream.iter_packets(
            duration_seconds=1.0,
            duration_from_start=True,
            monotonic=lambda: next(ticks),
        )
    )

    assert packets == []
    assert rendered.closed is True

def test_generated_stream_creates_rsa_key_before_startup_budget(monkeypatch) -> None:
    stream = HcNetSdkCommandPortGeneratedMultiSocketMediaStream(
        HcNetSdkLanEndpoint(serial="CAM123", host="192.0.2.10"),
        HcNetSdkCommandPortGeneratedMultiSocketPlan(steps=()),
        password=b"123456",
    )
    now = [0.0]
    generated_key = object()
    deadlines: list[float | None] = []

    def generate() -> object:
        now[0] = 5.0
        return generated_key

    def start(**kwargs: object) -> None:
        deadlines.append(cast(float | None, kwargs["deadline"]))
        raise EzvizLocalSdkDeadlineExpired

    monkeypatch.setattr(
        "pyezvizapi.local_stream.hcnetsdk_command_port_rsa_key",
        generate,
    )
    monkeypatch.setattr(stream, "start", start)

    packets = list(
        local_media_packet_source(stream).iter_media_packets(
            limits=CaptureLimits(duration_seconds=1.0),
            monotonic=lambda: now[0],
        )
    )

    assert packets == []
    assert stream.rsa_key is generated_key
    assert deadlines == [6.0]

def test_prestarted_generated_stream_skips_unused_rsa_key(monkeypatch) -> None:
    class RenderedStream:
        def iter_packets(self, **_kwargs: object) -> Iterator[EzvizLocalStreamPacket]:
            return iter(())

    stream = object.__new__(HcNetSdkCommandPortGeneratedMultiSocketMediaStream)
    stream.bootstrap = cast(Any, object())
    vars(stream)["_stream"] = cast(Any, RenderedStream())
    stream.rsa_key = None
    monkeypatch.setattr(
        "pyezvizapi.local_stream.hcnetsdk_command_port_rsa_key",
        lambda: pytest.fail("pre-started stream must not generate an unused RSA key"),
    )

    packets = list(stream.iter_packets(duration_seconds=1.0))

    assert packets == []

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

@pytest.mark.parametrize("command_port", [False, True])
@pytest.mark.parametrize("stream_id", [0xBA, 0xBC, 0xC0, 0xE0])
def test_local_media_stream_preserves_mixed_fragmented_and_single_ps_records(
    command_port: bool, stream_id: int
) -> None:
    first = b"\x00\x00\x01\xba" + b"pack"
    record = b"\x00\x00\x01" + bytes((stream_id,)) + b"record"
    frames = (
        _media(b"\x1c\x80" + first, sequence=1),
        _media(b"\x1c\x00middle", sequence=1),
        _media(b"\x1c\x40tail", sequence=1),
        _media(b"\x0d" + record, sequence=2),
    )
    stream: HcNetSdkCommandPortMediaStream | EzvizLocalSdkMediaStream
    if command_port:
        stream = HcNetSdkCommandPortMediaStream(
            _FakeCommandPortClient(*frames),  # type: ignore[arg-type]
            (b"preview-start",),
        )
    else:
        stream = EzvizLocalSdkMediaStream(
            _FakeSdkClient(*frames), _preview_request()  # type: ignore[arg-type]
        )

    packets = list(stream.iter_packets(max_packets=4))

    assert b"".join(packet.body for packet in packets) == first + b"middletail" + record


@pytest.mark.parametrize(
    "payload",
    [
        b"\x0d",
        b"\x0d\x00\x00\x01",
        b"\x0d\x00\x00\x01\x40\x01hevc",
        b"\x0d\x80\x60rtp",
        b"\x0dmedia",
        b"\x00\x00\x01\xbapack",
    ],
)
def test_local_sdk_media_stream_keeps_non_ps_shim_lookalikes(payload: bytes) -> None:
    stream = EzvizLocalSdkMediaStream(
        _FakeSdkClient(_media(payload)), _preview_request()  # type: ignore[arg-type]
    )

    assert next(stream.iter_packets(max_packets=1)).body == payload

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

def test_hcnetsdk_command_port_media_stream_keeps_malformed_rtp_like_payload() -> None:
    payload = (
        b"\x90\x60\x00\x01"
        b"\x00\x00\x00\x01"
        b"\x01\x02\x03\x04"
        b"\xbe\xde\xff\xff"
        b"raw-command-port-payload"
    )
    command_client = _FakeCommandPortClient(_raw_media(payload))
    stream = HcNetSdkCommandPortMediaStream(
        command_client,  # type: ignore[arg-type]
        (b"preview-start",),
        max_prefix_bytes=128,
    )

    packets = list(stream.iter_packets(max_packets=1))

    assert packets[0].body == payload

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

def test_get_local_sdk_stream_credentials_registers_p2p_before_cas(
    monkeypatch,
) -> None:
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

        def register_p2p_session(self, *, max_retries: int = 0) -> dict[str, Any]:
            calls.append(("p2p-register", max_retries))
            return {"meta": {"code": 200}}

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

    get_local_sdk_stream_credentials_from_client(
        FakeClient(),
        "CAM123456",
        cas_serial="FULLCAM123456",
        fetch_media_key=False,
        p2p_register_max_retries=2,
    )

    assert calls == [
        ("infos", "CAM123456"),
        ("p2p-register", 2),
        ("token",),
        ("cas-init", {"session_id": "session"}),
        ("cas", "FULLCAM123456"),
    ]

def test_get_local_sdk_stream_credentials_can_skip_p2p_register(
    monkeypatch,
) -> None:
    calls: list[Any] = []

    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            return {
                serial: {
                    "CONNECTION": {
                        "localIp": "192.0.2.10",
                        "localCmdPort": 9010,
                        "localStreamPort": 9020,
                    }
                }
            }

        def register_p2p_session(self, *, max_retries: int = 0) -> dict[str, Any]:
            calls.append(("p2p-register", max_retries))
            return {"meta": {"code": 200}}

        def export_token(self) -> dict[str, str]:
            return {"session_id": "session"}

    class FakeCas:
        def __init__(self, _token: dict[str, str]) -> None:
            return None

        def cas_get_encryption(self, _serial: str) -> dict[str, Any]:
            return {
                "Response": {
                    "Session": {
                        "@Key": "1234567890abcdef",
                        "@OperationCode": "0123456",
                    }
                }
            }

    monkeypatch.setattr("pyezvizapi.local_stream.EzvizCAS", FakeCas)

    get_local_sdk_stream_credentials_from_client(
        FakeClient(),
        "CAM123456",
        fetch_media_key=False,
        register_p2p_session=False,
    )

    assert calls == []

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

@pytest.mark.parametrize(
    "unsafe_bounds",
    [
        {},
        {"duration_seconds": 0.0},
        {"duration_seconds": -1.0},
        {"duration_seconds": float("nan")},
        {"duration_seconds": float("inf")},
        {"duration_seconds": 10**309},
        {"max_packets": 0},
        {"max_packets": -1},
        {"max_packets": float("nan")},
        {"max_packets": float("inf")},
        {"max_packets": 1, "duration_seconds": float("nan")},
        {"max_packets": 1, "duration_seconds": 10**309},
    ],
)
def test_copy_local_sdk_stream_from_client_rejects_unsafe_decrypt_bound_early(
    unsafe_bounds: dict[str, Any],
) -> None:
    class FakeClient:
        def get_device_infos(self, serial: str) -> dict[str, Any]:
            raise AssertionError("should not fetch device info for invalid decrypt bounds")

    with pytest.raises(
        PyEzvizError,
        match="requires a positive finite duration_seconds or max_packets",
    ):
        copy_local_sdk_stream_from_client(
            FakeClient(),
            "CAM123456",
            io.BytesIO(),
            decrypt_video=True,
            **unsafe_bounds,
        )
