"""Native owned-session stop, fresh command sockets and finite drain bounds."""

import socket

import pytest

# ruff: noqa: PLR2004
from pyezvizapi.exceptions import EzvizLocalSdkDeadlineExpired, PyEzvizError
from pyezvizapi.hcnetsdk import (
    EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES,
    EzvizCasDeviceInfo,
    EzvizLocalPreviewRequest,
    EzvizLocalSdkClient,
    HcNetSdkLanEndpoint,
    build_ezviz_local_sdk_frame,
    build_ezviz_local_stop_preview_request_body,
    decrypt_ezviz_local_sdk_body_aes_cbc,
    parse_ezviz_local_sdk_frame,
)

IV = b"0" * 16
TRAILER = b"0" * 32


class Peer:
    def __init__(self, data=b""):
        self.data = data
        self.sent = []
        self.closed = False
        self.timeout = 5.0
        self.shutdown_modes = []
        self.received = 0
        self.eof_reads = 0
        self.clock = None
        self.receive_step = 0.0
        self.receive_error = None

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, count):
        if self.receive_error is not None:
            raise self.receive_error
        if self.clock is not None:
            self.clock[0] += self.receive_step
        part, self.data = self.data[:count], self.data[count:]
        self.received += len(part)
        if not part:
            self.eof_reads += 1
        return part

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, mode):
        self.shutdown_modes.append(mode)

    def close(self):
        self.closed = True


def reply(command, body):
    return build_ezviz_local_sdk_frame(command=command, body=body) + TRAILER


@pytest.fixture
def peers():
    command = Peer(reply(0x2012, "<Response><Result>0</Result><Session>765</Session></Response>"))
    media = Peer(reply(0x3106, "<Response><Result>0</Result></Response>") + b"queued-media")
    stop = Peer(reply(0x2014, "<Response><Result>0</Result></Response>"))
    calls = []

    def factory(address, timeout, source_address=None):
        calls.append((address, timeout, source_address))
        return [command, media, stop][len(calls) - 1]

    client = EzvizLocalSdkClient(
        HcNetSdkLanEndpoint("CAM", "192.0.2.1", command_port=9010, stream_port=9020),
        EzvizCasDeviceInfo("CAM", "owner-operation", "1234567890abcdef"),
        socket_factory=factory,
        iv_factory=lambda _n: IV,
    )
    request = EzvizLocalPreviewRequest(
        operation_code="owner-operation",
        channel=1,
        receiver_info="receiver",
        receiver_info_ex="receiver-ex",
    )
    return client, request, command, media, stop, calls


def start(peers):
    client, request, *_ = peers
    client.bootstrap_preview_from_fields(
        preview_request=request, preview_sequence=1, stream_setup_sequence=2
    )
    return client


def test_close_stops_only_owned_session_on_fresh_command_then_drains_to_eof(peers):
    client = start(peers)
    _, _, command, media, stop, calls = peers
    client.close()
    assert [c[0][1] for c in calls] == [9010, 9020, 9010]
    assert calls[-1][2] is None  # no reuse of the preview's bound receiver port
    assert 0 < calls[-1][1] <= 2
    assert len(command.sent) == 1
    frame = parse_ezviz_local_sdk_frame(stop.sent[0])
    assert frame.header.command == 0x2013
    assert frame.header.sequence == 3
    body = decrypt_ezviz_local_sdk_body_aes_cbc(frame.body, key=client.device_info.key_bytes, iv=IV)
    assert body == build_ezviz_local_stop_preview_request_body(
        operation_code="owner-operation", session="765"
    )
    assert media.shutdown_modes == [socket.SHUT_WR]
    assert media.eof_reads == 1 and not media.data
    assert all(p.closed for p in (command, media, stop))
    client.close()
    assert len(calls) == 3


@pytest.mark.parametrize("session", [0, -1, True, "", "all", 0x80000000, "\u0661", "9" * 5000])
def test_stop_builder_rejects_wildcard_or_unrecognized_sessions(session):
    with pytest.raises(PyEzvizError, match="positive owned session"):
        build_ezviz_local_stop_preview_request_body(
            operation_code="owner-operation", session=session
        )


def test_stop_xml_escapes_owner_operation_code():
    assert b"&lt;&amp;" in build_ezviz_local_stop_preview_request_body(
        operation_code="<&", session=1
    )


@pytest.mark.parametrize(
    "command,body",
    [
        (0x2012, "<Response><Result>0</Result></Response>"),
        (0x2014, "<Response><Result>5</Result></Response>"),
        (0x2014, "<Response/>"),
    ],
)
def test_rejected_or_unexpected_stop_does_not_drain_and_still_closes_all_sockets(
    peers, command, body
):
    client = start(peers)
    peers[4].data = reply(command, body)
    client.close()
    assert not peers[3].shutdown_modes
    assert all(p.closed for p in peers[2:5])
    client.close()
    assert len(peers[5]) == 3


def test_raw_setup_body_does_not_imply_session_stop_authority(peers):
    client = peers[0]
    client.bootstrap_preview(preview_body="<Request/>", stream_setup_body="<Request/>")
    client.close()
    assert len(peers[5]) == 2


def test_preview_rejection_never_generates_wildcard_stop(peers):
    peers[2].data = reply(0x2012, "<Response><Result>5</Result></Response>")
    with pytest.raises(PyEzvizError, match="missing Session"):
        start(peers)
    peers[0].close()
    assert len(peers[5]) == 1


def test_stream_setup_failure_still_releases_accepted_preview(peers):
    peers[3].data = reply(0x2014, "<Response><Result>5</Result></Response>")
    with pytest.raises(PyEzvizError, match="unexpected command"):
        start(peers)
    peers[0].close()
    assert len(peers[4].sent) == 1
    assert all(p.closed for p in peers[2:5])


def test_sustained_input_cannot_make_stop_drain_unbounded(peers):
    client = start(peers)
    peers[3].data = b"x" * (EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES + 1)
    before = peers[3].received
    client.close()
    assert peers[3].received - before == EZVIZ_LOCAL_SDK_STOP_DRAIN_BYTES
    assert peers[3].data == b"x" and peers[3].closed


def test_stop_response_and_drain_share_one_deadline(peers):
    client = start(peers)
    clock = [10.0]
    peers[3].data = b"x" * 300000
    peers[3].clock, peers[4].clock = clock, clock
    peers[3].receive_step = peers[4].receive_step = 0.1
    with pytest.raises(EzvizLocalSdkDeadlineExpired):
        client.stop_preview(timeout=0.35, monotonic=lambda: clock[0])
    assert clock[0] <= 10.45
    client.close()
    assert len(peers[5]) == 3
    assert all(p.closed for p in peers[2:5])


@pytest.mark.parametrize("retry", [False, True])
def test_invalidated_owned_media_is_retained_only_for_stop_drain(peers, retry):
    client = start(peers)
    media = peers[3]
    clock = [10.0]
    media.clock = clock
    media.receive_step = 0.2
    with pytest.raises(EzvizLocalSdkDeadlineExpired):
        client.read_stream_frame_after_prefix(deadline=10.1, monotonic=lambda: clock[0])
    assert not media.closed
    if retry:
        with pytest.raises(PyEzvizError, match="invalidated"):
            client.read_stream_frame_after_prefix()
        with pytest.raises(PyEzvizError, match="Close this client"):
            start(peers)
        assert len(peers[5]) == 2
        assert not media.closed
    client.close()
    assert media.shutdown_modes == [socket.SHUT_WR]
    assert media.eof_reads == 1 and media.closed
    assert client._retired_stream_sock is None  # noqa: SLF001


def test_malformed_stop_reply_is_explicit_protocol_error(peers):
    client = start(peers)
    peers[4].data = reply(0x2014, "<Response>")
    with pytest.raises(PyEzvizError, match="malformed XML"):
        client.stop_preview()
    client.close()
    assert all(peer.closed for peer in peers[2:5])


def test_malformed_stop_reply_never_masks_context_body_exception(peers):
    client = start(peers)
    peers[4].data = reply(0x2014, "<Response>")
    original = ValueError("original context error")
    caught = None
    try:
        with client:
            raise original
    except ValueError as error:
        caught = error
    assert caught is original
    assert all(peer.closed for peer in peers[2:5])
    assert not peers[3].shutdown_modes


def test_stop_drain_os_timeout_is_sdk_deadline_error(peers):
    client = start(peers)
    peers[3].receive_error = TimeoutError("OS receive deadline")
    with pytest.raises(EzvizLocalSdkDeadlineExpired, match="drain exceeded") as caught:
        client.stop_preview()
    assert isinstance(caught.value.__cause__, TimeoutError)
    client.close()
    assert all(peer.closed for peer in peers[2:5])


@pytest.mark.parametrize("structured", [False, True])
def test_bootstrap_cannot_overwrite_accepted_session_before_close(peers, structured):
    client = start(peers)
    with pytest.raises(PyEzvizError, match="Close this client"):
        if structured:
            start(peers)
        else:
            client.bootstrap_preview(preview_body="<Request/>", stream_setup_body="<Request/>")
    assert len(peers[5]) == 2
    client.close()
    assert len(peers[5]) == 3
