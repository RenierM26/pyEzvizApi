"""LAN SD: fail closed on incomplete transport/media, never use cloud discovery."""

from io import BytesIO
import struct
from types import SimpleNamespace
from typing import Any

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import EzvizIncompleteMediaError, PyEzvizError
from pyezvizapi.streaming.capture import ClipOptions, LocalPlaybackClipSource
from pyezvizapi.streaming.local import playback
from pyezvizapi.streaming.local.hcnetsdk.api import HcNetSdkLanEndpoint
from pyezvizapi.streaming.media.models import CaptureLimits
from tests.streaming.media.test_stream_media import _timed_video_pes

BEGIN = "20261108T081522Z"
END = "20261108T081542Z"
SERIAL = "C12345678"
ENDPOINT = HcNetSdkLanEndpoint(SERIAL, "192.0.2.10")
PACK = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
HEADER = b"IMKH" + bytes(36)
KEEP = b"keep"


def media(seconds=20):
    return b"".join(PACK + _timed_video_pes(i * 90_000) for i in range(seconds + 1))


def block(kind, body=b""):
    return struct.pack(">II", len(body) + 8, kind) + body


def metadata(header=HEADER):
    # The advertised file size is not an exact output length (native SDK agrees).
    return block(19, struct.pack(">4I", 1, 21, 299, len(header)) + header)


def wire(body=None):
    return metadata() + block(20, media() if body is None else body) + block(21)


class Socket:
    def __init__(self, data):
        self.data = data
        self.reads = 0

    def recv(self, size):
        self.reads += 1
        # Fragment every header and body to exercise stream reassembly.
        part, self.data = self.data[: min(size, 3)], self.data[min(size, 3) :]
        return part

    def getsockname(self):
        return ("192.0.2.20", 12345)

    def settimeout(self, value):
        self.timeout = value


def transport(monkeypatch, data=None, *, login_error=None, selection_status=1, logout_error=None):
    clients: list[Any] = []

    class Client:
        def __init__(self, endpoint, **kwargs):
            self.index = len(clients)
            self.sock = Socket(wire() if data is None else data)
            self.closed = False
            self.sent = []
            clients.append(self)

        def __enter__(self):
            pytest.fail("Native client __enter__ would connect outside the shared deadline")

        def login(self, **kwargs):
            if login_error:
                raise login_error
            return SimpleNamespace(
                serial="CS-H9c-" + SERIAL,
                session_id=b"1234",
                auth_seed=5,
                challenge=b"synthetic-key-1234",
            )

        def send_command_frame(self, frame, **kwargs):
            self.sent.append(frame)

        def read_tcp_frame(self, **kwargs):
            if self.index == 2 and logout_error:
                raise logout_error
            return SimpleNamespace(
                header=SimpleNamespace(field_8=selection_status if self.index == 1 else 1)
            )

        def close(self):
            self.closed = True

    monkeypatch.setattr(playback, "HcNetSdkCommandPortClient", Client)
    monkeypatch.setattr(playback, "hcnetsdk_command_port_rsa_key", object)
    return clients


def download(output, **kwargs):
    return playback.download_lan_sd_recording(
        ENDPOINT, "synthetic-password", output, BEGIN, END, timezone="Africa/Johannesburg", **kwargs
    )


def test_native_selector_bytes_from_sdk_capture():
    assert playback.lan_playback_body(1, BEGIN, END, "Africa/Johannesburg") == bytes.fromhex(
        "00000001000007ea0000000b000000080000000a0000000f00000016"
        "000007ea0000000b000000080000000a0000000f0000002a000100000000000000000000"
    )


def test_complete_download_preserves_native_file_header_and_media(monkeypatch, tmp_path):
    clients = transport(monkeypatch)
    output = tmp_path / "clip.ps"
    output.write_bytes(b"old")
    result = download(output)
    assert output.read_bytes() == HEADER + media()
    assert result["range_complete"] and result["logout_acknowledged"]
    assert result["observed_pts_span_seconds"] == 20
    assert result["native_begin_time"] == "20261108T101522Z"
    assert result["bytes"] == len(HEADER + media())
    assert len(clients) == 3 and all(c.closed for c in clients)
    assert [int.from_bytes(f[12:16], "big") for c in clients for f in c.sent] == [
        0x30102,
        0x30103,
        0x10100,
    ]
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        metadata(),
        metadata() + block(20, media()),
        metadata() + block(20, media()) + block(21)[:5],
        metadata() + block(20, media())[:-1],
        metadata() + block(21),
        block(20, media()) + block(21),
        metadata() + metadata() + block(21),
        metadata() + block(20, b"") + block(21),
        metadata() + block(99),
        metadata() + block(21, b"extra"),
        struct.pack(">II", 7, 20),
        struct.pack(">II", 1024 * 1024 + 1, 20),
        block(19, bytes(8)),
        metadata(b"bad" + bytes(37)),
        metadata(bytes(41)),
        metadata() + block(20, media() + b"\x00\x00\x01\xe0\xff\xff") + block(21),
    ],
)
def test_truncated_or_invalid_download_preserves_existing_path(monkeypatch, tmp_path, data):
    clients = transport(monkeypatch, data)
    output = tmp_path / "keep.ps"
    output.write_bytes(KEEP)
    with pytest.raises(PyEzvizError):
        download(output)
    assert output.read_bytes() == KEEP
    assert all(c.closed for c in clients)
    assert list(tmp_path.iterdir()) == [output]


def test_short_media_span_cannot_be_published_despite_end_marker(monkeypatch):
    transport(monkeypatch, wire(media(2)))
    output = BytesIO(KEEP)
    with pytest.raises(EzvizIncompleteMediaError):
        download(output)
    assert output.getvalue() == KEEP


def test_wire_byte_limit_rejects_declared_body_before_reading(monkeypatch):
    clients = transport(monkeypatch, metadata() + struct.pack(">II", 5000, 20))
    with pytest.raises(PyEzvizError, match="byte budget"):
        download(BytesIO(), max_bytes=100)
    assert clients[1].sock.reads < 40
    assert all(c.closed for c in clients)


def test_auth_failure_is_not_retried_and_no_logout_is_invented(monkeypatch):
    clients = transport(monkeypatch, login_error=PyEzvizError("synthetic refusal"))
    with pytest.raises(PyEzvizError, match="refusal"):
        download(BytesIO())
    assert len(clients) == 1 and clients[0].closed


def test_selection_refusal_preserves_numeric_result_and_logs_out(monkeypatch):
    clients = transport(monkeypatch, selection_status=23)
    with pytest.raises(playback.LanPlaybackError) as error:
        download(BytesIO())
    assert error.value.result_code == 23
    assert len(clients[1].sent) == 1 and all(c.closed for c in clients)


def test_logout_failure_prevents_publishing_success(monkeypatch):
    clients = transport(monkeypatch, logout_error=PyEzvizError("logout failed"))
    output = BytesIO(KEEP)
    with pytest.raises(PyEzvizError, match="logout failed"):
        download(output)
    assert output.getvalue() == KEEP and all(c.closed for c in clients)


def test_cleanup_does_not_mask_original_failure(monkeypatch):
    transport(monkeypatch, metadata(), logout_error=PyEzvizError("logout failed"))
    with pytest.raises(PyEzvizError, match="end marker") as error:
        download(BytesIO())
    assert "logout was not acknowledged" in " ".join(error.value.__notes__)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": float("nan")},
        {"transfer_timeout": 0},
        {"max_bytes": True},
        {"channel": 0},
        {"channel": True},
        {"duration_seconds": 0.5},
        {"timezone": "invalid"},
    ],
)
def test_invalid_inputs_never_prepare_rsa_or_connect(monkeypatch, kwargs):
    def forbidden():
        pytest.fail("Invalid range reached RSA preparation")

    monkeypatch.setattr(playback, "hcnetsdk_command_port_rsa_key", forbidden)
    if "timezone" in kwargs:
        with pytest.raises(PyEzvizError):
            playback.download_lan_sd_recording(
                ENDPOINT, "password", BytesIO(), BEGIN, END, **kwargs
            )
    else:
        with pytest.raises(PyEzvizError):
            download(BytesIO(), **kwargs)


def test_typed_client_route_does_not_touch_account(monkeypatch):
    transport(monkeypatch)
    client = EzvizClient()
    monkeypatch.setattr(client, "_request_json", lambda *a, **k: pytest.fail("Cloud accessed"))
    try:
        options = ClipOptions(
            source=LocalPlaybackClipSource(
                BEGIN, END, ENDPOINT.host, "synthetic-password", timezone="Africa/Johannesburg"
            )
        )
        result = client.save_clip_with_options(SERIAL, BytesIO(), options)
        assert result["observed_pts_span_seconds"] == 20
    finally:
        client.close_session()


def test_legacy_client_omitted_duration_selects_full_range(monkeypatch):
    transport(monkeypatch)
    client = EzvizClient()
    try:
        result = client.save_clip(
            SERIAL,
            BytesIO(),
            source="local-playback",
            host=ENDPOINT.host,
            hcnetsdk_command_password="password",
            local_playback_begin_time=BEGIN,
            local_playback_end_time=END,
            local_playback_timezone="Africa/Johannesburg",
        )
        assert result["duration_seconds"] == 20
    finally:
        client.close_session()


def test_partial_output_settings_are_rejected_before_network(monkeypatch):
    clients = transport(monkeypatch)
    client = EzvizClient()
    try:
        with pytest.raises(PyEzvizError):
            client.save_clip_with_options(
                SERIAL,
                BytesIO(),
                ClipOptions(
                    source=LocalPlaybackClipSource(BEGIN, END, ENDPOINT.host, "password"),
                    capture=CaptureLimits(max_packets=1),
                ),
            )
    finally:
        client.close_session()
    assert not clients
