"""SD playback controls: complete ranges, bounded failures and live isolation."""

from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import (
    EzvizIncompleteMediaError,
    EzvizPlaybackNegotiationError,
    PyEzvizError,
)
from pyezvizapi.streaming.capture import ClipOptions, CloudPlaybackClipSource
from pyezvizapi.streaming.cloud import playback, protocol
from pyezvizapi.streaming.cloud.protocol import (
    VtmChannel,
    VtmMessageCode,
    VtmStreamClient,
    VtmStreamEOF,
    _proto_varint,
    build_stream_info_request,
    encode_vtm_packet,
)
from pyezvizapi.streaming.media import crypto, mpegps, rtp
from pyezvizapi.streaming.media.models import CaptureLimits
from tests.streaming.media.test_stream_media import _timed_video_pes
from tests.streaming.test_stream_transport import FakeVtmSocket

KEEP = b"keep"
EXISTING = b"existing"
BEGIN = "20261108T000000Z"
END = "20261108T000020Z"
PACK = b"\x00\x00\x01\xba\x44\x00\x04\x00\x04\x01\x00\x01\xff\xf8"
START = encode_vtm_packet(b"\x08\x00\x22\x07ssn-123", message_code=VtmMessageCode.STREAMINFO_RSP)


def media(seconds=20):
    return b"".join(PACK + _timed_video_pes(i * 90_000) for i in range(seconds + 1))


def transport(monkeypatch, body=None, tail=b"", *, socket_class=FakeVtmSocket):
    body = media() if body is None else body
    wire = (
        START + encode_vtm_packet(body, channel=VtmChannel.PLAYBACK_STREAM, message_code=0) + tail
    )
    sock = socket_class([wire])
    seen = []
    original = playback.open_cloud_playback_stream

    def open_stream(*args, **kwargs):
        seen.append((args, kwargs))
        return VtmStreamClient(
            "ysproto://example.test:8554/playback",
            stream_info_timeout=10,
            socket_factory=lambda *_args: sock,
        )

    monkeypatch.setattr(playback, "open_cloud_playback_stream", open_stream)
    return sock, seen, original


def test_url_matches_contributed_native_selector_and_preserves_channel_zero():
    url = playback.build_vtm_playback_url(
        "::1",
        8554,
        "CAM123",
        "?biz=4&cln=99",
        "token +",
        BEGIN,
        END,
        channel=0,
        lid="label +",
        timestamp_ms=123,
    )
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.hostname == "::1"
    assert parsed.path == "/playback"
    assert query["chn"] == ["0"]
    assert query["cln"] == ["3"]
    assert query["begin"] == [BEGIN] and query["end"] == [END]
    assert query["ssn"] == ["token +"] and query["lid"] == ["label +"]
    assert query["rnd"] == ["123"] and query["etp"] == ["1"]


@pytest.mark.parametrize(
    "begin,end",
    [
        ("", END),
        (BEGIN, BEGIN),
        (END, BEGIN),
        ("20261308T000000Z", END),
        (BEGIN, "20261110T000000Z"),
        ("20261108T000000", END),
    ],
)
def test_invalid_range_fails_before_account_access(begin, end):
    with pytest.raises(PyEzvizError):
        playback.get_cloud_playback_stream_info(object(), "CAM123", begin, end)


def test_native_request_timeout_field_does_not_change_default_live_bytes():
    live = build_stream_info_request("ysproto://example/live")
    selected = build_stream_info_request("ysproto://example/live", stream_info_timeout=10)
    assert selected == live + b"\x40\x0a"


def test_complete_packet_boundary_eof_is_distinct_from_truncation():
    for tail, error in [
        (b"", VtmStreamEOF),
        (b"\x24\x02", PyEzvizError),
        (encode_vtm_packet(b"payload", channel=2)[:-2], PyEzvizError),
    ]:
        sock = FakeVtmSocket([tail])
        with (
            VtmStreamClient(
                "ysproto://example.test:8554/playback",
                socket_factory=lambda *_, selected=sock: selected,
            ) as stream,
            pytest.raises(error),
        ):
            stream.read_packet()
        assert sock.closed


def test_full_requested_range_survives_eof_without_a_ten_second_default(monkeypatch):
    sock, _, _ = transport(monkeypatch)
    output = BytesIO()
    result = playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert output.getvalue() == media()
    assert result["range_complete"] and result["observed_pts_span_seconds"] == 20
    assert result["completion_reason"] == "peer_eof"
    assert sock.closed


@pytest.mark.parametrize("tail", [b"\x24\x02", encode_vtm_packet(b"truncated", channel=2)[:-1]])
def test_truncated_packet_after_valid_media_cannot_publish_prefix(monkeypatch, tail):
    sock, _, _ = transport(monkeypatch, tail=tail)
    output = BytesIO(KEEP)
    with pytest.raises(PyEzvizError):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert output.getvalue() == KEEP and sock.closed


@pytest.mark.parametrize(
    "tail",
    [
        b"\x00\x00\x01\xc0\x00\x20\x80\x00\x00audio",
        _timed_video_pes(21 * 90_000)[:-1],
        PACK[:-1],
        b"garbage",
        b"\x00\x00\x01\xc0\x00\x20\x80\x00\x00audio\x24kih\x04\x03\x02\x01",
        b"\x24kih\x04\x03\x02\x02",
    ],
)
def test_truncated_ps_tail_with_complete_vtm_and_pts_preserves_destination(
    monkeypatch, tmp_path, tail
):
    sock, _, _ = transport(monkeypatch, body=media() + tail)
    output = tmp_path / "existing.ps"
    output.write_bytes(KEEP)
    client = EzvizClient("user", "password")
    with pytest.raises(PyEzvizError, match="MPEG-PS framing"):
        client.save_clip_with_options(
            "CAM123", output, ClipOptions(source=CloudPlaybackClipSource(BEGIN, END))
        )
    assert output.read_bytes() == KEEP and sock.closed


@pytest.mark.parametrize("program_end", [b"", b"\x00\x00\x01\xb9", b"\x24kih\x04\x03\x02\x01"])
def test_unbounded_video_pes_and_optional_program_end_remain_supported(monkeypatch, program_end):
    unbounded = (
        b"".join(
            PACK + pes[:4] + b"\x00\x00" + pes[6:]
            for pes in (_timed_video_pes(i * 90_000) for i in range(21))
        )
        + program_end
    )
    sock, _, _ = transport(monkeypatch, body=unbounded)
    output = BytesIO()
    result = playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert result["range_complete"] and output.getvalue() == unbounded and sock.closed


def test_unbounded_video_cannot_hide_truncated_following_audio(monkeypatch):
    pes = _timed_video_pes(21 * 90_000)
    body = media() + PACK + pes[:4] + b"\x00\x00" + pes[6:]
    body += b"\x00\x00\x01\xc0\x00\x20\x80\x00\x00audio"
    sock, _, _ = transport(monkeypatch, body=body)
    output = BytesIO(KEEP)
    with pytest.raises(PyEzvizError, match="MPEG-PS framing"):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert output.getvalue() == KEEP and sock.closed


def test_encrypted_transport_after_clear_media_remains_failure(monkeypatch):
    sock, _, _ = transport(
        monkeypatch, tail=encode_vtm_packet(b"secret", channel=VtmChannel.ENCRYPTED_STREAM)
    )
    output = BytesIO()
    with pytest.raises(PyEzvizError, match="Encrypted VTM"):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert not output.getvalue() and sock.closed


def test_short_eof_is_not_a_completed_range(monkeypatch):
    sock, _, _ = transport(monkeypatch, body=media(2))
    output = BytesIO()
    with pytest.raises(EzvizIncompleteMediaError):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert not output.getvalue() and sock.closed


def test_byte_budget_failure_keeps_output_untouched(monkeypatch):
    sock, _, _ = transport(monkeypatch)
    output = BytesIO()
    with pytest.raises(PyEzvizError, match="byte budget"):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END, max_bytes=10)
    assert not output.getvalue() and sock.closed


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": None},
        {"timeout": 0},
        {"transfer_timeout": float("inf")},
        {"max_packets": True},
        {"max_bytes": 0},
        {"duration_seconds": -1},
    ],
)
def test_invalid_budgets_fail_before_metadata_or_key_access(kwargs):
    with pytest.raises(PyEzvizError):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", BytesIO(), BEGIN, END, **kwargs)


def test_packet_capped_output_is_explicitly_partial(monkeypatch):
    sock, _, _ = transport(monkeypatch, body=media(2))
    result = playback.copy_cloud_playback_to_mpegps(
        object(), "CAM123", BytesIO(), BEGIN, END, max_packets=1
    )
    assert not result["range_complete"] and sock.closed


def test_playback_channel_is_not_a_live_stream_channel():
    wire = encode_vtm_packet(b"playback", channel=2) + encode_vtm_packet(b"live", channel=1)
    for path, expected in [("live", b"live"), ("playback", b"playback")]:
        sock = FakeVtmSocket([wire])
        with VtmStreamClient(
            f"ysproto://example.test:8554/{path}",
            stream_info_timeout=10,
            socket_factory=lambda *_, selected=sock: selected,
        ) as stream:
            packets = list(stream.iter_packets(max_packets=1))
        assert packets[0].body == expected


@pytest.mark.parametrize("explicit", [False, True])
def test_convenience_default_range_and_explicit_duration_are_distinct(monkeypatch, explicit):
    calls = []

    def copy(client, serial, output, begin, end, **kwargs):
        calls.append(kwargs)
        output.write(b"PS")
        return {"bytes": 2}

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", copy)
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    explicit_options: dict[str, Any] = (
        {"duration_seconds": 10.0, "cloud_client_type": 9} if explicit else {}
    )
    result = client.save_clip(
        "CAM123",
        BytesIO(),
        source="cloud-playback",
        cloud_playback_begin_time=BEGIN,
        cloud_playback_end_time=END,
        **explicit_options,
    )
    assert result["source"] == "cloud-playback"
    assert calls[0]["duration_seconds"] == (10.0 if explicit else None)
    assert calls[0]["client_type"] == (9 if explicit else 3)
    client.close_session()


def test_failed_typed_save_does_not_truncate_existing_path(monkeypatch, tmp_path: Path):
    def fail(*args, **kwargs):
        raise EzvizIncompleteMediaError(
            source="cloud-playback", requested_duration_seconds=20, observed_pts_span_seconds=2
        )

    monkeypatch.setattr(playback, "copy_cloud_playback_to_mpegps", fail)
    path = tmp_path / "recording.ps"
    path.write_bytes(EXISTING)
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.test"})
    with pytest.raises(EzvizIncompleteMediaError):
        client.save_clip_with_options(
            "CAM123", path, ClipOptions(source=CloudPlaybackClipSource(BEGIN, END))
        )
    assert path.read_bytes() == EXISTING
    client.close_session()


@pytest.mark.parametrize("complete", [False, True])
def test_socket_idle_alone_cannot_make_a_short_recording_success(monkeypatch, complete):
    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    clock = Clock()

    class TimeoutSocket(FakeVtmSocket):
        def recv(self, size):
            if self._buffer:
                return super().recv(size)
            clock.value += self.timeout or 1
            raise TimeoutError

    sock, _, _ = transport(
        monkeypatch, body=media(20 if complete else 2), socket_class=TimeoutSocket
    )
    output = BytesIO()
    if complete:
        result = playback.copy_cloud_playback_to_mpegps(
            object(), "CAM123", output, BEGIN, END, monotonic=clock
        )
        assert result["range_complete"]
        assert result["completion_reason"] == "idle_timeout"
    else:
        with pytest.raises(EzvizIncompleteMediaError):
            playback.copy_cloud_playback_to_mpegps(
                object(), "CAM123", output, BEGIN, END, monotonic=clock
            )
        assert not output.getvalue()
    assert sock.closed and clock.value <= 60


def test_explicit_duration_changes_the_media_selector_not_wall_time(monkeypatch):
    sock, seen, _ = transport(monkeypatch, body=media(10))
    result = playback.copy_cloud_playback_to_mpegps(
        object(), "CAM123", BytesIO(), BEGIN, END, duration_seconds=10
    )
    assert seen[0][0][3] == "20261108T000010Z"
    assert result["end_time"] == "20261108T000010Z" and sock.closed


def test_bootstrap_preserves_resource_channel_zero(monkeypatch):
    monkeypatch.setattr(
        playback.bootstrap,
        "get_cloud_stream_info",
        lambda *a, **kw: {
            "resource": {"localIndex": 0, "streamBizUrl": "?biz=2"},
            "vtdu_token": "synthetic",
            "stream_url": "ysproto://example.test:8554/live?chn=0",
        },
    )
    result = playback.get_cloud_playback_stream_info(object(), "CAM123", BEGIN, END)
    assert parse_qs(urlparse(result["stream_url"]).query)["chn"] == ["0"]


@pytest.mark.parametrize("value", [0, -1, True, 1 << 31, "10"])
def test_invalid_native_timeout_field_never_reaches_varint_encoder(value):
    with pytest.raises(PyEzvizError, match="32-bit"):
        build_stream_info_request("ysproto://example.test/playback", stream_info_timeout=value)


def test_large_finite_duration_is_clamped_before_datetime_arithmetic(monkeypatch):
    sock, seen, _ = transport(monkeypatch)
    result = playback.copy_cloud_playback_to_mpegps(
        object(), "CAM123", BytesIO(), BEGIN, END, duration_seconds=1e300
    )
    assert result["end_time"] == END and sock.closed
    assert seen[0][0][3] == END


def test_application_level_playback_refusal_is_not_reported_as_an_empty_clip(monkeypatch):
    wire = encode_vtm_packet(b"\x08\x07", message_code=VtmMessageCode.STREAMINFO_RSP)
    sock = FakeVtmSocket([wire])
    monkeypatch.setattr(
        playback,
        "open_cloud_playback_stream",
        lambda *a, **kw: VtmStreamClient(
            "ysproto://example.test:8554/playback", socket_factory=lambda *_: sock
        ),
    )
    with pytest.raises(PyEzvizError, match=r"negotiation.*7"):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", BytesIO(), BEGIN, END)
    assert sock.closed


def test_invalid_native_timeout_is_rejected_before_connecting():
    with pytest.raises(PyEzvizError, match="32-bit"):
        VtmStreamClient("ysproto://example.test:8554/playback", stream_info_timeout=-1)


def test_short_writing_output_is_fully_written_not_reported_as_complete_prefix(monkeypatch):
    sock, _, _ = transport(monkeypatch)

    class ShortWriter(BytesIO):
        def write(self, value):
            return super().write(value[:17])

    output = ShortWriter()
    result = playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert len(output.getvalue()) == result["bytes"]
    assert output.getvalue() == media() and sock.closed


def test_zero_progress_output_write_fails(monkeypatch):
    sock, _, _ = transport(monkeypatch)

    class StalledWriter(BytesIO):
        def write(self, value):
            return 0

    with pytest.raises(PyEzvizError, match="write"):
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", StalledWriter(), BEGIN, END)
    assert sock.closed


@pytest.mark.parametrize("result_code", [6520, 401, 9999])
def test_typed_negotiation_refusal_closes_socket_without_retry(monkeypatch, result_code):

    sock = FakeVtmSocket(
        [
            encode_vtm_packet(
                _proto_varint(1, result_code), message_code=VtmMessageCode.STREAMINFO_RSP
            )
        ]
    )
    calls = []

    def opened(*args, **kwargs):
        calls.append(1)
        return VtmStreamClient(
            "ysproto://example.test:8554/playback", socket_factory=lambda *_: sock
        )

    monkeypatch.setattr(playback, "open_cloud_playback_stream", opened)
    output = BytesIO(KEEP)
    with pytest.raises(EzvizPlaybackNegotiationError) as caught:
        playback.copy_cloud_playback_to_mpegps(object(), "CAM123", output, BEGIN, END)
    assert caught.value.result_code == result_code
    assert caught.value.source == "cloud-playback"
    assert caught.value.reason == "playback_negotiation_failed"
    assert sock.closed and output.getvalue() == KEEP and calls == [1]


@pytest.mark.parametrize("failure", ["write", "flush", "fsync", "replace"])
def test_atomic_publication_failure_preserves_path_and_cleans_temp(monkeypatch, tmp_path, failure):
    transport(monkeypatch)
    path = tmp_path / "recording.ps"
    path.write_bytes(EXISTING)

    def fail(*args, **kwargs):
        raise OSError("simulated publication failure")

    if failure in ("write", "flush"):
        original = playback._publish_playback  # noqa: SLF001 -- injected publication failure

        def publish(staging, output):
            if failure == "write":
                output.write(b"partial")
                fail()
            original(staging, output)
            fail()

        monkeypatch.setattr(playback, "_publish_playback", publish)
    else:
        monkeypatch.setattr(playback.os, failure, fail)
    with pytest.raises(OSError, match="simulated"):
        playback.save_cloud_playback_clip(
            object(), "CAM123", path, ClipOptions(source=CloudPlaybackClipSource(BEGIN, END))
        )
    assert path.read_bytes() == EXISTING
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_publication_success_and_spool_rollover(monkeypatch, tmp_path):
    # Both collection and publication staging must spill rather than growing BytesIO.
    body = media() * 2000
    # Limit to a packet for this storage-focused case (PTS epochs repeat).
    wire = START + b"".join(
        encode_vtm_packet(body[i : i + 60000], channel=2) for i in range(0, len(body), 60000)
    )
    sock = FakeVtmSocket([wire])
    monkeypatch.setattr(
        playback,
        "open_cloud_playback_stream",
        lambda *a, **kw: VtmStreamClient(
            "ysproto://example.test:8554/playback", socket_factory=lambda *_: sock
        ),
    )
    rolled = []
    original = playback.SpooledTemporaryFile

    def spool(*args, **kwargs):
        staging = original(*args, **kwargs)
        original_rollover = staging.rollover

        def rollover():
            rolled.append(True)
            return original_rollover()

        monkeypatch.setattr(staging, "rollover", rollover)
        return staging

    monkeypatch.setattr(playback, "SpooledTemporaryFile", spool)

    path = tmp_path / "recording.ps"
    path.write_bytes(EXISTING)
    result = playback.save_cloud_playback_clip(
        object(),
        "CAM123",
        path,
        ClipOptions(
            source=CloudPlaybackClipSource(BEGIN, END),
            capture=CaptureLimits(max_packets=1000, duration_seconds=None),
        ),
    )
    assert result["bytes"] == len(body) and path.read_bytes() == body
    assert len(rolled) == 2 and list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("duration", [0.5, True, float("nan"), -1])
def test_typed_and_direct_duration_validation_agree(duration):

    with pytest.raises(PyEzvizError):
        ClipOptions(
            source=CloudPlaybackClipSource(BEGIN, END),
            capture=CaptureLimits(duration_seconds=duration),
        )
    with pytest.raises(PyEzvizError):
        playback.copy_cloud_playback_to_mpegps(
            object(), "CAM123", BytesIO(), BEGIN, END, duration_seconds=duration
        )


def test_shared_helper_compatibility_identities():

    assert protocol._mpeg_ps_video_decrypt_ranges is mpegps._mpeg_ps_video_decrypt_ranges  # noqa: SLF001 -- compatibility identity
    assert protocol.mpeg_ps_video_pts_span_seconds is mpegps.mpeg_ps_video_pts_span_seconds
    assert rtp._rtp_media_aes_key is crypto.media_aes_key  # noqa: SLF001 -- compatibility identity
    assert rtp._decrypt_idmx_aac_access_unit is crypto.decrypt_aac_access_unit  # noqa: SLF001 -- compatibility identity
