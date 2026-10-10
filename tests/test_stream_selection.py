from __future__ import annotations

import errno
from io import BytesIO
from pathlib import Path
from typing import Any, Literal

import pytest

from pyezvizapi import (
    AutoClipSource,
    ClipOptions,
    EzvizClient,
    _local_stream,
    local_stream_ecdh,
    stream_selection,
)
from pyezvizapi.clip import CloudClipSource, LocalSdkClipSource, LocalSdkEcdhClipSource
from pyezvizapi.exceptions import (
    DeviceException,
    EzvizAuthVerificationCode,
    EzvizLocalSdkDeadlineExpired,
    EzvizLocalSdkStreamClosed,
    EzvizNoMediaError,
    EzvizUnsupportedMediaError,
    PyEzvizError,
)
from pyezvizapi.hcnetsdk import EzvizCasDeviceInfo, HcNetSdkLanEndpoint
from pyezvizapi.local_stream_transport import EzvizLocalSdkCredentials, EzvizLocalStreamPacket
from pyezvizapi.media import CaptureLimits, MediaDecodeOptions, MediaPacket, MediaPacketMetadata
from pyezvizapi.stream_selection import fallback_stream_source, select_stream_source

CAMERA = "TESTCAM"
PAYLOAD = b"test-media"
EXISTING = b"existing"


def credentials() -> EzvizLocalSdkCredentials:
    return EzvizLocalSdkCredentials(
        HcNetSdkLanEndpoint(CAMERA, "192.0.2.10", command_port=9010, stream_port=9020),
        EzvizCasDeviceInfo(CAMERA, "operation", "0123456789abcdef"),
        "media-key",
    )


def fail(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("Cloud/account access is forbidden")


class NoCloudClient:
    get_device_infos = fail
    get_cam_key = fail
    export_token = fail
    register_p2p_session = fail
    login = fail


@pytest.mark.parametrize(
    ("support", "kind"),
    [
        ({"519": "1,2,3"}, "local-sdk-ecdh"),
        ({"519": "2,3"}, "local-sdk"),
        ({"519": "11"}, "local-sdk"),
        ({"other": "1"}, "local-sdk"),
        ({"519": " 1 , 3 "}, "local-sdk-ecdh"),
        ('{"519":"1,2,3"}', "local-sdk-ecdh"),
        (None, "local-sdk-ecdh"),
        ("not-json", "local-sdk-ecdh"),
        ({}, "local-sdk-ecdh"),
        ({"519": True}, "local-sdk-ecdh"),
    ],
)
def test_offline_metadata_selects_without_account_access(support: Any, kind: str) -> None:
    options = AutoClipSource(
        mode="offline", credentials=credentials(), device={"deviceInfos": {"supportExt": support}}
    )
    source = select_stream_source(NoCloudClient(), CAMERA, options, fetch_media_key=True)
    assert source.kind == kind
    assert "media-key" not in repr(source)
    assert "operation" not in repr(options)


def test_auto_uses_cached_metadata_and_one_credential_discovery(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []
    device = {
        "deviceInfos": {"supportExt": {"519": "1"}},
        "CONNECTION": {"localIp": "192.0.2.10", "localCmdPort": 9010},
    }

    class Client:
        def get_device_infos(self, serial: str) -> dict:
            assert serial == CAMERA
            return {CAMERA: device}

    def discover(client: Any, serial: str, **kwargs: Any) -> EzvizLocalSdkCredentials:
        calls.append(kwargs)
        return credentials()

    monkeypatch.setattr(stream_selection, "get_local_sdk_stream_credentials_from_client", discover)
    source = select_stream_source(Client(), CAMERA, AutoClipSource())
    assert source.kind == "local-sdk-ecdh"
    assert len(calls) == 1
    assert calls[0]["endpoint"].host == "192.0.2.10"
    assert calls[0]["fetch_media_key"] is False


@pytest.mark.parametrize("mode", ["offline", "auto"])
def test_missing_local_endpoint_only_cloud_when_allowed(mode: Literal["auto", "offline"]) -> None:
    if mode == "offline":
        with pytest.raises(PyEzvizError, match="caller-supplied"):
            AutoClipSource(mode=mode)
        return
    assert select_stream_source(NoCloudClient(), CAMERA, AutoClipSource(device={})).kind == "cloud"
    with pytest.raises(PyEzvizError, match="No local endpoint"):
        select_stream_source(
            NoCloudClient(), CAMERA, AutoClipSource(device={}, allow_cloud_fallback=False)
        )


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_automatic_timeout_is_finite(timeout: float) -> None:
    with pytest.raises(PyEzvizError, match="positive and finite"):
        AutoClipSource(timeout=timeout)


def test_supplied_credentials_fail_closed_on_identity_and_missing_key(monkeypatch) -> None:
    monkeypatch.setattr(_local_stream, "EzvizCAS", fail)
    with pytest.raises(PyEzvizError, match="do not match"):
        _local_stream.get_local_sdk_stream_credentials_from_client(
            NoCloudClient(), "OTHER", credentials=credentials()
        )
    no_key = EzvizLocalSdkCredentials(credentials().endpoint, credentials().device_info)
    with pytest.raises(PyEzvizError, match="no cloud refresh"):
        _local_stream.get_local_sdk_stream_credentials_from_client(
            NoCloudClient(), CAMERA, credentials=no_key
        )
    assert (
        _local_stream.get_local_sdk_stream_credentials_from_client(
            NoCloudClient(), CAMERA, credentials=credentials()
        )
        == credentials()
    )


@pytest.mark.parametrize(
    "error",
    [
        DeviceException("login rejected"),
        EzvizAuthVerificationCode("MFA"),
        PyEzvizError("HMAC failed"),
        FileNotFoundError("ffmpeg"),
        PermissionError(errno.EACCES, "output denied"),
        EzvizNoMediaError("silence"),
        EzvizUnsupportedMediaError("codec", source="local-sdk-ecdh", reason="unsupported_codec"),
    ],
)
def test_auth_codec_and_configuration_errors_never_fallback(error: Exception) -> None:
    assert fallback_stream_source(LocalSdkEcdhClipSource(), AutoClipSource(), error) is None


@pytest.mark.parametrize(
    "error",
    [
        ConnectionRefusedError(),
        TimeoutError(),
        EzvizLocalSdkDeadlineExpired(),
        EzvizLocalSdkStreamClosed(),
        OSError(errno.ENETUNREACH, "network unreachable"),
        OSError(errno.EHOSTUNREACH, "host unreachable"),
        OSError(errno.ENETDOWN, "network down"),
    ],
)
def test_network_fallback_obeys_offline_policy(error: Exception) -> None:
    source = LocalSdkEcdhClipSource(credentials=credentials())
    assert isinstance(fallback_stream_source(source, AutoClipSource(), error), CloudClipSource)
    assert fallback_stream_source(source, AutoClipSource(allow_cloud_fallback=False), error) is None
    assert (
        fallback_stream_source(
            source, AutoClipSource(mode="offline", credentials=credentials()), error
        )
        is None
    )


def test_confirmed_mismatch_switches_only_to_same_credentials_locally(monkeypatch) -> None:
    monkeypatch.setattr(stream_selection, "fresh_receiver_port", lambda: 12345)
    source = LocalSdkEcdhClipSource(credentials=credentials())
    options = AutoClipSource(mode="offline", credentials=credentials())
    fallback = fallback_stream_source(
        source,
        options,
        EzvizUnsupportedMediaError("legacy", source="local-sdk-ecdh", reason="protocol_mismatch"),
    )
    assert isinstance(fallback, LocalSdkClipSource)
    assert fallback.credentials is source.credentials
    assert fallback.receiver_port == 12345


@pytest.mark.parametrize("ecdh", [False, True])
def test_offline_clip_runs_real_credential_shortcut_without_cloud(monkeypatch, ecdh: bool) -> None:
    client = EzvizClient()
    monkeypatch.setattr(client, "get_device_infos", fail)
    monkeypatch.setattr(client, "get_cam_key", fail)
    monkeypatch.setattr(client, "export_token", fail)
    monkeypatch.setattr(client, "register_p2p_session", fail)
    monkeypatch.setattr(_local_stream, "EzvizCAS", fail)

    class Stream:
        media_key = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def copy(stream: Any, output: Any, *args: Any, **kwargs: Any) -> None:
        output.write(PAYLOAD)

    if ecdh:
        monkeypatch.setattr(
            local_stream_ecdh, "open_local_sdk_ecdh_stream", lambda *a, **kw: Stream()
        )
        monkeypatch.setattr(local_stream_ecdh, "copy_local_sdk_ecdh_stream_to_media", copy)
    else:
        monkeypatch.setattr(_local_stream, "open_local_sdk_stream", lambda *a, **kw: Stream())
        monkeypatch.setattr(_local_stream, "copy_local_stream_to_decrypted_mpegts", copy)
    output = BytesIO()
    result = client.save_clip_with_options(
        CAMERA,
        output,
        ClipOptions(
            source=AutoClipSource(
                mode="offline",
                credentials=credentials(),
                device={"deviceInfos": {"supportExt": {"519": "1" if ecdh else "0"}}},
            ),
            decode=MediaDecodeOptions(decrypt_video=True),
        ),
    )
    assert output.getvalue() == PAYLOAD
    assert result["source"] == ("local-sdk-ecdh" if ecdh else "local-sdk")
    assert result["bytes"] == len(PAYLOAD)


@pytest.mark.parametrize("partial", [False, True])
def test_auto_clip_stages_failed_attempt_and_never_splices(
    monkeypatch, tmp_path: Path, partial: bool
) -> None:
    client = EzvizClient()
    calls: list[str] = []
    monkeypatch.setattr(stream_selection, "fresh_receiver_port", lambda: 12345)

    def ecdh(serial: str, output: Any, **kwargs: Any) -> Any:
        calls.append("ecdh")
        if partial:
            output.write(b"partial")
        raise EzvizUnsupportedMediaError(
            "legacy", source="local-sdk-ecdh", reason="protocol_mismatch"
        )

    def legacy(serial: str, output: Any, **kwargs: Any) -> dict:
        calls.append("legacy")
        assert kwargs["receiver_port"] == 12345
        output.write(PAYLOAD)
        return {"ok": True, "source": "local-sdk", "format": "mpegts"}

    monkeypatch.setattr(client, "_save_local_sdk_ecdh_clip", ecdh)
    monkeypatch.setattr(client, "_save_local_sdk_clip", legacy)
    output = tmp_path / "clip.ts"
    output.write_bytes(EXISTING)
    options = ClipOptions(source=AutoClipSource(mode="offline", credentials=credentials()))
    if partial:
        with pytest.raises(EzvizUnsupportedMediaError):
            client.save_clip_with_options(CAMERA, output, options)
        assert output.read_bytes() == EXISTING
        assert calls == ["ecdh"]
    else:
        result = client.save_clip_with_options(CAMERA, output, options)
        assert output.read_bytes() == PAYLOAD
        assert result["source"] == "local-sdk"
        assert calls == ["ecdh", "legacy"]
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("after_packet", [False, True])
def test_live_offline_mismatch_before_output_only_and_cleanup(
    monkeypatch, after_packet: bool
) -> None:
    monkeypatch.setattr(stream_selection, "fresh_receiver_port", lambda: 12345)
    calls: list[str] = []
    streams: list[Any] = []

    class Stream:
        supports_startup_deadline_iter_packets = True
        closed = False

        def __init__(self, kind):
            self.kind = kind
            streams.append(self)

        def start(self, **kwargs):
            assert kwargs["deadline"] is not None

        def close(self):
            self.closed = True

        def iter_packets(self, **kwargs):
            if self.kind == "ecdh":
                if after_packet:
                    yield local_stream_ecdh.EzvizLocalSdkEcdhStreamPacket(channel=1, body=PAYLOAD)
                raise EzvizUnsupportedMediaError(
                    "legacy", source="local-sdk-ecdh", reason="protocol_mismatch"
                )
            yield EzvizLocalStreamPacket(channel=1, length=len(PAYLOAD), body=PAYLOAD)

    def open_ecdh(*args, **kwargs):
        calls.append("ecdh")
        return Stream("ecdh")

    def open_legacy(*args, **kwargs):
        assert kwargs["receiver_port"] == kwargs["receiver_ex_port"] == 12345
        calls.append("legacy")
        return Stream("legacy")

    monkeypatch.setattr(stream_selection, "open_local_sdk_ecdh_stream_from_client", open_ecdh)
    monkeypatch.setattr(stream_selection, "open_local_sdk_stream_from_client", open_legacy)
    stream = stream_selection.AutoMediaStream(
        NoCloudClient(), CAMERA, AutoClipSource(mode="offline", credentials=credentials())
    )
    with stream:
        if after_packet:
            packets = stream.iter_media_packets(limits=CaptureLimits(duration_seconds=3))
            assert next(packets).body == PAYLOAD
            with pytest.raises(EzvizUnsupportedMediaError):
                next(packets)
            assert calls == ["ecdh"]
        else:
            assert [
                p.body for p in stream.iter_media_packets(limits=CaptureLimits(duration_seconds=3))
            ] == [PAYLOAD]
            assert calls == ["ecdh", "legacy"]
            assert stream.source_kind == "local-sdk"
    assert all(s.closed for s in streams)


def test_auto_clip_rejects_unbounded_capture_before_discovery(monkeypatch) -> None:
    client = EzvizClient()
    monkeypatch.setattr(client, "get_device_infos", fail)
    with pytest.raises(PyEzvizError, match="capture limit"):
        client.save_clip_with_options(
            CAMERA, BytesIO(), ClipOptions(source=AutoClipSource(), capture=CaptureLimits())
        )


def test_unknown_camera_metadata_does_not_attempt_cloud() -> None:
    class Client:
        def get_device_infos(self, serial):
            return {"OTHER": {"CONNECTION": {}}}

    with pytest.raises(PyEzvizError, match="not found"):
        select_stream_source(Client(), CAMERA, AutoClipSource())


def test_live_connection_fallback_shares_deadline_and_is_sanitized(monkeypatch) -> None:
    clock = [0.0]
    closed: list[str] = []
    durations: list[float] = []

    class Local:
        def start(self, **kwargs):
            assert kwargs["deadline"] == 10
            clock[0] = 3.0
            raise TimeoutError("LAN connect")

        def close(self):
            closed.append("local")

    class Cloud:
        def start(self, **kwargs):
            assert kwargs["deadline"] == 10

        def close(self):
            closed.append("cloud")

    class Adapter:
        def iter_media_packets(self, *, limits, monotonic):
            durations.append(limits.duration_seconds)
            yield MediaPacket(PAYLOAD, MediaPacketMetadata(source="cloud_vtm"))

    monkeypatch.setattr(
        stream_selection, "open_local_sdk_ecdh_stream_from_client", lambda *a, **kw: Local()
    )
    monkeypatch.setattr(stream_selection, "open_cloud_stream", lambda *a, **kw: Cloud())
    monkeypatch.setattr(stream_selection, "vtm_media_packet_source", lambda stream: Adapter())
    source = AutoClipSource(
        credentials=credentials(), device={"deviceInfos": {"supportExt": {"519": "1"}}}
    )
    with stream_selection.AutoMediaStream(NoCloudClient(), CAMERA, source) as stream:
        assert [
            p.body
            for p in stream.iter_media_packets(
                limits=CaptureLimits(duration_seconds=10), monotonic=lambda: clock[0]
            )
        ] == [PAYLOAD]
        assert stream.source_kind == "cloud"
    assert durations == [7.0]
    assert closed == ["local", "cloud"]


@pytest.mark.parametrize("partial", [False, True])
def test_auto_clip_connection_fallback_only_before_staged_bytes(monkeypatch, partial: bool) -> None:
    client = EzvizClient()
    called: list[str] = []

    def local(serial, output, **kwargs):
        called.append("local")
        if partial:
            output.write(PAYLOAD)
        raise TimeoutError("LAN unavailable")

    def cloud(serial, output, **kwargs):
        called.append("cloud")
        assert kwargs["capture_deadline"] is not None
        output.write(PAYLOAD)
        return {"ok": True, "source": "cloud", "format": "mpegts"}

    monkeypatch.setattr(client, "_save_local_sdk_ecdh_clip", local)
    monkeypatch.setattr(client, "_save_cloud_clip", cloud)
    output = BytesIO()
    options = ClipOptions(source=AutoClipSource(credentials=credentials(), device={}))
    if partial:
        with pytest.raises(TimeoutError):
            client.save_clip_with_options(CAMERA, output, options)
        assert not output.getvalue()
        assert called == ["local"]
    else:
        result = client.save_clip_with_options(CAMERA, output, options)
        assert output.getvalue() == PAYLOAD
        assert result["source"] == "cloud"
        assert result["content_type"] == "video/mp2t"
        assert called == ["local", "cloud"]


def test_live_close_cancels_transport_and_prevents_reuse(monkeypatch) -> None:
    closed: list[bool] = []

    class Stream:
        def start(self, **kwargs):
            pass

        def close(self):
            closed.append(True)

        def iter_packets(self, **kwargs):
            while True:
                yield local_stream_ecdh.EzvizLocalSdkEcdhStreamPacket(channel=1, body=PAYLOAD)

    monkeypatch.setattr(
        stream_selection, "open_local_sdk_ecdh_stream_from_client", lambda *a, **kw: Stream()
    )
    stream = stream_selection.AutoMediaStream(
        NoCloudClient(), CAMERA, AutoClipSource(mode="offline", credentials=credentials())
    )
    with stream:
        packets = stream.iter_media_packets()
        assert next(packets).body == PAYLOAD
        stream.close()
        assert list(packets) == []
    assert closed
    with pytest.raises(PyEzvizError, match="closed"):
        next(stream.iter_media_packets())


def test_auto_allocates_independent_ports_for_concurrent_cameras(monkeypatch) -> None:
    ports = iter([12345, 12346])
    monkeypatch.setattr(stream_selection, "fresh_receiver_port", lambda: next(ports))
    options = AutoClipSource(mode="offline", credentials=credentials())
    first = select_stream_source(NoCloudClient(), CAMERA, options)
    second = select_stream_source(NoCloudClient(), CAMERA, options)
    assert isinstance(first, LocalSdkEcdhClipSource)
    assert isinstance(second, LocalSdkEcdhClipSource)
    assert first.receiver_port != second.receiver_port
    explicit = select_stream_source(NoCloudClient(), CAMERA, AutoClipSource(
        mode="offline", credentials=credentials(), receiver_port=12347))
    assert isinstance(explicit, LocalSdkEcdhClipSource)
    assert explicit.receiver_port == 12347


@pytest.mark.parametrize("port", [None, 10101])
def test_auto_long_form_preserves_explicit_default_port(monkeypatch, port: int | None) -> None:
    client = EzvizClient()
    captured: list[ClipOptions] = []

    def capture(serial, output, options):
        captured.append(options)
        return {"ok": True}

    monkeypatch.setattr(client, "save_clip_with_options", capture)
    client.save_clip(CAMERA, BytesIO(), source="auto", local_sdk_ecdh_receiver_port=port)
    source = captured[0].source
    assert isinstance(source, AutoClipSource)
    assert source.receiver_port == port
