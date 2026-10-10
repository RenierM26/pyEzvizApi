"""Discovery reuse is bounded, credential-scoped and cloud-free."""

from dataclasses import asdict, replace
from io import BytesIO
from types import SimpleNamespace

import pytest
from test_stream_header import header
from test_stream_selection import CAMERA, PAYLOAD, NoCloudClient, credentials

from pyezvizapi import EzvizClient, client as client_module, stream_selection
from pyezvizapi.clip import AutoClipSource, ClipOptions
from pyezvizapi.exceptions import EzvizNoMediaError, EzvizUnsupportedMediaError, PyEzvizError
from pyezvizapi.local_stream_transport import EzvizLocalStreamPacket
from pyezvizapi.media import CaptureLimits
from pyezvizapi.stream_discovery import LocalStreamDiscovery, LocalStreamDiscoveryCache
from pyezvizapi.stream_header import parse_ezviz_stream_header
from pyezvizapi.stream_selection import AutoMediaStream, select_stream_source


@pytest.mark.parametrize(("kwargs"), [{"ttl": 0}, {"ttl": float("inf")}, {"max_entries": 0}, {"max_entries": True}])
def test_cache_validation(kwargs):
    with pytest.raises(PyEzvizError):
        LocalStreamDiscoveryCache(**kwargs)


def test_ttl_reads_do_not_extend_freshness_and_lru_capacity():
    now = [0.0]
    cache = LocalStreamDiscoveryCache(ttl=10, max_entries=2, monotonic=lambda: now[0])
    entry = LocalStreamDiscovery("local-sdk")
    cache.remember("a", entry)
    cache.remember("b", entry)
    now[0] = 9
    assert cache.get("a") == entry
    cache.remember("c", entry)
    assert cache.get("b") is None
    now[0] = 10
    assert cache.get("a") is None
    cache.invalidate()
    assert cache.get("c") is None


def successful_legacy(monkeypatch, *, fail_after=False, malformed=False):
    calls: list[str] = []
    class Bootstrap:
        @property
        def stream_header(self):
            if malformed:
                raise PyEzvizError("Malformed header")
    class Stream:
        supports_startup_deadline_iter_packets = True
        bootstrap = Bootstrap()
        def start(self, **_kwargs):
            pass
        def close(self):
            pass
        def iter_packets(self, **_kwargs):
            yield EzvizLocalStreamPacket(channel=1, length=len(PAYLOAD), body=PAYLOAD)
            if fail_after:
                raise PyEzvizError("Read failed")
    def ecdh(*_args, **_kwargs):
        calls.append("ecdh")
        raise EzvizUnsupportedMediaError("legacy", source="local-sdk-ecdh", reason="protocol_mismatch")
    def legacy(*_args, **_kwargs):
        calls.append("legacy")
        return Stream()
    monkeypatch.setattr(stream_selection, "open_local_sdk_ecdh_stream_from_client", ecdh)
    monkeypatch.setattr(stream_selection, "open_local_sdk_stream_from_client", legacy)
    return calls


def play(options, *, channel=1):
    with AutoMediaStream(NoCloudClient(), CAMERA, options, channel=channel) as stream:
        assert [p.body for p in stream.iter_media_packets(limits=CaptureLimits(duration_seconds=2))] == [PAYLOAD]
        return stream.discovery


def test_auto_reuses_successful_transport_not_account_or_session_auth(monkeypatch):
    calls = successful_legacy(monkeypatch)
    cache = LocalStreamDiscoveryCache()
    options = AutoClipSource(mode="offline", credentials=credentials(), discovery_cache=cache)
    assert play(options).source_kind == "local-sdk"
    assert calls == ["ecdh", "legacy"]
    assert play(options).source_kind == "local-sdk"
    assert calls == ["ecdh", "legacy", "legacy"]
    assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk"
    assert select_stream_source(NoCloudClient(), CAMERA, options, channel=2).kind == "local-sdk-ecdh"
    assert select_stream_source(NoCloudClient(), CAMERA, replace(options, discovery_generation="new")).kind == "local-sdk-ecdh"
    assert select_stream_source(NoCloudClient(), CAMERA, replace(options, credentials=replace(credentials(), media_key="changed"))).kind == "local-sdk-ecdh"
    assert select_stream_source(NoCloudClient(), CAMERA, replace(options, credentials=replace(credentials(), endpoint=replace(credentials().endpoint, host="192.0.2.20")))).kind == "local-sdk-ecdh"
    cache.invalidate()
    assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk-ecdh"


def test_error_after_output_invalidates_without_switching(monkeypatch):
    calls = successful_legacy(monkeypatch, fail_after=True)
    options = AutoClipSource(mode="offline", credentials=credentials(), discovery_cache=LocalStreamDiscoveryCache())
    with AutoMediaStream(NoCloudClient(), CAMERA, options) as stream:
        packets = stream.iter_media_packets(limits=CaptureLimits(duration_seconds=2))
        assert next(packets).body == PAYLOAD
        with pytest.raises(PyEzvizError, match="Read failed"):
            next(packets)
    assert calls == ["ecdh", "legacy"]
    assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk-ecdh"


def test_malformed_optional_header_not_cached_but_playable(monkeypatch):
    successful_legacy(monkeypatch, malformed=True)
    options = AutoClipSource(mode="offline", credentials=credentials(), discovery_cache=LocalStreamDiscoveryCache())
    assert play(options).stream_header is None
    assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk-ecdh"


def test_fresh_negotiated_header_replaces_cached_metadata(monkeypatch):
    seen = [parse_ezviz_stream_header(header(video=5)), parse_ezviz_stream_header(header(video=0x100))]
    calls: list[str] = []
    class Stream:
        supports_startup_deadline_iter_packets = True
        def __init__(self):
            self.bootstrap = SimpleNamespace(stream_header=seen[len(calls)])
            calls.append("start")
        def start(self, **_kwargs):
            pass
        def close(self):
            pass
        def iter_packets(self, **_kwargs):
            yield EzvizLocalStreamPacket(channel=1, length=len(PAYLOAD), body=PAYLOAD)
    monkeypatch.setattr(stream_selection, "open_local_sdk_stream_from_client", lambda *_a, **_kw: Stream())
    options = AutoClipSource(mode="offline", credentials=credentials(), device={"deviceInfos": {"supportExt": {"other": "1"}}}, discovery_cache=LocalStreamDiscoveryCache())
    first = play(options)
    second = play(options)
    assert first.stream_header.video_codec == "hevc"
    assert second.stream_header.video_codec == "h264"
    assert "operation" not in str(asdict(second))
    assert "media-key" not in repr(second)


def test_fresh_account_capability_change_invalidates_previous_hint():
    support = {"other": "1"}
    class Client(NoCloudClient):
        def get_device_infos(self, _serial):
            return {"deviceInfos": {"supportExt": support}}
    cache = LocalStreamDiscoveryCache()
    options = AutoClipSource(credentials=credentials(), discovery_cache=cache)
    keys: list[str] = []
    assert select_stream_source(Client(), CAMERA, options, _discovery_keys=keys).kind == "local-sdk"
    cache.remember(keys[0], LocalStreamDiscovery("local-sdk"))
    support = {"519": "1"}
    assert select_stream_source(Client(), CAMERA, options).kind == "local-sdk-ecdh"


def test_expired_mru_never_evicts_live_lru():
    now = [0.0]
    cache = LocalStreamDiscoveryCache(ttl=10, max_entries=2, monotonic=lambda: now[0])
    entry = LocalStreamDiscovery("local-sdk")
    cache.remember("expiring", entry)
    now[0] = 4
    cache.remember("live", entry)
    now[0] = 9
    assert cache.get("expiring") == entry
    now[0] = 11
    cache.remember("new", entry)
    assert cache.get("live") == entry
    assert cache.get("expiring") is None
    assert cache.get("new") == entry


def test_clip_failure_invalidates_hint_learned_by_live_stream(monkeypatch):
    successful_legacy(monkeypatch)
    cache = LocalStreamDiscoveryCache()
    options = AutoClipSource(mode="offline", credentials=credentials(), discovery_cache=cache)
    play(options)
    assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk"
    def no_media(*_args, **_kwargs):
        raise EzvizNoMediaError("no packets")
    monkeypatch.setattr(client_module, "copy_local_sdk_stream_from_client", no_media)
    client = EzvizClient()
    try:
        with pytest.raises(EzvizNoMediaError, match="no packets"):
            client.save_clip_with_options(CAMERA, BytesIO(), ClipOptions(source=options, capture=CaptureLimits(duration_seconds=2)))
        assert select_stream_source(NoCloudClient(), CAMERA, options).kind == "local-sdk-ecdh"
    finally:
        client.close_session()
