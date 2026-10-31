"""HA HTTP, camera and config-flow contracts, not mocked HA module imports."""
import asyncio
from dataclasses import replace
import json
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import ClientPayloadError, web
from aiohttp.test_utils import make_mocked_request
from custom_components.ezviz_native.camera import NativeCamera
from custom_components.ezviz_native.config import load_settings
from custom_components.ezviz_native.const import DOMAIN
from custom_components.ezviz_native.diagnostics import async_get_config_entry_diagnostics
from custom_components.ezviz_native.route import (
    NativeStreamView,
    Registry,
    Runtime,
    source_url,
)
from homeassistant.components.camera import CameraEntityFeature, DynamicStreamSettings
from homeassistant.components.http import ApiConfig
from homeassistant.components.stream import create_stream
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from test_local_av_timeline import encode_three_track_ps
from test_native_stream import Source, repeated_ps_packets

from pyezvizapi.client import EzvizClient
from pyezvizapi.native_stream import NativeMpegTsStream


@pytest.fixture
def data(tmp_path):
    path = tmp_path / "private.json"
    path.write_text(json.dumps({
        "serial": "CAMERA123", "endpoint": {"host": "192.0.2.10", "command_port": 8000},
        "cas": {"operation_code": "ABC1234", "key": "0123456789abcdef"},
        "media_key": "secret",
    }))
    return {"name": "Lens A", "credentials_path": str(path), "channel": 0,
            "video_id": 480, "audio_id": 448, "video_codec": "hevc", "nalu_header_size": 2}


@pytest.fixture
def runtime(data):
    return Runtime(load_settings(data), MagicMock(spec=EzvizClient))


async def route_client(hass, aiohttp_client, runtime):
    assert await async_setup_component(hass, "http", {})
    registry = Registry()
    registry.entries["entry"] = runtime
    hass.http.register_view(NativeStreamView(registry))
    client = await aiohttp_client(hass.http.app, server_kwargs={"handler_cancellation": True})
    return client, registry


def path(runtime):
    return f"/api/ezviz_native/entry/stream.ts?auth={runtime.token}"


async def test_flow_is_explicit_and_does_not_acquire(hass, data):
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        assert result["type"] == "form"
        with patch("custom_components.ezviz_native.async_setup_entry", return_value=True):
            result = await hass.config_entries.flow.async_configure(result["flow_id"], data)
        assert result["type"] == "create_entry"
        assert "media_key" not in result["data"]
        assert result["data"]["credentials_path"] == data["credentials_path"]


async def test_bad_file_is_not_unsupported_camera(hass, data):
    data["credentials_path"] = "/nonexistent/private.json"
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"}, data=data)
    assert result["errors"] == {"base": "invalid_settings"}


@pytest.mark.parametrize("field,value", [("channel", True), ("video_id", 999),
    ("audio_id", -2), ("nalu_header_size", 0), ("video_codec", "vp9")])
def test_private_settings_reject_invalid_mapping(data, field, value):
    data[field] = value
    with pytest.raises(ValueError):
        load_settings(data)


async def test_camera_is_lazy_and_source_contains_no_camera_secret(hass, data, runtime):
    entry = MockConfigEntry(domain=DOMAIN, title="Lens A", data=data)
    entry.runtime_data = runtime
    camera = NativeCamera(entry)
    camera.hass = hass
    hass.config.api = ApiConfig("127.0.0.1", "127.0.0.1", 8123, False)
    hass.http = MagicMock(server_port=8123, server_host=None)
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        url = await camera.stream_source()
        assert url.startswith("http://127.0.0.1:8123/")
        assert "auth=" in url
        assert all(s not in url for s in ("CAMERA123", "192.0.2.10", "secret", "private.json"))
        assert camera.supported_features == CameraEntityFeature.STREAM
        assert await camera.async_camera_image() is None
        runtime.closing = True
        assert await camera.stream_source() is None
    hass.config.api.use_ssl = True
    with pytest.raises(ValueError):
        source_url(hass, entry.entry_id, runtime)


async def test_auth_precedes_factory(hass, aiohttp_client, runtime):
    client, registry = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        for url in ("/api/ezviz_native/entry/stream.ts", path(runtime)+"bad",
                    "/api/ezviz_native/missing/stream.ts?auth="+runtime.token,
                    "/api/ezviz_native/entry/stream.ts?auth=\u2603"):
            response = await client.get(url)
            assert response.status == 403
        response = await client.head(path(runtime))
        assert response.status == 405
    assert registry.entries["entry"].active is None


@pytest.mark.parametrize("peer", ["192.0.2.1", "::ffff:192.0.2.1"])
async def test_socket_peer_not_forwarded_ip(runtime, peer):
    registry = Registry()
    registry.entries["entry"] = runtime
    transport = MagicMock()
    transport.get_extra_info.return_value = (peer, 1234)
    request = make_mocked_request("GET", path(runtime),
                                 headers={"X-Forwarded-For": "127.0.0.1"}, transport=transport)
    with pytest.raises(web.HTTPForbidden):
        await NativeStreamView(registry).get(request, "entry")


async def test_actual_native_copy_over_ha_http(hass, aiohttp_client, runtime, tmp_path):
    data = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    source = Source(data)
    options = replace(runtime.settings.options, finite_source=True)
    owner = NativeMpegTsStream(lambda: source, options)
    expected = NativeMpegTsStream(lambda: Source(data), options)
    assert owner.source_clock is None  # No factory call or fixture-derived guess.
    expected_body = await asyncio.to_thread(lambda: b"".join(expected))
    expected.close()
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        response = await client.get(path(runtime))
        assert response.status == 200
        assert response.headers["Content-Type"] == "video/mp2t"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Stream-Retry"] == "default"
        assert owner.source_clock is not None
        assert response.headers["X-Stream-Clock-Origin-90k"] == str(
            owner.source_clock.origin_90k
        )
        actual = await response.read()
    assert actual == expected_body
    await hass.async_block_till_done()
    assert runtime.active is None
    assert source.closed and source.iterator_closed.is_set()
    receipt = runtime.last_receipt
    assert receipt["http_write_bytes"] == len(actual)
    assert receipt["source"]["worker_joined"]
    assert receipt["source"]["owned_output_bytes"] == 0
    assert not receipt["ha_verified"]


async def test_failed_startup_is_502_not_clean_eof(hass, aiohttp_client, runtime):
    source = Source(b"bad PS")
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        response = await client.get(path(runtime))
        assert response.status == 502
    assert source.closed and runtime.active is None


async def test_duplicate_and_closing_do_not_acquire(hass, aiohttp_client, runtime):
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        runtime.active = MagicMock()
        assert (await client.get(path(runtime))).status == 429
        runtime.active = None
        runtime.closing = True
        assert (await client.get(path(runtime))).status == 503


async def test_unload_joins_blocked_startup_and_revokes(hass, aiohttp_client, runtime):
    source = Source(block=True)
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    client, registry = await route_client(hass, aiohttp_client, runtime)
    old_path = path(runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        pending = asyncio.create_task(client.get(old_path))
        assert await asyncio.to_thread(source.entered.wait, 2)
        assert await registry.close_entry("entry")
        await asyncio.gather(pending, return_exceptions=True)
    assert registry.entries["entry"].closing
    assert registry.entries["entry"].active is None
    assert owner.receipt["worker_joined"] and owner.receipt["cancel_joined"]
    assert source.closed and source.iterator_closed.is_set()
    assert (await client.get(old_path)).status == 403


async def test_full_entry_setup_and_unload_is_acquisition_free(hass, data):
    entry = MockConfigEntry(domain=DOMAIN, title="Lens A", data=data)
    entry.add_to_hass(hass)
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        state = hass.states.get("camera.lens_a")
        assert state is not None
        assert state.attributes["supported_features"] == CameraEntityFeature.STREAM
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert entry.entry_id not in hass.data[DOMAIN].entries


@pytest.mark.parametrize("codec", ["h264", "hevc"])
async def test_real_ha_stream_worker_ingests_native_http(hass, aiohttp_client, runtime, tmp_path, codec):
    def encoded_sample():
        if codec == "hevc":
            return encode_three_track_ps(tmp_path).read_bytes()
        data = subprocess.run([
            "ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=64x48:rate=10",
            "-f", "lavfi", "-i", "color=red:size=64x48:rate=10",
            "-f", "lavfi", "-i", "sine=sample_rate=16000", "-t", "0.6",
            "-map", "0:v", "-map", "1:v", "-map", "2:a", "-c:v", "libx264",
            "-threads:v", "1", "-bf", "0", "-c:a", "aac", "-f", "mpegts", "pipe:1",
        ], check=True, capture_output=True, timeout=15).stdout
        return b"".join(repeated_ps_packets(data, 1, codec=codec))
    sample = await asyncio.to_thread(encoded_sample)
    runtime.settings = replace(runtime.settings,
        options=replace(runtime.settings.options, video_codec=codec))
    source = Source(bodies=repeated_ps_packets(sample, 20, codec=codec), block=True)
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    assert await async_setup_component(hass, "stream", {"stream": {"ll_hls": False}})
    client, registry = await route_client(hass, aiohttp_client, runtime)
    url = str(client.make_url(path(runtime)))
    stream = create_stream(hass, url, {}, DynamicStreamSettings(), stream_label="native-validation")
    provider = stream.add_provider("hls")
    stream.endpoint_url("hls")
    with patch.object(Runtime, "make_owner", return_value=owner):
        try:
            await stream.start()
            async with asyncio.timeout(15):
                while provider.last_segment is None:
                    await asyncio.sleep(0.02)
            segment = provider.last_segment
            assert segment.init and segment.parts
            video_tags = (b"hvc1", b"hev1") if codec == "hevc" else (b"avc1",)
            audio_tag = b"mp4a"
            assert any(tag in segment.init for tag in video_tags)
            assert audio_tag in segment.init
        finally:
            assert await registry.close_entry("entry")
            await stream.remove_provider(provider)
            await stream.stop()
    assert owner.receipt["worker_joined"] and source.closed


async def test_midstream_failure_aborts_http_and_joins(hass, aiohttp_client, runtime, tmp_path):
    sample = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    source = Source(bodies=repeated_ps_packets(sample, 20), error=ValueError("private details"))
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        response = await client.get(path(runtime))
        assert response.status == 200
        with pytest.raises(ClientPayloadError):
            await response.read()
    await hass.async_block_till_done()
    assert source.closed and runtime.active is None
    assert owner.receipt["worker_joined"] and owner.receipt["error_type"] == "ValueError"
    assert runtime.last_receipt["http_write_bytes"] > 0


async def test_failed_cleanup_retains_admission_and_explicit_recovery(hass, aiohttp_client, runtime):
    source = Source(block=True, cooperate=False)
    options = replace(runtime.settings.options, close_timeout=0.03)
    owner = NativeMpegTsStream(lambda: source, options)
    client, registry = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        pending = asyncio.create_task(client.get(path(runtime)))
        assert await asyncio.to_thread(source.entered.wait, 2)
        assert not await registry.close_entry("entry")
        await asyncio.gather(pending, return_exceptions=True)
        assert runtime.active is not None
        assert owner.receipt["shutdown_timed_out"]
        assert not owner.receipt["worker_joined"]
        source.cooperate = True
        source.release.set()
        assert await registry.close_entry("entry")
    assert runtime.active is None and source.closed
    assert owner.receipt["worker_joined"] and owner.receipt["cancel_joined"]


async def test_disconnect_during_startup_closes_source(hass, aiohttp_client, runtime):
    source = Source(block=True)
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner):
        pending = asyncio.create_task(client.get(path(runtime)))
        assert await asyncio.to_thread(source.entered.wait, 2)
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        async with asyncio.timeout(2):
            while runtime.active is not None:
                await asyncio.sleep(0.01)
    assert source.closed and source.iterator_closed.is_set()
    assert owner.receipt["worker_joined"] and owner.receipt["cancel_joined"]


async def test_global_admission_limit(hass, aiohttp_client, runtime):
    client, registry = await route_client(hass, aiohttp_client, runtime)
    for index in range(4):
        other = Runtime(runtime.settings, runtime.client)
        other.active = MagicMock()
        registry.entries[str(index)] = other
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        assert (await client.get(path(runtime))).status == 429


@pytest.mark.parametrize("failure", [TimeoutError(), ConnectionResetError("private"), None])
async def test_write_failure_closes_without_leaking_source_error(runtime, tmp_path, failure, monkeypatch):
    sample = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    source = Source(sample)
    owner = NativeMpegTsStream(lambda: source, replace(runtime.settings.options, finite_source=True))
    registry = Registry()
    registry.entries["entry"] = runtime
    transport = MagicMock()
    transport.get_extra_info.return_value = ("127.0.0.1", 1234)
    request = make_mocked_request("GET", path(runtime), transport=transport)
    response = MagicMock(prepared=True)
    async def blocked_write(_chunk):
        await asyncio.sleep(10)
    monkeypatch.setattr("custom_components.ezviz_native.route.WRITE_TIMEOUT", 0.01)
    response.write = AsyncMock(side_effect=blocked_write if failure is None else failure)
    response.write_eof = AsyncMock()
    with patch.object(Runtime, "make_owner", return_value=owner), patch(
        "custom_components.ezviz_native.route.web.StreamResponse", return_value=response
    ), pytest.raises(ConnectionResetError, match="Native source failed"):
        await NativeStreamView(registry).get(request, "entry")
    response.write_eof.assert_not_called()
    transport.close.assert_called_once()
    assert source.closed and runtime.active is None
    assert owner.receipt["worker_joined"] and owner.receipt["owned_output_bytes"] == 0


def test_runtime_composes_lazy_offline_owner(runtime):
    owner = runtime.make_owner()
    runtime.client.open_stream.assert_not_called()
    owner.close()
    runtime.client.open_stream.assert_not_called()


async def test_camera_remove_stops_preloaded_ha_providers(hass, runtime, data):
    entry = MockConfigEntry(domain=DOMAIN, title="Lens A", data=data)
    entry.runtime_data = runtime
    camera = NativeCamera(entry)
    camera.hass = hass
    provider = MagicMock()
    stream = MagicMock()
    stream.dynamic_stream_settings.preload_stream = True
    stream.outputs.return_value = {"hls": provider}
    stream.remove_provider = AsyncMock()
    stream.stop = AsyncMock()
    camera.stream = stream
    await camera.async_will_remove_from_hass()
    assert not stream.dynamic_stream_settings.preload_stream
    stream.remove_provider.assert_awaited_once_with(provider)
    stream.stop.assert_awaited_once()


async def test_diagnostics_exclude_private_file_and_credentials(hass, runtime, data):
    entry = MockConfigEntry(domain=DOMAIN, title="Lens A", data=data)
    entry.runtime_data = runtime
    report = await async_get_config_entry_diagnostics(hass, entry)
    serialized = json.dumps(report)
    assert not report["ha_frontend_verified"]
    assert all(value not in serialized for value in (
        data["credentials_path"], runtime.token, "CAMERA123", "secret", "192.0.2.10"))


async def test_topology_rejected_without_acquisition(hass, runtime):
    hass.config.api = ApiConfig("127.0.0.1", "192.0.2.1", 8123, False)
    hass.http = MagicMock(server_port=8123, server_host=["192.0.2.1"])
    with pytest.raises(ValueError, match="IPv4 loopback"):
        source_url(hass, "entry", runtime)
    runtime.client.open_stream.assert_not_called()


def test_credential_document_is_bounded(data):
    with open(data["credentials_path"], "wb") as target:
        target.write(b" " * 65537)
    with pytest.raises(ValueError, match="limit"):
        load_settings(data)


@pytest.mark.parametrize("value", [True, 1, "true"])
def test_source_clock_requires_explicit_relay(data, value):
    data["relay_source_clock"] = value
    with pytest.raises(ValueError):
        load_settings(data)


def test_source_clock_is_opt_in(data):
    assert not load_settings(data).relay_source_clock
    data.update(relay_api_port=1984, relay_source_clock=True)
    assert load_settings(data).relay_source_clock
