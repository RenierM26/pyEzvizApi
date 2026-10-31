"""Actual REST requests, cold reader serialization and finite native admission."""
import asyncio
from dataclasses import replace
from unittest.mock import patch

from aiohttp import web
from custom_components.ezviz_native.camera import NativeCamera
from custom_components.ezviz_native.config import load_settings
from custom_components.ezviz_native.const import DOMAIN
from custom_components.ezviz_native.relay import RelayError, SharedRelay
from custom_components.ezviz_native.route import Runtime
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from test_local_av_timeline import encode_three_track_ps
from test_native_integration import (
    data as data,  # noqa: PLC0414 - pytest fixture re-export
    path,
    route_client,
    runtime as runtime,  # noqa: PLC0414 - pytest fixture re-export
)
from test_native_stream import Source

from pyezvizapi.native_stream import NativeMpegTsStream


async def relay_server(aiohttp_client):
    streams = {"unrelated": ["rtsp://example.invalid/original"]}
    calls = []
    reject_delete = [False]
    reject_patch = [False]
    patch_gate = [None]

    async def api(request):
        calls.append((request.method, dict(request.query)))
        if request.method == "GET":
            return web.json_response(streams)
        if request.method == "PATCH":
            streams[request.query["name"]] = [request.query["src"]]
            if patch_gate[0] is not None:
                await patch_gate[0].wait()
            return web.Response(status=500 if reject_patch[0] else 200)
        if reject_delete[0]:
            return web.Response(status=500)
        streams.pop(request.query["src"], None)
        return web.Response()

    app = web.Application()
    app.router.add_route("*", "/api/streams", api)
    client = await aiohttp_client(app)
    relay = SharedRelay(client.session, client.server.port, 18554)
    return relay, streams, calls, reject_delete, reject_patch, patch_gate


async def test_cold_readers_lazy_single_registration_and_narrow_cleanup(aiohttp_client):
    relay, streams, calls, reject_delete, _, _ = await relay_server(aiohttp_client)
    assert calls == []
    urls = await asyncio.gather(*(relay.source("http://127.0.0.1/native?auth=private")
                                 for _ in range(8)))
    assert len(set(urls)) == 1
    assert urls[0].startswith("rtsp://127.0.0.1:18554/ezviz_native_upstream_")
    assert "auth" not in urls[0]
    assert [method for method, _ in calls] == ["GET", "PATCH"]
    reject_delete[0] = True
    assert not await relay.close()
    assert relay.name in streams
    with pytest.raises(RelayError, match="closing"):
        await relay.source("ignored")
    reject_delete[0] = False
    assert await relay.close()
    assert await relay.close()
    assert streams == {"unrelated": ["rtsp://example.invalid/original"]}
    assert calls[-1] == ("DELETE", {"src": relay.name})


async def test_uncertain_registration_is_not_retried_and_is_removed(aiohttp_client):
    relay, streams, calls, _, reject_patch, _ = await relay_server(aiohttp_client)
    reject_patch[0] = True
    with pytest.raises(RelayError, match="registration failed"):
        await relay.source("http://127.0.0.1/native?auth=private")
    assert relay.name in streams
    with pytest.raises(RelayError, match="uncertain"):
        await relay.source("ignored")
    assert sum(method == "PATCH" for method, _ in calls) == 1
    assert await relay.close()
    assert relay.name not in streams


async def test_cancelled_patch_retains_ownership_for_removal(aiohttp_client):
    relay, streams, _calls, _, _, patch_gate = await relay_server(aiohttp_client)
    patch_gate[0] = asyncio.Event()
    task = asyncio.create_task(relay.source("http://127.0.0.1/native?auth=private"))
    async with asyncio.timeout(3):
        while relay.name not in streams:
            await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    patch_gate[0].set()
    assert await relay.close()
    assert relay.name not in streams


async def test_collision_is_never_overwritten_or_removed(aiohttp_client):
    relay, streams, calls, _, _, _ = await relay_server(aiohttp_client)
    streams[relay.name] = ["existing"]
    with pytest.raises(RelayError, match="unavailable"):
        await relay.source("ignored")
    assert await relay.close()
    assert calls == [("GET", {})]
    assert streams[relay.name] == ["existing"]


@pytest.mark.parametrize("field,value", [("relay_api_port", 0), ("relay_api_port", True),
    ("relay_api_port", "1984"), ("relay_rtsp_port", 65536)])
def test_relay_ports_are_explicit_integers(data, field, value):
    with pytest.raises(ValueError):
        load_settings({**data, field: value})


async def test_relay_eof_retries_cannot_reacquire(hass, aiohttp_client, runtime, tmp_path):
    body = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    runtime.settings = replace(runtime.settings,
                               options=replace(runtime.settings.options, finite_source=True))
    owner = NativeMpegTsStream(lambda: Source(body), runtime.settings.options)
    relay, _, _, _, _, _ = await relay_server(aiohttp_client)
    runtime.relay = relay
    client, registry = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner) as factory:
        response = await client.get(path(runtime))
        assert response.status == 200
        assert response.headers["X-Stream-Finite"] == "1"
        assert response.headers["X-Stream-Retry"] == "never"
        assert await response.read()
        for _ in range(3):
            response = await client.get(path(runtime))
            assert response.status == 503
        assert factory.call_count == 1
    assert runtime.acquisition_attempts == 1
    assert runtime.retry_rejections == 3
    assert runtime.active is None
    assert await registry.close_entry("entry")


async def test_relay_failed_startup_consumes_attempt(hass, aiohttp_client, runtime):
    source = Source(b"bad PS")
    owner = NativeMpegTsStream(lambda: source, runtime.settings.options)
    relay, _, _, _, _, _ = await relay_server(aiohttp_client)
    runtime.relay = relay
    client, _ = await route_client(hass, aiohttp_client, runtime)
    with patch.object(Runtime, "make_owner", return_value=owner) as factory:
        assert (await client.get(path(runtime))).status == 502
        assert (await client.get(path(runtime))).status == 503
        assert factory.call_count == 1
    assert source.closed and runtime.active is None


async def test_registry_relay_removal_failure_retains_entry_for_recovery(
    hass, aiohttp_client, runtime,
):
    relay, streams, _, reject_delete, _, _ = await relay_server(aiohttp_client)
    runtime.relay = relay
    await relay.source("http://127.0.0.1/native?auth=private")
    _, registry = await route_client(hass, aiohttp_client, runtime)
    reject_delete[0] = True
    assert not await registry.close_entry("entry")
    assert registry.entries["entry"] is runtime and runtime.closing
    assert relay.name in streams
    reject_delete[0] = False
    assert await registry.close_entry("entry")
    assert relay.name not in streams


async def test_opt_in_entry_camera_and_unload_use_public_relay(hass, aiohttp_client, data):
    relay, streams, calls, _, _, _ = await relay_server(aiohttp_client)
    # The explicit operator port, not a private HA go2rtc runtime object.
    api_port = int(relay._api.split(":")[2].split("/")[0])  # noqa: SLF001 - local test server address
    entry = MockConfigEntry(domain=DOMAIN, title="Relay lens", data={
        **data, "relay_api_port": api_port, "relay_rtsp_port": 18554,
    })
    entry.add_to_hass(hass)
    with patch.object(Runtime, "make_owner", side_effect=AssertionError("acquisition")):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert calls == []  # Setup does not even register a relay stream.
        camera = NativeCamera(entry)
        camera.hass = hass
        urls = await asyncio.gather(*(camera.stream_source() for _ in range(8)))
        assert len(set(urls)) == 1 and urls[0].startswith("rtsp://127.0.0.1:18554/")
        assert entry.runtime_data.token not in urls[0]
        assert [method for method, _ in calls] == ["GET", "PATCH"]
        assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.entry_id not in hass.data[DOMAIN].entries
    assert set(streams) == {"unrelated"}


async def test_replaced_registration_is_not_removed(aiohttp_client):
    relay, streams, calls, _, _, _ = await relay_server(aiohttp_client)
    await relay.source("http://127.0.0.1/owned?auth=TEST_ONLY")
    streams[relay.name] = ["http://127.0.0.1:1/reassigned.ts"]
    assert not await relay.close()
    assert streams[relay.name] == ["http://127.0.0.1:1/reassigned.ts"]
    assert not any(method == "DELETE" for method, _ in calls)


@pytest.mark.parametrize("value", [
    {"producers": []},
    {"producers": [{"url": "http://127.0.0.1/owned?auth=***"}]},
    {"producers": [{"url": "http://127.0.0.1/owned?auth=TEST_ONLY"},
                   {"url": "http://127.0.0.1/extra"}]},
])
async def test_uncertain_inventory_is_not_removed(aiohttp_client, value):
    relay, streams, calls, _, _, _ = await relay_server(aiohttp_client)
    await relay.source("http://127.0.0.1/owned?auth=TEST_ONLY")
    streams[relay.name] = value
    assert not await relay.close()
    assert streams[relay.name] == value
    assert not any(method == "DELETE" for method, _ in calls)
