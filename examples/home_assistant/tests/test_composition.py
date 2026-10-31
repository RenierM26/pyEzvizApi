"""Real HA entries, one physical allocator, and whole-group recovery ownership."""
import asyncio
from dataclasses import replace
import json
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from custom_components.ezviz_native.admission import Admission
from custom_components.ezviz_native.config import load_settings
from custom_components.ezviz_native.const import DOMAIN
from custom_components.ezviz_native.diagnostics import async_get_config_entry_diagnostics
from custom_components.ezviz_native.entry_runtime import GroupEntry, IntegrationRegistry
from custom_components.ezviz_native.group import GroupIdentity, GroupRegistry
from custom_components.ezviz_native.relay import RelayError
from custom_components.ezviz_native.route import Runtime, physical_key
from homeassistant.components.camera.const import DATA_COMPONENT
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from test_local_av_timeline import encode_three_track_ps
from test_native_integration import data as data, runtime as runtime  # noqa: PLC0414
from test_native_stream import Source, options

from pyezvizapi.native_stream import NativeMpegTsStream


def grouped(data, port=1984):
    return {**data, "relay_api_port": port, "relay_rtsp_port": 18554,
            "relay_source_clock": True, "relay_atomic_ownership": True,
            "group_profile": "verified-source-profile", "credential_revision": "opaque-generation-1",
            "lenses": [{"lens_id": "telephoto", "name": "Telephoto", "video_id": 481,
                        "audio_id": 448}]}


async def atomic_relay(aiohttp_client):
    records = {"unrelated": ("other-token", "rtsp://example.invalid/original")}
    reject = [False]
    calls = []
    headers = {"X-Stream-Ownership": "runtime-token-v1"}

    async def api(request):
        calls.append(request.method)
        if request.method == "GET":
            return web.json_response({"contract": "runtime-token-v1", "features": [
                "runtime-token-v1", "source-clock-v1", "no-retry-v1",
            ]}, headers=headers)
        name = request.query["name"]
        token = request.headers.get("Authorization")
        if request.method == "POST":
            if name in records:
                return web.Response(status=409, headers=headers)
            records[name] = token, (await request.post())["src"]
            return web.Response(status=201, headers=headers)
        if reject[0] or (name in records and records[name][0] != token):
            return web.Response(status=409, headers=headers)
        records.pop(name, None)
        return web.Response(status=204, headers=headers)

    app = web.Application()
    app.router.add_route("*", "/api/streams/owned", api)
    client = await aiohttp_client(app)
    return client.server.port, records, reject, calls


async def setup(hass, aiohttp_client, data):
    port, records, reject, calls = await atomic_relay(aiohttp_client)
    assert await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(domain=DOMAIN, title="Primary", data=grouped(data, port))
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    client = await aiohttp_client(hass.http.app, server_kwargs={"handler_cancellation": True})
    return entry, client, records, reject, calls


def path(runtime, key):
    lens = runtime.lenses[key]
    return f"/api/ezviz_native_group/{lens.member}/stream.ts?auth={lens.token}"


def cameras(hass):
    component = hass.data[DATA_COMPONENT]
    return [component.get_entity(s.entity_id) for s in hass.states.async_all("camera")]


async def consume(client, runtime, key):
    response = await client.get(path(runtime, key))
    assert response.status == 200
    return await response.read()


async def settled(runtime):
    async with asyncio.timeout(3):
        while runtime.group.reserved:
            await asyncio.sleep(0.01)


@pytest.fixture
def clear_finite(monkeypatch):
    original, declare = load_settings, GroupRegistry.declare

    def finite(values):
        result = original(values)
        return replace(result, options=replace(result.options, finite_source=True))

    def clear_group(self, *args, **kwargs):
        kwargs["media_key"] = None  # Generated test PS is already clear.
        return declare(self, *args, **kwargs)

    monkeypatch.setattr("custom_components.ezviz_native.load_settings", finite)
    monkeypatch.setattr(GroupRegistry, "declare", clear_group)


async def test_group_setup_entities_and_source_registration_never_acquire(hass, aiohttp_client, data):
    with patch.object(GroupEntry, "make_source", side_effect=AssertionError("No preview")):
        entry, _, records, _, calls = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        assert len(cameras(hass)) == 2
        assert len(hass.states.async_all("button")) == len(hass.states.async_all("sensor")) == 1
        assert runtime.group.attempts == 0 and hass.data[DOMAIN].admission.active == 0
        assert calls == []
        urls = await asyncio.gather(*(camera.stream_source() for camera in cameras(hass)))
        assert len(set(urls)) == 2 and all(url.startswith("rtsp://127.0.0.1:") for url in urls)
        assert all("auth=" not in url for url in urls)
        assert runtime.group.attempts == 0 and len(records) == 3
        assert sorted(calls) == ["GET", "GET", "POST", "POST"]
        assert all(await asyncio.gather(*(camera.async_camera_image() for camera in cameras(hass)))) is False
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert list(records) == ["unrelated"]


async def test_button_prepare_revokes_every_lens_stops_cache_and_reopens_lazily(
    hass, aiohttp_client, data, tmp_path, clear_finite,
):
    payload = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    sources = []

    def factory(_runtime):
        source = Source(payload)
        sources.append(source)
        return source

    with patch.object(GroupEntry, "make_source", factory):
        entry, client, records, _, _ = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        entities = cameras(hass)
        await asyncio.gather(*(camera.stream_source() for camera in entities))
        old_names = {lens.relay.name for lens in runtime.lenses.values()}
        old_paths = [path(runtime, key) for key in runtime.lenses]
        first = await asyncio.gather(*(consume(client, runtime, key) for key in runtime.lenses))
        await settled(runtime)
        assert len(sources) == 1 and runtime.group.attempts == 1
        assert hass.data[DOMAIN].admission.active == 0
        registry = er.async_get(hass)
        identities = {s.entity_id: registry.async_get(s.entity_id).unique_id
                      for s in hass.states.async_all("camera")}
        assert set(identities.values()) == {entry.entry_id, entry.entry_id + "_telephoto"}
        cached = []
        for camera in entities:
            stream = await camera.async_create_stream()
            assert stream is None  # Exhausted source cannot re-enter through cached HLS.
            stream = MagicMock()
            stream.outputs.return_value = {"hls": MagicMock()}
            stream.remove_provider = AsyncMock()
            stream.stop = AsyncMock()
            stream.dynamic_stream_settings.preload_stream = True
            camera.stream = stream
            cached.append(stream)
        button_id = hass.states.async_all("button")[0].entity_id
        await hass.services.async_call("button", "press", {"entity_id": button_id}, blocking=True)
        assert entry.runtime_data is runtime  # Recovery is in-place, not identity churn.
        assert len(sources) == 1 and runtime.group.attempts == 0
        assert not runtime.group.paused and not runtime.recovery_pending
        assert list(records) == ["unrelated"]
        assert not old_names.intersection(lens.relay.name for lens in runtime.lenses.values())
        for old in old_paths:
            assert (await client.get(old)).status == 403
        for camera, stream in zip(entities, cached, strict=True):
            assert camera.stream is None
            assert not stream.dynamic_stream_settings.preload_stream
            stream.stop.assert_awaited_once()
            stream.remove_provider.assert_awaited_once()
        assert identities == {s.entity_id: registry.async_get(s.entity_id).unique_id
                              for s in hass.states.async_all("camera")}
        assert await asyncio.gather(*(consume(client, runtime, key) for key in runtime.lenses)) == first
        await settled(runtime)
        assert len(sources) == 2
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert all(s.closed for s in sources) and hass.data[DOMAIN].admission.active == 0


async def test_unknown_relay_removal_retains_recovery_handles_and_blocks_new_source(
    hass, aiohttp_client, data,
):
    entry, client, records, reject, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    await asyncio.gather(*(camera.stream_source() for camera in cameras(hass)))
    old_relays = [lens.relay for lens in runtime.lenses.values()]
    runtime.group.attempts = 1  # No preview: exercise explicit post-attempt recovery only.
    reject[0] = True
    assert not await runtime.prepare()
    assert runtime.recovery_pending and runtime.group.paused
    assert old_relays == [lens.relay for lens in runtime.lenses.values()]
    assert (await client.get(path(runtime, "primary"))).status == 503
    assert runtime.group.attempts == 1 and len(records) == 3
    reject[0] = False
    assert await runtime.prepare()
    assert runtime.group.attempts == 0 and list(records) == ["unrelated"]
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_unload_retries_uncertain_relay_after_physical_group_is_removed(
    hass, aiohttp_client, data,
):
    entry, _, records, reject, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    await asyncio.gather(*(camera.stream_source() for camera in cameras(hass)))
    reject[0] = True
    assert not await hass.config_entries.async_unload(entry.entry_id)
    assert hass.data[DOMAIN].group_entries[entry.entry_id] is runtime
    assert runtime.group.joined and runtime.client is not None
    assert runtime.group.identity.physical not in hass.data[DOMAIN].groups.groups
    assert entry.state is ConfigEntryState.FAILED_UNLOAD
    # HA correctly makes failed unload non-recoverable. Do not patch its private
    # state to pretend reload works; retained cleanup is retried at HA shutdown.
    reject[0] = False
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()
    assert list(records) == ["unrelated"]
    assert all(await asyncio.gather(*(lens.relay.close() for lens in runtime.lenses.values())))


async def test_shared_budget_excludes_same_physical_source_between_both_routes(runtime):
    registry = IntegrationRegistry()
    registry.entries["old"] = runtime
    task = asyncio.current_task()
    owner = NativeMpegTsStream(lambda: pytest.fail("not acquired"), runtime.settings.options)
    with patch.object(Runtime, "make_owner", return_value=owner):
        session = registry.admit(runtime, task)
    group = registry.groups.declare(GroupIdentity(physical_key(runtime.settings), "verified", "rev"),
                                     {"child": options()}, lambda: pytest.fail("no preview"))
    with pytest.raises(web.HTTPTooManyRequests):
        registry.groups.acquire("child", task)
    assert group.attempts == 0 and registry.admission.active == 1
    await owner.aclose()
    runtime.finish_session(session)
    _, lease = registry.groups.acquire("child", task)
    with pytest.raises(web.HTTPTooManyRequests):
        registry.admit(runtime, task)
    await group.release(lease)
    assert registry.admission.active == 0
    assert await registry.groups.close(group.identity.physical)


async def test_four_source_limit_is_one_budget_across_route_types(runtime):
    registry = IntegrationRegistry()
    owners = []
    for i in range(3):
        settings = replace(runtime.settings, channel=i)
        old = Runtime(settings, runtime.client)
        registry.entries[str(i)] = old
        owner = NativeMpegTsStream(lambda: pytest.fail("no acquisition"), settings.options)
        with patch.object(Runtime, "make_owner", return_value=owner):
            session = registry.admit(old, asyncio.current_task())
        owners.append((old, session))
    group = registry.groups.declare(GroupIdentity("fourth", "profile", "rev"),
                                     {"child": options()}, lambda: pytest.fail("no acquisition"))
    _, lease = registry.groups.acquire("child", asyncio.current_task())
    extra = Runtime(replace(runtime.settings, channel=7), runtime.client)
    with pytest.raises(web.HTTPTooManyRequests):
        registry.admit(extra, asyncio.current_task())
    assert registry.admission.active == 4
    await group.release(lease)
    for old, session in owners:
        await session.owner.aclose()
        old.finish_session(session)
    assert registry.admission.active == 0
    assert await registry.groups.close("fourth")


async def test_multilens_flow_is_explicit_and_keeps_logical_key(hass, data):
    root = {**data, "relay_api_port": 1984, "relay_source_clock": True,
            "relay_atomic_ownership": True, "configure_lenses": True}
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(result["flow_id"], root)
    assert result["type"] == "form" and result["step_id"] == "lenses"
    child = {"group_profile": "verified", "credential_revision": "generation-1",
             "lens_id": "telephoto", "lens_name": "Telephoto", "video_id": 481,
             "audio_id": 448, "add_another": False}
    with patch("custom_components.ezviz_native.async_setup_entry", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], child)
    assert result["type"] == "create_entry"
    assert result["data"]["lenses"][0]["lens_id"] == "telephoto"
    assert "configure_lenses" not in result["data"] and "media_key" not in result["data"]


@pytest.mark.parametrize("changes", [
    {"relay_source_clock": False}, {"relay_atomic_ownership": False},
    {"group_profile": " "}, {"credential_revision": ""},
    {"lenses": [{"lens_id": "primary", "name": "Bad", "video_id": 481}]},
    {"lenses": [{"lens_id": "Bad/ID", "name": "Bad", "video_id": 481}]},
    {"lenses": [{"lens_id": "extra", "name": "Bad", "video_id": 480, "audio_id": 448}]},
])
def test_unsafe_or_ambiguous_group_manifest_is_not_enabled(data, changes):
    with pytest.raises((ValueError, KeyError)):
        load_settings({**grouped(data), **changes})


async def test_physical_source_failure_invalidates_both_cameras_and_cached_retry(
    hass, aiohttp_client, data,
):
    source = Source(error=ValueError("private source detail"))
    with patch.object(GroupEntry, "make_source", return_value=source) as factory:
        entry, client, _, _, _ = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        assert (await client.get(path(runtime, "primary"))).status == 502
        await settled(runtime)
        await hass.async_block_till_done()
        assert source.closed and runtime.group.joined
        assert factory.call_count == 1
        assert hass.states.async_all("sensor")[0].state == "failed"
        assert all(s.state == "unavailable" for s in hass.states.async_all("camera"))
        for camera in cameras(hass):
            assert await camera.stream_source() is None
            assert await camera.async_create_stream() is None
        diagnostic = json.dumps(await async_get_config_entry_diagnostics(hass, entry))
        assert "private source detail" not in diagnostic
        assert str(data["credentials_path"]) not in diagnostic
        assert await runtime.prepare() and factory.call_count == 1
        assert await hass.config_entries.async_unload(entry.entry_id)


async def test_failed_physical_join_holds_common_slot_until_explicit_prepare_recovery(
    hass, aiohttp_client, data, clear_finite,
):
    source = Source(block=True, cooperate=False)
    from custom_components import ezviz_native  # noqa: PLC0415
    finite = ezviz_native.load_settings

    def bounded(values):
        result = finite(values)
        return replace(result, options=replace(result.options, close_timeout=0.03))

    with patch("custom_components.ezviz_native.load_settings", bounded), patch.object(GroupEntry, "make_source", return_value=source) as factory:
        entry, client, _, _, _ = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        pending = asyncio.create_task(client.get(path(runtime, "primary")))
        assert await asyncio.to_thread(source.entered.wait, 2)
        assert not await runtime.prepare()  # Still leased: no revocation/re-arm.
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        async with asyncio.timeout(3):
            while runtime.group.leases:
                await asyncio.sleep(0.01)
        assert runtime.group.cleanup_pending and hass.data[DOMAIN].admission.active == 1
        assert not await runtime.prepare()
        assert runtime.group.attempts == 1 and factory.call_count == 1
        source.release.set()
        assert await runtime.prepare()
        assert runtime.group.attempts == 0 and hass.data[DOMAIN].admission.active == 0
        assert factory.call_count == 1
        assert await hass.config_entries.async_unload(entry.entry_id)


async def test_concurrent_prepare_cannot_make_two_generations_or_admit_during_cleanup(
    hass, aiohttp_client, data,
):
    entry, client, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    runtime.group.attempts = 1
    entered, release = asyncio.Event(), asyncio.Event()

    async def blocked():
        entered.set()
        await release.wait()

    runtime.stoppers["test"] = blocked
    old = path(runtime, "primary")
    first = asyncio.create_task(runtime.prepare())
    await entered.wait()
    assert not await runtime.prepare()
    assert (await client.get(old)).status == 403
    assert (await client.get(path(runtime, "primary"))).status == 503
    release.set()
    assert await first
    assert runtime.group.attempts == 0
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_provider_failure_retains_stopped_generation_until_explicit_retry(
    hass, aiohttp_client, data,
):
    entry, client, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    runtime.group.attempts = 1
    camera = cameras(hass)[0]
    with patch.object(camera, "async_refresh_providers", AsyncMock(side_effect=RuntimeError("private"))):
        assert not await runtime.prepare()
    assert runtime.recovery_pending and runtime.group.paused
    assert (await client.get(path(runtime, "primary"))).status == 503
    assert await runtime.prepare()
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_parallel_provider_stops_join_the_same_cached_stream_once(hass, aiohttp_client, data):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    camera = cameras(hass)[0]
    stream = MagicMock()
    stream.outputs.return_value = {}
    entered, release = asyncio.Event(), asyncio.Event()

    async def blocked():
        entered.set()
        await release.wait()

    stream.stop = AsyncMock(side_effect=blocked)
    camera.stream = stream
    first = asyncio.create_task(camera._async_stop_aborted_delivery())  # noqa: SLF001
    await entered.wait()
    second = asyncio.create_task(camera._async_stop_aborted_delivery())  # noqa: SLF001
    release.set()
    await asyncio.gather(first, second)
    stream.stop.assert_awaited_once()
    assert camera.stream is None
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_reload_adopts_new_credential_revision_without_changing_lens_entity_ids(
    hass, aiohttp_client, data,
):
    with patch.object(GroupEntry, "make_source", side_effect=AssertionError("no preview")):
        entry, client, records, _, _ = await setup(hass, aiohttp_client, data)
        old = entry.runtime_data
        await asyncio.gather(*(camera.stream_source() for camera in cameras(hass)))
        old_paths = [path(old, key) for key in old.lenses]
        registry = er.async_get(hass)
        ids = {s.entity_id: (registry.async_get(s.entity_id).unique_id,
                            registry.async_get(s.entity_id).device_id)
               for s in hass.states.async_all("camera")}
        assert len({row[1] for row in ids.values()}) == 1
        updated = {**entry.data, "credential_revision": "opaque-generation-2",
                   "lenses": [{**entry.data["lenses"][0], "name": "New display name"}]}
        hass.config_entries.async_update_entry(entry, data=updated)
        with patch.object(old.client, "close_session", wraps=old.client.close_session) as close:
            assert await hass.config_entries.async_reload(entry.entry_id)
            close.assert_called_once()
        current = entry.runtime_data
        assert current is not old and current.group.identity.credential_revision == "opaque-generation-2"
        assert current.group.attempts == 0 and list(records) == ["unrelated"]
        assert ids == {s.entity_id: (registry.async_get(s.entity_id).unique_id,
                                    registry.async_get(s.entity_id).device_id)
                       for s in hass.states.async_all("camera")}
        for old_path in old_paths:
            assert (await client.get(old_path)).status == 403
        assert await hass.config_entries.async_unload(entry.entry_id)


async def test_live_source_factory_uses_only_supplied_offline_credentials(hass, aiohttp_client, data):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    with patch.object(runtime.client, "open_stream", return_value=MagicMock()) as opened:
        runtime.make_source()
        args, kwargs = opened.call_args
        assert args == (runtime.settings.credentials.device_info.serial,)
        assert kwargs["source"].mode == "offline" and not kwargs["source"].allow_cloud_fallback
        assert kwargs["source"].credentials is runtime.settings.credentials
        assert kwargs["channel"] == runtime.settings.channel
    assert await hass.config_entries.async_unload(entry.entry_id)



def test_an_owner_cannot_rebind_its_reserved_physical_selector():
    admission = Admission()
    owner = object()
    assert admission.reserve(owner, "first")
    assert not admission.reserve(owner, "different")
    assert admission.active == 1
    admission.release(owner)
    assert admission.active == 0


async def test_uncertain_relay_before_first_acquisition_is_explicitly_recoverable(
    hass, aiohttp_client, data,
):
    with patch.object(GroupEntry, "make_source", side_effect=AssertionError("no preview")):
        entry, client, records, _, _ = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        camera = next(c for c in cameras(hass) if c.runtime.key == "primary")
        relay = runtime.lenses["primary"].relay
        original = relay.source

        async def lost_ack(upstream):
            await original(upstream)
            raise RelayError("Registration acknowledgement unavailable")

        old_path = path(runtime, "primary")
        with patch.object(relay, "source", lost_ack), pytest.raises(RelayError):
            await camera.stream_source()
        assert runtime.group.attempts == 0 and runtime.recovery_pending
        assert runtime.can_prepare and runtime.group.paused
        assert (await client.get(old_path)).status == 403
        assert len(records) == 2
        assert await runtime.prepare()
        assert runtime.group.attempts == 0 and not runtime.recovery_pending
        assert list(records) == ["unrelated"]
        assert await hass.config_entries.async_unload(entry.entry_id)


async def test_lazy_rearm_construction_failure_keeps_a_recoverable_paused_generation(
    hass, aiohttp_client, data,
):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    runtime.group.attempts = 1
    with patch.object(runtime, "_new_relays", side_effect=RuntimeError("private")):
        assert not await runtime.prepare()
    assert runtime.recovery_pending and runtime.can_prepare and runtime.group.attempts == 0
    assert await runtime.prepare()
    assert not runtime.recovery_pending and not runtime.group.paused
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_prepare_waits_for_inflight_stream_creation_and_drops_old_generation(
    hass, aiohttp_client, data,
):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    camera = next(c for c in cameras(hass) if c.runtime.key == "primary")
    entered, release = asyncio.Event(), asyncio.Event()
    relay = runtime.lenses["primary"].relay

    async def source(_upstream):
        entered.set()
        await release.wait()
        return relay.url

    with patch.object(relay, "source", source):
        creating = asyncio.create_task(camera.async_create_stream())
        await entered.wait()
        runtime.recovery_pending = True  # Another lens lost its registration ACK.
        preparing = asyncio.create_task(runtime.prepare())
        async with asyncio.timeout(2):
            while not runtime.rearming:
                await asyncio.sleep(0)
        release.set()
        assert await creating is None
        assert await preparing
    assert camera.stream is None and runtime.group.attempts == 0
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_partial_setup_constructor_failure_rolls_back_group_and_client(
    hass, aiohttp_client, data,
):
    port, records, _, _ = await atomic_relay(aiohttp_client)
    assert await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(domain=DOMAIN, title="Primary", data=grouped(data, port))
    entry.add_to_hass(hass)
    with patch.object(GroupEntry, "_new_relays", side_effect=RuntimeError("construction failed")):
        assert not await hass.config_entries.async_setup(entry.entry_id)
    registry = hass.data[DOMAIN]
    assert not registry.groups.groups and not registry.group_entries
    assert registry.admission.active == 0 and list(records) == ["unrelated"]



async def test_direct_provider_source_lookup_discards_a_revoked_generation(
    hass, aiohttp_client, data,
):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    camera = next(c for c in cameras(hass) if c.runtime.key == "primary")
    relay = runtime.lenses["primary"].relay
    entered, release = asyncio.Event(), asyncio.Event()

    async def delayed(_upstream):
        entered.set()
        await release.wait()
        return relay.url

    with patch.object(relay, "source", delayed):
        pending = asyncio.create_task(camera.stream_source())
        await entered.wait()
        runtime.relay_failed()
        release.set()
        assert await pending is None
    assert runtime.group.attempts == 0 and await runtime.prepare()
    assert await hass.config_entries.async_unload(entry.entry_id)
