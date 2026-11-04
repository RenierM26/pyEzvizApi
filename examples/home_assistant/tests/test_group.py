"""Explicit HA group admission and real HTTP cold delivery, never live acquisition."""
import asyncio
from dataclasses import replace
from threading import Event
from unittest.mock import MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from custom_components.ezviz_native.group import GroupIdentity, GroupRegistry, GroupStreamView
from homeassistant.components.camera import DynamicStreamSettings
from homeassistant.components.stream import create_stream
from homeassistant.setup import async_setup_component
import pytest
from test_local_av_timeline import encode_three_track_ps
from test_native_stream import Source, options, repeated_ps_packets
from test_stream_sample import packet_oracle

from pyezvizapi.native_stream import NativeTrackSelection


def identity(physical="source", **changes):
    return GroupIdentity(physical, changes.get("profile", "verified-main"),
                         changes.get("credential_revision", "opaque-revision-1"))


def members(prefix="", **changes):
    return {prefix + "a": options(selection=NativeTrackSelection(480, 448), **changes),
            prefix + "b": options(**changes)}


def declare(registry, source=None, **kwargs):
    calls = []

    def factory():
        calls.append(1)
        return source if source is not None else Source()

    group = registry.declare(identity(), members(), factory, **kwargs)
    return group, calls


def path(group, member):
    return f"/api/ezviz_native_group/{member}/stream.ts?auth={group.tokens[member]}"


async def route(hass, aiohttp_client, registry):
    assert await async_setup_component(hass, "http", {})
    hass.http.register_view(GroupStreamView(registry))
    return await aiohttp_client(hass.http.app, server_kwargs={"handler_cancellation": True})


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    return encode_three_track_ps(tmp_path_factory.mktemp("ha-group")).read_bytes()


async def test_actual_ha_http_two_lenses_one_attempt_then_whole_group_prepare(
    hass, aiohttp_client, sample,
):
    registry = GroupRegistry()
    calls = []

    def factory():
        calls.append(1)
        return Source(sample)

    group = registry.declare(identity(), members(), factory)
    client = await route(hass, aiohttp_client, registry)
    old_paths = [path(group, member) for member in ("a", "b")]
    assert calls == []

    async def read(member):
        response = await client.get(path(group, member))
        assert response.status == 200
        assert response.headers["X-Stream-Retry"] == "never"
        return await response.read()

    bodies = await asyncio.gather(read("a"), read("b"))
    async with asyncio.timeout(2):
        while group.reserved:
            await asyncio.sleep(0.01)
    assert calls == [1] and group.attempts == 1 and not group.reserved
    assert group.joined and group.terminal
    assert group.last_receipt["all_outputs_completed"]
    original = packet_oracle(sample)
    for body, video in zip(bodies, (0, 2), strict=True):
        actual = packet_oracle(body)
        assert actual[1] == original[1]
        assert [row[1:] for row in actual[0]] == [row[1:] for row in original[video]]
    assert (await client.get(old_paths[0])).status == 503
    results = await asyncio.gather(registry.prepare("source"), registry.prepare("source"))
    assert sorted(results) == [False, True]
    assert calls == [1] and group.attempts == 0 and group.used == set()
    for old in old_paths:
        assert (await client.get(old)).status == 403
    assert await asyncio.gather(read("a"), read("b")) == bodies
    async with asyncio.timeout(2):
        while group.reserved:
            await asyncio.sleep(0.01)
    assert calls == [1, 1] and group.attempts == 1
    close_result = await registry.close("source")
    assert close_result
    assert not registry.members and not registry.groups


async def test_barrier_timeout_is_terminal_without_source_acquisition(hass, aiohttp_client):
    registry = GroupRegistry()
    group, calls = declare(registry, barrier_timeout=0.02)
    client = await route(hass, aiohttp_client, registry)
    assert (await client.get(path(group, "a"))).status == 503
    assert group.terminal and group.attempts == 1 and calls == []
    assert not group.leases and not group.reserved and group.joined
    assert (await client.get(path(group, "b"))).status == 503
    assert await registry.prepare("source") and calls == []
    close_result = await registry.close("source")
    assert close_result


async def test_duplicate_reader_and_prepare_cannot_acquire_during_barrier():
    registry = GroupRegistry()
    group, calls = declare(registry)
    _, lease = registry.acquire("a", asyncio.current_task())
    with pytest.raises(web.HTTPTooManyRequests):
        registry.acquire("a", asyncio.current_task())
    assert not await registry.prepare("source")
    assert not group.ready.is_set() and group.reserved and calls == []
    await group.release(lease)
    assert group.terminal and calls == []
    close_result = await registry.close("source")
    assert close_result


async def test_global_limit_counts_physical_groups_not_lenses():
    registry = GroupRegistry()
    leases = []
    for index in range(5):
        prefix = str(index)
        group = registry.declare(identity(prefix), members(prefix), lambda: pytest.fail("no source"))
        if index == 4:
            with pytest.raises(web.HTTPTooManyRequests):
                registry.acquire(prefix + "a", asyncio.current_task())
            assert group.attempts == 0
            continue
        leases.append((group, registry.acquire(prefix + "a", asyncio.current_task())[1]))
        leases.append((group, registry.acquire(prefix + "b", asyncio.current_task())[1]))
    assert sum(g.reserved for g in registry.groups.values()) == 4
    for group, lease in leases:
        await group.release(lease)
    for physical in tuple(registry.groups):
        close_result = await registry.close(physical)
        assert close_result


@pytest.mark.parametrize("changes", [{}, {"profile": "different"},
                                    {"credential_revision": "new-key"}])
def test_same_physical_identity_never_creates_second_profile_or_credential_owner(changes):
    registry = GroupRegistry()
    group, calls = declare(registry)
    with pytest.raises(ValueError):
        registry.declare(identity(**changes), members("other"), lambda: pytest.fail("no source"))
    assert list(registry.groups.values()) == [group] and calls == []


@pytest.mark.parametrize("choices", [
    {}, {"a": options(), "b": options()},
    {"a": options(), "b": replace(options(), video_codec="h264")},
    {"": options()},
])
def test_invalid_manifest_is_atomic_and_lazy(choices):
    registry = GroupRegistry()
    with pytest.raises(ValueError):
        registry.declare(identity(), choices, lambda: pytest.fail("no source"))
    assert registry.members == registry.groups == {}


@pytest.mark.parametrize("value", [0, -1, True, float("nan"), 31])
def test_unbounded_or_invalid_barrier_rejected(value):
    with pytest.raises(ValueError):
        declare(GroupRegistry(), barrier_timeout=value)


async def test_failed_physical_join_retains_owner_and_budget_until_explicit_recovery():
    source = Source(block=True, cooperate=False)
    registry = GroupRegistry()
    calls = []

    def factory():
        calls.append(1)
        return source

    group = registry.declare(identity(), members(finite_source=False, close_timeout=0.03), factory)
    leases = [registry.acquire(m, asyncio.current_task())[1] for m in ("a", "b")]
    group.owner.start()
    assert await asyncio.to_thread(source.entered.wait, 2)
    owner = group.owner
    await group.release(leases[0])
    assert not source.closed  # Healthy sibling retains the physical source.
    await group.release(leases[1])
    assert group.cleanup_pending and group.reserved and not group.joined
    assert group.owner is owner and calls == [1]
    with pytest.raises(web.HTTPServiceUnavailable):
        registry.acquire("a", asyncio.current_task())
    assert not await registry.prepare("source")
    close_result = await registry.close("source")
    assert not close_result
    assert registry.groups["source"].owner is owner
    source.release.set()
    close_result = await registry.close("source")
    assert close_result
    assert owner.physical_receipt["worker_joined"] and source.closed
    assert not registry.groups


async def test_detaching_running_lens_does_not_close_healthy_sibling(hass, aiohttp_client):
    source = Source(block=True)
    registry = GroupRegistry()
    group = registry.declare(identity(), members(finite_source=False), lambda: source)
    client = await route(hass, aiohttp_client, registry)
    old_a = path(group, "a")
    pending = [asyncio.create_task(client.get(path(group, m))) for m in ("a", "b")]
    assert await asyncio.to_thread(source.entered.wait, 2)
    assert await registry.detach("a")
    assert "a" not in registry.members and "b" in group.leases
    assert not source.closed and not group.owner.physical_receipt["worker_joined"]
    assert (await client.get(old_a)).status == 403
    assert not await registry.prepare("source")
    assert await registry.detach("b")
    await asyncio.gather(*pending, return_exceptions=True)
    assert source.closed and group.joined and not registry.groups


async def test_detach_before_barrier_aborts_without_silent_manifest_shrink():
    registry = GroupRegistry()
    group, calls = declare(registry)
    assert await registry.detach("a")
    assert group.terminal and calls == []
    with pytest.raises(web.HTTPServiceUnavailable):
        registry.acquire("b", asyncio.current_task())
    assert not await registry.prepare("source")
    assert await registry.detach("b")


async def test_remote_socket_or_forged_forwarded_peer_never_acquires():
    registry = GroupRegistry()
    group, calls = declare(registry)
    transport = MagicMock()
    transport.get_extra_info.return_value = ("192.0.2.20", 40000)
    request = make_mocked_request("GET", path(group, "a"), transport=transport,
                                  headers={"X-Forwarded-For": "127.0.0.1"})
    with pytest.raises(web.HTTPForbidden):
        await GroupStreamView(registry).get(request, "a")
    assert group.attempts == 0 and calls == []
    close_result = await registry.close("source")
    assert close_result


async def test_real_ha_hls_workers_share_group_http_source(hass, aiohttp_client, sample):
    registry = GroupRegistry()
    source = Source(bodies=repeated_ps_packets(sample, 20), block=True)
    calls = []

    def factory():
        calls.append(1)
        return source

    group = registry.declare(identity(), members(finite_source=False), factory)
    assert await async_setup_component(hass, "stream", {"stream": {"ll_hls": False}})
    client = await route(hass, aiohttp_client, registry)
    streams = [create_stream(hass, str(client.make_url(path(group, m))), {},
                             DynamicStreamSettings(), stream_label="group-" + m)
               for m in ("a", "b")]
    providers = [s.add_provider("hls") for s in streams]
    for stream in streams:
        stream.endpoint_url("hls")
    try:
        await asyncio.gather(*(s.start() for s in streams))
        async with asyncio.timeout(15):
            while any(p.last_segment is None for p in providers):
                await asyncio.sleep(0.02)
        assert calls == [1] and group.attempts == 1
        for provider in providers:
            assert provider.last_segment.parts
            assert any(tag in provider.last_segment.init for tag in (b"hvc1", b"hev1"))
            audio_tag = b"mp4a"
            assert audio_tag in provider.last_segment.init
        assert len(group.leases) == 2
        await streams[0].remove_provider(providers[0])
        await streams[0].stop()
        async with asyncio.timeout(3):
            while "a" in group.leases:
                await asyncio.sleep(0.01)
        assert "b" in group.leases and not source.closed
        assert not await registry.prepare("source")
    finally:
        close_result = await registry.close("source")
        assert close_result
        for stream, provider in zip(streams, providers, strict=True):
            if provider.name in stream.outputs():
                await stream.remove_provider(provider)
            await stream.stop()
    assert group.joined and source.closed
    assert all(o["owned_output_bytes"] == 0 for o in group.owner.receipt["outputs"])


async def test_http_failed_join_does_not_repeat_implicit_cleanup_budget(hass, aiohttp_client):
    registry = GroupRegistry()
    source = Source(block=True, cooperate=False)
    group = registry.declare(identity(), members(finite_source=False, close_timeout=0.03),
                             lambda: source)
    client = await route(hass, aiohttp_client, registry)
    pending = [asyncio.create_task(client.get(path(group, m))) for m in ("a", "b")]
    assert await asyncio.to_thread(source.entered.wait, 2)
    with patch.object(group.owner, "close", wraps=group.owner.close) as close:
        # The final output invokes _close_session itself. Neither handler exit
        # nor registry.close may then call the physical close method implicitly.
        close_result = await registry.close("source")
        assert not close_result
        close.assert_not_called()
    await asyncio.gather(*pending, return_exceptions=True)
    assert group.cleanup_pending and group.reserved
    source.release.set()
    close_result = await registry.close("source")
    assert close_result


async def test_disconnect_during_cold_barrier_never_acquires(hass, aiohttp_client):
    registry = GroupRegistry()
    group, calls = declare(registry)
    client = await route(hass, aiohttp_client, registry)
    pending = asyncio.create_task(client.get(path(group, "a")))
    async with asyncio.timeout(2):
        while not group.leases:
            await asyncio.sleep(0.01)
    pending.cancel()
    await asyncio.gather(pending, return_exceptions=True)
    async with asyncio.timeout(2):
        while group.reserved:
            await asyncio.sleep(0.01)
    assert calls == [] and group.terminal and group.attempts == 1
    close_result = await registry.close("source")
    assert close_result


async def test_manifest_is_copied_and_frozen_and_redeclaration_requires_full_close():
    registry = GroupRegistry()
    choices = members()
    group = registry.declare(identity(), choices, lambda: pytest.fail("not acquired"))
    choices.clear()
    assert tuple(group.options) == ("a", "b")
    with pytest.raises(TypeError):
        group.options["a"] = options()
    close_result = await registry.close("source")
    assert close_result
    revised = registry.declare(identity(credential_revision="new-generation"), members(),
                               lambda: pytest.fail("not acquired"))
    assert revised is not group and revised.identity != group.identity
    close_result = await registry.close("source")
    assert close_result


async def test_old_group_close_preserves_reassigned_detached_member():
    registry = GroupRegistry()
    old, _ = declare(registry)
    assert await registry.detach("a")
    replacement = registry.declare(identity("replacement"), {"a": options()},
                                   lambda: pytest.fail("not acquired"))
    close_result = await registry.close("source")
    assert close_result
    assert registry.members["a"] is replacement
    close_result = await registry.close("replacement")
    assert close_result
    assert old.joined


async def test_explicit_late_mode_opens_second_http_lens_without_cold_barrier(
    hass, aiohttp_client, sample,
):
    registry = GroupRegistry()
    source = Source(bodies=repeated_ps_packets(sample, 20))
    calls = []

    def factory():
        calls.append(1)
        return source

    group = registry.declare(identity(), members(), factory, late_join=True)
    ready, release = Event(), Event()
    original = group.owner._deliver_packet  # noqa: SLF001
    count = 0

    def observed(av, stack, binding, packet):
        nonlocal count
        original(av, stack, binding, packet)
        if binding.output is group.owner.outputs[0] and packet.stream.id == 480:
            count += 1
            if count == 40:
                ready.set()
                assert release.wait(3)

    client = await route(hass, aiohttp_client, registry)

    async def read(member):
        response = await client.get(path(group, member))
        assert response.status == 200
        return await response.read()

    with patch.object(group.owner, "_deliver_packet", observed):
        first = asyncio.create_task(read("a"))
        assert await asyncio.to_thread(ready.wait, 3)
        assert set(group.leases) == {"a"} and calls == [1]
        second = asyncio.create_task(read("b"))
        async with asyncio.timeout(3):
            while not group.owner.outputs[1].requested:
                await asyncio.sleep(0.01)
        release.set()
        bodies = await asyncio.gather(first, second)
    async with asyncio.timeout(2):
        while group.reserved:
            await asyncio.sleep(0.01)
    full, late = [packet_oracle(body) for body in bodies]
    assert len(late[0]) < len(full[0]) and late[0][0][1] > full[0][0][1]
    assert group.owner.outputs[1].receipt["join_origin_90k"] == late[0][0][1]
    assert calls == [1] and group.attempts == 1 and group.joined
    close_result = await registry.close("source")
    assert close_result
