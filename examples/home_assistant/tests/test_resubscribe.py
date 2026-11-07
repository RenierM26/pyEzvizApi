"""Per-lens operator recovery, real HA entities and one generated acquisition."""
import asyncio
from threading import Event
from unittest.mock import AsyncMock, MagicMock, patch

from custom_components.ezviz_native.const import DOMAIN
from custom_components.ezviz_native.entry_runtime import GroupEntry
from homeassistant.helpers import entity_registry as er
import pytest
from test_composition import (
    cameras,
    clear_finite as clear_finite,  # noqa: PLC0414
    consume,
    path,
    settled,
    setup,
)
from test_native_integration import data as data  # noqa: PLC0414
from tests.streaming.test_native_late_join import oracle
from tests.streaming.test_native_stream import Source, repeated_ps_packets
from tests.tools.test_local_av_timeline import encode_three_track_ps

from pyezvizapi.native_session import NativeMpegTsSession


async def test_lens_button_revokes_only_retired_lens_and_rejoins_same_source(  # noqa: PLR0915
    hass, aiohttp_client, data, tmp_path, clear_finite, monkeypatch,
):
    sample = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    payload = b"".join(repeated_ps_packets(sample, 30))
    source, calls = Source(payload), []
    gates = {n: (Event(), Event()) for n in (40, 80, 120)}
    count = [0]
    original = NativeMpegTsSession._deliver_packet  # noqa: SLF001

    def deliver(self, av, stack, binding, packet):
        original(self, av, stack, binding, packet)
        if binding.output is self.outputs[0] and packet.stream.id == 480:
            count[0] += 1
            if count[0] in gates:
                ready, release = gates[count[0]]
                ready.set()
                assert release.wait(8)

    def factory(_runtime):
        calls.append(1)
        return source

    monkeypatch.setattr(NativeMpegTsSession, "_deliver_packet", deliver)
    with patch.object(GroupEntry, "make_source", factory):
        entry, client, records, _, _ = await setup(hass, aiohttp_client, data)
        runtime = entry.runtime_data
        primary_lens, lens = runtime.lenses.values()
        entities = {c.runtime.key: c for c in cameras(hass)}
        await asyncio.gather(*(camera.stream_source() for camera in entities.values()))
        primary_relay, old_relay = primary_lens.relay, lens.relay
        primary_path, old_path = path(runtime, "primary"), path(runtime, "telephoto")
        owner = runtime.group.owner
        primary = asyncio.create_task(consume(client, runtime, "primary"))
        try:
            assert await asyncio.to_thread(gates[40][0].wait, 5)
            secondary = asyncio.create_task(client.get(old_path))
            gates[40][1].set()
            response = await secondary
            assert response.status == 200
            reader = asyncio.create_task(response.read())
            assert await asyncio.to_thread(gates[80][0].wait, 5)
            response.close()
            await asyncio.gather(reader, return_exceptions=True)
            async with asyncio.timeout(3):
                while lens.active is not None:
                    await asyncio.sleep(0.01)
            assert (await client.get(old_path)).status == 503
            gates[80][1].set()
            assert await asyncio.to_thread(gates[120][0].wait, 5)
            assert runtime.can_prepare_lens("telephoto")
            assert not runtime.can_prepare_lens("primary") and not runtime.can_prepare
            old_output = owner.outputs[1]
            cache = MagicMock()
            cache.outputs.return_value = {}
            cache.stop = AsyncMock()
            entities["telephoto"].stream = cache
            button_id = er.async_get(hass).async_get_entity_id(
                "button", DOMAIN, f"{entry.entry_id}_telephoto_prepare_lens",
            )
            assert button_id is not None
            await hass.services.async_call("button", "press", {"entity_id": button_id}, blocking=True)
            cache.stop.assert_awaited_once()
            assert entities["telephoto"].stream is None
            assert runtime.group.owner is owner and runtime.group.attempts == 1 and calls == [1]
            assert hass.data[DOMAIN].admission.active == 1
            assert primary_lens.relay is primary_relay and path(runtime, "primary") == primary_path
            assert lens.relay is not old_relay and old_relay.name not in records
            assert primary_relay.name in records and lens.relay.name not in records
            assert (await client.get(old_path)).status == 403
            assert owner.outputs[1] is not old_output
            assert owner.outputs[1].receipt["status"] == "unused"
            assert not await runtime.prepare_lens("telephoto")  # Already prepared, never renew twice.
            fresh = asyncio.create_task(consume(client, runtime, "telephoto"))
            gates[120][1].set()
            first, replacement = await asyncio.wait_for(asyncio.gather(primary, fresh), 10)
        finally:
            for _, release in gates.values():
                release.set()
        await settled(runtime)
        baseline, actual = oracle(payload), oracle(replacement)
        assert oracle(first)[256] == baseline[480] and oracle(first)[257] == baseline[448]
        for output_id, input_id in ((256, 481), (257, 448)):
            start = baseline[input_id].index(actual[output_id][0])
            assert start > 0 and actual[output_id] == baseline[input_id][start:]
        assert calls == [1] and source.closed and owner.receipt["worker_joined"]
        assert owner.receipt["retired_subscriptions"] == 1
        assert hass.data[DOMAIN].admission.active == 0
        assert await hass.config_entries.async_unload(entry.entry_id)
        assert list(records) == ["unrelated"]


@pytest.mark.parametrize("failure", ["provider", "relay", "constructor", "replace"])
async def test_failed_lens_prepare_blocks_only_that_member_and_retains_ownership(
    hass, aiohttp_client, data, monkeypatch, failure,
):
    entry, _, records, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    group = runtime.group
    lens = runtime.lenses["telephoto"]
    await asyncio.gather(*(camera.stream_source() for camera in cameras(hass)))
    primary_token, old_relay = runtime.lenses["primary"].token, lens.relay
    monkeypatch.setattr(runtime, "can_prepare_lens", lambda key: not lens.preparing)
    group.used.add(lens.member)
    runtime.stoppers["telephoto"] = AsyncMock(side_effect=RuntimeError if failure == "provider" else None)
    if failure == "relay":
        monkeypatch.setattr(old_relay, "close", AsyncMock(return_value=False))
    if failure == "constructor":
        monkeypatch.setattr(runtime, "_make_relay", MagicMock(side_effect=ValueError))
    monkeypatch.setattr(group.owner, "replace_output", MagicMock(side_effect=RuntimeError))
    assert not await runtime.prepare_lens("telephoto")
    assert lens.member in group.blocked_members and lens.member in group.used
    assert lens.recovery_pending and lens.session_status == "cleanup_pending"
    assert lens.relay is old_relay
    assert runtime.lenses["primary"].token == primary_token and not group.paused
    assert group.attempts == 0  # No camera/source acquired on a recovery error.
    runtime.stoppers.clear()  # Recovery injectors must not also sabotage entry unload.
    if failure == "relay":
        monkeypatch.undo()
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert list(records) == ["unrelated"]


async def test_cancelled_prepare_retains_executor_result_until_explicit_retry(
    hass, aiohttp_client, data, monkeypatch,
):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    lens = runtime.lenses["telephoto"]
    runtime.group.used.add(lens.member)
    monkeypatch.setattr(runtime, "can_prepare_lens", lambda key: not lens.preparing)
    entered, release = Event(), Event()
    calls = []

    def replace(_previous):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return runtime.group.owner.outputs[1]  # Scheduling control; no source/mux is opened.

    monkeypatch.setattr(runtime.group.owner, "replace_output", replace)
    pending = asyncio.create_task(runtime.prepare_lens("telephoto"))
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        pending.cancel()
        await asyncio.sleep(0)
        assert not pending.done() and lens.preparing
        assert not await runtime.prepare_lens("telephoto")
        pending.cancel()  # Repeated cancellation cannot release ownership early either.
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        _ = await pending
    assert lens.recovery_pending and lens.member in runtime.group.blocked_members
    assert lens.pending_output is runtime.group.owner.outputs[1]
    assert await runtime.prepare_lens("telephoto")
    assert lens.pending_output is None and lens.member not in runtime.group.used
    assert calls == [1] and runtime.group.attempts == 0
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_physical_end_during_member_prepare_never_publishes_replacement(
    hass, aiohttp_client, data, monkeypatch,
):
    entry, _, _, _, _ = await setup(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    lens = runtime.lenses["telephoto"]
    runtime.group.used.add(lens.member)
    monkeypatch.setattr(runtime, "can_prepare_lens", lambda key: not lens.preparing)

    def replace(_previous):
        runtime.group.terminal = True  # Simulate a last-sibling departure while off-loop.
        return runtime.group.owner.outputs[1]

    monkeypatch.setattr(runtime.group.owner, "replace_output", replace)
    assert not await runtime.prepare_lens("telephoto")
    assert lens.member in runtime.group.used and lens.member in runtime.group.blocked_members
    assert lens.recovery_pending and runtime.group.attempts == 0
    assert await hass.config_entries.async_unload(entry.entry_id)
