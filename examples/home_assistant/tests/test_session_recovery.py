"""Explicit UI recovery and no-source semantics across real HA entry reloads."""
import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

from custom_components.ezviz_native.button import PrepareSessionButton
from custom_components.ezviz_native.camera import NativeCamera
from custom_components.ezviz_native.const import DOMAIN
from custom_components.ezviz_native.route import Runtime
from homeassistant.components.camera.const import DATA_COMPONENT
from homeassistant.exceptions import HomeAssistantError
from homeassistant.setup import async_setup_component
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from test_local_av_timeline import encode_three_track_ps
from test_native_integration import data as data, runtime as runtime  # noqa: PLC0414
from test_native_stream import Source
from test_shared_relay import relay_server

from pyezvizapi.native_stream import NativeMpegTsStream


async def setup_entry(hass, aiohttp_client, data):
    relay, streams, _, _, _, _ = await relay_server(aiohttp_client)
    port = int(relay._api.split(":")[2].split("/")[0])  # noqa: SLF001
    assert await async_setup_component(hass, "http", {})
    entry = MockConfigEntry(domain=DOMAIN, title="Recovery lens", data={
        **data, "relay_api_port": port, "relay_rtsp_port": 18554,
    })
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    client = await aiohttp_client(hass.http.app, server_kwargs={"handler_cancellation": True})
    camera_id = next(s.entity_id for s in hass.states.async_all("camera"))
    button_id = next(s.entity_id for s in hass.states.async_all("button"))
    return entry, client, camera_id, button_id, streams


def url(entry, token):
    return f"/api/ezviz_native/{entry.entry_id}/stream.ts?auth={token}"


async def test_explicit_button_reloads_without_acquiring_and_revokes_old_url(
    hass, aiohttp_client, data, tmp_path,
):
    entry, client, camera_id, button_id, streams = await setup_entry(hass, aiohttp_client, data)
    payload = await asyncio.to_thread(lambda: encode_three_track_ps(tmp_path).read_bytes())
    owners = []

    def make_owner(runtime):
        owner = NativeMpegTsStream(lambda: Source(payload), replace(
            runtime.settings.options, finite_source=True,
        ))
        owners.append(owner)
        return owner

    with patch.object(Runtime, "make_owner", make_owner):
        old_runtime = entry.runtime_data
        old_token = old_runtime.token
        camera = hass.data[DATA_COMPONENT].get_entity(camera_id)
        await camera.stream_source()  # Register lazily, not acquire.
        assert owners == []
        response = await client.get(url(entry, old_token))
        first = await response.read()
        assert response.status == 200 and first
        await hass.async_block_till_done()
        assert old_runtime.session_status == "ended"
        assert await camera.stream_source() is None
        assert hass.states.get(camera_id).attributes["prepare_new_session_required"]
        assert hass.states.get(button_id).state != "unavailable"
        assert len(owners) == 1

        await hass.services.async_call("button", "press", {"entity_id": button_id}, blocking=True)
        await hass.async_block_till_done()
        current = entry.runtime_data
        assert current is not old_runtime and current.token != old_token
        assert current.session_status == "ready" and current.acquisition_attempts == 0
        assert len(owners) == 1  # Re-arm is not a preview or a second factory call.
        assert (await client.get(url(entry, old_token))).status == 403
        assert not hass.states.get(camera_id).attributes["prepare_new_session_required"]
        assert hass.states.get(button_id).state == "unavailable"

        response = await client.get(url(entry, current.token))
        assert await response.read() == first
        assert response.status == 200 and len(owners) == 2
        assert current.acquisition_attempts == 1
        await hass.async_block_till_done()
        assert await hass.config_entries.async_unload(entry.entry_id)
    assert all(o.receipt["worker_joined"] and o.receipt["owned_output_bytes"] == 0 for o in owners)
    assert set(streams) == {"unrelated"}


async def test_failed_session_is_unavailable_and_rearmable(hass, aiohttp_client, data):
    entry, client, camera_id, button_id, _ = await setup_entry(hass, aiohttp_client, data)
    runtime = entry.runtime_data
    camera = hass.data[DATA_COMPONENT].get_entity(camera_id)
    cached_stream = await camera.async_create_stream()
    assert cached_stream is not None
    cached_stream.add_provider("hls")
    cached_stream.dynamic_stream_settings.preload_stream = True
    owner = NativeMpegTsStream(lambda: Source(b"invalid PS"), runtime.settings.options)
    with patch.object(Runtime, "make_owner", return_value=owner):
        assert (await client.get(url(entry, runtime.token))).status == 502
        await hass.async_block_till_done()
    assert runtime.session_status == "failed"
    assert next(s for s in hass.states.async_all("sensor")).state == "failed"
    assert hass.states.get(camera_id).state == "unavailable"
    assert hass.states.get(button_id).state != "unavailable"
    camera = hass.data[DATA_COMPONENT].get_entity(camera_id)
    assert await camera.stream_source() is None
    assert await camera.async_create_stream() is None
    assert not cached_stream.outputs()
    assert not cached_stream.dynamic_stream_settings.preload_stream
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_prepare_rejects_active_cleanup_and_concurrent_presses(hass, runtime):
    runtime.relay = MagicMock()
    runtime.acquisition_attempts = 1
    runtime.delivery_ended = True
    entry = MockConfigEntry(domain=DOMAIN, title="Recovery", data={})
    entry.runtime_data = runtime
    button = PrepareSessionButton(entry)
    button.hass = hass
    runtime.active = MagicMock()
    assert runtime.session_status == "cleanup_pending"
    with pytest.raises(HomeAssistantError):
        await button.async_press()
    runtime.active = None
    entered, release = asyncio.Event(), asyncio.Event()

    async def reload(_entry_id):
        entered.set()
        await release.wait()
        return True

    with patch.object(hass.config_entries, "async_reload", AsyncMock(side_effect=reload)) as call:
        first = asyncio.create_task(button.async_press())
        await entered.wait()
        with pytest.raises(HomeAssistantError):
            await button.async_press()
        release.set()
        await first
        call.assert_awaited_once_with(entry.entry_id)

    runtime.status_changed = MagicMock()
    with (
        patch.object(hass.config_entries, "async_reload", AsyncMock(return_value=False)),
        pytest.raises(HomeAssistantError, match="could not be prepared"),
    ):
        await button.async_press()
    assert button.available  # A failed reload must not leave the UI disabled.
    assert runtime.status_changed.call_count == 2


async def test_direct_mode_does_not_become_one_shot(hass, runtime):
    entry = MockConfigEntry(domain=DOMAIN, title="Direct", data={})
    entry.runtime_data = runtime
    camera = NativeCamera(entry)
    camera.hass = hass
    runtime.acquisition_attempts = 1
    runtime.delivery_ended = True
    assert not runtime.exhausted
    assert runtime.session_status == "ready"
    assert not camera.extra_state_attributes["prepare_new_session_required"]


async def test_failed_lazy_owner_construction_is_rearmable(hass, aiohttp_client, data):
    entry, client, camera_id, button_id, _ = await setup_entry(hass, aiohttp_client, data)
    with patch.object(Runtime, "make_owner", side_effect=ValueError("private configuration")):
        assert (await client.get(url(entry, entry.runtime_data.token))).status == 502
        await hass.async_block_till_done()
    assert entry.runtime_data.session_status == "failed"
    assert entry.runtime_data.active is None
    assert hass.states.get(camera_id).state == "unavailable"
    assert hass.states.get(button_id).state != "unavailable"
    assert await hass.config_entries.async_unload(entry.entry_id)
