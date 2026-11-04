"""Explicit joint finite-A/V profile negotiation and task-local source selection."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import ClientSession, web
from custom_components.ezviz_native.camera import NativeCamera
from custom_components.ezviz_native.config import load_settings
from custom_components.ezviz_native.entry_runtime import GroupEntry, LensRuntime
from custom_components.ezviz_native.group import GroupRegistry
from custom_components.ezviz_native.relay import RelayError, SharedRelay
from homeassistant.components.camera import Camera
from homeassistant.exceptions import HomeAssistantError
import pytest
from test_composition import grouped
from test_native_integration import data as data  # noqa: PLC0414

from pyezvizapi.client import EzvizClient


def configured(data):
    return {**grouped(data), "finite_source": True, "relay_native_opus": True}


@pytest.mark.parametrize("changes", [
    {"relay_native_opus": 1}, {"finite_source": "true"}, {"finite_source": False},
    {"relay_source_clock": False}, {"relay_atomic_ownership": False},
    {"audio_id": -1}, {"lenses": []},
    {"lenses": [{"lens_id": "telephoto", "name": "Telephoto", "video_id": 481}]},
])
def test_joint_profile_requires_explicit_complete_contracts(data, changes):
    with pytest.raises(ValueError):
        load_settings({**configured(data), **changes})


def test_native_audio_and_finite_profile_are_not_legacy_defaults(data):
    settings = load_settings(grouped(data))
    assert not settings.relay_native_opus and not settings.options.finite_source
    settings = load_settings(configured(data))
    assert settings.relay_native_opus and settings.options.finite_source


async def test_missing_native_relay_capability_never_registers(aiohttp_client):
    calls = []

    async def api(request):
        calls.append(request.method)
        return web.json_response({"contract": "runtime-token-v1", "features": [
            "runtime-token-v1", "source-clock-v1", "no-retry-v1",
        ]}, headers={"X-Stream-Ownership": "runtime-token-v1"})

    app = web.Application()
    app.router.add_route("*", "/api/streams/owned", api)
    client = await aiohttp_client(app)
    async with ClientSession() as session:
        relay = SharedRelay(session, client.server.port, 8554,
                            trusted_source_clock=True, atomic_ownership=True, native_opus=True)
        with pytest.raises(RelayError, match="unavailable"):
            await relay.source("http://127.0.0.1/forbidden-source")
        assert await relay.close()
    assert calls == ["GET"]


async def test_concurrent_hls_keeps_aac_and_other_tasks_select_opus(hass, data):
    registry = GroupRegistry()
    settings = load_settings(configured(data))
    owner = GroupEntry(hass, "entry", "Primary", settings, MagicMock(spec=EzvizClient), registry)
    entry = MagicMock(entry_id="entry", title="Primary", runtime_data=owner)
    camera = NativeCamera(entry, owner.lenses["primary"])
    camera.hass = hass
    base = "rtsp://127.0.0.1:8554/named?source_clock=trusted"
    owner.lenses["primary"].relay = MagicMock(spec=SharedRelay, source=AsyncMock(return_value=base))
    entered, release = asyncio.Event(), asyncio.Event()
    sources = []
    stream = SimpleNamespace()

    async def create(entity):
        sources.append(await entity.stream_source())
        entered.set()
        await release.wait()
        return stream

    with (patch.object(LensRuntime, "upstream", return_value="http://127.0.0.1/capability"),
          patch.object(Camera, "async_create_stream", create),
          patch("custom_components.ezviz_native.camera.maybe_finite_delivery",
                return_value=SimpleNamespace(stream=stream)),
          patch.object(GroupEntry, "make_source", side_effect=AssertionError("No preview"))):
        task = asyncio.create_task(camera.async_create_stream())
        await entered.wait()
        assert await camera.stream_source() == base + "&video&audio=opus"
        release.set()
        assert await task is stream
        assert sources == [base]
    assert owner.group.attempts == 0
    await registry.close(owner.group.identity.physical)


async def test_joint_profile_refuses_missing_ha_contract_before_source(hass, data):
    registry = GroupRegistry()
    owner = GroupEntry(hass, "entry", "Primary", load_settings(configured(data)),
                       MagicMock(spec=EzvizClient), registry)
    camera = NativeCamera(MagicMock(entry_id="entry", title="Primary", runtime_data=owner),
                          owner.lenses["primary"])
    camera.hass = hass
    with (patch.object(Camera, "async_create_stream", AsyncMock(return_value=SimpleNamespace())),
          patch("custom_components.ezviz_native.camera.maybe_finite_delivery", return_value=None),
          patch.object(GroupEntry, "make_source", side_effect=AssertionError("No preview")),
          pytest.raises(HomeAssistantError, match="public HA finite-source API")):
        await camera.async_create_stream()
    assert owner.group.attempts == 0
    await registry.close(owner.group.identity.physical)
