"""Temporary upstream-oriented native delivery validation, not cloud discovery."""
from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import async_dispatcher_send

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError

from .config import load_settings
from .const import DOMAIN, status_signal
from .entry_runtime import GroupEntry, IntegrationRegistry
from .group import GroupStreamView
from .relay import SharedRelay
from .route import NativeStreamView, Runtime, validate_http

_LOGGER = logging.getLogger(__name__)
type NativeConfigEntry = ConfigEntry[Runtime | GroupEntry]
_PLATFORMS = [Platform.CAMERA, Platform.BUTTON, Platform.SENSOR]


def registry_for(hass: HomeAssistant) -> IntegrationRegistry:
    """Register both views once, with one retained physical-source budget."""
    if DOMAIN not in hass.data:
        registry = hass.data[DOMAIN] = IntegrationRegistry()
        hass.http.register_view(NativeStreamView(registry))
        hass.http.register_view(GroupStreamView(registry.groups))

        async def stop(_event: object) -> None:
            keys = [*registry.entries, *registry.group_entries]
            results = await asyncio.gather(*(registry.close_config_entry(key) for key in keys),
                                           return_exceptions=True)
            if any(result is not True for result in results):
                _LOGGER.error("Native source shutdown incomplete; owner retained")

        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    return hass.data[DOMAIN]


async def async_setup_entry(hass: HomeAssistant, entry: NativeConfigEntry) -> bool:
    """Read explicit credentials/manifest; setup and entity creation never preview."""
    client = None
    try:
        settings = await hass.async_add_executor_job(load_settings, dict(entry.data))
        validate_http(hass)
        client = await hass.async_add_executor_job(EzvizClient)
        registry = registry_for(hass)
        runtime: Runtime | GroupEntry
        if settings.lenses:
            runtime = GroupEntry(hass, entry.entry_id, entry.title, settings, client, registry.groups)
        else:
            runtime = Runtime(settings, client)
            if settings.relay_api_port is not None:
                runtime.relay = SharedRelay(
                    async_get_clientsession(hass), settings.relay_api_port, settings.relay_rtsp_port,
                    trusted_source_clock=settings.relay_source_clock,
                    atomic_ownership=settings.relay_atomic_ownership,
                )
    except (OSError, ValueError, KeyError, TypeError, PyEzvizError):
        if client is not None:
            await hass.async_add_executor_job(client.close_session)
        raise ConfigEntryError("Invalid private source, listener topology or group declaration") from None
    if isinstance(runtime, GroupEntry):
        registry.group_entries[entry.entry_id] = runtime
    else:
        registry.entries[entry.entry_id] = runtime
    entry.runtime_data = runtime
    runtime.status_changed = lambda: async_dispatcher_send(hass, status_signal(entry.entry_id))
    try:
        if isinstance(runtime, GroupEntry):
            runtime.initialize_relays()
        await hass.config_entries.async_forward_entry_setups(entry, _PLATFORMS)
    except BaseException:
        if await registry.close_config_entry(entry.entry_id):
            await hass.async_add_executor_job(client.close_session)
            registry.forget(entry.entry_id)
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NativeConfigEntry) -> bool:
    """Revoke all consumers and join before dropping platform/client ownership."""
    registry: IntegrationRegistry = hass.data[DOMAIN]
    if not await registry.close_config_entry(entry.entry_id):
        return False
    if not await hass.config_entries.async_unload_platforms(entry, _PLATFORMS):
        return False
    await hass.async_add_executor_job(entry.runtime_data.client.close_session)
    registry.forget(entry.entry_id)
    return True
