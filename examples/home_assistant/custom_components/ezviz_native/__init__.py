"""Temporary upstream-oriented native delivery validation, not cloud discovery."""
from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError

from .config import load_settings
from .const import DOMAIN
from .route import NativeStreamView, Registry, Runtime, source_url

_LOGGER = logging.getLogger(__name__)
type NativeConfigEntry = ConfigEntry[Runtime]


async def async_setup_entry(hass: HomeAssistant, entry: NativeConfigEntry) -> bool:
    """Read private configuration only; preview begins on HA's HTTP request."""
    try:
        settings = await hass.async_add_executor_job(load_settings, dict(entry.data))
        client = await hass.async_add_executor_job(EzvizClient)
        runtime = Runtime(settings, client)
    except (OSError, ValueError, KeyError, TypeError, PyEzvizError):
        raise ConfigEntryError("Invalid private native source configuration") from None
    try:
        source_url(hass, entry.entry_id, runtime)
    except ValueError:
        raise ConfigEntryError(
            "Validation requires plain HA HTTP on IPv4 loopback; direct TLS is not supported"
        ) from None
    registry = hass.data.get(DOMAIN)
    if registry is None:
        registry = hass.data[DOMAIN] = Registry()
        hass.http.register_view(NativeStreamView(registry))

        async def stop(_event: object) -> None:
            results = await asyncio.gather(
                *(registry.close_entry(key) for key in list(registry.entries)),
                return_exceptions=True,
            )
            if any(result is not True for result in results):
                _LOGGER.error("Native source shutdown incomplete; owner retained")

        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, stop)
    registry.entries[entry.entry_id] = entry.runtime_data = runtime
    await hass.config_entries.async_forward_entry_setups(entry, [Platform.CAMERA])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NativeConfigEntry) -> bool:
    """Revoke and join active owners before dropping platform/client ownership."""
    registry: Registry = hass.data[DOMAIN]
    if not await registry.close_entry(entry.entry_id):
        return False
    if not await hass.config_entries.async_unload_platforms(entry, [Platform.CAMERA]):
        return False
    await hass.async_add_executor_job(entry.runtime_data.client.close_session)
    registry.entries.pop(entry.entry_id)
    return True
