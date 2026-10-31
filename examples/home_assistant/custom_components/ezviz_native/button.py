"""Explicit re-arming of a stopped one-shot validation entry, never a preview."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NativeConfigEntry
from .const import status_signal
from .route import Runtime


async def async_setup_entry(
    hass: HomeAssistant, entry: NativeConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    if entry.runtime_data.relay is not None:
        async_add_entities([PrepareSessionButton(entry)])


class PrepareSessionButton(ButtonEntity):
    """Reload only after joined cleanup; concurrent presses cannot re-arm twice."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:restart"

    def __init__(self, entry: NativeConfigEntry) -> None:
        self.entry_id = entry.entry_id
        self.runtime: Runtime = entry.runtime_data
        self._attr_unique_id = f"{entry.entry_id}_prepare_session"
        self._attr_name = f"{entry.title} prepare new session"

    @property
    def available(self) -> bool:
        return (self.runtime.exhausted and self.runtime.active is None
                and not self.runtime.closing and not self.runtime.rearming)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(async_dispatcher_connect(
            self.hass, status_signal(self.entry_id), self._async_status_changed,
        ))

    @callback
    def _async_status_changed(self) -> None:
        self.async_write_ha_state()

    async def async_press(self) -> None:
        if not self.available:
            raise HomeAssistantError("Finish source cleanup before preparing a new session")
        self.runtime.rearming = True  # Reserve before the first await.
        self.runtime.status_changed()
        try:
            if not await self.hass.config_entries.async_reload(self.entry_id):
                raise HomeAssistantError("Session could not be prepared; entry reload required")
        finally:
            self.runtime.rearming = False
            self.runtime.status_changed()
