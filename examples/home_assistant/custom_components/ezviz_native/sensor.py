"""Persistent session status, including when the camera entity is unavailable."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.core import HomeAssistant, callback
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
        async_add_entities([SessionStatusSensor(entry)])


class SessionStatusSensor(SensorEntity):
    """Do not hide recovery guidance when HA removes unavailable camera attributes."""

    _attr_should_poll = False
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry: NativeConfigEntry) -> None:
        self._attr_options = ["ready", "streaming", "ended", "failed", "cleanup_pending", "closing"]
        self.entry_id = entry.entry_id
        self.runtime: Runtime = entry.runtime_data
        self._attr_unique_id = f"{entry.entry_id}_session_status"
        self._attr_name = f"{entry.title} validation session"

    @property
    def native_value(self) -> str:
        return self.runtime.session_status

    @property
    def extra_state_attributes(self) -> dict[str, bool | int | str]:
        return {
            "prepare_new_session_required": self.runtime.exhausted,
            "native_acquisition_attempts": self.runtime.acquisition_attempts,
            "observed_video_codec": self.runtime.settings.options.video_codec,
            "recovery": self.recovery_guidance,
            "playback_requirement": (
                "HEVC needs a compatible browser or app; video is not converted"
                if self.runtime.settings.options.video_codec == "hevc"
                else "H.264-compatible client"
            ),
        }

    @property
    def recovery_guidance(self) -> str:
        if self.runtime.active is not None and self.runtime.delivery_ended:
            return "Cleanup has not joined; retry entry unload or reload"
        if self.runtime.exhausted:
            return "Prepare a new session, then reopen the camera"
        return "Open the camera to start" if self.runtime.active is None else "Close viewers to stop"

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(async_dispatcher_connect(
            self.hass, status_signal(self.entry_id), self._async_status_changed,
        ))

    @callback
    def _async_status_changed(self) -> None:
        self.async_write_ha_state()
