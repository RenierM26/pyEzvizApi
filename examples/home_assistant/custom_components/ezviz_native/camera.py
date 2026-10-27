"""Separate camera entity for one explicitly configured native video track."""
from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NativeConfigEntry
from .route import Runtime, source_url


async def async_setup_entry(
    hass: HomeAssistant, entry: NativeConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Register without opening a transport or fetching a snapshot."""
    async_add_entities([NativeCamera(entry)])


class NativeCamera(Camera):
    """Use HA's own stream pipeline; no still image or player dependency."""

    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_should_poll = False
    _attr_brand = "EZVIZ"

    def __init__(self, entry: NativeConfigEntry) -> None:
        super().__init__()
        self.entry_id = entry.entry_id
        self.runtime: Runtime = entry.runtime_data
        self._attr_unique_id = entry.entry_id
        self._attr_name = entry.title
        # Source clocks already exist; do not enable wall-clock timestamp repair.
        self.stream_options = {"use_wallclock_as_timestamps": False}

    async def stream_source(self) -> str | None:
        """Return only the internal capability, never camera credentials."""
        if self.runtime.closing:
            return None
        return source_url(self.hass, self.entry_id, self.runtime)

    async def async_camera_image(self, width: int | None = None,
                                 height: int | None = None) -> bytes | None:
        """No implicit preview acquisition for still images."""
        return None

    async def async_will_remove_from_hass(self) -> None:
        """Stop HA ingest too, even if preload was enabled during validation."""
        if self.stream is not None:
            self.stream.dynamic_stream_settings.preload_stream = False
            for provider in list(self.stream.outputs().values()):
                await self.stream.remove_provider(provider)
            await self.stream.stop()
        await super().async_will_remove_from_hass()
