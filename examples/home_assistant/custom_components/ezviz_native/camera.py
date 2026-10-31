"""Separate camera entity for one explicitly configured native video track."""
from __future__ import annotations

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.components.stream import Stream
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NativeConfigEntry
from .const import status_signal
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
        if self.runtime.closing or self.runtime.exhausted:
            return None
        upstream = source_url(self.hass, self.entry_id, self.runtime)
        if self.runtime.relay is not None:
            return await self.runtime.relay.source(upstream)
        return upstream

    async def async_create_stream(self) -> Stream | None:
        """Do not let HA's cached HLS stream bypass exhausted source admission."""
        if self.runtime.closing or self.runtime.exhausted:
            return None
        return await super().async_create_stream()

    @property
    def extra_state_attributes(self) -> dict[str, str | int | bool]:
        """Sanitized recovery guidance; no claim of browser HEVC capability."""
        return {
            "validation_session": self.runtime.session_status,
            "native_acquisition_attempts": self.runtime.acquisition_attempts,
            "prepare_new_session_required": self.runtime.exhausted,
            "observed_video_codec": self.runtime.settings.options.video_codec,
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(async_dispatcher_connect(
            self.hass, status_signal(self.entry_id), self._async_delivery_changed,
        ))

    @callback
    def _async_delivery_changed(self) -> None:
        # Clean finite input may still be draining downstream queues. Do not
        # tear down an accepted final picture just because its native owner ended.
        receipt = self.runtime.last_receipt
        aborted = self.runtime.exhausted and receipt is not None and not (
            receipt["source"]["finite_source_end"]
        )
        self._attr_available = not (self.runtime.closing or aborted)
        self.async_write_ha_state()
        if aborted:
            self.hass.async_create_task(self._async_stop_aborted_delivery())

    async def _async_stop_aborted_delivery(self) -> None:
        """Provider refresh stops WebRTC, not the separate native HLS retry worker."""
        await self.async_refresh_providers()
        await self._async_stop_stream()

    async def _async_stop_stream(self) -> None:
        if self.stream is not None:
            self.stream.dynamic_stream_settings.preload_stream = False
            for provider in list(self.stream.outputs().values()):
                await self.stream.remove_provider(provider)
            await self.stream.stop()

    async def async_camera_image(self, width: int | None = None,
                                 height: int | None = None) -> bytes | None:
        """No implicit preview acquisition for still images."""
        return None

    async def async_will_remove_from_hass(self) -> None:
        """Stop HA ingest too, even if preload was enabled during validation."""
        await self._async_stop_stream()
        await super().async_will_remove_from_hass()
