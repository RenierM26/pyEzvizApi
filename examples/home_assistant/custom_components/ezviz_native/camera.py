"""Separate camera entity for one explicitly configured native video track."""
from __future__ import annotations

import asyncio
from contextvars import ContextVar

from homeassistant.components.camera import (
    Camera,
    CameraEntityFeature,
    WebRTCError,
)
from homeassistant.components.stream import Stream
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import NativeConfigEntry
from .completion import GroupFiniteDelivery, finite_source_host_available, maybe_finite_delivery
from .const import status_signal
from .entry_runtime import GroupEntry, LensRuntime
from .relay import RelayError
from .route import Runtime, source_url
from .webrtc_offer import receives_codec

_hls_source: ContextVar[bool] = ContextVar("ezviz_native_hls_source", default=False)


async def async_setup_entry(
    hass: HomeAssistant, entry: NativeConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Register without opening a transport or fetching a snapshot."""
    runtime = entry.runtime_data
    async_add_entities([NativeCamera(entry, lens) for lens in runtime.lenses.values()]
                       if isinstance(runtime, GroupEntry) else [NativeCamera(entry)])


class NativeCamera(Camera):
    """Use HA's own stream pipeline; no still image or player dependency."""

    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_should_poll = False
    _attr_brand = "EZVIZ"

    def __init__(self, entry: NativeConfigEntry, lens: LensRuntime | None = None) -> None:
        super().__init__()
        self.entry_id = entry.entry_id
        self._delivery_stop_lock = asyncio.Lock()
        self._delivery_create_lock = asyncio.Lock()
        self._finite_delivery: GroupFiniteDelivery | None = None
        self.runtime: Runtime | LensRuntime
        if lens is None:
            assert isinstance(entry.runtime_data, Runtime)
            self.runtime = entry.runtime_data
        else:
            self.runtime = lens
            self._attr_device_info = lens.entry.device_info
        self._attr_unique_id = (entry.entry_id if lens is None or lens.key == "primary"
                               else f"{entry.entry_id}_{lens.key}")
        self._attr_name = lens.name if lens is not None else entry.title
        # Source clocks already exist; do not enable wall-clock timestamp repair.
        self.stream_options = {"use_wallclock_as_timestamps": False}
        if self.runtime.settings.relay_native_opus:
            self.stream_options["preserve_initial_timestamps"] = True

    def _require_finite_host(self) -> None:
        if self.runtime.settings.relay_native_opus and (
            not finite_source_host_available()
            or not callable(getattr(Camera, "async_validate_webrtc_offer", None))
        ):
            raise HomeAssistantError("Native finite AV requires the public HA finite-source API")

    async def stream_source(self) -> str | None:
        """Return only the internal capability, never camera credentials."""
        if self.runtime.closing or self.runtime.exhausted or self.runtime.rearming:
            return None
        self._require_finite_host()
        upstream = (self.runtime.upstream(self.hass) if isinstance(self.runtime, LensRuntime)
                    else source_url(self.hass, self.entry_id, self.runtime))
        if self.runtime.relay is not None:
            token = self.runtime.token
            try:
                result = await self.runtime.relay.source(upstream)
                if (self.runtime.closing or self.runtime.exhausted or self.runtime.rearming
                        or token != self.runtime.token):
                    return None
                if self.runtime.settings.relay_native_opus and not _hls_source.get():
                    return result + "&video&audio=opus"
                return result
            except (RelayError, asyncio.CancelledError):
                if isinstance(self.runtime, LensRuntime):
                    self.runtime.entry.relay_failed()
                raise
        return upstream

    @callback
    def async_validate_webrtc_offer(self, offer_sdp: str) -> WebRTCError | None:
        """Preflight the explicit joint profile without claiming native signaling."""
        if self.runtime.settings.relay_native_opus:
            video = "H265" if self.runtime.settings.options.video_codec == "hevc" else "H264"
            for kind, codec, rate in (("video", video, 90000), ("audio", "opus", 48000)):
                if not receives_codec(offer_sdp, kind, codec, rate):
                    return WebRTCError(
                        f"unsupported_{kind}_codec",
                        f"This client cannot receive the configured native {codec} {kind} stream.",
                    )
        return None

    async def async_create_stream(self) -> Stream | None:
        """Keep HLS on original AAC while WebRTC requests the native Opus view."""
        token = _hls_source.set(True)
        try:
            return await self._async_create_native_stream()
        finally:
            _hls_source.reset(token)

    async def _async_create_native_stream(self) -> Stream | None:
        """Do not let HA's cached HLS stream bypass exhausted source admission."""
        if self.runtime.closing or self.runtime.exhausted or self.runtime.rearming:
            return None
        self._require_finite_host()
        async with self._delivery_create_lock:
            token = self.runtime.token
            if self.runtime.closing or self.runtime.exhausted or self.runtime.rearming:
                return None
            stream = await super().async_create_stream()
            if (self.runtime.closing or self.runtime.exhausted or self.runtime.rearming
                    or token != self.runtime.token):
                async with self._delivery_stop_lock:
                    await self._stop_stream_owned()
                return None
            if (stream is not None and isinstance(self.runtime, LensRuntime)
                    and (self._finite_delivery is None or self._finite_delivery.stream is not stream)):
                self._finite_delivery = maybe_finite_delivery(self.hass, self.runtime, stream)
            if self.runtime.settings.relay_native_opus and self._finite_delivery is None:
                raise HomeAssistantError("Native finite AV requires the public HA finite-source API")
            return stream

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
        if isinstance(self.runtime, LensRuntime):
            entry, key = self.runtime.entry, self.runtime.key
            stopper = self._async_stop_aborted_delivery
            entry.stoppers[key] = stopper

            def remove_stopper() -> None:
                if entry.stoppers.get(key) is stopper:
                    entry.stoppers.pop(key)

            self.async_on_remove(remove_stopper)
        self.async_on_remove(async_dispatcher_connect(
            self.hass, status_signal(self.entry_id), self._async_delivery_changed,
        ))

    @callback
    def _async_delivery_changed(self) -> None:
        # Clean finite input may still be draining downstream queues. Do not
        # tear down an accepted final picture just because its native owner ended.
        receipt = self.runtime.last_receipt
        aborted = self.runtime.exhausted and (
            (receipt is not None and not receipt["source"]["finite_source_end"])
            or (isinstance(self.runtime, LensRuntime) and receipt is None)
        )
        self._attr_available = not (self.runtime.closing or aborted)
        self.async_write_ha_state()
        if aborted:
            self.hass.async_create_task(self._async_stop_aborted_delivery())

    async def _async_stop_aborted_delivery(self) -> None:
        """Provider refresh stops WebRTC, not the separate native HLS retry worker."""
        if self._finite_delivery is not None:
            self._finite_delivery.revoke()
        async with self._delivery_create_lock, self._delivery_stop_lock:
            await self.async_refresh_providers()
            await self._stop_stream_owned()

    async def _async_stop_stream(self) -> None:
        async with self._delivery_create_lock, self._delivery_stop_lock:
            await self._stop_stream_owned()

    async def _stop_stream_owned(self) -> None:
        if self._finite_delivery is not None:
            delivery, self._finite_delivery = self._finite_delivery, None
            await delivery.close()
        stream = self.stream
        if stream is not None:
            stream.dynamic_stream_settings.preload_stream = False
            for provider in list(stream.outputs().values()):
                await stream.remove_provider(provider)
            await stream.stop()
            if self.stream is stream:
                self.stream = None  # Rearm must not retain an old capability URL.

    async def async_camera_image(self, width: int | None = None,
                                 height: int | None = None) -> bytes | None:
        """No implicit preview acquisition for still images."""
        return None

    async def async_will_remove_from_hass(self) -> None:
        """Stop HA ingest too, even if preload was enabled during validation."""
        await self._async_stop_stream()
        await super().async_will_remove_from_hass()
