"""Export only sanitized configuration/evidence, never file paths or secrets."""
from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import NativeConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: NativeConfigEntry,
) -> dict[str, Any]:
    """Keep HA verification distinct from encoded/HTTP ingestion evidence."""
    runtime = entry.runtime_data
    settings = runtime.settings
    return {
        "preview_channel": settings.channel,
        "video_id": settings.options.selection.video_id,
        "audio_id": settings.options.selection.audio_id,
        "video_codec": settings.options.video_codec,
        "closing": runtime.closing,
        "active": runtime.active is not None,
        "last_delivery": runtime.last_receipt,
        "shared_relay": runtime.relay is not None,
        "acquisition_attempts": runtime.acquisition_attempts,
        "retry_rejections": runtime.retry_rejections,
        "ha_frontend_verified": False,
    }
