"""Export only sanitized configuration/evidence, never file paths or secrets."""
from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import NativeConfigEntry
from .entry_runtime import GroupEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: NativeConfigEntry,
) -> dict[str, Any]:
    """Keep HA verification distinct from encoded/HTTP ingestion evidence."""
    runtime = entry.runtime_data
    settings = runtime.settings
    if isinstance(runtime, GroupEntry):
        return {
            "validation_session": runtime.session_status,
            "acquisition_attempts": runtime.group.attempts,
            "physical_cleanup_joined": runtime.group.joined,
            "lens_sessions": {key: lens.session_status for key, lens in runtime.lenses.items()},
            "last_delivery": runtime.group.last_receipt,
            "ha_frontend_verified": False,
        }
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
        "validation_session": runtime.session_status,
        "prepare_new_session_required": runtime.exhausted,
        "ha_frontend_verified": False,
    }
