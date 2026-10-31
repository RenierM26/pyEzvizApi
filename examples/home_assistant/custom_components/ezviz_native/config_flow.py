"""Explicit private-file and observed-track configuration; no discovery probes."""
from __future__ import annotations

import hashlib
from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import selector
import probatio as vol

from pyezvizapi.exceptions import PyEzvizError

from .config import load_settings
from .const import DOMAIN

SCHEMA = vol.Schema({
    vol.Required("name", default="EZVIZ Native validation"): str,
    vol.Required("credentials_path"): str,
    vol.Required("channel", default=0): vol.All(vol.Coerce(int), vol.Range(min=0, max=255)),
    vol.Required("video_id"): vol.All(vol.Coerce(int), vol.Range(min=0, max=511)),
    vol.Required("audio_id", default=-1): vol.All(vol.Coerce(int), vol.Range(min=-1, max=511)),
    vol.Required("video_codec", default="hevc"): selector.SelectSelector(
        selector.SelectSelectorConfig(options=["h264", "hevc"])),
    vol.Required("nalu_header_size", default=2): vol.In([1, 2]),
    vol.Optional("relay_api_port"): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
    vol.Optional("relay_rtsp_port", default=8554): vol.All(
        vol.Coerce(int), vol.Range(min=1, max=65535)),
})


class NativeFlow(ConfigFlow, domain=DOMAIN):
    """The operator supplies an already observed camera/profile/lens mapping."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                settings = await self.hass.async_add_executor_job(load_settings, user_input)
            except (OSError, ValueError, KeyError, TypeError, PyEzvizError):
                errors["base"] = "invalid_settings"
            else:
                identity = (f"{settings.credentials.device_info.serial}:"
                            f"{settings.channel}:{settings.options.selection.video_id}")
                await self.async_set_unique_id(hashlib.sha256(identity.encode()).hexdigest())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=user_input["name"], data=user_input)
        return self.async_show_form(step_id="user", data_schema=SCHEMA, errors=errors)
