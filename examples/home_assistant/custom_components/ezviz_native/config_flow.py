"""Explicit private-file and observed-track configuration; no discovery probes."""
from __future__ import annotations

import hashlib
from typing import Any

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import selector
import probatio as vol

from pyezvizapi.exceptions import PyEzvizError

from .config import Settings, load_settings
from .const import DOMAIN

SCHEMA = vol.Schema({
    vol.Required("name", default="EZVIZ Native validation"): str,
    vol.Optional("configure_lenses", default=False): bool,
    vol.Required("credentials_path"): str,
    vol.Required("channel", default=0): vol.All(vol.Coerce(int), vol.Range(min=0, max=255)),
    vol.Required("video_id"): vol.All(vol.Coerce(int), vol.Range(min=0, max=511)),
    vol.Required("audio_id", default=-1): vol.All(vol.Coerce(int), vol.Range(min=-1, max=511)),
    vol.Required("video_codec", default="hevc"): selector.SelectSelector(
        selector.SelectSelectorConfig(options=["h264", "hevc"])),
    vol.Required("nalu_header_size", default=2): vol.In([1, 2]),
    vol.Optional("relay_source_clock", default=False): bool,
    vol.Optional("relay_atomic_ownership", default=False): bool,
    vol.Optional("relay_api_port"): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
    vol.Optional("relay_rtsp_port", default=8554): vol.All(
        vol.Coerce(int), vol.Range(min=1, max=65535)),
})


class NativeFlow(ConfigFlow, domain=DOMAIN):
    """The operator supplies an already observed camera/profile/lens mapping."""

    VERSION = 1

    def __init__(self) -> None:
        self._pending: dict[str, Any] = {}

    async def _finish(self, data: dict[str, Any], settings: Settings) -> ConfigFlowResult:
        selector = "group" if settings.lenses else str(settings.options.selection.video_id)
        identity = f"{settings.credentials.device_info.serial}:{settings.channel}:{selector}"
        await self.async_set_unique_id(hashlib.sha256(identity.encode()).hexdigest())
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=data["name"], data=data)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = dict(user_input)
            multiple = data.pop("configure_lenses", False)
            try:
                settings = await self.hass.async_add_executor_job(load_settings, data)
                if multiple and not (settings.relay_api_port is not None
                                     and settings.relay_source_clock
                                     and settings.relay_atomic_ownership):
                    raise ValueError("Grouped lenses require explicit relay contracts")
            except (OSError, ValueError, KeyError, TypeError, PyEzvizError):
                errors["base"] = "invalid_settings"
            else:
                if multiple:
                    self._pending = data
                    return await self.async_step_lenses()
                return await self._finish(data, settings)
        return self.async_show_form(step_id="user", data_schema=SCHEMA, errors=errors)

    async def async_step_lenses(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = dict(self._pending)
            data["group_profile"] = user_input["group_profile"]
            data["credential_revision"] = user_input["credential_revision"]
            child = {"lens_id": user_input["lens_id"], "name": user_input["lens_name"],
                     "video_id": user_input["video_id"], "audio_id": user_input["audio_id"]}
            data["lenses"] = [*data.get("lenses", []), child]
            more = user_input.get("add_another", False)
            try:
                settings = await self.hass.async_add_executor_job(load_settings, data)
                if more and len(settings.lenses) >= 3:
                    raise ValueError("All four declared lens slots are used")
            except (OSError, ValueError, KeyError, TypeError, PyEzvizError):
                errors["base"] = "invalid_settings"
            else:
                if not more:
                    return await self._finish(data, settings)
                self._pending = data
        schema = vol.Schema({
            vol.Required("group_profile", default=self._pending.get("group_profile", "")): str,
            vol.Required("credential_revision", default=self._pending.get("credential_revision", "")): str,
            vol.Required("lens_id"): str,
            vol.Required("lens_name"): str,
            vol.Required("video_id"): vol.All(vol.Coerce(int), vol.Range(min=0, max=511)),
            vol.Required("audio_id", default=-1): vol.All(vol.Coerce(int), vol.Range(min=-1, max=511)),
            vol.Optional("add_another", default=False): bool,
        })
        return self.async_show_form(step_id="lenses", data_schema=schema, errors=errors)
