"""Explicit physical-entry composition; entities own lens views, not transports."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo

from pyezvizapi.client import EzvizClient
from pyezvizapi.clip import AutoClipSource
from pyezvizapi.native_stream import NativePacketStream

from .config import Settings
from .const import DOMAIN
from .group import Group, GroupIdentity, GroupRegistry
from .relay import SharedRelay
from .route import Registry, physical_key, validate_http


class GroupEntry:
    """One credential/profile generation, persistent lens identities and recovery."""

    def __init__(self, hass: HomeAssistant, entry_id: str, title: str, settings: Settings,
                 client: EzvizClient, registry: GroupRegistry) -> None:
        self.hass, self.entry_id, self.settings, self.client = hass, entry_id, settings, client
        self.registry = registry
        self.device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)},
                                      manufacturer="EZVIZ", name=title)
        self.closing = self.rearming = self.recovery_pending = False
        self.stoppers: dict[str, Callable[[], Awaitable[None]]] = {}
        self.status_changed: Callable[[], None] = lambda: None
        assert settings.group_profile is not None and settings.credential_revision is not None
        choices = {self.member("primary"): settings.options}
        choices.update({self.member(lens.key): replace(settings.options, selection=lens.selection)
                        for lens in settings.lenses})
        self.group = registry.declare(
            GroupIdentity(physical_key(settings), settings.group_profile, settings.credential_revision),
            choices, self.make_source, media_key=settings.credentials.media_key,
            nalu_header_size=settings.nalu_header_size, late_join=True,
        )
        self.group.status_changed = self.notify
        self.lenses = {"primary": LensRuntime(self, "primary", title, settings)}
        self.lenses.update({lens.key: LensRuntime(
            self, lens.key, lens.name, replace(settings, options=choices[self.member(lens.key)]),
        ) for lens in settings.lenses})

    def initialize_relays(self) -> None:
        """Lazy relay construction runs under setup's retained-owner rollback."""
        self._new_relays()

    def notify(self) -> None:
        """Resolve the current dispatcher after setup has installed it."""
        self.status_changed()

    def member(self, key: str) -> str:
        return f"{self.entry_id}_{key}"

    def make_source(self) -> NativePacketStream:
        """The sole acquisition site: supplied local credentials, no fallback/login."""
        return self.client.open_stream(
            self.settings.credentials.device_info.serial,
            source=AutoClipSource(mode="offline", credentials=self.settings.credentials,
                                  allow_cloud_fallback=False), channel=self.settings.channel,
        )

    def _new_relays(self) -> None:
        assert self.settings.relay_api_port is not None
        session = async_get_clientsession(self.hass)
        for lens in self.lenses.values():
            lens.relay = SharedRelay(
                session, self.settings.relay_api_port, self.settings.relay_rtsp_port,
                trusted_source_clock=True, atomic_ownership=True,
            )

    @property
    def can_prepare(self) -> bool:
        return ((bool(self.group.attempts) or self.recovery_pending) and not self.group.leases
                and not self.closing and not self.rearming)

    @property
    def session_status(self) -> str:
        if self.closing:
            return "closing"
        if self.rearming:
            return "preparing"
        if self.group.cleanup_pending or self.recovery_pending:
            return "cleanup_pending"
        if self.group.leases:
            return "streaming"
        if self.group.attempts:
            receipt = self.group.last_receipt
            return "failed" if receipt and (receipt.get("error_type")
                                             or receipt.get("status") == "failed") else "ended"
        return "ready"

    def relay_failed(self) -> None:
        """Uncertain registration is recoverable even before a preview attempt."""
        self.recovery_pending = self.group.paused = True
        self.group.rotate()
        self.status_changed()

    async def _stop_providers(self) -> bool:
        results = await asyncio.gather(*(stop() for stop in tuple(self.stoppers.values())),
                                       return_exceptions=True)
        return all(not isinstance(result, BaseException) for result in results)

    async def _close_relays(self) -> bool:
        results = await asyncio.gather(*(lens.relay.close() for lens in self.lenses.values()
                                            if lens.relay is not None),
                                       return_exceptions=True)
        return all(result is True for result in results)

    async def prepare(self) -> bool:
        """Revoke and stop old consumers before lazy whole-group re-arm."""
        if not self.can_prepare:
            return False
        self.rearming = self.group.paused = True  # No await before exclusion/revocation.
        self.group.rotate()
        self.status_changed()
        success = False
        try:
            if not await self._stop_providers() or not await self.group.close_owner():
                return False
            if not await self._close_relays():
                return False
            if not await self.registry.prepare(self.group.identity.physical,
                                               allow_unused=self.recovery_pending):
                return False
            self._new_relays()  # Construction/register-source lookup do not acquire.
            success = True
            return True
        except Exception:
            return False  # Retain the paused generation; no private error text to UI.
        finally:
            self.recovery_pending = not success
            self.group.paused = not success
            self.rearming = False
            self.status_changed()

    async def close(self) -> bool:
        """Retain entry/client/uncertain relay handles until every cleanup succeeds."""
        self.closing = self.group.paused = True
        self.group.rotate()
        self.status_changed()
        providers = await self._stop_providers()
        physical = (await self.registry.close(self.group.identity.physical)
                    if self.registry.groups.get(self.group.identity.physical) is self.group
                    else self.group.joined)
        relays = await self._close_relays()
        return providers and physical and relays


class LensRuntime:
    """Entity-facing view; never owns or replaces the physical session."""

    def __init__(self, entry: GroupEntry, key: str, name: str, settings: Settings) -> None:
        self.entry, self.key, self.name, self.settings = entry, key, name, settings
        self.relay: SharedRelay | None = None

    @property
    def group(self) -> Group:
        return self.entry.group

    @property
    def member(self) -> str:
        return self.entry.member(self.key)

    @property
    def active(self) -> object | None:
        return self.group.leases.get(self.member)

    @property
    def closing(self) -> bool:
        return self.entry.closing or self.group.closing

    @property
    def rearming(self) -> bool:
        return self.entry.rearming or self.group.paused

    @property
    def exhausted(self) -> bool:
        return self.group.terminal or (self.member in self.group.used and self.active is None)

    @property
    def acquisition_attempts(self) -> int:
        return self.group.attempts

    @property
    def retry_rejections(self) -> int:
        return self.group.retry_rejections

    @property
    def delivery_ended(self) -> bool:
        return self.exhausted

    @property
    def last_receipt(self) -> dict[str, Any] | None:
        if self.member not in self.group.used:
            return None
        index = tuple(self.group.options).index(self.member)
        receipt = self.group.owner.outputs[index].receipt
        receipt["finite_source_end"] = (self.group.owner.physical_receipt["finite_source_end"]
                                        and receipt["status"] == "completed")
        return {"source": receipt, "ha_verified": False}

    @property
    def session_status(self) -> str:
        shared = self.entry.session_status
        if shared in {"closing", "preparing", "cleanup_pending"}:
            return shared
        if self.active is not None:
            return "streaming"
        if self.exhausted:
            if shared == "failed":
                return "failed"
            receipt = self.last_receipt
            return "failed" if receipt and receipt["source"]["error_type"] else "ended"
        return "ready"

    def upstream(self, hass: HomeAssistant) -> str:
        # Reuse the existing strict HTTP/IPv4-listener validation, not its route.
        validate_http(hass)
        return (f"http://127.0.0.1:{hass.http.server_port}/api/ezviz_native_group/"
                f"{self.member}/stream.ts?auth={self.token}")

    @property
    def token(self) -> str:
        return self.group.tokens[self.member]


class IntegrationRegistry(Registry):
    """One admission authority shared by old entries and explicit physical groups."""

    def __init__(self) -> None:
        super().__init__()
        self.groups = GroupRegistry(self.admission)
        self.group_entries: dict[str, GroupEntry] = {}

    async def close_config_entry(self, entry_id: str) -> bool:
        if entry_id in self.group_entries:
            return await self.group_entries[entry_id].close()
        return await self.close_entry(entry_id)

    def forget(self, entry_id: str) -> None:
        self.group_entries.pop(entry_id, None)
        self.entries.pop(entry_id, None)
