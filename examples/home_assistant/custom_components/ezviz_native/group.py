"""Experimental HA-owned fixed-cold groups, separate from per-entry Runtime.

The caller declares a verified physical selector/profile and opaque credential
revision. No discovery, secret hashing, dynamic attach or automatic UI grouping.
All methods run on HA's event loop; only owner cleanup runs off-loop.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from contextlib import aclosing
from dataclasses import dataclass, field
import hmac
import ipaddress
import math
import secrets
from types import MappingProxyType
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from pyezvizapi.native_session import NativeMpegTsSession
from pyezvizapi.native_stream import NativeMpegTsStream, NativePacketStream, NativeStreamOptions

from .const import MAX_ACTIVE, WRITE_TIMEOUT
from .route import clock_headers


@dataclass(frozen=True, repr=False)
class GroupIdentity:
    """Explicit source identity, not camera secrets or inferred channel equality."""

    physical: str
    profile: str
    credential_revision: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (
            self.physical, self.profile, self.credential_revision,
        )):
            raise ValueError("Explicit physical, profile and credential revision required")


@dataclass(eq=False, repr=False)
class Lease:
    """An HTTP output lease never substitutes for its physical source owner."""

    member: str
    output: NativeMpegTsStream
    task: asyncio.Task[Any]
    response: web.StreamResponse | None = None


@dataclass(repr=False)
class Group:
    """One immutable manifest and one consumed attempt until explicit prepare."""

    identity: GroupIdentity
    options: Mapping[str, NativeStreamOptions]
    build: Callable[[], NativeMpegTsSession]
    owner: NativeMpegTsSession
    barrier_timeout: float
    tokens: dict[str, str] = field(default_factory=dict)
    leases: dict[str, Lease] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)
    attempts: int = 0
    terminal: bool = False
    closing: bool = False
    cleanup_pending: bool = False
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    close_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_receipt: dict[str, Any] | None = None

    @property
    def reserved(self) -> bool:
        """A cold barrier and failed join also retain a physical admission slot."""
        return bool(self.leases or self.cleanup_pending)

    @property
    def joined(self) -> bool:
        """Only the physical owner's receipt can establish cleanup success."""
        receipt = self.owner.physical_receipt
        return bool(receipt["worker_joined"] and receipt["cancel_joined"] and (
            receipt["source_closed"] or (receipt["source_packets"] == 0
                                        and not receipt["cleanup_error_types"])
        ))

    def rotate(self) -> None:
        """Revoke the complete manifest, never just the selected lens."""
        self.tokens = {member: secrets.token_urlsafe(32) for member in self.options}

    async def wait_ready(self) -> None:
        """No native read starts until every declared member has a lease."""
        try:
            async with asyncio.timeout(self.barrier_timeout):
                await self.ready.wait()
        except TimeoutError:
            await self.abort()
            raise web.HTTPServiceUnavailable() from None
        if self.terminal or self.closing:
            raise web.HTTPServiceUnavailable()

    async def close_owner(self) -> bool:
        """Retain the owner and admission slot after an uncertain join."""
        async with self.lock:
            self.cleanup_pending = True
            try:
                await self.owner.aclose()
            except Exception:
                return False
            finally:
                self.last_receipt = self.owner.receipt
            self.cleanup_pending = not self.joined
            return not self.cleanup_pending

    async def abort(self) -> bool:
        """End an incomplete manifest; no automatic acquisition retry."""
        self.terminal = True
        self.ready.set()
        return await self.close_owner()

    async def release(self, lease: Lease) -> None:
        """Close only this output while a healthy declared sibling is active."""
        try:
            receipt = self.owner.physical_receipt
            if not self.joined and (receipt["shutdown_timed_out"] or receipt["cleanup_error_types"]):
                self.cleanup_pending = True
            else:
                try:
                    await lease.output.aclose()
                except Exception:
                    self.cleanup_pending = True
        finally:
            if self.leases.get(lease.member) is lease:
                del self.leases[lease.member]
        if not self.ready.is_set():
            await self.abort()  # A missing cold member cannot leave a barrier alive.
        elif not self.leases:
            self.terminal = True
            # An output may already have spent its failed join budget. Retain it
            # for explicit recovery rather than silently repeating that budget.
            if not self.cleanup_pending:
                await self.close_owner()
            self.last_receipt = self.owner.receipt


class GroupRegistry:
    """Explicit declarations and global physical-source admission, not lens counts."""

    def __init__(self) -> None:
        self.groups: dict[str, Group] = {}
        self.members: dict[str, Group] = {}

    def declare(self, identity: GroupIdentity, members: dict[str, NativeStreamOptions],
                source_factory: Callable[[], NativePacketStream], *,
                media_key: str | bytes | None = None, nalu_header_size: int | None = None,
                barrier_timeout: float = 5.0, late_join: bool = False) -> Group:
        """Validate fixed membership before committing any registry mutation."""
        if (not isinstance(identity, GroupIdentity) or identity.physical in self.groups
                or not members or any(not isinstance(m, str) or not m.strip() for m in members)
                or any(member in self.members for member in members)):
            raise ValueError("Physical source and members must be explicitly unclaimed")
        if (isinstance(barrier_timeout, bool) or not isinstance(barrier_timeout, int | float)
                or not math.isfinite(barrier_timeout) or not 0 < barrier_timeout <= 30):
            raise ValueError("Cold barrier must be bounded to at most thirty seconds")
        choices = dict(members)

        def build() -> NativeMpegTsSession:
            return NativeMpegTsSession(source_factory, tuple(choices.values()),
                                       media_key=media_key, nalu_header_size=nalu_header_size,
                                       late_join=late_join)

        group = Group(identity, MappingProxyType(choices), build, build(), float(barrier_timeout))
        group.rotate()
        self.groups[identity.physical] = group
        self.members.update(dict.fromkeys(choices, group))
        return group

    def acquire(self, member: str, task: asyncio.Task[Any]) -> tuple[Group, Lease]:
        """Reserve synchronously before any await or source construction/start."""
        group = self.members[member]
        if member in group.leases:
            raise web.HTTPTooManyRequests()
        if group.closing or group.terminal or group.cleanup_pending or member in group.used:
            raise web.HTTPServiceUnavailable()
        if not group.attempts:
            if sum(g.reserved for g in self.groups.values()) >= MAX_ACTIVE:
                raise web.HTTPTooManyRequests()
            group.attempts = 1
        output = group.owner.outputs[tuple(group.options).index(member)]
        lease = Lease(member, output, task)
        group.leases[member] = lease
        group.used.add(member)
        if group.owner.late_join or len(group.leases) == len(group.options):
            group.ready.set()
        return group, lease

    async def prepare(self, physical: str) -> bool:
        """Whole-group recovery is lazy; rotate every capability after joining."""
        group = self.groups[physical]
        if (group.leases or not group.attempts or group.closing
                or any(self.members.get(member) is not group for member in group.options)):
            return False
        # Lock encompasses rebuild/rotation as well as cleanup. Concurrent
        # prepare calls must not each replace an already rearmed generation.
        async with group.lock:
            if (group.leases or not group.attempts or group.closing
                or any(self.members.get(member) is not group for member in group.options)):
                return False
            try:
                await group.owner.aclose()
            except Exception:
                group.cleanup_pending = True
                return False
            if (not group.joined or group.closing
                    or any(self.members.get(member) is not group for member in group.options)):
                group.cleanup_pending = True
                return False
            group.last_receipt = group.owner.receipt
            group.owner = group.build()
            group.rotate()
            group.attempts = 0
            group.used.clear()
            group.ready = asyncio.Event()
            group.terminal = group.cleanup_pending = False
            return True

    async def detach(self, member: str) -> bool:
        """Unload a lens without stopping a sibling already admitted at cold start.

        Removing a member before the barrier completes ends the whole attempt;
        silently shrinking an already declared manifest is not supported.
        """
        group = self.members[member]
        group.tokens[member] = secrets.token_urlsafe(32)
        group.used.add(member)
        del self.members[member]
        lease = group.leases.get(member)
        if lease is not None and not lease.task.done():
            lease.task.cancel()
            await asyncio.gather(lease.task, return_exceptions=True)
        if not any(g is group for g in self.members.values()):
            return await self.close(group.identity.physical)
        if not group.ready.is_set():
            return await group.abort()
        return not group.cleanup_pending

    async def close(self, physical: str) -> bool:
        """Revoke the full manifest before cancelling HTTP tasks or joining."""
        group = self.groups[physical]
        async with group.close_lock:
            if self.groups.get(physical) is not group:
                return True
            group.closing = True
            group.rotate()
            group.terminal = True
            group.ready.set()
            tasks = []
            for lease in tuple(group.leases.values()):
                if lease.response is not None:
                    lease.response.force_close()
                if lease.task is not asyncio.current_task() and not lease.task.done():
                    lease.task.cancel()
                    tasks.append(lease.task)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                if group.cleanup_pending:
                    return False
            if not await group.close_owner():
                return False
            for member in group.options:
                if self.members.get(member) is group:
                    del self.members[member]
            del self.groups[physical]
            return True


class GroupStreamView(HomeAssistantView):
    """Explicit test/prototype route; not registered by existing config entries."""

    url = "/api/ezviz_native_group/{member}/stream.ts"
    name = "api:ezviz_native_group:stream"
    requires_auth = False

    def __init__(self, registry: GroupRegistry) -> None:
        self.registry = registry

    async def get(self, request: web.Request, member: str) -> web.StreamResponse:
        """Require socket loopback and a revocable member capability."""
        peer = request.transport.get_extra_info("peername") if request.transport else None
        try:
            loopback = bool(peer and ipaddress.ip_address(peer[0]).is_loopback)
        except ValueError:
            loopback = False
        group = self.registry.members.get(member)
        supplied = request.query.get("auth", "")
        if (not loopback or group is None or not supplied.isascii()
                or not hmac.compare_digest(supplied, group.tokens[member])):
            raise web.HTTPForbidden()
        task = asyncio.current_task()
        assert task is not None
        group, lease = self.registry.acquire(member, task)
        response = web.StreamResponse(headers={
            "Content-Type": "video/mp2t", "Cache-Control": "no-store",
            "X-Accel-Buffering": "no", "X-Stream-Retry": "never",
            "X-Stream-Finite": "1" if lease.output.options.finite_source else "0",
        })
        lease.response = response
        complete = False
        try:
            await group.wait_ready()
            async with lease.output, aclosing(lease.output.async_chunks()) as chunks:
                async for chunk in chunks:
                    async with asyncio.timeout(WRITE_TIMEOUT):
                        if not response.prepared:
                            response.headers.update(clock_headers(lease.output))
                            await response.prepare(request)
                        await response.write(chunk)
            async with asyncio.timeout(WRITE_TIMEOUT):
                await response.write_eof()
            complete = True
            return response
        except asyncio.CancelledError:
            raise
        except web.HTTPException:
            raise
        except Exception:
            if not response.prepared:
                raise web.HTTPBadGateway() from None
            raise ConnectionResetError("Grouped source failed after response start") from None
        finally:
            if not complete and response.prepared and request.transport is not None:
                request.transport.close()
            await group.release(lease)
