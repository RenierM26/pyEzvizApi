"""HA-owned, loopback-capability MPEG-TS delivery; never an external listener."""
from __future__ import annotations

import asyncio
from contextlib import aclosing
from dataclasses import dataclass, field
import hmac
import ipaddress
import logging
import secrets
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from pyezvizapi.client import EzvizClient
from pyezvizapi.clip import AutoClipSource
from pyezvizapi.native_stream import NativeMpegTsStream, native_mpegts_stream_from_client

from .config import Settings
from .const import MAX_ACTIVE, WRITE_TIMEOUT
from .relay import SharedRelay

_LOGGER = logging.getLogger(__name__)


@dataclass(eq=False, repr=False)
class Session:
    """Keep the source handle until joined, including failed-cleanup recovery."""

    owner: NativeMpegTsStream
    task: asyncio.Task[Any]
    response: web.StreamResponse | None = None
    write_bytes: int = 0
    write_calls: int = 0


@dataclass(repr=False)
class Runtime:
    """One explicitly selected track and at most one active HA ingest."""

    settings: Settings
    client: EzvizClient
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    active: Session | None = None
    closing: bool = False
    last_receipt: dict[str, Any] | None = None
    relay: SharedRelay | None = None
    acquisition_attempts: int = 0
    retry_rejections: int = 0

    def reserve_attempt(self) -> None:
        """Bound relay retries across EOF, disconnect and failure until reload."""
        if self.relay is not None and self.acquisition_attempts >= 1:
            self.retry_rejections += 1
            raise web.HTTPServiceUnavailable()
        self.acquisition_attempts += 1

    def make_owner(self) -> NativeMpegTsStream:
        """Only a verified HTTP request may construct the lazy source owner."""
        return native_mpegts_stream_from_client(
            self.client, self.settings.credentials.device_info.serial,
            source=AutoClipSource(mode="offline", credentials=self.settings.credentials,
                                  allow_cloud_fallback=False),
            options=self.settings.options, channel=self.settings.channel,
            nalu_header_size=self.settings.nalu_header_size,
        )


class Registry:
    """Constant bounded concurrency, explicit unload/recovery ownership."""

    def __init__(self) -> None:
        self.entries: dict[str, Runtime] = {}

    async def close_entry(self, entry_id: str) -> bool:
        """Revoke first; retain timed-out owners for explicit retry."""
        runtime = self.entries[entry_id]
        runtime.closing = True
        runtime.token = secrets.token_urlsafe(32)
        if session := runtime.active:
            if session.response is not None:
                session.response.force_close()
            if not session.task.done():
                session.task.cancel()
                await asyncio.gather(session.task, return_exceptions=True)
                if runtime.active is not None:
                    return False  # Do not repeat the handler's failed close budget.
            # An HTTP handler may already have exhausted its shutdown budget.
            # This explicit unload is a recovery operation, not implicit exit.
            if runtime.active is not None:
                try:
                    await session.owner.aclose()
                except Exception:  # Owner and sanitized evidence remain available.
                    return False
                runtime.active = None
        if runtime.relay is not None:
            return await runtime.relay.close()
        return True


class NativeStreamView(HomeAssistantView):
    """A private internal source URL for HA's native stream worker."""

    url = "/api/ezviz_native/{entry_id}/stream.ts"
    name = "api:ezviz_native:stream"
    # PyAV cannot present HA Bearer auth. Require BOTH a loopback socket peer
    # and an unguessable per-entry capability, not forwarded headers/remote IP.
    requires_auth = False

    def __init__(self, registry: Registry) -> None:
        self.registry = registry

    async def get(self, request: web.Request, entry_id: str) -> web.StreamResponse:
        """Authorize/reserve before acquisition; await every output write."""
        peer = request.transport.get_extra_info("peername") if request.transport else None
        try:
            loopback = bool(peer and ipaddress.ip_address(peer[0]).is_loopback)
        except ValueError:
            loopback = False
        runtime = self.registry.entries.get(entry_id)
        supplied = request.query.get("auth", "")
        if (not loopback or runtime is None or not supplied.isascii()
                or not hmac.compare_digest(supplied, runtime.token)):
            raise web.HTTPForbidden()
        if runtime.closing:
            raise web.HTTPServiceUnavailable()
        if (runtime.active is not None
                or sum(r.active is not None for r in self.registry.entries.values()) >= MAX_ACTIVE):
            raise web.HTTPTooManyRequests()
        runtime.reserve_attempt()
        task = asyncio.current_task()
        assert task is not None
        session = Session(runtime.make_owner(), task)
        runtime.active = session  # No await between admission check and ownership.
        response = web.StreamResponse(headers={
            "Content-Type": "video/mp2t", "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "X-Stream-Finite": "1" if runtime.settings.options.finite_source else "0",
        })
        session.response = response
        # A prepare/write failure must close an incomplete response, never
        # append a successful EOF to a failed live acquisition.
        complete = False
        try:
            async with session.owner, aclosing(session.owner.async_chunks()) as chunks:
                async for chunk in chunks:
                    async with asyncio.timeout(WRITE_TIMEOUT):
                        if not response.prepared:
                            await response.prepare(request)
                        await response.write(chunk)
                    session.write_bytes += len(chunk)
                    session.write_calls += 1
            # A successful EOF must follow joined source cleanup, not precede it.
            async with asyncio.timeout(WRITE_TIMEOUT):
                await response.write_eof()
            complete = True
            return response
        except asyncio.CancelledError:
            raise
        except Exception:
            # Do not log exception text, URLs, tokens, addresses or camera data.
            _LOGGER.warning("Native stream request failed; private source receipt retained")
            if not response.prepared:
                raise web.HTTPBadGateway() from None
            raise ConnectionResetError("Native source failed after response start") from None
        finally:
            if not complete and response.prepared and request.transport is not None:
                request.transport.close()
            runtime.last_receipt = {
                "source": session.owner.receipt,
                "http_write_bytes": session.write_bytes,
                "http_write_calls": session.write_calls,
                "ha_verified": False,
            }
            receipt = session.owner.receipt
            if receipt["worker_joined"] and receipt["cancel_joined"] and (
                receipt["source_closed"] or (receipt["source_packets"] == 0
                                              and not receipt["cleanup_error_types"])
            ):
                runtime.active = None


def source_url(hass: HomeAssistant, entry_id: str, runtime: Runtime) -> str:
    """Return a redacted-by-HA query capability, never camera credentials."""
    api = hass.config.api
    if api is None or api.use_ssl:
        raise ValueError("Validation integration requires HA HTTP without direct TLS")
    hosts = hass.http.server_host
    if hosts and not any(host in {"0.0.0.0", "127.0.0.1"} for host in hosts):
        raise ValueError("HA HTTP must listen on IPv4 loopback")
    return (f"http://127.0.0.1:{hass.http.server_port}/api/ezviz_native/"
            f"{entry_id}/stream.ts?auth={runtime.token}")
