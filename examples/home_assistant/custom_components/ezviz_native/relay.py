"""Explicit loopback go2rtc REST boundary, independent of HA private config."""
from __future__ import annotations

import asyncio
import secrets

from aiohttp import ClientError, ClientSession


class RelayError(Exception):
    """Sanitized relay failure; never include capability URLs."""


class SharedRelay:
    """Own only one random named upstream; no preload or acquisition at setup."""

    def __init__(self, session: ClientSession, api_port: int, rtsp_port: int,
                 *, trusted_source_clock: bool = False, atomic_ownership: bool = False) -> None:
        self._atomic_ownership = atomic_ownership
        self._ownership_token = secrets.token_hex(32)
        self._session = session
        self._api = f"http://127.0.0.1:{api_port}/api/streams"
        self.name = "ezviz_native_upstream_" + secrets.token_hex(16)
        self.url = f"rtsp://127.0.0.1:{rtsp_port}/{self.name}"
        if trusted_source_clock:
            self.url += "?source_clock=trusted"
        self._lock = asyncio.Lock()
        self._owned = False
        self._registered = False
        self._upstream: str | None = None
        self._closing = False

    async def source(self, upstream: str) -> str:
        """Register lazily, serialize cold readers, retain uncertain PATCH ownership."""
        async with self._lock:
            if self._closing:
                raise RelayError("Relay is closing")
            if self._registered:
                return self.url
            if self._owned:
                raise RelayError("Relay registration uncertain; unload required")
            try:
                async with asyncio.timeout(10):
                    if self._atomic_ownership:
                        # Reserve before sending: a timeout may follow a committed create.
                        self._owned = True
                        self._upstream = upstream
                        async with self._session.post(
                            self._api + "/owned", params={"name": self.name},
                            data={"src": upstream}, headers=self._ownership_headers(),
                            allow_redirects=False,
                        ) as response:
                            if (response.status != 201 or response.headers.get(
                                "X-Stream-Ownership") != "runtime-token-v1"):
                                raise RelayError("Atomic relay registration unavailable")
                        self._registered = True
                        return self.url
                    async with self._session.get(self._api, allow_redirects=False) as response:
                        if response.status != 200:
                            raise RelayError("Relay inventory failed")
                        streams = await response.json()
                        if not isinstance(streams, dict) or self.name in streams:
                            raise RelayError("Relay name unavailable")
                    # Reserve before mutation: timeout/cancellation may follow server commit.
                    self._upstream = upstream
                    self._owned = True
                    async with self._session.patch(
                        self._api, params={"name": self.name, "src": upstream},
                        allow_redirects=False,
                    ) as response:
                        if response.status != 200:
                            raise RelayError("Relay registration failed")
                    self._registered = True
            except (ClientError, TimeoutError, ValueError):
                raise RelayError("Relay registration failed") from None
            return self.url

    async def close(self) -> bool:
        """Narrow removal; retain uncertain ownership for explicit unload recovery."""
        async with self._lock:
            self._closing = True
            if not self._owned:
                return True
            try:
                async with asyncio.timeout(10):
                    removed = (await self._remove_atomic() if self._atomic_ownership
                               else await self._remove_legacy())
                    if not removed:
                        return False
            except (ClientError, TimeoutError, ValueError):
                return False
            self._owned = self._registered = False
            self._upstream = None
            return True

    async def _remove_atomic(self) -> bool:
        async with self._session.delete(
            self._api + "/owned", params={"name": self.name},
            headers=self._ownership_headers(), allow_redirects=False,
        ) as response:
            return (response.status == 204 and response.headers.get(
                "X-Stream-Ownership") == "runtime-token-v1")

    async def _remove_legacy(self) -> bool:
        owned = await self._owned_status()
        if owned is None:
            return False
        if owned:
            async with self._session.delete(
                self._api, params={"src": self.name}, allow_redirects=False,
            ) as response:
                if response.status not in {200, 404}:
                    # Runtime removal can succeed while config persistence fails.
                    async with self._session.get(
                        self._api, allow_redirects=False,
                    ) as check:
                        if check.status != 200:
                            return False
                        streams = await check.json()
                        if not isinstance(streams, dict) or self.name in streams:
                            return False
        return True

    def _ownership_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer " + self._ownership_token}

    async def _owned_status(self) -> bool | None:
        """False means absent, None uncertain/foreign; inventory GET does not preview."""
        # Best-effort preflight, not a lease: stock GET/DELETE is not atomic,
        # and active producer URLs may describe cached connections, not config.
        async with self._session.get(self._api, allow_redirects=False) as response:
            if response.status != 200:
                return None
            streams = await response.json()
            if not isinstance(streams, dict):
                return None
            if self.name not in streams:
                return False
            return True if self._matches_upstream(streams[self.name]) else None

    def _matches_upstream(self, stream: object) -> bool:
        """Reject observed reassignment or inventory that cannot confirm our source."""
        if self._upstream is None:
            return False
        if isinstance(stream, list):
            return stream == [self._upstream]
        if isinstance(stream, dict):
            producers = stream.get("producers")
            return (isinstance(producers, list) and len(producers) == 1
                    and isinstance(producers[0], dict)
                    and producers[0].get("url") == self._upstream)
        return False
