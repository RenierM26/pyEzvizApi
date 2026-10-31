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
                 *, trusted_source_clock: bool = False) -> None:
        self._session = session
        self._api = f"http://127.0.0.1:{api_port}/api/streams"
        self.name = "ezviz_native_upstream_" + secrets.token_hex(16)
        self.url = f"rtsp://127.0.0.1:{rtsp_port}/{self.name}"
        if trusted_source_clock:
            self.url += "?source_clock=trusted"
        self._lock = asyncio.Lock()
        self._owned = False
        self._registered = False
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
                    async with self._session.get(self._api, allow_redirects=False) as response:
                        if response.status != 200:
                            raise RelayError("Relay inventory failed")
                        streams = await response.json()
                        if not isinstance(streams, dict) or self.name in streams:
                            raise RelayError("Relay name unavailable")
                    # Reserve before mutation: timeout/cancellation may follow server commit.
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
                    async with self._session.delete(
                        self._api, params={"src": self.name}, allow_redirects=False,
                    ) as response:
                        if response.status not in {200, 404}:
                            # go2rtc can remove runtime state but fail to save config
                            # (e.g. managed raw-config mode). Confirm removal explicitly.
                            async with self._session.get(
                                self._api, allow_redirects=False,
                            ) as check:
                                if check.status != 200:
                                    return False
                                streams = await check.json()
                                if not isinstance(streams, dict) or self.name in streams:
                                    return False
            except (ClientError, TimeoutError, ValueError):
                return False
            self._owned = self._registered = False
            return True
