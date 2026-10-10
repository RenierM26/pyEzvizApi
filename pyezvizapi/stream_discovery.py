"""Caller-owned bounded reuse of successful local transport discovery."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
import math
from threading import Lock
import time
from typing import Literal

from .exceptions import PyEzvizError
from .stream_header import EzvizStreamHeader


@dataclass(frozen=True)
class LocalStreamDiscovery:
    """Negotiated transport/media metadata, never credentials or decoded proof."""

    source_kind: Literal["local-sdk", "local-sdk-ecdh"]
    stream_header: EzvizStreamHeader | None = None


class LocalStreamDiscoveryCache:
    """In-memory TTL/LRU cache; integrations own its lifetime and invalidation.

    Keys must represent endpoint, channel, credentials and metadata generation.
    AutoMediaStream supplies hashed keys and refreshes only after emitted input.
    A hit is a startup hint, not an authentication bypass or media decode proof.
    """

    def __init__(self, *, ttl: float = 300.0, max_entries: int = 32,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if not math.isfinite(ttl) or ttl <= 0:
            raise PyEzvizError("Discovery cache TTL must be positive and finite")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise PyEzvizError("Discovery cache capacity must be a positive integer")
        self._ttl = ttl
        self._max_entries = max_entries
        self._monotonic = monotonic
        self._entries: OrderedDict[str, tuple[float, LocalStreamDiscovery]] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> LocalStreamDiscovery | None:
        """Return an unexpired hint; cache reads do not extend its freshness."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if self._monotonic() >= entry[0]:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return entry[1]

    def remember(self, key: str, discovery: LocalStreamDiscovery) -> None:
        """Store successful discovery; evict oldest entries at capacity."""
        with self._lock:
            now = self._monotonic()
            expired = [identity for identity, entry in self._entries.items() if now >= entry[0]]
            for identity in expired:
                del self._entries[identity]
            self._entries[key] = (now + self._ttl, discovery)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def invalidate(self, key: str | None = None) -> None:
        """Forget one identity or all identities after configuration changes."""
        with self._lock:
            if key is None:
                self._entries.clear()
            else:
                self._entries.pop(key, None)
