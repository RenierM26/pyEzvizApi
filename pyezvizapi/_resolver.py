"""Explicit owner for a bounded lazy DNS worker, including stuck OS resolution."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
import math
from queue import Empty, Full, Queue
import socket
from threading import Event, Lock, Thread
from typing import Any, cast


class ResolverBusy(TimeoutError):
    """The single active and single queued resolver slots are occupied."""


class ResolverClosed(RuntimeError):
    """The resolver owner has closed this service."""


@dataclass
class _Request:
    host: str
    port: int
    cancelled: Event = field(default_factory=Event)
    result: Queue[tuple[bool, Any]] = field(default_factory=lambda: Queue(maxsize=1))

    def finish(self, succeeded: bool, result: Any) -> None:
        with suppress(Full):
            self.result.put_nowait((succeeded, result))


_STOP = object()


class BoundedResolver:
    """At most one active resolution and one queued request; no replacements.

    A timeout cannot kill platform getaddrinfo. close() cancels queued/caller
    waits and returns whether the owned worker exited within its join budget.
    """

    def __init__(self, resolve: Callable[..., list[tuple[Any, ...]]] | None = None) -> None:
        self._resolve = resolve
        self._jobs: Queue[_Request | object] = Queue(maxsize=1)
        self._lock = Lock()
        self._thread: Thread | None = None
        self._active: _Request | None = None
        self._closed = False

    def resolve(self, host: str, port: int, *, timeout: float | None) -> list[tuple[Any, ...]]:
        with self._lock:
            if self._closed:
                raise ResolverClosed("Hostname resolver is closed")
        if timeout is None:
            return (self._resolve or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("Resolver timeout must be positive and finite")
        try:
            finite = math.isfinite(timeout)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError("Resolver timeout must be positive and finite")
        job = _Request(host, port)
        with self._lock:
            if self._closed:
                raise ResolverClosed("Hostname resolver is closed")
            try:
                self._jobs.put_nowait(job)
            except Full as err:
                raise ResolverBusy("Hostname resolver is still busy") from err
            if self._thread is None:
                self._start_locked()
        try:
            succeeded, value = job.result.get(timeout=timeout)
        except Empty as err:
            job.cancelled.set()
            raise TimeoutError("Hostname resolution exceeded its deadline") from err
        except BaseException:
            job.cancelled.set()
            raise
        if not succeeded:
            raise value
        return cast(list[tuple[Any, ...]], value)

    def _start_locked(self) -> None:
        self._thread = Thread(target=self._run, name="pyezvizapi-dns", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            while True:
                try:
                    value = self._jobs.get(timeout=0.25)
                except Empty:
                    return
                if value is _STOP:
                    return
                job = cast(_Request, value)
                with self._lock:
                    if self._closed or job.cancelled.is_set():
                        continue
                    self._active = job
                try:
                    addresses = (self._resolve or socket.getaddrinfo)(
                        job.host, job.port, type=socket.SOCK_STREAM
                    )
                except Exception as err:
                    job.finish(False, err)
                else:
                    if not job.cancelled.is_set():
                        job.finish(True, addresses)
                finally:
                    with self._lock:
                        self._active = None
        finally:
            with self._lock:
                self._thread = None
                # A submission can race idle exit; do not orphan its queue.
                if not self._closed and not self._jobs.empty():
                    self._start_locked()

    def close(self, *, wait_seconds: float = 0.05) -> bool:
        """Cancel caller/queued work; never pretend a stuck OS call was killed."""
        if (
            isinstance(wait_seconds, bool)
            or not isinstance(wait_seconds, (int, float))
            or not 0 <= wait_seconds <= 60
        ):
            raise ValueError("Resolver close wait must be between zero and 60 seconds")
        with self._lock:
            self._closed = True
            if self._active is not None:
                self._active.cancelled.set()
                self._active.finish(False, ResolverClosed("Hostname resolver is closed"))
            while True:
                try:
                    value = self._jobs.get_nowait()
                except Empty:
                    break
                if isinstance(value, _Request):
                    value.cancelled.set()
                    value.finish(False, ResolverClosed("Hostname resolver is closed"))
            thread = self._thread
            if thread is not None:
                self._jobs.put_nowait(_STOP)
        if thread is not None:
            thread.join(timeout=max(0.0, wait_seconds))
            return not thread.is_alive()
        return True


DEFAULT_RESOLVER = BoundedResolver()
