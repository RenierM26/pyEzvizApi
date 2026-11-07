"""Bounded caller waits for scoped bootstrap HTTP, including slow bodies/DNS.

One lazy worker and one queued job are shared process-wide. Timed-out calls do
not create replacement workers. Ordinary HTTP remains synchronous and unchanged.
"""
from __future__ import annotations

from contextlib import suppress
from copy import copy
from dataclasses import dataclass, field
from queue import Empty, Full, Queue
import socket
from threading import Event, Lock, Thread
from typing import Any

import requests
from requests.cookies import RequestsCookieJar

from pyezvizapi._http_transport import isolated_session
from pyezvizapi._request_deadline import remaining_request_budget
from pyezvizapi.exceptions import PyEzvizError

MAX_BOOTSTRAP_BODY_BYTES = 8 * 1024 * 1024
_IDLE_SECONDS = 0.25


def _commit_cookies(
    target: RequestsCookieJar,
    initial: RequestsCookieJar,
    final: RequestsCookieJar,
) -> None:
    """Commit only the successful worker's cookie delta, including deletions."""
    before = {(cookie.domain, cookie.path, cookie.name): cookie for cookie in initial}
    after = {(cookie.domain, cookie.path, cookie.name): cookie for cookie in final}
    current = {(cookie.domain, cookie.path, cookie.name): cookie for cookie in target}
    for key in before.keys() - after.keys():
        # A later caller-side replacement is not the cookie this response expired.
        if key in current and vars(current[key]) == vars(before[key]):
            with suppress(KeyError):
                target.clear(*key)
    for key, cookie in after.items():
        if key not in before or vars(cookie) != vars(before[key]):
            target.set_cookie(copy(cookie))


def _response_socket(response: requests.Response) -> socket.socket | None:
    """Requests/urllib3 socket ownership adapter, isolated for compatibility tests."""
    connection = getattr(response.raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if isinstance(sock, socket.socket):
        return sock
    fp = getattr(getattr(response.raw, "_fp", None), "fp", None)
    sock = getattr(getattr(fp, "raw", None), "_sock", None)
    return sock if isinstance(sock, socket.socket) else None


@dataclass
class _HttpJob:
    session: requests.Session
    operation: str
    kwargs: dict[str, Any]
    cancelled: Event = field(default_factory=Event)
    result: Queue[tuple[bool, Any]] = field(default_factory=lambda: Queue(maxsize=1))
    lock: Lock = field(default_factory=Lock)
    wire: socket.socket | None = None
    delivered: requests.Response | None = None

    def abort(self) -> None:
        self.cancelled.set()
        with self.lock:
            wire = self.wire
            delivered = self.delivered
            self.delivered = None
        if wire is not None:
            with suppress(OSError):
                wire.shutdown(socket.SHUT_RDWR)
        if delivered is not None:
            delivered.close()

    def run(self) -> requests.Response:
        if self.cancelled.is_set():
            raise TimeoutError("Cloud bootstrap HTTP job cancelled before acquisition")
        response: requests.Response = getattr(self.session, self.operation)(**self.kwargs)
        accepted = False
        try:
            # Test/custom transports may return an already materialized response.
            content = response._content  # noqa: SLF001 -- requests response ownership adapter
            if not isinstance(content, bytes):
                with self.lock:
                    self.wire = _response_socket(response)
                if self.cancelled.is_set():
                    self.abort()
                    raise TimeoutError("Cloud bootstrap HTTP job cancelled")
                if self.wire is None and getattr(response.raw, "length_remaining", None) != 0:
                    raise PyEzvizError("Scoped bootstrap requires an interruptible HTTP response transport")
                parts: list[bytes] = []
                size = 0
                for chunk in response.iter_content(chunk_size=16384):
                    if self.cancelled.is_set():
                        raise TimeoutError("Cloud bootstrap HTTP job cancelled")
                    size += len(chunk)
                    if size > MAX_BOOTSTRAP_BODY_BYTES:
                        raise PyEzvizError("Cloud bootstrap response exceeds its byte limit")
                    parts.append(chunk)
                content = b"".join(parts)
                response._content = content  # noqa: SLF001
                response.__dict__["_content_consumed"] = True
            if len(content) > MAX_BOOTSTRAP_BODY_BYTES:
                raise PyEzvizError("Cloud bootstrap response exceeds its byte limit")
            if self.cancelled.is_set():
                raise TimeoutError("Cloud bootstrap HTTP job cancelled")
            accepted = True
            return response
        finally:
            with self.lock:
                self.wire = None
            if not accepted:
                response.close()


class _HttpWorker:
    """Own at most one active and one queued job; reclaim idle workers."""

    def __init__(self) -> None:
        self._jobs: Queue[_HttpJob] = Queue(maxsize=1)
        self._lock = Lock()
        self._thread: Thread | None = None

    def submit(self, job: _HttpJob) -> None:
        with self._lock:
            try:
                self._jobs.put_nowait(job)
            except Full as err:
                raise TimeoutError("Cloud bootstrap HTTP worker is busy") from err
            if self._thread is None:
                self._thread = Thread(target=self._run, name="pyezvizapi-http-budget", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                job = self._jobs.get(timeout=_IDLE_SECONDS)
            except Empty:
                with self._lock:
                    if self._jobs.empty():
                        self._thread = None
                        return
                continue
            try:
                response = job.run()
            except Exception as err:
                job.result.put_nowait((False, err))
            else:
                with job.lock:
                    cancelled = job.cancelled.is_set()
                    if not cancelled:
                        job.delivered = response
                        job.result.put_nowait((True, response))
                if cancelled:
                    response.close()


_WORKER = _HttpWorker()


def budgeted_http_call(session: requests.Session, operation: str, **kwargs: Any) -> requests.Response:
    """Bound the caller even if system DNS or server reads ignore socket totals.

    Borrow a detached session state, never mutate shared headers/cookies from a
    worker, and never spawn unbounded replacements for stuck system resolvers.
    """
    remaining = remaining_request_budget()
    if remaining is None:
        return getattr(session, operation)(**kwargs)
    borrowed = isolated_session(session)
    initial_cookies = borrowed.cookies.copy()
    if operation == "send" and isinstance(kwargs.get("request"), requests.PreparedRequest):
        kwargs["request"] = kwargs["request"].copy()
    job = _HttpJob(borrowed, operation, {**kwargs, "stream": True})
    _WORKER.submit(job)
    try:
        succeeded, value = job.result.get(timeout=remaining)
    except Empty as err:
        job.abort()
        raise TimeoutError("Cloud bootstrap HTTP exhausted capture deadline") from err
    except BaseException:
        job.abort()
        raise
    if not succeeded:
        raise value
    with job.lock:
        job.delivered = None
    _commit_cookies(session.cookies, initial_cookies, borrowed.cookies)
    return value
