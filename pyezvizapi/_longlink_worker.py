"""Single-owner reconnect lifecycle for channel-99 sessions."""

from __future__ import annotations

from collections.abc import Callable
import logging
from threading import Event, Lock, Thread, current_thread
from typing import Protocol

_LOGGER = logging.getLogger(__name__)


class PushSession(Protocol):
    """One bounded, interruptible LBS/MQTT session owned by the worker."""

    def run(self, stopped: Event) -> None: ...
    def close(self) -> None: ...


class PushWorker:
    """Build fresh LBS/MQTT credentials after every disconnect.

    The factory must not perform network I/O. Session.run must respect stopped,
    and close must interrupt pending network operations. No paho reconnect loop
    is used: reconnecting with an old session key is not sufficient.
    """

    def __init__(self, factory: Callable[[], PushSession], *, retry_delay: float = 30) -> None:
        if retry_delay <= 0:
            raise ValueError("Retry delay must be positive")
        self.factory = factory
        self.retry_delay = retry_delay
        self._lock = Lock()
        self._stopped = Event()
        self._thread: Thread | None = None
        self._session: PushSession | None = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                if self._stopped.is_set():
                    raise RuntimeError("Previous push worker is still stopping")
                return
            self._stopped.clear()
            self._thread = Thread(target=self._run, name="ezviz-channel99", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5) -> None:
        """Signal stop and interrupt I/O; never join the callback's own thread."""
        with self._lock:
            self._stopped.set()
            session, thread = self._session, self._thread
        if session is not None:
            self._close(session)
        if thread is not None and thread is not current_thread():
            thread.join(timeout)
            if thread.is_alive():
                raise TimeoutError("Push worker did not stop within deadline")

    @staticmethod
    def _close(session: PushSession) -> None:
        try:
            session.close()
        except Exception:
            # Exception messages can contain remote URLs or credentials.
            _LOGGER.warning("Channel-99 session cleanup failed")

    def _run(self) -> None:
        while not self._stopped.is_set():
            session: PushSession | None = None
            try:
                with self._lock:
                    if self._stopped.is_set():
                        return
                    session = self.factory()
                    self._session = session
                session.run(self._stopped)
            except Exception:
                if not self._stopped.is_set():
                    _LOGGER.warning("Channel-99 connection interrupted; retry scheduled")
            finally:
                if session is not None:
                    self._close(session)
                with self._lock:
                    self._session = None
            if self._stopped.wait(self.retry_delay):
                return
