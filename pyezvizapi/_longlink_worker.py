"""Single-owner reconnect lifecycle for channel-99 sessions."""

from __future__ import annotations

from collections.abc import Callable
import logging
from threading import Event, Lock, Thread, current_thread
from typing import Any, Protocol

from .exceptions import EzvizPushFatalError

_LOGGER = logging.getLogger(__name__)


class PushSession(Protocol):
    """One bounded, interruptible LBS/MQTT session owned by the worker."""

    def run(self, stopped: Event) -> None:
        """Run until disconnected or cancelled."""
        raise NotImplementedError
    def close(self) -> None:
        """Interrupt and release the session."""
        raise NotImplementedError


class PushWorker:
    """Build fresh LBS/MQTT credentials after every disconnect.

    The factory must not perform network I/O. Session.run must respect stopped,
    and close must interrupt pending network operations. No paho reconnect loop
    is used: reconnecting with an old session key is not sufficient.
    """

    def __init__(self, factory: Callable[[], PushSession], *, retry_delay: float = 30) -> None:
        if retry_delay <= 0:
            raise ValueError("Retry delay must be positive")
        self.failure: EzvizPushFatalError | None = None
        self.factory = factory
        self.retry_delay = retry_delay
        self._lock = Lock()
        self._stopped = Event()
        self._thread: Thread | None = None
        self._session: PushSession | None = None
        self._state = "idle"
        self._attempts = 0
        self._transient_failures = 0
        self._last_error_type: str | None = None

    def start(self) -> None:
        with self._lock:
            self.raise_if_failed()
            if self._thread is not None and self._thread.is_alive():
                if self._stopped.is_set():
                    raise RuntimeError("Previous push worker is still stopping")
                return
            self._stopped.clear()
            self._state = "starting"
            self._thread = Thread(target=self._run, name="ezviz-channel99", daemon=True)
            self._thread.start()

    def diagnostics(self) -> dict[str, Any]:
        """Return worker health without endpoints, identifiers, or credentials."""
        with self._lock:
            thread = self._thread
            session = self._session
            snapshot: dict[str, Any] = {
                "state": self._state,
                "worker_alive": thread is not None and thread.is_alive(),
                "retry_delay_seconds": self.retry_delay,
                "attempts": self._attempts,
                "transient_failures": self._transient_failures,
                "last_error_type": self._last_error_type,
                "fatal_error_type": type(self.failure).__name__ if self.failure else None,
            }
        diagnostics = getattr(session, "diagnostics", None)
        snapshot["session"] = diagnostics() if callable(diagnostics) else None
        if (
            snapshot["state"] == "connecting"
            and isinstance(snapshot["session"], dict)
            and snapshot["session"].get("ready")
        ):
            snapshot["state"] = "connected"
        return snapshot

    def raise_if_failed(self) -> None:
        """Expose fatal background errors without logging credential-bearing causes."""
        if self.failure is not None:
            raise self.failure

    def stop(self, timeout: float = 5) -> None:
        """Signal stop and interrupt I/O; never join the callback's own thread."""
        with self._lock:
            self._stopped.set()
            self._state = "stopping"
            session, thread = self._session, self._thread
        if session is not None:
            self._close(session)
        if thread is not None and thread is not current_thread():
            thread.join(timeout)
            if thread.is_alive():
                raise TimeoutError("Push worker did not stop within deadline")
        with self._lock:
            self._state = "stopped"

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
                        break
                    self._attempts += 1
                    self._state = "connecting"
                    session = self.factory()
                    self._session = session
                session.run(self._stopped)
                if not self._stopped.is_set():
                    with self._lock:
                        self._state = "retry_wait"
            except EzvizPushFatalError as error:
                with self._lock:
                    self.failure = error
                    self._last_error_type = type(error).__name__
                    self._state = "fatal"
                    self._stopped.set()
                _LOGGER.error("Channel-99 stopped; caller intervention required (%s)", type(error).__name__)
            except Exception as error:
                if not self._stopped.is_set():
                    with self._lock:
                        self._transient_failures += 1
                        self._last_error_type = type(error).__name__
                        self._state = "retry_wait"
                    _LOGGER.warning("Channel-99 connection interrupted; retry scheduled")
            finally:
                if session is not None:
                    self._close(session)
                with self._lock:
                    self._session = None
            if self._stopped.wait(self.retry_delay):
                break
        with self._lock:
            if self._state != "fatal":
                self._state = "stopped"
