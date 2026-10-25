"""Explicit single-demand prepared-source worker; no acquisition or output wiring.

The consumer must reserve downstream capacity before request(), then accept the
returned borrowed event before requesting another. This helper creates no extra
lookahead queue and does not make an arbitrary iterator interruptible.
"""
from __future__ import annotations

from collections.abc import Callable
import math
from threading import Condition, Thread
from typing import Any


class PullCleanupError(ValueError):
    """The pull owner could not establish joined, clean source shutdown."""


def validate_timeout(timeout: float) -> None:
    if (isinstance(timeout, bool) or not isinstance(timeout, int | float)
            or not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ValueError('pull join timeout must be finite and in (0, 30] seconds')


class PreparedPull:
    """Own next/close on one worker, with one explicitly requested result at most.

    request/poll/close are single-consumer operations. interrupt is a supplied
    thread-safe, promptly returning cancellation hook, not iterator.close; the
    worker alone closes the iterator. close's timeout bounds its join, not an
    arbitrary blocking cancellation hook. A timed-out worker remains owned and
    must be joined by a later close; it is never reported as cleanly stopped.
    """

    def __init__(self, iterator: Any, *, interrupt: Callable[[], None]) -> None:
        if not callable(interrupt):
            raise ValueError('explicit interrupt callback required')
        self.iterator = iter(iterator)
        self.interrupt = interrupt
        self.condition = Condition()
        self.pending = self.demand = self.reading = self.closing = False
        self.ended = self.iterator_closed = False
        self.interrupt_called = False
        self.outcome: tuple[str, Any] | None = None
        self.requested = self.yielded = self.consumed = self.abandoned = 0
        self.source_error_type: str | None = None
        self.close_error_type: str | None = None
        self.interrupt_error_type: str | None = None
        self.worker = Thread(target=self._run, name='prepared-source-pull', daemon=True)
        try:
            self.worker.start()
        except BaseException:
            # No worker exists: construction must release the claimed iterator
            # here, while retaining the original thread-start exception.
            self._close_iterator()
            raise

    def request(self) -> None:
        with self.condition:
            if self.closing or self.ended or self.pending:
                raise ValueError('pull closed, ended or already outstanding')
            self.pending = self.demand = True
            self.requested += 1
            self.condition.notify()

    def poll(self) -> tuple[bool, Any]:
        with self.condition:
            if self.closing or not self.pending:
                raise ValueError('no open outstanding pull')
            if self.outcome is None:
                return False, None
            kind, value = self.outcome
            self.outcome = None
            self.pending = False
            if kind == 'value':
                self.consumed += 1
                return True, value
        if kind == 'end':
            raise StopIteration
        raise value

    def _read(self) -> tuple[str, Any]:
        try:
            return 'value', next(self.iterator)
        except StopIteration:
            return 'end', None
        except BaseException as error:
            return 'error', error

    def _run(self) -> None:
        terminal: tuple[str, Any] | None = None
        try:
            while True:
                with self.condition:
                    self.condition.wait_for(lambda: self.demand or self.closing)
                    if self.closing:
                        break
                    self.demand = False
                    self.reading = True
                outcome = self._read()
                with self.condition:
                    self.reading = False
                    if outcome[0] != 'value':
                        terminal = outcome
                        self.ended = True
                        if outcome[0] == 'error':
                            self.source_error_type = type(outcome[1]).__name__
                        break
                    self.yielded += 1
                    self.outcome = outcome
                del outcome  # The result slot, not a worker local, owns the borrow.
        finally:
            self._close_iterator()
            # Publish terminal success only after source cleanup is known.
            with self.condition:
                if terminal is not None:
                    if terminal[0] == 'end' and self.close_error_type is not None:
                        terminal = 'error', PullCleanupError('prepared source close failed')
                    self.outcome = terminal

    def _close_iterator(self) -> None:
        try:
            close = getattr(self.iterator, 'close', None)
            if close is not None:
                close()
            with self.condition:
                self.iterator_closed = True
        except BaseException as error:
            with self.condition:
                self.close_error_type = type(error).__name__

    def _cancel(self) -> None:
        with self.condition:
            self.closing = True
            interrupt = self.reading and not self.interrupt_called
            if interrupt:
                self.interrupt_called = True
            self.condition.notify()
        if interrupt:
            try:
                self.interrupt()
            except BaseException as error:
                with self.condition:
                    self.interrupt_error_type = type(error).__name__

    def close(self, timeout: float) -> None:
        """Stop, interrupt an active read once, join, then release owned result."""
        validate_timeout(timeout)
        self._cancel()
        self.worker.join(timeout)
        if self.worker.is_alive():
            raise PullCleanupError('prepared source worker did not stop; ownership retained')
        with self.condition:
            if self.outcome is not None and self.outcome[0] == 'value':
                self.abandoned += 1
            self.outcome = None
            self.pending = self.demand = False
            failed = self.close_error_type is not None or self.interrupt_error_type is not None
        if failed:
            raise PullCleanupError('prepared source cleanup failed; inspect cleanup error types')

    def result(self) -> dict[str, Any]:
        with self.condition:
            return dict(profile='single-demand-prepared-pull-v1', requested=self.requested,
                yielded=self.yielded, consumed=self.consumed, abandoned=self.abandoned,
                outstanding=self.pending, read_active=self.reading,
                result_ready=self.outcome is not None, source_ended=self.ended,
                source_error_type=self.source_error_type, iterator_closed=self.iterator_closed,
                interrupt_called=self.interrupt_called, interrupt_error_type=self.interrupt_error_type,
                close_error_type=self.close_error_type, worker_alive=self.worker.is_alive(),
                consumer_closed=self.closing)
