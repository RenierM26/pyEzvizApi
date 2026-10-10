"""Context-local HTTP bootstrap budgets, without mutating client settings."""
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
import time
from typing import Any

from urllib3.util import Timeout

_BUDGET: ContextVar[tuple[float, Callable[[], float]] | None] = ContextVar("ezviz_request_budget", default=None)


def remaining_request_budget() -> float | None:
    """Reject an exhausted scoped request budget before doing more work."""
    budget = _BUDGET.get()
    if budget is None:
        return None
    remaining = budget[0] - budget[1]()
    if remaining <= 0:
        raise TimeoutError("Cloud bootstrap exhausted capture deadline")
    return remaining


@contextmanager
def request_deadline(deadline: float | None, monotonic: Callable[[], float] = time.monotonic) -> Iterator[None]:
    """Apply a budget to nested HTTP calls and authentication retries."""
    if deadline is None:
        yield
        return
    parent_remaining = remaining_request_budget()
    if parent_remaining is not None:
        deadline = min(deadline, monotonic() + parent_remaining)
    token = _BUDGET.set((deadline, monotonic))
    try:
        remaining_request_budget()
        yield
        remaining_request_budget()
    finally:
        _BUDGET.reset(token)


def bounded_request_timeout(default: float | None) -> Any:
    """Give requests one total connect/read budget; preserve ordinary calls."""
    remaining = remaining_request_budget()
    if remaining is None:
        return default
    return Timeout(total=remaining if default is None else min(default, remaining))


@contextmanager
def request_budget_lock(lock: Any) -> Iterator[None]:
    """Include token-lock contention in the scoped bootstrap deadline."""
    remaining = remaining_request_budget()
    if remaining is None:
        with lock:
            yield
        return
    if not lock.acquire(timeout=remaining):
        raise TimeoutError("Cloud bootstrap token lock exhausted capture deadline")
    try:
        remaining_request_budget()
        yield
    finally:
        lock.release()
