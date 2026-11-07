"""Owned resolver cancellation, bounded close and queue behavior."""
# ruff: noqa: SLF001 -- assert the owned worker has actually drained.
from queue import Queue
from threading import Event, Thread

import pytest

from pyezvizapi import _resolver
from pyezvizapi._resolver import BoundedResolver, ResolverClosed


def test_close_reports_stuck_resolution_then_drains_without_replacement():
    entered, release = Event(), Event()
    errors = []
    def resolve(*_args, **_kwargs):
        entered.set()
        release.wait(2)
        return []
    owner = BoundedResolver(resolve)
    def wait_for_result():
        try:
            owner.resolve("unused.invalid", 9010, timeout=1)
        except ResolverClosed as error:
            errors.append(error)
    caller = Thread(target=wait_for_result)
    caller.start()
    try:
        assert entered.wait(1)
        drained = owner.close(wait_seconds=0.01)
        assert drained is False
        caller.join(timeout=1)
        assert not caller.is_alive() and len(errors) == 1
        with pytest.raises(ResolverClosed):
            owner.resolve("unused.invalid", 9010, timeout=1)
    finally:
        release.set()
        caller.join(timeout=2)
        drained = owner.close(wait_seconds=1)
        assert drained


def test_cancelled_queued_resolution_never_starts():
    release = Event()
    calls = []
    def resolve(*_args, **_kwargs):
        calls.append(True)
        release.wait(2)
        return []
    owner = BoundedResolver(resolve)
    try:
        for _ in range(2):
            with pytest.raises(TimeoutError):
                owner.resolve("unused.invalid", 9010, timeout=0.02)
        thread = owner._thread
        release.set()
        assert thread is not None
        thread.join(timeout=2)
        assert not thread.is_alive() and len(calls) == 1
    finally:
        release.set()
        owner.close(wait_seconds=1)


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), 10**1000])
def test_invalid_resolver_timeout_does_not_acquire(timeout):
    def forbidden(*_args, **_kwargs):
        pytest.fail("invalid timeout must not acquire a resolver")
    owner = BoundedResolver(forbidden)
    try:
        with pytest.raises(ValueError):
            owner.resolve("unused.invalid", 9010, timeout=timeout)
    finally:
        drained = owner.close()
        assert drained


def test_close_notifies_a_request_dequeued_before_active_assignment():
    dequeued, release = Event(), Event()
    errors = []
    calls = []
    class PausedQueue(Queue):
        def get(self, *args, **kwargs):
            value = super().get(*args, **kwargs)
            if isinstance(value, _resolver._Request):
                dequeued.set()
                release.wait(3)
            return value
    def resolve(*_args, **_kwargs):
        calls.append(True)
        return []
    owner = BoundedResolver(resolve)
    owner._jobs = PausedQueue(maxsize=1)
    def wait_for_result():
        try:
            owner.resolve("unused.invalid", 9010, timeout=2)
        except Exception as error:
            errors.append(error)
    caller = Thread(target=wait_for_result)
    caller.start()
    try:
        assert dequeued.wait(1)
        drained = owner.close(wait_seconds=0)
        assert drained is False
        release.set()
        caller.join(timeout=1)
        assert not caller.is_alive()
        assert len(errors) == 1 and isinstance(errors[0], ResolverClosed)
        assert not calls
    finally:
        release.set()
        caller.join(timeout=3)
        drained = owner.close(wait_seconds=1)
        assert drained
