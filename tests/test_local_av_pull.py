"""Demand, stalled-read cancellation and sole-thread iterator ownership."""
from pathlib import Path
import runpy
import threading
import time
import weakref

import pytest

M = runpy.run_path(str(Path(__file__).parents[1] / 'tools/local_av_pull.py'))


class Source:
    def __init__(self, rows=(), *, failure=None, close_failure=None, blocked=False):
        self.rows = iter(rows)
        self.failure = failure
        self.close_failure = close_failure
        self.entered = threading.Event()
        self.release = threading.Event()
        if not blocked:
            self.release.set()
        self.threads = []
        self.pulls = self.closes = self.interrupts = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.threads.append(threading.get_ident())
        self.pulls += 1
        self.entered.set()
        if not self.release.wait(3):
            raise TimeoutError('test failed to release fake source')
        if self.failure:
            raise self.failure
        return next(self.rows)

    def close(self):
        self.threads.append(threading.get_ident())
        self.closes += 1
        if self.close_failure:
            raise self.close_failure

    def interrupt(self):
        self.interrupts += 1
        self.release.set()


def ready(pull):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        available, value = pull.poll()
        if available:
            return value
        time.sleep(.001)
    raise AssertionError('fake pull did not complete')


def test_no_implicit_pull_and_close_before_request_uses_only_owner_thread():
    source = Source([1])
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    pull.close(1)
    assert source.pulls == 0 and source.closes == 1 and source.interrupts == 0
    assert source.threads[0] != threading.get_ident()
    assert pull.result()['iterator_closed'] and not pull.result()['worker_alive']


def test_exact_order_one_demand_and_terminal_close_before_eof_is_visible():
    source = Source([None, ('same', b'unchanged')])
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    try:
        for index, expected in enumerate([None, ('same', b'unchanged')], 1):
            pull.request()
            assert ready(pull) == expected
            assert source.pulls == index and source.closes == 0
        pull.request()
        with pytest.raises(StopIteration):
            ready(pull)
        assert source.closes == 1
        with pytest.raises(ValueError, match='ended'):
            pull.request()
    finally:
        pull.close(1)
    result = pull.result()
    assert result['requested'] == 3 and result['yielded'] == result['consumed'] == 2
    assert result['source_ended'] and result['abandoned'] == 0
    assert len(set(source.threads)) == 1 and source.threads[0] != threading.get_ident()


def test_pending_poll_is_nonblocking_and_cancellation_joins_stalled_read():
    source = Source([1], blocked=True)
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    pull.request()
    assert source.entered.wait(1)
    try:
        assert pull.poll() == (False, None)
        with pytest.raises(ValueError, match='outstanding'):
            pull.request()
        assert source.pulls == 1
    finally:
        pull.close(1)
    result = pull.result()
    assert source.interrupts == source.closes == 1
    assert result['yielded'] == result['abandoned'] == 1 and result['consumed'] == 0
    assert not result['worker_alive'] and not result['outstanding']
    pull.close(1)
    assert source.interrupts == source.closes == 1 and pull.result()['abandoned'] == 1


def test_ready_slot_retains_demand_until_consumed_and_close_marks_abandonment():
    source = Source([1, 2])
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    try:
        pull.request()
        assert source.entered.wait(1)
        with pytest.raises(ValueError, match='outstanding'):
            pull.request()
        assert source.pulls == 1
    finally:
        pull.close(1)
    assert pull.result()['abandoned'] == 1
    assert source.pulls == 1


def test_borrow_is_not_resumed_until_consumer_explicitly_requests_again():
    resumed = threading.Event()
    closed = threading.Event()
    def source():
        try:
            yield ('event', b'original payload')
            resumed.set()
        finally:
            closed.set()
    pull = M['PreparedPull'](source(), interrupt=lambda: None)
    try:
        pull.request()
        assert ready(pull) == ('event', b'original payload')
        assert not resumed.is_set() and not closed.is_set()
    finally:
        pull.close(1)
    assert not resumed.is_set() and closed.is_set()


@pytest.mark.parametrize('failure', [ValueError('source failure'), KeyboardInterrupt(), SystemExit(7)])
def test_source_exception_identity_survives_cleanup(failure):
    source = Source(failure=failure)
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    try:
        pull.request()
        with pytest.raises(type(failure)) as caught:
            ready(pull)
        assert caught.value is failure and source.closes == 1
        assert pull.result()['source_error_type'] == type(failure).__name__
    finally:
        pull.close(1)


@pytest.mark.parametrize('failure', [None, LookupError('primary')])
def test_source_cleanup_failure_never_reports_clean_eof_or_masks_primary(failure):
    source = Source(failure=failure, close_failure=OSError('private detail not in receipt'))
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    pull.request()
    with pytest.raises(type(failure) if failure else M['PullCleanupError']):
        ready(pull)
    with pytest.raises(M['PullCleanupError'], match='cleanup failed'):
        pull.close(1)
    result = pull.result()
    assert result['close_error_type'] == 'OSError' and not result['iterator_closed']
    assert 'private detail' not in str(result) and not result['worker_alive']


def test_uninterruptible_read_times_out_without_claiming_join_or_closing_executing_iterator():
    source = Source([1], blocked=True)
    pull = M['PreparedPull'](source, interrupt=lambda: None)
    pull.request()
    assert source.entered.wait(1)
    try:
        with pytest.raises(M['PullCleanupError'], match='ownership retained'):
            pull.close(.01)
        result = pull.result()
        assert result['worker_alive'] and result['read_active'] and result['outstanding']
        assert not result['iterator_closed'] and source.closes == 0
        with pytest.raises(ValueError, match='closed'):
            pull.request()
    finally:
        source.release.set()
        pull.close(1)
    assert not pull.result()['worker_alive'] and source.closes == 1


def test_interrupt_failure_is_reported_even_if_read_and_worker_finish():
    source = Source([1], blocked=True)
    def interrupt():
        source.release.set()
        raise OSError('private cancellation detail')
    pull = M['PreparedPull'](source, interrupt=interrupt)
    pull.request()
    assert source.entered.wait(1)
    with pytest.raises(M['PullCleanupError'], match='cleanup failed'):
        pull.close(1)
    result = pull.result()
    assert result['interrupt_error_type'] == 'OSError' and not result['worker_alive']
    assert source.closes == 1 and 'private cancellation detail' not in str(result)


@pytest.mark.parametrize('timeout', [True, False, None, 0, -1, 31, float('nan'), float('inf')])
def test_invalid_join_bound_does_not_cancel_or_consume_source(timeout):
    source = Source()
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    try:
        with pytest.raises(ValueError, match='join timeout'):
            pull.close(timeout)
        assert not pull.result()['consumer_closed'] and source.pulls == 0
    finally:
        pull.close(1)


def test_poll_requires_outstanding_open_request():
    source = Source()
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    try:
        with pytest.raises(ValueError, match='outstanding'):
            pull.poll()
    finally:
        pull.close(1)
    with pytest.raises(ValueError, match='outstanding'):
        pull.poll()


def test_abandoned_payload_has_no_worker_local_reference_after_join():
    class Payload:
        pass
    payload = Payload()
    reference = weakref.ref(payload)
    source = Source([payload])
    # The list iterator itself retains its underlying list until exhausted;
    # use a generator that releases its local on close instead.
    def values(value):
        yield value
    pull = M['PreparedPull'](values(payload), interrupt=lambda: None)
    del source, payload
    pull.request()
    try:
        assert ready(pull) is reference()
    finally:
        pull.close(1)
    assert reference() is None


def test_callback_is_validated_before_claiming_iterator():
    class Untouched:
        def __iter__(self):
            pytest.fail('invalid arguments claimed input')
    with pytest.raises(ValueError, match='callback'):
        M['PreparedPull'](Untouched(), interrupt=None)


def test_failed_thread_start_closes_claimed_iterator_without_masking_error(monkeypatch):
    source = Source(close_failure=OSError('secondary close failure'))
    failure = RuntimeError('thread start failed')
    class BrokenThread:
        def __init__(self, **kwargs):
            pass
        def start(self):
            raise failure
    monkeypatch.setitem(M['PreparedPull'].__init__.__globals__, 'Thread', BrokenThread)
    with pytest.raises(RuntimeError) as caught:
        M['PreparedPull'](source, interrupt=source.interrupt)
    assert caught.value is failure and source.closes == 1 and source.pulls == 0


def test_eof_waits_for_blocked_source_finalizer_and_join_timeout_retains_ownership():
    class SlowClose(Source):
        def __init__(self):
            super().__init__()
            self.close_entered = threading.Event()
            self.close_release = threading.Event()
        def close(self):
            super().close()
            self.close_entered.set()
            assert self.close_release.wait(3)
    source = SlowClose()
    pull = M['PreparedPull'](source, interrupt=source.interrupt)
    pull.request()
    assert source.close_entered.wait(1)
    try:
        assert pull.poll() == (False, None)
        with pytest.raises(M['PullCleanupError'], match='ownership retained'):
            pull.close(.01)
        assert not pull.result()['iterator_closed'] and pull.result()['worker_alive']
        assert source.closes == 1 and source.interrupts == 0
    finally:
        source.close_release.set()
        pull.close(1)
    assert pull.result()['iterator_closed'] and not pull.result()['worker_alive']


@pytest.mark.parametrize('bound_interrupt', [False, True])
def test_successful_close_releases_owned_iterator_and_cancellation_hook_references(bound_interrupt):
    class Payload:
        pass
    payload = Payload()
    payload_reference = weakref.ref(payload)
    source = Source([payload])
    source_reference = weakref.ref(source)
    pull = M['PreparedPull'](source, interrupt=source.interrupt if bound_interrupt else lambda: None)
    del source, payload
    pull.request()
    try:
        assert ready(pull) is payload_reference()
    finally:
        pull.close(1)
    assert source_reference() is None and payload_reference() is None
