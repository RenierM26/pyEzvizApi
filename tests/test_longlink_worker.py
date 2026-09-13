"""Reconnect, cancellation and callback teardown without cloud credentials."""

from threading import Event

from pyezvizapi._longlink_worker import PushWorker


class Session:
    def __init__(self) -> None:
        self.running = Event()
        self.closed = Event()

    def run(self, stopped: Event) -> None:
        self.running.set()
        self.closed.wait(2)

    def close(self) -> None:
        self.closed.set()


def test_disconnect_creates_fresh_session_and_stop_interrupts_it() -> None:
    sessions = [Session(), Session()]
    pending = iter(sessions)
    worker = PushWorker(lambda: next(pending), retry_delay=0.01)
    try:
        worker.start()
        assert sessions[0].running.wait(2)
        sessions[0].close()
        assert sessions[1].running.wait(2)
    finally:
        worker.stop()
    assert sessions[1].closed.is_set()


def test_callback_can_stop_its_own_worker() -> None:
    finished = Event()

    class CallbackSession(Session):
        def run(self, stopped: Event) -> None:
            worker.stop()
            finished.set()

    session = CallbackSession()
    worker = PushWorker(lambda: session)
    worker.start()
    assert finished.wait(2)
    worker.stop()
    assert session.closed.is_set()


def test_stop_interrupts_retry_wait_and_restart_works() -> None:
    first = Session()
    second = Session()
    pending = iter([first, second])
    worker = PushWorker(lambda: next(pending), retry_delay=60)
    worker.start()
    assert first.running.wait(2)
    worker.stop()
    worker.start()
    assert second.running.wait(2)
    worker.stop()
