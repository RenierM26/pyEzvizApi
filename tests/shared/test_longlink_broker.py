"""Actual Paho MQTT 3.1.1 packet handlers driving the SDK session/worker."""
# ruff: noqa: SLF001

from threading import Event
from unittest.mock import Mock

import paho.mqtt.client as mqtt
import pytest

from pyezvizapi._longlink_auth import PushCredentials
from pyezvizapi._longlink_session import Channel99Session
from pyezvizapi._longlink_worker import PushWorker
from pyezvizapi.exceptions import EzvizPushFatalError

KEY = bytes(range(16))
CREDENTIALS = PushCredentials(bytes(range(32)), KEY, KEY, {"Address": "broker.invalid", "Port": 8667})


def connection():
    return Channel99Session(("lbs.invalid", 8777), b"serial", lambda: "session", {}, Mock(), Mock())


def connack(client, code):
    client._in_packet["remaining_length"] = 2
    client._in_packet["packet"] = bytearray([0, code])
    return client._handle_connack()


def suback(client, codes, mid=42):
    client._in_packet["packet"] = bytearray(mid.to_bytes(2, "big") + bytes(codes))
    client._handle_suback()


def broker(monkeypatch, session, code, grants=None, *, cleanup_fails=False):
    client = session._client(CREDENTIALS)
    monkeypatch.setattr(session, "_client", lambda credentials: client)
    monkeypatch.setattr(client, "connect", Mock(return_value=mqtt.MQTT_ERR_SUCCESS))
    monkeypatch.setattr(client, "subscribe", Mock(return_value=(mqtt.MQTT_ERR_SUCCESS, 42)))
    monkeypatch.setattr(client, "disconnect", Mock())
    first = True

    def loop(**kwargs):
        nonlocal first
        if session._closed.is_set():
            if cleanup_fails:
                raise OSError("cleanup failed")
            return mqtt.MQTT_ERR_NO_CONN
        if first:
            first = False
            result = connack(client, code)
            if code == 0 and grants is not None:
                suback(client, grants)
            return result
        return mqtt.MQTT_ERR_NO_CONN

    monkeypatch.setattr(client, "loop", loop)
    return client


@pytest.mark.parametrize("code", [1, 2, 4, 5])
@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_permanent_connack_stops_worker_without_renegotiation(monkeypatch, code, cleanup_fails):
    session = connection()
    broker(monkeypatch, session, code, cleanup_fails=cleanup_fails)
    monkeypatch.setattr(session, "run", lambda stopped: session._run_mqtt(CREDENTIALS, stopped))
    factory = Mock(return_value=session)
    worker = PushWorker(factory, retry_delay=0.01)
    try:
        worker.start()
        assert worker._thread is not None
        worker._thread.join(2)
        assert not worker._thread.is_alive()
        with pytest.raises(EzvizPushFatalError):
            worker.raise_if_failed()
        with pytest.raises(EzvizPushFatalError):
            worker.start()
        assert factory.call_count == 1
        assert not session.ready.is_set()
        assert session._mqtt is None
        if code != 1:  # Paho suppresses the callback for protocol-version refusal.
            assert session.last_connect_reason == mqtt.convert_connack_rc_to_reason_code(code).value
    finally:
        worker.stop()


def test_server_unavailable_retries_with_a_new_session(monkeypatch):
    first, second = connection(), connection()
    broker(monkeypatch, first, 3)
    monkeypatch.setattr(first, "run", lambda stopped: first._run_mqtt(CREDENTIALS, stopped))
    running = Event()

    def run_second(stopped):
        running.set()
        assert stopped.wait(2)

    monkeypatch.setattr(second, "run", run_second)
    factory = Mock(side_effect=[first, second])
    worker = PushWorker(factory, retry_delay=0.01)
    try:
        worker.start()
        assert running.wait(2)
        worker.raise_if_failed()
        assert factory.call_count == 2
        assert first.last_connect_reason == 136
    finally:
        worker.stop()


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_explicit_suback_refusal_is_fatal(monkeypatch, cleanup_fails):
    session = connection()
    broker(monkeypatch, session, 0, [128], cleanup_fails=cleanup_fails)
    with pytest.raises(EzvizPushFatalError, match="subscription rejected"):
        session._run_mqtt(CREDENTIALS, Event())
    assert session.last_subscribe_reasons == [128]
    assert not session.ready.is_set()
    assert session._mqtt is None


@pytest.mark.parametrize("grants", [[], [0, 1], [2]])
def test_malformed_or_excessive_grants_do_not_mark_ready(monkeypatch, grants):
    session = connection()
    client = broker(monkeypatch, session, 0, grants)
    session._run_mqtt(CREDENTIALS, Event())
    assert session._failure is None
    assert not session.ready.is_set()
    assert client.disconnect.call_count >= 1


@pytest.mark.parametrize("acknowledge_connect", [False, True])
def test_missing_connack_or_suback_has_bounded_retryable_setup(monkeypatch, acknowledge_connect):
    session = connection()
    client = broker(monkeypatch, session, 0)
    ticks = iter([0, 31])
    monkeypatch.setattr("pyezvizapi._longlink_session.monotonic", lambda: next(ticks))

    def loop(**kwargs):
        if not session._closed.is_set() and acknowledge_connect:
            connack(client, 0)
        return mqtt.MQTT_ERR_SUCCESS

    monkeypatch.setattr(client, "loop", loop)
    with pytest.raises(TimeoutError, match="acknowledgement timed out"):
        session._run_mqtt(CREDENTIALS, Event())
    assert session._failure is None
    assert not session.ready.is_set()
    assert session._mqtt is None


def test_suback_mid_and_shutdown_guard_prevent_false_readiness(monkeypatch):
    session = connection()
    client = broker(monkeypatch, session, 0)
    connack(client, 0)
    suback(client, [1], mid=43)
    assert not session.ready.is_set()
    suback(client, [1])
    assert session.ready.is_set()
    session.close()
    suback(client, [1])
    connack(client, 5)
    assert not session.ready.is_set()
    assert session._failure is None


def test_disconnect_exception_cannot_hide_recorded_authorization_failure(monkeypatch):
    session = connection()
    client = broker(monkeypatch, session, 5)
    monkeypatch.setattr(client, "disconnect", Mock(side_effect=OSError("socket failure")))
    sock = Mock()
    monkeypatch.setattr(client, "socket", Mock(return_value=sock))
    with pytest.raises(EzvizPushFatalError, match="reason 135"):
        session._run_mqtt(CREDENTIALS, Event())
    assert session.last_connect_reason == 135
    assert session._mqtt is None
    sock.close.assert_called_once()


@pytest.mark.parametrize("result,fatal", [(mqtt.MQTT_ERR_NO_CONN, False), (mqtt.MQTT_ERR_INVAL, True)])
def test_local_subscription_errors_distinguish_disconnect_from_invalid_request(monkeypatch, result, fatal):
    session = connection()
    client = broker(monkeypatch, session, 0)
    monkeypatch.setattr(client, "subscribe", Mock(return_value=(result, None)))
    if fatal:
        with pytest.raises(EzvizPushFatalError, match="Invalid MQTT subscription"):
            session._run_mqtt(CREDENTIALS, Event())
    else:
        session._run_mqtt(CREDENTIALS, Event())
        assert session._failure is None
    assert not session.ready.is_set()


@pytest.mark.parametrize("grant", [0, 1])
def test_successful_subscription_survives_setup_deadline_and_ignores_late_shutdown_ack(monkeypatch, grant):
    session = connection()
    client = broker(monkeypatch, session, 0)
    stopped = Event()
    monkeypatch.setattr("pyezvizapi._longlink_session.monotonic", lambda: 0 if not session.ready.is_set() else 100)

    def loop(**kwargs):
        if session._closed.is_set():
            suback(client, [grant])  # Queued packet during the final cleanup loop.
        else:
            connack(client, 0)
            suback(client, [grant])
            assert session.ready.is_set()
            stopped.set()
        return mqtt.MQTT_ERR_SUCCESS

    monkeypatch.setattr(client, "loop", loop)
    session._run_mqtt(CREDENTIALS, stopped)
    assert session.last_subscribe_reasons == [grant]
    assert session._failure is None
    assert not session.ready.is_set()
    assert session._mqtt is None
