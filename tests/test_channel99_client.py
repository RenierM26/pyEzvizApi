"""Public migration and durable-state callback contracts."""
# ruff: noqa: SLF001

from copy import deepcopy
import json
from threading import Event, Thread
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from pyezvizapi._longlink_profile import HEADERS as PUSH_HEADERS
from pyezvizapi._longlink_session import Channel99Session
from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.exceptions import (
    EzvizAuthTokenExpired,
    EzvizPushFatalError,
    EzvizTokenPersistenceError,
    PyEzvizError,
)
from pyezvizapi.mqtt import MQTTClient


def response(body):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(body).encode()
    return result


def token():
    return {
        "push_profile": "android-channel99",
        "user_id": "synthetic-user",
        "username": "internal-user",
        "feature_code": FEATURE_CODE,
        "api_url": "apiieu.ezvizlife.com",
        "session_id": "synthetic-session",
        "rf_session_id": "synthetic-refresh",
        "service_urls": {"pushDasDomain": "example.invalid", "pushDasPort": 8777},
    }


def test_legacy_token_migration_requires_credentials():
    client = EzvizClient(token={"session_id": "legacy", "api_url": "apiieu.ezvizlife.com"})
    before = client.export_token()
    with pytest.raises(EzvizAuthTokenExpired):
        client.enable_channel99()
    assert client.export_token() == before


@pytest.mark.parametrize("saved_code", [None, "previous-host-feature-code"])
def test_login_uses_existing_host_feature_code_and_registers_channel(monkeypatch, saved_code):
    saved = {"api_url": "apiieu.ezvizlife.com", "feature_code": saved_code} if saved_code else None
    client = EzvizClient(account="synthetic", password="synthetic", token=saved)
    post = Mock(
        return_value=response(
            {
                "meta": {"code": 200},
                "loginSession": {"sessionId": "session", "rfSessionId": "refresh"},
                "loginUser": {"username": "internal", "userId": "uid"},
                "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
            }
        )
    )
    monkeypatch.setattr(client._session, "post", post)
    monkeypatch.setattr(client, "get_service_urls", lambda: {"pushDasDomain": "example.invalid"})
    result = client.enable_channel99()
    assert result["user_id"] == "uid"
    expected_code = FEATURE_CODE
    assert result["feature_code"] == expected_code
    assert client._session.headers["featureCode"] == expected_code
    assert post.call_args.kwargs["data"]["featureCode"] == expected_code
    assert client._session.headers["clientNo"] == "google"
    assert client._session.headers["clientVersion"] == "7.4.1.0421"
    assert json.loads(post.call_args.kwargs["data"]["pushRegisterJson"]) == [{"channel": 99}]


def test_refresh_retains_identity_and_includes_registration(monkeypatch):
    saved = token()
    saved["push_state"] = {"device_id": "synthetic-device"}
    client = EzvizClient(token=saved)
    put = Mock(
        return_value=response(
            {
                "meta": {"code": 200},
                "sessionInfo": {"sessionId": "rotated", "refreshSessionId": "rotated-refresh"},
            }
        )
    )
    monkeypatch.setattr(client._session, "put", put)
    result = client.login()
    assert result["feature_code"] == FEATURE_CODE
    assert result["push_state"] == saved["push_state"]
    assert put.call_args.kwargs["data"]["featureCode"] == FEATURE_CODE
    assert "pushRegisterJson" in put.call_args.kwargs["data"]


def test_channel99_requires_persistence_callback():
    client = MQTTClient(token(), requests.Session())
    with pytest.raises(PyEzvizError, match="on_token_updated"):
        client.connect()


def test_background_start_and_full_token_snapshot(monkeypatch):
    saved = token()
    snapshots: list[dict[str, Any]] = []
    client = MQTTClient(saved, requests.Session(), on_token_updated=snapshots.append)
    worker = Mock()
    factory_holder = []

    def worker_factory(factory):
        factory_holder.append(factory)
        return worker

    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker", worker_factory)
    client.connect()
    worker.start.assert_called_once()
    session = factory_holder[0]()
    session.save({"device_id": "device", "master_key": "key"})
    assert snapshots[0]["session_id"] == saved["session_id"]
    assert snapshots[0]["push_state"]["device_id"] == "device"
    old = deepcopy(snapshots[0])
    saved["push_state"]["device_id"] = "changed"
    assert snapshots[0] == old
    client.stop()
    worker.stop.assert_called_once()


def test_decoded_callback_and_cache_unchanged():
    callback = Mock()
    client = MQTTClient(
        token(),
        requests.Session(),
        on_message_callback=callback,
        on_token_updated=lambda snapshot: None,
    )
    payload = b'{"alert":"test","ext":"synthetic,1,2,3,4"}'
    expected = client.decode_mqtt_message(payload)
    client._handle_payload(payload)
    callback.assert_called_once_with(expected)
    assert client.messages_by_device["2"] == expected


def test_rotated_credentials_saved_before_service_discovery_failure(monkeypatch):
    saved = token()
    saved.pop("service_urls")
    snapshots: list[dict[str, Any]] = []
    client = EzvizClient(token=saved, on_token_updated=snapshots.append)
    put = Mock(
        return_value=response(
            {
                "meta": {"code": 200},
                "sessionInfo": {"sessionId": "rotated", "refreshSessionId": "new-refresh"},
            }
        )
    )
    monkeypatch.setattr(client._session, "put", put)
    monkeypatch.setattr(
        client, "get_service_urls", Mock(side_effect=ConnectionError("discovery unavailable"))
    )
    with pytest.raises(ConnectionError):
        client.login()
    assert snapshots[0]["session_id"] == "rotated"
    assert snapshots[0]["rf_session_id"] == "new-refresh"
    saved["session_id"] = "later"
    assert snapshots[0]["session_id"] == "rotated"


def test_persistence_failure_aborts_before_service_discovery(monkeypatch):
    saved = token()
    saved.pop("service_urls")
    persist = Mock(side_effect=OSError("storage unavailable"))
    client = EzvizClient(token=saved, on_token_updated=persist)
    monkeypatch.setattr(
        client._session,
        "put",
        Mock(
            return_value=response(
                {
                    "meta": {"code": 200},
                    "sessionInfo": {"sessionId": "rotated", "refreshSessionId": "new-refresh"},
                }
            )
        ),
    )
    discovery = Mock()
    monkeypatch.setattr(client, "get_service_urls", discovery)
    with pytest.raises(OSError):
        client.login()
    discovery.assert_not_called()
    assert client.export_token()["rf_session_id"] == "new-refresh"


def test_login_persistence_callback_is_reused_for_push(monkeypatch):
    saved: list[dict[str, Any]] = []
    client = EzvizClient(token=token(), on_token_updated=saved.append)
    worker = Mock()
    factories = []

    def make_worker(factory):
        factories.append(factory)
        return worker

    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker", make_worker)
    push = client.get_mqtt_client()
    push.connect()
    session = factories[0]()
    session.save({"device_id": "saved-device", "master_key": "saved-key"})
    assert saved[0]["push_state"]["device_id"] == "saved-device"
    assert saved[0]["session_id"] == client.export_token()["session_id"]
    worker.start.assert_called_once()
    push.stop()
    worker.stop.assert_called_once()


def test_unmigrated_push_never_calls_legacy_service():
    http = Mock()
    client = MQTTClient(
        {
            "username": "legacy-user",
            "session_id": "legacy",
            "service_urls": {"pushAddr": "old.invalid"},
        },
        http,
    )
    with pytest.raises(EzvizAuthTokenExpired, match="enable_channel99"):
        client.connect()
    client.stop()
    http.post.assert_not_called()
    http.put.assert_not_called()


@pytest.mark.parametrize("saved_code", [None, "different-host"])
def test_changed_or_unknown_host_rejects_saved_channel99_credentials(saved_code):
    saved = token()
    saved["feature_code"] = saved_code
    before = deepcopy(saved)
    with pytest.raises(EzvizAuthTokenExpired, match="host feature code"):
        EzvizClient(token=saved)
    assert saved == before  # Caller must explicitly obtain a fresh login.
    http = Mock()
    push = MQTTClient(saved, http, on_token_updated=lambda snapshot: None)
    with pytest.raises(EzvizAuthTokenExpired, match="host feature code"):
        push.connect()
    http.put.assert_not_called()


def test_push_serial_uses_host_constant(monkeypatch):
    client = MQTTClient(token(), requests.Session(), on_token_updated=lambda snapshot: None)
    factories = []

    def capture_factory(factory):
        factories.append(factory)
        return Mock()

    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker", capture_factory)
    client.connect()
    assert factories[0]().serial == f"MOBILE:ys7:synthetic-user:{FEATURE_CODE}".encode()


def test_close_session_preserves_android_profile_for_refresh(monkeypatch):
    client = EzvizClient(token=token())
    client.close_session()
    captured: dict[str, Any] = {}

    def refresh(**kwargs):
        captured.update(client._session.headers)
        return response({"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "new-session", "refreshSessionId": "new-refresh"
        }})

    monkeypatch.setattr(client._session, "put", refresh)
    client.login()
    assert captured["clientNo"] == "google"
    assert captured["featureCode"] == FEATURE_CODE


@pytest.mark.parametrize("http_status,meta_code", [(401, None), (200, 403)])
def test_push_registration_refreshes_expired_session_and_persists_before_retry(
    monkeypatch, http_status, meta_code
):
    saved = token()
    saved["push_state"] = {"device_id": "unchanged"}
    snapshots: list[dict[str, Any]] = []
    registrations = []

    def put(session, url, **kwargs):
        if url.endswith("/v3/push/token"):
            registrations.append(session.headers["sessionId"])
            if len(registrations) == 1:
                result = response({"meta": {"code": meta_code}})
                result.status_code = http_status
                return result
            assert snapshots[-1]["session_id"] == "rotated"
            return response({"meta": {"code": 200}})
        assert kwargs["data"]["refreshSessionId"] == "synthetic-refresh"
        return response({"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "rotated", "refreshSessionId": "rotated-refresh"
        }})

    monkeypatch.setattr(requests.Session, "put", put)
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(saved, requests.Session(), on_token_updated=snapshots.append)
    client.connect()
    prepare_push(client)
    assert registrations == ["synthetic-session", "rotated"]
    assert client._session.headers["sessionId"] == "rotated"
    assert saved["push_state"]["device_id"] == "unchanged"


def test_push_refresh_persistence_failure_stops_before_registration_retry(monkeypatch):

    registrations = []

    def put(session, url, **kwargs):
        if url.endswith("/v3/push/token"):
            registrations.append(url)
            result = response({})
            result.status_code = 401
            return result
        return response({"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "rotated", "refreshSessionId": "rotated-refresh"
        }})

    monkeypatch.setattr(requests.Session, "put", put)
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    saver = Mock(side_effect=OSError("private filesystem error"))
    client = MQTTClient(token(), requests.Session(), on_token_updated=saver)
    client.connect()
    with pytest.raises(EzvizTokenPersistenceError, match="persist channel-99"):
        prepare_push(client)
    assert len(registrations) == 1


def test_push_state_save_failure_is_fatal(monkeypatch):

    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(token(), requests.Session(), on_token_updated=Mock(side_effect=OSError()))
    client.connect()
    with pytest.raises(EzvizTokenPersistenceError):
        push_session(client).save({"phase": "creation_pending"})


def push_session(client: MQTTClient) -> Channel99Session:
    assert client._push_worker is not None
    result = client._push_worker.factory()
    assert isinstance(result, Channel99Session)
    return result


def prepare_push(client: MQTTClient) -> None:
    result = push_session(client)
    assert result.prepare is not None
    result.prepare()


@pytest.mark.parametrize("refresh_status", [401, 403])
@pytest.mark.parametrize("metadata_rejection", [False, True])
def test_rejected_refresh_requires_intervention(monkeypatch, refresh_status, metadata_rejection):
    calls = []

    def put(session, url, **kwargs):
        calls.append(url)
        if url.endswith("/v3/push/token"):
            return response({"meta": {"code": 403}})
        result = response({"meta": {"code": refresh_status}})
        result.status_code = 200 if metadata_rejection else refresh_status
        return result

    monkeypatch.setattr(requests.Session, "put", put)
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(token(), requests.Session(), on_token_updated=lambda snapshot: None)
    client.connect()
    with pytest.raises(EzvizPushFatalError, match="reauthentication required"):
        prepare_push(client)
    assert len(calls) == 2


def test_login_and_push_snapshots_are_serialized(monkeypatch):

    entered, release, attempted, pushed = Event(), Event(), Event(), Event()
    written = []

    def persist(snapshot):
        if not entered.is_set():
            entered.set()
            assert release.wait(2)
        written.append(snapshot)

    client = EzvizClient(token=token(), on_token_updated=persist)
    monkeypatch.setattr(client._session, "put", lambda **kwargs: response({
        "meta": {"code": 200}, "sessionInfo": {
            "sessionId": "rotated", "refreshSessionId": "rotated-refresh"
        }
    }))
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    push = client.get_mqtt_client()
    push.connect()
    session = push_session(push)

    def save_push():
        attempted.set()
        session.save({"device_id": "new-device"})
        pushed.set()

    login_thread = Thread(target=client.login)
    push_thread = Thread(target=save_push)
    login_thread.start()
    assert entered.wait(2)
    push_thread.start()
    assert attempted.wait(2)
    try:
        assert not pushed.wait(0.1)
        assert written == []  # New snapshot must not overtake the blocked old save.
    finally:
        release.set()
        login_thread.join(2)
        push_thread.join(2)
    assert not login_thread.is_alive() and not push_thread.is_alive()
    assert len(written) == 2
    assert written[-1]["session_id"] == "rotated"
    assert written[-1]["push_state"]["device_id"] == "new-device"
    session.state["unsaved"] = True
    assert "unsaved" not in client.export_token()["push_state"]


def test_migrated_login_discards_old_discovery_and_recovers_after_restart(monkeypatch):
    snapshots: list[dict[str, Any]] = []
    client = EzvizClient(account="synthetic", password="synthetic", token={
        "session_id": "legacy", "api_url": "apiieu.ezvizlife.com",
        "service_urls": {"pushAddr": "legacy.invalid"},
    }, on_token_updated=snapshots.append)
    monkeypatch.setattr(client._session, "post", lambda **kwargs: response({
        "meta": {"code": 200},
        "loginSession": {"sessionId": "new-session", "rfSessionId": "new-refresh"},
        "loginUser": {"username": "internal", "userId": "uid"},
        "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
    }))
    monkeypatch.setattr(client, "get_service_urls", Mock(side_effect=ConnectionError()))
    with pytest.raises(ConnectionError):
        client.enable_channel99()
    assert snapshots[-1]["session_id"] == "new-session"
    assert snapshots[-1]["push_profile"] == "android-channel99"
    assert "service_urls" not in snapshots[-1]

    resumed = EzvizClient(token=deepcopy(snapshots[-1]), on_token_updated=snapshots.append)
    monkeypatch.setattr(resumed._session, "put", lambda **kwargs: response({
        "meta": {"code": 200},
        "sessionInfo": {"sessionId": "refreshed", "refreshSessionId": "refreshed-refresh"},
    }))
    discovery = Mock(return_value={"pushDasDomain": "current.invalid", "pushDasPort": 8777})
    monkeypatch.setattr(resumed, "get_service_urls", discovery)
    resumed.login()
    discovery.assert_called_once()
    assert snapshots[-1]["service_urls"]["pushDasDomain"] == "current.invalid"
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    push = resumed.get_mqtt_client()
    push.connect()
    assert push_session(push).endpoint == ("current.invalid", 8777)


@pytest.mark.parametrize("port", ["not-a-port", "", None, [], {}, True, 1.5, 0, -1, 65536])
def test_invalid_service_ports_raise_handled_error_before_worker_start(monkeypatch, port):
    saved = token()
    saved["service_urls"]["pushDasPort"] = port
    start = Mock()
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", start)
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    with pytest.raises(PyEzvizError):
        client.connect()
    start.assert_not_called()


@pytest.mark.parametrize("urls", [None, [], "invalid"])
def test_malformed_service_discovery_raises_handled_error(urls):
    saved = token()
    saved["service_urls"] = urls
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    with pytest.raises(PyEzvizError, match="service discovery"):
        client.connect()


@pytest.mark.parametrize("host", ["bad\x00host", "bad host", "https://example.test", "bad/host",
                                  "-bad.test", "bad..test", "a" * 64 + ".test", "bad\ud800"])
def test_invalid_hostnames_fail_before_worker_start(monkeypatch, host):
    saved = token()
    saved["service_urls"]["pushDasDomain"] = host
    start = Mock()
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", start)
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    with pytest.raises(PyEzvizError, match="hostname"):
        client.connect()
    start.assert_not_called()


@pytest.mark.parametrize("user_id", ["café", "id/other", "id+#", "id\x00", 123, [], "x" * 128])
def test_invalid_user_ids_raise_handled_error(user_id):
    saved = token()
    saved["user_id"] = user_id
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    with pytest.raises(PyEzvizError):
        client.connect()


@pytest.mark.parametrize("host", ["example.test", "example.test.", "127.0.0.1", "::1", "bücher.test"])
def test_valid_hostnames_and_ip_literals_are_accepted(monkeypatch, host):
    saved = token()
    saved["service_urls"]["pushDasDomain"] = host
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    client.connect()


def test_reconnect_and_explicit_restart_use_current_discovery(monkeypatch):
    saved = token()
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    client.connect()
    first = push_session(client)
    assert first.endpoint == ("example.invalid", 8777)
    saved["service_urls"] = {"pushDasDomain": "rediscovered.invalid", "pushDasPort": 8888}
    second = push_session(client)
    assert second.endpoint == ("rediscovered.invalid", 8888)
    assert first.endpoint == ("example.invalid", 8777)
    client.stop()
    saved["service_urls"] = {"pushDasDomain": "restarted.invalid", "pushDasPort": 8999}
    client.connect()
    assert push_session(client).endpoint == ("restarted.invalid", 8999)


def test_identity_change_refreshes_factory_and_rejects_old_session_save(monkeypatch):
    saved = token()
    saved["push_state"] = {"device_id": "old-device"}
    snapshots: list[dict[str, Any]] = []
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(saved, requests.Session(), on_token_updated=snapshots.append)
    client.connect()
    old = push_session(client)
    assert old.is_current()
    assert old.credentials_input() == saved["session_id"]
    saved["session_id"] = "same-account-refreshed"
    assert old.credentials_input() == "same-account-refreshed"
    saved["user_id"] = "new-user"
    saved["session_id"] = "new-account-session"
    saved.pop("push_state")
    assert not old.is_current()
    with pytest.raises(PyEzvizError, match="identity changed"):
        old.credentials_input()
    with pytest.raises(PyEzvizError, match="identity changed"):
        old.save({"device_id": "old-device"})
    assert "push_state" not in saved
    assert snapshots == []
    new = push_session(client)
    assert new.serial == f"MOBILE:ys7:new-user:{FEATURE_CODE}".encode()
    assert new.state == {}
    assert new.is_current()
    assert new.credentials_input() == "new-account-session"
    new.save({"device_id": "new-device"})
    client.stop()
    client.connect()
    assert push_session(client).state == {"device_id": "new-device"}


def test_push_refresh_updates_owner_replacement_http_session(monkeypatch):
    snapshots: list[dict[str, Any]] = []
    owner = EzvizClient(token=token(), on_token_updated=snapshots.append)
    push = owner.get_mqtt_client()
    previous = owner._session
    owner.close_session()
    assert owner._session is not previous
    assert push._session is owner._session
    assert owner._session.headers["sessionId"] == "synthetic-session"
    registrations = []

    def put(session, url, **kwargs):
        if url.endswith("/v3/push/token"):
            registrations.append(session.headers["sessionId"])
            return response({"meta": {"code": 403 if len(registrations) == 1 else 200}})
        return response({"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "rotated", "refreshSessionId": "rotated-refresh"
        }})

    monkeypatch.setattr(requests.Session, "put", put)
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    push.connect()
    prepare_push(push)
    assert registrations == ["synthetic-session", "rotated"]
    assert owner._session.headers["sessionId"] == "rotated"
    assert owner.get_mqtt_client() is push
    assert snapshots[-1]["session_id"] == "rotated"


@pytest.mark.parametrize("host", ["::1", "2001:db8::1", "::ffff:192.0.2.1"])
def test_ipv6_api_host_fails_before_worker_start(monkeypatch, host):
    saved = token()
    saved["api_url"] = host
    start = Mock()
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", start)
    client = MQTTClient(saved, requests.Session(), on_token_updated=lambda snapshot: None)
    with pytest.raises(PyEzvizError, match="IPv6 API hosts"):
        client.connect()
    start.assert_not_called()


def test_push_registration_and_refresh_preserve_transport_without_mutating_owner(monkeypatch):
    supplied = requests.Session()
    supplied.proxies = {"https": "http://proxy.invalid:8080"}
    supplied.cert = ("client.crt", "client.key")
    supplied.verify = "private-ca.pem"
    supplied.trust_env = False
    supplied.auth = ("proxy-user", "synthetic-password")
    supplied.params = {"custom": "parameter"}
    supplied.cookies.set("owner", "original")
    adapter = requests.adapters.HTTPAdapter()
    close_adapter = Mock()
    monkeypatch.setattr(adapter, "close", close_adapter)
    supplied.mount("https://", adapter)
    calls = []

    def put(session, url, **kwargs):
        calls.append(url)
        assert session is not supplied
        assert all(session.headers[key] == value for key, value in PUSH_HEADERS.items())
        assert session.headers["featureCode"] == FEATURE_CODE
        assert session.proxies == supplied.proxies
        assert session.cert == supplied.cert
        assert session.verify == supplied.verify
        assert session.trust_env is False
        assert session.auth == supplied.auth
        assert session.params == supplied.params
        assert session.get_adapter(url) is adapter
        session.cookies.set("worker", "private")
        session.headers["Worker-Only"] = "private"
        if url.endswith("/v3/push/token"):
            return response({"meta": {"code": 403 if len(calls) == 1 else 200}})
        return response({"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "rotated", "refreshSessionId": "rotated-refresh"
        }})

    monkeypatch.setattr(requests.Session, "put", put)
    monkeypatch.setattr("pyezvizapi.mqtt.PushWorker.start", lambda self: None)
    client = MQTTClient(token(), supplied, on_token_updated=lambda snapshot: None)
    client.connect()
    prepare_push(client)
    assert len(calls) == 3
    assert supplied.cookies.get("worker") is None
    assert "Worker-Only" not in supplied.headers
    assert "clientNo" not in supplied.headers
    assert supplied.headers["sessionId"] == "rotated"
    close_adapter.assert_not_called()
