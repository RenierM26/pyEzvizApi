"""Public migration and durable-state callback contracts."""
# ruff: noqa: SLF001

from copy import deepcopy
import json
from typing import Any
from unittest.mock import Mock

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.exceptions import EzvizAuthTokenExpired, PyEzvizError
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
