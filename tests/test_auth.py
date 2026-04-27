from __future__ import annotations

from hashlib import md5
from typing import Any

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.constants import FEATURE_CODE, REQUEST_HEADER
from pyezvizapi.exceptions import EzvizAuthTokenExpired, EzvizAuthVerificationCode, PyEzvizError


def _response(payload: dict[str, Any], *, status_code: int = 200) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = __import__("json").dumps(payload).encode()
    resp.url = "https://api.example.test/path"
    return resp


def test_client_init_with_token_sets_session_header() -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})

    assert client._session.headers["sessionId"] == "session-id"
    assert client.export_token() == {"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"}


def test_export_token_returns_shallow_copy() -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})

    exported = client.export_token()
    exported["session_id"] = "changed"

    assert client.export_token()["session_id"] == "session-id"


def test_close_session_resets_requests_session_and_default_headers() -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})

    client.close_session()

    assert client._session.headers["sessionId"] == REQUEST_HEADER["sessionId"]
    assert client._session.headers["clientType"] == REQUEST_HEADER["clientType"]


def test_login_refreshes_existing_token(monkeypatch) -> None:
    client = EzvizClient(
        token={
            "session_id": "old-session",
            "rf_session_id": "old-refresh",
            "api_url": "apiieu.ezvizlife.com",
        }
    )
    captured: dict[str, Any] = {}

    def fake_put(**kwargs: Any) -> requests.Response:
        captured.update(kwargs)
        return _response(
            {
                "meta": {"code": 200},
                "sessionInfo": {
                    "sessionId": "new-session",
                    "refreshSessionId": "new-refresh",
                },
            }
        )

    monkeypatch.setattr(client._session, "put", fake_put)
    monkeypatch.setattr(client, "get_service_urls", lambda: {"pushAddr": "push.example.test"})

    token = client.login()

    assert captured["data"] == {
        "refreshSessionId": "old-refresh",
        "featureCode": FEATURE_CODE,
    }
    assert token["session_id"] == "new-session"
    assert token["rf_session_id"] == "new-refresh"
    assert token["service_urls"] == {"pushAddr": "push.example.test"}
    assert client._session.headers["sessionId"] == "new-session"


def test_login_refresh_uses_existing_service_urls(monkeypatch) -> None:
    client = EzvizClient(
        token={
            "session_id": "old-session",
            "rf_session_id": "old-refresh",
            "api_url": "apiieu.ezvizlife.com",
            "service_urls": {"pushAddr": "existing.example.test"},
        }
    )

    def fake_put(**kwargs: Any) -> requests.Response:
        return _response(
            {
                "meta": {"code": 200},
                "sessionInfo": {
                    "sessionId": "new-session",
                    "refreshSessionId": "new-refresh",
                },
            }
        )

    monkeypatch.setattr(client._session, "put", fake_put)
    monkeypatch.setattr(
        client,
        "get_service_urls",
        lambda: pytest.fail("service URLs should not be fetched when already present"),
    )

    assert client.login()["service_urls"] == {"pushAddr": "existing.example.test"}


def test_login_refresh_expired_without_credentials_raises(monkeypatch) -> None:
    client = EzvizClient(
        token={
            "session_id": "old-session",
            "rf_session_id": "old-refresh",
            "api_url": "apiieu.ezvizlife.com",
        }
    )
    monkeypatch.setattr(client._session, "put", lambda **kwargs: _response({"meta": {"code": 403}}))

    with pytest.raises(EzvizAuthTokenExpired):
        client.login()


def test_login_with_credentials_posts_hashed_password_and_stores_token(monkeypatch) -> None:
    client = EzvizClient(account="user@example.test", password="secret", url="eu")
    captured: dict[str, Any] = {}

    def fake_post(**kwargs: Any) -> requests.Response:
        captured.update(kwargs)
        return _response(
            {
                "meta": {"code": 200},
                "loginSession": {
                    "sessionId": "session-id",
                    "rfSessionId": "refresh-id",
                },
                "loginUser": {"username": "internal-user"},
                "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
            }
        )

    monkeypatch.setattr(client._session, "post", fake_post)
    monkeypatch.setattr(client, "get_service_urls", lambda: {"pushAddr": "push.example.test"})

    token = client.login()

    assert captured["url"] == "https://apiieu.ezvizlife.com/v3/users/login/v5"
    assert captured["data"]["account"] == "user@example.test"
    assert captured["data"]["password"] == md5(b"secret").hexdigest()
    assert captured["data"]["msgType"] == "0"
    assert token == {
        "session_id": "session-id",
        "rf_session_id": "refresh-id",
        "username": "internal-user",
        "api_url": "apiieu.ezvizlife.com",
        "service_urls": {"pushAddr": "push.example.test"},
    }


def test_login_with_sms_code_sets_mfa_payload(monkeypatch) -> None:
    client = EzvizClient(account="user@example.test", password="secret")
    captured: dict[str, Any] = {}

    def fake_post(**kwargs: Any) -> requests.Response:
        captured.update(kwargs)
        return _response(
            {
                "meta": {"code": 200},
                "loginSession": {
                    "sessionId": "session-id",
                    "rfSessionId": "refresh-id",
                },
                "loginUser": {"username": "internal-user"},
                "loginArea": {"apiDomain": "apiieu.ezvizlife.com"},
            }
        )

    monkeypatch.setattr(client._session, "post", fake_post)
    monkeypatch.setattr(client, "get_service_urls", lambda: {})

    client.login(sms_code=123456)

    assert captured["data"]["msgType"] == "3"
    assert captured["data"]["bizType"] == "TERMINAL_BIND"
    assert captured["data"]["smsCode"] == 123456


def test_login_mfa_required_sends_code_and_raises(monkeypatch) -> None:
    client = EzvizClient(account="user@example.test", password="secret")
    send_calls = 0

    monkeypatch.setattr(client._session, "post", lambda **kwargs: _response({"meta": {"code": 6002}}))

    def fake_send_mfa_code() -> bool:
        nonlocal send_calls
        send_calls += 1
        return True

    monkeypatch.setattr(client, "send_mfa_code", fake_send_mfa_code)

    with pytest.raises(EzvizAuthVerificationCode):
        client.login()

    assert send_calls == 1


def test_send_mfa_code_success_and_failure(monkeypatch) -> None:
    client = EzvizClient(account="user@example.test", password="secret")
    calls: list[dict[str, Any]] = []

    def fake_request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append({"method": method, "path": path, **kwargs})
        return {"meta": {"code": 200}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    assert client.send_mfa_code() is True
    assert calls[0]["data"] == {"from": "user@example.test", "bizType": "TERMINAL_BIND"}
    assert calls[0]["retry_401"] is False

    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: {"meta": {"code": 500}})

    with pytest.raises(PyEzvizError, match="Could not request MFA code"):
        client.send_mfa_code()


def test_logout_deletes_session_and_closes_local_session(monkeypatch) -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})
    captured: dict[str, Any] = {}
    closed = False

    def fake_delete(**kwargs: Any) -> requests.Response:
        captured.update(kwargs)
        return _response({"meta": {"code": 200}})

    def fake_close_session() -> None:
        nonlocal closed
        closed = True

    monkeypatch.setattr(client._session, "delete", fake_delete)
    monkeypatch.setattr(client, "close_session", fake_close_session)

    assert client.logout() is True
    assert captured["url"] == "https://apiieu.ezvizlife.com/v3/users/logout/v2"
    assert captured["timeout"] == 25
    assert closed is True


def test_logout_returns_false_for_non_ok_meta_and_still_closes(monkeypatch) -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})
    closed = False

    def fake_delete(**kwargs: Any) -> requests.Response:
        return _response({"meta": {"code": 500}})

    def fake_close_session() -> None:
        nonlocal closed
        closed = True

    monkeypatch.setattr(client._session, "delete", fake_delete)
    monkeypatch.setattr(client, "close_session", fake_close_session)

    assert client.logout() is False
    assert closed is True


def test_logout_treats_401_as_already_invalid(monkeypatch) -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})

    def fake_delete(**kwargs: Any) -> requests.Response:
        return _response({"meta": {"code": 401}}, status_code=401)

    monkeypatch.setattr(client._session, "delete", fake_delete)
    monkeypatch.setattr(client, "close_session", lambda: pytest.fail("401 logout should not close again"))

    assert client.logout() is True


def test_logout_wraps_invalid_json(monkeypatch) -> None:
    client = EzvizClient(token={"session_id": "session-id", "api_url": "apiieu.ezvizlife.com"})
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"not-json"
    resp.url = "https://api.example.test/logout"

    monkeypatch.setattr(client._session, "delete", lambda **kwargs: resp)

    with pytest.raises(PyEzvizError, match="Impossible to decode response"):
        client.logout()
