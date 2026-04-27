from __future__ import annotations

from typing import Any

import pytest
import requests

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import HTTPError, PyEzvizError


def _client() -> EzvizClient:
    return EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"},
        timeout=1,
    )


def _response(*, status_code: int = 200, text: str = '{"meta": {"code": 200}}') -> requests.Response:
    resp = requests.Response()
    resp.status_code = status_code
    resp._content = text.encode()
    resp.url = "https://api.example.test/path"
    return resp


def test_parse_json_returns_decoded_payload() -> None:
    assert EzvizClient._parse_json(_response(text='{"resultCode": "0", "value": 1}')) == {
        "resultCode": "0",
        "value": 1,
    }


def test_parse_json_raises_contextual_error_for_invalid_json() -> None:
    with pytest.raises(PyEzvizError, match="Impossible to decode response"):
        EzvizClient._parse_json(_response(text="not-json"))


def test_normalize_json_payload_accepts_common_shapes() -> None:
    assert EzvizClient._normalize_json_payload({"a": 1}) == {"a": 1}
    assert EzvizClient._normalize_json_payload(("a", "b")) == ["a", "b"]
    assert EzvizClient._normalize_json_payload(b'{"a": 1}') == {"a": 1}
    assert EzvizClient._normalize_json_payload('["a"]') == ["a"]


def test_normalize_json_payload_rejects_invalid_shapes() -> None:
    with pytest.raises(PyEzvizError, match="Invalid JSON payload"):
        EzvizClient._normalize_json_payload("not-json")

    with pytest.raises(PyEzvizError, match="Unsupported payload type"):
        EzvizClient._normalize_json_payload(123)


def test_meta_and_ok_helpers_support_modern_and_legacy_responses() -> None:
    assert EzvizClient._meta_code({"meta": {"code": "200"}}) == 200
    assert EzvizClient._meta_ok({"meta": {"code": 200}}) is True
    assert EzvizClient._is_ok({"meta": {"code": 200}}) is True
    assert EzvizClient._is_ok({"resultCode": "0"}) is True
    assert EzvizClient._is_ok({"resultCode": 0}) is True
    assert EzvizClient._is_ok({"meta": {"code": 500}}) is False
    assert EzvizClient._response_code({"status": 200}) == 200


def test_ensure_ok_raises_contextual_error() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="Could not test"):
        client._ensure_ok({"meta": {"code": 500}}, "Could not test")


def test_http_request_relogs_and_retries_on_401(monkeypatch) -> None:
    client = _client()
    responses = [_response(status_code=401, text="{}"), _response(text='{"ok": true}')]
    calls: list[dict[str, Any]] = []
    login_calls = 0

    def fake_request(**kwargs: Any) -> requests.Response:
        calls.append(kwargs)
        return responses.pop(0)

    def fake_login(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal login_calls
        login_calls += 1
        return {"session_id": "new-session", "api_url": "apiieu.ezvizlife.com"}

    monkeypatch.setattr(client._session, "request", fake_request)
    monkeypatch.setattr(client, "login", fake_login)

    resp = client._http_request("GET", "https://api.example.test/path")

    assert resp.status_code == 200
    assert login_calls == 1
    assert len(calls) == 2


def test_http_request_wraps_non_401_errors(monkeypatch) -> None:
    client = _client()

    def fake_request(**kwargs: Any) -> requests.Response:
        return _response(status_code=500, text="server error")

    monkeypatch.setattr(client._session, "request", fake_request)

    with pytest.raises(HTTPError):
        client._http_request("GET", "https://api.example.test/path")


def test_request_json_uses_url_and_parses_payload(monkeypatch) -> None:
    client = _client()
    captured: dict[str, Any] = {}

    def fake_http_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        captured.update({"method": method, "url": url, **kwargs})
        return _response(text='{"meta": {"code": 200}, "value": 1}')

    monkeypatch.setattr(client, "_http_request", fake_http_request)

    payload = client._request_json("POST", "/api/path", json_body={"x": 1})

    assert payload == {"meta": {"code": 200}, "value": 1}
    assert captured["method"] == "POST"
    assert captured["url"] == "https://apiieu.ezvizlife.com/api/path"
    assert captured["json_body"] == {"x": 1}
