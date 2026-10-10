"""HTTP bootstrap budget regressions."""
from threading import RLock
from unittest.mock import Mock

import pytest

from pyezvizapi._request_deadline import (
    bounded_request_timeout,
    remaining_request_budget,
    request_budget_lock,
    request_deadline,
)
from pyezvizapi.client import EzvizClient
from pyezvizapi.cloud_stream import open_cloud_stream


def test_deadline_bounds_http_without_mutating_client_and_resets(monkeypatch) -> None:
    client = EzvizClient(timeout=30)
    response = Mock()
    request = Mock(return_value=response)
    monkeypatch.setattr(client._session, "request", request)  # noqa: SLF001
    clock = [10.0]
    with pytest.raises(TimeoutError), request_deadline(12, lambda: clock[0]):
        client._http_request("GET", "https://example.invalid")  # noqa: SLF001
        timeout = request.call_args.kwargs["timeout"]
        assert timeout.total == 2
        clock[0] = 12
        with pytest.raises(TimeoutError):
            client._http_request("GET", "https://example.invalid")  # noqa: SLF001
    assert request.call_count == 1
    assert client._timeout == 30  # noqa: SLF001
    assert bounded_request_timeout(30) == 30


def test_budget_lock_uses_remaining_time_and_releases() -> None:
    lock = Mock()
    lock.acquire.return_value = False
    with request_deadline(7, lambda: 5), pytest.raises(TimeoutError), request_budget_lock(lock):
        pytest.fail("lock acquisition should fail")
    lock.acquire.assert_called_once_with(timeout=2)
    lock.release.assert_not_called()
    with request_deadline(7, lambda: 5), request_budget_lock(RLock()):
        assert remaining_request_budget() == 2


def test_cloud_metadata_exhaustion_prevents_transport_construction(monkeypatch) -> None:
    clock = [10.0]
    def metadata(*_args, **_kwargs):
        assert bounded_request_timeout(30).total == 2
        clock[0] = 12
        return {"stream_url": "unused"}
    monkeypatch.setattr("pyezvizapi.cloud_stream.get_cloud_stream_info", metadata)
    monkeypatch.setattr("pyezvizapi.cloud_stream.VtmStreamClient", lambda *_a, **_kw: pytest.fail("expired metadata must not open transport"))
    with pytest.raises(TimeoutError):
        open_cloud_stream(object(), "camera", capture_deadline=12, monotonic=lambda: clock[0])
    assert remaining_request_budget() is None


def test_nested_budget_cannot_extend_parent_and_is_restored() -> None:
    with request_deadline(12, lambda: 10):
        with request_deadline(30, lambda: 10):
            assert bounded_request_timeout(30).total == 2
        with request_deadline(11, lambda: 10):
            assert bounded_request_timeout(30).total == 1
        assert remaining_request_budget() == 2
    assert remaining_request_budget() is None


def test_expired_unauthorized_request_cannot_start_login(monkeypatch) -> None:
    import requests  # noqa: PLC0415
    client = EzvizClient(timeout=30)
    clock = [10.0]
    response = Mock(status_code=401)
    def request(**_kwargs):
        clock[0] = 12
        response.raise_for_status.side_effect = requests.HTTPError(response=response)
        return response
    monkeypatch.setattr(client._session, "request", request)  # noqa: SLF001
    login = Mock()
    monkeypatch.setattr(client, "login", login)
    with pytest.raises(TimeoutError), request_deadline(12, lambda: clock[0]):
        client._http_request("GET", "https://example.invalid")  # noqa: SLF001
    login.assert_not_called()


@pytest.mark.parametrize("expires_during_refresh", [False, True])
def test_401_refresh_and_retry_share_budget_and_preserve_rotated_token(monkeypatch, expires_during_refresh) -> None:
    import json  # noqa: PLC0415

    import requests  # noqa: PLC0415
    saved: list[dict] = []
    client = EzvizClient(timeout=30, token={
        "session_id": "old-session", "rf_session_id": "old-refresh",
        "api_url": "example.invalid", "service_urls": {"existing": True},
    }, on_token_updated=saved.append)
    clock = [10.0]
    timeouts: list[float] = []
    def response(status, body):
        result = requests.Response()
        result.status_code = status
        result._content = json.dumps(body).encode()  # noqa: SLF001
        return result
    calls = [0]
    def request(**kwargs):
        timeouts.append(kwargs["timeout"].total)
        calls[0] += 1
        clock[0] += 0.5
        return response(401 if calls[0] == 1 else 200, {})
    def refresh(**kwargs):
        timeouts.append(kwargs["timeout"].total)
        clock[0] = 12 if expires_during_refresh else 11
        return response(200, {"meta": {"code": 200}, "sessionInfo": {
            "sessionId": "new-session", "refreshSessionId": "new-refresh",
        }})
    monkeypatch.setattr(client._session, "request", request)  # noqa: SLF001
    monkeypatch.setattr(client._session, "put", refresh)  # noqa: SLF001
    if expires_during_refresh:
        with pytest.raises(TimeoutError), request_deadline(12, lambda: clock[0]):
            client._http_request("GET", "https://example.invalid")  # noqa: SLF001
        assert timeouts == [2, 1.5]
    else:
        with request_deadline(12, lambda: clock[0]):
            client._http_request("GET", "https://example.invalid")  # noqa: SLF001
        assert timeouts == [2, 1.5, 1]
    assert saved[0]["session_id"] == "new-session"
    assert saved[0]["rf_session_id"] == "new-refresh"
    assert client._timeout == 30  # noqa: SLF001
