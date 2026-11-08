"""Application-level control acceptance, using synthetic responses only."""
from collections.abc import Iterator
from unittest.mock import Mock

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import HTTPError, PyEzvizError


@pytest.fixture
def client() -> Iterator[EzvizClient]:
    instance = EzvizClient()
    yield instance
    instance.close_session()


def invoke(client: EzvizClient, operation: str) -> bool:
    if operation == "lock":
        return client.remote_lock("TEST123", "user", 1)
    if operation == "unlock":
        return client.remote_unlock("TEST123", "user", 1, use_terminal_bind=False)
    return bool(client.ptz_control("LEFT", "TEST123", "START"))


@pytest.mark.parametrize("operation", ["lock", "unlock", "ptz"])
@pytest.mark.parametrize("payload", [
    {"meta": {"code": 200}}, {"resultCode": 0}, {"resultCode": "0"},
])
def test_controls_return_true_only_for_api_acceptance(client, monkeypatch, operation, payload):
    request = Mock(return_value=payload)
    monkeypatch.setattr(client, "_request_json", request)
    assert invoke(client, operation) is True
    request.assert_called_once()


@pytest.mark.parametrize("operation", ["lock", "unlock", "ptz"])
@pytest.mark.parametrize("payload", [
    {"meta": {"code": 500}}, {"resultCode": "-1"}, {},
    {"meta": {}}, {"meta": {"code": "rejected"}},
])
def test_controls_reject_application_errors(client, monkeypatch, operation, payload):
    request = Mock(return_value=payload)
    monkeypatch.setattr(client, "_request_json", request)
    with pytest.raises(PyEzvizError):
        invoke(client, operation)
    request.assert_called_once()


@pytest.mark.parametrize("operation", ["lock", "unlock", "ptz"])
@pytest.mark.parametrize("failure", [HTTPError("synthetic HTTP failure"), PyEzvizError("synthetic failure")])
def test_controls_preserve_transport_failures(client, monkeypatch, operation, failure):
    request = Mock(side_effect=failure)
    monkeypatch.setattr(client, "_request_json", request)
    with pytest.raises(type(failure)) as caught:
        invoke(client, operation)
    assert caught.value is failure
    request.assert_called_once()
