"""Malformed refresh/discovery responses must not partially rotate credentials."""
import json
from unittest.mock import Mock

import pytest
import requests

from pyezvizapi._auth import discover_services, refresh_credentials
from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.exceptions import PyEzvizError


@pytest.mark.parametrize("info", [None, [], "bad", {"sessionId": "new"}, {"refreshSessionId": "new"}, {"sessionId": None, "refreshSessionId": "new"}, {"sessionId": "new", "refreshSessionId": ""}, {"sessionId": ["new"], "refreshSessionId": "new"}])
def test_malformed_refresh_keeps_both_credentials_and_headers_unchanged(monkeypatch, info):
    session = requests.Session()
    session.headers["sessionId"] = "old"
    token = {"session_id": "old", "rf_session_id": "old-refresh", "api_url": "unused.invalid", "feature_code": FEATURE_CODE, "service_urls": {"sysConf": []}}
    before = dict(token)
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"meta": {"code": 200}, "sessionInfo": info}).encode()  # noqa: SLF001
    monkeypatch.setattr(session, "put", Mock(return_value=response))
    notify, discover = Mock(), Mock()
    try:
        with pytest.raises(PyEzvizError):
            refresh_credentials(session, token, 1, notify, discover)
        assert token == before
        assert session.headers["sessionId"] == "old"
        notify.assert_not_called()
        discover.assert_not_called()
    finally:
        session.close()


@pytest.mark.parametrize("config", [None, [], "bad"])
def test_service_discovery_rejects_non_object_configuration(monkeypatch, config):
    session = requests.Session()
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"meta": {"code": 200}, "systemConfigInfo": config}).encode()  # noqa: SLF001
    monkeypatch.setattr(session, "get", Mock(return_value=response))
    try:
        with pytest.raises(PyEzvizError):
            discover_services(session, {"api_url": "unused.invalid"}, 1)
    finally:
        session.close()
