"""Synthetic pagelist progress and merge-contract regressions."""
# ruff: noqa: SLF001 -- pagelist is an internal client boundary.
from unittest.mock import Mock

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError


@pytest.fixture
def client():
    instance = EzvizClient()
    yield instance
    instance.close_session()


@pytest.mark.parametrize("kwargs", [{"limit": 0}, {"limit": -1}, {"limit": True}, {"limit": 1.5}, {"offset": -1}, {"offset": True}])
def test_invalid_page_bounds_fail_before_http(client, monkeypatch, kwargs):
    request = Mock(side_effect=AssertionError("must validate before HTTP"))
    monkeypatch.setattr(client, "_request_json", request)
    with pytest.raises(PyEzvizError):
        client._api_get_pagelist("deviceInfos", **kwargs)
    request.assert_not_called()


@pytest.mark.parametrize("page", [[1], {"hasNext": "unknown"}, {"hasNext": True}])
def test_malformed_or_empty_non_final_page_is_rejected(client, monkeypatch, page):
    request = Mock(return_value={"meta": {"code": 200}, "page": page, "deviceInfos": []})
    monkeypatch.setattr(client, "_request_json", request)
    with pytest.raises(PyEzvizError):
        client._api_get_pagelist("deviceInfos")
    assert request.call_count == 1


def test_repeated_page_stops_without_duplicate_accumulation(client, monkeypatch):
    request = Mock(return_value={"meta": {"code": 200}, "page": {"hasNext": True}, "deviceInfos": [{"deviceSerial": "ONE"}]})
    monkeypatch.setattr(client, "_request_json", request)
    with pytest.raises(PyEzvizError, match="repeat"):
        client._api_get_pagelist("deviceInfos", json_key="deviceInfos")
    assert request.call_count == 2


def test_many_pages_do_not_recurse(client, monkeypatch):
    def page(_method, _path, *, params, **_kwargs):
        offset = params["offset"]
        return {"meta": {"code": 200}, "page": {"hasNext": offset < 299}, "deviceInfos": [offset]}
    monkeypatch.setattr(client, "_request_json", page)
    assert client._api_get_pagelist("deviceInfos", json_key="deviceInfos", limit=1) == list(range(300))


def test_nested_mixed_values_keep_original_right_associative_merge(client, monkeypatch):
    values = iter([{"x": {"a": 1}}, {"x": 2}, {"x": {"b": 3}}])
    calls = [0]
    def page(*_a, **_k):
        calls[0] += 1
        return {"meta": {"code": 200}, "page": {"hasNext": calls[0] < 3}, "VALUE": next(values)}
    monkeypatch.setattr(client, "_request_json", page)
    assert client._api_get_pagelist("VALUE", json_key="VALUE") == {"x": {"a": 1, "b": 3}}
