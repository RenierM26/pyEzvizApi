from __future__ import annotations

from typing import Any

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError


def _client() -> EzvizClient:
    return EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"},
        timeout=1,
    )


def test_api_get_pagelist_fetches_and_merges_pages(monkeypatch) -> None:
    client = _client()
    calls: list[dict[str, Any]] = []

    def fake_request_json(
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        retry_401: bool = True,
        max_retries: int = 0,
    ) -> dict[str, Any]:
        calls.append(
            {
                "method": method,
                "path": path,
                "params": params,
                "retry_401": retry_401,
                "max_retries": max_retries,
            }
        )
        offset = params["offset"] if params else 0
        if offset == 0:
            return {
                "meta": {"code": 200},
                "page": {"hasNext": True},
                "SWITCH": {"CAM1": [{"type": 7, "enable": 1}]},
            }
        return {
            "meta": {"code": 200},
            "page": {"hasNext": False},
            "SWITCH": {"CAM2": [{"type": 21, "enable": 0}]},
        }

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    data = client._api_get_pagelist("SWITCH", json_key="SWITCH", limit=1)

    assert data == {
        "CAM1": [{"type": 7, "enable": 1}],
        "CAM2": [{"type": 21, "enable": 0}],
    }
    assert [call["params"]["offset"] for call in calls] == [0, 1]
    assert all(call["params"]["filter"] == "SWITCH" for call in calls)


def test_api_get_pagelist_returns_full_payload_when_json_key_omitted(monkeypatch) -> None:
    client = _client()

    def fake_request_json(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "meta": {"code": 200},
            "page": {"hasNext": False},
            "deviceInfos": [{"deviceSerial": "CAM1"}],
        }

    monkeypatch.setattr(client, "_request_json", fake_request_json)

    data = client._api_get_pagelist("deviceInfos")

    assert data["deviceInfos"] == [{"deviceSerial": "CAM1"}]


def test_api_get_pagelist_relogs_in_on_non_200_meta(monkeypatch) -> None:
    client = _client()
    responses = iter(
        [
            {"meta": {"code": 401}, "page": {"hasNext": False}, "SWITCH": {}},
            {
                "meta": {"code": 200},
                "page": {"hasNext": False},
                "SWITCH": {"CAM1": [{"type": 7, "enable": 1}]},
            },
        ]
    )
    login_calls = 0

    def fake_request_json(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return next(responses)

    def fake_login(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal login_calls
        login_calls += 1
        return {"session_id": "new-session", "api_url": "apiieu.ezvizlife.com"}

    monkeypatch.setattr(client, "_request_json", fake_request_json)
    monkeypatch.setattr(client, "login", fake_login)

    data = client._api_get_pagelist("SWITCH", json_key="SWITCH")

    assert data == {"CAM1": [{"type": 7, "enable": 1}]}
    assert login_calls == 1


def test_api_get_pagelist_rejects_missing_filter() -> None:
    client = _client()

    with pytest.raises(PyEzvizError, match="without filter"):
        client._api_get_pagelist(None)  # type: ignore[arg-type]


def test_api_get_pagelist_stops_after_max_retries(monkeypatch) -> None:
    client = _client()

    def fake_request_json(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"meta": {"code": 401}, "page": {"hasNext": False}, "SWITCH": {}}

    monkeypatch.setattr(client, "_request_json", fake_request_json)
    monkeypatch.setattr(client, "login", lambda *args, **kwargs: {})

    with pytest.raises(PyEzvizError, match="Max retries exceeded"):
        client._api_get_pagelist("SWITCH", json_key="SWITCH")
