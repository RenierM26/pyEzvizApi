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


@pytest.mark.parametrize(
    ("bad_page", "message"),
    [
        ({"page": {"hasNext": True}, "deviceInfos": {"deviceSerial": "CAM1"}}, "deviceInfos"),
        ({"page": {}, "deviceInfos": [{"deviceSerial": "CAM2"}]}, "hasNext"),
        ({"deviceInfos": []}, "hasNext"),
        ({"page": {"hasNext": False}, "deviceInfos": [{"deviceSerial": " "}]}, "deviceInfos"),
        ({"page": {"hasNext": False}}, "deviceInfos"),
    ],
)
def test_get_device_strict_rejects_incomplete_inventory(monkeypatch, bad_page, message) -> None:
    client = _client()
    responses = iter(
        [
            {"meta": {"code": 200}, **bad_page},
            {"meta": {"code": 200}, "page": {"hasNext": False}, "deviceInfos": []},
        ]
    )
    monkeypatch.setattr(client, "_request_json", lambda *args, **kwargs: next(responses))

    with pytest.raises(PyEzvizError, match=message):
        client.get_device(strict=True)


@pytest.mark.parametrize("serials", [[], ["CAM1"], ["CAM1", "CAM2"]])
def test_get_device_strict_collects_complete_inventory(monkeypatch, serials) -> None:
    client = _client()
    offsets: list[int] = []

    def request(*args: Any, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        offset = params["offset"]
        offsets.append(offset)
        assert params["filter"] == "CLOUD"
        return {
            "meta": {"code": 200},
            "page": {"hasNext": int(offset == 0 and len(serials) > 1)},
            "deviceInfos": [{"deviceSerial": serial} for serial in serials[offset // 30 :][:1]],
        }

    monkeypatch.setattr(client, "_request_json", request)
    assert client.get_device(strict=True) == [{"deviceSerial": serial} for serial in serials]
    assert offsets == ([0, 30] if len(serials) > 1 else [0])


def test_get_device_default_accepts_legacy_page_without_metadata(monkeypatch) -> None:
    client = _client()
    devices = [{"deviceSerial": "CAM1"}]
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda *args, **kwargs: {"meta": {"code": 200}, "deviceInfos": devices},
    )

    assert client.get_device() == devices


@pytest.mark.parametrize("missing", ["page", "resourceInfos"])
def test_projected_pagelist_retries_once_at_same_offset(monkeypatch, missing) -> None:
    client = _client()
    first = {"page": {"hasNext": True}, "deviceInfos": [{"deviceSerial": "A"}], "resourceInfos": []}
    last = {"page": {"hasNext": False}, "deviceInfos": [{"deviceSerial": "B"}], "resourceInfos": []}
    partial = {key: value for key, value in last.items() if key != missing}
    offsets = []
    responses = {0: iter([first]), 30: iter([partial, last])}

    def fetch(_method, _path, *, params, **_kwargs):
        offsets.append(params["offset"])
        return {"meta": {"code": 200}, **next(responses[params["offset"]])}

    monkeypatch.setattr(client, "_request_json", fetch)
    records = client.get_device_records()
    assert isinstance(records, dict)
    assert set(records) == {"A", "B"}
    assert offsets == [0, 30, 30]


def test_raw_pagelist_still_returns_incomplete_payload_without_retry(monkeypatch) -> None:
    client = _client()
    payload = {"meta": {"code": 200}, "deviceInfos": [{"deviceSerial": "A"}]}
    calls = []

    def fetch(*_args, **kwargs):
        calls.append(kwargs["params"]["offset"])
        return payload

    monkeypatch.setattr(client, "_request_json", fetch)
    assert client.get_page_list() == payload
    assert calls == [0]
    with pytest.raises(PyEzvizError, match="explicit hasNext"):
        client.get_device_records()
    assert calls == [0, 0, 0]


def test_inventory_debug_logs_only_safe_diagnostics(monkeypatch, caplog) -> None:
    client = _client()
    private = "PRIVATE_CANARY"
    responses = iter(
        [
            {
                "deviceInfos": [{"deviceSerial": private}],
                "meta": {
                    "code": 200,
                    "message": private,
                    "moreInfo": {"STATUS": private, private: private},
                },
            },
            {
                "deviceInfos": [{"deviceSerial": private}],
                "resourceInfos": [],
                "meta": {"code": 200},
                "page": {"hasNext": False},
            },
        ]
    )
    monkeypatch.setattr(client, "_request_json", lambda *a, **kw: next(responses))
    with caplog.at_level("DEBUG", logger="pyezvizapi.cloud.pagination"):
        client.get_device_records()
    assert private not in caplog.text
    assert "deferred_sections=['STATUS']" in caplog.text
    assert "phase=retry invalid_has_next=False missing_resources=False" in caplog.text
    assert "pages_checked=1 incomplete_pages=1 retries_recovered=1" in caplog.text
