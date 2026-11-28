"""Shared offline HTTP fixture for device controls."""

from collections.abc import Iterator
import json
from typing import Any

import pytest
import requests

from pyezvizapi import EzvizClient


@pytest.fixture
def device_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[EzvizClient, list[requests.PreparedRequest], list[dict[str, Any]]]]:
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.invalid"})
    sent: list[requests.PreparedRequest] = []
    replies: list[dict[str, Any]] = []

    def send(
        _session: requests.Session, request: requests.PreparedRequest, **_kwargs: Any
    ) -> requests.Response:
        sent.append(request)
        assert replies, f"Unexpected request: {request.method} {request.url}"
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(replies.pop(0)).encode()  # noqa: SLF001 - offline response.
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    try:
        yield client, sent, replies
    finally:
        client.close_session()
