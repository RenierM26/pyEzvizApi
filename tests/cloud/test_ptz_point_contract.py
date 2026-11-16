"""Offline app-shaped point PTZ requests through the real IoT serializer."""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest
import requests

from pyezvizapi import EzvizClient
from pyezvizapi.exceptions import PyEzvizError


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("Point PTZ controls must remain offline")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.mark.parametrize(("x", "y"), [(0, 0), (0.5, 0.5), (1, 1), (0.25, 0.75)])
@pytest.mark.parametrize("route", [{}, {"resource_identifier": "Video", "local_index": "0"}])
def test_point_request_matches_app_model(
    monkeypatch: pytest.MonkeyPatch, x: float, y: float, route: dict[str, str]
) -> None:
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.invalid"})
    requests_sent: list[requests.PreparedRequest] = []

    def send(request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        requests_sent.append(request)
        assert kwargs == {"retry_401": True, "max_retries": 0}
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"meta":{"code":200}}'  # noqa: SLF001 - Synthetic transport response.
        return response

    monkeypatch.setattr(client, "_send_prepared", send)
    try:
        assert client.ptz_control_coordinates(
            "CAM001",
            x,
            y,
            resource_identifier=route.get("resource_identifier", "Video_1"),
            local_index=route.get("local_index", "1"),
        )
        assert len(requests_sent) == 1
        request = requests_sent[0]
        resource = route.get("resource_identifier", "Video_1")
        index = route.get("local_index", "1")
        assert request.method == "PUT"
        assert (
            request.url
            == f"https://api.example.invalid/v3/iot-feature/action/CAM001/{resource}/{index}/PTZManualCtrl/CtrlPTZ3DPosition"
        )
        assert request.headers["Content-Type"] == "application/json"
        assert isinstance(request.body, (str, bytes))
        assert json.loads(request.body) == {
            "positionCtrlType": "point",
            "zoomType": "zoomIn",
            "positionPoint": {"x": x, "y": y},
            "positionRect": {"height": 1.0, "width": 1.0, "x": 0.0, "y": 0.0},
        }
    finally:
        client.close_session()


@pytest.mark.parametrize("axis", ["x", "y"])
@pytest.mark.parametrize(
    "value", [True, False, -0.01, 1.01, float("nan"), float("inf"), -float("inf"), None, "0.5"]
)
def test_invalid_coordinate_never_reaches_transport(
    monkeypatch: pytest.MonkeyPatch, axis: str, value: Any
) -> None:
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.invalid"})

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("Invalid coordinate reached transport")

    monkeypatch.setattr(client, "_send_prepared", forbidden)
    try:
        with pytest.raises(PyEzvizError, match=f"Invalid {axis.upper()} coordinate"):
            client.ptz_control_coordinates(
                "CAM001", value if axis == "x" else 0.5, value if axis == "y" else 0.5
            )
    finally:
        client.close_session()


@pytest.mark.parametrize("code", [400, 403, 500])
def test_point_rejection_is_not_success(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    client = EzvizClient(token={"session_id": "synthetic", "api_url": "api.example.invalid"})

    def send(*_args: Any, **_kwargs: Any) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"meta": {"code": code}}).encode()  # noqa: SLF001 - Synthetic transport response.
        return response

    monkeypatch.setattr(client, "_send_prepared", send)
    try:
        with pytest.raises(PyEzvizError, match="Could not move PTZ to coordinates"):
            client.ptz_control_coordinates("CAM001", 0.5, 0.5)
    finally:
        client.close_session()
