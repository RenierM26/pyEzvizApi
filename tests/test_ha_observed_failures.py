"""Offline controls derived from HA log signatures, with synthetic identifiers."""

# ruff: noqa: SLF001 -- replace the private HTTP session to forbid real requests.
from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest
import requests

import pyezvizapi.client as client_module
from pyezvizapi.constants import DeviceCatagories
from pyezvizapi.exceptions import HTTPError


@pytest.mark.parametrize(
    ("category", "factory", "stage"),
    [
        (DeviceCatagories.CAMERA_DEVICE_CATEGORY.value, "camera_status", "camera_status"),
        (DeviceCatagories.LIGHTING.value, "light_bulb_status", "light_bulb_status"),
        (DeviceCatagories.SOCKET.value, "smart_plug_status", "smart_plug_status"),
    ],
)
@pytest.mark.parametrize("error", [HTTPError(), ValueError("PRIVATE_PAYLOAD_CANARY")])
def test_device_load_warning_identifies_stage_and_error_without_raw_payload(
    monkeypatch,
    caplog,
    category,
    factory,
    stage,
    error,
):
    client = client_module.EzvizClient(token={"session_id": "test", "api_url": "example.test"})
    monkeypatch.setattr(
        client,
        "get_device_records",
        lambda _serial=None: {
            "TEST_DEVICE": client_module.EzvizDeviceRecord.from_api(
                "TEST_DEVICE",
                {
                    "deviceInfos": {"deviceCategory": category},
                },
            ),
        },
    )
    monkeypatch.setattr(client_module.device_factory, factory, Mock(side_effect=error))
    with caplog.at_level(logging.WARNING, logger="pyezvizapi.client"):
        assert client.load_devices(refresh=False) == {}
    assert f"error_type={type(error).__name__}" in caplog.text
    assert f"stage={stage}" in caplog.text
    assert "PRIVATE_PAYLOAD_CANARY" not in caplog.text
    client.close_session()


def test_observed_alarm_connection_reset_is_not_replayed_and_next_poll_can_recover(monkeypatch):
    client = client_module.EzvizClient(token={"session_id": "test", "api_url": "example.test"})
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"meta":{"code":200},"mode":1}'
    reset = requests.ConnectionError(
        "Connection aborted.", ConnectionResetError(104, "Connection reset by peer")
    )
    request = Mock(side_effect=[reset, response])
    login = Mock(side_effect=AssertionError("A network reset is not an authentication failure"))
    monkeypatch.setattr(client._session, "request", request)
    monkeypatch.setattr(client, "login", login)
    with pytest.raises(requests.ConnectionError) as caught:
        client.get_group_defence_mode()
    assert caught.value is reset
    assert request.call_count == 1
    login.assert_not_called()
    assert client.get_group_defence_mode() == 1
    assert request.call_count == 2
    client.close_session()


def test_unlock_connection_reset_does_not_retry_a_possibly_applied_action(monkeypatch):
    client = client_module.EzvizClient(token={"session_id": "test", "api_url": "example.test"})
    request = Mock(side_effect=requests.ConnectionError("Connection reset by peer"))
    login = Mock(side_effect=AssertionError("Do not relogin and replay controls after a reset"))
    monkeypatch.setattr(client._session, "request", request)
    monkeypatch.setattr(client, "login", login)
    with pytest.raises(requests.ConnectionError):
        client.remote_unlock("TEST_DEVICE", "test-user", 1, use_terminal_bind=False)
    assert request.call_count == 1
    login.assert_not_called()
    client.close_session()
