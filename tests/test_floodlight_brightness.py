"""Tests for set_floodlight_brightness luminance validation."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from pyezvizapi.client import EzvizClient
from pyezvizapi.exceptions import PyEzvizError


def _client() -> EzvizClient:
    return EzvizClient(
        token={"session_id": "session", "api_url": "apiieu.ezvizlife.com"},
        timeout=1,
    )


def _ok_response(*_a: Any, **_kw: Any) -> dict[str, Any]:
    return {"meta": {"code": 200}, "resultCode": "0"}


@pytest.mark.parametrize("luminance", [1, 50, 99, 100])
def test_set_floodlight_brightness_accepts_valid_range(luminance: int) -> None:
    """Luminance values 1-100 (inclusive) must be accepted.

    Regression test for an off-by-one in the validation:
    range(1, 100) excluded 100 even though the docstring/error message
    documented 1-100 as the valid range. Some camera models switch to
    colour night-vision only at exactly 100, so rejecting 100 was a
    real user-facing regression.
    """
    client = _client()
    with patch.object(EzvizClient, "_request_json", side_effect=_ok_response):
        assert client.set_floodlight_brightness(
            serial="ABC123",
            luminance=luminance,
            channelno=1,
        ) is True


@pytest.mark.parametrize("luminance", [-1, 0, 101, 200])
def test_set_floodlight_brightness_rejects_out_of_range(luminance: int) -> None:
    """Luminance values outside 1-100 must raise PyEzvizError."""
    client = _client()
    with (
        patch.object(EzvizClient, "_request_json", side_effect=_ok_response),
        pytest.raises(PyEzvizError, match="Range of luminance"),
    ):
        client.set_floodlight_brightness(
            serial="ABC123",
            luminance=luminance,
            channelno=1,
        )
