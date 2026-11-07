"""Fallback branches identified by CodeQL must remain reachable and truthful."""
import pytest

from pyezvizapi import hcnetsdk
from pyezvizapi.cli import main as cli
from pyezvizapi.exceptions import PyEzvizError


def test_native_address_preserves_printable_non_ip_fallback():
    assert hcnetsdk._fixed_ipv4_text(b"camera-host\0\0") == "camera-host"  # noqa: SLF001


def test_native_secret_preserves_non_utf8_wire_bytes():
    assert hcnetsdk._fixed_secret_text(b"\xff") == "\xff"  # noqa: SLF001


def test_cli_legacy_decimal_fallback_is_not_unreachable():
    assert cli._hcnetsdk_int("010") == 10  # noqa: SLF001
    with pytest.raises(PyEzvizError, match="Invalid HCNetSDK integer"):
        cli._hcnetsdk_int("not-a-number")  # noqa: SLF001
