"""CLI OTP handling and explicit channel selection without a real account."""

from unittest.mock import Mock

import pytest

from pyezvizapi.cli import main as cli
from pyezvizapi.exceptions import EzvizAuthVerificationCode, PyEzvizError


@pytest.mark.parametrize("channel, expected", [("sms", 1), ("email", 3)])
def test_cli_login_keeps_selected_contact_and_string_code(monkeypatch, channel, expected):
    client = Mock(account="synthetic", password="synthetic")
    client.login.side_effect = [EzvizAuthVerificationCode(code=6002, code_sent=True), None]
    monkeypatch.setattr("builtins.input", lambda _: "001234")
    cli._login(client, mfa_channel=channel, mfa_account="bound@example.test")  # noqa: SLF001
    assert client.login.call_args_list[0].kwargs == {"mfa_channel": expected, "mfa_account": "bound@example.test"}
    assert client.login.call_args_list[1].kwargs == {"sms_code": "001234", "mfa_channel": expected, "mfa_account": "bound@example.test"}


def test_cli_unsent_challenge_does_not_prompt_for_undelivered_code(monkeypatch):
    client = Mock(account="synthetic", password="synthetic")
    client.login.side_effect = EzvizAuthVerificationCode(code=6002, code_sent=False)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("No code requested"))
    with pytest.raises(PyEzvizError, match="No MFA code requested"):
        cli._login(client)  # noqa: SLF001
    assert client.login.call_count == 1


@pytest.mark.parametrize("code", ["", "not-numeric", "\uff11\uff12\uff13"])
def test_cli_bad_code_never_repeats_plain_login(monkeypatch, code):
    client = Mock(account="synthetic", password="synthetic")
    client.login.side_effect = EzvizAuthVerificationCode()
    monkeypatch.setattr("builtins.input", lambda _: code)
    with pytest.raises(PyEzvizError, match="ASCII digit"):
        cli._login(client)  # noqa: SLF001
    assert client.login.call_count == 1
