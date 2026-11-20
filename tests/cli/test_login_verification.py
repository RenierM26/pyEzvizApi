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


@pytest.fixture(params=["normal", "mqtt"])
def authentication_flow(request, monkeypatch):
    """Run each actual CLI wrapper with no live client, broker or persistent token."""
    import argparse  # noqa: PLC0415

    client = Mock(account="synthetic", password="synthetic")
    monkeypatch.setattr(cli.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    authenticate = client.login if request.param == "normal" else client.enable_channel99

    def run(channel=None, account=None):
        if request.param == "normal":
            cli._login(client, mfa_channel=channel, mfa_account=account)  # noqa: SLF001
        else:
            cli._handle_mqtt(argparse.Namespace(mfa_channel=channel, mfa_account=account), client)  # noqa: SLF001

    return run, authenticate


@pytest.mark.parametrize("channel, expected", [("email", 3), ("sms", 1)])
@pytest.mark.parametrize("code", ["001234", "000000", "123456"])
def test_both_cli_flows_share_contact_and_string_code_handling(authentication_flow, monkeypatch, channel, expected, code):
    run, authenticate = authentication_flow
    authenticate.side_effect = [EzvizAuthVerificationCode(code=6002, code_sent=True), None]
    prompt = Mock(return_value=code)
    monkeypatch.setattr("builtins.input", prompt)
    run(channel, "bound@example.test")
    assert [call.kwargs for call in authenticate.call_args_list] == [
        {"mfa_channel": expected, "mfa_account": "bound@example.test"},
        {"mfa_channel": expected, "mfa_account": "bound@example.test", "sms_code": code},
    ]
    prompt.assert_called_once()


def test_both_cli_flows_keep_legacy_no_option_call_shape(authentication_flow, monkeypatch):
    run, authenticate = authentication_flow
    authenticate.side_effect = [EzvizAuthVerificationCode(), None]
    monkeypatch.setattr("builtins.input", lambda _: "001234")
    run()
    assert [call.kwargs for call in authenticate.call_args_list] == [{}, {"sms_code": "001234"}]


def test_both_cli_flows_do_not_prompt_for_unsent_challenge(authentication_flow, monkeypatch):
    run, authenticate = authentication_flow
    authenticate.side_effect = EzvizAuthVerificationCode(code=6002, code_sent=False)
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("unsent code"))
    with pytest.raises(PyEzvizError, match="No MFA code requested"):
        run()
    assert authenticate.call_count == 1


@pytest.mark.parametrize("code", ["", "invalid", "\uff11\uff12\uff13"])
def test_both_cli_flows_stop_on_bad_input(authentication_flow, monkeypatch, code):
    run, authenticate = authentication_flow
    authenticate.side_effect = EzvizAuthVerificationCode()
    monkeypatch.setattr("builtins.input", lambda _: code)
    with pytest.raises(PyEzvizError, match="ASCII digit"):
        run()
    assert authenticate.call_count == 1


def test_both_cli_flows_never_retry_second_verification_error(authentication_flow, monkeypatch):
    run, authenticate = authentication_flow
    second = EzvizAuthVerificationCode(reason="verification_incorrect", code=1011)
    authenticate.side_effect = [EzvizAuthVerificationCode(), second]
    monkeypatch.setattr("builtins.input", lambda _: "001234")
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        run()
    assert caught.value is second and authenticate.call_count == 2


def test_both_cli_flows_do_not_prompt_for_non_mfa_errors(authentication_flow, monkeypatch):
    run, authenticate = authentication_flow
    authenticate.side_effect = PyEzvizError("synthetic failure")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("not MFA"))
    with pytest.raises(PyEzvizError, match="synthetic failure"):
        run()
    assert authenticate.call_count == 1
