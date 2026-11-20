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


@pytest.mark.parametrize("for_mfa, code", [(False, 1015), (True, 1101), (True, 1141)])
def test_human_captcha_resumes_correct_purpose_then_submits_one_otp(monkeypatch, for_mfa, code):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415
    from pyezvizapi.cloud.challenges import CaptchaChallenge  # noqa: PLC0415
    from pyezvizapi.exceptions import EzvizLoginError  # noqa: PLC0415

    image = CaptchaChallenge(b"synthetic", "image/png")
    first = EzvizLoginError("image needed", reason="captcha_required", code=code)
    authenticate = Mock(side_effect=[first, None] if for_mfa else [first, EzvizAuthVerificationCode(code=6002, code_sent=True), None])
    fetch = Mock(return_value=image)
    request = Mock(return_value=True)
    answer = Mock(return_value="aB01")
    cancel = Mock()
    monkeypatch.setattr("builtins.input", lambda _: "001234")
    login_with_verification(authenticate, mfa_channel="sms", fetch_captcha=fetch, send_mfa=request, answer_captcha=answer, cancel_captcha=cancel)
    fetch.assert_called_once_with(for_mfa=for_mfa)
    answer.assert_called_once_with(image)
    cancel.assert_called_once()
    assert authenticate.call_args_list[-1].kwargs == {"mfa_channel": 1, "sms_code": "001234"}
    if for_mfa:
        request.assert_called_once_with(captcha=image, captcha_code="aB01", mfa_channel=1)
    else:
        request.assert_not_called()
        assert authenticate.call_args_list[1].kwargs["captcha_code"] == "aB01"


def test_login_captcha_then_request_captcha_has_finite_human_stages(monkeypatch):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415
    from pyezvizapi.cloud.challenges import CaptchaChallenge  # noqa: PLC0415
    from pyezvizapi.exceptions import EzvizLoginError  # noqa: PLC0415

    authenticate = Mock(side_effect=[EzvizLoginError("image", reason="captcha_required", code=1015), EzvizLoginError("image", reason="captcha_required", code=1141), None])
    fetch = Mock(return_value=CaptchaChallenge(b"image", "image/png"))
    request = Mock(return_value=True)
    monkeypatch.setattr("builtins.input", lambda _: "000000")
    login_with_verification(authenticate, fetch_captcha=fetch, send_mfa=request, answer_captcha=lambda _: "aB01")
    assert authenticate.call_count == 3 and fetch.call_count == 2 and request.call_count == 1
    assert authenticate.call_args_list[-1].kwargs == {"sms_code": "000000"}


@pytest.mark.parametrize("failure", [KeyboardInterrupt(), ValueError("cancelled")])
def test_captcha_cancellation_never_retries_or_requests_otp(failure, monkeypatch):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415
    from pyezvizapi.cloud.challenges import CaptchaChallenge  # noqa: PLC0415
    from pyezvizapi.exceptions import EzvizLoginError  # noqa: PLC0415

    authenticate = Mock(side_effect=EzvizLoginError("image", reason="captcha_required", code=1015))
    cancel = Mock()
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("no OTP"))
    with pytest.raises(type(failure)):
        login_with_verification(authenticate, fetch_captcha=Mock(return_value=CaptchaChallenge(b"image", "image/png")), answer_captcha=Mock(side_effect=failure), cancel_captcha=cancel)
    cancel.assert_called_once()
    assert authenticate.call_count == 1


def test_repeated_captcha_error_stops_without_more_images(monkeypatch):
    from pyezvizapi.cli.auth import login_with_verification  # noqa: PLC0415
    from pyezvizapi.cloud.challenges import CaptchaChallenge  # noqa: PLC0415
    from pyezvizapi.exceptions import EzvizLoginError  # noqa: PLC0415

    authenticate = Mock(side_effect=EzvizLoginError("image", reason="captcha_required", code=1015))
    fetch = Mock(return_value=CaptchaChallenge(b"image", "image/png"))
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("no OTP"))
    with pytest.raises(EzvizLoginError):
        login_with_verification(authenticate, fetch_captcha=fetch, answer_captcha=lambda _: "aB01")
    assert authenticate.call_count == 2 and fetch.call_count == 1


def test_missing_phone_notice_is_not_replaced_by_generic_unsent_message(authentication_flow, monkeypatch):
    run, authenticate = authentication_flow
    problem = EzvizAuthVerificationCode("No usable bound phone was reported", reason="verification_phone_unavailable", code=6002)
    authenticate.side_effect = problem
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("no code requested"))
    with pytest.raises(EzvizAuthVerificationCode) as caught:
        run("sms")
    assert caught.value is problem and authenticate.call_count == 1


def test_captcha_file_is_private_and_removed_after_answer(monkeypatch):
    import os  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415
    import re  # noqa: PLC0415

    from pyezvizapi.cli import auth  # noqa: PLC0415
    from pyezvizapi.cloud.challenges import CaptchaChallenge  # noqa: PLC0415

    paths = []
    image_bytes = b"image"
    def report(message, **kwargs):
        path = Path(re.sub(r"^Open this CAPTCHA image: ", "", message))
        assert path.read_bytes() == image_bytes and os.stat(path).st_mode & 0o777 == 0o600
        paths.append(path)
    monkeypatch.setattr("builtins.print", report)
    monkeypatch.setattr("builtins.input", lambda _: "aB01")
    assert auth._answer_captcha(CaptchaChallenge(b"image", "image/png")) == "aB01"  # noqa: SLF001
    assert len(paths) == 1 and not paths[0].exists()
