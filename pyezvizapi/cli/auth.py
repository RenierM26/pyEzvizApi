"""Bounded human-completed CAPTCHA and OTP handling shared by both CLI paths."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import sys
import tempfile
from typing import Any

from pyezvizapi.cloud.challenges import CHANNEL_NAMES, CaptchaChallenge
from pyezvizapi.cloud.login import verification_code
from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizLoginError, PyEzvizError


def _answer_captcha(challenge: CaptchaChallenge) -> str:
    """Expose only a temporary private image path, never contacts or request tokens."""
    suffix = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif"}[
        challenge.content_type
    ]
    with tempfile.NamedTemporaryFile(
        prefix="ezviz-captcha-", suffix=suffix, delete=False
    ) as stream:
        image_path = Path(stream.name)
        stream.write(challenge.image)
    try:
        print(f"Open this CAPTCHA image: {image_path}", file=sys.stderr)
        return input("Enter the four image characters (Ctrl-C cancels): ")
    finally:
        image_path.unlink(missing_ok=True)


def _otp(error: EzvizAuthVerificationCode | None = None) -> str | None:
    if error is not None and error.code in (6002, 1011, 1012) and not error.code_sent:
        if error.reason == "verification_phone_unavailable":
            raise error
        raise PyEzvizError(
            "No MFA code requested; select a bound --mfa-channel/--mfa-account "
            "or complete security verification in the EZVIZ app."
        ) from None
    return verification_code(input("MFA code required, please input MFA code.\n"))


def _channel_options(channel: str | None, account: str | None) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if channel is not None:
        names = {name: code for code, name in CHANNEL_NAMES.items()}
        if channel not in names:
            raise PyEzvizError("Unknown MFA channel")
        options["mfa_channel"] = names[channel]
    if account is not None:
        options["mfa_account"] = account
    return options


def login_with_verification(
    authenticate: Callable[..., object],
    *,
    mfa_channel: str | None = None,
    mfa_account: str | None = None,
    fetch_captcha: Callable[..., CaptchaChallenge] | None = None,
    send_mfa: Callable[..., bool] | None = None,
    answer_captcha: Callable[[CaptchaChallenge], str] = _answer_captcha,
    cancel_captcha: Callable[[], None] | None = None,
) -> None:
    """At most one image per purpose and one OTP; no retries of submitted OTP errors."""
    options = _channel_options(mfa_channel, mfa_account)
    pending = dict(options)
    solved: set[bool] = set()
    try:
        for _ in range(3):
            try:
                authenticate(**pending)
                return
            except EzvizAuthVerificationCode as error:
                if "sms_code" in pending:
                    raise
                pending = {**options, "sms_code": _otp(error)}
            except EzvizLoginError as error:
                if (
                    error.reason != "captcha_required"
                    or "sms_code" in pending
                    or fetch_captcha is None
                ):
                    raise
                for_mfa = error.code in (1101, 1141)
                if for_mfa in solved or (for_mfa and send_mfa is None):
                    raise
                solved.add(for_mfa)
                challenge = fetch_captcha(for_mfa=for_mfa)
                answer = answer_captcha(challenge)
                if for_mfa:
                    assert send_mfa is not None
                    if not send_mfa(captcha=challenge, captcha_code=answer, **options):
                        raise PyEzvizError("MFA code request was not accepted") from None
                    pending = {**options, "sms_code": _otp()}
                else:
                    pending = {**options, "captcha": challenge, "captcha_code": answer}
        raise PyEzvizError("Authentication challenge limit reached")
    finally:
        if cancel_captcha is not None:
            cancel_captcha()
