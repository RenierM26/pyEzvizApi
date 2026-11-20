"""Shared interactive login/MFA handling for account login and push migration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pyezvizapi.cloud.login import verification_code
from pyezvizapi.exceptions import EzvizAuthVerificationCode, PyEzvizError


def login_with_verification(
    authenticate: Callable[..., object],
    *,
    mfa_channel: str | None = None,
    mfa_account: str | None = None,
) -> None:
    """Attempt once, prompt at most once for MFA, and never retry the second error."""
    options: dict[str, Any] = {}
    if mfa_channel is not None:
        options["mfa_channel"] = 1 if mfa_channel == "sms" else 3
    if mfa_account is not None:
        options["mfa_account"] = mfa_account
    try:
        authenticate(**options)
    except EzvizAuthVerificationCode as error:
        if error.code == 6002 and not error.code_sent:
            raise PyEzvizError(
                "No MFA code requested; select a bound --mfa-channel/--mfa-account "
                "or complete security verification in the EZVIZ app."
            ) from None
        code = verification_code(input("MFA code required, please input MFA code.\n"))
        authenticate(sms_code=code, **options)
