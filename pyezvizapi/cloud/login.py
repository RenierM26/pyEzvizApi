"""App-backed login failures and short-lived, non-persisted MFA state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizLoginError, PyEzvizError


def verification_code(value: str | int | None) -> str | None:
    """Preserve zeros in strings; old integer callers remain accepted without padding."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise PyEzvizError("MFA code must be an ASCII digit string")
    code = str(value).strip()
    if not code or not code.isascii() or not code.isdigit():
        raise PyEzvizError("MFA code must be an ASCII digit string")
    return code


def login_error(code: int | None, result: dict[str, Any]) -> EzvizLoginError | None:
    """Translate only evidenced codes; never include server messages or temp tokens."""
    if code in (1011, 1012):
        return EzvizAuthVerificationCode(
            "The MFA code is incorrect." if code == 1011 else "The MFA code has expired.",
            reason="verification_incorrect" if code == 1011 else "verification_expired",
            code=code,
        )
    errors = {
        1013: ("incorrect_username", "Incorrect Username."),
        1014: ("incorrect_password", "Incorrect Password."),
        1226: ("incorrect_credentials", "Incorrect username or password."),
        1015: ("captcha_required", "Image verification required; recover login in the EZVIZ app."),
        1069: (
            "terminal_limit",
            "Terminal limit reached; manage registered terminals in the EZVIZ app.",
        ),
        1102: (
            "region_selection_required",
            "Select the account region in the EZVIZ app before retrying.",
        ),
        1407: ("clock_incorrect", "Correct the system time before retrying login."),
        1402: (
            "public_key_refresh_required",
            "Login key rejected; retry explicitly to fetch a fresh key.",
        ),
        1041: (
            "verification_rate_limited",
            "Verification requests are too frequent; wait before retrying.",
        ),
        1043: (
            "verification_attempts_exceeded",
            "SMS verification attempt limit reached; stop retrying.",
        ),
        1006: (
            "verification_rate_limited",
            "Verification code already requested; wait before requesting another.",
        ),
        1026: (
            "verification_rate_limited",
            "Email code already requested; wait before requesting another.",
        ),
    }
    if code == 1400:
        minutes = result.get("lockMinutes")
        # The app's model declares an int. Ignore malformed/negative/boolean values.
        minutes = minutes if type(minutes) is int and 0 < minutes <= 2**31 - 1 else None
        return EzvizLoginError(
            "Login temporarily locked; wait before retrying.",
            reason="account_locked",
            code=code,
            lock_minutes=minutes,
        )
    if code in errors:
        reason, message = errors[code]
        return EzvizLoginError(message, reason=reason, code=code)
    return None


@dataclass
class LoginVerification:
    """Do not persist contacts, expose them in repr/errors, or infer channel from username."""

    channel: int = 3  # Historical default; callers may explicitly select SMS 1.
    sent: bool = False
    contacts: dict[int, str] = field(default_factory=dict, repr=False)
    recipient: str | None = field(default=None, repr=False)
    metadata_present: bool = False
    app_required: bool = False

    def select(self, channel: int | None, recipient: str | None) -> None:
        if channel is not None:
            if type(channel) is not int or channel not in (1, 3):
                raise PyEzvizError("MFA channel must be SMS 1 or email 3")
            if channel != self.channel:
                self.sent = False
                self.recipient = None
            self.channel = channel
        if recipient is not None:
            if not isinstance(recipient, str) or not recipient.strip():
                raise PyEzvizError("MFA recipient must be nonempty text")
            if recipient != self.recipient:
                self.sent = False
            self.recipient = recipient

    def update(self, result: dict[str, Any]) -> None:
        info = result.get("loginUser") or result.get("contactExt")
        self.contacts.clear()
        self.metadata_present = "loginUser" in result or "contactExt" in result
        self.app_required = False
        if not isinstance(info, dict):
            return
        self.app_required = bool(
            info.get("isSecurityBind") or info.get("verifyAccessToken") or info.get("accessToken")
        )
        for channel, name in ((1, "phone"), (3, "email")):
            value = info.get(name)
            if isinstance(value, str) and value.strip() and "*" not in value:
                self.contacts[channel] = value

    def destination(self, account: str | None) -> str | None:
        if self.app_required:
            return None
        if self.recipient:
            return self.recipient
        if self.metadata_present:
            return self.contacts.get(self.channel)
        # Preserve the old email-only API when no contact metadata was returned.
        return account if self.channel == 3 else None
