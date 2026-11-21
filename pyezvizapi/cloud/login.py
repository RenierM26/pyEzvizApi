"""App-backed login failures and short-lived, non-persisted MFA state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from pyezvizapi.cloud.challenges import CHANNEL_NAMES, PHONE_CHANNELS
from pyezvizapi.exceptions import EzvizAuthVerificationCode, EzvizLoginError, PyEzvizError

_LOGIN_ERRORS: Final[Mapping[int, tuple[str, str]]] = MappingProxyType(
    {
        1013: ("incorrect_username", "Incorrect Username."),
        1014: ("incorrect_password", "Incorrect Password."),
        1226: ("incorrect_credentials", "Incorrect username or password."),
        1101: ("captcha_incorrect", "Incorrect image code; fetch a fresh CAPTCHA before retrying."),
        1015: (
            "captcha_required",
            "Image verification required; fetch a CAPTCHA and submit the human answer.",
        ),
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
)


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
    if code is not None and code in _LOGIN_ERRORS:
        reason, message = _LOGIN_ERRORS[code]
        return EzvizLoginError(message, reason=reason, code=code)
    return None


def verification_request_error(code: int | None, result: dict[str, Any]) -> EzvizLoginError | None:
    """Request-side image challenges are not incorrect SMS/email codes."""
    if code in (1101, 1141):
        return EzvizLoginError(
            "Image verification required before requesting an MFA code.",
            reason="captcha_required",
            code=code,
        )
    return login_error(code, result)


@dataclass(frozen=True)
class _MfaChannelPolicy:
    """An immutable regional grant, independent of contact and request state."""

    channels: tuple[int, ...] = (1, 3)
    region: str | None = field(default=None, repr=False)

    def validate(self, channel: int, region: str | None) -> None:
        if type(channel) is not int or channel not in CHANNEL_NAMES:
            raise PyEzvizError(
                "MFA channel must be SMS 1 or email 3, or an explicitly discovered supported channel"
            )
        if channel in (2, 6, 7) and self.region != region:
            raise EzvizLoginError(
                "Discover verification channels for this region before selecting this method.",
                reason="verification_channel_unavailable",
            )
        if channel not in self.channels:
            raise PyEzvizError(
                "MFA channel must be SMS 1 or email 3, or an explicitly discovered supported channel"
            )


@dataclass
class LoginVerification:
    """Do not persist contacts, expose them in repr/errors, or infer channel from username."""

    channel: int = 3  # Historical default; callers may explicitly select SMS 1.
    _requested_contact: tuple[int, str] | None = field(default=None, init=False, repr=False)
    contacts: dict[int, str] = field(default_factory=dict, repr=False)
    recipient: str | None = field(default=None, repr=False)
    metadata_present: bool = False
    app_required: bool = False

    def contact_error(self) -> tuple[str, str]:
        if self.channel in PHONE_CHANNELS:
            return (
                "verification_phone_unavailable",
                "No usable bound phone was reported for this verification method. "
                "Link and verify a phone in the EZVIZ app, then retry login, or choose email.",
            )
        return (
            "security_verification_required"
            if self.app_required
            else "verification_contact_required",
            "No usable bound email was reported; select a contact or verify in the EZVIZ app.",
        )

    @property
    def login_channel(self) -> int:
        # The app requests WhatsApp/Zalo delivery with 6/7, then logs in with 1.
        return 1 if self.channel in (6, 7) else self.channel

    def available_channels(
        self, region: str, policy: _MfaChannelPolicy = _MfaChannelPolicy()
    ) -> tuple[int, ...]:
        reported = set(self.contacts)
        if 1 in self.contacts and policy.region == region:
            reported.update(code for code in policy.channels if code in PHONE_CHANNELS)
        return tuple(sorted(reported))

    @property
    def sent(self) -> bool:
        """A request succeeded for this explicit selection; blocks automatic resend.

        Contact metadata changes do not clear this guard. Use ``code_sent`` for
        whether the successful request still matches the active destination.
        """
        return self._requested_contact is not None

    def mark_sent(self, destination: str) -> None:
        """Record acceptance only after the HTTP request succeeded."""
        self._requested_contact = (self.channel, destination)

    def code_sent(self, account: str | None) -> bool:
        """Report acceptance for the current channel/contact, not an older contact."""
        return self._requested_contact == (self.channel, self.destination(account))

    def select(
        self,
        channel: int | None,
        recipient: str | None,
        *,
        policy: _MfaChannelPolicy = _MfaChannelPolicy(),
        region: str | None = None,
    ) -> None:
        # Revalidate retained selections too: an explicit refresh may revoke them.
        selected_channel = self.channel if channel is None else channel
        policy.validate(selected_channel, region)
        if recipient is not None and (not isinstance(recipient, str) or not recipient.strip()):
            raise PyEzvizError("MFA recipient must be nonempty text")
        selected_recipient = self.recipient if selected_channel == self.channel else None
        if recipient is not None:
            selected_recipient = recipient
        if (selected_channel, selected_recipient) != (self.channel, self.recipient):
            self._requested_contact = None
        self.channel = selected_channel
        self.recipient = selected_recipient

    def update(self, result: dict[str, Any]) -> None:
        info = result.get("loginUser")
        if info is None:
            info = result.get("contactExt")
        self.contacts.clear()
        self.metadata_present = "loginUser" in result or "contactExt" in result
        self.app_required = False
        if not isinstance(info, dict):
            return
        for channel, name in ((1, "phone"), (3, "email")):
            value = info.get(name)
            if isinstance(value, str) and value.strip() and "*" not in value:
                self.contacts[channel] = value
        # VerifyUtils.getSupportFlow treats these as alternatives, not a veto
        # on the ordinary email/phone choices. Never retain the temporary token.
        self.app_required = not self.contacts and bool(
            info.get("isSecurityBind") or info.get("verifyAccessToken") or info.get("accessToken")
        )

    def destination(self, account: str | None) -> str | None:
        if self.app_required:
            return None
        if self.recipient:
            return self.recipient
        if self.metadata_present:
            return self.contacts.get(1 if self.channel in PHONE_CHANNELS else 3)
        # Preserve the old email-only API when no contact metadata was returned.
        return account if self.channel == 3 else None
