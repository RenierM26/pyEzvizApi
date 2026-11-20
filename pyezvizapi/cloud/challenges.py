"""Ephemeral, human-completed image challenges and reported MFA channel policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pyezvizapi.exceptions import EzvizLoginError, PyEzvizError

CHANNEL_NAMES = {1: "sms", 2: "voice", 3: "email", 6: "whatsapp", 7: "zalo"}
PHONE_CHANNELS = (1, 2, 6, 7)


@dataclass(frozen=True)
class MfaChannel:
    """A regional/business option; not proof that this account has a bound contact."""

    channel: int
    title: str
    order: int

    @property
    def supported(self) -> bool:
        return self.channel in CHANNEL_NAMES


@dataclass(frozen=True, eq=False)
class CaptchaChallenge:
    """Image bytes for a human; identity-based matching prevents stale submissions."""

    image: bytes = field(repr=False)
    content_type: str


@dataclass
class CaptchaState:
    """Bind one answer to its client, region, feature identity, account and purpose."""

    challenge: CaptchaChallenge | None = field(default=None, repr=False)
    context: tuple[Any, ...] | None = field(default=None, repr=False)

    def clear(self) -> None:
        self.challenge = None
        self.context = None

    def issue(self, image: bytes, context: tuple[Any, ...]) -> CaptchaChallenge:
        if image.startswith(b"\x89PNG\r\n\x1a\n"):
            content_type = "image/png"
        elif image.startswith(b"\xff\xd8\xff"):
            content_type = "image/jpeg"
        elif image.startswith((b"GIF87a", b"GIF89a")):
            content_type = "image/gif"
        else:
            raise EzvizLoginError(
                "No supported CAPTCHA image returned; continue verification in the EZVIZ app.",
                reason="captcha_image_unavailable",
            )
        self.challenge = CaptchaChallenge(image, content_type)
        self.context = context
        return self.challenge

    def consume(
        self, challenge: CaptchaChallenge | None, answer: str | None, context: tuple[Any, ...]
    ) -> str | None:
        if challenge is None and answer is None:
            return None
        if (
            challenge is None
            or challenge is not self.challenge
            or context != self.context
            or not isinstance(answer, str)
            or len(answer) != 4
            or not answer.isascii()
            or not answer.isalnum()
        ):
            raise EzvizLoginError(
                "Fetch a current CAPTCHA and enter its four ASCII letters/digits.",
                reason="captcha_answer_invalid",
            )
        # Consume before transport: a timeout does not make replay safe.
        self.clear()
        return answer


def parse_channels(result: dict[str, Any]) -> tuple[MfaChannel, ...]:
    """Select only TERMINAL_BIND, preserving unknown advertised channels as unsupported."""
    data = result.get("data")
    if data is None:
        return ()
    if not isinstance(data, dict):
        raise PyEzvizError("Invalid verification channel configuration")
    items = data.get("TERMINAL_BIND", [])
    if not isinstance(items, list):
        raise PyEzvizError("Invalid terminal verification channel configuration")
    channels = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise PyEzvizError("Invalid verification channel item")
        channel, title, order = item.get("channel"), item.get("title"), item.get("order")
        if type(channel) is not int or not isinstance(title, str) or type(order) is not int:
            raise PyEzvizError("Invalid verification channel fields")
        if channel not in seen:
            channels.append(MfaChannel(channel, title, order))
            seen.add(channel)
    return tuple(sorted(channels, key=lambda item: item.order))
