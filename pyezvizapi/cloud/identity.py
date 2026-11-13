"""Validate application-owned identities without changing process-wide defaults."""

import re
from typing import TypedDict

from pyezvizapi.constants import FEATURE_CODE
from pyezvizapi.exceptions import PyEzvizError


def resolve_feature_code(feature_code: str | None, default: str) -> str:
    """Select a validated explicit installation identity or the legacy host code."""
    if feature_code is None:
        return default
    if not isinstance(feature_code, str) or re.fullmatch(r"[0-9a-f]{32}", feature_code) is None:
        raise PyEzvizError("Client feature code must be 32 lowercase hexadecimal characters")
    return feature_code


class IdentityOptions(TypedDict, total=False):
    """Optional identity keyword shared by SDK-owned child transports."""

    feature_code: str


def feature_code_options(feature_code: str | None) -> IdentityOptions:
    """Forward non-default identities without changing legacy factory call shapes."""
    return (
        {}
        if feature_code is None or feature_code == FEATURE_CODE
        else {"feature_code": feature_code}
    )
