"""Android login profile required by channel-99 registration."""

from typing import Any

from .constants import FEATURE_CODE
from .exceptions import EzvizAuthTokenExpired

PROFILE = "android-channel99"
HEADERS = {"clientNo": "google", "clientVersion": "7.4.1.0421", "osVersion": "13"}
REGISTER = {"pushRegisterJson": '[{"channel":99}]', "pushExtJson": '{"language":"","protoVer":"2"}'}


def validate_feature_code(token: dict[str, Any]) -> None:
    """Reject saved channel-99 credentials belonging to a different host identity."""
    if token.get("push_profile") == PROFILE and token.get("feature_code") != FEATURE_CODE:
        raise EzvizAuthTokenExpired(
            "Channel-99 host feature code changed or is missing; "
            "create a fresh login without the old token or push state"
        )
