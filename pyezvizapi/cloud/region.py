"""Explicit, credential-free lookup of an EZVIZ login API host."""

from dataclasses import dataclass
import re
import time

import requests

from pyezvizapi.cloud._area_catalog import AREA_NAMES
from pyezvizapi.cloud.budget import budgeted_http_call
from pyezvizapi.cloud.deadline import bounded_request_timeout, request_deadline
from pyezvizapi.exceptions import HTTPError, PyEzvizError

_AREA_LOOKUP = "https://api.ezvizlife.com/api/area/domain"
_VENDOR_HOST = re.compile(
    r"(?:https://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:ezvizlife\.com|ezvizru\.com))/?",
    re.ASCII | re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class LoginArea:
    """A named area in the EZVIZ login picker."""

    area_id: int
    name: str


def list_login_areas() -> tuple[LoginArea, ...]:
    """Return the bundled Android catalog, sorted by name, without network access."""
    return _LOGIN_AREAS


_LOGIN_AREAS = tuple(LoginArea(area_id, name) for area_id, name in AREA_NAMES)


def resolve_login_host(area_id: int) -> str:
    """Resolve an EZVIZ catalog area ID (not a dialing code) to a bare API hostname.

    This does not prove the area exists or belongs to an account: the lookup
    service may return its global host for unknown IDs.
    """
    if type(area_id) is not int or not 0 < area_id <= 2**31 - 1:
        raise ValueError("EZVIZ area ID must be a positive 32-bit integer")

    if area_id == 114:  # The Android picker routes Russia separately.
        return "api.ezvizru.com"

    with requests.Session() as session, request_deadline(time.monotonic() + 10):
        # A bootstrap lookup needs neither netrc credentials nor environment headers.
        session.trust_env = False
        try:
            with budgeted_http_call(
                session,
                "post",
                url=_AREA_LOOKUP,
                data={"areaId": area_id},
                allow_redirects=False,
                timeout=bounded_request_timeout(None),
                max_body_bytes=16_384,
            ) as response:
                if response.status_code != 200:
                    raise HTTPError("EZVIZ area lookup did not return HTTP 200")
                result = response.json()
        except requests.exceptions.InvalidJSONError:
            raise PyEzvizError("EZVIZ area lookup returned invalid JSON") from None
        except requests.RequestException:
            raise HTTPError("EZVIZ area lookup request failed") from None

        if not isinstance(result, dict) or result.get("resultCode") not in ("0", 0):
            raise PyEzvizError("EZVIZ area lookup did not succeed")
        domain = result.get("areaDomain")
        match = _VENDOR_HOST.fullmatch(domain) if isinstance(domain, str) else None
        if match is None or len(match[1]) > 253:
            raise PyEzvizError("EZVIZ area lookup returned an invalid API hostname")
        return match[1].lower()
