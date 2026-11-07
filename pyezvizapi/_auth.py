"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import auth as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.auth import (
    API_ENDPOINT_REFRESH_SESSION_ID as API_ENDPOINT_REFRESH_SESSION_ID,
    API_ENDPOINT_SERVER_INFO as API_ENDPOINT_SERVER_INFO,
    Any as Any,
    Callable as Callable,
    EzvizAuthTokenExpired as EzvizAuthTokenExpired,
    FEATURE_CODE as FEATURE_CODE,
    HTTPError as HTTPError,
    PyEzvizError as PyEzvizError,
    _http_transport as _http_transport,
    annotations as annotations,
    budgeted_http_call as budgeted_http_call,
    discover_services as discover_services,
    isolated_session as isolated_session,
    meta_code as meta_code,
    object_section as object_section,
    parse_json as parse_json,
    profile_for_token as profile_for_token,
    refresh_credentials as refresh_credentials,
    requests as requests,
    response_summary as response_summary,
    synchronize_http_headers as synchronize_http_headers,
    validate_feature_code as validate_feature_code,
    )

sys.modules[__name__] = _implementation
