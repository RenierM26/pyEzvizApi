# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import auth as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.auth as _compat_module_0
    API_ENDPOINT_REFRESH_SESSION_ID = _compat_module_0.API_ENDPOINT_REFRESH_SESSION_ID
    API_ENDPOINT_SERVER_INFO = _compat_module_0.API_ENDPOINT_SERVER_INFO
    FEATURE_CODE = _compat_module_0.FEATURE_CODE
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    EzvizAuthTokenExpired = _compat_module_0.EzvizAuthTokenExpired
    HTTPError = _compat_module_0.HTTPError
    PyEzvizError = _compat_module_0.PyEzvizError
    _http_transport = _compat_module_0._http_transport
    annotations = _compat_module_0.annotations
    budgeted_http_call = _compat_module_0.budgeted_http_call
    discover_services = _compat_module_0.discover_services
    isolated_session = _compat_module_0.isolated_session
    meta_code = _compat_module_0.meta_code
    object_section = _compat_module_0.object_section
    parse_json = _compat_module_0.parse_json
    profile_for_token = _compat_module_0.profile_for_token
    refresh_credentials = _compat_module_0.refresh_credentials
    requests = _compat_module_0.requests
    response_summary = _compat_module_0.response_summary
    synchronize_http_headers = _compat_module_0.synchronize_http_headers
    validate_feature_code = _compat_module_0.validate_feature_code

sys.modules[__name__] = _implementation
