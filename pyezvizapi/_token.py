# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.token`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import token as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.token as _compat_module_0
    FEATURE_CODE = _compat_module_0.FEATURE_CODE
    PROFILE = _compat_module_0.PROFILE
    Any = _compat_module_0.Any
    ClientToken = _compat_module_0.ClientToken
    EzvizAuthTokenExpired = _compat_module_0.EzvizAuthTokenExpired
    NotRequired = _compat_module_0.NotRequired
    PyEzvizError = _compat_module_0.PyEzvizError
    ServiceUrls = _compat_module_0.ServiceUrls
    TypedDict = _compat_module_0.TypedDict
    _hostname = _compat_module_0._hostname
    _push_endpoint = _compat_module_0._push_endpoint
    _push_serial = _compat_module_0._push_serial
    annotations = _compat_module_0.annotations
    ipaddress = _compat_module_0.ipaddress
    re = _compat_module_0.re
    validate_feature_code = _compat_module_0.validate_feature_code
    validate_push_token = _compat_module_0.validate_push_token

sys.modules[__name__] = _implementation
