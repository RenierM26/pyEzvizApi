# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.profile`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import profile as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.longlink.profile as _compat_module_0
    ANDROID_PROFILE = _compat_module_0.ANDROID_PROFILE
    WEB_PROFILE = _compat_module_0.WEB_PROFILE
    Any = _compat_module_0.Any
    HttpProfile = _compat_module_0.HttpProfile
    Literal = _compat_module_0.Literal
    Mapping = _compat_module_0.Mapping
    MutableMapping = _compat_module_0.MutableMapping
    annotations = _compat_module_0.annotations
    current_session_header = _compat_module_0.current_session_header
    profile_for_token = _compat_module_0.profile_for_token
    recreated_session_header_for_token = _compat_module_0.recreated_session_header_for_token
    session_header_for_token = _compat_module_0.session_header_for_token
    synchronize_http_headers = _compat_module_0.synchronize_http_headers

sys.modules[__name__] = _implementation
