"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.profile`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import profile as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.profile import (
    ANDROID_PROFILE as ANDROID_PROFILE,
    Any as Any,
    HttpProfile as HttpProfile,
    Literal as Literal,
    Mapping as Mapping,
    MutableMapping as MutableMapping,
    WEB_PROFILE as WEB_PROFILE,
    annotations as annotations,
    current_session_header as current_session_header,
    profile_for_token as profile_for_token,
    recreated_session_header_for_token as recreated_session_header_for_token,
    session_header_for_token as session_header_for_token,
    synchronize_http_headers as synchronize_http_headers,
    )

sys.modules[__name__] = _implementation
