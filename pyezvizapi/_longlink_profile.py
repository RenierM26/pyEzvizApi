# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.profile`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import profile as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.profile import (
        ANDROID_PROFILE as ANDROID_PROFILE,
        WEB_PROFILE as WEB_PROFILE,
        Any as Any,
        HttpProfile as HttpProfile,
        Literal as Literal,
        Mapping as Mapping,
        MutableMapping as MutableMapping,
        annotations as annotations,
        current_session_header as current_session_header,
        profile_for_token as profile_for_token,
        recreated_session_header_for_token as recreated_session_header_for_token,
        session_header_for_token as session_header_for_token,
        synchronize_http_headers as synchronize_http_headers,
    )

sys.modules[__name__] = _implementation
