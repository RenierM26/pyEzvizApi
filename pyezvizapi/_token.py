# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.token`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import token as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.token import (
        FEATURE_CODE as FEATURE_CODE,
        PROFILE as PROFILE,
        Any as Any,
        ClientToken as ClientToken,
        EzvizAuthTokenExpired as EzvizAuthTokenExpired,
        NotRequired as NotRequired,
        PyEzvizError as PyEzvizError,
        ServiceUrls as ServiceUrls,
        TypedDict as TypedDict,
        _hostname as _hostname,
        _push_endpoint as _push_endpoint,
        _push_serial as _push_serial,
        annotations as annotations,
        ipaddress as ipaddress,
        re as re,
        validate_feature_code as validate_feature_code,
        validate_push_token as validate_push_token,
    )

sys.modules[__name__] = _implementation
