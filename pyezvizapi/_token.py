"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.token`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import token as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.token import (
    Any as Any,
    ClientToken as ClientToken,
    EzvizAuthTokenExpired as EzvizAuthTokenExpired,
    FEATURE_CODE as FEATURE_CODE,
    NotRequired as NotRequired,
    PROFILE as PROFILE,
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
