# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import auth as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.auth import (
    Any as Any,
    Callable as Callable,
    Exchange as Exchange,
    EzvizPushFatalError as EzvizPushFatalError,
    Protocol as Protocol,
    PushCredentials as PushCredentials,
    _cached as _cached,
    _redirect as _redirect,
    _response as _response,
    _saved_key as _saved_key,
    annotations as annotations,
    authenticate as authenticate,
    dataclass as dataclass,
    hashlib as hashlib,
    secrets as secrets,
    wire as wire,
    )

sys.modules[__name__] = _implementation
