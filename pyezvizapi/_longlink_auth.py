# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.auth`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import auth as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.longlink.auth as _compat_module_0
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    Exchange = _compat_module_0.Exchange
    EzvizPushFatalError = _compat_module_0.EzvizPushFatalError
    Protocol = _compat_module_0.Protocol
    PushCredentials = _compat_module_0.PushCredentials
    _cached = _compat_module_0._cached
    _redirect = _compat_module_0._redirect
    _response = _compat_module_0._response
    _saved_key = _compat_module_0._saved_key
    annotations = _compat_module_0.annotations
    authenticate = _compat_module_0.authenticate
    dataclass = _compat_module_0.dataclass
    hashlib = _compat_module_0.hashlib
    secrets = _compat_module_0.secrets
    wire = _compat_module_0.wire

sys.modules[__name__] = _implementation
