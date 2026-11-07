# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import transport as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.transport as _compat_module_0
    CaseInsensitiveDict = _compat_module_0.CaseInsensitiveDict
    OrderedDict = _compat_module_0.OrderedDict
    copy = _compat_module_0.copy
    deepcopy = _compat_module_0.deepcopy
    isolated_session = _compat_module_0.isolated_session
    requests = _compat_module_0.requests

sys.modules[__name__] = _implementation
