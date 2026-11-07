# Compatibility export assignments include retained private attributes.
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.details`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import details as _implementation

if TYPE_CHECKING:
    import pyezvizapi.streaming.local.details as _compat_module_0
    HcNetSdkStreamDetails = _compat_module_0.HcNetSdkStreamDetails
    discover_hcnetsdk_stream_details = _compat_module_0.discover_hcnetsdk_stream_details
    discover_hcnetsdk_stream_details_for_login = _compat_module_0.discover_hcnetsdk_stream_details_for_login

sys.modules[__name__] = _implementation
