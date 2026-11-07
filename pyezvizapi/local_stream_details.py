# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.streaming.local.details`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.streaming.local import details as _implementation

if TYPE_CHECKING:
    from pyezvizapi.streaming.local.details import (
    HcNetSdkStreamDetails as HcNetSdkStreamDetails,
    discover_hcnetsdk_stream_details as discover_hcnetsdk_stream_details,
    discover_hcnetsdk_stream_details_for_login as discover_hcnetsdk_stream_details_for_login,
    )

sys.modules[__name__] = _implementation
