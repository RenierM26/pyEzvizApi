# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.alarm_time`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import alarm_time as _implementation

if TYPE_CHECKING:
    import pyezvizapi._shared.alarm_time as _compat_module_0
    MILLISECONDS_THRESHOLD = _compat_module_0.MILLISECONDS_THRESHOLD
    Any = _compat_module_0.Any
    ZoneInfo = _compat_module_0.ZoneInfo
    ZoneInfoNotFoundError = _compat_module_0.ZoneInfoNotFoundError
    _re = _compat_module_0._re
    annotations = _compat_module_0.annotations
    compute_motion_from_alarm = _compat_module_0.compute_motion_from_alarm
    datetime = _compat_module_0.datetime
    normalize_alarm_time = _compat_module_0.normalize_alarm_time
    parse_timezone_value = _compat_module_0.parse_timezone_value

sys.modules[__name__] = _implementation
