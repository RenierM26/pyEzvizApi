# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.alarm_time`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import alarm_time as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.alarm_time import (
        MILLISECONDS_THRESHOLD as MILLISECONDS_THRESHOLD,
        Any as Any,
        ZoneInfo as ZoneInfo,
        ZoneInfoNotFoundError as ZoneInfoNotFoundError,
        _re as _re,
        annotations as annotations,
        compute_motion_from_alarm as compute_motion_from_alarm,
        datetime as datetime,
        normalize_alarm_time as normalize_alarm_time,
        parse_timezone_value as parse_timezone_value,
    )

sys.modules[__name__] = _implementation
