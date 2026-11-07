# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.camera`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import camera as _implementation

if TYPE_CHECKING:
    from pyezvizapi.devices.camera import (
        _LOGGER as _LOGGER,
        DEFAULT_ALARM_IMAGE_URL as DEFAULT_ALARM_IMAGE_URL,
        UNIFIEDMSG_LOOKBACK_DAYS as UNIFIEDMSG_LOOKBACK_DAYS,
        Any as Any,
        BatteryCameraWorkMode as BatteryCameraWorkMode,
        CameraStatus as CameraStatus,
        DeviceSwitchType as DeviceSwitchType,
        EzvizCamera as EzvizCamera,
        EzvizChimeMusic as EzvizChimeMusic,
        EzvizDeviceChimeInfo as EzvizDeviceChimeInfo,
        EzvizDeviceRecord as EzvizDeviceRecord,
        Literal as Literal,
        PyEzvizError as PyEzvizError,
        SoundMode as SoundMode,
        TypedDict as TypedDict,
        annotations as annotations,
        cast as cast,
        compute_motion_from_alarm as compute_motion_from_alarm,
        datetime as datetime,
        fetch_nested_value as fetch_nested_value,
        local_ip_address as local_ip_address,
        logging as logging,
        parse_timezone_value as parse_timezone_value,
        string_to_list as string_to_list,
        switch_values as switch_values,
    )

sys.modules[__name__] = _implementation
