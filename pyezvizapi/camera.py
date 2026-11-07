# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.devices.camera`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.devices import camera as _implementation

if TYPE_CHECKING:
    import pyezvizapi.devices.camera as _compat_module_0
    _LOGGER = _compat_module_0._LOGGER
    DEFAULT_ALARM_IMAGE_URL = _compat_module_0.DEFAULT_ALARM_IMAGE_URL
    UNIFIEDMSG_LOOKBACK_DAYS = _compat_module_0.UNIFIEDMSG_LOOKBACK_DAYS
    Any = _compat_module_0.Any
    BatteryCameraWorkMode = _compat_module_0.BatteryCameraWorkMode
    CameraStatus = _compat_module_0.CameraStatus
    DeviceSwitchType = _compat_module_0.DeviceSwitchType
    EzvizCamera = _compat_module_0.EzvizCamera
    EzvizChimeMusic = _compat_module_0.EzvizChimeMusic
    EzvizDeviceChimeInfo = _compat_module_0.EzvizDeviceChimeInfo
    EzvizDeviceRecord = _compat_module_0.EzvizDeviceRecord
    Literal = _compat_module_0.Literal
    PyEzvizError = _compat_module_0.PyEzvizError
    SoundMode = _compat_module_0.SoundMode
    TypedDict = _compat_module_0.TypedDict
    annotations = _compat_module_0.annotations
    cast = _compat_module_0.cast
    compute_motion_from_alarm = _compat_module_0.compute_motion_from_alarm
    datetime = _compat_module_0.datetime
    fetch_nested_value = _compat_module_0.fetch_nested_value
    local_ip_address = _compat_module_0.local_ip_address
    logging = _compat_module_0.logging
    parse_timezone_value = _compat_module_0.parse_timezone_value
    string_to_list = _compat_module_0.string_to_list
    switch_values = _compat_module_0.switch_values

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _LOGGER,
        DEFAULT_ALARM_IMAGE_URL,
        UNIFIEDMSG_LOOKBACK_DAYS,
        Any,
        BatteryCameraWorkMode,
        CameraStatus,
        DeviceSwitchType,
        EzvizCamera,
        EzvizChimeMusic,
        EzvizDeviceChimeInfo,
        EzvizDeviceRecord,
        Literal,
        PyEzvizError,
        SoundMode,
        TypedDict,
        annotations,
        cast,
        compute_motion_from_alarm,
        datetime,
        fetch_nested_value,
        local_ip_address,
        logging,
        parse_timezone_value,
        string_to_list,
        switch_values,
    )

sys.modules[__name__] = _implementation
