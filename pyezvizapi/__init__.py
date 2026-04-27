"""Top-level package for the Ezviz Cloud API helpers.

This package provides a small, typed API surface around Ezviz cloud
endpoints tailored for Home Assistant and light scripting. The
submodules contain focused functionality (client, camera/light models,
MQTT push, CAS, utilities) and this package exports the most useful
symbols for convenient imports.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .camera import EzvizCamera
    from .cas import EzvizCAS
    from .client import EzvizClient
    from .constants import (
        AlarmDetectHumanCar,
        BatteryCameraNewWorkMode,
        BatteryCameraWorkMode,
        DefenseModeType,
        DeviceCatagories,
        DeviceSwitchType,
        DisplayMode,
        IntelligentDetectionSmartApp,
        MessageFilterType,
        NightVisionMode,
        SoundMode,
        SupportExt,
    )
    from .exceptions import (
        AuthTestResultFailed,
        DeviceException,
        EzvizAuthTokenExpired,
        EzvizAuthVerificationCode,
        HTTPError,
        InvalidHost,
        InvalidURL,
        PyEzvizError,
    )
    from .feature import (
        day_night_mode_value,
        day_night_sensitivity_value,
        device_icr_dss_config,
        display_mode_value,
        get_algorithm_value,
        has_algorithm_subtype,
        has_osd_overlay,
        iter_algorithm_entries,
        iter_channel_algorithm_entries,
        lens_defog_config,
        lens_defog_value,
        night_vision_config,
        night_vision_duration_value,
        night_vision_luminance_value,
        night_vision_mode_value,
        night_vision_payload,
        normalize_port_security,
        optionals_mapping,
        port_security_config,
        port_security_has_port,
        port_security_port_enabled,
        resolve_channel,
        supplement_light_available,
        supplement_light_enabled,
        supplement_light_params,
        support_ext_value,
    )
    from .light_bulb import EzvizLightBulb
    from .models import EzvizDeviceRecord, build_device_records_map
    from .mqtt import EzvizToken, MQTTClient, MqttData, ServiceUrls
    from .smart_plug import EzvizSmartPlug
    from .test_cam_rtsp import TestRTSPAuth

_EXPORTS = {
    "AlarmDetectHumanCar": "constants",
    "AuthTestResultFailed": "exceptions",
    "BatteryCameraNewWorkMode": "constants",
    "BatteryCameraWorkMode": "constants",
    "DefenseModeType": "constants",
    "DeviceCatagories": "constants",
    "DeviceException": "exceptions",
    "DeviceSwitchType": "constants",
    "DisplayMode": "constants",
    "EzvizAuthTokenExpired": "exceptions",
    "EzvizAuthVerificationCode": "exceptions",
    "EzvizCAS": "cas",
    "EzvizCamera": "camera",
    "EzvizClient": "client",
    "EzvizDeviceRecord": "models",
    "EzvizLightBulb": "light_bulb",
    "EzvizSmartPlug": "smart_plug",
    "EzvizToken": "mqtt",
    "HTTPError": "exceptions",
    "IntelligentDetectionSmartApp": "constants",
    "InvalidHost": "exceptions",
    "InvalidURL": "exceptions",
    "MQTTClient": "mqtt",
    "MessageFilterType": "constants",
    "MqttData": "mqtt",
    "NightVisionMode": "constants",
    "PyEzvizError": "exceptions",
    "ServiceUrls": "mqtt",
    "SoundMode": "constants",
    "SupportExt": "constants",
    "TestRTSPAuth": "test_cam_rtsp",
    "build_device_records_map": "models",
    "day_night_mode_value": "feature",
    "day_night_sensitivity_value": "feature",
    "device_icr_dss_config": "feature",
    "display_mode_value": "feature",
    "get_algorithm_value": "feature",
    "has_algorithm_subtype": "feature",
    "has_osd_overlay": "feature",
    "iter_algorithm_entries": "feature",
    "iter_channel_algorithm_entries": "feature",
    "lens_defog_config": "feature",
    "lens_defog_value": "feature",
    "night_vision_config": "feature",
    "night_vision_duration_value": "feature",
    "night_vision_luminance_value": "feature",
    "night_vision_mode_value": "feature",
    "night_vision_payload": "feature",
    "normalize_port_security": "feature",
    "optionals_mapping": "feature",
    "port_security_config": "feature",
    "port_security_has_port": "feature",
    "port_security_port_enabled": "feature",
    "resolve_channel": "feature",
    "supplement_light_available": "feature",
    "supplement_light_enabled": "feature",
    "supplement_light_params": "feature",
    "support_ext_value": "feature",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Lazily resolve package-level exports from their owning modules."""

    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module = import_module(f"{__name__}.{_EXPORTS[name]}")
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return module attributes including lazy exports."""

    return sorted((*globals(), *__all__))
