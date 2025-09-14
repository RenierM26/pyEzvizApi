"""Top-level package for the Ezviz Cloud API helpers.

This package provides a small, typed API surface around Ezviz cloud
endpoints tailored for Home Assistant and light scripting. The
submodules contain focused functionality (client, camera/light models,
MQTT push, CAS, utilities) and this package exports the most useful
symbols for convenient imports.
"""

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
from .light_bulb import EzvizLightBulb
from .models import EzvizDeviceRecord, build_device_records_map
from .mqtt import EzvizToken, MQTTClient, MqttData, ServiceUrls
from .test_cam_rtsp import TestRTSPAuth

__all__ = [
    "AlarmDetectHumanCar",
    "AuthTestResultFailed",
    "BatteryCameraNewWorkMode",
    "BatteryCameraWorkMode",
    "DefenseModeType",
    "DeviceCatagories",
    "DeviceException",
    "DeviceSwitchType",
    "DisplayMode",
    "EzvizAuthTokenExpired",
    "EzvizAuthVerificationCode",
    "EzvizCAS",
    "EzvizCamera",
    "EzvizClient",
    "EzvizDeviceRecord",
    "EzvizLightBulb",
    "EzvizToken",
    "HTTPError",
    "IntelligentDetectionSmartApp",
    "InvalidHost",
    "InvalidURL",
    "MQTTClient",
    "MessageFilterType",
    "MqttData",
    "NightVisionMode",
    "PyEzvizError",
    "ServiceUrls",
    "SoundMode",
    "SupportExt",
    "TestRTSPAuth",
    "build_device_records_map",
]
