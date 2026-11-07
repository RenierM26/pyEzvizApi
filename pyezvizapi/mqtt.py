# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.mqtt`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push import mqtt as _implementation

if TYPE_CHECKING:
    import pyezvizapi.push.mqtt as _compat_module_0
    _LOGGER = _compat_module_0._LOGGER
    ANDROID_PROFILE = _compat_module_0.ANDROID_PROFILE
    DEFAULT_TIMEOUT = _compat_module_0.DEFAULT_TIMEOUT
    EXT_FIELD_NAMES = _compat_module_0.EXT_FIELD_NAMES
    EXT_INT_FIELDS = _compat_module_0.EXT_INT_FIELDS
    PUSH_PROFILE = _compat_module_0.PUSH_PROFILE
    PUSH_REGISTER = _compat_module_0.PUSH_REGISTER
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    Channel99Session = _compat_module_0.Channel99Session
    EzvizAuthTokenExpired = _compat_module_0.EzvizAuthTokenExpired
    EzvizPushFatalError = _compat_module_0.EzvizPushFatalError
    EzvizToken = _compat_module_0.EzvizToken
    EzvizTokenPersistenceError = _compat_module_0.EzvizTokenPersistenceError
    Final = _compat_module_0.Final
    HTTPError = _compat_module_0.HTTPError
    MQTTClient = _compat_module_0.MQTTClient
    MqttData = _compat_module_0.MqttData
    OrderedDict = _compat_module_0.OrderedDict
    PushWorker = _compat_module_0.PushWorker
    PyEzvizError = _compat_module_0.PyEzvizError
    RLock = _compat_module_0.RLock
    ServiceUrls = _compat_module_0.ServiceUrls
    TypedDict = _compat_module_0.TypedDict
    _push_endpoint = _compat_module_0._push_endpoint
    _push_serial = _compat_module_0._push_serial
    annotations = _compat_module_0.annotations
    cast = _compat_module_0.cast
    deepcopy = _compat_module_0.deepcopy
    discover_services = _compat_module_0.discover_services
    isolated_session = _compat_module_0.isolated_session
    json = _compat_module_0.json
    logging = _compat_module_0.logging
    profile_for_token = _compat_module_0.profile_for_token
    refresh_credentials = _compat_module_0.refresh_credentials
    requests = _compat_module_0.requests
    suppress = _compat_module_0.suppress
    synchronize_http_headers = _compat_module_0.synchronize_http_headers
    validate_push_token = _compat_module_0.validate_push_token

sys.modules[__name__] = _implementation
