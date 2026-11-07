"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.mqtt`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push import mqtt as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.mqtt import (
    ANDROID_PROFILE as ANDROID_PROFILE,
    Any as Any,
    Callable as Callable,
    Channel99Session as Channel99Session,
    DEFAULT_TIMEOUT as DEFAULT_TIMEOUT,
    EXT_FIELD_NAMES as EXT_FIELD_NAMES,
    EXT_INT_FIELDS as EXT_INT_FIELDS,
    EzvizAuthTokenExpired as EzvizAuthTokenExpired,
    EzvizPushFatalError as EzvizPushFatalError,
    EzvizToken as EzvizToken,
    EzvizTokenPersistenceError as EzvizTokenPersistenceError,
    Final as Final,
    HTTPError as HTTPError,
    MQTTClient as MQTTClient,
    MqttData as MqttData,
    OrderedDict as OrderedDict,
    PUSH_PROFILE as PUSH_PROFILE,
    PUSH_REGISTER as PUSH_REGISTER,
    PushWorker as PushWorker,
    PyEzvizError as PyEzvizError,
    RLock as RLock,
    ServiceUrls as ServiceUrls,
    TypedDict as TypedDict,
    _LOGGER as _LOGGER,
    _push_endpoint as _push_endpoint,
    _push_serial as _push_serial,
    annotations as annotations,
    cast as cast,
    deepcopy as deepcopy,
    discover_services as discover_services,
    isolated_session as isolated_session,
    json as json,
    logging as logging,
    profile_for_token as profile_for_token,
    refresh_credentials as refresh_credentials,
    requests as requests,
    suppress as suppress,
    synchronize_http_headers as synchronize_http_headers,
    validate_push_token as validate_push_token,
    )

sys.modules[__name__] = _implementation
