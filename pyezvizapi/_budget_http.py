"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.budget`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import budget as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.budget import (
    Any as Any,
    Empty as Empty,
    Event as Event,
    Full as Full,
    Lock as Lock,
    MAX_BOOTSTRAP_BODY_BYTES as MAX_BOOTSTRAP_BODY_BYTES,
    PyEzvizError as PyEzvizError,
    Queue as Queue,
    RequestsCookieJar as RequestsCookieJar,
    Thread as Thread,
    _HttpJob as _HttpJob,
    _HttpWorker as _HttpWorker,
    _IDLE_SECONDS as _IDLE_SECONDS,
    _WORKER as _WORKER,
    _commit_cookies as _commit_cookies,
    _response_socket as _response_socket,
    annotations as annotations,
    budgeted_http_call as budgeted_http_call,
    copy as copy,
    dataclass as dataclass,
    field as field,
    isolated_session as isolated_session,
    remaining_request_budget as remaining_request_budget,
    requests as requests,
    socket as socket,
    suppress as suppress,
    )

sys.modules[__name__] = _implementation
