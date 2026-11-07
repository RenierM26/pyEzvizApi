# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.budget`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import budget as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.budget as _compat_module_0

    _IDLE_SECONDS = _compat_module_0._IDLE_SECONDS
    _WORKER = _compat_module_0._WORKER
    MAX_BOOTSTRAP_BODY_BYTES = _compat_module_0.MAX_BOOTSTRAP_BODY_BYTES
    Any = _compat_module_0.Any
    Empty = _compat_module_0.Empty
    Event = _compat_module_0.Event
    Full = _compat_module_0.Full
    Lock = _compat_module_0.Lock
    PyEzvizError = _compat_module_0.PyEzvizError
    Queue = _compat_module_0.Queue
    RequestsCookieJar = _compat_module_0.RequestsCookieJar
    Thread = _compat_module_0.Thread
    _commit_cookies = _compat_module_0._commit_cookies
    _HttpJob = _compat_module_0._HttpJob
    _HttpWorker = _compat_module_0._HttpWorker
    _response_socket = _compat_module_0._response_socket
    annotations = _compat_module_0.annotations
    budgeted_http_call = _compat_module_0.budgeted_http_call
    copy = _compat_module_0.copy
    dataclass = _compat_module_0.dataclass
    field = _compat_module_0.field
    isolated_session = _compat_module_0.isolated_session
    remaining_request_budget = _compat_module_0.remaining_request_budget
    requests = _compat_module_0.requests
    socket = _compat_module_0.socket
    suppress = _compat_module_0.suppress

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _IDLE_SECONDS,
        _WORKER,
        MAX_BOOTSTRAP_BODY_BYTES,
        Any,
        Empty,
        Event,
        Full,
        Lock,
        PyEzvizError,
        Queue,
        RequestsCookieJar,
        Thread,
        _commit_cookies,
        _HttpJob,
        _HttpWorker,
        _response_socket,
        annotations,
        budgeted_http_call,
        copy,
        dataclass,
        field,
        isolated_session,
        remaining_request_budget,
        requests,
        socket,
        suppress,
    )

sys.modules[__name__] = _implementation
