# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.deadline`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import deadline as _implementation

if TYPE_CHECKING:
    import pyezvizapi.cloud.deadline as _compat_module_0

    _BUDGET = _compat_module_0._BUDGET
    Any = _compat_module_0.Any
    Callable = _compat_module_0.Callable
    ContextVar = _compat_module_0.ContextVar
    Iterator = _compat_module_0.Iterator
    Timeout = _compat_module_0.Timeout
    bounded_request_timeout = _compat_module_0.bounded_request_timeout
    contextmanager = _compat_module_0.contextmanager
    remaining_request_budget = _compat_module_0.remaining_request_budget
    request_budget_lock = _compat_module_0.request_budget_lock
    request_deadline = _compat_module_0.request_deadline
    time = _compat_module_0.time

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        _BUDGET,
        Any,
        Callable,
        ContextVar,
        Iterator,
        Timeout,
        bounded_request_timeout,
        contextmanager,
        remaining_request_budget,
        request_budget_lock,
        request_deadline,
        time,
    )

sys.modules[__name__] = _implementation
