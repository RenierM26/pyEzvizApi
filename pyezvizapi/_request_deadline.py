"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.deadline`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import deadline as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.deadline import (
    Any as Any,
    Callable as Callable,
    ContextVar as ContextVar,
    Iterator as Iterator,
    Timeout as Timeout,
    _BUDGET as _BUDGET,
    bounded_request_timeout as bounded_request_timeout,
    contextmanager as contextmanager,
    remaining_request_budget as remaining_request_budget,
    request_budget_lock as request_budget_lock,
    request_deadline as request_deadline,
    time as time,
    )

sys.modules[__name__] = _implementation
