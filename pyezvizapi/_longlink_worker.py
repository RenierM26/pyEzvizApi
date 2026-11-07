"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.worker`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import worker as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.worker import (
    Any as Any,
    Callable as Callable,
    Event as Event,
    EzvizPushFatalError as EzvizPushFatalError,
    Lock as Lock,
    Protocol as Protocol,
    PushSession as PushSession,
    PushWorker as PushWorker,
    Thread as Thread,
    _LOGGER as _LOGGER,
    annotations as annotations,
    current_thread as current_thread,
    logging as logging,
    )

sys.modules[__name__] = _implementation
