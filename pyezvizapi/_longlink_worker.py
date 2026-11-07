# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi.push.longlink.worker`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi.push.longlink import worker as _implementation

if TYPE_CHECKING:
    from pyezvizapi.push.longlink.worker import (
        _LOGGER as _LOGGER,
        Any as Any,
        Callable as Callable,
        Event as Event,
        EzvizPushFatalError as EzvizPushFatalError,
        Lock as Lock,
        Protocol as Protocol,
        PushSession as PushSession,
        PushWorker as PushWorker,
        Thread as Thread,
        annotations as annotations,
        current_thread as current_thread,
        logging as logging,
    )

sys.modules[__name__] = _implementation
