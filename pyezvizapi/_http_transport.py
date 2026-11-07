"""Compatibility alias. Implementation: :mod:`pyezvizapi.cloud.transport`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi.cloud import transport as _implementation

if TYPE_CHECKING:
    from pyezvizapi.cloud.transport import (
    CaseInsensitiveDict as CaseInsensitiveDict,
    OrderedDict as OrderedDict,
    copy as copy,
    deepcopy as deepcopy,
    isolated_session as isolated_session,
    requests as requests,
    )

sys.modules[__name__] = _implementation
