"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.image_crypto`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
# ruff: noqa: F401, I001, SLF001 -- explicit legacy typing/export surface.
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import image_crypto as _implementation

if TYPE_CHECKING:
    from pyezvizapi._shared.image_crypto import (
    AES as AES,
    HIK_ENCRYPTION_HEADER as HIK_ENCRYPTION_HEADER,
    PyEzvizError as PyEzvizError,
    _LOGGER as _LOGGER,
    _decrypt_single_block as _decrypt_single_block,
    _split_encrypted_blocks as _split_encrypted_blocks,
    annotations as annotations,
    decrypt_image as decrypt_image,
    logging as logging,
    md5 as md5,
    return_password_hash as return_password_hash,
    )

sys.modules[__name__] = _implementation
