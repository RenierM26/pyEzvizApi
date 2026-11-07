# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.image_crypto`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import image_crypto as _implementation

if TYPE_CHECKING:
    from Crypto.Cipher import AES as AES

    from pyezvizapi._shared.image_crypto import (
        _LOGGER as _LOGGER,
        HIK_ENCRYPTION_HEADER as HIK_ENCRYPTION_HEADER,
        PyEzvizError as PyEzvizError,
        _decrypt_single_block as _decrypt_single_block,
        _split_encrypted_blocks as _split_encrypted_blocks,
        annotations as annotations,
        decrypt_image as decrypt_image,
        logging as logging,
        md5 as md5,
        return_password_hash as return_password_hash,
    )

sys.modules[__name__] = _implementation
