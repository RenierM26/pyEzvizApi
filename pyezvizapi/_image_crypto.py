# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.image_crypto`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import image_crypto as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher as _compat_module_0
    AES = _compat_module_0.AES

    import pyezvizapi._shared.image_crypto as _compat_module_1
    _LOGGER = _compat_module_1._LOGGER
    HIK_ENCRYPTION_HEADER = _compat_module_1.HIK_ENCRYPTION_HEADER
    PyEzvizError = _compat_module_1.PyEzvizError
    _decrypt_single_block = _compat_module_1._decrypt_single_block
    _split_encrypted_blocks = _compat_module_1._split_encrypted_blocks
    annotations = _compat_module_1.annotations
    decrypt_image = _compat_module_1.decrypt_image
    logging = _compat_module_1.logging
    md5 = _compat_module_1.md5
    return_password_hash = _compat_module_1.return_password_hash

sys.modules[__name__] = _implementation
