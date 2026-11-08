# Compatibility export assignments include retained private attributes.
# ruff: noqa: SLF001
# Compatibility aliases are explicit type-checker re-exports.
# Compatibility aliases are explicit type-checker re-exports.

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.utils`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""

import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import utils as _implementation

if TYPE_CHECKING:
    import Crypto.Cipher.AES as _compat_typed_AES

    AES = _compat_typed_AES

    import pyezvizapi._shared.utils as _compat_module_1

    HIK_ENCRYPTION_HEADER = _compat_module_1.HIK_ENCRYPTION_HEADER
    MILLISECONDS_THRESHOLD = _compat_module_1.MILLISECONDS_THRESHOLD
    WILDCARD_STEP = _compat_module_1.WILDCARD_STEP
    Any = _compat_module_1.Any
    Iterable = _compat_module_1.Iterable
    Iterator = _compat_module_1.Iterator
    PathComponent = _compat_module_1.PathComponent
    PyEzvizError = _compat_module_1.PyEzvizError
    ZoneInfo = _compat_module_1.ZoneInfo
    ZoneInfoNotFoundError = _compat_module_1.ZoneInfoNotFoundError
    _decrypt_single_block = _compat_module_1._decrypt_single_block
    _image_crypto = _compat_module_1._image_crypto
    _split_encrypted_blocks = _compat_module_1._split_encrypted_blocks
    annotations = _compat_module_1.annotations
    coerce_int = _compat_module_1.coerce_int
    compute_motion_from_alarm = _compat_module_1.compute_motion_from_alarm
    convert_to_dict = _compat_module_1.convert_to_dict
    datetime = _compat_module_1.datetime
    decode_json = _compat_module_1.decode_json
    decrypt_image = _compat_module_1.decrypt_image
    deep_merge = _compat_module_1.deep_merge
    fetch_nested_value = _compat_module_1.fetch_nested_value
    first_nested = _compat_module_1.first_nested
    iter_nested = _compat_module_1.iter_nested
    json = _compat_module_1.json
    logging = _compat_module_1.logging
    md5 = _compat_module_1.md5
    normalize_alarm_time = _compat_module_1.normalize_alarm_time
    parse_timezone_value = _compat_module_1.parse_timezone_value
    return_password_hash = _compat_module_1.return_password_hash
    string_to_list = _compat_module_1.string_to_list

    def _declare_compatibility_exports(*exports: object) -> None:
        """Declare retained named exports to static analyzers; no runtime import work."""
        if not exports:
            raise AssertionError("compatibility export list must not be empty")

    _declare_compatibility_exports(
        AES,
        HIK_ENCRYPTION_HEADER,
        MILLISECONDS_THRESHOLD,
        WILDCARD_STEP,
        Any,
        Iterable,
        Iterator,
        PathComponent,
        PyEzvizError,
        ZoneInfo,
        ZoneInfoNotFoundError,
        _decrypt_single_block,
        _image_crypto,
        _split_encrypted_blocks,
        annotations,
        coerce_int,
        compute_motion_from_alarm,
        convert_to_dict,
        datetime,
        decode_json,
        decrypt_image,
        deep_merge,
        fetch_nested_value,
        first_nested,
        iter_nested,
        json,
        logging,
        md5,
        normalize_alarm_time,
        parse_timezone_value,
        return_password_hash,
        string_to_list,
    )

sys.modules[__name__] = _implementation
