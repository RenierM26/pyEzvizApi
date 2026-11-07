# Compatibility aliases are explicit type-checker re-exports.
# ruff: noqa: PLC0414

"""Compatibility alias. Implementation: :mod:`pyezvizapi._shared.utils`.

New development belongs in the domain package; legacy module identity and
patch hooks are preserved. This module contains no implementation.
"""
import sys
from typing import TYPE_CHECKING

from pyezvizapi._shared import utils as _implementation

if TYPE_CHECKING:
    from Crypto.Cipher import AES as AES

    from pyezvizapi._shared.utils import (
        HIK_ENCRYPTION_HEADER as HIK_ENCRYPTION_HEADER,
        MILLISECONDS_THRESHOLD as MILLISECONDS_THRESHOLD,
        WILDCARD_STEP as WILDCARD_STEP,
        Any as Any,
        Iterable as Iterable,
        Iterator as Iterator,
        PathComponent as PathComponent,
        PyEzvizError as PyEzvizError,
        ZoneInfo as ZoneInfo,
        ZoneInfoNotFoundError as ZoneInfoNotFoundError,
        _decrypt_single_block as _decrypt_single_block,
        _image_crypto as _image_crypto,
        _split_encrypted_blocks as _split_encrypted_blocks,
        annotations as annotations,
        coerce_int as coerce_int,
        compute_motion_from_alarm as compute_motion_from_alarm,
        convert_to_dict as convert_to_dict,
        datetime as datetime,
        decode_json as decode_json,
        decrypt_image as decrypt_image,
        deep_merge as deep_merge,
        fetch_nested_value as fetch_nested_value,
        first_nested as first_nested,
        iter_nested as iter_nested,
        json as json,
        logging as logging,
        md5 as md5,
        normalize_alarm_time as normalize_alarm_time,
        parse_timezone_value as parse_timezone_value,
        return_password_hash as return_password_hash,
        string_to_list as string_to_list,
    )

sys.modules[__name__] = _implementation
