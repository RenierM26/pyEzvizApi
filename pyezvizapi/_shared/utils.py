"""Compatibility imports for the API utility families.

Implementations live in focused coercion, mapping, alarm-time and image modules.
Existing helper imports and the shared datetime module used by callers remain
available here. Tolerant coercion is not a strict protocol validator.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
import datetime
from hashlib import md5
import json
import logging
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from Crypto.Cipher import AES

from pyezvizapi._shared import image_crypto as _image_crypto
from pyezvizapi._shared.alarm_time import (
    MILLISECONDS_THRESHOLD,
    compute_motion_from_alarm,
    normalize_alarm_time,
    parse_timezone_value,
)
from pyezvizapi._shared.coercion import coerce_int, convert_to_dict, decode_json, string_to_list
from pyezvizapi._shared.mapping import (
    WILDCARD_STEP,
    PathComponent,
    deep_merge,
    fetch_nested_value,
    first_nested,
    iter_nested,
)
from pyezvizapi.constants import HIK_ENCRYPTION_HEADER
from pyezvizapi.exceptions import PyEzvizError

decrypt_image = _image_crypto.decrypt_image
return_password_hash = _image_crypto.return_password_hash

# Private compatibility hooks are attributes, not wildcard exports.
def _decrypt_single_block(block: bytes, password: str, header_len: int, hash_end: int) -> bytes:
    return _image_crypto._decrypt_single_block(block, password, header_len, hash_end)  # noqa: SLF001


def _split_encrypted_blocks(data: bytes, header_len: int, min_length: int) -> list[bytes]:
    return _image_crypto._split_encrypted_blocks(data, header_len, min_length)  # noqa: SLF001

__all__ = ['AES', 'HIK_ENCRYPTION_HEADER', 'MILLISECONDS_THRESHOLD', 'WILDCARD_STEP', 'Any', 'Iterable', 'Iterator', 'PathComponent', 'PyEzvizError', 'ZoneInfo', 'ZoneInfoNotFoundError', 'annotations', 'coerce_int', 'compute_motion_from_alarm', 'convert_to_dict', 'datetime', 'decode_json', 'decrypt_image', 'deep_merge', 'fetch_nested_value', 'first_nested', 'iter_nested', 'json', 'logging', 'md5', 'normalize_alarm_time', 'parse_timezone_value', 'return_password_hash', 'string_to_list']
