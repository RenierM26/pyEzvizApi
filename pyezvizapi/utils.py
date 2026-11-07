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

from . import _image_crypto
from ._alarm_time import (
    MILLISECONDS_THRESHOLD,
    compute_motion_from_alarm,
    normalize_alarm_time,
    parse_timezone_value,
)
from ._coercion import (
    coerce_int,
    convert_to_dict,
    decode_json,
    string_to_list,
)
from ._mapping import (
    WILDCARD_STEP,
    PathComponent,
    deep_merge,
    fetch_nested_value,
    first_nested,
    iter_nested,
)
from .constants import HIK_ENCRYPTION_HEADER
from .exceptions import PyEzvizError

decrypt_image = _image_crypto.decrypt_image
return_password_hash = _image_crypto.return_password_hash

# Private compatibility hooks are attributes, not wildcard exports.
_decrypt_single_block = _image_crypto._decrypt_single_block  # noqa: SLF001
_split_encrypted_blocks = _image_crypto._split_encrypted_blocks  # noqa: SLF001

__all__ = ['AES', 'HIK_ENCRYPTION_HEADER', 'MILLISECONDS_THRESHOLD', 'WILDCARD_STEP', 'Any', 'Iterable', 'Iterator', 'PathComponent', 'PyEzvizError', 'ZoneInfo', 'ZoneInfoNotFoundError', 'annotations', 'coerce_int', 'compute_motion_from_alarm', 'convert_to_dict', 'datetime', 'decode_json', 'decrypt_image', 'deep_merge', 'fetch_nested_value', 'first_nested', 'iter_nested', 'json', 'logging', 'md5', 'normalize_alarm_time', 'parse_timezone_value', 'return_password_hash', 'string_to_list']
