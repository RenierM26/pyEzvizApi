"""Compatibility imports for the API utility families.

Implementations live in focused coercion, mapping, alarm-time and image modules.
Existing helper imports and the shared datetime module used by callers remain
available here. Tolerant coercion is not a strict protocol validator.
"""

import datetime

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
from ._image_crypto import (
    _decrypt_single_block,
    _split_encrypted_blocks,
    decrypt_image,
    return_password_hash,
)
from ._mapping import (
    WILDCARD_STEP,
    PathComponent,
    deep_merge,
    fetch_nested_value,
    first_nested,
    iter_nested,
)

__all__ = ['MILLISECONDS_THRESHOLD', 'WILDCARD_STEP', 'PathComponent', '_decrypt_single_block', '_split_encrypted_blocks', 'coerce_int', 'compute_motion_from_alarm', 'convert_to_dict', 'datetime', 'decode_json', 'decrypt_image', 'deep_merge', 'fetch_nested_value', 'first_nested', 'iter_nested', 'normalize_alarm_time', 'parse_timezone_value', 'return_password_hash', 'string_to_list']
