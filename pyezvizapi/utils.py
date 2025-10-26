"""Decrypt camera images."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
import datetime
from hashlib import md5
import json
import logging
import re as _re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from Crypto.Cipher import AES

from .constants import HIK_ENCRYPTION_HEADER
from .exceptions import PyEzvizError

_LOGGER = logging.getLogger(__name__)


def coerce_int(value: Any) -> int | None:
    """Best-effort coercion to int for mixed payloads."""

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, (int, float)):
        return int(value)

    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def decode_json(value: Any) -> Any:
    """Decode a JSON string when possible, otherwise return the original value."""

    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None
    return value


def convert_to_dict(data: Any) -> Any:
    """Recursively convert a string representation of a dictionary to a dictionary."""
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                try:
                    # Attempt to convert the string back into a dictionary
                    data[key] = json.loads(value)

                except ValueError:
                    continue
            continue

    return data


def string_to_list(data: Any, separator: str = ",") -> Any:
    """Convert a string representation of a list to a list."""
    if isinstance(data, str) and separator in data:
        try:
            # Attempt to convert the string into a list
            return data.split(separator)

        except AttributeError:
            return data

    return data


PathComponent = str | int
WILDCARD_STEP = "*"
_MISSING = object()
MILLISECONDS_THRESHOLD = 1e11


def iter_nested(data: Any, path: Iterable[PathComponent]) -> Iterator[Any]:
    """Yield values reachable by following a dotted path with optional wildcards."""

    current: list[Any] = [data]

    for step in path:
        next_level: list[Any] = []
        for candidate in current:
            if step == WILDCARD_STEP:
                if isinstance(candidate, dict):
                    next_level.extend(candidate.values())
                elif isinstance(candidate, (list, tuple)):
                    next_level.extend(candidate)
                continue

            if isinstance(candidate, dict) and step in candidate:
                next_level.append(candidate[step])
                continue

            if (
                isinstance(candidate, (list, tuple))
                and isinstance(step, int)
                and -len(candidate) <= step < len(candidate)
            ):
                next_level.append(candidate[step])

        current = next_level
        if not current:
            break

    yield from current


def first_nested(
    data: Any, path: Iterable[PathComponent], default: Any = None
) -> Any:
    """Return the first value produced by iter_nested or ``default``."""

    return next(iter_nested(data, path), default)


def fetch_nested_value(data: Any, keys: list, default_value: Any = None) -> Any:
    """Fetch the value corresponding to the given nested keys in a dictionary.

    If any of the keys in the path doesn't exist, the default value is returned.

    Args:
        data (dict): The nested dictionary to search for keys.
        keys (list): A list of keys representing the path to the desired value.
        default_value (optional): The value to return if any of the keys doesn't exist.

    Returns:
        The value corresponding to the nested keys or the default value.

    """
    value = first_nested(data, keys, _MISSING)
    return default_value if value is _MISSING else value


def decrypt_image(input_data: bytes, password: str) -> bytes:
    """Decrypts image data with provided password.

    Args:
        input_data (bytes): Encrypted image data
        password (string): Verification code

    Raises:
        PyEzvizError

    Returns:
        bytes: Decrypted image data

    """
    header_len = len(HIK_ENCRYPTION_HEADER)
    min_length = header_len + 32  # header + md5 hash

    if len(input_data) < min_length:
        raise PyEzvizError("Invalid image data")

    header_index = input_data.find(HIK_ENCRYPTION_HEADER)
    if header_index == -1:
        _LOGGER.debug("Image header doesn't contain %s", HIK_ENCRYPTION_HEADER)
        return input_data

    if header_index:
        _LOGGER.debug("Image header found at offset %s, trimming preamble", header_index)
        input_data = input_data[header_index:]
        if len(input_data) < min_length:
            raise PyEzvizError("Invalid image data after trimming preamble")

    hash_end = header_len + 32
    blocks = _split_encrypted_blocks(input_data, header_len, min_length)
    if not blocks:
        raise PyEzvizError("Invalid image data")

    decrypted_parts = [
        _decrypt_single_block(block, password, header_len, hash_end) for block in blocks
    ]
    if len(decrypted_parts) > 1:
        _LOGGER.debug("Decrypted %s concatenated image blocks", len(decrypted_parts))
    return b"".join(decrypted_parts)


def _split_encrypted_blocks(
    data: bytes, header_len: int, min_length: int
) -> list[bytes]:
    """Split concatenated hikencodepicture segments into individual blocks."""
    blocks: list[bytes] = []
    cursor = 0
    data_len = len(data)

    while cursor <= data_len - min_length:
        if data[cursor : cursor + header_len] != HIK_ENCRYPTION_HEADER:
            next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + 1)
            if next_header == -1:
                break
            cursor = next_header
            continue

        next_header = data.find(HIK_ENCRYPTION_HEADER, cursor + header_len)
        block = data[cursor : next_header if next_header != -1 else data_len]
        if len(block) < min_length:
            break
        blocks.append(block)
        if next_header == -1:
            break
        cursor = next_header

    return blocks


def _decrypt_single_block(
    block: bytes, password: str, header_len: int, hash_end: int
) -> bytes:
    """Decrypt a single hikencodepicture block."""
    file_hash = block[header_len:hash_end]
    passwd_hash = md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()
    if file_hash != str.encode(passwd_hash):
        raise PyEzvizError("Invalid password")

    ciphertext = block[hash_end:]
    if not ciphertext:
        raise PyEzvizError("Missing ciphertext payload")

    remainder = len(ciphertext) % AES.block_size
    if remainder:
        _LOGGER.debug(
            "Ciphertext not aligned to 16 bytes; trimming %s trailing bytes", remainder
        )
        ciphertext = ciphertext[:-remainder]
    if not ciphertext:
        raise PyEzvizError("Ciphertext too short after alignment adjustment")

    key = str.encode(password.ljust(16, "\u0000")[:16])
    iv_code = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES.new(key, AES.MODE_CBC, iv_code)

    chunk_size = 1024 * AES.block_size
    output_data = bytearray()

    for start in range(0, len(ciphertext), chunk_size):
        block_chunk = cipher.decrypt(ciphertext[start : start + chunk_size])
        if start + chunk_size >= len(ciphertext):
            padding_length = block_chunk[-1]
            block_chunk = block_chunk[:-padding_length]
        output_data.extend(block_chunk)

    return bytes(output_data)



def return_password_hash(password: str) -> str:
    """Return the password hash."""
    return md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()


def deep_merge(dict1: Any, dict2: Any) -> Any:
    """Recursively merges two dictionaries, handling lists as well.

    Args:
    dict1 (dict): The first dictionary.
    dict2 (dict): The second dictionary.

    Returns:
    dict: The merged dictionary.

    """
    # If one of the dictionaries is None, return the other one
    if dict1 is None:
        return dict2
    if dict2 is None:
        return dict1

    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        if isinstance(dict1, list) and isinstance(dict2, list):
            return dict1 + dict2
        return dict2

    # Create a new dictionary to store the merged result
    merged = {}

    # Merge keys from both dictionaries
    for key in set(dict1.keys()) | set(dict2.keys()):
        if key in dict1 and key in dict2:
            if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                merged[key] = deep_merge(dict1[key], dict2[key])
            elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
                merged[key] = dict1[key] + dict2[key]
            else:
                # If both values are not dictionaries or lists, keep the value from dict2
                merged[key] = dict2[key]
        elif key in dict1:
            # If the key is only in dict1, keep its value
            merged[key] = dict1[key]
        else:
            # If the key is only in dict2, keep its value
            merged[key] = dict2[key]

    return merged


# ---------------------------------------------------------------------------
# Time helpers for alarm/motion handling
# ---------------------------------------------------------------------------


def normalize_alarm_time(
    last_alarm: dict[str, Any], tzinfo: datetime.tzinfo
) -> tuple[datetime.datetime | None, datetime.datetime | None, str | None]:
    """Normalize EZVIZ alarm timestamps.

    Returns a tuple of:
      - alarm_dt_local: datetime in the camera's timezone (for display)
      - alarm_dt_utc: datetime in UTC (for robust delta calculation)
      - alarm_time_str: formatted 'YYYY-MM-DD HH:MM:SS' string in camera tz

    Behavior:
      - Prefer epoch fields (alarmStartTime/alarmTime). Interpret as UTC by default.
      - If a string time exists and differs from the epoch by >120 seconds,
        reinterpret the epoch as if reported in camera local time.
      - If no epoch, fall back to parsing the string time in the camera tz.
    """
    # Prefer epoch
    epoch = last_alarm.get("alarmStartTime") or last_alarm.get("alarmTime")
    raw_time_str = str(
        last_alarm.get("alarmStartTimeStr") or last_alarm.get("alarmTimeStr") or ""
    )

    alarm_dt_local: datetime.datetime | None = None
    alarm_dt_utc: datetime.datetime | None = None
    alarm_str: str | None = None

    now_local = datetime.datetime.now(tz=tzinfo)

    if epoch is not None:
        try:
            ts = float(epoch if not isinstance(epoch, str) else float(epoch))
            if ts > MILLISECONDS_THRESHOLD:  # milliseconds
                ts /= 1000.0
            event_utc = datetime.datetime.fromtimestamp(ts, tz=datetime.UTC)
            alarm_dt_local = event_utc.astimezone(tzinfo)
            alarm_dt_utc = event_utc

            if raw_time_str:
                raw_norm = raw_time_str.replace("Today", str(now_local.date()))
                try:
                    dt_str_local = datetime.datetime.strptime(
                        raw_norm, "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=tzinfo)
                    diff = abs(
                        (
                            event_utc - dt_str_local.astimezone(datetime.UTC)
                        ).total_seconds()
                    )
                    if diff > 120:
                        # Reinterpret epoch as local clock time in camera tz
                        naive_utc = datetime.datetime.fromtimestamp(
                            ts, tz=datetime.UTC
                        ).replace(tzinfo=None)
                        event_local_reint = naive_utc.replace(tzinfo=tzinfo)
                        alarm_dt_local = event_local_reint
                        alarm_dt_utc = event_local_reint.astimezone(datetime.UTC)
                except ValueError:
                    pass

            if alarm_dt_local is not None:
                alarm_str = alarm_dt_local.strftime("%Y-%m-%d %H:%M:%S")
                return alarm_dt_local, alarm_dt_utc, alarm_str
            # If conversion failed unexpectedly, fall through to string parsing
        except (TypeError, ValueError, OSError):
            alarm_dt_local = None

    # Fallback to string parsing
    if raw_time_str:
        raw = raw_time_str.replace("Today", str(now_local.date()))
        try:
            alarm_dt_local = datetime.datetime.strptime(
                raw, "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=tzinfo)
            alarm_dt_utc = alarm_dt_local.astimezone(datetime.UTC)
            alarm_str = alarm_dt_local.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    return alarm_dt_local, alarm_dt_utc, alarm_str


def compute_motion_from_alarm(
    last_alarm: dict[str, Any], tzinfo: datetime.tzinfo, window_seconds: float = 60.0
) -> tuple[bool, float, str | None]:
    """Compute motion state and seconds-since from an alarm payload.

    Returns (active, seconds_since, last_alarm_time_str).
    - Uses UTC for delta when epoch-derived UTC is available.
    - Falls back to camera local tz deltas when only string times are present.
    - Clamps negative deltas to 0.0 and deactivates motion.
    """
    alarm_dt_local, alarm_dt_utc, alarm_str = normalize_alarm_time(last_alarm, tzinfo)
    if alarm_dt_local is None:
        return False, 0.0, None

    now_local = datetime.datetime.now(tz=tzinfo).replace(microsecond=0)
    now_utc = datetime.datetime.now(tz=datetime.UTC).replace(microsecond=0)

    delta = (
        now_utc - alarm_dt_utc
        if alarm_dt_utc is not None
        else now_local - alarm_dt_local
    )

    seconds = float(delta.total_seconds())
    if seconds < 0:
        return False, 0.0, alarm_str

    return seconds < window_seconds, seconds, alarm_str


def parse_timezone_value(tz_val: Any) -> datetime.tzinfo:
    """Parse EZVIZ timeZone value into a tzinfo.

    Supports:
      - IANA names like 'Europe/Paris'
      - Offsets like 'UTC+02:00', 'GMT-5', '+0530', or integers (hours/minutes/seconds)
    Falls back to the local system timezone, or UTC if unavailable.
    """
    # IANA zone name
    if isinstance(tz_val, str) and "/" in tz_val:
        try:
            return ZoneInfo(tz_val)
        except ZoneInfoNotFoundError:
            pass

    # Numeric offsets
    offset_minutes: int | None = None
    if isinstance(tz_val, int):
        if -14 <= tz_val <= 14:
            offset_minutes = tz_val * 60
        elif -24 * 60 <= tz_val <= 24 * 60:
            offset_minutes = tz_val
        elif -24 * 3600 <= tz_val <= 24 * 3600:
            offset_minutes = int(tz_val / 60)
    elif isinstance(tz_val, str):
        s = tz_val.strip().upper().replace("UTC", "").replace("GMT", "")
        m = _re.match(r"^([+-]?)(\d{1,2})(?::?(\d{2}))?$", s)
        if m:
            sign = -1 if m.group(1) == "-" else 1
            hours = int(m.group(2))
            minutes = int(m.group(3)) if m.group(3) else 0
            offset_minutes = sign * (hours * 60 + minutes)

    if offset_minutes is not None:
        return datetime.timezone(datetime.timedelta(minutes=offset_minutes))

    # Fallbacks
    return datetime.datetime.now().astimezone().tzinfo or datetime.UTC
