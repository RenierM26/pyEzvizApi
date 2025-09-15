"""Decrypt camera images."""

from __future__ import annotations

import datetime
from hashlib import md5
import json
import logging
import re as _re
from typing import Any
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from Crypto.Cipher import AES

from .exceptions import PyEzvizError

_LOGGER = logging.getLogger(__name__)


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
    if isinstance(data, str):
        if separator in data:
            try:
                # Attempt to convert the string into a list
                return data.split(separator)

            except AttributeError:
                return data

    return data


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
    try:
        for key in keys:
            data = data[key]

    except (KeyError, TypeError):
        return default_value

    return data


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
    if len(input_data) < 48:
        raise PyEzvizError("Invalid image data")

    # check header
    if input_data[:16] != b"hikencodepicture":
        _LOGGER.debug("Image header doesn't contain 'hikencodepicture'")
        return input_data

    file_hash = input_data[16:48]
    passwd_hash = md5(str.encode(md5(str.encode(password)).hexdigest())).hexdigest()
    if file_hash != str.encode(passwd_hash):
        raise PyEzvizError("Invalid password")

    key = str.encode(password.ljust(16, "\u0000")[:16])
    iv_code = bytes([48, 49, 50, 51, 52, 53, 54, 55, 0, 0, 0, 0, 0, 0, 0, 0])
    cipher = AES.new(key, AES.MODE_CBC, iv_code)

    next_chunk = b""
    output_data = b""
    finished = False
    i = 48  # offset hikencodepicture + hash
    chunk_size = 1024 * AES.block_size
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(input_data[i : i + chunk_size])
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True
        output_data += chunk
        i += chunk_size
    return output_data


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


def generate_unique_code() -> str:
    """Generate a deterministic, platform-agnostic unique code for the current host.

    This function retrieves the host's MAC address using Python's standard
    `uuid.getnode()` (works on Windows, Linux, macOS), converts it to a
    canonical string representation, and then hashes it using MD5 to produce
    a fixed-length hexadecimal string.

    Returns:
        str: A 32-character hexadecimal string uniquely representing
        the host's MAC address. For example:
        'a94e6756hghjgfghg49e0f310d9e44a'.

    Notes:
        - The output is deterministic: the same machine returns the same code.
        - If the MAC address changes (e.g., different network adapter),
          the output will change.
        - MD5 is used here only for ID generation, not for security.
    """
    mac_int = uuid.getnode()
    mac_str = ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in range(40, -1, -8))
    return md5(mac_str.encode("utf-8")).hexdigest()


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
            if ts > 1e11:  # milliseconds
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

    if alarm_dt_utc is not None:
        delta = now_utc - alarm_dt_utc
    else:
        delta = now_local - alarm_dt_local

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
