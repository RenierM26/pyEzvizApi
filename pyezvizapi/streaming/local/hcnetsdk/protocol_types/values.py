"""values protocol values and pure helpers; dependency-closed implementation."""

from __future__ import annotations

from pyezvizapi.streaming.local.hcnetsdk.constants import (
    SADP_NUL_BYTE,
    Any,
    Mapping,
    PyEzvizError,
)


def _mapping_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if isinstance(value, str) and value:
        return value
    return None


def _mapping_int(
    data: Mapping[str, Any],
    key: str,
    *,
    default: int | None,
    zero_is_missing: bool = False,
) -> int | None:
    value = data.get(key)
    if value is None:
        return default
    if isinstance(value, int):
        return default if zero_is_missing and value == 0 else value
    if isinstance(value, str):
        try:
            int_value = int(value)
        except ValueError:
            return default
        return default if zero_is_missing and int_value == 0 else int_value
    return default


def _stdxml_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise PyEzvizError(f"HCNetSDK STDXML {label} must be bytes or string")
    return value.encode("utf-8")


def _optional_raw_byte(raw: bytes, offset: int) -> int | None:
    return raw[offset] if len(raw) > offset else None


def _optional_raw_byte_triplet(
    raw: bytes,
    first_offset: int,
    second_offset: int,
    third_offset: int,
) -> tuple[int, int, int] | None:
    if len(raw) <= max(first_offset, second_offset, third_offset):
        return None
    return raw[first_offset], raw[second_offset], raw[third_offset]


def _optional_raw_u32_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 4:
        return None
    return int.from_bytes(raw[offset : offset + 4], "big")


def _optional_raw_u16_be(raw: bytes, offset: int) -> int | None:
    if len(raw) < offset + 2:
        return None
    return int.from_bytes(raw[offset : offset + 2], "big")


def _optional_raw_u16_be_pair(
    raw: bytes,
    first_offset: int,
    second_offset: int,
) -> tuple[int, int] | None:
    first = _optional_raw_u16_be(raw, first_offset)
    second = _optional_raw_u16_be(raw, second_offset)
    if first is None or second is None:
        return None
    return first, second


def _byte_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFF:
        raise PyEzvizError(f"EZVIZ LAN {label} must fit in one byte")
    return value


def _word_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFFFF:
        raise PyEzvizError(f"EZVIZ LAN {label} must fit in one unsigned word")
    return value


def _device_ability_bytes(label: str, value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise PyEzvizError(f"HCNetSDK device ability {label} must be bytes or string")
    return value.encode("utf-8")


def _ability_option_tuple(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(option.strip() for option in value.split(",") if option.strip())


def _bounded_bytes(
    label: str,
    value: str | bytes,
    limit: int,
    *,
    truncate: bool = False,
) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise PyEzvizError(f"EZVIZ LAN {label} must be bytes or string")
    if len(raw) <= limit:
        return raw
    if truncate:
        return raw[:limit]
    raise PyEzvizError(f"EZVIZ LAN {label} must be at most {limit} bytes")


def _nul_stripped_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    text = value.decode("utf-8") if isinstance(value, bytes) else value
    return text.replace("\x00", "").strip()


def _optional_native_bytes(label: str, value: str | bytes | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise PyEzvizError(f"{label} must be bytes or string")


def _native_path_value(
    label: str,
    value: str | bytes,
    *,
    include_buffers: bool = False,
) -> str | bytes:
    raw = _optional_native_bytes(f"HCNetSDK {label}", value)
    if not raw:
        raise PyEzvizError(f"HCNetSDK {label} cannot be empty")
    if SADP_NUL_BYTE in raw:
        raise PyEzvizError(f"HCNetSDK {label} cannot contain NUL bytes")
    if include_buffers:
        return raw
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise PyEzvizError(f"HCNetSDK {label} must be UTF-8") from err


def _native_secret_key_bytes(label: str, value: str | bytes) -> bytes:
    raw = _optional_native_bytes(label, value)
    if not raw:
        raise PyEzvizError(f"{label} cannot be empty")
    if len(raw) > 4096:
        raise PyEzvizError(f"{label} must be at most 4096 bytes")
    return raw


def _port_value(label: str, value: int) -> int:
    if not 0 <= value <= 0xFFFF:
        raise PyEzvizError(f"{label} must be between 0 and 65535")
    return value
