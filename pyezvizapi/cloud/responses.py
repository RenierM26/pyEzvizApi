"""Pure JSON/envelope interpretation and credential-safe response descriptions."""

from __future__ import annotations

from collections.abc import Mapping
from itertools import islice
import json
from typing import Any

import requests

from pyezvizapi.exceptions import PyEzvizError

JsonDict = dict[str, Any]


def parse_json(resp: requests.Response) -> JsonDict:
    """Parse an API object without echoing potentially secret response text."""
    try:
        payload = resp.json()
    except ValueError:
        # Parser exceptions may embed response text; keep tracebacks redacted too.
        raise PyEzvizError("Impossible to decode response: invalid JSON") from None
    if not isinstance(payload, dict):
        raise PyEzvizError("Expected a JSON object in API response")
    return payload


def object_section(payload: JsonDict, key: str, *, required: bool = False) -> JsonDict:
    """Validate a named response object without including its values in errors."""
    if required and key not in payload:
        raise PyEzvizError(f"Missing API object section: {key}")
    value = payload.get(key, {})
    if not isinstance(value, dict):
        raise PyEzvizError(f"Invalid API object section: {key}")
    return value


def normalize_json_payload(payload: Any) -> Any:
    """Return a payload suitable for json= usage, decoding strings when needed."""

    if isinstance(payload, (Mapping, list)):
        return payload
    if isinstance(payload, tuple):
        return list(payload)
    if isinstance(payload, (bytes, bytearray)):
        try:
            return json.loads(payload.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as err:
            raise PyEzvizError("Invalid JSON payload provided") from err
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except json.JSONDecodeError as err:
            raise PyEzvizError("Invalid JSON payload provided") from err
    raise PyEzvizError("Unsupported payload type for JSON body")


def is_ok(payload: JsonDict) -> bool:
    """Return True if payload indicates success for both API styles."""
    meta = payload.get("meta")
    if isinstance(meta, dict) and meta.get("code") == 200:
        return True
    rc = payload.get("resultCode")
    return not isinstance(rc, bool) and rc in (0, "0")


def meta_code(payload: JsonDict) -> int | None:
    """Safely extract meta.code as an int, or None if missing/invalid."""
    meta = payload.get("meta")
    code = meta.get("code") if isinstance(meta, Mapping) else None
    if isinstance(code, (int, str)):
        try:
            return int(code)
        except (TypeError, ValueError):
            return None
    return None


def response_code(payload: JsonDict) -> int | str | None:
    """Return a best-effort code from a response for logging.

    Prefers modern ``meta.code`` if present; falls back to legacy
    ``resultCode`` or a top-level ``status`` field when available.
    Returns None if no code-like field is found.
    """
    candidate = meta_code(payload)
    if candidate is None:
        candidate = payload.get("resultCode", payload.get("status"))
    if isinstance(candidate, bool) or not isinstance(candidate, (int, str)):
        return None
    if isinstance(candidate, str):
        if len(candidate) > 12 or not candidate.isascii():
            return None
        try:
            int(candidate)
        except ValueError:
            return None
        return candidate.strip()
    return candidate if -(10**12) < candidate < 10**12 else None


def summarize_payload(payload: Any) -> str:
    """Return a compact, credential-safe payload description for debug logs."""

    if payload is None:
        return "-"
    if isinstance(payload, Mapping):
        sensitive_keys = {
            "password",
            "oldPassword",
            "newPassword",
            "token",
            "sessionId",
        }
        keys = ", ".join(
            "<redacted>" if key in sensitive_keys else key
            for key in sorted(str(key)[:32] for key in islice(payload, 16))
        )
        return f"dict[{keys}](fields={len(payload)})"
    if isinstance(payload, (list, tuple, set)):
        return f"{type(payload).__name__}(len={len(payload)})"
    if isinstance(payload, (bytes, bytearray)):
        return f"bytes(len={len(payload)})"
    if isinstance(payload, str):
        return f"str(len={len(payload)})"
    return f"{type(payload).__name__}"


def body_debug_summary(payload: Any) -> str:
    """Return a request-body summary without inspecting sensitive contents."""

    if payload is None:
        return "-"
    try:
        return f"{type(payload).__name__}(len={len(payload)})"
    except TypeError:
        return type(payload).__name__


def response_summary(payload: Any) -> str:
    """Describe a response using numeric codes and shape, never raw values."""
    if not isinstance(payload, Mapping):
        return f"response type={type(payload).__name__}"
    meta = payload.get("meta")
    code = meta.get("code") if isinstance(meta, Mapping) else None
    if code is None:
        code = payload.get("resultCode", payload.get("status"))
    if isinstance(code, bool) or not isinstance(code, (int, str)):
        code = None
    elif isinstance(code, str):
        # Restrict both conversion cost and output; error messages are not
        # a channel for arbitrary server-provided strings or credentials.
        digits = code[1:] if code.startswith(("+", "-")) else code
        code = int(code) if len(code) <= 12 and code.isascii() and digits.isdigit() else None
    if isinstance(code, int) and not -(10**12) < code < 10**12:
        code = None
    return f"response code={code}, fields={len(payload)}"
