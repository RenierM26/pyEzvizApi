"""Pure EZVIZ notification decoding, independent of MQTT lifecycle and credentials.

Android 7.4.1 AnalyzePushMessageManager dispatches JSON ext, CSV alarm type 1,
and CSV call type 14 separately. Historical alarm names remain compatibility
aliases, not evidence that every notification uses the same positional schema.
"""

from __future__ import annotations

from contextlib import suppress
import json
from typing import Any, Final

from pyezvizapi.exceptions import PyEzvizError

# Field names in the comma-separated ``ext`` payload from EZVIZ.
EXT_FIELD_NAMES: Final[tuple[str, ...]] = (
    "channel_type",
    "time",
    "device_serial",
    "channel_no",
    "alert_type_code",
    "default_pic_url",
    "media_url_alt1",
    "media_url_alt2",
    "resource_type",
    "status_flag",
    "file_id",
    "is_encrypted",
    "picChecksum",
    "is_dev_video",
    "metadata",
    "msgId",
    "image",
    "device_name",
    "reserved",
    "sequence_number",
)

# Fields that should be converted to ``int`` if present.
EXT_INT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "channel_type",
        "channel_no",
        "alert_type_code",
        "resource_type",
        "status_flag",
        "is_encrypted",
        "is_dev_video",
        "sequence_number",
    }
)


_CALL_FIELDS: Final[tuple[str, ...]] = (
    "channel_type",
    "time",
    "device_serial",
    "channel_no",
    "calling_type",
    "calling_id",
    "calling_status",
    "image",
    "is_encrypted",
    "picChecksum",
    "analysis_type",
    "analysis_result",
    "reserved",
    "alarm_name",
    "reserved_alt",
    "custom_info",
)
_CALL_INT_FIELDS = frozenset(
    {
        "channel_type",
        "channel_no",
        "calling_type",
        "calling_status",
        "is_encrypted",
        "analysis_type",
    }
)


def _fields(parts: list[str], names: tuple[str, ...], integers: frozenset[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for index, name in enumerate(names):
        value: Any = parts[index] if index < len(parts) else None
        if value is not None and name in integers:
            with suppress(ValueError):
                value = int(value)
        result[name] = value
    return result


def _decode_ext(value: str) -> dict[str, Any]:
    if value.lstrip().startswith("{"):
        # The app also dispatches JSON control/event ext objects; never split
        # them into CSV alarm slots or infer an alarm from an x-type/title.
        return json.loads(value)
    parts = value.split(",")
    if parts[0] == "1":
        result = _fields(parts, EXT_FIELD_NAMES, EXT_INT_FIELDS)
        # App AlarmLogInfo.Z is customerType (slot 8), BaseMessageInfo.y is
        # subType (slot 19). Keep the old resource_type/sequence_number aliases.
        if len(parts) > 8:
            result["customerType"] = parts[8]
        if len(parts) > 19:
            result["subType"] = result["sequence_number"]
        return result
    if parts[0] == "14":
        result = _fields(parts, _CALL_FIELDS, _CALL_INT_FIELDS)
        if isinstance(result["time"], str):
            result["time"] = result["time"].replace("+", " ")
        # calling_id is NOT an alarm msgId; calling_type is NOT an alarmType.
        return result
    return {"channel_type": parts[0], "raw_fields": parts[1:]}


def decode_notification(payload: bytes) -> dict[str, Any]:
    """Decode one JSON notification; malformed input never controls a worker.

    Both a mapping ext and a JSON-encoded ext object are retained as objects.
    Unknown CSV families stay opaque rather than acquiring camera alarm fields.
    """
    try:
        data = json.loads(payload.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Notification must be an object")
        if isinstance(data.get("ext"), str):
            data["ext"] = _decode_ext(data["ext"])
    except (UnicodeError, ValueError) as error:
        raise PyEzvizError("Unable to decode MQTT message") from error
    return data
