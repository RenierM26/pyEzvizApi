"""Normalize evidenced intercom events without translated text or identity guesses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from typing import Any, Literal

from pyezvizapi.exceptions import PyEzvizError

_EVENT_TYPES = {2701: "ring", 10242: "lock_unlocked"}
# Only customerType values evidenced in retained public HP7 alarm records.
_METHODS = {"Card": "rfid", "Monitor": "monitor"}


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 512 else None


def intercom_event_type(code: Any) -> str | None:
    """Recognize only verified codes; unknown alarm codes retain existing semantics."""
    value = _integer(code)
    return _EVENT_TYPES.get(value) if value is not None else None


def _time(value: Any, zone: tzinfo | None) -> datetime | None:
    numeric = _integer(value)
    try:
        if numeric is not None and numeric > 0:
            return datetime.fromtimestamp(numeric / 1000 if numeric >= 10**12 else numeric, UTC)
        if isinstance(value, str):
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is None:
                if zone is None:
                    return None
                stamp = stamp.replace(tzinfo=zone)
            return stamp.astimezone(UTC)
    except (ValueError, OverflowError, OSError):
        # Invalid/out-of-range vendor timestamps remain unknown, never now/UTC.
        return None
    return None


@dataclass(frozen=True)
class IntercomEvent:
    """Small credential-free event view, not a physical lock/contact state."""

    serial: str
    event_id: str
    event_type: Literal["ring", "lock_unlocked"]
    code: int
    occurred_at: datetime | None
    channel: int | None = None
    method: str | None = None


def normalize_intercom_event(
    payload: Mapping[str, Any], *, zone: tzinfo | None = None
) -> IntercomEvent | None:
    """Accept unified messages, legacy alarms or already-decoded MQTT pushes.

    Prefer unified-message `time` over ext.alarmStartTime: real HP7 reports
    contain conflicting values. Naive local strings need an explicit timezone;
    unknown timestamps remain unknown. IDs are required for reliable deduplication.
    """
    ext = payload.get("ext")
    ext = ext if isinstance(ext, Mapping) else {}
    if "channel_type" in ext and _integer(ext["channel_type"]) != 1:
        return None
    raw_code = ext.get("alert_type_code", ext.get("alarmType", payload.get("alarmType")))
    code = _integer(raw_code)
    # MessageItem.convToAlarmItem explicitly promotes only zero/missing
    # alarmType + subType 2701. An unknown nonzero type must not become a ring.
    if (raw_code is None or code == 0) and _integer(
        payload.get("subType", ext.get("subType"))
    ) == 2701:
        code = 2701
    kind = intercom_event_type(code)
    serial = _text(payload.get("deviceSerial") or ext.get("device_serial"))
    event_id = _text(payload.get("msgId") or payload.get("alarmId") or ext.get("msgId"))
    if code is None or kind is None or serial is None or event_id is None:
        return None
    value = payload.get("time")
    if value is None:
        value = payload.get("alarmStartTime")
    if value is None:
        value = ext.get("time", ext.get("alarmStartTime"))
    channel = _integer(payload.get("channel", payload.get("channelNo", ext.get("channel_no"))))
    if channel is not None and channel < 0:
        channel = None
    method = ext.get("customerType", payload.get("customerType"))
    return IntercomEvent(
        serial,
        event_id,
        "ring" if kind == "ring" else "lock_unlocked",
        code,
        _time(value, zone),
        channel,
        _METHODS.get(method) if isinstance(method, str) and kind == "lock_unlocked" else None,
    )


def get_intercom_events(client: Any, serials: tuple[str, ...]) -> tuple[IntercomEvent, ...]:
    """Read one bounded recent-history window, without a persistent consumer cursor.

    At most 50 recent messages are returned. Consumers own replay/freshness policy;
    this is not lossless backfill after an outage or a local-only event transport.
    """
    if not serials:
        return ()
    response = client.get_device_messages_list(
        serials=",".join(serials), s_type="92,2701", limit=50, date="", end_time=""
    )
    messages = response.get("message", response.get("messages"))
    if not isinstance(messages, list):
        raise PyEzvizError("Intercom history response has no message list")
    events = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        event = normalize_intercom_event(message)
        if event is not None and event.serial in serials:
            events.append(event)
    return tuple(events)
