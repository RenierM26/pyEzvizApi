"""Bounded cloud SD index discovery, separate from catalog and download ownership."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime, timedelta
import json
from typing import Any
import zlib

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.ranges import (
    native_playback_range,
    playback_integer,
    playback_range,
    record_time as _record_time,
    utc_stamp as _stamp,
)
from pyezvizapi.streaming.recording_models import RecordingCatalog, StoredRecording


def _index_records(payload: Any) -> tuple[list[Any], bool]:
    """Return records and inherited incompleteness without hiding nested flags."""
    if isinstance(payload, list):
        return payload, False
    if isinstance(payload, str):
        try:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(base64.b64decode(payload, validate=True), 8 * 1024 * 1024)
            # App index payloads can zero-pad the compressed buffer (31 bytes observed).
            if not decoder.eof or decoder.unused_data.strip(b"\x00"):
                raise ValueError
            decoded = json.loads(raw)
            if not isinstance(decoded, list):
                raise ValueError
            return decoded, False
        except (ValueError, zlib.error, UnicodeError) as error:
            raise PyEzvizError("Invalid compressed SD catalog") from error
    if isinstance(payload, Mapping):
        for key in ("records", "record", "files", "fileList", "videos", "videoList", "data"):
            if key in payload:
                records, incomplete = _index_records(payload[key])
                return records, incomplete or payload.get("isFinished") in (0, False)
    raise PyEzvizError("SD index response has no supported record list")


def query_recordings(
    client: Any,
    serial: str,
    begin_time: str,
    end_time: str,
    *,
    channel: int = 0,
    timezone: str = "UTC",
    page_size: int = 100,
    max_queries: int = 256,
    max_records: int = 10000,
) -> RecordingCatalog:
    """Search an explicit UTC range, subdividing saturated index responses.

    No cursor is guessed. A full one-second window or an exhausted budget
    fails rather than returning a misleadingly complete catalog. The endpoint
    may still omit footage; this is index completeness, not SD integrity proof.
    Multi-day ranges are accepted and queried in at most one-day windows.
    """
    for name, value in (
        ("page_size", page_size),
        ("max_queries", max_queries),
        ("max_records", max_records),
    ):
        playback_integer(value, name)
    RecordingCatalog(serial, channel, timezone, ())
    # Validate public format without imposing the per-download one-day limit.
    begin, _ = playback_range(
        begin_time, _stamp(_record_time(begin_time, "UTC") + timedelta(seconds=1))
    )
    end, _ = playback_range(end_time, _stamp(_record_time(end_time, "UTC") + timedelta(seconds=1)))
    if end <= begin:
        raise PyEzvizError("Catalog end must follow begin")
    pending = [(begin, end)]
    found: set[StoredRecording] = set()
    queries = 0
    while pending:
        left, right = pending.pop()
        seconds = int((right - left).total_seconds())
        if seconds > 86400:
            middle = left + timedelta(days=1)
            pending.extend(((middle, right), (left, middle)))
            continue
        if queries >= max_queries:
            raise PyEzvizError("SD catalog query budget exhausted; narrow the range")
        native_left, native_right = native_playback_range(_stamp(left), _stamp(right), timezone)
        response = client.search_records_v2(
            serial,
            channel,
            datetime.strptime(native_left, "%Y%m%dT%H%M%SZ").isoformat(),
            datetime.strptime(native_right, "%Y%m%dT%H%M%SZ").isoformat(),
            size=page_size,
            sort_by=0,
            max_retries=0,
        )
        queries += 1
        records, incomplete = _index_records(response)
        if len(records) >= page_size or incomplete:
            if seconds <= 1:
                raise PyEzvizError("SD catalog saturated at one second; completeness unknown")
            middle = left + timedelta(seconds=seconds // 2)
            pending.extend(((middle, right), (left, middle)))
            continue
        for record in records:
            if not isinstance(record, Mapping):
                raise PyEzvizError("Invalid SD catalog record")
            start = _record_time(
                record.get("B", record.get("begin", record.get("startTime"))), timezone
            )
            stop = _record_time(
                record.get("E", record.get("end", record.get("stopTime"))), timezone
            )
            if stop <= start:
                raise PyEzvizError("Invalid SD catalog interval")
            start, stop = max(start, begin), min(stop, end)
            if start < stop:
                found.add(StoredRecording(_stamp(start), _stamp(stop)))
            if len(found) > max_records:
                raise PyEzvizError("SD catalog record budget exhausted")
    return RecordingCatalog(serial, channel, timezone, tuple(sorted(found)))
