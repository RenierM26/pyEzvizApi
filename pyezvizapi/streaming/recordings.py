"""Finite SD catalog discovery and resumable downloads over explicit routes.

Discovery uses the cloud v2 SD index, NOT subscription cloud storage. Catalogs
contain UTC intervals only; source URLs, keys and raw descriptors are not saved.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any
import zlib

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.cloud.playback_range import (
    native_playback_range,
    playback_integer,
    playback_range,
    playback_timezone,
    positive_timeout,
)


@dataclass(frozen=True, order=True)
class StoredRecording:
    """A UTC SD interval, not a promise that the camera can play it."""

    begin_time: str
    end_time: str

    def __post_init__(self) -> None:
        playback_range(self.begin_time, self.end_time)


@dataclass(frozen=True)
class RecordingCatalog:
    """A bounded, deduplicated snapshot of the cloud SD index."""

    serial: str
    channel: int
    timezone: str
    recordings: tuple[StoredRecording, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.serial, str) or not self.serial:
            raise PyEzvizError("Catalog requires a serial")
        playback_integer(self.channel, "catalog channel", minimum=0)
        playback_timezone(self.timezone)
        if not isinstance(self.recordings, tuple) or any(
            not isinstance(item, StoredRecording) for item in self.recordings
        ):
            raise PyEzvizError("Catalog recordings must be StoredRecording values")

    def to_dict(self) -> dict[str, Any]:
        return {"version": 1, "discovery": "cloud-sd-v2", **asdict(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RecordingCatalog:
        """Load only the versioned public catalog shape."""
        try:
            if value["version"] != 1 or value["discovery"] != "cloud-sd-v2":
                raise ValueError
            return cls(
                value["serial"],
                value["channel"],
                value["timezone"],
                tuple(StoredRecording(**item) for item in value["recordings"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PyEzvizError("Invalid recording catalog") from error


def _stamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def _record_time(value: Any, timezone: str) -> datetime:
    if not isinstance(value, str):
        raise PyEzvizError("SD catalog timestamp must be an ISO date/time string")
    try:
        instant = datetime.fromisoformat(value)
    except ValueError as error:
        raise PyEzvizError("Invalid SD catalog date/time") from error
    if instant.microsecond:
        raise PyEzvizError("SD catalog requires whole-second timestamps")
    if instant.tzinfo is None:
        zone = playback_timezone(timezone)
        instant = instant.replace(tzinfo=zone)
        if instant.replace(fold=0).utcoffset() != instant.replace(fold=1).utcoffset():
            raise PyEzvizError("Ambiguous SD catalog local time")
        if instant.astimezone(UTC).astimezone(zone).replace(tzinfo=None) != datetime.fromisoformat(
            value
        ):
            raise PyEzvizError("Nonexistent SD catalog local time")
    return instant.astimezone(UTC)


def _index_records(payload: Any) -> list[Any]:
    """Do not confuse a malformed/compressed index with an empty card."""
    if isinstance(payload, list):
        return payload
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
            return decoded
        except (ValueError, zlib.error, UnicodeError) as error:
            raise PyEzvizError("Invalid compressed SD catalog") from error
    if isinstance(payload, Mapping):
        for key in ("records", "record", "files", "fileList", "videos", "videoList", "data"):
            if key in payload:
                return _index_records(payload[key])
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
        records = _index_records(response)
        if len(records) >= page_size or response.get("isFinished") in (0, False):
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


def write_recording_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomically publish private catalog/manifest metadata."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temp = Path(stream.name)
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download_recordings(  # noqa: PLR0913
    client: Any,
    catalog: RecordingCatalog,
    output: str | Path,
    *,
    source: str,
    channel: int | None = None,
    host: str | None = None,
    password: str | bytes | None = None,
    username: str = "admin",
    media_key: str | bytes | None = None,
    decrypt: bool = True,
    max_bytes: int = 128 * 1024 * 1024,
    transfer_timeout: float = 60,
    max_clips: int = 10000,
) -> dict[str, Any]:
    """Sequential, no-fallback downloads with hash-verified resume receipts.

    Channels are deliberately route-specific (e.g. cloud 0 vs LAN 1). Existing
    files without matching receipts are never overwritten. One refused clip
    does not abort the remaining catalog. Process interrupts are not swallowed.
    One writer per output directory is required.
    """
    if source not in {"local-playback", "cloud-playback"}:
        raise PyEzvizError("Batch source must be local-playback or cloud-playback")
    playback_integer(max_bytes, "max_bytes")
    positive_timeout(transfer_timeout, "transfer_timeout")
    playback_integer(max_clips, "max_clips")
    if len(catalog.recordings) > max_clips:
        raise PyEzvizError("Catalog exceeds batch clip budget")
    if source == "local-playback" and (not host or not password):
        raise PyEzvizError("LAN batch requires explicit host and device password")
    selected_channel = (
        channel if channel is not None else (1 if source == "local-playback" else catalog.channel)
    )
    playback_integer(selected_channel, "channel", minimum=0)
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    # Bind receipts to route, selector clock and decryption profile, never keys.
    identity = {
        "serial": catalog.serial,
        "source": source,
        "channel": selected_channel,
        "timezone": catalog.timezone,
        "decrypt": decrypt if source == "cloud-playback" else False,
    }
    prefix = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
    manifest = root / f"{prefix}-manifest.json"
    previous = json.loads(manifest.read_text()) if manifest.exists() else {}
    if previous and previous.get("identity") != identity:
        raise PyEzvizError("Batch manifest identity mismatch")
    entries = previous.get("entries", {})
    report: dict[str, Any] = {
        "version": 1,
        "identity": identity,
        "entries": entries,
        "downloaded": 0,
        "skipped": 0,
        "failed": 0,
    }
    for item in catalog.recordings:
        name = f"{prefix}-{item.begin_time}-{item.end_time}.ps"
        path = root / name
        receipt = entries.get(name, {})
        if path.exists() or path.is_symlink():
            if (
                receipt.get("status") == "complete"
                and path.is_file()
                and not path.is_symlink()
                and _digest(path) == receipt.get("sha256")
            ):
                report["skipped"] += 1
                continue
            entries[name] = {"status": "conflict"}
            report["failed"] += 1
            write_recording_json(manifest, report)
            continue
        kwargs: dict[str, Any] = {
            "source": source,
            "output_format": "mpegps",
            "channel": selected_channel,
            "duration_seconds": None,
        }
        route = "local" if source == "local-playback" else "cloud"
        kwargs.update(
            {
                f"{route}_playback_begin_time": item.begin_time,
                f"{route}_playback_end_time": item.end_time,
                f"{route}_playback_timezone": catalog.timezone,
                f"{route}_playback_max_bytes": max_bytes,
                f"{route}_playback_transfer_timeout": transfer_timeout,
            }
        )
        if route == "local":
            kwargs.update(
                host=host, hcnetsdk_command_password=password, local_playback_username=username
            )
        else:
            kwargs.update(
                decrypt_video=decrypt, cloud_playback_decrypt_audio=decrypt, media_key=media_key
            )
        try:
            client.save_clip(catalog.serial, path, **kwargs)
            entries[name] = {
                "status": "complete",
                "sha256": _digest(path),
                "bytes": path.stat().st_size,
            }
            report["downloaded"] += 1
        except (PyEzvizError, OSError) as error:
            # Exception messages can contain private descriptors; retain only category/code.
            entries[name] = {
                "status": "failed",
                "error": type(error).__name__,
                "result_code": getattr(error, "result_code", None),
            }
            report["failed"] += 1
        write_recording_json(manifest, report)
    write_recording_json(manifest, report)
    return report
