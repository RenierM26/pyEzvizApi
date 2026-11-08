"""Sequential no-fallback recording acquisition; persistence has its own owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.ranges import playback_integer
from pyezvizapi.streaming.recording_models import RecordingCatalog
from pyezvizapi.streaming.recording_routes import (
    CloudRecordingRoute,
    LanRecordingRoute,
    RecordingBatchLimits,
    RecordingRoute,
)
from pyezvizapi.streaming.recording_store import RecordingBatchStore


def _batch_channel(catalog: RecordingCatalog, source: str, channel: int | None) -> int:
    if catalog.discovery == "lan-hcnetsdk" and source == "cloud-playback" and channel is None:
        raise PyEzvizError("LAN catalogs require an explicit cloud channel")
    selected_channel = (
        channel
        if channel is not None
        else (
            1
            if source == "local-playback" and catalog.discovery == "cloud-sd-v2"
            else catalog.channel
        )
    )
    playback_integer(selected_channel, "channel", minimum=0)
    return selected_channel


def _select_route(
    catalog: RecordingCatalog,
    source: str,
    channel: int | None,
    host: str | None,
    password: str | bytes | None,
    username: str,
    media_key: str | bytes | None,
    decrypt: bool,
) -> RecordingRoute:
    if source == "local-playback":
        if not host or not password:
            raise PyEzvizError("LAN batch requires explicit host and device password")
        return LanRecordingRoute(_batch_channel(catalog, source, channel), host, password, username)
    return CloudRecordingRoute(_batch_channel(catalog, source, channel), media_key, decrypt)


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
    limits = RecordingBatchLimits(max_bytes, transfer_timeout, max_clips)
    if len(catalog.recordings) > max_clips:
        raise PyEzvizError("Catalog exceeds batch clip budget")
    route = _select_route(catalog, source, channel, host, password, username, media_key, decrypt)
    store = RecordingBatchStore(
        Path(output),
        {
            "serial": catalog.serial,
            "source": route.source,
            "channel": route.channel,
            "timezone": catalog.timezone,
            "decrypt": route.decrypt,
        },
    )
    for item in catalog.recordings:
        path = store.path_for(item)
        if store.reuse_or_conflict(path):
            continue
        try:
            route.save(None if client is None else client.save_clip, catalog, item, path, limits)
            store.complete(path)
        except (PyEzvizError, OSError) as error:
            store.failed(path, error)
        store.publish()
    store.publish()
    return store.report
