"""Sequential no-fallback recording acquisition; persistence has its own owner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.ranges import playback_integer, positive_timeout
from pyezvizapi.streaming.recording_models import RecordingCatalog
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
    selected_channel = _batch_channel(catalog, source, channel)
    store = RecordingBatchStore(
        Path(output),
        {
            "serial": catalog.serial,
            "source": source,
            "channel": selected_channel,
            "timezone": catalog.timezone,
            "decrypt": decrypt if source == "cloud-playback" else False,
        },
    )
    for item in catalog.recordings:
        path = store.path_for(item)
        if store.reuse_or_conflict(path):
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
            store.complete(path)
        except (PyEzvizError, OSError) as error:
            store.failed(path, error)
        store.publish()
    store.publish()
    return store.report
