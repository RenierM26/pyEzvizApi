"""Compatibility entrypoints for SD catalogs and resumable batch downloads.

Models, discovery, persistence and orchestration have independent owners. Public
call signatures and versioned catalog/manifest formats are retained.
"""

# ruff: noqa: SLF001 -- retain pre-split private imports at the compatibility boundary
from pyezvizapi.streaming import (
    ranges as _ranges,
    recording_batch as _batch,
    recording_store as _store,
)
from pyezvizapi.streaming.cloud import recordings as _cloud
from pyezvizapi.streaming.cloud.recordings import query_recordings
from pyezvizapi.streaming.recording_batch import download_recordings
from pyezvizapi.streaming.recording_models import RecordingCatalog, StoredRecording
from pyezvizapi.streaming.recording_store import write_recording_json

_record_time = _ranges.record_time
_stamp = _ranges.utc_stamp
_index_records = _cloud._index_records
_batch_channel = _batch._batch_channel
_digest = _store._digest

__all__ = [
    "RecordingCatalog",
    "StoredRecording",
    "download_recordings",
    "query_recordings",
    "write_recording_json",
]
