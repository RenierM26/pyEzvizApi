"""Compatibility and backend independence across the recording owner split."""

import pickle
import subprocess
import sys

from pyezvizapi.streaming import recording_batch, recording_models, recording_store, recordings
from pyezvizapi.streaming.cloud import playback_range, recordings as cloud_recordings
from pyezvizapi.streaming.ranges import native_playback_range


def test_legacy_entrypoints_keep_identity():
    assert recordings.StoredRecording is recording_models.StoredRecording
    assert recordings.RecordingCatalog is recording_models.RecordingCatalog
    assert recordings.query_recordings is cloud_recordings.query_recordings
    assert recordings.download_recordings is recording_batch.download_recordings
    assert recordings.write_recording_json is recording_store.write_recording_json
    assert playback_range.native_playback_range is native_playback_range


def test_pre_split_catalog_pickle_remains_readable():
    value = recording_models.RecordingCatalog(
        "SYNTHETIC",
        0,
        "UTC",
        (recording_models.StoredRecording("20261108T060000Z", "20261108T060020Z"),),
    )
    old_payload = pickle.dumps(value, protocol=0).replace(
        b"pyezvizapi.streaming.recording_models", b"pyezvizapi.streaming.recordings"
    )
    assert pickle.loads(old_payload) == value


def test_models_import_without_discovery_or_download_backends():
    script = """
import importlib.abc, sys
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"pyezvizapi.streaming.cloud.recordings", "pyezvizapi.streaming.recording_batch", "pyezvizapi.streaming.local.recordings"}:
            raise AssertionError("Model import loaded backend: " + fullname)
sys.meta_path.insert(0, Block())
from pyezvizapi.streaming.recording_models import RecordingCatalog
assert RecordingCatalog("SYNTHETIC", 1, "UTC", ()).recordings == ()
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
