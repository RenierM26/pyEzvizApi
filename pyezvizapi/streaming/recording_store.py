"""Private atomic catalog writes and one-writer batch receipt persistence."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from pyezvizapi.exceptions import PyEzvizError
from pyezvizapi.streaming.recording_models import StoredRecording


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


class RecordingBatchStore:
    """Own deterministic filenames, existing-file checks and atomic receipts."""

    def __init__(self, root: Path, identity: dict[str, Any]) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.prefix = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
        self.manifest = root / f"{self.prefix}-manifest.json"
        previous = json.loads(self.manifest.read_text()) if self.manifest.exists() else {}
        if previous and previous.get("identity") != identity:
            raise PyEzvizError("Batch manifest identity mismatch")
        self.report: dict[str, Any] = {
            "version": 1,
            "identity": identity,
            "entries": previous.get("entries", {}),
            "downloaded": 0,
            "skipped": 0,
            "failed": 0,
        }

    def path_for(self, recording: StoredRecording) -> Path:
        return self.root / f"{self.prefix}-{recording.begin_time}-{recording.end_time}.ps"

    def reuse_or_conflict(self, path: Path) -> bool:
        """Return True only when the caller must not acquire this path."""
        if not path.exists() and not path.is_symlink():
            return False
        receipt = self.report["entries"].get(path.name, {})
        if (
            receipt.get("status") == "complete"
            and path.is_file()
            and not path.is_symlink()
            and _digest(path) == receipt.get("sha256")
        ):
            self.report["skipped"] += 1
        else:
            self.report["entries"][path.name] = {"status": "conflict"}
            self.report["failed"] += 1
            self.publish()
        return True

    def complete(self, path: Path) -> None:
        self.report["entries"][path.name] = {
            "status": "complete",
            "sha256": _digest(path),
            "bytes": path.stat().st_size,
        }
        self.report["downloaded"] += 1

    def failed(self, path: Path, error: Exception) -> None:
        # Raw exception messages can contain private descriptors or credentials.
        self.report["entries"][path.name] = {
            "status": "failed",
            "error": type(error).__name__,
            "result_code": getattr(error, "result_code", None),
        }
        self.report["failed"] += 1

    def publish(self) -> None:
        write_recording_json(self.manifest, self.report)
