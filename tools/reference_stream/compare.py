"""Compare two bounded software benchmark reports without claiming real-time playback."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

FIELDS = (
    "video_before_eof",
    "audio_before_eof",
    "host_video_span_seconds",
    "collector_payload_bytes",
    "collector_transport_bytes",
    "host_audio_peak_pending_including_active",
    "host_audio_rejected",
    "host_audio_retained",
    "host_audio_partial_bytes",
    "unforwarded_vqe_outputs",
)


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    settings = (
        "profile",
        "dummy_host",
        "sink_deadline_seconds",
        "requested_observation_seconds",
        "verified_samples",
        "source_video_geometry",
        "source_video_media_ms",
    )
    mismatches = [key for key in settings if before.get(key) != after.get(key)]
    missing = [key for key in settings if before.get(key) is None or after.get(key) is None]
    values: dict[str, Any] = {}
    for key in FIELDS:
        a, b = before.get(key), after.get(key)
        values[key] = dict(
            before=a,
            after=b,
            delta=b - a if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None,
        )
    for label, report in (("before", before), ("after", after)):
        values["source_pipe_stages_" + label] = report.get("source_pipe_stages")
        delays = report.get("host_audio_received_to_write_complete_ms", [])
        values["host_audio_residence_" + label] = dict(
            count=len(delays), max_ms=max(delays, default=None)
        )
    stages = {}
    for label, report in (("before", before), ("after", after)):
        stages[label] = {
            owner: profile.get("stages", {})
            for owner, profile in report.get("stage_profile", {}).items()
            if profile
        }
    return dict(
        settings_mismatches=mismatches,
        settings_missing=missing,
        outcomes={
            label: {key: report.get(key) for key in ("status", "error", "stop_reason", "transport")}
            for label, report in (("before", before), ("after", after))
        },
        measurements=values,
        stages=stages,
        note="different live captures, not identical media or a controlled causal latency measurement",
        sustained_realtime_verified=False,
        physical_av_measured=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()
    reports = []
    for path in (args.before, args.after):
        if path.stat().st_size > 32 * 1024 * 1024:
            parser.error("benchmark report exceeds 32 MiB")
        reports.append(json.loads(path.read_text()))
    print(json.dumps(compare(*reports), indent=2))


if __name__ == "__main__":
    main()
