"""Explicit fleet inventory CLI; never starts a live preview or changes settings."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .hcnetsdk import HcNetSdkLanEndpoint, HcNetSdkLoginCandidate
from .stream_capabilities import (
    MAX_FLEET_SAMPLE_BYTES,
    MAX_FLEET_TARGETS,
    StreamCapabilityTarget,
    StreamSampleEvidence,
    probe_stream_capabilities,
)
from .stream_sample import MAX_SAMPLE_BYTES


def load_inventory(path: Path) -> tuple[list[StreamCapabilityTarget], list[StreamSampleEvidence]]:
    """Resolve explicit targets, environment secrets and optional saved samples.

    All preflight validation completes before a caller opens any camera. Samples
    are relative to the inventory, not the shell working directory. No secret
    values, exception messages or file contents are printed by the CLI.
    """
    with path.open("rb") as inventory_file:
        raw = inventory_file.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Inventory exceeds 1 MiB")
    inventory = json.loads(raw)
    if not isinstance(inventory, list) or not 0 < len(inventory) <= MAX_FLEET_TARGETS:
        raise ValueError("Supply a list of 1 to 64 camera/channel targets")
    targets = []
    samples = []
    sample_bytes = 0
    for item in inventory:
        login = item["login"]
        if not isinstance(login["https"], bool):
            raise ValueError("HTTPS assertion must be a boolean")
        password = os.environ[login["password_env"]]
        if not password:
            raise ValueError("Supplied credential is empty")
        targets.append(
            StreamCapabilityTarget(
                alias=item["alias"],
                channel=item["channel"],
                endpoint=HcNetSdkLanEndpoint(serial=item["serial"], host=item["host"]),
                login=HcNetSdkLoginCandidate(
                    username=login["username"],
                    password=password,
                    port=login["port"],
                    api=login["api"],
                    https=login["https"],
                ),
            )
        )
        entries = item.get("samples", [])
        if not isinstance(entries, list) or len(entries) > 3:
            raise ValueError("Supply at most one saved sample per main/sub/unknown profile")
        for sample in entries:
            with (path.parent / sample["path"]).open("rb") as media_file:
                data = media_file.read(MAX_SAMPLE_BYTES + 1)
            sample_bytes += len(data)
            if sample_bytes > MAX_FLEET_SAMPLE_BYTES:
                raise ValueError("Saved fleet samples exceed 64 MiB per batch")
            samples.append(
                StreamSampleEvidence(item["alias"], item["channel"], sample["profile"], data)
            )
    return targets, samples


def main(argv: list[str] | None = None) -> int:
    """Print sanitized JSON to stdout; credentials must be in the environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inventory", type=Path, help="Private JSON inventory; see docs/ha-streaming-plan.md"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-camera and per-process deadline, at most 30s",
    )
    parser.add_argument(
        "--decode-samples", action="store_true", help="Also decode supplied saved samples locally"
    )
    args = parser.parse_args(argv)
    try:
        targets, samples = load_inventory(args.inventory)
        report = probe_stream_capabilities(
            targets, timeout=args.timeout, samples=samples, decode_samples=args.decode_samples
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as err:
        print(
            json.dumps({"status": "invalid_inventory", "error_type": type(err).__name__}),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2))
    return 0 if all(entry["metadata_status"] != "unknown" for entry in report["targets"]) else 1


if __name__ == "__main__":
    sys.exit(main())
