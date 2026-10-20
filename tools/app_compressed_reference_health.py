"""Summarize retained native metadata; no camera access, media decode or output."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import runpy
from typing import Any

H = runpy.run_path(str(Path(__file__).parent / 'reference_stream/health.py'))


def analyze(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with path.open('rb') as source:
        for _ in range(20_001):
            line = source.readline(8193)
            if not line:
                break
            if len(rows) >= 20_000 or len(line) > 8192:
                raise ValueError('native metadata row/line limit')
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('native metadata row must be an object')
            rows.append(row)
    return H['summarize'](rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', type=Path, help='private capture events.jsonl (metadata only)')
    args = parser.parse_args()
    print(json.dumps(analyze(args.events), indent=2))


if __name__ == '__main__':
    main()
