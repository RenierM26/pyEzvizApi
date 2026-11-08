"""Bounded encrypted media bodies, not credentials or decoded media acceptance.

Run with --verify DIRECTORY to check a finalized local evidence set offline.
Hashes detect corruption; they are not an authenticity signature.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
from typing import Any

PROFILES = runpy.run_path(str(Path(__file__).with_name('local_av_lan_profiles.py')))
MAX_PACKETS = 15000
MAX_BYTES = 32 * 1024 * 1024
MAX_INDEX = 3 * 1024 * 1024
PROFILE = "encrypted-lan-packets-v1"


def evidence_limits(name: str) -> dict[str, Any]:
    result = PROFILES['get'](name)['evidence']
    if name == PROFILES['DEFAULT']:
        result.update(max_packets=MAX_PACKETS, max_bytes=MAX_BYTES, max_index=MAX_INDEX)
    return result


def directory(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


@contextmanager
def regular(root: int, name: str, limit: int) -> Iterator[Any]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= limit:
            raise ValueError("invalid evidence file")
        yield source


def write_json(root: int, name: str, value: Any, limit: int) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(raw) > limit:
        raise ValueError("evidence JSON bound")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return hashlib.sha256(raw).hexdigest()


class PacketEvidence:
    """Source-thread writer; finalize only after that thread has joined.

    Only the media packet body is retained, never transport/login metadata.
    A missing manifest means incomplete evidence, including an unjoined worker.
    """

    def __init__(self, path: Path, *, capture_profile: str = 'prefix-30s'):
        PROFILES['get'](capture_profile)
        self.capture_profile = capture_profile
        self.root = directory(path)
        try:
            fd = os.open(
                "packet-bodies.bin",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self.root,
            )
            self.output = os.fdopen(fd, "wb")
        except BaseException:
            os.close(self.root)
            raise
        self.rows: list[dict[str, Any]] = []
        self.extent = 0
        self.digest = hashlib.sha256()
        self.failed = False

    @property
    def limits(self) -> dict[str, Any]:
        return evidence_limits(self.capture_profile)

    def retain(self, iterator: Any) -> Any:
        try:
            for packet in iterator:
                body = packet.body
                if (
                    type(body) is not bytes
                    or not body
                    or len(self.rows) >= self.limits['max_packets']
                    or self.extent + len(body) > self.limits['max_bytes']
                ):
                    self.failed = True
                    raise ValueError("encrypted packet evidence bound")
                try:
                    self.output.write(body)
                except BaseException:
                    self.failed = True
                    raise
                self.rows.append(
                    dict(
                        offset=self.extent, bytes=len(body), sha256=hashlib.sha256(body).hexdigest()
                    )
                )
                self.digest.update(body)
                self.extent += len(body)
                yield packet
        finally:
            iterator.close()

    def finish(self, binding: dict[str, str]) -> dict[str, Any]:
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
            if self.failed:
                raise ValueError("packet writer did not finish cleanly")
            index_hash = write_json(self.root, "packet-index.json", self.rows, self.limits['max_index'])
            summary = dict(
                profile=self.limits['profile'],
                packets=len(self.rows),
                bytes=self.extent,
                sha256=self.digest.hexdigest(),
                index_sha256=index_hash,
                binding=binding,
            )
            # Publish this last, only after closed bodies and a durable index.
            write_json(self.root, "manifest.json", summary, 4096)
            os.fsync(self.root)
            return summary
        finally:
            self.output.close()
            os.close(self.root)


def verify(path: Path, *, capture_profile: str = 'prefix-30s') -> dict[str, Any]:
    """Read fixed regular files under a pinned directory, with bounded work."""
    limits = evidence_limits(capture_profile)
    root = directory(path)
    try:
        with regular(root, "manifest.json", 4096) as source:
            manifest = json.loads(source.read(4097))
        with regular(root, "packet-index.json", limits['max_index']) as source:
            raw = source.read(limits['max_index'] + 1)
        rows = json.loads(raw)
        if (
            type(manifest) is not dict
            or set(manifest) != {"profile", "packets", "bytes", "sha256", "index_sha256", "binding"}
            or manifest.get("profile") != limits['profile']
            or type(rows) is not list
            or len(rows) > limits['max_packets']
            or hashlib.sha256(raw).hexdigest() != manifest.get("index_sha256")
        ):
            raise ValueError("invalid packet evidence index")
        binding = manifest.get("binding")
        if (
            type(binding) is not dict
            or set(binding) != {"package_sha256", "config_sha256"}
            or any(
                type(v) is not str or len(v) != 64 or any(c not in "0123456789abcdef" for c in v)
                for v in binding.values()
            )
        ):
            raise ValueError("invalid packet evidence binding")
        extent, digest = 0, hashlib.sha256()
        with regular(root, "packet-bodies.bin", limits['max_bytes']) as source:
            for row in rows:
                if (
                    type(row) is not dict
                    or set(row) != {"offset", "bytes", "sha256"}
                    or type(row["offset"]) is not int
                    or row["offset"] != extent
                    or type(row["bytes"]) is not int
                    or not 0 < row["bytes"] <= limits['max_bytes'] - extent
                ):
                    raise ValueError("invalid packet evidence extent")
                body = source.read(row["bytes"])
                if len(body) != row["bytes"] or hashlib.sha256(body).hexdigest() != row["sha256"]:
                    raise ValueError("packet evidence digest mismatch")
                digest.update(body)
                extent += len(body)
            if source.read(1):
                raise ValueError("trailing packet evidence bytes")
        if (
            type(manifest.get("packets")) is not int
            or manifest["packets"] != len(rows)
            or type(manifest.get("bytes")) is not int
            or manifest["bytes"] != extent
            or manifest.get("sha256") != digest.hexdigest()
        ):
            raise ValueError("packet evidence summary mismatch")
        return manifest
    finally:
        os.close(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path, required=True)
    parser.add_argument('--capture-profile', choices=PROFILES['NAMES'], default=PROFILES['DEFAULT'])
    args = parser.parse_args()
    try:
        result = verify(args.verify, capture_profile=args.capture_profile)
    except Exception:
        print(json.dumps(dict(status="invalid-or-incomplete")))
        return 2
    print(json.dumps(dict(status="integrity-verified", **result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
