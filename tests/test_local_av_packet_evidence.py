"""Synthetic encrypted-body retention, corruption and filesystem boundaries."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

TOOL = Path(__file__).parents[1] / "tools/local_av_packet_evidence.py"
M = runpy.run_path(str(TOOL))
G = M["verify"].__globals__
BINDING = dict(package_sha256="a" * 64, config_sha256="b" * 64)


def packets(bodies):
    for body in bodies:
        yield SimpleNamespace(body=body)


def saved(tmp_path, bodies=(b"one", b"two")):
    root = tmp_path / "evidence"
    root.mkdir(mode=0o700)
    writer = M["PacketEvidence"](root)
    assert [p.body for p in writer.retain(packets(bodies))] == list(bodies)
    summary = writer.finish(BINDING)
    return root, summary


def rewrite(root, rows=None, **changes):
    manifest = json.loads((root / "manifest.json").read_text())
    if rows is not None:
        raw = json.dumps(rows).encode()
        (root / "packet-index.json").write_bytes(raw)
        manifest["index_sha256"] = hashlib.sha256(raw).hexdigest()
    manifest.update(changes)
    (root / "manifest.json").write_text(json.dumps(manifest))


def test_roundtrip_retains_exact_bodies_and_only_fixed_metadata(tmp_path):
    root, summary = saved(tmp_path)
    assert M["verify"](root) == summary
    assert summary["packets"] == 2 and summary["bytes"] == 6
    assert summary["sha256"] == hashlib.sha256(b"onetwo").hexdigest()
    expected = b"onetwo"
    assert (root / "packet-bodies.bin").read_bytes() == expected
    assert {p.name for p in root.iterdir()} == {
        "packet-bodies.bin",
        "packet-index.json",
        "manifest.json",
    }
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir())


def test_failed_source_can_leave_stable_diagnostic_prefix_without_claiming_playback(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    writer = M["PacketEvidence"](root)

    def source():
        yield SimpleNamespace(body=b"prefix")
        raise TimeoutError("source failure")

    with pytest.raises(TimeoutError):
        list(writer.retain(source()))
    summary = writer.finish(BINDING)
    assert M["verify"](root) == summary and summary["packets"] == 1
    assert "status" not in summary


def test_closed_consumer_leaves_stable_prefix_and_closes_source(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    writer = M["PacketEvidence"](root)
    closed = []

    def source():
        try:
            yield SimpleNamespace(body=b"prefix")
            yield SimpleNamespace(body=b"unread")
        finally:
            closed.append(True)

    iterator = writer.retain(source())
    next(iterator)
    iterator.close()
    summary = writer.finish(BINDING)
    assert closed and M["verify"](root) == summary and summary["bytes"] == 6


@pytest.mark.parametrize("case", ["packets", "bytes", "empty", "mutable", "write"])
def test_writer_failure_never_publishes_a_complete_manifest(tmp_path, monkeypatch, case):
    root = tmp_path / "evidence"
    root.mkdir()
    writer = M["PacketEvidence"](root)
    bodies: list[Any] = [b"a", b"b"]
    if case == "packets":
        monkeypatch.setitem(G, "MAX_PACKETS", 1)
    elif case == "bytes":
        monkeypatch.setitem(G, "MAX_BYTES", 1)
    elif case == "empty":
        bodies = [b""]
    elif case == "mutable":
        bodies = [bytearray(b"a")]
    else:
        writer.output.close()
    with pytest.raises((ValueError, OSError)):
        list(writer.retain(packets(bodies)))
    with pytest.raises((ValueError, OSError)):
        writer.finish(BINDING)
    assert not (root / "manifest.json").exists()
    with pytest.raises(OSError):
        M["verify"](root)


@pytest.mark.parametrize(
    "case",
    [
        "body",
        "truncated",
        "trailing",
        "index-hash",
        "offset",
        "bool-offset",
        "bool-size",
        "zero-size",
        "oversize",
        "row-shape",
        "count",
        "bool-count",
        "extent",
        "digest",
        "binding",
        "profile",
        "missing",
        "large-index",
        "extra-manifest-field",
    ],
)
def test_corruption_and_semantic_forgery_rejected_with_bounded_work(tmp_path, case):
    root, _ = saved(tmp_path)
    rows = json.loads((root / "packet-index.json").read_text())
    if case in ("body", "truncated", "trailing"):
        (root / "packet-bodies.bin").write_bytes(
            {
                "body": b"Xnetwo",
                "truncated": b"onetw",
                "trailing": b"onetwoX",
            }[case]
        )
    elif case == "index-hash":
        (root / "packet-index.json").write_text("[]")
    elif case in ("offset", "bool-offset", "bool-size", "zero-size", "oversize", "row-shape"):
        if case == "row-shape":
            rows[0] = []
        else:
            field, value = {
                "offset": ("offset", 1),
                "bool-offset": ("offset", False),
                "bool-size": ("bytes", True),
                "zero-size": ("bytes", 0),
                "oversize": ("bytes", M["MAX_BYTES"] + 1),
            }[case]
            rows[0][field] = value
        rewrite(root, rows)
    elif case == "missing":
        (root / "manifest.json").unlink()
    elif case == "large-index":
        (root / "packet-index.json").write_bytes(b" " * (M["MAX_INDEX"] + 1))
    elif case == "extra-manifest-field":
        rewrite(root, unexpected="must-not-be-echoed")
    else:
        field, value = {
            "count": ("packets", 3),
            "bool-count": ("packets", True),
            "extent": ("bytes", 5),
            "digest": ("sha256", "0" * 64),
            "binding": ("binding", dict(package_sha256="bad")),
            "profile": ("profile", "bad"),
        }[case]
        rewrite(root, **{field: value})
    with pytest.raises((ValueError, OSError)):
        M["verify"](root)


@pytest.mark.parametrize(
    "member", ["directory", "packet-bodies.bin", "packet-index.json", "manifest.json"]
)
@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_special_paths_never_followed_or_blocked(tmp_path, member, kind):
    root, _ = saved(tmp_path)
    path = root if member == "directory" else root / member
    target = tmp_path / "original"
    path.rename(target)
    if kind == "symlink":
        path.symlink_to(target, target_is_directory=member == "directory")
    else:
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        M["verify"](root)


def test_exclusive_writer_never_overwrites_evidence(tmp_path):
    root, _ = saved(tmp_path)
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    with pytest.raises(FileExistsError):
        M["PacketEvidence"](root)
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


def test_offline_checker_cli_has_no_package_or_camera_dependency(tmp_path):
    root, summary = saved(tmp_path)
    command = [sys.executable, "-I", str(TOOL), "--verify", str(root)]
    good = subprocess.run(command, capture_output=True, timeout=5, check=False)
    assert good.returncode == 0
    assert json.loads(good.stdout)["sha256"] == summary["sha256"]
    (root / "manifest.json").unlink()
    bad = subprocess.run(command, capture_output=True, timeout=5, check=False)
    assert bad.returncode == 2 and json.loads(bad.stdout) == dict(status="invalid-or-incomplete")


def test_metadata_failure_closes_the_newly_opened_evidence_file(tmp_path, monkeypatch):
    root, _ = saved(tmp_path)
    opened = []
    real_open, real_stat = os.open, os.fstat
    directory = M["directory"](root)

    def open_file(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail_stat(_fd):
        raise OSError("metadata unavailable")

    # Restore before pytest captures output; its own capture now calls fstat.
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", open_file)
        scoped.setattr(os, "fstat", fail_stat)
        try:
            with (
                pytest.raises(OSError, match="metadata unavailable"),
                M["regular"](
                    directory,
                    "manifest.json",
                    4096,
                ),
            ):
                pytest.fail("metadata failure was ignored")
            assert len(opened) == 1
            with pytest.raises(OSError) as error:
                real_stat(opened[0])
            assert error.value.errno == 9  # EBADF: the file was closed on the failure path.
        finally:
            os.close(directory)
