from __future__ import annotations

import argparse
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
import sys
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/apk-re/bin/local-sdk-live-check"


def load_live_check() -> ModuleType:
    loader = SourceFileLoader("local_sdk_live_check", str(SCRIPT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def _args(*values: str) -> argparse.Namespace:
    return argparse.Namespace(local_sdk_dump_args=list(values))


def test_passthrough_args_strips_separator() -> None:
    live_check = load_live_check()

    assert live_check._passthrough_args(_args("--", "--serial", "CAM123456")) == [  # noqa: SLF001
        "--serial",
        "CAM123456",
    ]


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("--output=leak.ts", "owns artifacts"),
        ("--metadata-output=leak.json", "owns artifacts"),
        ("--format=mpegps", "captures MPEG-TS"),
        ("--duration=30s", "local-sdk-live-check --duration"),
        ("--ffmpeg-path=/tmp/ffmpeg", "local-sdk-live-check --ffmpeg-path"),
    ],
)
def test_passthrough_args_rejects_owned_equals_options(option: str, message: str) -> None:
    live_check = load_live_check()

    with pytest.raises(ValueError, match=message):
        live_check._passthrough_args(_args("--serial", "CAM123456", option))  # noqa: SLF001


@pytest.mark.parametrize(
    ("option", "message"),
    [
        ("--output", "owns artifacts"),
        ("--metadata-output", "owns artifacts"),
        ("--format", "captures MPEG-TS"),
        ("--duration", "local-sdk-live-check --duration"),
        ("--ffmpeg-path", "local-sdk-live-check --ffmpeg-path"),
    ],
)
def test_passthrough_args_rejects_owned_separate_options(option: str, message: str) -> None:
    live_check = load_live_check()

    with pytest.raises(ValueError, match=message):
        live_check._passthrough_args(  # noqa: SLF001
            _args("--serial", "CAM123456", option, "owned-value")
        )
