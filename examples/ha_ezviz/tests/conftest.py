"""Load a pinned, unmodified external HA consumer for offline acceptance."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

SOURCE = Path(os.environ["HA_EZVIZ_SOURCE"]).resolve()
PIN = "aa37ffa0349d26bcc7ba262c9ad90f50d904b4af"
if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip() != PIN:
    raise RuntimeError("ha-ezviz checkout must match the reviewed consumer pin")
if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=SOURCE):
    raise RuntimeError("ha-ezviz tracked source must be unmodified")
sys.path.insert(0, str(SOURCE))


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations):
    """Enable the pinned consumer without installing its old release pin."""
