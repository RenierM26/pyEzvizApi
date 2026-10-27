"""Run the validation integration against an isolated real HA runtime."""
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "tests"))


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations, socket_enabled):
    """Permit only the test integration under this example root."""
