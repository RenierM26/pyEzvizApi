"""Run the validation integration against an isolated real HA runtime."""
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "tests"))


@pytest.fixture(autouse=True)
def custom_integrations(enable_custom_integrations, socket_enabled):
    """Permit only the test integration under this example root."""


@pytest.fixture
def data(tmp_path):
    path = tmp_path / "private.json"
    path.write_text(json.dumps({
        "serial": "CAMERA123", "endpoint": {"host": "192.0.2.10", "command_port": 8000},
        "cas": {"operation_code": "ABC1234", "key": "0123456789abcdef"},
        "media_key": "secret",
    }))
    return {"name": "Lens A", "credentials_path": str(path), "channel": 0,
            "video_id": 480, "audio_id": 448, "video_codec": "hevc", "nalu_header_size": 2}



@pytest.fixture
def runtime(data):
    from custom_components.ezviz_native.config import load_settings  # noqa: PLC0415 -- fixture-scoped HA dependency
    from custom_components.ezviz_native.route import Runtime  # noqa: PLC0415 -- fixture-scoped HA dependency

    from pyezvizapi.client import EzvizClient  # noqa: PLC0415 -- fixture-scoped HA dependency

    return Runtime(load_settings(data), MagicMock(spec=EzvizClient))



@pytest.fixture
def supported_host(monkeypatch):
    """Declare the complete public host surface without creating HLS delivery."""
    from custom_components.ezviz_native import completion  # noqa: PLC0415 -- fixture-scoped HA dependency
    from homeassistant.components.camera import Camera  # noqa: PLC0415 -- fixture-scoped HA dependency

    monkeypatch.setattr(completion.ha_stream, "FINITE_SOURCE_COMPLETION_CONTRACT",
                        completion.CONTRACT, raising=False)
    monkeypatch.setattr(completion.ha_stream, "FiniteSourceCounts", SimpleNamespace, raising=False)
    monkeypatch.setattr(Camera, "async_validate_webrtc_offer", lambda self, offer: None, raising=False)
    for method in ("async_prepare_finite_source", "async_confirm_finite_source",
                   "async_cancel_finite_source"):
        monkeypatch.setattr(completion.Stream, method, MagicMock(), raising=False)



@pytest.fixture
def clear_finite(monkeypatch):
    from custom_components.ezviz_native.config import load_settings  # noqa: PLC0415 -- fixture-scoped HA dependency
    from custom_components.ezviz_native.group import GroupRegistry  # noqa: PLC0415 -- fixture-scoped HA dependency

    original, declare = load_settings, GroupRegistry.declare

    def finite(values):
        result = original(values)
        return replace(result, options=replace(result.options, finite_source=True))

    def clear_group(self, *args, **kwargs):
        kwargs["media_key"] = None  # Generated test PS is already clear.
        return declare(self, *args, **kwargs)

    monkeypatch.setattr("custom_components.ezviz_native.load_settings", finite)
    monkeypatch.setattr(GroupRegistry, "declare", clear_group)
